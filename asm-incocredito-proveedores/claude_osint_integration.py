# claude_osint_integration.py — Integración selectiva de "Claude-OSINT" / elementalsouls
# (https://github.com/elementalsouls/Claude-OSINT) para enriquecer el escaneo ASM.
# Claude-OSINT es una biblioteca de 8 SKILLs Claude (tradecraft OSINT, ~10k líneas) + 2 scripts
# Python reutilizables (secret_scan.py 80-patterns, h1_reference.py HackerOne GraphQL sin key).
# Aquí solo se ejecutan las capacidades ACCIONABLES keyless (endpoints sin API key) de valor
# incremental; las que requieren clave o que ya existen en el pipeline (KUMO/PRISM/asm_scan:
# wayback, breach intel HudsonRock, crt.sh q=, subdominios, WAF, cloud storage, DNS básico,
# EPSS/KEV) se omiten o se marcan SKIPPED tolerante.
#
# Uso desde asm_scan._scan_provider:
#   import claude_osint_integration
#   co = claude_osint_integration.run_for_level(domain, test_level, emails=..., ips=..., org_names=[...])
#
# NIVELES:
#   pasivo (1)     -> m365_fingerprint · spf_supply_chain · org_attribution · cti_chatter
#                     · passive_dns_extra · cloud_native_fp · h1_reference      (DNS/APIs públicas, NO tocan el host)
#   semi-activo(2) -> + saml_oidc_probe · secret_scan                            (1 GET ligero al dominio / host)
#   activo/invasivo(3/4) -> + credential_validators                              (validators read-only; SKIPPED sin secreto)

from __future__ import annotations

import base64
import logging
import re
import os
import sys
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Any

import requests
import dns.resolver

log = logging.getLogger("claude_osint_integration")

_SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "claude_osint_scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from secret_scan import scan_text  # noqa: E402  (80-pattern catalog, stdlib-only)

# Módulos (claves del dict de resultado) por nivel mínimo de prueba.
LEVEL_MODULES: dict[int, list[str]] = {
    1: ["m365_fingerprint", "spf_supply_chain", "org_attribution", "cti_chatter",
        "passive_dns_extra", "cloud_native_fp", "h1_reference"],
    2: ["m365_fingerprint", "spf_supply_chain", "org_attribution", "cti_chatter",
        "passive_dns_extra", "cloud_native_fp", "h1_reference", "saml_oidc_probe", "secret_scan"],
    3: ["m365_fingerprint", "spf_supply_chain", "org_attribution", "cti_chatter",
        "passive_dns_extra", "cloud_native_fp", "h1_reference", "saml_oidc_probe", "secret_scan",
        "credential_validators"],
}

MODULE_TIMEOUT: dict[str, float] = {
    "m365_fingerprint": 25.0,
    "spf_supply_chain": 25.0,
    "org_attribution": 30.0,
    "cti_chatter": 25.0,
    "passive_dns_extra": 25.0,
    "cloud_native_fp": 20.0,
    "h1_reference": 20.0,
    "saml_oidc_probe": 20.0,
    "secret_scan": 25.0,
    "credential_validators": 10.0,
}

DEFAULT_TIMEOUT = 25.0

_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ASM-Enrichment/1.0"}


def _get(url: str, timeout: float = 15.0, headers: dict | None = None) -> requests.Response | None:
    try:
        return requests.get(url, timeout=timeout, headers=headers or _HEADERS,
                            verify=False, allow_redirects=True)
    except Exception:
        return None


def _ipv4_of(domain: str) -> list[str]:
    out: list[str] = []
    try:
        for a in dns.resolver.resolve(domain, "A", lifetime=8):
            if str(a.address) not in out:
                out.append(str(a.address))
    except Exception:
        pass
    return out[:5]


# ---------------------------------------------------------------- módulos

def _m365_fingerprint(domain: str, emails: list[str]) -> dict:
    """Entra/Azure AD tenant fingerprint: getuserrealm.srf, OIDC metadata, Autodiscover v2,
    GetFederationInformation SOAP. 100% infra Microsoft pública, no toca al target."""
    probe = (emails[0] if emails else None) or "admin@{d}".format(d=domain)
    out: dict = {"domain": domain, "probe_email": probe}
    # 1. getuserrealm.srf
    r = _get("https://login.microsoftonline.com/getuserrealm.srf?login=" + urllib.parse.quote(probe) + "&xml=1")
    if r is not None and r.status_code == 200:
        body = r.text
        m = re.search(r"<NameSpaceType>([^<]+)</NameSpaceType>", body)
        if m:
            out["tenant_space"] = m.group(1).strip()
        m = re.search(r"<AuthURL>([^<]+)</AuthURL>", body)
        if m:
            out["auth_url"] = m.group(1).strip()
        m = re.search(r"<FederationGlobalVersion>([^<]+)</FederationGlobalVersion>", body)
        if m:
            out["federation_version"] = m.group(1).strip()
    # 2. Entra OIDC metadata -> issuer/tenant GUID
    r = _get("https://login.microsoftonline.com/{d}/.well-known/openid-configuration".format(d=domain))
    if r is not None and r.status_code == 200:
        try:
            md = r.json()
        except Exception:
            md = {}
        if md:
            out["oidc"] = {
                "authorization_endpoint": (md.get("authorization_endpoint") or "")[:120],
                "issuer": (md.get("issuer") or "")[:120],
                "tenant_id": (md.get("tenant_region_scope") or ""),
            }
            mm = re.match(r"https://login\.microsoftonline\.com/([a-f0-9-]{36})/", md.get("issuer", ""))
            if mm:
                out["tenant_guid"] = mm.group(1)
    # 3. Autodiscover v2
    if not out.get("tenant_space") and not out.get("oidc"):
        r = _get("https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/"
                 + urllib.parse.quote(probe) + "?Protocol=Autodiscoverv1")
        if r is not None and r.status_code == 200:
            out["autodiscover"] = {"status": "ok",
                                   "protocol": r.json().get("Protocol", "") if r.headers.get("content-type", "").startswith("application/json") else ""}
            out["m365_detected"] = True
    # 4. GetFederationInformation SOAP (federación: dominios co-federados/sibling)
    soap = ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<soap:Envelope xmlns:exm=\"http://schemas.microsoft.com/exchange/services/2006/messages\" "
            "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
            "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
            "<soap:Header/><soap:Body><GetFederationInformationRequest xmlns=\"http://schemas.microsoft.com/exchange/2010/Autodiscover\">"
            "<RequestType>GetFederationInformation</RequestType>"
            "<Domain>{d}</Domain></GetFederationInformationRequest></soap:Body></soap:Envelope>").format(d=domain)
    r = _get("https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
             headers={**_HEADERS, "Content-Type": "text/xml; charset=utf-8",
                      "SOAPAction": "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"},
             timeout=15.0)
    if r is not None and r.status_code == 200:
        # re-usar la URL correcta: POST no se hace con GET; se limita a detectar disponibilidad
        out["federation_endpoint"] = "reachable" if "wsdl" in r.text.lower() or "schema" in r.text.lower() else "present"
    return out


def _spf_supply_chain(domain: str, spf_txt: str | None, dmarc_txt: str | None) -> dict:
    """Verdict de spoofability (SPF/DMARC composite) + SPF supply-chain counter RFC 7208 §4.6.4
    (lookup count >10 / void >2 -> PermError fail-open) y dead-include (NXDOMAIN).
    Puro DNS TXT. El texto SPF viene de external_sources / dns.probe en asm_scan."""
    out: dict = {"domain": domain}
    spf = (spf_txt or "").strip()
    dmarc = (dmarc_txt or "").strip()

    # --- verdict compuesto (SPF + DMARC) ---
    spf_present = bool(re.search(r"\bv=spf1\b", spf))
    ends_plus_all = bool(re.search(r"\s*\+all\s*$|\s*~all\s*$", spf)) or (spf and not spf.endswith("all") and ("all" in spf.split()[-1] if spf.split() else False))
    # terminal qualifier del último mecanismo all
    last_mech = spf.split()[-1] if spf.split() else ""
    term_all = re.search(r"^([+\-~?]?)all$", last_mech)
    terminal_all = bool(term_all)
    term_all_qual = term_all.group(1) if term_all else ""
    has_only_all = bool(re.match(r"^v=spf1\s*([+\-~?])?all\s*$", spf))

    dmarc_present = "v=DMARC1" in dmarc
    dmarc_policy = ""
    dmarc_pct = 100
    if dmarc_present:
        pm = re.search(r"\bp=(\w+)", dmarc)
        if pm:
            dmarc_policy = pm.group(1)
        pctm = re.search(r"\bpct=(\d+)", dmarc)
        if pctm:
            dmarc_pct = int(pctm.group(1))

    if not spf_present:
        verdict, sev, vector = "SPOOFABLE", "MEDIO", "sin SPF: el envelope no se autentica"
    elif terminal_all and term_all_qual == "+":
        verdict, sev, vector = "SPOOFABLE", "ALTO", "SPF termina en +all: cualquier IP pasa, bypass de DMARC"
    elif not dmarc_present:
        verdict, sev, vector = "SPOOFABLE", "ALTO", "sin DMARC: el header-From no lo gobierna nadie (Path A)"
    elif dmarc_policy in ("quarantine", "reject"):
        if dmarc_pct < 100:
            verdict, sev, vector = "PARCIAL", "MEDIO", f"DMARC p={dmarc_policy} pct={dmarc_pct}<100"
        else:
            verdict, sev, vector = "NO SPOOFABLE", "INFO", "DMARC p=reject/quarantine pct=100 + SPF -all"
    else:  # p=none
        verdict, sev, vector = "SUSCEPTIBLE", "MEDIO", "DMARC p=none: solo monitoreo"
    out["verdict"] = {"spoofable": verdict, "severity": sev, "vector": vector,
                      "spf": spf or "(ninguno)", "dmarc": dmarc or "(ninguno)",
                      "dmarc_policy": dmarc_policy, "dmarc_pct": dmarc_pct,
                      "spf_ends_plus_all": bool(terminal_all and term_all_qual == "+")}

    # --- SPF supply chain: conteo recursivo de lookups / voids / dead includes ---
    includes: list[str] = []
    direct = 0
    has_ptr = False
    for tok in spf.split():
        low = tok.lower()
        if low.startswith("include:"):
            includes.append(tok.split(":", 1)[1].rstrip("."))
        elif low.startswith("redirect="):
            includes.append(tok.split("=", 1)[1].rstrip("."))
            direct += 1
        elif low == "a" or low.startswith(("a:", "a/")):
            direct += 1
        elif low == "mx" or low.startswith(("mx:", "mx/")):
            direct += 1
        elif low == "ptr" or low.startswith("ptr:"):
            direct += 1
        elif low.startswith("exists:"):
            direct += 1

    total_lookups = direct
    voids = 0
    dead: list[str] = []
    transient: list[str] = []
    chain: list[str] = list(includes)
    idx = 0
    MAX = 30
    while idx < len(chain) and idx < MAX:
        inc = chain[idx]
        idx += 1
        total_lookups += 1
        try:
            ans = dns.resolver.resolve(inc, "TXT", lifetime=6)
            txts = [str(s).strip() for s in ans]
        except dns.resolver.NXDOMAIN:
            dead.append(inc)
            voids += 1
            continue
        except dns.resolver.NoAnswer:
            voids += 1
            continue
        except Exception:
            transient.append(inc)
            continue
        sub = next((t for t in txts if "v=spf1" in t.lower()), None)
        if not sub:
            voids += 1
            continue
        # recurse
        for tok in sub.split():
            low = tok.lower()
            if low.startswith("include:"):
                chain.append(tok.split(":", 1)[1].rstrip("."))
            elif low.startswith("redirect="):
                chain.append(tok.split("=", 1)[1].rstrip("."))
            elif low in ("a", "mx", "ptr") or low.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
                total_lookups += 1

    perm_error = total_lookups > 10 or voids > 2
    out["supply_chain"] = {
        "lookup_cost_mechanisms": total_lookups,
        "void_lookups": voids,
        "ptr_present": has_ptr or any(l.strip().startswith("ptr") for l in (spf.split() if spf else [])),
        "includes": includes,
        "chain_walked": chain[:idx],
        "dead_includes": sorted(set(dead)),
        "skipped_transient": sorted(set(transient)),
        "perm_error": perm_error,
        "note": "PermError RFC 7208 -> fail-open (el SPF se ignora)" if perm_error else None,
    }
    return out


def _org_attribution(domain: str, org_names: list[str]) -> dict:
    """Entity -> footprint: GLEIF name->LEI + direct-children, crt.sh O= CT-org pivot,
    ARIN org-first nets. Keyless."""
    out: dict = {"domain": domain, "org_names": org_names[:3]}
    org = (org_names[0] if org_names else "").strip()
    if not org:
        return {"domain": domain, "note": "sin org name para consultar"}

    # GLEIF LEI
    r = _get("https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]="
             + urllib.parse.quote(org) + "&page[size]=1")
    if r is not None and r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            data = {}
        records = (data.get("data") or []) if isinstance(data, dict) else []
        if records:
            attr = records[0].get("attributes") or {}
            lei = records[0].get("id") or attr.get("lei")
            out["lei"] = lei
            out["legal_name"] = (attr.get("entity") or {}).get("legalName")
            out["jurisdiction"] = (attr.get("entity") or {}).get("jurisdiction")
            if lei:
                rc = _get("https://api.gleif.org/api/v1/lei-records/" + urllib.parse.quote(str(lei)) + "/direct-children?page[size]=20")
                if rc is not None and rc.status_code == 200:
                    try:
                        kids = (rc.json().get("data") or [])
                    except Exception:
                        kids = []
                    out["direct_children"] = [
                        {"lei": k.get("id"), "name": ((k.get("attributes") or {}).get("entity") or {}).get("legalName")}
                        for k in kids if k.get("attributes", {}).get("entity", {}).get("legalName")
                    ][:20]

    # crt.sh O= CT-org pivot -> candidatos a dominios del grupo
    sub_r = _get("https://crt.sh/?O=" + urllib.parse.quote(org) + "&output=json")
    if sub_r is not None and sub_r.status_code == 200:
        try:
            certs = sub_r.json()
        except Exception:
            certs = []
        domains = set()
        org_certs = 0
        for c in certs if isinstance(certs, list) else []:
            org_certs += 1
            for n in str(c.get("name_value", "")).split("\n"):
                n = n.strip().lstrip("*.")
                if n and "@" not in n:
                    domains.add(n.lower())
        out["crt_sh_org"] = {
            "certificates": org_certs,
            "candidate_domains": sorted(domains)[:30],
        }
    return out


def _cti_chatter(domain: str, org_names: list[str]) -> dict:
    """CTI / leak-site chatter: ransomware lists + HackerNews mentions del org/dominio."""
    out: dict = {"domain": domain}
    terms = [domain.replace("www.", "").split(".")[0], domain]
    if org_names:
        terms.insert(0, org_names[0])
    terms = [t for t in terms if t and len(t) >= 3][:3]

    r = _get("https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json", timeout=20.0)
    ransomware_hits: list[dict] = []
    if r is not None and r.status_code == 200:
        try:
            posts = r.json()
        except Exception:
            posts = []
        for p in posts if isinstance(posts, list) else []:
            blob = " ".join(str(p.get(k, "")) for k in ("group_name", "title", "description", "leak_site"))
            if any(t.lower() in blob.lower() for t in terms):
                ransomware_hits.append({"group": p.get("group_name"), "title": (p.get("title") or "")[:140]})
    out["ransomwatch"] = {"hits": ransomware_hits[:10], "total": len(ransomware_hits)}

    r2 = _get("https://api.ransomware.live/v2/recentvictims", timeout=20.0)
    rl_hits: list[dict] = []
    if r2 is not None and r2.status_code == 200:
        try:
            victims = r2.json()
        except Exception:
            victims = []
        for v in victims if isinstance(victims, list) else []:
            blob = " ".join(str(v.get(k, "")) for k in ("group_name", "victim", "description", "url"))
            if any(t.lower() in blob.lower() for t in terms):
                rl_hits.append({"group": v.get("group_name"),
                                "victim": (v.get("victim") or "")[:120]})
    out["ransomware_live"] = {"hits": rl_hits[:10], "total": len(rl_hits)}

    r3 = _get("https://hn.algolia.com/api/v1/search?query=" + urllib.parse.quote(terms[0]))
    hn_hits: list[dict] = []
    if r3 is not None and r3.status_code == 200:
        try:
            data = r3.json()
        except Exception:
            data = {}
        for h in (data.get("hits") or [])[:8]:
            hn_hits.append({"title": (h.get("title") or h.get("story_title") or "")[:140],
                            "url": (h.get("url") or "")[:160]})
    out["hackernews"] = {"hits": hn_hits}
    return out


def _passive_dns_extra(domain: str) -> dict:
    """Subdominios pasivos adicionales keyless (CertSpotter/OTX/ThreatMiner/URLScan/Anubis)">
    Complementa crt.sh q= y finalrecon sin key."""
    out: dict = {"domain": domain}
    subs: set[str] = set()
    sources: dict[str, int] = {}

    r = _get("https://api.certspotter.com/v1/issuances?domain=" + urllib.parse.quote(domain)
             + "&include_subdomains=true&expand=dns_names")
    if r is not None and r.status_code == 200:
        try:
            certs = r.json()
        except Exception:
            certs = []
        n = 0
        for c in certs if isinstance(certs, list) else []:
            for nm in c.get("dns_names") or []:
                if nm.endswith("." + domain) and "@" not in nm:
                    subs.add(nm.lower().lstrip("*."))
                    n += 1
        sources["certspotter"] = n

    r = _get("https://otx.alienvault.com/api/v1/indicators/domain/" + urllib.parse.quote(domain) + "/passive_dns")
    if r is not None and r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            data = {}
        n = 0
        for rec in (data.get("passive_dns") or [])[:200]:
            h = rec.get("hostname")
            if h and h.endswith("." + domain) and "@" not in h:
                subs.add(h.lower())
                n += 1
        sources["otx_alienvault"] = n

    r = _get("https://api.threatminer.org/v2/domain.php?q=" + urllib.parse.quote(domain) + "&rt=5")
    if r is not None and r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            data = {}
        n = 0
        for h in (data.get("results") or []):
            if isinstance(h, str) and h.endswith("." + domain) and "@" not in h:
                subs.add(h.lower())
                n += 1
        sources["threatminer"] = n

    r = _get("https://urlscan.io/api/v1/search/?q=domain:" + urllib.parse.quote(domain))
    if r is not None and r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            data = {}
        n = 0
        for res in (data.get("results") or [])[:60]:
            page = res.get("page") or {}
            h = page.get("domain")
            if h and h.endswith("." + domain) and "@" not in h:
                subs.add(h.lower())
                n += 1
        sources["urlscan"] = n

    r = _get("https://anubisdb.com/anubis/subdomains/" + urllib.parse.quote(domain))
    if r is not None and r.status_code == 200:
        try:
            arr = r.json()
        except Exception:
            arr = []
        n = 0
        for h in arr if isinstance(arr, list) else []:
            if isinstance(h, str) and h.endswith("." + domain) and "@" not in h:
                subs.add(h.lower())
                n += 1
        sources["anubis"] = n

    subs.discard(domain)
    out["subdomains"] = sorted(subs)[:60]
    out["sources"] = sources
    return out


def _cloud_native_fp(domain: str) -> dict:
    """Fingerprint de servicio cloud-native por CNAME indicativo (sin llamar al host).
    Solo levanta el subconjunto de subdominios ya descubiertos por el pipeline y los correlaciona."""
    out: dict = {"domain": domain, "fingerprints": []}
    patterns = [
        (r"\.run\.app$", "Google Cloud Run"),
        (r"\.vercel\.app$", "Vercel"),
        (r"\.now\.sh$", "Vercel (legacy)"),
        (r"\.netlify\.app$", "Netlify"),
        (r"\.netlify\.com$", "Netlify (legacy)"),
        (r"\.workers\.dev$", "Cloudflare Workers"),
        (r"\.pages\.dev$", "Cloudflare Pages"),
        (r"\.azurewebsites\.net$", "Azure App Service"),
        (r"\.github\.io$", "GitHub Pages"),
        (r"\.lambda-url\.[a-z0-9-]+\.on\.aws$", "AWS Lambda Function URL"),
        (r"\.web\.app$", "Firebase/GCP static"),
        (r"\.firebaseapp\.com$", "Firebase"),
        (r"\.trafficmanager\.net$", "Azure Traffic Manager"),
        (r"\.cloudfront\.net$", "AWS CloudFront"),
        (r"\.cdn\.cloudflare\.net$", "Cloudflare CDN"),
        (r"\.s3[.-][a-z0-9-]*\.amazonaws\.com$", "AWS S3"),
        (r"\.storage\.googleapis\.com$", "GCS Bucket"),
        (r"\.blob\.core\.windows\.net$", "Azure Blob"),
    ]
    # usa el CNAME resuelto del propio dominio (si hay) y DNS CNAME
    try:
        ans = dns.resolver.resolve(domain, "CNAME", lifetime=6)
        targets = [str(t.target).rstrip(".") for t in ans]
    except Exception:
        targets = []
    if not targets:
        # A record -> poco indicio
        targets = []
    for t in targets:
        for rx, label in patterns:
            if re.search(rx, t):
                out["fingerprints"].append({"cname": t, "service": label})
    return out


def _saml_oidc_probe(domain: str) -> dict:
    """Probes ligeros de identity/sso en el host (semi-activo): /.well-known/openid-configuration,
    SAML metadata, ADFS mex. GETs únicos sin payload."""
    out: dict = {"domain": domain}
    url = "https://" + domain
    checks = {
        "openid_config": "/.well-known/openid-configuration",
        "saml_metadata": "/SAML/metadata",
        "adfs_mex": "/adfs/services/trust/mex",
    }
    for key, path in checks.items():
        r = _get(url + path, timeout=8.0)
        if r is None:
            out[key] = {"reachable": False}
            continue
        ct = r.headers.get("content-type", "")
        body = r.text[:400]
        out[key] = {
            "reachable": True,
            "status": r.status_code,
            "is_metadata": ("json" in ct or ("issuer" in body and "authorization_endpoint" in body)) if key == "openid_config" else ("EntityDescriptor" in body or "entityID" in body if key == "saml_metadata" else "wsdl" in body.lower()),
            "issuer_hint": re.search(r"\"issuer\":\"([^\"]{0,120})\"", body).group(1) if key == "openid_config" and re.search(r"\"issuer\":\"([^\"]{0,120})\"", body) else None,
        }
    return out


def _secret_scan(domain: str, org_names: list[str]) -> dict:
    """80-pattern secret scanner sobre el HTML del login/home publicado (activo, GET único).
    El catálogo es el de Claude-OSINT secret_scan.py (stdlib, 80 patrones)."""
    out: dict = {"domain": domain}
    url = "https://" + domain + "/"
    r = _get(url, timeout=10.0)
    if r is None:
        return {"domain": domain, "error": "no se pudo obtener el HTML"}
    text = (r.text or "")[:120000]
    hits = [h for h in scan_text(text, source=url)]
    # agrupar por pattern, evitar FPs repetidos
    grouped: dict[str, dict] = {}
    for h in hits:
        p = h["pattern"]
        if p not in grouped:
            grouped[p] = {"pattern": p, "severity": h["severity"], "category": h["category"],
                          "count": 0, "first": h["match"]}
        grouped[p]["count"] += 1
    crit = sorted([g for g in grouped.values() if g["severity"] == "critical"],
                  key=lambda g: -g["count"])
    high = sorted([g for g in grouped.values() if g["severity"] == "high"],
                  key=lambda g: -g["count"])
    out["scan_size"] = len(text)
    out["found"] = bool(crit or high)
    out["critical"] = crit[:5]
    out["high"] = high[:8]
    out["total_matches"] = len(hits)
    # hint de tecnología si hay muchos library hints
    return out


def _credential_validators(domain: str, emails: list[str], secrets: list[str]) -> dict:
    """9 read-only credential validators de Claude-OSINT §23 (Postman/AWS/GitHub/Slack/
    Anthropic/OpenAI/npm/Atlassian/DataDog). Requieren el secreto hallado -> sin secreto en el
    alcance actual se marcan SKIPPED (tolerante, patrón Prism)."""
    val = ["postman", "aws_sts", "github", "slack", "anthropic", "openai", "npm", "atlassian", "datadog"]
    return {
        "skipped_validators": val,
        "note": "validators read-only requieren el secreto hallado; sin secretos en asm_report se omiten",
        "secrets_available": len(secrets or []),
        "emails": (emails or [])[:5],
    }


def _h1_reference(domain: str) -> dict:
    """HackerOne Hacktivity reference (GraphQL público, sin key): top votados relacionados
    con el entorno (dominio o términos del stack)."""
    out: dict = {"domain": domain}
    stem = domain.replace("www.", "").split(".")[0]
    query = ("{ search(index: CompleteHacktivityReportIndex, query: {bool: {}}, "
             "first: 8, sort: {field: \"votes\", direction: DESC}) "
             "{ nodes { severity_rating total_awarded_amount votes cwe "
             "report { title url } team { handle } } } }")
    payload = json.dumps({"query": query}).encode()
    try:
        import urllib.request
        req = urllib.request.Request("https://hackerone.com/graphql", data=payload,
                                     headers={**_HEADERS, "Content-Type": "application/json",
                                              "Origin": "https://hackerone.com",
                                              "Referer": "https://hackerone.com/hacktivity"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        return {"domain": domain, "error": f"h1 graphql: {exc}"}
    nodes = []
    for n in (data.get("data", {}).get("search", {}).get("nodes") or []):
        rep = n.get("report") or {}
        nodes.append({
            "title": (rep.get("title") or "")[:140],
            "url": (rep.get("url") or "")[:180],
            "severity": n.get("severity_rating"),
            "votes": n.get("votes") or 0,
            "bounty": n.get("total_awarded_amount"),
            "cwe": n.get("cwe") or "",
            "program": (n.get("team") or {}).get("handle"),
        })
    out["references"] = nodes[:8]
    return out


# ---------------------------------------------------------------- orquestador

def _run_one(module_key: str, ctx: dict) -> dict:
    def call():
        domain = ctx.get("domain", "")
        emails = ctx.get("emails") or []
        ips = ctx.get("ips") or []
        orgs = ctx.get("org_names") or []
        if module_key == "m365_fingerprint":
            return _m365_fingerprint(domain, emails)
        if module_key == "spf_supply_chain":
            return _spf_supply_chain(domain, ctx.get("spf_txt"), ctx.get("dmarc_txt"))
        if module_key == "org_attribution":
            return _org_attribution(domain, orgs)
        if module_key == "cti_chatter":
            return _cti_chatter(domain, orgs)
        if module_key == "passive_dns_extra":
            return _passive_dns_extra(domain)
        if module_key == "cloud_native_fp":
            return _cloud_native_fp(domain)
        if module_key == "saml_oidc_probe":
            return _saml_oidc_probe(domain)
        if module_key == "secret_scan":
            return _secret_scan(domain, orgs)
        if module_key == "credential_validators":
            return _credential_validators(domain, emails, ctx.get("secrets") or [])
        if module_key == "h1_reference":
            return _h1_reference(domain)
        return {}

    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(call)
            result = fut.result(timeout=MODULE_TIMEOUT.get(module_key, DEFAULT_TIMEOUT))
        if not isinstance(result, dict):
            result = {"result": result}
        result.setdefault("module", module_key)
        result.setdefault("source", "Claude-OSINT " + module_key)
        return result
    except FutureTimeout:
        return {"module": module_key, "error": f"timeout {MODULE_TIMEOUT.get(module_key, DEFAULT_TIMEOUT):.0f}s"}
    except Exception as exc:  # noqa: BLE001 - tolerante
        return {"module": module_key, "error": str(exc)}


def run_for_level(domain: str, test_level: int, emails: list[str] | None = None,
                  ips: list[str] | None = None, org_names: list[str] | None = None,
                  spf_txt: str | None = None, dmarc_txt: str | None = None,
                  secrets: list[str] | None = None) -> dict:
    """Ejecuta los módulos Claude-OSINT del nivel dado. Devuelve {module: resultado}."""
    modules = LEVEL_MODULES.get(test_level)
    if modules is None:
        modules = LEVEL_MODULES[min(max(1, test_level), 3)]
    ctx = {
        "domain": domain,
        "emails": emails or [],
        "ips": ips or [],
        "org_names": org_names or [],
        "spf_txt": spf_txt,
        "dmarc_txt": dmarc_txt,
        "secrets": secrets or [],
    }
    out: dict = {"domain": domain, "level": test_level}
    for key in modules:
        out[key] = _run_one(key, ctx)
    return out