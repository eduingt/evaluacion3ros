#!/usr/bin/env python3
"""
ASM ligero para dominios de proveedores: DNS, puertos 80/443, HTTPS,
cabeceras de seguridad, negociación TLS (incl. prueba TLS 1.3-only), SAN,
CAA, MTA-STS, TLS-RPT, BIMI y subdominios pasivos vía crt.sh, Hackertarget, Rapiddns.
Solo tráfico estándar a servicios públicos; no fuzzing ni escaneo amplio de puertos.

Panel web (escaneo + PDF en el navegador):
  pip install -r requirements-dashboard.txt
  playwright install chromium
  python dashboard_server.py

Lista de dominios: providers.json (ahora solo www.incocredito.com.co).
Para volver a los 11 proveedores: copia providers_11_incocredito_proveedores.json sobre providers.json

Complemento OrgASM (subdominios vía APIs públicas + brute tiny + export web):
  pip install -r OrgASM/requirements.txt
  python run_orgasm_providers.py --dry-run

Informe HTML estilo TPRA/SOCRadar:
  python generate_socradar_style_report.py

Informe único ASM + último export OrgASM por dominio:
  python merge_asm_orgasm.py
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
import re
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.resolver
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import social_osint
import owasp_agentic
import log_utils
import external_sources

TIMEOUT = 12
USER_AGENT = "ASM-Incocredito-Proveedores/1.0 (+research)"

# Enumeración DNS pasiva acotada (sin fuerza bruta masiva).
SUBDOMAIN_PREFIXES: tuple[str, ...] = (
    "www",
    "api",
    "app",
    "portal",
    "admin",
    "mail",
    "smtp",
    "mx",
    "vpn",
    "remote",
    "cdn",
    "static",
    "assets",
    "img",
    "m",
    "mobile",
    "dev",
    "staging",
    "stage",
    "test",
    "uat",
    "sandbox",
    "ws",
    "graphql",
    "auth",
    "login",
    "sso",
    "id",
    "docs",
    "status",
    "blog",
    "help",
    "support",
)

# Rutas frecuentes en APIs y documentación pública (solo HEAD).
PUBLIC_PATHS: tuple[str, ...] = (
    "/robots.txt",
    "/.well-known/security.txt",
    "/health",
    "/api/health",
    "/actuator/health",
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/.well-known/openid-configuration",
)


@dataclass
class PortCheck:
    open: bool
    error: str | None = None


@dataclass
class TLSProbe:
    tls13_only_ok: bool
    negotiated_version: str | None
    cert_subject: str | None
    cert_issuer: str | None
    cert_expiry: str | None
    cert_serial: str | None
    cert_version: str | None
    san_list: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class HTTPProbe:
    final_url: str | None
    status_code: int | None
    https_ok: bool
    redirect_chain: list[str]
    headers: dict[str, str]
    server_fingerprint: str | None
    x_powered_by: str | None
    feature_policy: str | None
    expect_ct: str | None
    x_permitted_cross_domain: str | None
    via: str | None
    cf_ray: str | None
    x_cdn: str | None
    error: str | None = None


@dataclass
class DNSProbe:
    ipv4: list[str]
    ipv6: list[str]
    spf_record: str | None
    dmarc_record: str | None
    dmarc_policy: str | None
    mx_records: list[dict[str, str]] = field(default_factory=list)
    ns_records: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    ip_country: str | None = None
    dnssec_ok: bool = False
    dkim_records: list[dict[str, str]] = field(default_factory=list)
    dane_records: list[dict[str, str]] = field(default_factory=list)
    ip_reputation: list[dict[str, str]] = field(default_factory=list)
    starttls_results: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ProviderASM:
    id: str
    name: str
    domain: str
    dns: DNSProbe
    port_80: PortCheck
    port_443: PortCheck
    tls: TLSProbe
    https: HTTPProbe
    scanned_at: str
    subdomains: list[dict[str, Any]] = field(default_factory=list)
    public_paths: list[dict[str, Any]] = field(default_factory=list)
    crt_subdomains: list[str] = field(default_factory=list)
    caa_records: list[dict[str, str]] = field(default_factory=list)
    mta_sts: str | None = None
    tls_rpt: str | None = None
    bimi: str | None = None
    san_list: list[str] = field(default_factory=list)
    mx_records: list[dict[str, str]] = field(default_factory=list)
    ns_records: list[dict[str, str]] = field(default_factory=list)
    urlhaus: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    credential_leaks: list[dict[str, Any]] = field(default_factory=list)
    typosquatting: list[dict[str, Any]] = field(default_factory=list)
    patching: list[dict[str, Any]] = field(default_factory=list)
    supply_chain: list[dict[str, Any]] = field(default_factory=list)
    takeover_risks: list[dict[str, Any]] = field(default_factory=list)
    csp_findings: list[dict[str, Any]] = field(default_factory=list)
    cookie_findings: list[dict[str, Any]] = field(default_factory=list)
    supply_chain_reputation: dict[str, Any] = field(default_factory=lambda: {"dnsbl": [], "urlhaus": []})
    social: dict[str, Any] = field(default_factory=dict)
    external: dict[str, Any] = field(default_factory=dict)


def resolve_dns(domain: str) -> DNSProbe:
    ipv4: list[str] = []
    ipv6: list[str] = []
    spf_record: str | None = None
    dmarc_record: str | None = None
    dmarc_policy: str | None = None
    mx_records: list[dict[str, str]] = []
    ns_records: list[dict[str, str]] = []
    errors: list[str] = []

    try:
        for r in dns.resolver.resolve(domain, "A", lifetime=8):
            ipv4.append(str(r))
    except Exception as e:
        errors.append(f"A: {e}")

    try:
        for r in dns.resolver.resolve(domain, "AAAA", lifetime=8):
            ipv6.append(str(r))
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        errors.append(f"AAAA: {e}")

    try:
        for r in dns.resolver.resolve(domain, "TXT", lifetime=8):
            txt = b"".join(r.strings).decode("utf-8", errors="replace")
            if txt.strip().lower().startswith("v=spf1"):
                spf_record = txt
                break
    except Exception as e:
        errors.append(f"TXT/SPF: {e}")

    dmarc_name = f"_dmarc.{domain}"
    try:
        for r in dns.resolver.resolve(dmarc_name, "TXT", lifetime=8):
            txt = b"".join(r.strings).decode("utf-8", errors="replace")
            if txt.strip().lower().startswith("v=dmarc1"):
                dmarc_record = txt
                low = txt.lower()
                for pol in ("p=reject", "p=quarantine", "p=none"):
                    if pol in low:
                        dmarc_policy = pol.replace("p=", "")
                        break
                break
    except Exception as e:
        errors.append(f"TXT/DMARC: {e}")

    # MX records
    try:
        for r in dns.resolver.resolve(domain, "MX", lifetime=8):
            mx_records.append({"preference": str(r.preference), "exchange": str(r.exchange).rstrip('.')})
    except Exception as e:
        errors.append(f"MX: {e}")

    # NS records
    try:
        for r in dns.resolver.resolve(domain, "NS", lifetime=8):
            ns_records.append({"nameserver": str(r.target).rstrip('.')})
    except Exception as e:
        errors.append(f"NS: {e}")

    # DNSSEC
    dnssec_ok = query_dnssec(domain)

    # DKIM
    dkim_records = query_dkim(domain)

    # DANE/TLSA
    dane_records = query_dane(domain)

    # IP reputation (DNSBL)
    ip_reputation = check_ip_reputation(ipv4)

    # STARTTLS check on MX servers
    starttls_results = check_starttls(mx_records)

    return DNSProbe(
        ipv4=ipv4,
        ipv6=ipv6,
        spf_record=spf_record,
        dmarc_record=dmarc_record,
        dmarc_policy=dmarc_policy,
        mx_records=mx_records,
        ns_records=ns_records,
        errors=errors,
        dnssec_ok=dnssec_ok,
        dkim_records=dkim_records,
        dane_records=dane_records,
        ip_reputation=ip_reputation,
        starttls_results=starttls_results,
    )


def check_port(host: str, port: int) -> PortCheck:
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return PortCheck(open=True)
    except Exception as e:
        return PortCheck(open=False, error=str(e))


def probe_tls(domain: str) -> TLSProbe:
    def tls_version_name(v: int | str) -> str:
        if isinstance(v, str):
            return v
        return {768: "TLSv1.0", 769: "TLSv1.1", 770: "TLSv1.2", 771: "TLSv1.3"}.get(v, f"unknown({v})")

    tls13_only_ok = False
    negotiated: str | None = None
    cert_subject = cert_issuer = cert_expiry = cert_serial = cert_version = None
    san_list: list[str] = []
    err: str | None = None

    # Default TLS handshake
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as ssock:
                negotiated = tls_version_name(ssock.version())
                cert = ssock.getpeercert()
                if cert:
                    subj = cert.get("subject")
                    if subj:
                        parts = []
                        for tup in subj:
                            for k, v in tup:
                                parts.append(f"{k}={v}")
                        cert_subject = ", ".join(parts)
                    iss = cert.get("issuer")
                    if iss:
                        parts = []
                        for tup in iss:
                            for k, v in tup:
                                parts.append(f"{k}={v}")
                        cert_issuer = ", ".join(parts)
                    nb = cert.get("notAfter")
                    if nb:
                        cert_expiry = nb
                    cert_serial = cert.get("serialNumber")
                    # cert version is an integer (e.g., 2 for X509 v3)
                    version_int = cert.get("version")
                    if version_int is not None:
                        cert_version = str(version_int)
                    san_list = extract_san(cert)
    except Exception as e:
        err = str(e)
        return TLSProbe(
            tls13_only_ok=False,
            negotiated_version=None,
            cert_subject=None,
            cert_issuer=None,
            cert_expiry=None,
            cert_serial=None,
            cert_version=None,
            san_list=[],
            error=err,
        )

    # TLS 1.3-only probe
    try:
        ctx13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx13.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx13.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx13.check_hostname = True
        ctx13.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((domain, 443), timeout=8) as raw:
            with ctx13.wrap_socket(raw, server_hostname=domain) as ssock:
                if ssock.version() == "TLSv1.3":
                    tls13_only_ok = True
    except Exception:
        tls13_only_ok = False

    return TLSProbe(
        tls13_only_ok=tls13_only_ok,
        negotiated_version=negotiated,
        cert_subject=cert_subject,
        cert_issuer=cert_issuer,
        cert_expiry=cert_expiry,
        cert_serial=cert_serial,
        cert_version=cert_version,
        san_list=san_list,
        error=None,
    )


def session_with_retries() -> requests.Session:
    s = requests.Session()
    retries = Retry(total=2, backoff_factor=0.4, status_forcelist=[502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def probe_https(domain: str, sess: requests.Session) -> HTTPProbe:
    url = f"https://{domain}/"
    redirect_chain: list[str] = []
    try:
        r = sess.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=True,
        )
        for h in r.history:
            redirect_chain.append(f"{h.status_code} {h.url}")
        redirect_chain.append(f"{r.status_code} {r.url}")

        interesting = (
            "strict-transport-security",
            "content-security-policy",
            "content-security-policy-report-only",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "server",
            "via",
            "cf-ray",
            "x-powered-by",
            "set-cookie",
        )
        hmap: dict[str, str] = {}
        # Collect all Set-Cookie headers separately (can appear multiple times)
        all_set_cookies: list[str] = []
        for k, v in r.headers.items():
            lk = k.lower()
            if lk == "set-cookie":
                all_set_cookies.append(v[:500] if isinstance(v, str) else str(v)[:500])
            elif lk in interesting:
                hmap[lk] = v[:500] if isinstance(v, str) else str(v)[:500]
        if all_set_cookies:
            hmap["set-cookie"] = " | ".join(all_set_cookies)

        fp_parts: list[str] = []
        if "server" in hmap:
            fp_parts.append(f"server={hmap['server']}")
        if "cf-ray" in hmap:
            fp_parts.append("cloudflare")
        if "x-powered-by" in hmap:
            fp_parts.append(f"x-powered-by={hmap['x-powered-by']}")
        server_fp = " | ".join(fp_parts) if fp_parts else None

        return HTTPProbe(
            final_url=str(r.url),
            status_code=r.status_code,
            https_ok=200 <= r.status_code < 500,
            redirect_chain=redirect_chain,
            headers=hmap,
            server_fingerprint=server_fp,
            x_powered_by=hmap.get("x-powered-by"),
            feature_policy=hmap.get("permissions-policy"),  # Note: Feature-Policy is now Permissions-Policy
            expect_ct=hmap.get("expect-ct"),
            x_permitted_cross_domain=hmap.get("x-permitted-cross-domain"),
            via=hmap.get("via"),
            cf_ray=hmap.get("cf-ray"),
            x_cdn=hmap.get("x-cdn"),
            error=None,
        )
    except requests.exceptions.SSLError as e:
        return HTTPProbe(None, None, False, [], {}, None, None, None, None, None, None, None, None, error=f"SSL: {e}")
    except requests.exceptions.RequestException as e:
        return HTTPProbe(None, None, False, [], {}, None, None, None, None, None, None, None, None, error=str(e))


def enumerate_subdomains(apex: str) -> list[dict[str, Any]]:
    """Resuelve A para prefijos comunes; solo DNS, sin HTTP."""
    hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pre in SUBDOMAIN_PREFIXES:
        host = f"{pre}.{apex}"
        if host in seen:
            continue
        seen.add(host)
        try:
            ips = [str(r) for r in dns.resolver.resolve(host, "A", lifetime=4)]
            if ips:
                hits.append({"host": host, "ipv4": ips})
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            continue
    return hits


def query_crtsh(domain: str) -> set[str]:
    """Consulta crt.sh (Certificate Transparency) para subdominios pasivos."""
    subs: set[str] = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        if r.status_code == 200:
            for entry in r.json():
                nv = entry.get("name_value", "")
                for name in nv.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(f".{domain}") and name.count(".") >= 2:
                        subs.add(name)
    except Exception:
        pass
    return subs


def query_hackertarget(domain: str) -> set[str]:
    """Consulta Hackertarget API para subdominios pasivos."""
    subs: set[str] = set()
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        if r.status_code == 200:
            for line in r.text.strip().split("\n"):
                if "," in line:
                    host = line.split(",")[0].strip().lower()
                    if host.endswith(f".{domain}"):
                        subs.add(host)
    except Exception:
        pass
    return subs


def query_rapiddns(domain: str) -> set[str]:
    """Consulta Rapiddns.io para subdominios pasivos (scrape HTML)."""
    subs: set[str] = set()
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        if r.status_code == 200:
            found = re.findall(r"([\w.-]+\." + re.escape(domain) + ")", r.text)
            for host in found:
                host = host.strip().lower()
                if host.endswith(f".{domain}"):
                    subs.add(host)
    except Exception:
        pass
    return subs


MULTI_TLD = frozenset({
    "com.ar", "com.au", "com.br", "com.co", "com.mx", "com.pe", "com.ua",
    "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "or.jp", "ne.jp",
    "org.uk", "org.au", "org.br", "org.mx", "net.au", "net.uk",
    "ac.uk", "gov.uk", "edu.au", "gov.au",
})


def derive_apex(domain: str) -> str:
    """Deriva el dominio apex de un subdominio (ej. www.example.com -> example.com)."""
    parts = domain.strip().lower().rstrip(".").split(".")
    if len(parts) < 3:
        return domain
    # Si los últimos 2 segmentos son multi-TLD conocido, apex = últimos 3
    two_tld = ".".join(parts[-2:])
    if len(parts) > 3 and two_tld in MULTI_TLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def query_bufferover(domain: str) -> set[str]:
    """Consulta Bufferover.run para subdominios pasivos."""
    subs: set[str] = set()
    try:
        r = requests.get(
            f"https://dns.bufferover.run/dns?q=.{domain}",
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if r.status_code == 200:
            data = r.json()
            # Bufferover returns FDNS_A and FDNS_CNAME arrays
            for record in data.get("FDNS_A", []) + data.get("FDNS_CNAME", []):
                # record format: "host,domain" or just "domain" for CNAME?
                parts = record.split(",")
                if len(parts) == 2:
                    host = parts[0].strip()
                    if host.endswith("." + domain):
                        subs.add(host)
                elif len(parts) == 1:
                    # Sometimes it's just the domain? We'll skip if not a subdomain
                    host = parts[0].strip()
                    if host != domain and host.endswith("." + domain):
                        subs.add(host)
    except Exception as e:
        # Silently fail, just return empty set
        pass
    return subs


def query_threatcrowd(domain: str) -> set[str]:
    """Consulta ThreatCrowd para subdominios pasivos (API v2)."""
    subs: set[str] = set()
    try:
        r = requests.get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("response_code") == "1":  # Success
                for sub in data.get("subdomains", []):
                    if sub.endswith("." + domain):
                        subs.add(sub)
    except Exception as e:
        pass
    return subs
def query_passive_subdomains(domain: str) -> list[str]:
    """Agrega subdominios de múltiples fuentes OSINT pasivas.
    Consulta tanto el dominio dado como su apex para maximizar cobertura."""
    all_subs: set[str] = set()
    apex = derive_apex(domain)
    targets = {domain}
    if apex != domain:
        targets.add(apex)
    for target in targets:
        for fn in (query_crtsh, query_hackertarget, query_rapiddns, query_bufferover, query_threatcrowd):
            try:
                result = fn(target)
                if result:
                    all_subs.update(result)
            except Exception:
                pass
    return sorted(all_subs)


def query_caa(domain: str) -> list[dict[str, str]]:
    """Consulta registro CAA (autorización emisión certificados)."""
    records: list[dict[str, str]] = []
    try:
        for r in dns.resolver.resolve(domain, "CAA", lifetime=8):
            tag = getattr(r, "tag", "")
            val = getattr(r, "value", "")
            flags = getattr(r, "flags", 0)
            records.append({"tag": str(tag), "value": str(val), "flags": str(flags)})
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception:
        pass
    return records


def query_dns_txt(name: str) -> str | None:
    """Consulta un registro TXT DNS."""
    try:
        for r in dns.resolver.resolve(name, "TXT", lifetime=8):
            txt = b"".join(r.strings).decode("utf-8", errors="replace")
            if txt.strip():
                return txt.strip()
    except Exception:
        return None
    return None


def query_mta_sts(domain: str) -> str | None:
    """Consulta registro MTA-STS (_mta-sts.{domain} TXT)."""
    return query_dns_txt(f"_mta-sts.{domain}")


def query_tls_rpt(domain: str) -> str | None:
    """Consulta registro TLS-RPT (_smtp._tls.{domain} TXT)."""
    return query_dns_txt(f"_smtp._tls.{domain}")


def query_bimi(domain: str) -> str | None:
    """Consulta registro BIMI (default._bimi.{domain} TXT)."""
    return query_dns_txt(f"default._bimi.{domain}")


def query_dnssec(domain: str) -> bool:
    """Verifica si el dominio tiene DNSSEC mediante consulta DNSKEY."""
    try:
        for _ in dns.resolver.resolve(domain, "DNSKEY", lifetime=8):
            return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception:
        pass
    return False


def query_dkim(domain: str) -> list[dict[str, str]]:
    """Consulta registros DKIM para selectores comunes."""
    selectors = ("default", "google", "selector1", "selector2", "dkim", "mail", "smtp", "20200101", "20230601")
    results: list[dict[str, str]] = []
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        try:
            for r in dns.resolver.resolve(name, "TXT", lifetime=8):
                txt = b"".join(r.strings).decode("utf-8", errors="replace")
                if txt.strip().lower().startswith("v=dkim1"):
                    results.append({"selector": sel, "record": txt[:500]})
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            pass
    return results


def query_dane(domain: str) -> list[dict[str, str]]:
    """Consulta registros DANE/TLSA (SMTP y HTTPS)."""
    results: list[dict[str, str]] = []
    for port, proto in [("25", "tcp"), ("443", "tcp")]:
        name = f"_{port}._{proto}.{domain}"
        try:
            for r in dns.resolver.resolve(name, "TLSA", lifetime=8):
                usage = getattr(r, "usage", 0)
                selector = getattr(r, "selector", 0)
                mtype = getattr(r, "mtype", 0)
                cert_data = getattr(r, "cert", b"")
                results.append({
                    "port": port,
                    "protocol": proto,
                    "usage": str(usage),
                    "selector": str(selector),
                    "mtype": str(mtype),
                    "cert_association": cert_data.hex()[:80] if isinstance(cert_data, bytes) else str(cert_data)[:80],
                })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            pass
    return results


DNSBLS = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "cbl.abuseat.org",
]


def check_ip_reputation(ips: list[str]) -> list[dict[str, str]]:
    """Consulta DNSBL para cada IP. Retorna lista de listings encontrados."""
    listings: list[dict[str, str]] = []
    for ip in ips:
        reversed_parts = ip.strip().split(".")
        if len(reversed_parts) != 4:
            continue
        lookup = ".".join(reversed(reversed_parts))
        for dnsbl in DNSBLS:
            try:
                for _ in dns.resolver.resolve(f"{lookup}.{dnsbl}", "A", lifetime=5):
                    listings.append({"ip": ip, "dnsbl": dnsbl})
                    break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception:
                pass
    return listings


def check_starttls(mx_records: list[dict[str, str]], timeout: int = 5) -> list[dict[str, Any]]:
    """Conecta a cada servidor MX en puerto 25, envía EHLO y verifica si STARTTLS está anunciado."""
    results: list[dict[str, Any]] = []
    for mx in mx_records:
        exchange = mx.get("exchange", "")
        if not exchange:
            continue
        result: dict[str, Any] = {"exchange": exchange, "preference": mx.get("preference", "")}
        try:
            sock = socket.create_connection((exchange, 25), timeout=timeout)
            sock.settimeout(timeout)
            buf = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in chunk:
                    break
            sock.sendall(b"EHLO asm-check.local\r\n")
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                except socket.timeout:
                    break
            sock.sendall(b"QUIT\r\n")
            sock.close()
            text = buf.decode("utf-8", errors="replace")
            result["starttls"] = "STARTTLS" in text.upper()
        except Exception as e:
            result["error"] = str(e)[:200]
            result["starttls"] = False
        results.append(result)
    return results


URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"


def check_urlhaus(domain: str) -> dict[str, Any]:
    """Consulta URLhaus para ver si el dominio está reportado como malicioso."""
    try:
        r = requests.post(URLHAUS_API, data={"host": domain}, timeout=15)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        data = r.json()
        if data.get("query_status") == "ok":
            urls = data.get("urls", [])
            return {
                "malicious": True,
                "url_count": len(urls),
                "first_seen": urls[0].get("date_added") if urls else None,
                "last_seen": urls[-1].get("url_last_seen") if urls else None,
                "urls": [u.get("url") for u in urls[:5]],
            }
        return {"malicious": False, "url_count": 0}
    except requests.RequestException as e:
        return {"error": str(e)}


OSV_API = "https://api.osv.dev/v1/query"
SERVER_TECH_MAP: dict[str, str] = {
    "nginx": "nginx",
    "apache": "apache http server",
    "cloudflare": "cloudflare",
    "openresty": "openresty",
    "iis": "microsoft iis",
    "caddy": "caddy",
    "lighttpd": "lighttpd",
    "tomcat": "apache tomcat",
    "jetty": "eclipse jetty",
    "node.js": "node.js",
    "express": "express",
    "python/": "python",
    "gunicorn": "gunicorn",
    "uvicorn": "uvicorn",
    "werkzeug": "werkzeug",
    "php/": "php",
    "ruby": "ruby",
    "rails": "ruby on rails",
    "java": "java",
    "cowboy": "cowboy",
}
XPB_TECH_MAP: dict[str, str] = {
    "asp.net": "asp.net",
    "php": "php",
    "uber": "uber",
    "express": "express",
    "nginx": "nginx",
    "apache": "apache http server",
}


def extract_technologies(headers: dict[str, str]) -> list[dict[str, str]]:
    """Extrae tecnologías y versiones desde cabeceras HTTP."""
    techs: list[dict[str, str]] = []
    server = (headers.get("server") or "").strip()
    if server:
        srv_lower = server.lower()
        for prefix, name in SERVER_TECH_MAP.items():
            if prefix in srv_lower:
                ver = ""
                import re as _re
                m = _re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", server)
                if m:
                    ver = m.group()
                techs.append({"source": "Server", "name": name, "version": ver, "raw": server[:80]})
                break
        else:
            techs.append({"source": "Server", "name": server.split("/")[0], "version": "", "raw": server[:80]})
    xpb = (headers.get("x-powered-by") or "").strip()
    if xpb:
        xpb_lower = xpb.lower()
        for prefix, name in XPB_TECH_MAP.items():
            if prefix in xpb_lower:
                ver = ""
                import re as _re
                m = _re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", xpb)
                if m:
                    ver = m.group()
                techs.append({"source": "X-Powered-By", "name": name, "version": ver, "raw": xpb[:80]})
                break
        else:
            techs.append({"source": "X-Powered-By", "name": xpb.split("/")[0], "version": "", "raw": xpb[:80]})
    return techs


def query_osv(techs: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Consulta OSV.dev para cada tecnología detectada y retlista de CVEs."""
    vulns: list[dict[str, Any]] = []
    seen: set[str] = set()
    for t in techs:
        pkg_name = t["name"]
        pkg_version = t.get("version", "")
        body = {"package": {"name": pkg_name, "ecosystem": "General"}, "version": pkg_version} if pkg_version else {"package": {"name": pkg_name, "ecosystem": "General"}}
        try:
            r = requests.post(OSV_API, json=body, timeout=10)
            if r.status_code != 200:
                continue
            data = r.json()
            for vuln in data.get("vulns", []):
                cve_id = vuln.get("id", "")
                if cve_id in seen:
                    continue
                seen.add(cve_id)
                aliases = vuln.get("aliases", [])
                vulns.append({
                    "cve_id": cve_id,
                    "aliases": aliases,
                    "summary": (vuln.get("summary") or "")[:200],
                    "severity": "",
                    "package": pkg_name,
                    "detected_version": pkg_version,
                })
                if len(vulns) >= 20:
                    return vulns
        except requests.RequestException:
            pass
    return vulns


LEAK_API_URL = "https://leak-lookup.com/api/search"
_CONFIG_FILE = ROOT / "integrations_config.json"


def _get_api_key(key_id: str) -> str:
    env_val = os.environ.get(key_id, "")
    if env_val:
        return env_val
    try:
        cfg = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
        for integ in cfg.get("integrations", []):
            if integ.get("key_id") == key_id:
                return integ.get("_key", "")
    except Exception:
        pass
    return ""


LEAK_API_KEY = _get_api_key("LEAK_API_KEY")


def check_credential_leaks(domain: str) -> list[dict[str, Any]]:
    """Consulta leak-lookup.com para filtrar el dominio en breaches conocidos."""
    if not LEAK_API_KEY:
        return [{"error": "LEAK_API_KEY no configurada"}]
    try:
        r = requests.get(LEAK_API_URL, params={"key": LEAK_API_KEY, "type": "domain", "query": domain}, timeout=15)
        if r.status_code != 200:
            return [{"error": f"HTTP {r.status_code}"}]
        data = r.json()
        if data.get("error") == "false":
            results = data.get("data") or {}
            breaches = []
            for breach_name, rows in results.items():
                breaches.append({"breach": breach_name, "records": len(rows) if isinstance(rows, list) else 0})
            return breaches
        return []
    except requests.RequestException as e:
        return [{"error": str(e)}]


def _domain_variations(domain: str) -> set[str]:
    """Genera variantes de typosquatting para un dominio."""
    variants: set[str] = set()
    domain = domain.strip().lower()
    parts = domain.split(".")
    if len(parts) < 2:
        return variants
    # Si el primer componente es www, usar el SLD como nombre
    if parts[0] == "www" and len(parts) > 2:
        name = parts[1]
        tld = ".".join(parts[2:])
    else:
        name = parts[0]
        tld = ".".join(parts[1:])
    # Cambiar TLD
    for alt_tld in ("com", "net", "org", "co", "io", "app", "dev", "info", "biz", "online"):
        if alt_tld != tld:
            variants.add(f"{name}.{alt_tld}")
    # Duplicar letras
    for i in range(len(name)):
        variants.add(f"{name[:i]}{name[i]}{name[i:]}.{tld}")
    # Omitir letras
    for i in range(len(name)):
        variants.add(f"{name[:i]}{name[i+1:]}.{tld}")
    # Teclas adyacentes
    adjacent = {
        "a": "sq", "b": "nvg", "c": "xdfv", "d": "sfre", "e": "wrsd",
        "f": "dcv", "g": "fvbh", "h": "gbnj", "i": "uokj", "j": "hnmk",
        "k": "jiml", "l": "kop", "m": "nk", "n": "bmh", "o": "ipkl",
        "p": "ol", "q": "wa", "r": "etdf", "s": "awed", "t": "ryfg",
        "u": "yihj", "v": "cfgb", "w": "qesa", "x": "zdc", "y": "tugh",
        "z": "ax",
    }
    for i, ch in enumerate(name):
        for replacement in adjacent.get(ch, ""):
            variants.add(f"{name[:i]}{replacement}{name[i+1:]}.{tld}")
    # Singular/plural
    if name.endswith("s"):
        variants.add(f"{name[:-1]}.{tld}")
    else:
        variants.add(f"{name}s.{tld}")
    # Prefijos comunes
    for prefix in ("my-", "my", "www-", "secure-", "login-", "app-", "m."):
        variants.add(f"{prefix}{name}.{tld}")
    return variants


def check_typosquatting(domain: str) -> list[dict[str, Any]]:
    """Genera variantes de typosquatting y verifica si resuelven en DNS."""
    findings: list[dict[str, Any]] = []
    for variant in _domain_variations(domain):
        if len(variant) > 100:
            continue
        try:
            ips: list[str] = []
            for r in dns.resolver.resolve(variant, "A", lifetime=4):
                ips.append(str(r))
            if ips:
                findings.append({"domain": variant, "ips": ips})
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass
        if len(findings) >= 15:
            break
    return findings


EOL_API = "https://endoflife.date/api/{product}.json"
PATCH_CACHE: dict[str, list[dict[str, Any]]] = {}


def check_patching_cadence(techs: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Consulta endoflife.date para cada tecnología y determina si la versión está EOL/antigua."""
    results: list[dict[str, Any]] = []
    for t in techs:
        name = t["name"]
        version = t.get("version", "")
        eol_name = name.replace(" ", "-").lower()
        # Mapear nombres comunes
        alias_map = {
            "cloudflare": "cloudflare",
            "nginx": "nginx",
            "apache http server": "apache",
            "microsoft iis": "iis",
            "openresty": "openresty",
            "caddy": "caddy",
            "lighttpd": "lighttpd",
            "node.js": "nodejs",
            "python": "python",
            "php": "php",
            "ruby": "ruby",
            "java": "java",
            "asp.net": "dotnet",
        }
        eol_name = alias_map.get(name, eol_name)
        if eol_name not in PATCH_CACHE:
            try:
                r = requests.get(EOL_API.format(product=eol_name), timeout=10)
                if r.status_code == 200:
                    PATCH_CACHE[eol_name] = r.json()
                else:
                    PATCH_CACHE[eol_name] = []
            except requests.RequestException:
                PATCH_CACHE[eol_name] = []
        cycles = PATCH_CACHE[eol_name]
        if not cycles:
            continue
        if not version:
            # Sin versión específica, marcar como "versión no detectable"
            results.append({"technology": name, "version": "", "status": "unknown", "detail": "Versión no detectable desde cabeceras"})
            continue
        found = False
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        for cycle in cycles:
            cycle_version = str(cycle.get("cycle", ""))
            if version.startswith(cycle_version) or cycle_version.startswith(version):
                eol_date_str = cycle.get("eol", "")
                if eol_date_str and eol_date_str != "false":
                    try:
                        eol_date = datetime.fromisoformat(eol_date_str.replace("Z", "+00:00"))
                        if eol_date.tzinfo is None:
                            eol_date = eol_date.replace(tzinfo=timezone.utc)
                        if now > eol_date:
                            results.append({"technology": name, "version": version, "status": "eol", "detail": f"EOL desde {eol_date.strftime('%Y-%m-%d')}"})
                        else:
                            days_left = (eol_date - now).days
                            if days_left < 365:
                                results.append({"technology": name, "version": version, "status": "ending", "detail": f"Soporte hasta {eol_date.strftime('%Y-%m-%d')} ({days_left} días)"})
                            else:
                                results.append({"technology": name, "version": version, "status": "current", "detail": f"Soportada hasta {eol_date.strftime('%Y-%m-%d')}"})
                    except (ValueError, TypeError):
                        results.append({"technology": name, "version": version, "status": "unknown", "detail": "Fecha EOL no parseable"})
                else:
                    results.append({"technology": name, "version": version, "status": "current", "detail": "Sin fecha EOL definida (aún con soporte activo)"})
                found = True
                break
        if not found:
            results.append({"technology": name, "version": version, "status": "unknown", "detail": "Versión no encontrada en ciclos EOL"})
    return results


def extract_san(cert: dict[str, Any] | None) -> list[str]:
    """Extrae Subject Alternative Names del certificado TLS."""
    sans: list[str] = []
    if cert:
        san_tuple = cert.get("subjectAltName", ())
        for entry in san_tuple:
            if isinstance(entry, tuple) and len(entry) == 2 and entry[0] == "DNS":
                sans.append(entry[1].lower())
    return sorted(set(sans))


def probe_public_paths(domain: str, sess: requests.Session) -> list[dict[str, Any]]:
    """HEAD a rutas típicas en el apex HTTPS (certificado verificado)."""
    out: list[dict[str, Any]] = []
    for path in PUBLIC_PATHS:
        url = f"https://{domain}{path}"
        try:
            r = sess.head(url, timeout=8, allow_redirects=True, verify=True)
            out.append(
                {
                    "path": path,
                    "url": str(r.url),
                    "status_code": r.status_code,
                    "method": "HEAD",
                }
            )
        except requests.exceptions.SSLError as e:
            out.append({"path": path, "url": url, "status_code": None, "method": "HEAD", "error": f"SSL: {e}"[:200]})
        except requests.exceptions.RequestException as e:
            out.append({"path": path, "url": url, "status_code": None, "method": "HEAD", "error": str(e)[:200]})
    return out


def _extract_csp_domains(headers: dict[str, str]) -> set[str]:
    """Extrae dominios de terceros desde CSP header."""
    domains: set[str] = set()
    csp = (headers.get("content-security-policy") or headers.get("content-security-policy-report-only") or "")
    if not csp:
        return domains
    known_self = {"self", "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "blob:", "data:", "mediastream:", "filesystem:", "http:", "https:", "*"}
    for val in csp.split(";"):
        directive = val.strip()
        for part in directive.split():
            part = part.strip().rstrip(";")
            if not part or part in known_self:
                continue
            if part.startswith("'") or part.startswith("http://") or part.startswith("https://"):
                from urllib.parse import urlparse
                parsed = urlparse(part)
                host = parsed.hostname
                if host:
                    domains.add(host.lower())
            elif "." in part and not part.startswith("sha") and not part.startswith("nonce"):
                domains.add(part.lower())
    return domains


def check_supply_chain(domain: str, headers: dict[str, str], sess: requests.Session) -> list[dict[str, Any]]:
    """Analiza dependencias de terceros desde CSP y HTML."""
    seen: set[str] = set()
    results: list[dict[str, Any]] = []

    # De CSP
    for dep in sorted(_extract_csp_domains(headers)):
        if dep in seen or dep.endswith(domain):
            continue
        seen.add(dep)
        entry: dict[str, Any] = {"domain": dep, "source": "CSP", "resolves": False, "ips": []}
        try:
            for r in dns.resolver.resolve(dep, "A", lifetime=4):
                entry["ips"].append(str(r))
            if entry["ips"]:
                entry["resolves"] = True
        except Exception:
            pass
        results.append(entry)
        if len(results) >= 15:
            break

    # Fetch HTML para extraer scripts externos
    if len(results) < 15:
        try:
            for scheme in ("https://", "http://"):
                r = sess.get(f"{scheme}{domain}", timeout=10)
                if r.status_code < 400:
                    break
            if r and r.status_code < 400:
                import re as _re
                for src in _re.findall(r'<script[^>]+src=["\'](https?://[^"\']+)["\']', r.text):
                    from urllib.parse import urlparse
                    parsed = urlparse(src)
                    host = parsed.hostname
                    if host and host not in seen and not host.endswith(domain):
                        seen.add(host)
                        entry = {"domain": host, "source": "script_src", "resolves": False, "ips": []}
                        try:
                            for r2 in dns.resolver.resolve(host, "A", lifetime=4):
                                entry["ips"].append(str(r2))
                            if entry["ips"]:
                                entry["resolves"] = True
                        except Exception:
                            pass
                        results.append(entry)
                        if len(results) >= 15:
                            break
        except Exception:
            pass

    return results


def check_supply_reputation(supply: list[dict[str, Any]]) -> dict[str, Any]:
    """Verifica reputacion DNSBL/URLhaus de dominios e IPs de la cadena de suministro."""
    from itertools import chain as _chain
    dnsbl_hits: list[dict[str, Any]] = []
    urlhaus_hits: list[dict[str, Any]] = []
    all_ips: list[str] = list(dict.fromkeys(_chain.from_iterable(s.get("ips", []) for s in supply)))
    seen_domains: set[str] = set()
    if all_ips:
        dnsbl_hits = check_ip_reputation(all_ips)
    for s in supply:
        dom = s.get("domain", "")
        if dom and dom not in seen_domains:
            seen_domains.add(dom)
            uh = check_urlhaus(dom)
            if uh.get("malicious"):
                urlhaus_hits.append({"domain": dom, "url_count": uh.get("url_count", 0)})
    return {"dnsbl": dnsbl_hits, "urlhaus": urlhaus_hits, "dnsbl_count": len(dnsbl_hits), "urlhaus_count": len(urlhaus_hits), "clean": len(dnsbl_hits) == 0 and len(urlhaus_hits) == 0}


TAKEOVER_FINGERPRINTS: dict[str, str] = {
    "s3.amazonaws.com": "Amazon S3 bucket no configurado",
    "cloudfront.net": "CloudFront distribution no configurada",
    "github.io": "GitHub Pages no configurado",
    "herokuapp.com": "Heroku app no configurado",
    "herokudns.com": "Heroku DNS no configurado",
    "azurewebsites.net": "Azure Web App no configurado",
    "trafficmanager.net": "Azure Traffic Manager no configurado",
    "azureedge.net": "Azure CDN no configurado",
    "azurefd.net": "Azure Front Door no configurado",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk no configurado",
    "awsglobalaccelerator.com": "AWS Global Accelerator no configurado",
    "firebaseio.com": "Firebase no configurado",
    "appspot.com": "Google App Engine no configurado",
    "pantheon.io": "Pantheon no configurado",
    "pantheonsite.io": "Pantheon no configurado",
    "surge.sh": "Surge.sh no configurado",
    "bitbucket.io": "Bitbucket Pages no configurado",
    "readthedocs.io": "Read the Docs no configurado",
    "helpshift.com": "Helpshift no configurado",
    "zendesk.com": "Zendesk no configurado",
    "freshdesk.com": "Freshdesk no configurado",
    "unbounce.com": "Unbounce no configurado",
    "strikingly.com": "Strikingly no configurado",
    "wordpress.com": "WordPress.com no configurado",
    "squarespace.com": "Squarespace no configurado",
    "wixsite.com": "Wix no configurado",
    "ghost.io": "Ghost.io no configurado",
    "tumblr.com": "Tumblr no configurado",
    "shopify.com": "Shopify no configurado",
    "myshopify.com": "Shopify no configurado",
    "bigcartel.com": "Big Cartel no configurado",
    "statuspage.io": "Statuspage no configurado",
    "atlassian.net": "Atlassian no configurado",
    "fastly.net": "Fastly no configurado",
    "pages.dev": "Cloudflare Pages no configurado",
    "fly.dev": "Fly.io no configurado",
    "netlify.app": "Netlify no configurado",
    "vercel.app": "Vercel no configurado",
    "render.com": "Render no configurado",
    "onrender.com": "Render no configurado",
    "duckdns.org": "DuckDNS no configurado",
}


def check_subdomain_takeover(apex: str, resolved_subdomains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Verifica CNAME de cada prefijo de subdominio contra servicios externos no configurados."""
    risks: list[dict[str, Any]] = []
    checked: set[str] = set()

    candidates: set[str] = set()
    for pre in SUBDOMAIN_PREFIXES:
        candidates.add(f"{pre}.{apex}")
    for s in resolved_subdomains:
        host = s.get("host", "")
        if host:
            candidates.add(host)

    for host in sorted(candidates):
        if host in checked:
            continue
        checked.add(host)

        cname_target: str | None = None
        try:
            for r in dns.resolver.resolve(host, "CNAME", lifetime=4):
                cname_target = str(r.target).rstrip(".")
                break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except Exception:
            continue

        if not cname_target:
            continue

        target_resolves = False
        try:
            for _ in dns.resolver.resolve(cname_target, "A", lifetime=4):
                target_resolves = True
                break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            target_resolves = False
        except Exception:
            pass

        matched = None
        for pattern, desc in TAKEOVER_FINGERPRINTS.items():
            if pattern in cname_target.lower():
                matched = {"pattern": pattern, "description": desc}
                break

        if not target_resolves or matched:
            risks.append({
                "host": host,
                "cname": cname_target,
                "vulnerable": not target_resolves,
                "service": matched["pattern"] if matched else None,
                "description": matched["description"] if matched else "CNAME no resuelve (potencial takeover)",
            })

    return risks


CSP_BYPASS_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"ajax\.googleapis\.com", "desc": "CDN allowlist (Google AJAX) permite JSONP bypass"},
    {"pattern": r"cdnjs\.cloudflare\.com", "desc": "CDN allowlist (cdnjs) permite JSONP bypass"},
    {"pattern": r"jsdelivr\.net", "desc": "CDN allowlist (jsDelivr) permite JSONP bypass"},
    {"pattern": r"code\.jquery\.com", "desc": "CDN allowlist (jQuery CDN) permite JSONP bypass"},
    {"pattern": r"maxcdn\.bootstrapcdn\.com", "desc": "CDN allowlist (Bootstrap CDN) permite JSONP bypass"},
    {"pattern": r"storage\.googleapis\.com", "desc": "Google Storage allowlist permite JSONP bypass"},
    {"pattern": r"fonts\.googleapis\.com", "desc": "Google Fonts allowlist permite JSONP bypass"},
]


def check_csp_security(csp_header: str | None) -> list[dict[str, Any]]:
    """Analiza CSP en busca de directivas débiles, bypasses conocidos y faltantes."""
    findings: list[dict[str, Any]] = []
    if not csp_header:
        return findings

    directives: dict[str, list[str]] = {}
    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            dir_name = tokens[0].lower()
            dir_vals = tokens[1:]
            if dir_name not in directives:
                directives[dir_name] = []
            directives[dir_name].extend(dir_vals)

    # Check missing important directives
    important = ["base-uri", "object-src", "frame-ancestors", "form-action"]
    for d in important:
        if d not in directives:
            findings.append({
                "type": "missing_directive",
                "severity": "high" if d in ("base-uri", "object-src") else "medium",
                "directive": d,
                "description": f"Falta directiva {d}, lo que permite vectores de bypass (inyección de scripts, clickjacking, exfiltración).",
                "recommendation": f"Agregue la directiva {d} con valores restrictivos a su CSP.",
            })

    # Check weak directives
    for dir_name, dir_vals in directives.items():
        vals_joined = " ".join(dir_vals)
        if "'unsafe-inline'" in vals_joined:
            findings.append({
                "type": "weak_directive",
                "severity": "high",
                "directive": dir_name,
                "description": f"'{dir_name}' permite estilos/scripts inline ('unsafe-inline'), facilitando XSS.",
                "recommendation": "Elimine 'unsafe-inline' y use nonces o hashes en su lugar.",
            })
        if "'unsafe-eval'" in vals_joined:
            findings.append({
                "type": "weak_directive",
                "severity": "medium",
                "directive": dir_name,
                "description": f"'{dir_name}' permite eval() ('unsafe-eval'), exponiendo a ataques de inyección.",
                "recommendation": "Elimine 'unsafe-eval' a menos que sea estrictamente necesario.",
            })
        if "*" in vals_joined:
            findings.append({
                "type": "wildcard",
                "severity": "high",
                "directive": dir_name,
                "description": f"'{dir_name}' usa comodín (*), permitiendo cualquier origen.",
                "recommendation": "Reemplace el comodín (*) con una lista blanca de orígenes específicos.",
            })
        if dir_name in ("script-src", "default-src") and not dir_vals:
            findings.append({
                "type": "empty_directive",
                "severity": "high",
                "directive": dir_name,
                "description": f"'{dir_name}' está vacía, lo que desactiva efectivamente la protección.",
                "recommendation": f"Defina valores explícitos para {dir_name}.",
            })

    # Check known bypass patterns (CDN allowlists)
    if "script-src" in directives or "default-src" in directives:
        import re as _re
        check_sources = directives.get("script-src", []) + directives.get("default-src", [])
        for pat in CSP_BYPASS_PATTERNS:
            for src in check_sources:
                if _re.search(pat["pattern"], src.lower()):
                    findings.append({
                        "type": "cdn_bypass",
                        "severity": "high",
                        "directive": "script-src",
                        "description": f"CDN allowlist detectado ({src}): {pat['desc']}.",
                        "recommendation": "Elimine orígenes CDN que permitan JSONP de script-src y use nonces/hashes.",
                    })
                    break

    # Check for report-uri or report-to
    has_report = any(d in directives for d in ("report-uri", "report-to"))
    if not has_report:
        findings.append({
            "type": "missing_reporting",
            "severity": "low",
            "directive": "report-uri/report-to",
            "description": "CSP no configura report-uri ni report-to; las violaciones no serán reportadas.",
            "recommendation": "Configure report-uri o report-to para recibir informes de violaciones CSP.",
        })

    return findings


def check_cookie_security(set_cookie_header: str | None) -> list[dict[str, Any]]:
    """Analiza cabeceras Set-Cookie en busca de flags de seguridad faltantes."""
    findings: list[dict[str, Any]] = []
    if not set_cookie_header:
        return findings

    # Set-Cookie puede tener múltiples cookies separadas por pipe (unidas arriba) o venir en múltiples cabeceras
    cookie_strs = [c.strip() for c in set_cookie_header.replace(" | ", "\n").split("\n") if c.strip()]

    for raw in cookie_strs:
        # Parse first semicolon-separated part as name=value
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        cookie_name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0]
        attrs_lower = " ".join(p.lower() for p in parts[1:])

        cookie_finding: dict[str, Any] = {
            "cookie": cookie_name[:100],
            "secure": "secure" in attrs_lower,
            "httponly": "httponly" in attrs_lower,
        }

        if not cookie_finding["secure"]:
            findings.append({
                "type": "missing_secure",
                "severity": "high",
                "cookie": cookie_name[:100],
                "description": f"Cookie '{cookie_name[:50]}' sin flag Secure: se transmite en texto plano si hay HTTP.",
                "recommendation": "Agregue el flag Secure a la cookie.",
            })
        if not cookie_finding["httponly"]:
            findings.append({
                "type": "missing_httponly",
                "severity": "high",
                "cookie": cookie_name[:100],
                "description": f"Cookie '{cookie_name[:50]}' sin flag HttpOnly: accesible desde JavaScript (XSS).",
                "recommendation": "Agregue el flag HttpOnly a la cookie si no necesita acceso desde JS.",
            })

        # Check SameSite
        samesite = None
        for attr in parts[1:]:
            a = attr.strip().lower()
            if a.startswith("samesite="):
                samesite = a.split("=", 1)[1]
            elif a == "samesite":
                samesite = "true"
        cookie_finding["samesite"] = samesite
        if samesite is None:
            findings.append({
                "type": "missing_samesite",
                "severity": "medium",
                "cookie": cookie_name[:100],
                "description": f"Cookie '{cookie_name[:50]}' sin flag SameSite: vulnerable a CSRF en navegadores antiguos.",
                "recommendation": "Agregue SameSite=Lax o SameSite=Strict a la cookie.",
            })
        elif samesite.lower() == "none":
            findings.append({
                "type": "samesite_none",
                "severity": "low",
                "cookie": cookie_name[:100],
                "description": f"Cookie '{cookie_name[:50]}' con SameSite=None: permitida en contexto跨sitio. Asegúrese de que Secure también esté presente.",
                "recommendation": "Considere usar SameSite=Lax a menos que necesite cross-site.",
            })

        # Check if Domain is set (too broad)
        for attr in parts[1:]:
            a = attr.strip().lower()
            if a.startswith("domain="):
                cookie_finding["domain"] = a.split("=", 1)[1]
                break

    return findings


def dataclass_to_dict(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return {k: dataclass_to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [dataclass_to_dict(x) for x in obj]
    return obj


def build_matrix_row(p: ProviderASM) -> dict[str, Any]:
    h = p.https.headers
    https_cell = p.https.status_code if p.https.final_url else p.https.error or "—"
    spf = "ok" if p.dns.spf_record and "-all" in p.dns.spf_record.replace(" ", "").lower() else (
        "partial" if p.dns.spf_record else "missing"
    )
    m = {
        "proveedor": p.name,
        "dominio": p.domain,
        "subdominios": len(p.subdomains),
        "https": https_cell,
        "hsts": bool(h.get("strict-transport-security")),
        "csp": bool(h.get("content-security-policy") or h.get("content-security-policy-report-only")),
        "spf_dmarc": f"SPF:{spf} DMARC:{p.dns.dmarc_policy or '-'}",
        "tls13_negociado": p.tls.tls13_only_ok,
        "tls_version": p.tls.negotiated_version,
        "puertos": f"80:{'open' if p.port_80.open else 'closed'} 443:{'open' if p.port_443.open else 'closed'}",
        "huella": p.https.server_fingerprint or "-",
        "rutas_interesantes": sum(
            1 for x in p.public_paths if x.get("status_code") in (200, 201, 204, 301, 302, 401, 403)
        ),
        "crt_subdominios": len(p.crt_subdomains),
        "caa": bool(p.caa_records),
        "mta_sts": bool(p.mta_sts),
        "tls_rpt": bool(p.tls_rpt),
        "bimi": bool(p.bimi),
        "san_count": len(p.san_list),
        "mx_count": len(p.mx_records),
        "ns_count": len(p.ns_records),
        "dnssec_ok": p.dns.dnssec_ok,
        "dkim_count": len(p.dns.dkim_records),
        "dane_count": len(p.dns.dane_records),
        "ip_reputation_count": len(p.dns.ip_reputation),
        "ip_reputation_clean": len(p.dns.ip_reputation) == 0,
        "starttls_results": p.dns.starttls_results,
        "starttls_ok": all(s.get("starttls") for s in p.dns.starttls_results) if p.dns.starttls_results else False,
        "starttls_count": len(p.dns.starttls_results),
        "urlhaus_malicious": p.urlhaus.get("malicious", False),
        "urlhaus_count": p.urlhaus.get("url_count", 0),
        "vulnerability_count": len(p.vulnerabilities),
        "credential_leak_count": len([l for l in p.credential_leaks if "error" not in l]),
        "credential_leak_error": any("error" in l for l in p.credential_leaks),
        "typosquatting_count": len(p.typosquatting),
        "patching_eol": sum(1 for x in p.patching if x.get("status") == "eol"),
        "patching_ending": sum(1 for x in p.patching if x.get("status") == "ending"),
        "supply_chain_count": len(p.supply_chain),
        "supply_reputation_dnsbl": p.supply_chain_reputation.get("dnsbl", []),
        "supply_reputation_urlhaus": p.supply_chain_reputation.get("urlhaus", []),
        "supply_reputation_dnsbl_count": p.supply_chain_reputation.get("dnsbl_count", 0),
        "supply_reputation_urlhaus_count": p.supply_chain_reputation.get("urlhaus_count", 0),
        "supply_reputation_clean": p.supply_chain_reputation.get("clean", True),
        "takeover_count": len(p.takeover_risks),
        "takeover_vulnerable": any(r.get("vulnerable") for r in p.takeover_risks),
        "csp_findings": p.csp_findings,
        "csp_weak": bool(p.csp_findings),
        "csp_finding_count": len(p.csp_findings),
        "cookie_findings": p.cookie_findings,
        "cookie_insecure": any(f.get("severity") in ("high",) for f in p.cookie_findings),
        "cookie_count": len({f.get("cookie") for f in p.cookie_findings}) or (1 if p.cookie_findings else 0),
        "social": p.social,
        "social_str": ", ".join(f"{k}:{v.get('username','')}" for k, v in p.social.items() if not v.get("error")),
        "external": p.external,
        "external_whois_registrar": (p.external.get("whois") or {}).get("registrar"),
        "external_whois_creation": (p.external.get("whois") or {}).get("creation_date"),
        "external_whois_expiration": (p.external.get("whois") or {}).get("expiration_date"),
        "external_whois_org": (p.external.get("whois") or {}).get("registrant_organization"),
        "external_whois_country": (p.external.get("whois") or {}).get("registrant_country"),
        "external_whois_emails": (p.external.get("whois") or {}).get("emails") or [],
        "external_whois_nameservers": (p.external.get("whois") or {}).get("name_servers") or [],
        "external_dnsdumpster_hosts": (p.external.get("dnsdumpster") or {}).get("host_records") or [],
        "external_shodan_hosts": (p.external.get("shodan") or {}).get("hosts") or [],
        "external_shodan_ports": list({p2 for h in ((p.external.get("shodan") or {}).get("hosts") or []) for p2 in h.get("ports", [])}),
        "external_shodan_vulns": list({v for h in ((p.external.get("shodan") or {}).get("hosts") or []) for v in h.get("vulns", [])}),
        "external_censys_certificates": (p.external.get("censys") or {}).get("certificates") or [],
        "external_censys_hosts": (p.external.get("censys") or {}).get("hosts") or [],
        "external_theharvester_emails": (p.external.get("theharvester") or {}).get("emails") or [],
        "external_theharvester_subdomains": (p.external.get("theharvester") or {}).get("subdomains") or [],
    }
    try:
        m["owasp"] = owasp_agentic.evaluate_provider(m)
    except Exception as e:
        m["owasp"] = {"overall_compliance": 0, "overall_grade": "?", "risks": {}, "error": str(e)}
    return m


def render_html(results: list[ProviderASM], matrix: list[dict[str, Any]], generated: str) -> str:
    rows = ""
    for m in matrix:
        def yn(x: Any) -> str:
            if x is True:
                return "✓"
            if x is False:
                return "✗"
            return str(x)[:80]

        rows += f"""<tr>
<td><strong>{html.escape(str(m['proveedor']))}</strong><br><span class="muted">{html.escape(str(m['dominio']))}</span></td>
<td>{m['subdominios']}</td>
<td>{html.escape(str(m['https']))}</td>
<td>{yn(m['hsts'])}</td>
<td>{yn(m['csp'])}</td>
<td>{m['csp_finding_count']}</td>
<td>{yn(not m['cookie_insecure'])}</td>
<td>{html.escape(str(m['spf_dmarc']))}</td>
<td>{yn(m['tls13_negociado'])}</td>
<td class="muted">{html.escape(str(m['puertos']))}</td>
<td class="muted small">{html.escape(str(m['rutas_interesantes']))}</td>
<td class="muted small">{html.escape(str(m['huella']))}</td>
<td>{m['crt_subdominios']}</td>
<td>{yn(m['caa'])}</td>
<td>{yn(m['mta_sts'])}</td>
<td>{yn(m['tls_rpt'])}</td>
<td>{yn(m['starttls_ok'])}</td>
<td>{m['mx_count']}</td>
<td>{m['ns_count']}</td>
<td>{yn(m['dnssec_ok'])}</td>
<td>{m['dkim_count']}</td>
<td>{m['dane_count']}</td>
<td>{m['ip_reputation_count']}</td>
<td>{yn(m['urlhaus_malicious'])}</td>
<td>{m['vulnerability_count']}</td>
<td>{m['credential_leak_count']}</td>
<td>{m['typosquatting_count']}</td>
<td>{m['patching_eol'] + m['patching_ending']}</td>
<td>{yn(m['takeover_vulnerable'])}</td>
<td>{m['supply_chain_count']}</td>
<td>{yn(m['supply_reputation_clean'])}</td>
<td>{m.get('owasp', {}).get('overall_grade', '—')}</td>
</tr>"""

    cards = ""
    for p in results:
        hjson = json.dumps(p.https.headers, indent=2, ensure_ascii=False)
        sub_block = ""
        if p.subdomains:
            sub_block = '<p class="muted">Subdominios (DNS prefijos)</p><ul>' + "".join(
                f"<li><code>{html.escape(str(s.get('host', '')))}</code> → "
                f"{html.escape(', '.join(s.get('ipv4') or []) or str(s.get('error', '')))}</li>"
                for s in p.subdomains
            ) + "</ul>"
        crt_block = ""
        if p.crt_subdomains:
            crt_block = '<p class="muted">Subdominios (crt.sh)</p><ul>' + "".join(
                f"<li><code>{html.escape(s)}</code></li>"
                for s in p.crt_subdomains[:30]
            ) + (f"<li class='muted' style='font-size:11px'>… y {len(p.crt_subdomains) - 30} más</li>" if len(p.crt_subdomains) > 30 else "") + "</ul>"
        san_block = ""
        if p.san_list:
            san_block = '<p class="muted">SAN del certificado</p><ul>' + "".join(
                f"<li><code>{html.escape(s)}</code></li>"
                for s in p.san_list[:20]
            ) + (f"<li class='muted' style='font-size:11px'>… y {len(p.san_list) - 20} más</li>" if len(p.san_list) > 20 else "") + "</ul>"
        paths_block = ""
        if p.public_paths:
            interesting = [x for x in p.public_paths if x.get("status_code") not in (None, 404)]
            to_show = interesting if interesting else p.public_paths[:8]
            paths_block = '<p class="muted">Rutas (HEAD)</p><ul>' + "".join(
                f"<li><code>{html.escape(str(x.get('path', '')))}</code> → "
                f"{html.escape(str(x.get('status_code') if x.get('status_code') is not None else x.get('error') or '—'))}</li>"
                for x in to_show
            ) + "</ul>"

        dnssec_items = []
        if p.caa_records:
            for rec in p.caa_records:
                dnssec_items.append(f"CAA: {rec.get('tag', '?')} {rec.get('value', '?')}")
        if p.mta_sts:
            dnssec_items.append(f"MTA-STS: {html.escape(p.mta_sts[:120])}")
        if p.tls_rpt:
            dnssec_items.append(f"TLS-RPT: {html.escape(p.tls_rpt[:120])}")
        if p.bimi:
            dnssec_items.append(f"BIMI: {html.escape(p.bimi[:120])}")
        dnssec_block = ""
        if dnssec_items:
            dnssec_block = '<p class="muted">Registros DNS pasivos</p><ul>' + "".join(
                f"<li>{item}</li>" for item in dnssec_items
            ) + "</ul>"

        starttls_block = ""
        if p.dns.starttls_results:
            starttls_items = []
            for s in p.dns.starttls_results:
                status = "✓ STARTTLS" if s.get("starttls") else "✗ no STARTTLS"
                err = f" · error: {html.escape(s['error'])}" if s.get("error") else ""
                starttls_items.append(f"<code>{html.escape(s['exchange'])}</code> (pref {s['preference']}) {status}{err}")
            starttls_block = '<p class="muted">STARTTLS (puerto 25)</p><ul class="compact">' + "".join(
                f"<li>{item}</li>" for item in starttls_items
            ) + "</ul>"

        takeover_block = ""
        if p.takeover_risks:
            takeover_items = []
            for r in p.takeover_risks:
                sev = "🔴" if r.get("vulnerable") else "🟡"
                desc = html.escape(r.get("description", ""))
                takeover_items.append(
                    f"<li><code>{html.escape(r['host'])}</code> CNAME → <code>{html.escape(r['cname'])}</code> "
                    f"{sev} {desc}</li>"
                )
            takeover_block = '<p class="muted">Riesgos de Subdomain Takeover</p><ul>' + "".join(takeover_items) + "</ul>"

        csp_block = ""
        if p.csp_findings:
            csp_items = []
            for f in p.csp_findings[:8]:
                sev_map = {"high": "🔴", "medium": "🟡", "low": "⚪"}
                sev = sev_map.get(f.get("severity", ""), "⚪")
                csp_items.append(f"<li>{sev} [{f.get('severity','').upper()}] {html.escape(f.get('directive',''))}: {html.escape(f.get('description',''))}</li>")
            csp_block = '<p class="muted">Hallazgos de CSP</p><ul>' + "".join(csp_items) + "</ul>"

        cookie_block = ""
        if p.cookie_findings:
            cookie_items = []
            for f in p.cookie_findings[:8]:
                sev_map = {"high": "🔴", "medium": "🟡", "low": "⚪"}
                sev = sev_map.get(f.get("severity", ""), "⚪")
                cookie_items.append(f"<li>{sev} [{f.get('severity','').upper()}] {html.escape(f.get('description',''))}</li>")
            cookie_block = '<p class="muted">Hallazgos de Cookies</p><ul>' + "".join(cookie_items) + "</ul>"

        social_block = '<p class="muted">Redes Sociales (OSINT)</p><p class="muted">Sin datos de redes sociales configurados. Agregue social_* al providers.json.</p>'
        if p.social:
            items = []
            SOCIAL_LABELS = {"instagram": "Instagram", "tiktok": "TikTok", "twitter": "Twitter", "twitch": "Twitch", "telegram": "Telegram", "github": "GitHub"}
            SOCIAL_URLS = {"instagram": "https://www.instagram.com/", "tiktok": "https://www.tiktok.com/@", "twitter": "https://nitter.net/", "twitch": "https://www.twitch.tv/", "telegram": "https://t.me/", "github": "https://github.com/"}
            for net, data in p.social.items():
                uname = data.get("username", "")
                err = data.get("error")
                label = SOCIAL_LABELS.get(net, net)
                if err:
                    items.append(f"<li>{label}: <code>@{html.escape(uname)}</code> — error: {html.escape(str(err))}</li>")
                else:
                    url = SOCIAL_URLS.get(net, "") + uname
                    followers = data.get("followers") or data.get("seguidores") or ""
                    items.append(f"<li>{label}: <a href='{html.escape(url)}' target='_blank'>@{html.escape(uname)}</a> · {html.escape(data.get('name','') or data.get('full_name',''))} · seguidores: {html.escape(str(followers))} · posts: {html.escape(str(data.get('posts','')))} · desc: {html.escape(str(data.get('description',''))[:150])}</li>")
            social_block = '<p class="muted">Redes Sociales (OSINT)</p><ul>' + "".join(items) + "</ul>"

        supply_block = ""
        if p.supply_chain:
            supply_block = '<p class="muted">Dependencias de terceros (Supply Chain)</p><ul>' + "".join(
                f"<li><code>{html.escape(s['domain'])}</code> ({s['source']}) {'✓ resuelve' if s.get('resolves') else '✗ no resuelve'} · "
                f"{html.escape(', '.join(s.get('ips', [])[:3]) or '—')}</li>"
                for s in p.supply_chain[:10]
            ) + "</ul>"
        scr = p.supply_chain_reputation
        scr_block = ""
        scr_hits = []
        for d in scr.get("dnsbl", []):
            scr_hits.append(f"DNSBL:{d.get('ip','')} en {d.get('dnsbl','?')}")
        for u in scr.get("urlhaus", []):
            scr_hits.append(f"URLhaus:{u.get('domain','')} ({u.get('url_count',0)} urls)")
        if scr_hits:
            scr_block = '<p class="muted">Reputacion de terceros (Supply Chain)</p><ul>' + "".join(
                f"<li style=color:#f85149>⚠ {html.escape(h)}</li>" for h in scr_hits[:10]
            ) + "</ul>"

        owasp_block = '<p class="muted">OWASP Agentic Top 10</p><p class="muted">Sin evaluacion disponible.</p>'
        for m_row in matrix:
            if m_row.get("proveedor") == p.name:
                ow = m_row.get("owasp") or {}
                if ow:
                    grade = ow.get("overall_grade", "—")
                    pct = ow.get("overall_compliance", 0)
                    items = []
                    for r_id, r_data in sorted((ow.get("risks") or {}).items()):
                        if r_data.get("finding_count", 0) > 0:
                            items.append(f"<li>{r_id}: Grado {r_data['grade']} ({r_data['compliance_pct']}%) — {r_data['finding_count']} hallazgo(s)")
                    owasp_block = f'<p class="muted">OWASP Agentic Top 10 — Grado: {grade} ({pct}%)</p>'
                    if items:
                        owasp_block += '<ul class="compact">' + "".join(items) + "</ul>"
                break

        cards += f"""
<section class="card">
<h2>{html.escape(p.name)} <span class="muted">{html.escape(p.domain)}</span></h2>
<p class="muted">IPv4: {html.escape(', '.join(p.dns.ipv4) or '—')} · TLS: {html.escape(str(p.tls.negotiated_version or p.tls.error or '—'))} · Cert hasta: {html.escape(str(p.tls.cert_expiry or '—'))}</p>
{sub_block}
{crt_block}
{san_block}
{paths_block}
{dnssec_block}
{starttls_block}
{takeover_block}
{csp_block}
{cookie_block}
{social_block}
{supply_block}
{scr_block}
{owasp_block}
<p class="muted">Cabeceras HTTPS (apex /)</p>
<pre class="box">{hjson}</pre>
</section>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ASM — Proveedores Incocredito</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 24px; background: #0f1419; color: #e6edf3; }}
h1 {{ font-size: 1.25rem; font-weight: 600; }}
.muted {{ color: #8b949e; font-weight: 400; }}
.small {{ font-size: 11px; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 16px; font-size: 13px; }}
th, td {{ border-bottom: 1px solid #30363d; padding: 10px 8px; text-align: left; vertical-align: top; }}
th {{ color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; }}
tr:hover td {{ background: #161b22; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 16px 0; }}
.card h2 {{ margin: 0 0 8px; font-size: 1rem; }}
.box {{ background: #0d1117; padding: 12px; border-radius: 6px; overflow: auto; font-size: 12px; max-height: 280px; }}
</style>
</head>
<body>
<h1>ASM — proveedores (escaneo en vivo)</h1>
<p class="muted">Generado: {html.escape(generated)} (UTC). DNS SPF/DMARC, subdominios ({len(SUBDOMAIN_PREFIXES)} prefijos + crt.sh), puertos 80/443, HTTPS, cabeceras, TLS, SAN, CAA, MTA-STS, TLS-RPT, BIMI, STARTTLS.</p>
<table>
<thead><tr>
<th>Proveedor</th><th>Sub</th><th>HTTPS</th><th>HSTS</th><th>CSP</th><th>CSP-W</th><th>COOK</th><th>SPF/DMARC</th><th>TLS 1.3</th><th>Puertos</th><th>Rutas</th><th>Huella</th><th>crt.sh</th><th>CAA</th><th>MTA-STS</th><th>TLS-RPT</th><th>STARTTLS</th><th>MX</th><th>NS</th><th>DNSSEC</th><th>DKIM</th><th>DANE</th><th>DNSBL</th><th>URLH</th><th>CVE</th><th>LEAK</th><th>TYPO</th><th>PATCH</th><th>TKO</th><th>SC</th><th>SC-REP</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
{cards}
</body>
</html>"""


def _json_for_script(data: object) -> str:
    return (
        json.dumps(data, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_dashboard_html(payload: dict[str, Any], n_prefixes: int, n_paths: int) -> str:
    blob = _json_for_script(payload)
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ASM Dashboard — Proveedores Incocredito</title>
<style>
:root {{ --bg:#0f1419; --card:#161b22; --br:#30363d; --txt:#e6edf3; --muted:#8b949e; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--txt); min-height: 100vh; }}
.wrap {{ max-width: 1180px; margin: 0 auto; padding: 22px; }}
.hdr {{ display:flex; flex-wrap:wrap; align-items: baseline; justify-content: space-between; gap: 12px; border-bottom: 1px solid var(--br); padding-bottom: 14px; margin-bottom: 18px; }}
h1 {{ font-size: 1.15rem; font-weight: 600; letter-spacing: -0.02em; margin: 0; }}
.sub {{ font-size: 11px; color: var(--muted); margin-top: 4px; }}
.kgrid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-bottom: 16px; }}
.kpi {{ background: var(--card); border: 1px solid var(--br); border-radius: 8px; padding: 10px 12px; }}
.kl {{ font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
.kv {{ font-size: 20px; font-weight: 600; margin-top: 4px; }}
.tabs {{ display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 12px; }}
.tab {{ font-size: 12px; padding: 6px 14px; border-radius: 6px; border: 1px solid transparent; background: transparent; color: var(--muted); cursor: pointer; }}
.tab.on {{ background: var(--card); border-color: var(--br); color: var(--txt); }}
.panel {{ display: none; }}
.panel.on {{ display: block; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }}
th, td {{ text-align: left; padding: 8px 6px; border-bottom: 1px solid var(--br); vertical-align: top; }}
th {{ color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; }}
tr:hover td {{ background: var(--card); }}
.badge {{ font-size: 10px; padding: 2px 8px; border-radius: 999px; background: #E6F1FB; color: #185FA5; }}
pre {{ background: #0d1117; border: 1px solid var(--br); border-radius: 8px; padding: 12px; font-size: 11px; overflow: auto; max-height: 70vh; margin: 0; }}
code {{ font-size: 11px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div>
      <h1>ASM — Proveedores Incocredito</h1>
      <div class="sub" id="subline"></div>
    </div>
    <span class="badge">live scan</span>
  </div>
  <div class="kgrid" id="kpis"></div>
  <div class="tabs" id="tabs"></div>
  <div id="panels"></div>
</div>
<script>
const DATA = {blob};
const N_PREFIXES = {n_prefixes};
const N_PATHS = {n_paths};
(function () {{
  const providers = DATA.providers || [];
  const matrix = DATA.matrix || [];
  const gen = DATA.generated_utc || "";
  document.getElementById("subline").textContent =
    "Third-party attack surface · UTC " + gen + " · " + N_PREFIXES + " prefijos DNS · " + N_PATHS + " rutas HEAD";

  let totalSubs = 0, usefulPaths = 0, tls13 = 0, hsts = 0;
  for (const p of providers) {{
    totalSubs += (p.subdomains || []).length;
    for (const r of p.public_paths || []) {{
      const sc = r.status_code;
      if ([200,201,204,301,302,401,403].includes(sc)) usefulPaths++;
    }}
    if (p.tls && p.tls.tls13_only_ok) tls13++;
    const h = p.https && p.https.headers;
    if (h && h["strict-transport-security"]) hsts++;
  }}

  const kpis = document.getElementById("kpis");
  const items = [
    ["Proveedores", providers.length],
    ["Subdominios resueltos", totalSubs],
    ["TLS 1.3-only OK", tls13 + " / " + providers.length],
    ["HSTS (apex)", hsts + " / " + providers.length],
    ["Rutas útiles (HEAD)", usefulPaths],
  ];
  for (const [a, b] of items) {{
    const d = document.createElement("div");
    d.className = "kpi";
    d.innerHTML = '<div class="kl"></div><div class="kv"></div>';
    d.querySelector(".kl").textContent = a;
    d.querySelector(".kv").textContent = String(b);
    kpis.appendChild(d);
  }}

  const tabs = document.getElementById("tabs");
  const panels = document.getElementById("panels");
  const defs = [
    ["matriz", "Matriz ASM"],
    ["subs", "Subdominios"],
    ["rutas", "Rutas públicas"],
    ["raw", "JSON"],
  ];

  function esc(s) {{
    return String(s == null ? "" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  }}

  function buildMatriz() {{
    let h = "<table><thead><tr><th>Proveedor</th><th>Sub</th><th>HTTPS</th><th>HSTS</th><th>CSP</th><th>CSP-W</th><th>COOK</th><th>SPF/DMARC</th><th>TLS1.3</th><th>Puertos</th><th>Rutas</th><th>Huella</th><th>STLS</th><th>MX</th><th>NS</th><th>DNSSEC</th><th>DKIM</th><th>DANE</th><th>DNSBL</th><th>URLH</th><th>CVE</th><th>LEAK</th><th>TYPO</th><th>PATCH</th><th>TKO</th><th>SC</th><th>SC-REP</th><th>OWASP</th></tr></thead><tbody>";
    for (const m of matrix) {{
      h += "<tr><td><strong>" + esc(m.proveedor) + "</strong><br><span style=color:var(--muted)>" + esc(m.dominio) + "</span></td>";
      h += "<td>" + esc(m.subdominios) + "</td><td>" + esc(m.https) + "</td>";
      h += "<td>" + (m.hsts ? "✓" : "✗") + "</td><td>" + (m.csp ? "✓" : "✗") + "</td>";
      h += "<td>" + esc(m.csp_finding_count) + "</td>";
      h += "<td>" + (m.cookie_insecure ? "✗" : "✓") + "</td>";
      h += "<td>" + esc(m.spf_dmarc) + "</td><td>" + (m.tls13_negociado ? "✓" : "✗") + "</td>";
      h += "<td style=color:var(--muted)>" + esc(m.puertos) + "</td><td>" + esc(m.rutas_interesantes) + "</td>";
      h += "<td class=small style=color:var(--muted);font-size:11px>" + esc(m.huella) + "</td>";
      h += "<td>" + (m.starttls_ok ? "✓" : "✗") + "</td><td>" + esc(m.mx_count) + "</td><td>" + esc(m.ns_count) + "</td>";
      h += "<td>" + (m.dnssec_ok ? "✓" : "✗") + "</td><td>" + esc(m.dkim_count) + "</td><td>" + esc(m.dane_count) + "</td>";
      h += "<td>" + (m.ip_reputation_clean ? "✓" : esc(m.ip_reputation_count)) + "</td>";
      h += "<td>" + (m.urlhaus_malicious ? "✓" : "✗") + "</td>";
      h += "<td>" + esc(m.vulnerability_count) + "</td>";
      h += "<td>" + (m.credential_leak_error ? esc(m.credential_leak_count) : esc(m.credential_leak_count)) + "</td>";
      h += "<td>" + esc(m.typosquatting_count) + "</td>";
      h += "<td>" + esc(m.patching_eol + m.patching_ending) + "</td>";
      h += "<td>" + (m.takeover_vulnerable ? "✓" : m.takeover_count > 0 ? esc(m.takeover_count) : "✗") + "</td>";
      h += "<td>" + esc(m.supply_chain_count) + "</td>";
      h += "<td>" + (m.supply_reputation_clean ? "✓" : "✗") + "</td>";
      h += "<td>" + ((m.owasp && m.owasp.overall_grade) ? m.owasp.overall_grade : "—") + "</td></tr>";
    }}
    return h + "</tbody></table>";
  }}

  function buildSubs() {{
    let h = "<table><thead><tr><th>Proveedor</th><th>Host</th><th>IPv4</th></tr></thead><tbody>";
    for (const p of providers) {{
      const subs = p.subdomains || [];
      if (!subs.length) {{
        h += "<tr><td>" + esc(p.name) + "</td><td colspan=2 style=color:var(--muted)>Sin subdominios del diccionario</td></tr>";
        continue;
      }}
      for (const s of subs) {{
        h += "<tr><td>" + esc(p.name) + "</td><td><code>" + esc(s.host) + "</code></td><td style=font-size:11px;color:var(--muted)>" + esc((s.ipv4 || []).join(", ")) + "</td></tr>";
      }}
    }}
    return h + "</tbody></table>";
  }}

  function buildRutas() {{
    let h = "<table><thead><tr><th>Proveedor</th><th>Ruta</th><th>HTTP</th><th>Detalle</th></tr></thead><tbody>";
    for (const p of providers) {{
      for (const r of p.public_paths || []) {{
        const det = r.status_code != null ? esc(String(r.status_code)) : esc(r.error || "—");
        h += "<tr><td>" + esc(p.name) + "</td><td><code>" + esc(r.path) + "</code></td><td>" + det + "</td>";
        h += "<td style=font-size:11px;color:var(--muted);word-break:break-all>" + esc(r.url || "") + "</td></tr>";
      }}
    }}
    return h + "</tbody></table>";
  }}

  defs.forEach(([id, label], idx) => {{
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tab" + (idx === 0 ? " on" : "");
    b.textContent = label;
    b.dataset.idx = String(idx);
    tabs.appendChild(b);

    const div = document.createElement("div");
    div.className = "panel" + (idx === 0 ? " on" : "");
    div.id = "panel-" + id;
    if (id === "matriz") div.innerHTML = buildMatriz();
    else if (id === "subs") div.innerHTML = buildSubs();
    else if (id === "rutas") div.innerHTML = buildRutas();
    else div.innerHTML = "<pre>" + esc(JSON.stringify(DATA, null, 2)) + "</pre>";
    panels.appendChild(div);

    b.addEventListener("click", () => {{
      [...tabs.children].forEach((t, i) => t.classList.toggle("on", i === idx));
      [...panels.children].forEach((p, i) => p.classList.toggle("on", i === idx));
    }});
  }});
}})();
</script>
</body>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser(description="ASM ligero para lista de dominios.")
    ap.add_argument(
        "--providers",
        type=Path,
        default=Path(__file__).resolve().parent / "providers.json",
        help="JSON con id, name, domain",
    )
    ap.add_argument(
        "--out-json",
        type=Path,
        default=Path(__file__).resolve().parent / "asm_report.json",
    )
    ap.add_argument(
        "--out-html",
        type=Path,
        default=Path(__file__).resolve().parent / "asm_report.html",
    )
    ap.add_argument(
        "--out-dashboard",
        type=Path,
        default=Path(__file__).resolve().parent / "asm_dashboard.html",
    )
    ap.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Omitir enumeración DNS de subdominios (prefijos comunes).",
    )
    ap.add_argument(
        "--no-public-paths",
        action="store_true",
        help="Omitir sondas HEAD a rutas públicas típicas.",
    )
    args = ap.parse_args()

    # Ensure output directories exist
    for p in (args.out_json, args.out_html, args.out_dashboard):
        if p:
            p.parent.mkdir(parents=True, exist_ok=True)

    log = log_utils.get_logger("asm_scan")
    raw = json.loads(args.providers.read_text(encoding="utf-8"))
    sess = session_with_retries()
    results: list[ProviderASM] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    for row in raw:
        domain = row["domain"].strip().lower().rstrip(".")
        log.info("%s (%s)...", row['name'], domain)
        dns_p = resolve_dns(domain)
        p80 = check_port(domain, 80)
        p443 = check_port(domain, 443)
        tls_p = probe_tls(domain) if p443.open else TLSProbe(False, None, None, None, None, None, None, error="443 cerrado / sin TLS")
        http_p = (
            probe_https(domain, sess)
            if p443.open
            else HTTPProbe(None, None, False, [], {}, None, None, None, None, None, None, None, None, error="443 no disponible")
        )

        subs: list[dict[str, Any]] = []
        if not args.no_subdomains:
            subs = enumerate_subdomains(domain)

        paths: list[dict[str, Any]] = []
        if not args.no_public_paths and p443.open:
            paths = probe_public_paths(domain, sess)

        crt_subs = query_passive_subdomains(domain)
        caa_recs = query_caa(domain)
        mta_sts = query_mta_sts(domain)
        tls_rpt = query_tls_rpt(domain)
        bimi = query_bimi(domain)
        urlhaus = check_urlhaus(domain)

        techs = extract_technologies(http_p.headers)
        vulns = query_osv(techs)
        patch = check_patching_cadence(techs)
        supply = check_supply_chain(domain, http_p.headers, sess)
        leaks = check_credential_leaks(domain)
        typos = check_typosquatting(domain)
        takeover = check_subdomain_takeover(domain, subs)
        csp_header = http_p.headers.get("content-security-policy") or http_p.headers.get("content-security-policy-report-only")
        csp_findings_list = check_csp_security(csp_header)
        cookie_findings_list = check_cookie_security(http_p.headers.get("set-cookie"))

        social_data: dict[str, Any] = {}
        for net in ("instagram", "tiktok", "twitter", "twitch", "telegram", "github"):
            uname = row.get(f"social_{net}", "").strip()
            if uname:
                try:
                    social_data[net] = social_osint.scan_social(uname, [net]).get(net, {})
                except Exception:
                    social_data[net] = {"username": uname, "error": "scan_failed"}

        external_data: dict[str, Any] = {}
        try:
            external_data = external_sources.run_all(domain)
            log.info("External sources OK: whois=%s dnsdumpster=%s shodan=%s censys=%s theharvester=%s",
                "ok" if "error" not in external_data.get("whois", {}) else external_data["whois"].get("error","fail"),
                "ok" if "error" not in external_data.get("dnsdumpster", {}) else external_data["dnsdumpster"].get("error","fail"),
                "ok" if "error" not in external_data.get("shodan", {}) else external_data["shodan"].get("error","fail"),
                "ok" if "error" not in external_data.get("censys", {}) else external_data["censys"].get("error","fail"),
                "ok" if "error" not in external_data.get("theharvester", {}) else external_data["theharvester"].get("error","fail"),
            )
        except Exception as exc:
            log.warning("External sources error: %s", exc)

        results.append(
            ProviderASM(
                id=row["id"],
                name=row["name"],
                domain=domain,
                dns=dns_p,
                port_80=p80,
                port_443=p443,
                tls=tls_p,
                https=http_p,
                scanned_at=now,
                subdomains=subs,
                public_paths=paths,
                crt_subdomains=crt_subs,
                caa_records=caa_recs,
                mta_sts=mta_sts,
                tls_rpt=tls_rpt,
                bimi=bimi,
                san_list=tls_p.san_list,
                urlhaus=urlhaus,
                vulnerabilities=vulns,
                credential_leaks=leaks,
                typosquatting=typos,
                patching=patch,
                supply_chain=supply,
                supply_chain_reputation=check_supply_reputation(supply),
                social=social_data,
                external=external_data,
                takeover_risks=takeover,
                csp_findings=csp_findings_list,
                cookie_findings=cookie_findings_list,
            )
        )
        time.sleep(0.35)

    matrix = [build_matrix_row(p) for p in results]
    payload = {
        "generated_utc": now,
        "providers": [dataclass_to_dict(p) for p in results],
        "matrix": matrix,
    }
    args.out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    args.out_html.write_text(render_html(results, matrix, now), encoding="utf-8")
    args.out_dashboard.write_text(
        render_dashboard_html(payload, len(SUBDOMAIN_PREFIXES), len(PUBLIC_PATHS)),
        encoding="utf-8",
    )
    log.info("JSON: %s", args.out_json)
    log.info("HTML: %s", args.out_html)
    log.info("Dashboard: %s", args.out_dashboard)
    return 0


if __name__ == "__main__":
    sys.exit(main())
