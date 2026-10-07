# prism_integration.py — Integración selectiva de "Prism-platform" (OSINT Toolkit)
# (https://github.com/NovaCode37/Prism-platform) para enriquecer el escaneo ASM.
# Solo se ejecutan módulos de valor incremental (los que no existen en el pipeline propio:
# WHOIS/DNS/CT/WAF/cloud/internetdb/api/wayback/secrets se mantienen en asm_scan + KUMO).
#
# Uso desde asm_scan._scan_provider:
#   import prism_integration
#   prism_data = prism_integration.run_for_level(domain, test_level, emails=..., ips=..., org_name=...)
#
# NIVELES:
#   pasivo (1)     -> leak_lookup · onion_checker · gravatar · github_recon   (APIs OSINT, no tocan el host)
#   semi-activo(2) -> + website_analyzer                                       (1 GET ligero al dominio)
#   activo/invasivo(3/4) -> + smtp_verify · virustotal · abuseipdb             (sondas SMTP/reputación; tolerantes sin API keys)

from __future__ import annotations

import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

_PRISM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prism_osint")
if _PRISM_DIR not in sys.path:
    sys.path.insert(0, _PRISM_DIR)

from modules.leak_lookup import LeakLookup  # noqa: E402
from modules.onion_checker import OnionChecker  # noqa: E402
from modules.gravatar import GravatarRecon  # noqa: E402
from modules.github_recon import GitHubRecon  # noqa: E402
from modules.extra_tools import WebsiteAnalyzer  # noqa: E402
from modules.smtp_verify import SMTPVerifier  # noqa: E402
from modules.threat_intel import VirusTotal, AbuseIPDB  # noqa: E402

log = logging.getLogger("prism_integration")

# Módulos (claves del dict de resultado) por nivel mínimo de prueba.
LEVEL_MODULES: dict[int, list[str]] = {
    1: ["leak_lookup", "onion_checker", "gravatar", "github_recon"],
    2: ["leak_lookup", "onion_checker", "gravatar", "github_recon", "website_analyzer"],
    3: ["leak_lookup", "onion_checker", "gravatar", "github_recon", "website_analyzer",
        "smtp_verify", "virustotal", "abuseipdb"],
}

# Timeout global por módulo (segundos).
MODULE_TIMEOUT: dict[str, float] = {
    "leak_lookup": 40.0,
    "onion_checker": 30.0,
    "gravatar": 15.0,
    "github_recon": 45.0,
    "website_analyzer": 20.0,
    "smtp_verify": 35.0,
    "virustotal": 20.0,
    "abuseipdb": 20.0,
}

DEFAULT_TIMEOUT = 30.0


def _collect_emails(*sources) -> list[str]:
    out: list[str] = []
    for src in sources:
        if not src or not isinstance(src, dict):
            continue
        for key in ("emails",):
            for e in (src.get(key) or []):
                if isinstance(e, str) and "@" in e and e not in out:
                    out.append(e)
        for sub in (src.get("whois") or {}, src.get("theharvester") or {}):
            for e in (sub.get("emails") or []):
                if isinstance(e, str) and "@" in e and e not in out:
                    out.append(e)
    return out[:20]


def _run_one(module_key: str, domain: str, emails: list[str], ips: list[str], org_name: str) -> dict:
    def call():
        try:
            if module_key == "leak_lookup":
                if not emails:
                    return {"query": domain, "note": "sin emails para consultar", "found": False}
                results = []
                for em in emails[:3]:
                    results.append(LeakLookup().check_email_full(em))
                return {
                    "domain": domain,
                    "emails_checked": [em for em in emails[:3]],
                    "found": any(r.get("found") or r.get("is_compromised") for r in results if isinstance(r, dict)),
                    "breaches": _merge_breaches(results),
                    "per_email": results,
                    "email_count": len(emails[:3]),
                }
            if module_key == "onion_checker":
                return OnionChecker().check(domain)
            if module_key == "gravatar":
                if not emails:
                    return {"email": emails[0] if emails else None, "note": "sin emails para consultar"}
                hits = []
                for em in emails[:3]:
                    r = GravatarRecon().lookup(em)
                    if isinstance(r, dict) and r.get("display_name"):
                        hits.append({"email": em, "display_name": r.get("display_name"),
                                     "accounts": r.get("accounts") or []})
                return {"domain": domain, "emails_checked": emails[:3], "hits": hits, "total_hits": len(hits)}
            if module_key == "github_recon":
                if not org_name:
                    return {"note": "sin org name para consultar"}
                return GitHubRecon().lookup(org_name)
            if module_key == "website_analyzer":
                return WebsiteAnalyzer().analyze(domain)
            if module_key == "smtp_verify":
                if not emails:
                    return {"note": "sin emails para verificar"}
                results = []
                for em in emails[:2]:
                    results.append(SMTPVerifier().verify_email(em))
                return {"domain": domain, "emails_checked": emails[:2], "per_email": results,
                        "any_exists": any(r.get("exists") is True for r in results if isinstance(r, dict)),
                        "catch_all": any(r.get("catch_all") for r in results if isinstance(r, dict))}
            if module_key == "virustotal":
                if ips and ":" not in (ips[0] or ""):
                    return VirusTotal().check_domain(domain)
                return VirusTotal().check_domain(domain)
            if module_key == "abuseipdb":
                if not ips:
                    return {"note": "sin IP para consultar"}
                return AbuseIPDB().check_ip(ips[0])
        except Exception:
            raise
        return {}

    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(call)
            result = fut.result(timeout=MODULE_TIMEOUT.get(module_key, DEFAULT_TIMEOUT))
        if not isinstance(result, dict):
            result = {"result": result}
        result.setdefault("module", module_key)
        result.setdefault("source", "Prism " + module_key)
        return result
    except FutureTimeout:
        return {"module": module_key, "error": f"timeout {MODULE_TIMEOUT.get(module_key, DEFAULT_TIMEOUT):.0f}s"}
    except Exception as exc:  # noqa: BLE001 - tolerante: el pipeline no debe caer por un módulo
        return {"module": module_key, "error": str(exc)}


def _merge_breaches(results: list) -> list:
    out: list[dict] = []
    seen: set[str] = set()
    for r in results:
        if not isinstance(r, dict):
            continue
        for sub in (r.get("xon"), r.get("leakcheck"), r.get("hibp"), r.get("leak_lookup")):
            if not isinstance(sub, dict):
                continue
            for b in (sub.get("breaches") or []):
                name = b.get("name") if isinstance(b, dict) else b
                if not name or str(name).lower() in seen:
                    continue
                seen.add(str(name).lower())
                out.append({"name": name if isinstance(b, dict) else str(b)})
    return out[:40]


def run_for_level(domain: str, test_level: int, emails: list[str] | None = None,
                  ips: list[str] | None = None, org_name: str | None = None) -> dict:
    """Ejecuta los módulos Prism del nivel dado. Devuelve {module: resultado}."""
    modules = LEVEL_MODULES.get(test_level)
    if modules is None:
        modules = LEVEL_MODULES[min(max(1, test_level), 3)]
    out: dict = {"domain": domain, "level": test_level}
    for key in modules:
        out[key] = _run_one(key, domain, emails or [], ips or [], org_name or "")
    return out