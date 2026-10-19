#!/usr/bin/env python3
"""
OWASP Web Top 10 2025 — compliance mapping desde hallazgos ASM.
Espejo de owasp_agentic.py pero contra el Top 10 Web (2025).

Referencia normativa: https://owasp.org/Top10/2025/ (CC BY-SA 4.0, OWASP Foundation).
Contenido local propio; los titulos/descripciones sintetizan el estandar.
Ver tambien skill hve-core: .github/skills/security/owasp-top-10/SKILL.md
"""

from __future__ import annotations

from typing import Any

OWASP_WEB: list[dict[str, Any]] = [
    {"id": "W-01", "title": "Broken Access Control", "description": "Falta de controles de acceso en funciones/objetos; shadow APIs y rutas publicas expuestas."},
    {"id": "W-02", "title": "Security Misconfiguration", "description": "Cabeceras de seguridad ausentes/debiles, TLS mal configurado, verbosidad y defaults inseguros."},
    {"id": "W-03", "title": "Software Supply Chain Failures", "description": "Dependencias de terceros, scripts externos, takeover de subdominios, reputacion DNSBL/URLhaus."},
    {"id": "W-04", "title": "Cryptographic Failures", "description": "TLS obsoleto, sin TLS 1.3-only, certificados debiles, sin STARTTLS/DANE/DNSSEC."},
    {"id": "W-05", "title": "Injection", "description": "CSP debil (unsafe-inline/eval, wildcards), XSS potencial, endpoints API inyectables."},
    {"id": "W-06", "title": "Insecure Design", "description": "Falta de controles de diseno: sin HTTPS, cookies sin flags, SPF/DMARC/DKIM ausentes."},
    {"id": "W-07", "title": "Authentication Failures", "description": "Cookies sin Secure/HttpOnly/SameSite, credenciales filtradas, typosquatting activo."},
    {"id": "W-08", "title": "Software or Data Integrity Failures", "description": "Sin SRI/CSP con report-uri, supply chain sin verificar, parches EOL."},
    {"id": "W-09", "title": "Security Logging and Alerting Failures", "description": "Sin CSP report-uri/report-to, sin MTA-STS/TLS-RPT, sin monitoreo de reputacion."},
    {"id": "W-10", "title": "Mishandling of Exceptional Conditions", "description": "Errores TLS/HTTPS no manejados, redirecciones inseguras, puerto 80 abierto sin upgrade."},
]

OWASP_BY_ID = {r["id"]: r for r in OWASP_WEB}

ASM_TO_WEB_RULES: list[tuple[str, list[str], float]] = [
    ("missing_hsts", ["W-02"], 0.3),
    ("missing_csp", ["W-02", "W-05"], 0.4),
    ("missing_x_frame_options", ["W-01", "W-02"], 0.2),
    ("missing_x_content_type_options", ["W-02", "W-05"], 0.2),
    ("csp_weak_unsafe_inline", ["W-05"], 0.5),
    ("csp_weak_unsafe_eval", ["W-05"], 0.5),
    ("csp_weak_wildcard", ["W-02", "W-05"], 0.4),
    ("csp_missing_base_uri", ["W-05"], 0.3),
    ("csp_missing_object_src", ["W-05"], 0.3),
    ("csp_missing_frame_ancestors", ["W-01"], 0.3),
    ("csp_missing_form_action", ["W-05"], 0.3),
    ("csp_allowlist_bypass", ["W-05"], 0.4),
    ("csp_no_report_uri", ["W-08", "W-09"], 0.2),
    ("cookie_no_secure", ["W-06", "W-07"], 0.4),
    ("cookie_no_httponly", ["W-07"], 0.4),
    ("cookie_no_samesite", ["W-01", "W-07"], 0.3),
    ("tls_old_version", ["W-04"], 0.5),
    ("tls_not_13_only", ["W-04"], 0.3),
    ("tls_error", ["W-04", "W-10"], 0.6),
    ("starttls_missing", ["W-04"], 0.4),
    ("spf_missing", ["W-06"], 0.3),
    ("dmarc_missing", ["W-06"], 0.3),
    ("dkim_missing", ["W-06"], 0.2),
    ("dnssec_missing", ["W-04", "W-08"], 0.2),
    ("dane_missing", ["W-04"], 0.2),
    ("takeover_vulnerable", ["W-03"], 0.7),
    ("takeover_potential", ["W-03"], 0.4),
    ("supply_chain_detected", ["W-03", "W-08"], 0.3),
    ("supply_reputation_dnsbl", ["W-03"], 0.6),
    ("supply_reputation_urlhaus", ["W-03"], 0.6),
    ("cve_detected", ["W-02", "W-03"], 0.5),
    ("patching_eol", ["W-02", "W-06"], 0.5),
    ("credential_leak", ["W-07"], 0.6),
    ("typosquatting_active", ["W-07", "W-03"], 0.5),
    ("http_open", ["W-10", "W-02"], 0.2),
    ("https_missing", ["W-02", "W-04", "W-06"], 0.5),
    ("shadow_api", ["W-01"], 0.5),
    ("social_network_found", ["W-07"], 0.2),
]

_RULE_IDX = {r[0]: (r[1], r[2]) for r in ASM_TO_WEB_RULES}


def _add(findings: list, key: str, mult: float = 1.0) -> None:
    ids, w = _RULE_IDX[key]
    findings.append((key, ids, w * mult))


def evaluate_provider(p: dict[str, Any]) -> dict[str, Any]:
    scores: dict[str, float] = {r["id"]: 0.0 for r in OWASP_WEB}
    findings_by_risk: dict[str, list[dict[str, Any]]] = {r["id"]: [] for r in OWASP_WEB}
    findings: list[tuple[str, list[str], float]] = []

    h = {}
    https_raw = p.get("https")
    if isinstance(https_raw, dict):
        inner = https_raw.get("headers")
        if isinstance(inner, dict):
            h = inner
    headers_raw = p.get("https_headers") or {}
    if isinstance(headers_raw, dict):
        h = {**h, **headers_raw}
    tls_raw = p.get("tls")
    tls = tls_raw if isinstance(tls_raw, dict) else {}

    https_code = p.get("https")
    if isinstance(https_code, dict):
        https_code = https_code.get("status")
    if not (isinstance(https_code, int) and 200 <= https_code < 400):
        _add(findings, "https_missing")

    if not h.get("strict-transport-security"):
        _add(findings, "missing_hsts")

    has_csp = bool(h.get("content-security-policy") or h.get("content-security-policy-report-only"))
    if not has_csp:
        _add(findings, "missing_csp")
    else:
        for f in p.get("csp_findings") or []:
            sev = f.get("severity", "")
            desc = f.get("description", "")
            directive = f.get("directive", "")
            w = 1.0 if sev == "high" else 0.5
            if "unsafe-inline" in desc:
                _add(findings, "csp_weak_unsafe_inline", w)
            if "unsafe-eval" in desc:
                _add(findings, "csp_weak_unsafe_eval", w)
            if "comodín" in desc or "wildcard" in desc.lower() or "*" in directive:
                _add(findings, "csp_weak_wildcard", w)
            if "base-uri" in desc or directive == "base-uri":
                _add(findings, "csp_missing_base_uri")
            if "object-src" in desc or directive == "object-src":
                _add(findings, "csp_missing_object_src")
            if "frame-ancestors" in desc or directive == "frame-ancestors":
                _add(findings, "csp_missing_frame_ancestors")
            if "form-action" in desc or directive == "form-action":
                _add(findings, "csp_missing_form_action")
            if "bypass" in desc.lower() or "jsonp" in desc.lower():
                _add(findings, "csp_allowlist_bypass", w)
            if "report-uri" in desc:
                _add(findings, "csp_no_report_uri")

    if not h.get("x-frame-options"):
        _add(findings, "missing_x_frame_options")
    if not h.get("x-content-type-options"):
        _add(findings, "missing_x_content_type_options")

    for f in p.get("cookie_findings") or []:
        sev = f.get("severity", "")
        desc = f.get("description", "")
        w = 1.0 if sev == "high" else 0.5
        if "secure" in desc.lower() and "inseguro" in desc.lower():
            _add(findings, "cookie_no_secure", w)
        if "httponly" in desc.lower() and "inseguro" in desc.lower():
            _add(findings, "cookie_no_httponly", w)
        if "samesite" in desc.lower() and ("none" in desc.lower() or "inseguro" in desc.lower()):
            _add(findings, "cookie_no_samesite", w)

    tls_ver = tls.get("negotiated_version", "")
    if tls_ver and "1.3" not in tls_ver:
        _add(findings, "tls_old_version")
    if tls.get("error"):
        _add(findings, "tls_error")
    elif tls and not tls.get("tls13_only_ok"):
        _add(findings, "tls_not_13_only")

    if p.get("mx_count", 0) > 0 and not p.get("starttls_ok", False):
        _add(findings, "starttls_missing")

    spf_dmarc = str(p.get("spf_dmarc", ""))
    if "SPF:missing" in spf_dmarc:
        _add(findings, "spf_missing")
    elif "SPF:partial" in spf_dmarc:
        _add(findings, "spf_missing", 0.5)
    if "DMARC:-" in spf_dmarc or "DMARC:none" in spf_dmarc:
        _add(findings, "dmarc_missing")
    if p.get("dkim_count", 0) == 0 and p.get("mx_count", 0) > 0:
        _add(findings, "dkim_missing")
    if not p.get("dnssec_ok"):
        _add(findings, "dnssec_missing")
    if p.get("dane_count", 0) == 0 and p.get("mx_count", 0) > 0:
        _add(findings, "dane_missing")

    if any(r.get("vulnerable") for r in (p.get("takeover_risks") or [])):
        _add(findings, "takeover_vulnerable")
    elif p.get("takeover_count", 0) > 0:
        _add(findings, "takeover_potential")

    if p.get("supply_chain_count", 0) > 0:
        _add(findings, "supply_chain_detected")
    if p.get("supply_reputation_dnsbl_count", 0) > 0:
        _add(findings, "supply_reputation_dnsbl")
    if p.get("supply_reputation_urlhaus_count", 0) > 0:
        _add(findings, "supply_reputation_urlhaus")

    if p.get("vulnerability_count", 0) > 0 or p.get("cve_finding_count", 0) > 0:
        _add(findings, "cve_detected")
    if p.get("patching_eol", 0) > 0:
        _add(findings, "patching_eol", min(1.0, p.get("patching_eol", 0) / 3))

    if p.get("credential_leak_count", 0) > 0:
        _add(findings, "credential_leak")
    if p.get("typosquatting_count", 0) > 0:
        _add(findings, "typosquatting_active")
    if "80:open" in str(p.get("puertos", "")):
        _add(findings, "http_open")
    if p.get("shadow_api_count", 0) > 0:
        _add(findings, "shadow_api")
    if p.get("social_str", ""):
        _add(findings, "social_network_found")

    for asm_id, web_ids, weight in findings:
        for oid in web_ids:
            scores[oid] = min(1.0, scores[oid] + weight * 0.25)
            findings_by_risk[oid].append({"id": asm_id, "weight": weight})

    compliance_scores = {}
    for r in OWASP_WEB:
        oid = r["id"]
        raw = min(1.0, scores[oid])
        compliance = round((1.0 - raw) * 100, 1)
        compliance_scores[oid] = {
            "score": raw,
            "compliance_pct": compliance,
            "grade": _grade(compliance),
            "findings": findings_by_risk[oid],
            "finding_count": len(findings_by_risk[oid]),
        }

    overall = round(sum(cs["compliance_pct"] for cs in compliance_scores.values()) / max(1, len(OWASP_WEB)), 1)
    return {"overall_compliance": overall, "overall_grade": _grade(overall), "risks": compliance_scores}


def _grade(pct: float) -> str:
    if pct >= 90:
        return "A"
    if pct >= 75:
        return "B"
    if pct >= 60:
        return "C"
    if pct >= 45:
        return "D"
    if pct >= 30:
        return "E"
    return "F"
