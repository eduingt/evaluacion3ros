#!/usr/bin/env python3
"""
OWASP Agentic Top 10 — compliance mapping from ASM findings.
Cada hallazgo ASM se mapea a uno o mas riesgos OWASP Agentic con
peso (0-1) y recomendacion de mitigacion usando el Agent Governance Toolkit.
"""

from __future__ import annotations

from typing import Any

# ── Definicion de los 10 riesgos OWASP Agentic ──────────────────────────
OWASP_AGENTIC: list[dict[str, Any]] = [
    {
        "id": "ASI-01",
        "title": "Agent Goal Hijack",
        "description": "Manipulacion de objetivos del agente via prompt injection o entradas envenenadas.",
        "toolkit_component": "Agent OS — Policy Engine",
        "toolkit_mitigation": "Instalar agent-governance-toolkit, configurar PolicyEvaluator con reglas deny-by-default. Cada accion del agente pasa por el motor antes de ejecutarse.",
    },
    {
        "id": "ASI-02",
        "title": "Tool Misuse & Exploitation",
        "description": "Herramientas autorizadas usadas de forma no prevista (exfiltracion, ejecucion no deseada).",
        "toolkit_component": "Agent OS — Capability Sandboxing",
        "toolkit_mitigation": "Implementar capability grants (read/write/execute/network) con allowlists/denylists y sanitizacion de entradas.",
    },
    {
        "id": "ASI-03",
        "title": "Identity & Privilege Abuse",
        "description": "Agentes escalan privilegios abusando de identidades o heredando credenciales excesivas.",
        "toolkit_component": "AgentMesh — DID Identity & Trust Scoring",
        "toolkit_mitigation": "Usar identidades DID con Ed25519, trust scoring (Untrusted→Verified), cadenas de delegacion con alcance decreciente.",
    },
    {
        "id": "ASI-04",
        "title": "Agentic Supply Chain Vulnerabilities",
        "description": "Vulnerabilidades en herramientas de terceros, plugins, registros o dependencias de runtime.",
        "toolkit_component": "AgentMesh — AI-BOM (model + data + weights provenance)",
        "toolkit_mitigation": "Generar AI-BOM con proveniencia de modelo, datasets, hashes de pesos y dependencias SPDX. Firmar con Ed25519.",
    },
    {
        "id": "ASI-05",
        "title": "Unexpected Code Execution",
        "description": "Agentes ejecutan codigo remoto a traves de herramientas, interpretes o APIs sin control.",
        "toolkit_component": "Agent Runtime — Execution Rings",
        "toolkit_mitigation": "Implementar rings de ejecucion (Ring 0-3), limites de recursos, kill switch, saga compensation.",
    },
    {
        "id": "ASI-06",
        "title": "Memory & Context Poisoning",
        "description": "Memoria persistente o contexto envenenado con instrucciones maliciosas.",
        "toolkit_component": "Agent OS — VFS Policies + CMVK Verification",
        "toolkit_mitigation": "Politicas VFS para memoria (read-only en /policy/*), deteccion de patrones de prompt injection, verificacion cross-model.",
    },
    {
        "id": "ASI-07",
        "title": "Insecure Inter-Agent Communication",
        "description": "Agentes colaboran sin autenticacion, confidencialidad o validacion adecuadas.",
        "toolkit_component": "AgentMesh — IATP + Encrypted Channels (Signal Protocol)",
        "toolkit_mitigation": "Implementar IATP para firmar/verificar mensajes, canales E2E con Signal (X3DH + Double Ratchet), trust-gated encryption.",
    },
    {
        "id": "ASI-08",
        "title": "Cascading Failures",
        "description": "Error inicial o compromiso desencadena fallos compuestos multi-paso entre agentes encadenados.",
        "toolkit_component": "Agent SRE — Circuit Breakers + SLOs",
        "toolkit_mitigation": "Circuit breakers, deteccion de fallos en cascada, SLO enforcement, error budgets, canary deploys, trazabilidad OTel.",
    },
    {
        "id": "ASI-09",
        "title": "Human-Agent Trust Exploitation",
        "description": "Atacantes explotan la confianza del usuario en la autonomia del agente para autorizar acciones peligrosas.",
        "toolkit_component": "Agent OS — Approval Workflows",
        "toolkit_mitigation": "Workflows de aprobacion con clasificacion de riesgo (critical/high/medium/low), quorum logic, expiracion.",
    },
    {
        "id": "ASI-10",
        "title": "Rogue Agents",
        "description": "Agentes operan fuera de su alcance definido por desviacion de configuracion, reprogramacion o mal comportamiento emergente.",
        "toolkit_component": "Agent Runtime — Kill Switch + Ring Isolation + Trust Decay",
        "toolkit_mitigation": "Aislamiento por rings, kill switch, monitoreo de comportamiento, audit trail inmutable (Merkle chain), decaimiento de trust score.",
    },
]

OWASP_BY_ID = {r["id"]: r for r in OWASP_AGENTIC}


# ── Mapeo: hallazgo ASM -> lista de riesgos OWASP ──────────────────────
# Cada entry: (check_function, [owasp_ids], weight)
ASM_TO_OWASP_RULES: list[tuple[str, list[str], float]] = [
    # Cabeceras de seguridad faltantes → Goal Hijack, Tool Misuse
    ("missing_hsts", ["ASI-01", "ASI-02"], 0.3),
    ("missing_csp", ["ASI-01", "ASI-06"], 0.4),
    ("missing_x_frame_options", ["ASI-02"], 0.2),
    ("missing_x_content_type_options", ["ASI-02", "ASI-05"], 0.2),
    # CSP debil → Goal Hijack, Memory Poisoning
    ("csp_weak_unsafe_inline", ["ASI-01", "ASI-06"], 0.5),
    ("csp_weak_unsafe_eval", ["ASI-01", "ASI-05"], 0.5),
    ("csp_weak_wildcard", ["ASI-01", "ASI-02"], 0.4),
    ("csp_missing_base_uri", ["ASI-01", "ASI-06"], 0.3),
    ("csp_missing_object_src", ["ASI-01", "ASI-05"], 0.3),
    ("csp_missing_frame_ancestors", ["ASI-02"], 0.3),
    ("csp_missing_form_action", ["ASI-01"], 0.3),
    ("csp_allowlist_bypass", ["ASI-01", "ASI-02"], 0.4),
    ("csp_no_report_uri", ["ASI-01", "ASI-09"], 0.2),
    # Cookies inseguras → Identity Abuse, Trust Exploitation
    ("cookie_no_secure", ["ASI-03", "ASI-09"], 0.4),
    ("cookie_no_httponly", ["ASI-03", "ASI-09"], 0.4),
    ("cookie_no_samesite", ["ASI-03", "ASI-09"], 0.3),
    # TLS debil → Insecure Communication
    ("tls_old_version", ["ASI-07"], 0.5),
    ("tls_not_13_only", ["ASI-07"], 0.3),
    ("tls_error", ["ASI-07"], 0.6),
    # STARTTLS no soportado → Insecure Communication
    ("starttls_missing", ["ASI-07"], 0.4),
    # DNS debil → Supply Chain, Identity
    ("spf_missing", ["ASI-03", "ASI-04"], 0.3),
    ("dmarc_missing", ["ASI-03", "ASI-04"], 0.3),
    ("dkim_missing", ["ASI-03", "ASI-04"], 0.2),
    ("dnssec_missing", ["ASI-03", "ASI-04"], 0.2),
    ("dane_missing", ["ASI-07"], 0.2),
    # Subdomain Takeover → Supply Chain, Rogue Agents
    ("takeover_vulnerable", ["ASI-04", "ASI-10"], 0.7),
    ("takeover_potential", ["ASI-04"], 0.4),
    # Supply Chain terceros → Supply Chain
    ("supply_chain_detected", ["ASI-04"], 0.3),
    ("supply_reputation_dnsbl", ["ASI-04", "ASI-10"], 0.6),
    ("supply_reputation_urlhaus", ["ASI-04", "ASI-10"], 0.6),
    # Vulnerabilidades → Code Execution, Supply Chain
    ("cve_detected", ["ASI-04", "ASI-05"], 0.5),
    ("patching_eol", ["ASI-04", "ASI-05"], 0.5),
    # Credential leaks → Identity Abuse
    ("credential_leak", ["ASI-03"], 0.6),
    # Typosquatting → Goal Hijack, Rogue Agents
    ("typosquatting_active", ["ASI-01", "ASI-10"], 0.5),
    # Puertos abiertos → Code Execution
    ("http_open", ["ASI-05"], 0.2),
    # Sin HTTPS → Todo lo anterior
    ("https_missing", ["ASI-01", "ASI-02", "ASI-05", "ASI-07"], 0.5),
    # Redes sociales sin proteger → Trust Exploitation, Identity
    ("social_network_found", ["ASI-03", "ASI-09"], 0.3),
]


def evaluate_provider(p: dict[str, Any]) -> dict[str, Any]:
    """Evalua un provider contra los 10 riesgos OWASP. Retorna dict con scores."""
    scores: dict[str, float] = {r["id"]: 0.0 for r in OWASP_AGENTIC}
    max_scores: dict[str, float] = {r["id"]: 0.0 for r in OWASP_AGENTIC}
    findings_by_risk: dict[str, list[dict[str, Any]]] = {r["id"]: [] for r in OWASP_AGENTIC}

    # Determinar que hallazgos aplicar
    findings: list[tuple[str, list[str], float]] = []

    h = (p.get("https") or {}).get("headers") or {}
    tls = p.get("tls") or {}
    dns = p.get("dns") or {}

    # HTTPS
    https_code = p.get("https")
    if not (isinstance(https_code, int) and 200 <= https_code < 400):
        findings.append(("https_missing", ASM_TO_OWASP_RULES[35][1], ASM_TO_OWASP_RULES[35][2]))

    # HSTS
    if not h.get("strict-transport-security"):
        findings.append(("missing_hsts", ASM_TO_OWASP_RULES[0][1], ASM_TO_OWASP_RULES[0][2]))

    # CSP
    has_csp = bool(h.get("content-security-policy") or h.get("content-security-policy-report-only"))
    if not has_csp:
        findings.append(("missing_csp", ASM_TO_OWASP_RULES[1][1], ASM_TO_OWASP_RULES[1][2]))
    else:
        csp_f = p.get("csp_findings") or []
        for f in csp_f:
            sev = f.get("severity", "")
            desc = f.get("description", "")
            directive = f.get("directive", "")
            if "unsafe-inline" in desc:
                findings.append(("csp_weak_unsafe_inline", ASM_TO_OWASP_RULES[3][1], ASM_TO_OWASP_RULES[3][2] * (1.0 if sev == "high" else 0.5)))
            if "unsafe-eval" in desc:
                findings.append(("csp_weak_unsafe_eval", ASM_TO_OWASP_RULES[4][1], ASM_TO_OWASP_RULES[4][2] * (1.0 if sev == "high" else 0.5)))
            if "comodín" in desc or "wildcard" in desc.lower() or "*" in directive:
                findings.append(("csp_weak_wildcard", ASM_TO_OWASP_RULES[5][1], ASM_TO_OWASP_RULES[5][2] * (1.0 if sev == "high" else 0.5)))
            if "base-uri" in desc or directive == "base-uri":
                findings.append(("csp_missing_base_uri", ASM_TO_OWASP_RULES[6][1], ASM_TO_OWASP_RULES[6][2]))
            if "object-src" in desc or directive == "object-src":
                findings.append(("csp_missing_object_src", ASM_TO_OWASP_RULES[7][1], ASM_TO_OWASP_RULES[7][2]))
            if "frame-ancestors" in desc or directive == "frame-ancestors":
                findings.append(("csp_missing_frame_ancestors", ASM_TO_OWASP_RULES[8][1], ASM_TO_OWASP_RULES[8][2]))
            if "form-action" in desc or directive == "form-action":
                findings.append(("csp_missing_form_action", ASM_TO_OWASP_RULES[9][1], ASM_TO_OWASP_RULES[9][2]))
            if "bypass" in desc.lower() or "jsonp" in desc.lower():
                findings.append(("csp_allowlist_bypass", ASM_TO_OWASP_RULES[10][1], ASM_TO_OWASP_RULES[10][2] * (1.0 if sev == "high" else 0.5)))
            if "report-uri" in desc or "report-to" not in desc:
                findings.append(("csp_no_report_uri", ASM_TO_OWASP_RULES[11][1], ASM_TO_OWASP_RULES[11][2]))

    # X-Frame-Options
    if not h.get("x-frame-options"):
        findings.append(("missing_x_frame_options", ASM_TO_OWASP_RULES[2][1], ASM_TO_OWASP_RULES[2][2]))

    # X-Content-Type-Options
    if not h.get("x-content-type-options"):
        findings.append(("missing_x_content_type_options", ASM_TO_OWASP_RULES[3][1], ASM_TO_OWASP_RULES[3][2]))

    # Cookies
    cookie_f = p.get("cookie_findings") or []
    for f in cookie_f:
        sev = f.get("severity", "")
        desc = f.get("description", "")
        w = 1.0 if sev == "high" else 0.5
        if "secure" in desc.lower() and "inseguro" in desc.lower():
            findings.append(("cookie_no_secure", ASM_TO_OWASP_RULES[12][1], ASM_TO_OWASP_RULES[12][2] * w))
        if "httponly" in desc.lower() and "inseguro" in desc.lower():
            findings.append(("cookie_no_httponly", ASM_TO_OWASP_RULES[13][1], ASM_TO_OWASP_RULES[13][2] * w))
        if "samesite" in desc.lower() and ("none" in desc.lower() or "inseguro" in desc.lower()):
            findings.append(("cookie_no_samesite", ASM_TO_OWASP_RULES[14][1], ASM_TO_OWASP_RULES[14][2] * w))

    # TLS
    tls_ver = tls.get("negotiated_version", "")
    if tls_ver and "1.3" not in tls_ver:
        findings.append(("tls_old_version", ASM_TO_OWASP_RULES[15][1], ASM_TO_OWASP_RULES[15][2]))
    if tls.get("error"):
        findings.append(("tls_error", ASM_TO_OWASP_RULES[17][1], ASM_TO_OWASP_RULES[17][2]))
    elif not tls.get("tls13_only_ok"):
        findings.append(("tls_not_13_only", ASM_TO_OWASP_RULES[16][1], ASM_TO_OWASP_RULES[16][2]))

    # STARTTLS
    mx_count = p.get("mx_count", 0)
    starttls_ok = p.get("starttls_ok", False)
    if mx_count > 0 and not starttls_ok:
        findings.append(("starttls_missing", ASM_TO_OWASP_RULES[18][1], ASM_TO_OWASP_RULES[18][2]))

    # DNS
    spf_dmarc = str(p.get("spf_dmarc", ""))
    if "SPF:missing" in spf_dmarc:
        findings.append(("spf_missing", ASM_TO_OWASP_RULES[19][1], ASM_TO_OWASP_RULES[19][2]))
    elif "SPF:partial" in spf_dmarc:
        findings.append(("spf_missing", ASM_TO_OWASP_RULES[19][1], ASM_TO_OWASP_RULES[19][2] * 0.5))
    if "DMARC:-" in spf_dmarc or "DMARC:none" in spf_dmarc:
        findings.append(("dmarc_missing", ASM_TO_OWASP_RULES[20][1], ASM_TO_OWASP_RULES[20][2]))
    if p.get("dkim_count", 0) == 0 and mx_count > 0:
        findings.append(("dkim_missing", ASM_TO_OWASP_RULES[21][1], ASM_TO_OWASP_RULES[21][2]))
    if not p.get("dnssec_ok"):
        findings.append(("dnssec_missing", ASM_TO_OWASP_RULES[22][1], ASM_TO_OWASP_RULES[22][2]))
    if p.get("dane_count", 0) == 0 and mx_count > 0:
        findings.append(("dane_missing", ASM_TO_OWASP_RULES[23][1], ASM_TO_OWASP_RULES[23][2]))

    # Takeover
    takeover_vuln = any(r.get("vulnerable") for r in (p.get("takeover_risks") or []))
    takeover_count = p.get("takeover_count", 0)
    if takeover_vuln:
        findings.append(("takeover_vulnerable", ASM_TO_OWASP_RULES[24][1], ASM_TO_OWASP_RULES[24][2]))
    elif takeover_count > 0:
        findings.append(("takeover_potential", ASM_TO_OWASP_RULES[25][1], ASM_TO_OWASP_RULES[25][2]))

    # Supply chain
    if p.get("supply_chain_count", 0) > 0:
        findings.append(("supply_chain_detected", ASM_TO_OWASP_RULES[26][1], ASM_TO_OWASP_RULES[26][2]))
    if p.get("supply_reputation_dnsbl_count", 0) > 0:
        findings.append(("supply_reputation_dnsbl", ASM_TO_OWASP_RULES[27][1], ASM_TO_OWASP_RULES[27][2]))
    if p.get("supply_reputation_urlhaus_count", 0) > 0:
        findings.append(("supply_reputation_urlhaus", ASM_TO_OWASP_RULES[28][1], ASM_TO_OWASP_RULES[28][2]))

    # Vulnerabilidades
    if p.get("vulnerability_count", 0) > 0:
        findings.append(("cve_detected", ASM_TO_OWASP_RULES[29][1], ASM_TO_OWASP_RULES[29][2]))
    patch_eol = p.get("patching_eol", 0)
    if patch_eol > 0:
        findings.append(("patching_eol", ASM_TO_OWASP_RULES[30][1], ASM_TO_OWASP_RULES[30][2] * min(1.0, patch_eol / 3)))

    # Credential leaks
    if p.get("credential_leak_count", 0) > 0:
        findings.append(("credential_leak", ASM_TO_OWASP_RULES[31][1], ASM_TO_OWASP_RULES[31][2]))

    # Typosquatting
    if p.get("typosquatting_count", 0) > 0:
        findings.append(("typosquatting_active", ASM_TO_OWASP_RULES[32][1], ASM_TO_OWASP_RULES[32][2]))

    # HTTP open
    puertos = p.get("puertos", "")
    if "80:open" in puertos:
        findings.append(("http_open", ASM_TO_OWASP_RULES[33][1], ASM_TO_OWASP_RULES[33][2]))

    # Redes sociales
    if p.get("social_str", ""):
        findings.append(("social_network_found", ASM_TO_OWASP_RULES[35][1], ASM_TO_OWASP_RULES[35][2]))

    # Acumular scores
    for asm_id, owasp_ids, weight in findings:
        for oid in owasp_ids:
            scores[oid] = min(1.0, scores[oid] + weight * 0.25)
            max_scores[oid] = max(max_scores[oid], weight * 0.25)
            findings_by_risk[oid].append({"id": asm_id, "weight": weight})

    # Calcular compliance (inverso del score)
    compliance_scores = {}
    for r in OWASP_AGENTIC:
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

    overall = round(sum(cs["compliance_pct"] for cs in compliance_scores.values()) / max(1, len(OWASP_AGENTIC)), 1)
    return {
        "overall_compliance": overall,
        "overall_grade": _grade(overall),
        "risks": compliance_scores,
    }


def _grade(pct: float) -> str:
    if pct >= 90: return "A"
    if pct >= 75: return "B"
    if pct >= 60: return "C"
    if pct >= 45: return "D"
    if pct >= 30: return "E"
    return "F"