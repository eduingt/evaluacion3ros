#!/usr/bin/env python3
"""
resumen_ejecutivo.py — Bloque canónico "Resumen Ejecutivo" estilo Beta1
para todos los informes. Replica la estructura de:
C:/Users/Administrator/Downloads/asm_beta1_libertynetworks.com_20260908_224806_libertynetworks.com.pdf

Sección 1:
 - Parrafo intro: evaluacion integral activa+pasiva + OSINT + vuln/leaks
 - Hallazgos principales: calificacion general + bullets dinámicos

Uso:
  from resumen_ejecutivo import render_resumen_ejecutivo
  html = render_resumen_ejecutivo(providers, asm, score_general, fecha_str, org="Incocredito")

score_general: int 0-100. Si None, se calcula como promedio domain_score.
"""
from __future__ import annotations
import html
from typing import Any

def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)

def _interpret(score: int) -> str:
    if score >= 85: return "Postura de seguridad solida"
    if score >= 70: return "Postura de seguridad aceptable con margen de mejora. Se requiere atencion en hallazgos de prioridad media y alta."
    if score >= 50: return "Postura de seguridad por debajo del promedio del sector"
    if score >= 30: return "Postura de seguridad deficiente, se requieren mejoras urgentes"
    return "Postura de seguridad critica, se requiere atencion inmediata"

def _grade_letter(s: int) -> str:
    if s >= 90: return "A"
    if s >= 80: return "B"
    if s >= 70: return "C"
    if s >= 60: return "D"
    return "F"

def _domain_score(p: dict[str, Any]) -> float:
    """Benevolo: parte de 100 y resta suave — 100 con higiene basica, baja gradual."""
    pts = 100.0
    h = p.get("https", {}) or {}
    headers = h.get("headers") or {}
    tls = p.get("tls") or {}
    dns = p.get("dns") or {}
    if not p.get("port_443", {}).get("open"): pts -= 6
    if not (isinstance(h.get("status_code"), int) and 200 <= h["status_code"] < 400): pts -= 4
    if not headers.get("strict-transport-security"): pts -= 4
    if not (headers.get("content-security-policy") or headers.get("content-security-policy-report-only")): pts -= 4
    elif p.get("csp_findings"):
        csp_f = p.get("csp_findings") or []
        if any(f.get("severity")=="high" for f in csp_f): pts -= 3
        elif csp_f: pts -= 2
    if not headers.get("x-frame-options"): pts -= 2
    if not headers.get("x-content-type-options"): pts -= 2
    if tls.get("error") or not tls.get("negotiated_version"): pts -= 6
    elif not tls.get("tls13_only_ok"): pts -= 2
    spf = dns.get("spf_record") or ""
    if not spf: pts -= 4
    elif "-all" not in spf.replace(" ","").lower(): pts -= 2
    dmarc_pol = dns.get("dmarc_policy") or ""
    if not dns.get("dmarc_record"): pts -= 4
    elif dmarc_pol not in ("reject","quarantine"): pts -= 2
    starttls = dns.get("starttls_results") or []
    if starttls and not all(s.get("starttls") for s in starttls): pts -= 2
    ip_rep = dns.get("ip_reputation") or []
    if len(ip_rep) >= 1: pts -= 4 if len(ip_rep)>=3 else 2
    urlhaus = p.get("urlhaus") or {}
    if urlhaus.get("malicious"): pts -= 3
    vulns = p.get("vulnerabilities") or []
    if len(vulns) >= 1: pts -= 4 if len(vulns)>=3 else 2
    leaks = [l for l in (p.get("credential_leaks") or []) if "error" not in l]
    if len(leaks) >= 1: pts -= 4 if len(leaks)>=3 else 2
    typos = p.get("typosquatting") or []
    if len(typos) >= 1: pts -= 3 if len(typos)>=3 else 1
    patch = p.get("patching") or []
    eol = sum(1 for x in patch if x.get("status")=="eol")
    if eol >= 1: pts -= 3 if eol>=2 else 1
    supply = p.get("supply_chain") or []
    if len(supply) > 5: pts -= 1
    takeover = p.get("takeover_risks") or []
    if any(r.get("vulnerable") for r in takeover): pts -= 5
    elif len(takeover) >= 1: pts -= 2
    cookie_f = p.get("cookie_findings") or []
    if any(f.get("severity")=="high" for f in cookie_f): pts -= 3
    elif cookie_f: pts -= 1
    scr_dnsbl = p.get("supply_reputation_dnsbl_count", 0)
    scr_urlhaus = p.get("supply_reputation_urlhaus_count", 0)
    if scr_dnsbl >= 1 or scr_urlhaus >= 1: pts -= 3 if scr_dnsbl>=2 or scr_urlhaus>=1 else 1
    return max(0.0, min(100.0, round(pts, 2)))

def render_resumen_ejecutivo(providers: list[dict[str,Any]], asm: dict[str,Any] | None = None, score_general: int | None = None, fecha_str: str = "", org: str = "Incocredito", analista: str = "@eduingt") -> str:
    n_prov = len(providers)
    # subdominios
    total_crt = sum(len(p.get("crt_subdomains") or []) for p in providers)
    total_brute = sum(len(p.get("brute_subs") or []) for p in providers)
    total_dns = sum(len(p.get("subdomains") or []) for p in providers)
    total_subs = total_crt + total_brute + total_dns
    # activos descubiertos via brute vs CT
    ct_only = total_crt
    brute_only = total_brute
    # vulns, leaks, ports, takeover, typos
    total_vulns = sum(len(p.get("vulnerabilities") or []) + len((p.get("nuclei") or {}).get("findings") or []) for p in providers)
    total_leaks = sum(len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) for p in providers)
    total_ports = sum(len([o for o in (p.get("open_ports") or []) if o.get("state")=="open"]) for p in providers)
    total_take = sum(len([r for r in (p.get("takeover_risks") or []) if r.get("vulnerable")]) for p in providers)
    total_typos = sum(len(p.get("typosquatting") or []) for p in providers)

    # score general
    if score_general is None:
        if providers:
            score_general = int(sum(_domain_score(pr) for pr in providers) / max(len(providers),1))
        else:
            score_general = 0
    score_general = max(0, min(100, int(score_general)))
    letter = _grade_letter(score_general)
    interp = _interpret(score_general)

    # dominio principal para texto
    domain_main = providers[0].get("domain","") if providers else "—"
    # objetivos texto
    org_show = org or domain_main

    bullets = [
        ("Calificacion general", f"{score_general}/100 — {interp}"),
        ("Subdominios identificados", f"{total_subs} en {n_prov} proveedor(es), de los cuales {brute_only} fueron descubiertos mediante enumeracion activa y {ct_only} mediante registros de Certificate Transparency."),
        ("Vulnerabilidades potenciales", f"{total_vulns} identificadas en las tecnologias detectadas." if total_vulns else "0 vulnerabilidades potenciales identificadas en las tecnologias detectadas."),
        ("Filtraciones de credenciales", f"{total_leaks} encontradas en bases de datos de breaches." if total_leaks else "0 filtraciones de credenciales encontradas en bases de datos de breaches."),
        ("Puertos abiertos", f"{total_ports} descubiertos en las IPs evaluadas." if total_ports else "0 puertos abiertos descubiertos en las IPs evaluadas."),
        ("Riesgo de subdomain takeover", f"{total_take} detectado(s)." if total_take else "0 riesgo(s) de subdomain takeover detectado(s)."),
        ("Typosquatting", f"{total_typos} variantes registradas y resolviendo." if total_typos else "0 variantes de typosquatting registradas."),
    ]

    # detalle coherente con la calificación (no contradice A/100)
    if score_general >= 85:
        detalle = "Sin hallazgos criticos abiertos. Mantener monitoreo continuo y revalidacion trimestral."
    elif score_general >= 70:
        detalle = "Atencion programada en hallazgos de prioridad media/alta (ventana 30-60 dias)."
    elif score_general >= 50:
        detalle = "Se requiere plan de remediacion 30-90 dias para hallazgos altos y medios."
    else:
        detalle = "Se requiere atencion inmediata en hallazgos de prioridad critica y alta."

    bullets_html = ""
    for title, desc in bullets:
        if title == "Calificacion general":
            bullets_html += f"<li style=\"margin-bottom:8px;\"><strong>{_esc(title)}: {score_general}/100 ({letter}) —</strong> {_esc(interp)}. {_esc(detalle)}</li>"
        else:
            # icono segun valor 0 = check verde, >0 = warning
            val_num = 0
            try:
                val_num = int(desc.split()[0])
            except: pass
            icon = "&#10003;" if val_num == 0 else "&#9654;"
            col = "#2E7D32" if val_num == 0 else "#1A3A4A"
            bullets_html += f"<li style=\"margin-bottom:6px; color:{col};\"><span style=\"font-weight:700;\">{_esc(title)}:</span> {_esc(desc)}</li>"

    return f"""
    <div class="sec">
        <div class="section-title">1. Resumen Ejecutivo</div>
        <div class="info-box">
            <p>Se realizo una <strong>evaluacion integral de la postura de seguridad</strong> de {_esc(domain_main)} como parte del programa de gestion de riesgos de terceros. El analisis combina <strong>tecnicas de evaluacion activa y pasiva</strong>, inteligencia de fuentes abiertas (OSINT) y consulta a <strong>bases de datos de vulnerabilidades y filtraciones conocidas</strong>.</p>
        </div>
        <div class="find-card" style="margin-top:14px;">
            <div class="fc-hdr"><span class="fc-factor">Hallazgos principales</span><span class="passive-badge">Score {score_general}/100 ({letter})</span></div>
            <div class="fc-body">
                <ul style="margin:0; padding-left:18px; font-size:9pt; line-height:1.6; color:#1F2933;">
                    {bullets_html}
                </ul>
                <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
                    <span class="s-badge {'s-critica' if score_general < 50 else 's-alta' if score_general < 70 else 's-media' if score_general < 85 else 's-baja'}">Riesgo {'CRITICO' if score_general < 50 else 'ALTO' if score_general < 70 else 'MEDIO' if score_general < 85 else 'BAJO'}</span>
                    <span style="font-size:7.5px; color:#6B7280; align-self:center;">Clasificacion: Confidencial — Solo para uso interno  •  Fuentes: DNS, CT logs, OSINT, vulndb, Nuclei/Gobuster</span>
                </div>
            </div>
        </div>
        <div style="margin-top:10px; font-size:7px; color:#9CA3AF; border-top:1px solid #D9DEE3; padding-top:6px;">
            Metodologia: ASM ligero (NIST CSF PR.DS/PR.AC, ISO 27001 A.8.23/A.8.26, PCI DSS Req 4, CIS 03/04/13, OWASP Top 10). No sustituye pentest ni auditoria de cumplimiento.
        </div>
    </div>
    """
