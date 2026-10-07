#!/usr/bin/env python3
"""
precia_scorecard.py — Gráfico estilo Precia/SecurityScorecard para todos los informes.
Replica el layout del PDF C:/Users/Administrator/Pictures/Precia-Scorecard-2026-08-18.pdf:
  - Header: Scorecard for <org> · Generated <date> · by <analista>
  - KPI grande: Threat Indicators + Score Overall
  - Grid 10 factores (5x2) con score + descripcion
  - Industry Comparison bar (precia.co vs Financial Services avg)
  - Vulnerabilities Measure (Open Ports / Site Vulns / Malware / Leaked Info)
  - Radar chart 10 ejes (SVG)

Uso desde cualquier generate_*.py:
    from precia_scorecard import factor_scores, overall_score, render_precialike_block, render_radar_svg

Scores 0-100 por factor, con deducciones transparentes basadas en datos ya recolectados
(dns, tls, headers, open_ports, vulns, leaks, csp, cookies, typos, takeover, supply, etc.)
No requiere datos nuevos.
"""
from __future__ import annotations
import html
import math
from typing import Any

FACTOR_DEFS = [
    ("NETWORK SECURITY", "Detecting insecure network settings", "network"),
    ("DNS HEALTH", "Detecting DNS insecure configurations and vulnerabilities", "dns"),
    ("PATCHING CADENCE", "Out of date company assets which may contain vulnerabilities or risks", "patching"),
    ("ENDPOINT SECURITY", "Detecting unprotected endpoints or entry points of user tools", "endpoint"),
    ("IP REPUTATION", "Detecting suspicious activity, such as malware or spam, within your company network", "iprep"),
    ("APPLICATION SECURITY", "Detecting common website application vulnerabilities", "appsec"),
    ("CUBIT SCORE", "Proprietary algorithms checking for implementation of common security best practices", "cubit"),
    ("HACKER CHATTER", "Monitoring hacker sites for chatter about your company", "chatter"),
    ("INFORMATION LEAK", "Potentially confidential company information which may have been inadvertently leaked", "leak"),
    ("SOCIAL ENGINEERING", "Measuring company awareness to a social engineering or phishing attack", "social"),
]
# Nota: "Precia" era solo el nombre de la empresa del PDF de referencia (Precia-Scorecard-2026-08-18.pdf).
# El módulo se llama precia_scorecard.py por origen, pero en los informes se muestra como "Overall Score (Scorecard)".

def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)

def _score_color(s: int) -> str:
    if s >= 90: return "#2E7D32"  # verde
    if s >= 80: return "#4CAF50"
    if s >= 70: return "#F9A825"  # amarillo
    if s >= 60: return "#EF6C00"  # naranja
    return "#C62828"  # rojo

def _score_bg(s: int) -> str:
    if s >= 90: return "#E8F5E9"
    if s >= 80: return "#E8F5E9"
    if s >= 70: return "#FFF8E1"
    if s >= 60: return "#FFF3E0"
    return "#FFEBEE"

def factor_scores(p: dict[str, Any]) -> dict[str, int]:
    """Calcula 0-100 por cada factor clave. Heurística transparente."""
    dns = p.get("dns") or {}
    https = p.get("https") or {}
    headers = https.get("headers") or {}
    tls = p.get("tls") or {}
    open_ports = [o for o in (p.get("open_ports") or []) if o.get("state") == "open"]
    vulns = p.get("vulnerabilities") or []
    leaks = [l for l in (p.get("credential_leaks") or []) if "error" not in l]
    csp_f = p.get("csp_findings") or []
    cookie_f = p.get("cookie_findings") or []
    typos = p.get("typosquatting") or []
    takeover = p.get("takeover_risks") or []
    supply = p.get("supply_chain") or []
    patching = p.get("patching") or []
    finalrecon = p.get("finalrecon") or {}
    kumo = p.get("kumo") or {}
    prism = p.get("prism") or {}
    co = p.get("claude_osint") or {}
    urlhaus = p.get("urlhaus") or {}
    ip_rep = dns.get("ip_reputation") or []
    ext = p.get("external") or {}
    # CTI chatter
    cti = co.get("cti_chatter") or {}
    rw = (cti.get("ransomwatch") or {}).get("total", 0) if isinstance(cti, dict) else 0
    rl = (cti.get("ransomware_live") or {}).get("total", 0) if isinstance(cti, dict) else 0
    total_chatter = (rw or 0) + (rl or 0)

    out: dict[str,int] = {}

    # 1 NETWORK SECURITY — puertos, TLS, HTTPS
    s = 100
    if tls.get("error"): s -= 25
    if not p.get("port_443",{}).get("open"): s -= 20
    if len(open_ports) > 5: s -= 25
    elif len(open_ports) > 3: s -= 15
    elif len(open_ports) > 1: s -= 7
    if not headers.get("strict-transport-security"): s -= 8
    if not tls.get("tls13_only_ok") and not tls.get("negotiated_version"): s -= 5
    out["network"] = max(0, min(100, s))

    # 2 DNS HEALTH — SPF/DMARC/DKIM/DNSSEC/CAA/NS/MX
    s = 100
    if not dns.get("spf_record"): s -= 20
    elif "-all" not in str(dns.get("spf_record")).replace(" ","").lower(): s -= 10
    if not dns.get("dmarc_record"): s -= 20
    elif (dns.get("dmarc_policy") or "") not in ("reject","quarantine"): s -= 10
    if not dns.get("dnssec_ok"): s -= 10
    if not p.get("caa_records"): s -= 7
    if not dns.get("dkim_records"): s -= 7
    if dns.get("ip_reputation"): s -= 5
    out["dns"] = max(0, min(100, s))

    # 3 PATCHING CADENCE — EOL, vulns
    s = 100
    eol = sum(1 for x in patching if x.get("status")=="eol")
    if eol >= 2: s -= 30
    elif eol == 1: s -= 15
    if len(vulns) >= 5: s -= 20
    elif len(vulns) >= 1: s -= 10
    # nuclei findings if any
    nuclei = p.get("nuclei") or {}
    if nuclei.get("findings"):
        sev = nuclei.get("severity_counts") or {}
        if sev.get("critical") or sev.get("high"): s -= 15
        elif sev.get("medium"): s -= 7
    out["patching"] = max(0, min(100, s))

    # 4 ENDPOINT SECURITY — takeover, endpoints expuestos, brute subs
    s = 100
    vuln_take = sum(1 for r in takeover if r.get("vulnerable"))
    if vuln_take >= 1: s -= 30
    elif len(takeover) >= 1: s -= 10
    brute = p.get("brute_subs") or []
    if len(brute) > 10: s -= 10
    if len(open_ports) > 3: s -= 10
    out["endpoint"] = max(0, min(100, s))

    # 5 IP REPUTATION — DNSBL, URLhaus, supply reputation
    s = 100
    if len(ip_rep) >= 3: s -= 30
    elif len(ip_rep) >= 1: s -= 15
    if urlhaus.get("malicious"): s -= 25
    scr = p.get("supply_chain_reputation") or {}
    if scr.get("dnsbl_count",0) >= 2: s -= 15
    elif scr.get("dnsbl_count",0) >= 1: s -= 7
    if scr.get("urlhaus_count",0) >= 1: s -= 10
    out["iprep"] = max(0, min(100, s))

    # 6 APPLICATION SECURITY — CSP, cookies, vulns headers, WAF
    s = 100
    if not (headers.get("content-security-policy") or headers.get("content-security-policy-report-only")): s -= 20
    elif csp_f:
        crit = sum(1 for f in csp_f if f.get("severity")=="high")
        if crit: s -= 15
        else: s -= 7
    if any(f.get("severity")=="high" for f in cookie_f): s -= 15
    elif cookie_f: s -= 7
    if not headers.get("x-frame-options"): s -= 7
    if not headers.get("x-content-type-options"): s -= 5
    # nuclei vulns already counted but also appsec
    if vulns and len(vulns) >= 3: s -= 10
    out["appsec"] = max(0, min(100, s))

    # 7 CUBIT SCORE — best practices composite (domain_score-like)
    # promedio de varios best practices
    s = 100
    checks = 0
    fails = 0
    for ok in [
        bool(headers.get("strict-transport-security")),
        bool(headers.get("content-security-policy") or headers.get("content-security-policy-report-only")),
        bool(headers.get("x-frame-options")),
        bool(headers.get("x-content-type-options")),
        bool(dns.get("spf_record")),
        bool(dns.get("dmarc_record")),
        bool(dns.get("dnssec_ok")),
        bool(p.get("caa_records")),
        bool(p.get("mta_sts")),
        bool(tls.get("tls13_only_ok") or tls.get("negotiated_version")),
    ]:
        checks += 1
        if not ok: fails += 1
    s -= fails * 7
    # waf/cloud as positive
    waf = p.get("waf_detection") or {}
    if waf.get("detected"): s = min(100, s+3)
    out["cubit"] = max(0, min(100, s))

    # 8 HACKER CHATTER — ransomwatch, ransomware.live, HN
    s = 100
    if total_chatter >= 3: s -= 30
    elif total_chatter >= 1: s -= 15
    # breach intel also counts as chatter
    bi = (kumo.get("breachintel") or {}).get("summary") or {}
    if bi.get("total_employees_leaked",0) >= 5: s -= 10
    out["chatter"] = max(0, min(100, s))

    # 9 INFORMATION LEAK — leaks, breach intel, finalrecon wayback
    s = 100
    if len(leaks) >= 3: s -= 30
    elif len(leaks) >= 1: s -= 15
    wayback_api = int((finalrecon.get("wayback") or {}).get("stats",{}).get("API endpoints","0") or 0)
    wayback_js = int((finalrecon.get("wayback") or {}).get("stats",{}).get("JS files","0") or 0)
    if wayback_api >= 1: s -= 10
    if wayback_js >= 20: s -= 7
    js_secrets = (kumo.get("js_secrets") or {}).get("secrets") or []
    if len(js_secrets) >= 3: s -= 15
    elif len(js_secrets) >= 1: s -= 7
    out["leak"] = max(0, min(100, s))

    # 10 SOCIAL ENGINEERING — typosquatting, social
    s = 100
    if len(typos) >= 3: s -= 25
    elif len(typos) >= 1: s -= 12
    # supply chain phishing risk via typo of supply?
    if len(supply) > 10: s -= 5
    out["social"] = max(0, min(100, s))

    return out

def factor_incidences(p: dict[str, Any]) -> dict[str, int]:
    """Cuenta incidencias por factor (misma lógica que factor_scores, pero cuenta)."""
    dns = p.get("dns") or {}
    https = p.get("https") or {}
    headers = https.get("headers") or {}
    tls = p.get("tls") or {}
    open_ports = [o for o in (p.get("open_ports") or []) if o.get("state") == "open"]
    vulns = p.get("vulnerabilities") or []
    leaks = [l for l in (p.get("credential_leaks") or []) if "error" not in l]
    csp_f = p.get("csp_findings") or []
    cookie_f = p.get("cookie_findings") or []
    typos = p.get("typosquatting") or []
    takeover = p.get("takeover_risks") or []
    supply = p.get("supply_chain") or []
    patching = p.get("patching") or []
    finalrecon = p.get("finalrecon") or {}
    kumo = p.get("kumo") or {}
    co = p.get("claude_osint") or {}
    urlhaus = p.get("urlhaus") or {}
    ip_rep = dns.get("ip_reputation") or []
    cti = co.get("cti_chatter") or {}
    rw = (cti.get("ransomwatch") or {}).get("total", 0) if isinstance(cti, dict) else 0
    rl = (cti.get("ransomware_live") or {}).get("total", 0) if isinstance(cti, dict) else 0
    total_chatter = (rw or 0) + (rl or 0)
    out: dict[str,int] = {}
    # 1 network: cuenta cada deducción como 1 incidencia
    inc = 0
    if tls.get("error"): inc += 1
    if not p.get("port_443",{}).get("open"): inc += 1
    if len(open_ports) > 1: inc += 1
    if not headers.get("strict-transport-security"): inc += 1
    if not tls.get("tls13_only_ok") and not tls.get("negotiated_version"): inc += 1
    out["network"] = inc
    inc = 0
    if not dns.get("spf_record"): inc += 1
    elif "-all" not in str(dns.get("spf_record")).replace(" ","").lower(): inc += 1
    if not dns.get("dmarc_record"): inc += 1
    elif (dns.get("dmarc_policy") or "") not in ("reject","quarantine"): inc += 1
    if not dns.get("dnssec_ok"): inc += 1
    if not p.get("caa_records"): inc += 1
    if not dns.get("dkim_records"): inc += 1
    if dns.get("ip_reputation"): inc += 1
    out["dns"] = inc
    inc = 0
    if sum(1 for x in patching if x.get("status")=="eol") >= 1: inc += 1
    if len(vulns) >= 1: inc += 1
    if (p.get("nuclei") or {}).get("findings"): 
        sev = (p.get("nuclei") or {}).get("severity_counts") or {}
        if sev.get("critical") or sev.get("high") or sev.get("medium"): inc += 1
    out["patching"] = inc
    inc = 0
    if sum(1 for r in takeover if r.get("vulnerable")) >= 1: inc += 1
    elif len(takeover) >= 1: inc += 1
    if len(p.get("brute_subs") or []) > 10: inc += 1
    if len(open_ports) > 3: inc += 1
    out["endpoint"] = inc
    inc = 0
    if len(ip_rep) >= 1: inc += 1
    if urlhaus.get("malicious"): inc += 1
    scr = p.get("supply_chain_reputation") or {}
    if scr.get("dnsbl_count",0) >= 1: inc += 1
    if scr.get("urlhaus_count",0) >= 1: inc += 1
    out["iprep"] = inc
    inc = 0
    if not (headers.get("content-security-policy") or headers.get("content-security-policy-report-only")): inc += 1
    elif csp_f: inc += 1
    if cookie_f: inc += 1
    if not headers.get("x-frame-options"): inc += 1
    if not headers.get("x-content-type-options"): inc += 1
    if vulns and len(vulns) >= 3: inc += 1
    out["appsec"] = inc
    inc = 0
    for ok in [bool(headers.get("strict-transport-security")), bool(headers.get("content-security-policy") or headers.get("content-security-policy-report-only")), bool(headers.get("x-frame-options")), bool(headers.get("x-content-type-options")), bool(dns.get("spf_record")), bool(dns.get("dmarc_record")), bool(dns.get("dnssec_ok")), bool(p.get("caa_records")), bool(p.get("mta_sts")), bool(tls.get("tls13_only_ok") or tls.get("negotiated_version"))]:
        if not ok: inc += 1
    out["cubit"] = inc
    inc = 0
    if total_chatter >= 1: inc += 1
    if (kumo.get("breachintel") or {}).get("summary",{}).get("total_employees_leaked",0) >= 5: inc += 1
    out["chatter"] = inc
    inc = 0
    if len(leaks) >= 1: inc += 1
    if int((finalrecon.get("wayback") or {}).get("stats",{}).get("API endpoints","0") or 0) >= 1: inc += 1
    if int((finalrecon.get("wayback") or {}).get("stats",{}).get("JS files","0") or 0) >= 20: inc += 1
    if len((kumo.get("js_secrets") or {}).get("secrets") or []) >= 1: inc += 1
    out["leak"] = inc
    inc = 0
    if len(typos) >= 1: inc += 1
    if len(supply) > 10: inc += 1
    out["social"] = inc
    return out

def overall_score(factors: dict[str,int]) -> int:
    if not factors: return 0
    vals = list(factors.values())
    # ponderacion: network, dns, patching, iprep, appsec pesan 1.2x (criticos)
    weights = {"network":1.2,"dns":1.2,"patching":1.2,"endpoint":1.0,"iprep":1.2,"appsec":1.2,"cubit":0.8,"chatter":0.8,"leak":1.0,"social":0.9}
    tot_w = sum(weights.get(k,1.0) for k in vals)
    # actually sum weighted
    s = 0.0
    wsum = 0.0
    for k,v in factors.items():
        w = weights.get(k,1.0)
        s += v * w
        wsum += w
    return int(round(s / wsum)) if wsum else 0

def threat_indicators(p: dict[str,Any], factors: dict[str,int] | None = None) -> int:
    # conteo de hallazgos ponderados (similar a SecurityScorecard Threat Indicators)
    cnt = 0
    cnt += len([f for f in (p.get("csp_findings") or [])])
    cnt += len([f for f in (p.get("cookie_findings") or [])])
    cnt += len([l for l in (p.get("credential_leaks") or []) if "error" not in l])
    cnt += len(p.get("typosquatting") or [])
    cnt += len([r for r in (p.get("takeover_risks") or []) if r.get("vulnerable")])
    cnt += len([o for o in (p.get("open_ports") or []) if o.get("state")=="open"])
    cnt += len(p.get("vulnerabilities") or [])
    cnt += len((p.get("nuclei") or {}).get("findings") or [])
    cnt += len((p.get("gobuster") or {}).get("modes",{}).get("dir",{}).get("findings") or [])
    # vuln por IP reputation
    cnt += len((p.get("dns") or {}).get("ip_reputation") or [])
    if (p.get("urlhaus") or {}).get("malicious"): cnt += 2
    return cnt

def render_radar_svg(factors: dict[str,int], size: int = 360, title: str = "", industry_avg: int | None = None) -> str:
    """Radar 10 ejes 0-100, grillas 60/80/100, etiquetas. Si industry_avg se pasa, dibuja polígono discontinuo del promedio sectorial."""
    labels = [lbl for lbl,_desc,_key in FACTOR_DEFS]
    keys = [k for _lbl,_desc,k in FACTOR_DEFS]
    n = len(keys)
    cx = cy = size // 2
    r_max = size * 0.38
    # colores
    grid_color = "#D9DEE3"
    # helper polar
    def polar(idx: int, val: float):
        ang = math.radians(-90 + idx * 360 / n)
        r = r_max * (val / 100.0)
        return (cx + r * math.cos(ang), cy + r * math.sin(ang))
    svg = f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg" style="font-family:Arial,Helvetica,sans-serif;">'
    # fondo por umbrales — ahora sí visible: 0-60 rojo, 60-70 naranja, 70-80 amarillo, 80-100 verde claro
    for pct, fill, op in [(60, "#FFEBEE", 0.55),(70, "#FFF3E0", 0.5),(80, "#FFF8E1", 0.45),(100, "#E8F5E9", 0.4)]:
        pts = " ".join(f"{polar(i,pct)[0]:.1f},{polar(i,pct)[1]:.1f}" for i in range(n))
        # relleno de banda
        svg += f'<polygon points="{pts}" fill="{fill}" stroke="none" opacity="{op}"/>'
        # borde
        svg += f'<polygon points="{pts}" fill="none" stroke="{grid_color}" stroke-width="1" opacity="0.35"/>'
        svg += f'<text x="{cx}" y="{cy - r_max*pct/100 - 4}" text-anchor="middle" font-size="6" fill="#9CA3AF">{pct}</text>'
    # axes
    for i in range(n):
        x,y = polar(i,100)
        svg += f'<line x1="{cx}" y1="{cy}" x2="{x}" y2="{y}" stroke="{grid_color}" stroke-width="0.8" opacity="0.6"/>'
    # industry average polygon (discontinua) — si se pasa
    if industry_avg is not None:
        ipts = " ".join(f"{polar(i,industry_avg)[0]:.1f},{polar(i,industry_avg)[1]:.1f}" for i in range(n))
        svg += f'<polygon points="{ipts}" fill="none" stroke="#9CA3AF" stroke-width="1.8" stroke-dasharray="6,4" opacity="0.9"/>'
        # etiqueta pequeña
        svg += f'<text x="{cx}" y="{cy - r_max*industry_avg/100 - 10}" text-anchor="middle" font-size="5.5" font-weight="700" fill="#6B7280">Industry avg {industry_avg}</text>'
    # data polygon
    vals = [factors.get(k,0) for k in keys]
    pts = " ".join(f"{polar(i,vals[i])[0]:.1f},{polar(i,vals[i])[1]:.1f}" for i in range(n))
    svg += f'<polygon points="{pts}" fill="#2F6F9F" fill-opacity="0.18" stroke="#173B57" stroke-width="2.2" stroke-linejoin="round"/>'
    for i,v in enumerate(vals):
        x,y = polar(i,v)
        col = _score_color(v)
        svg += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{col}" stroke="white" stroke-width="1.5"/>'
        # valor siempre visible en su color correspondiente
        ang = math.radians(-90 + i*360/n)
        lx = x + 9 * math.cos(ang)
        ly = y + 9 * math.sin(ang)
        svg += f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" font-size="6.5" font-weight="800" fill="{col}" stroke="white" stroke-width="0.3" paint-order="stroke">{v}</text>'
    # labels outside
    for i,lab in enumerate(labels):
        ang = math.radians(-90 + i*360/n)
        lx = cx + (r_max + 22) * math.cos(ang)
        ly = cy + (r_max + 22) * math.sin(ang)
        anchor = "middle"
        if 10 < (i*36) < 170: anchor = "start"
        elif 190 < (i*36) < 350: anchor = "end"
        # abreviar
        short = lab.replace("SECURITY","SEC.").replace("HEALTH","").strip()
        svg += f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="{anchor}" font-size="6.5" font-weight="700" fill="#1A3A4A">{_esc(short)}</text>'
    if title:
        svg += f'<text x="{cx}" y="{size-8}" text-anchor="middle" font-size="7" fill="#6B7280">{_esc(title)}</text>'
    svg += "</svg>"
    return svg

INDUSTRY_AVG = {
    "Financial Services": 88, "Banking": 88, "Insurance": 86, "Healthcare": 82,
    "Telecommunications": 84, "Technology": 85, "Retail": 83, "Manufacturing": 81,
    "Energy & Utilities": 80, "Government": 78, "Education": 79, "Professional Services": 84,
}
INDUSTRY_KEYWORDS = {
    "Banking": ["bank","banco","bancolombia","cibest","financial","fintech","credit","credito","incocredito","banc"],
    "Insurance": ["insurance","seguro","seguros","aseguradora","assurance"],
    "Healthcare": ["health","salud","hospital","clinic","medical","pharma","ips","eps"],
    "Telecommunications": ["telecom","telco","libertynetworks","networks","communications","comcel","movil","celular","tigo","claro"],
    "Technology": ["tech","software","systems","digital","cloud","saas","it ","informatica","techno"],
    "Retail": ["retail","shop","store","commerce","mall","tienda","exito","alkosto"],
    "Manufacturing": ["manufacturing","industrial","factory","manufactura","fabrica","produccion"],
    "Energy & Utilities": ["energy","energia","utility","power","oil","gas","electric","epm","enel","isa"],
    "Government": ["gov","gobierno","estado","ministerio","alcaldia","municipio","gobernacion","contraloria"],
    "Education": ["edu","university","universidad","college","school","campus","colegio","instituto","politécnico"],
    "Professional Services": ["consulting","services","servicios","professional","legal","audit","consultoria","abogados"],
    "Financial Services": ["financial","fintech"],
}

def detect_industry(p: dict[str,Any]) -> str:
    # override explícito en providers.json
    for k in ("sector","industry","industria"):
        v = p.get(k)
        if v and isinstance(v, str):
            vv = v.strip()
            for canon in INDUSTRY_AVG:
                if vv.lower() == canon.lower():
                    return canon
            # si viene texto libre, buscar coincidencia parcial
            for canon in INDUSTRY_AVG:
                if canon.lower() in vv.lower() or vv.lower() in canon.lower():
                    return canon
            return vv  # devuelve tal cual si no está en tabla
    # autodetección por texto: domain + name + whois + website_analyzer + org_attribution
    blob_parts = []
    for key in ("domain","name","id"):
        v = p.get(key)
        if v: blob_parts.append(str(v))
    ext = p.get("external") or {}
    whois = ext.get("whois") or {}
    if whois.get("registrant_organization"): blob_parts.append(str(whois["registrant_organization"]))
    if whois.get("registrar"): blob_parts.append(str(whois["registrar"]))
    prism = p.get("prism") or {}
    wa = prism.get("website_analyzer") or {}
    if wa.get("title"): blob_parts.append(str(wa["title"]))
    if wa.get("technologies"): blob_parts.append(" ".join(wa["technologies"]))
    co = p.get("claude_osint") or {}
    org_attr = co.get("org_attribution") or {}
    if org_attr.get("legal_name"): blob_parts.append(str(org_attr["legal_name"]))
    if org_attr.get("lei"): blob_parts.append(str(org_attr["lei"]))
    # juntar blob lower
    blob = " ".join(blob_parts).lower()
    best = None
    best_hits = 0
    for industry, kws in INDUSTRY_KEYWORDS.items():
        hits = sum(1 for kw in kws if kw.lower() in blob)
        if hits > best_hits:
            best_hits = hits
            best = industry
    if best and best_hits >= 1:
        return best
    return "Financial Services"

def render_precialike_block(p: dict[str,Any], analista: str = "@eduingt", org: str | None = None, generated: str | None = None, industry: str | None = None) -> str:
    """Bloque HTML estilo Precia Scorecard listo para incrustar en cualquier informe."""
    domain = p.get("domain","")
    org_show = org or domain or p.get("name","")
    scores = factor_scores(p)
    overall = overall_score(scores)
    threats = threat_indicators(p, scores)
    detected_industry = industry or detect_industry(p)
    industry_avg = INDUSTRY_AVG.get(detected_industry, 88)
    # vulnerabilities measure
    open_ports = len([o for o in (p.get("open_ports") or []) if o.get("state")=="open"])
    site_vulns = len(p.get("vulnerabilities") or []) + len((p.get("nuclei") or {}).get("findings") or [])
    malware = 1 if (p.get("urlhaus") or {}).get("malicious") or (p.get("dns") or {}).get("ip_reputation") else 0
    leaked = len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) + len(((p.get("kumo") or {}).get("breachintel") or {}).get("summary",{}).get("breach_names",[]) or [])

    # factor cards html — estilo PDF: tarjetas blancas, score grande coloreado, borde fino + incidencias
    incidences = factor_incidences(p)
    cards_html = ""
    for label, desc, key in FACTOR_DEFS:
        s = scores.get(key, 0)
        inc = incidences.get(key, 0)
        col = _score_color(s)
        inc_bg = "#E8F5E9" if inc==0 else "#FFF3E0" if inc==1 else "#FFEBEE"
        inc_col = "#2E7D32" if inc==0 else "#EF6C00" if inc==1 else "#C62828"
        inc_text = "0 incidencias" if inc==0 else f"{inc} incidencia" if inc==1 else f"{inc} incidencias"
        cards_html += f"""
        <div style="flex:1 1 18%; min-width:155px; max-width:19%; background:#fff; border:1px solid #E5E7EB; border-radius:10px; padding:10px 8px 8px; text-align:center; display:flex; flex-direction:column; justify-content:space-between; box-shadow:0 1px 2px rgba(0,0,0,0.04);">
          <div style="display:flex; justify-content:center; align-items:center; gap:6px;">
            <div style="font-size:28px; font-weight:800; color:{col}; line-height:1;">{s}</div>
            <span style="font-size:7px; font-weight:700; color:{inc_col}; background:{inc_bg}; border:1px solid #E5E7EB; border-radius:10px; padding:2px 6px;">{inc_text}</span>
          </div>
          <div style="font-size:7px; font-weight:800; letter-spacing:0.06em; color:#111827; text-transform:uppercase; line-height:1.2; margin-top:6px; min-height:22px;">{_esc(label)}</div>
          <div style="font-size:6px; color:#6B7280; line-height:1.35; margin-top:4px; min-height:30px;">{_esc(desc)}</div>
        </div>"""

    # industry bar SVG — sector autodetectado
    def bar_svg():
        w, h = 320, 70
        maxv = 100
        x0 = 30
        y0 = 12
        bh = 18
        def bar(x, y, val, col):
            ww = (val/maxv) * 160
            return f'<rect x="{x}" y="{y}" width="{ww}" height="{bh}" rx="4" fill="{col}"/><text x="{x+ww+6}" y="{y+12}" font-size="9" font-weight="700" fill="{col}">{val}</text>'
        svg = f'<svg width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg" style="font-family:Arial,Helvetica,sans-serif;">'
        svg += f'<text x="{x0}" y="{y0}" font-size="7" font-weight="700" fill="#1A3A4A">Industry Comparison: {_esc(detected_industry)}</text>'
        svg += f'<text x="{x0}" y="{y0+20}" font-size="7" fill="#6B7280">{_esc(org_show)} (you)</text>'
        svg += bar(x0+110, y0+10, overall, "#173B57")
        svg += f'<text x="{x0}" y="{y0+46}" font-size="7" fill="#6B7280">Industry average ({_esc(detected_industry)})</text>'
        svg += bar(x0+110, y0+36, industry_avg, "#9CA3AF")
        svg += "</svg>"
        return svg

    radar = render_radar_svg(scores, size=340, title="", industry_avg=industry_avg)

    gen_str = generated or ""
    return f"""
    <section style="background:#fff; border:1px solid #E5E7EB; border-radius:12px; overflow:hidden; margin:18px 0; page-break-inside:avoid; font-family:Arial,Helvetica,sans-serif;">
      <!-- Header estilo Precia PDF: blanco, tipografia SecurityScorecard -->
      <div style="padding:18px 20px 14px; border-bottom:1px solid #E5E7EB;">
        <div style="font-size:8px; letter-spacing:0.18em; color:#6B7280; text-transform:uppercase; text-align:center;">SECURITY SUMMARY REPORT</div>
        <div style="font-size:22px; font-weight:800; color:#111827; text-align:center; margin-top:4px; letter-spacing:-0.02em;">Scorecard for {_esc(org_show)}</div>
        <div style="font-size:8px; color:#6B7280; text-align:center; margin-top:3px;">Generated { _esc(gen_str) } by { _esc(analista) }, GrupoCibest &nbsp;·&nbsp; CONFIDENCIAL — Uso interno</div>
        <div style="font-size:7px; color:#9CA3AF; text-align:center; margin-top:2px; letter-spacing:0.06em;">powered by ASM &nbsp;·&nbsp; SecurityScorecard style</div>
      </div>
      <div style="padding:12px 18px; display:flex; justify-content:space-between; align-items:center; background:#F9FAFB; border-bottom:1px solid #E5E7EB;">
        <div style="text-align:center; flex:1;">
          <div style="font-size:42px; font-weight:800; line-height:1; color:{_score_color(overall)};">{overall}</div>
          <div style="font-size:7px; letter-spacing:0.1em; color:#6B7280; text-transform:uppercase; margin-top:2px; font-weight:700;">Puntuación Global</div>
        </div>
        <div style="width:1px; height:52px; background:#E5E7EB; margin:0 12px;"></div>
        <div style="text-align:center; flex:1;">
          <div style="font-size:32px; font-weight:800; line-height:1; color:#111827;">{threats}</div>
          <div style="font-size:7px; letter-spacing:0.1em; color:#6B7280; text-transform:uppercase; margin-top:2px; font-weight:700;">Threat Indicators</div>
        </div>
        <div style="flex:1; text-align:right; font-size:6.5px; color:#9CA3AF; line-height:1.4;">Industry avg ~{industry_avg}/100<br/>{_esc(detected_industry)}</div>
      </div>
      <div style="padding:14px 14px 8px; background:#fff;">
        <div style="display:flex; flex-wrap:wrap; gap:8px; justify-content:center;">{cards_html}</div>
      </div>
      <div style="display:flex; gap:14px; padding:10px 14px 14px; flex-wrap:wrap; align-items:stretch;">
        <div style="flex:1 1 340px; background:#F3F5F7; border:1px solid #D9DEE3; border-radius:8px; padding:10px; text-align:center;">
          <div style="font-size:7px; font-weight:700; letter-spacing:0.08em; color:#1A3A4A; text-transform:uppercase; margin-bottom:6px;">Vulnerabilities Measure — {_esc(detected_industry)}</div>
          <div style="display:flex; gap:8px; justify-content:center; flex-wrap:wrap;">
            <div style="flex:1; background:#fff; border:1px solid #D9DEE3; border-radius:6px; padding:8px;">
              <div style="font-size:18px; font-weight:800; color:#1A3A4A;">{open_ports}</div>
              <div style="font-size:6.5px; color:#6B7280; text-transform:uppercase; letter-spacing:0.05em;">Open Ports</div>
            </div>
            <div style="flex:1; background:#fff; border:1px solid #D9DEE3; border-radius:6px; padding:8px;">
              <div style="font-size:18px; font-weight:800; color:#1A3A4A;">{site_vulns}</div>
              <div style="font-size:6.5px; color:#6B7280; text-transform:uppercase; letter-spacing:0.05em;">Site Vulns</div>
            </div>
            <div style="flex:1; background:#fff; border:1px solid #D9DEE3; border-radius:6px; padding:8px;">
              <div style="font-size:18px; font-weight:800; color:{'#C62828' if malware else '#2E7D32'};">{malware}</div>
              <div style="font-size:6.5px; color:#6B7280; text-transform:uppercase; letter-spacing:0.05em;">Malware</div>
            </div>
            <div style="flex:1; background:#fff; border:1px solid #D9DEE3; border-radius:6px; padding:8px;">
              <div style="font-size:18px; font-weight:800; color:#1A3A4A;">{leaked}</div>
              <div style="font-size:6.5px; color:#6B7280; text-transform:uppercase; letter-spacing:0.05em;">Leaked Info</div>
            </div>
          </div>
          <div style="margin-top:10px; background:#fff; border:1px solid #D9DEE3; border-radius:6px; padding:6px;">{bar_svg()}</div>
          <div style="font-size:6px; color:#9CA3AF; margin-top:6px; line-height:1.4; text-align:left;">Industry avg {_esc(detected_industry)} ~{industry_avg}/100 · Autodetectado por keywords (WHOIS/website/GLEIF) — override con <code>providers.json: "sector": "Healthcare"</code>.</div>
        </div>
        <div style="flex:0 0 420px; background:#fff; border:1px solid #D9DEE3; border-radius:8px; padding:10px; text-align:center;">
          <div style="font-size:7px; font-weight:700; letter-spacing:0.08em; color:#1A3A4A; text-transform:uppercase;">Risk Panorama (10 factores 0-100)</div>
          <div style="display:flex; gap:10px; align-items:center; margin-top:6px;">
            <div style="flex:1;">{radar}</div>
            <div style="flex:0 0 110px; text-align:left; font-size:6.5px; line-height:1.4; color:#374151; background:#F9FAFB; border:1px solid #E5E7EB; border-radius:6px; padding:8px;">
              <div style="font-weight:800; color:#1A3A4A; margin-bottom:6px; font-size:7px; text-transform:uppercase; letter-spacing:0.05em;">Leyenda</div>
              <div style="display:flex; align-items:center; gap:6px; margin-bottom:4px;"><span style="width:10px; height:10px; background:#2E7D32; border-radius:2px; display:inline-block;"></span> 90-100 Verde — Excelente</div>
              <div style="display:flex; align-items:center; gap:6px; margin-bottom:4px;"><span style="width:10px; height:10px; background:#F9A825; border-radius:2px; display:inline-block;"></span> 70-89 Amarillo — Aceptable</div>
              <div style="display:flex; align-items:center; gap:6px; margin-bottom:4px;"><span style="width:10px; height:10px; background:#EF6C00; border-radius:2px; display:inline-block;"></span> 60-69 Naranja — Deficiente</div>
              <div style="display:flex; align-items:center; gap:6px; margin-bottom:6px;"><span style="width:10px; height:10px; background:#C62828; border-radius:2px; display:inline-block;"></span> &lt;60 Rojo — Crítico</div>
              <div style="border-top:1px solid #E5E7EB; margin:6px 0;"></div>
              <div style="display:flex; align-items:center; gap:6px; margin-bottom:4px;"><span style="width:14px; height:0; border-top:2.5px solid #173B57; display:inline-block; vertical-align:middle;"></span> Sólido azul = Tú ({org_show[:18]})</div>
              <div style="display:flex; align-items:center; gap:6px; margin-bottom:4px;"><span style="width:14px; height:0; border-top:1.5px dashed #9CA3AF; display:inline-block; vertical-align:middle;"></span> Discontinua gris = Industria ({_esc(detected_industry)} {industry_avg})</div>
              <div style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:10px; border:1px solid #D1D5DB; border-radius:50%; display:inline-block;"></span> Anillo ext. = 100</div>
              <div style="margin-top:6px; font-size:5.5px; color:#6B7280; line-height:1.3; font-style:italic;">Valores &lt;70 en amarillo/rojo requieren plan. Ponderación: Network/DNS/Patching/IPRep/AppSec ×1.2</div>
            </div>
          </div>
          <div style="margin-top:4px; font-size:6px; color:#6B7280; text-align:center;"><span style="display:inline-block; width:8px; height:8px; background:#2F6F9F; opacity:0.18; border:1px solid #173B57; vertical-align:middle; margin-right:4px;"></span> Tú ({org_show}) <span style="margin:0 8px; display:inline-block; width:12px; height:0; border-top:1.5px dashed #9CA3AF; vertical-align:middle;"></span> Industria {_esc(detected_industry)}</div>
        </div>
      </div>
      <div style="font-size:6px; color:#9CA3AF; padding:8px 14px 10px; border-top:1px solid #D9DEE3; line-height:1.4;">
        Security-related analyses, including ratings, and statements in the Content of this document are statements of opinion of relative future security risks as of the date they are expressed, and not statements of current or historical fact. Parties disclaim warranties of merchantability, accuracy, completeness and fitness for purpose. Views expressed are those of authors and do not reflect official policy of GrupoCibest.
      </div>
    </section>
    """
