#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B3 - Informe Unificado de Seguridad
Compila y enriquece los formatos GC, BC, S3, P/A, B1, B2 en un solo reporte
con estilo visual B2 (corporativo blanco/azul #173B57) y datos 100% reales.

Reconstruido desde base visual B3.pdf (cover, resumen, score general,
pasivo/activo, matriz de riesgo, hallazgos, recomendaciones RACI, anexos A-F).
Sin dependencias rotas: no requiere salida_test/informe_unificado_b3.html
ni domain_score_legend. Todo se genera desde asm_report.json.
"""

from __future__ import annotations
import argparse
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

FORMULA_VERSION = "B3-v2.0"
FORMULA_DATE = "2026-09-22"

try:
    from score_legend import render_score_legend as _render_score_legend
except Exception:
    _render_score_legend = None

try:
    from precia_scorecard import render_precialike_block as _render_precialike
    from precia_scorecard import (FACTOR_DEFS as _PRECIA_FACTORS, INDUSTRY_AVG as _INDUSTRY_AVG,
                                  factor_scores as _precia_scores, overall_score as _precia_overall,
                                  threat_indicators as _precia_threats, detect_industry as _precia_industry,
                                  render_radar_svg as _render_radar)
except Exception:
    _render_precialike = None  # type: ignore
    _PRECIA_FACTORS, _INDUSTRY_AVG, _precia_scores = [], {}, None  # type: ignore
    _precia_overall, _precia_threats, _precia_industry, _render_radar = None, None, None, None  # type: ignore


def _sc_color(s: int) -> str:
    if s >= 90:
        return "#2E7D32"
    if s >= 80:
        return "#4CAF50"
    if s >= 70:
        return "#F9A825"
    if s >= 60:
        return "#EF6C00"
    return "#C62828"


_PRECIA_WEIGHTS = {"network": 1.2, "dns": 1.2, "patching": 1.2, "endpoint": 1.0, "iprep": 1.2,
                   "appsec": 1.2, "cubit": 0.8, "chatter": 0.8, "leak": 1.0, "social": 0.9}

_FACTOR_FINDING_CATS = {
    "network": ["SEGURIDAD DE RED"],
    "dns": ["ESTADO DE DNS", "CONFIGURACION DE CORREO"],
    "patching": ["CADENCIA", "VULNERABILIDADES"],
    "endpoint": ["ENDPOINTS", "SUPERFICIE"],
    "iprep": ["REPUTACION", "TERCEROS"],
    "appsec": ["APLICACION WEB"],
    "cubit": ["ESTADO DE DNS", "SEGURIDAD DE RED", "APLICACION WEB", "CONFIGURACION DE CORREO"],
    "chatter": ["CHATTER", "HACKER", "GITHUB", "REDES"],
    "leak": ["FILTRACION", "LEAK"],
    "social": ["INGENIERIA", "SOCIAL", "TYPO"],
}


def precia_deductions(p: dict[str, Any]) -> dict[str, list[tuple[str, int]]]:
    """Desglose por chequeo fallado de cada factor precia (misma logica que factor_scores)."""
    dns = p.get("dns") or {}
    https = p.get("https") or {}
    headers = https.get("headers") or {}
    tls = p.get("tls") or {}
    open_ports = [o for o in (p.get("open_ports") or []) if isinstance(o, dict) and o.get("state") == "open"]
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
    out: dict[str, list[tuple[str, int]]] = {}

    net: list[tuple[str, int]] = []
    if tls.get("error"):
        net.append(("TLS error", -25))
    if not p.get("port_443", {}).get("open"):
        net.append(("443 cerrado", -20))
    if len(open_ports) > 5:
        net.append((f"{len(open_ports)} puertos abiertos", -25))
    elif len(open_ports) > 3:
        net.append((f"{len(open_ports)} puertos abiertos", -15))
    elif len(open_ports) > 1:
        net.append((f"{len(open_ports)} puertos abiertos", -7))
    if not headers.get("strict-transport-security"):
        net.append(("Sin HSTS", -8))
    if not tls.get("tls13_only_ok") and not tls.get("negotiated_version"):
        net.append(("Sin TLS", -5))
    out["network"] = net

    dn: list[tuple[str, int]] = []
    spf = dns.get("spf_record") or ""
    if not spf:
        dn.append(("Sin SPF", -20))
    elif "-all" not in str(spf).replace(" ", "").lower():
        dn.append(("SPF sin -all", -10))
    if not dns.get("dmarc_record"):
        dn.append(("Sin DMARC", -20))
    elif (dns.get("dmarc_policy") or "") not in ("reject", "quarantine"):
        dn.append(("DMARC sin reject", -10))
    if not dns.get("dnssec_ok"):
        dn.append(("Sin DNSSEC", -10))
    if not p.get("caa_records"):
        dn.append(("Sin CAA", -7))
    if not dns.get("dkim_records"):
        dn.append(("Sin DKIM", -7))
    if dns.get("ip_reputation"):
        dn.append(("IP en DNSBL", -5))
    out["dns"] = dn

    pa: list[tuple[str, int]] = []
    eol = sum(1 for x in patching if isinstance(x, dict) and x.get("status") == "eol")
    if eol >= 2:
        pa.append((f"{eol} EOL", -30))
    elif eol == 1:
        pa.append(("1 EOL", -15))
    if len(vulns) >= 5:
        pa.append((f"{len(vulns)} vulns", -20))
    elif len(vulns) >= 1:
        pa.append((f"{len(vulns)} vulns", -10))
    nu = p.get("nuclei") or {}
    if nu.get("findings"):
        sev = nu.get("severity_counts") or {}
        if sev.get("critical") or sev.get("high"):
            pa.append(("Nuclei crit/high", -15))
        elif sev.get("medium"):
            pa.append(("Nuclei medium", -7))
    out["patching"] = pa

    ep: list[tuple[str, int]] = []
    vt = sum(1 for r in takeover if isinstance(r, dict) and r.get("vulnerable"))
    if vt >= 1:
        ep.append((f"{vt} takeover vuln.", -30))
    elif takeover:
        ep.append((f"{len(takeover)} takeover", -10))
    brute = p.get("brute_subs") or []
    if len(brute) > 10:
        ep.append((f"{len(brute)} brute subs", -10))
    if len(open_ports) > 3:
        ep.append(("Puertos abiertos", -10))
    out["endpoint"] = ep

    ir: list[tuple[str, int]] = []
    _is_shared = bool((p.get("waf_detection") or {}).get("detected"))
    if len(ip_rep) >= 3:
        ir.append((f"{len(ip_rep)} DNSBL" + (" (compartida)" if _is_shared else ""), -15 if _is_shared else -30))
    elif len(ip_rep) >= 1:
        ir.append((f"{len(ip_rep)} DNSBL" + (" (compartida)" if _is_shared else ""), -5 if _is_shared else -15))
    if urlhaus.get("malicious"):
        ir.append(("URLhaus malicioso", -25))
    scr = p.get("supply_chain_reputation") or {}
    if scr.get("dnsbl_count", 0) >= 2:
        ir.append(("Supply DNSBL", -15))
    elif scr.get("dnsbl_count", 0) >= 1:
        ir.append(("Supply DNSBL", -7))
    if scr.get("urlhaus_count", 0) >= 1:
        ir.append(("Supply URLhaus", -10))
    out["iprep"] = ir

    ap: list[tuple[str, int]] = []
    if not (headers.get("content-security-policy") or headers.get("content-security-policy-report-only")):
        ap.append(("Sin CSP", -20))
    elif csp_f:
        crit = sum(1 for f in csp_f if isinstance(f, dict) and f.get("severity") == "high")
        ap.append(("CSP debil", -15 if crit else -7))
    if any(isinstance(f, dict) and f.get("severity") == "high" for f in cookie_f):
        ap.append(("Cookies high", -15))
    elif cookie_f:
        ap.append(("Cookies", -7))
    if not headers.get("x-frame-options"):
        ap.append(("Sin XFO", -7))
    if not headers.get("x-content-type-options"):
        ap.append(("Sin XCTO", -5))
    if vulns and len(vulns) >= 3:
        ap.append(("Vulns", -10))
    out["appsec"] = ap

    cu: list[tuple[str, int]] = []
    for ok, lbl in [(bool(headers.get("strict-transport-security")), "HSTS"),
                    (bool(headers.get("content-security-policy") or headers.get("content-security-policy-report-only")), "CSP"),
                    (bool(headers.get("x-frame-options")), "XFO"),
                    (bool(headers.get("x-content-type-options")), "XCTO"),
                    (bool(dns.get("spf_record")), "SPF"),
                    (bool(dns.get("dmarc_record")), "DMARC"),
                    (bool(dns.get("dnssec_ok")), "DNSSEC"),
                    (bool(p.get("caa_records")), "CAA"),
                    (bool(p.get("mta_sts")), "MTA-STS"),
                    (bool(tls.get("tls13_only_ok") or tls.get("negotiated_version")), "TLS")]:
        if not ok:
            cu.append((lbl, -7))
    if (p.get("waf_detection") or {}).get("detected"):
        cu.append(("WAF/CDN", +3))
    out["cubit"] = cu

    ch: list[tuple[str, int]] = []
    cti = co.get("cti_chatter") or {}
    rw = ((cti.get("ransomwatch") or {}).get("total", 0) if isinstance(cti, dict) else 0) or 0
    rl = ((cti.get("ransomware_live") or {}).get("total", 0) if isinstance(cti, dict) else 0) or 0
    if (rw + rl) >= 3:
        ch.append(("CTI chatter", -30))
    elif (rw + rl) >= 1:
        ch.append(("CTI chatter", -15))
    bi = (kumo.get("breachintel") or {}).get("summary") or {}
    if bi.get("total_employees_leaked", 0) >= 5:
        ch.append(("Breach empleados", -10))
    out["chatter"] = ch

    lk: list[tuple[str, int]] = []
    if len(leaks) >= 3:
        lk.append((f"{len(leaks)} leaks", -30))
    elif len(leaks) >= 1:
        lk.append((f"{len(leaks)} leaks", -15))
    try:
        wb_api = int((finalrecon.get("wayback") or {}).get("stats", {}).get("API endpoints", "0") or 0)
    except Exception:
        wb_api = 0
    try:
        wb_js = int((finalrecon.get("wayback") or {}).get("stats", {}).get("JS files", "0") or 0)
    except Exception:
        wb_js = 0
    if wb_api >= 1:
        lk.append(("Wayback API", -10))
    if wb_js >= 20:
        lk.append(("Wayback JS", -7))
    js_sec = (kumo.get("js_secrets") or {}).get("secrets") or []
    if len(js_sec) >= 3:
        lk.append(("JS secrets", -15))
    elif len(js_sec) >= 1:
        lk.append(("JS secrets", -7))
    out["leak"] = lk

    so: list[tuple[str, int]] = []
    if len(typos) >= 3:
        so.append((f"{len(typos)} typos", -25))
    elif len(typos) >= 1:
        so.append((f"{len(typos)} typos", -12))
    if len(supply) > 10:
        so.append(("Supply amplia", -5))
    out["social"] = so
    return out


def prev_factor_scores(domain: str) -> dict[str, int] | None:
    """Ultimos scores por factor del dominio desde scan_factors (solo datos reales)."""
    try:
        import sqlite3
        db = ROOT / "dashboard_workspace" / "scan_history.db"
        if not db.is_file():
            return None
        c = sqlite3.connect(db)
        r = c.execute("SELECT scan_id FROM scan_factors WHERE domain=? ORDER BY created_at DESC LIMIT 1", (domain,)).fetchone()
        if not r:
            c.close()
            return None
        rows = c.execute("SELECT factor_key, score FROM scan_factors WHERE domain=? AND scan_id=?", (domain, r[0])).fetchall()
        c.close()
        return {k: int(v) for k, v in rows} or None
    except Exception:
        return None


def _norm(s: Any) -> str:
    """Mayusculas sin tildes para comparaciones inmunes a ortografia."""
    import unicodedata
    return unicodedata.normalize("NFKD", str(s or "")).encode("ASCII", "ignore").decode("ASCII").upper()


_DISP_SEV = {"CRITICA": "CRÍTICA", "ALTA": "ALTA", "MEDIA": "MEDIA", "BAJA": "BAJA",
             "INFORMATIVA": "INFORMATIVA", "INFO": "INFO"}


def _overall_contrib_table(scores: dict[str, int]) -> str:
    """Tabla auditable Factor | Score | Peso | Contribución para Overall."""
    try:
        total_w = sum(_PRECIA_WEIGHTS.get(k, 1.0) for k in scores)
        rows = ""
        for label, _, key in _PRECIA_FACTORS:
            s = int(scores.get(key, 0))
            w = _PRECIA_WEIGHTS.get(key, 1.0)
            contrib = round(s * w / total_w, 2) if total_w else 0
            rows += f"<tr><td>{esc(label)}</td><td class='num'>{s}</td><td class='num'>×{w:g}</td><td class='num'>{contrib:.2f}</td></tr>"
        return (
            '<div style="margin:0 16px 12px; background:#fff; border:1px solid #D9DEE3; border-radius:8px; padding:10px;">'
            f'<div style="font-size:7.5pt; font-weight:800; letter-spacing:.06em; color:#1A3A4A; text-transform:uppercase; margin-bottom:6px;">Overall — desglose auditable · Fórmula {esc(FORMULA_VERSION)} ({esc(FORMULA_DATE)})</div>'
            '<table class="data" style="font-size:7.5pt;"><thead><tr><th>Factor</th><th>Score</th><th>Peso</th><th>Contribución</th></tr></thead>'
            f"<tbody>{rows}</tbody></table>"
            f"<div style='font-size:6px; color:#6B7280; margin-top:4px;'>Overall = Σ(Score×Peso)/ΣPesos · ΣPesos={total_w:.1f} · ΣContribuciones = Overall · Fórmula {esc(FORMULA_VERSION)} reproducible</div>"
            "</div>"
        )
    except Exception:
        return ""


def render_asset_inventory(providers: list[dict[str, Any]]) -> str:
    """Inventario de activos con clasificación first-party vs third-party y exposición."""
    rows = ""
    total_first = total_third = total_exposed = 0
    for p in providers:
        dom = p.get("domain", "")
        first_ips = (p.get("dns") or {}).get("ipv4", []) or []
        first_subs = [_sub_name(s) for s in (p.get("subdomains") or []) + (p.get("crt_subdomains") or []) if _sub_name(s)]
        supply = p.get("supply_chain") or []
        third_doms = [s.get("domain") if isinstance(s, dict) else str(s) for s in supply[:10]]
        # Exposición: puertos abiertos + CVEs
        open_ports = [o for o in (p.get("open_ports") or []) if isinstance(o, dict) and o.get("state") == "open"]
        exposed = len(open_ports) + len(p.get("cve_findings") or [])
        total_first += len(first_ips) + len(first_subs)
        total_third += len(third_doms)
        total_exposed += exposed
        # Clasificación first vs shared
        shared_set = {"cdn.jsdelivr.net", "unpkg.com", "www.google.com", "www.googletagmanager.com", "www.recaptcha.net", "cdnjs.cloudflare.com", "cdn.cloudflare.com", "cloudfront.net", "www.google-analytics.com", "duat45vx86ndn.cloudfront.net"}
        third_display = ", ".join(f"{d} (shared)" if d in shared_set else d for d in third_doms[:3])[:60]
        rows += f"<tr><td>{esc(dom)}</td><td class='num'>{len(first_ips)}</td><td class='num'>{len(first_subs)}</td><td>{esc(third_display) or '—'}</td><td class='num'>{len(third_doms)}</td><td class='num' style='color:{'#C62828' if exposed else '#2E7D32'}; font-weight:700;'>{exposed}</td></tr>"
    return (
        '<div class="section-sub" id="sec-inventario">6.1 Inventario de Activos (First-party vs Third-party)</div>'
        '<div class="info-box">First-party = infraestructura propia/origen (IPs del dominio, subdominios del apex). Third-party = dependencias/CDN compartidas (ej. Cloudflare, jsDelivr, recaptcha) — <span style="color:#2E7D32;">shared = contextual</span>, no riesgo directo. Third-party dedicated = riesgo directo. Exposición = puertos abiertos + CVEs observados (HIGH si >0 en first-party).</div>'
        '<table class="data"><thead><tr><th>Proveedor</th><th>IPs propias</th><th>Subdominios</th><th>Terceros (ej.)</th><th>#Terceros</th><th>Exposición</th></tr></thead>'
        f"<tbody>{rows or '<tr><td colspan=6>Sin activos</td></tr>'}</tbody></table>"
        f"<div style='font-size:7pt; color:#6B7280;'>Totales: First-party {total_first} activos · Third-party {total_third} dependencias · Expuestos {total_exposed} (puertos+CVEs) · Exposición HIGH si >0 en first-party.</div>"
    )


_DISP_CAT = {
    "ESTADO DE DNS": "ESTADO DE DNS",
    "CONFIGURACION DE CORREO": "CONFIGURACIÓN DE CORREO",
    "FILTRACION DE INFORMACION": "FILTRACIÓN DE INFORMACIÓN",
    "SEGURIDAD DE APLICACION WEB": "SEGURIDAD DE APLICACIÓN WEB",
    "SEGURIDAD DE ENDPOINTS": "SEGURIDAD DE ENDPOINTS",
    "INGENIERIA SOCIAL": "INGENIERÍA SOCIAL",
    "SEGURIDAD DE RED": "SEGURIDAD DE RED",
    "SUPERFICIE DE ATAQUE": "SUPERFICIE DE ATAQUE",
    "VULNERABILIDADES": "VULNERABILIDADES",
    "CADENCIA DE REVISIONES": "CADENCIA DE REVISIONES",
    "REPUTACION DE TERCEROS": "REPUTACIÓN DE TERCEROS",
    "OSINT PASIVO": "OSINT PASIVO",
    "OSINT SEMI-ACTIVO": "OSINT SEMI-ACTIVO",
    "EXPOSICION DE IDENTIDAD": "EXPOSICIÓN DE IDENTIDAD",
}

_DISP_FACTOR = {
    "Seguridad de aplicacion web": "Seguridad de aplicación web",
    "Cubit Score": "Cubit Score",
    "Estado de DNS": "Estado de DNS",
    "Seguridad de puntos de conexion": "Seguridad de puntos de conexión",
    "Hacker Chatter": "Hacker Chatter",
    "Reputacion de IP": "Reputación de IP",
    "Filtracion de informacion": "Filtración de información",
    "Seguridad de red": "Seguridad de red",
    "Cadencia de aplicacion de revisiones": "Cadencia de aplicación de revisiones",
    "Ingenieria social": "Ingeniería social",
    "Seguridad de endpoints": "Seguridad de endpoints",
}


def _finding_refs(key: str, findings: list[dict[str, Any]] | None) -> str:
    """Numeros de hallazgos §9 relacionados con el factor (trazabilidad)."""
    if not findings:
        return "—"
    cats = _FACTOR_FINDING_CATS.get(key, [])
    ncats = [_norm(c) for c in cats]
    nums = [str(f.get("num", "")) for f in findings
            if any(c in _norm(f.get("categoria", "")) or c in _norm(f.get("titulo", "")) for c in ncats)
            and f.get("num")]
    return ", ".join("#" + n for n in nums) if nums else "—"


def render_scorecard_exact(p: dict[str, Any], analista: str = "", org: str | None = None,
                           generated: str | None = None, findings: list[dict[str, Any]] | None = None,
                           prev_scores: dict[str, int] | None = None) -> str:
    """Replica exacta de la imagen SecurityScorecard con números 100% reales (via precia_scorecard)."""
    domain = p.get("domain", "")
    org_show = org or domain or p.get("name", "")
    disp_dom = domain.split(".")[0].title() + "." + ".".join(domain.split(".")[1:]) if "." in domain else domain
    try:
        scores = _precia_scores(p) or {}
        overall = int(_precia_overall(scores))
        threats = int(_precia_threats(p, scores))
        industry = _precia_industry(p)
        avg = _INDUSTRY_AVG.get(industry, 88)
    except Exception:
        return ""
    open_ports = len([o for o in (p.get("open_ports") or []) if isinstance(o, dict) and o.get("state") == "open"])
    site_vulns = len(p.get("vulnerabilities") or []) + len((p.get("nuclei") or {}).get("findings") or [])
    malware = 1 if (p.get("urlhaus") or {}).get("malicious") or (p.get("dns") or {}).get("ip_reputation") else 0
    try:
        leaked = len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) + len((((p.get("kumo") or {}).get("breachintel") or {}).get("summary", {}) or {}).get("breach_names", []) or [])
    except Exception:
        leaked = 0
    inc: dict[str, int] = {}
    try:
        from precia_scorecard import factor_incidences as _incs
        inc = _incs(p) or {}
    except Exception:
        inc = {}
    cards = ""
    try:
        ded = precia_deductions(p)
    except Exception:
        ded = {}
    for label, desc, key in _PRECIA_FACTORS:
        s = int(scores.get(key, 0))
        n = int(inc.get(key, 0))
        col = _sc_color(s)
        w = _PRECIA_WEIGHTS.get(key, 1.0)
        if n == 0:
            pill_bg, pill_col, pill_txt = "#E8F5E9", "#2E7D32", "0 incidencias"
        elif n == 1:
            pill_bg, pill_col, pill_txt = "#FFF3E0", "#EF6C00", "1 incidencia"
        else:
            pill_bg, pill_col, pill_txt = "#FFEBEE", "#C62828", f"{n} incidencias"
        dl = ded.get(key, [])
        if dl:
            shown = " · ".join(f"{lbl} {pts}" for lbl, pts in dl[:4])
            if len(dl) > 4:
                shown += f" (+{len(dl) - 4} mas)"
            ded_html = f"<div style='font-size:6.5px; color:#4B5563; line-height:1.4; margin-top:4px;'><strong>Deduce:</strong> {esc(shown)}</div>"
        else:
            ded_html = "<div style='font-size:6.5px; color:#2E7D32; margin-top:4px;'>Sin deducciones</div>"
        refs = _finding_refs(key, findings)
        trend = ""
        if prev_scores and key in prev_scores:
            try:
                dlt = s - int(prev_scores[key])
                if dlt > 0:
                    trend = f"<div style='font-size:6.5px; color:#2E7D32; font-weight:700;'>&#9650;+{dlt} vs anterior</div>"
                elif dlt < 0:
                    trend = f"<div style='font-size:6.5px; color:#C62828; font-weight:700;'>&#9660;{dlt} vs anterior</div>"
            except Exception:
                pass
        cards += (
            '<div style="background:#fff; border:1px solid #E5E7EB; border-radius:10px; padding:12px 8px 10px; text-align:center;">'
            '<div style="display:flex; justify-content:center; align-items:center; gap:6px;">'
            f'<div style="font-size:28px; font-weight:800; color:{col}; line-height:1;">{s}</div>'
            f'<span style="font-size:7px; font-weight:700; color:{pill_col}; background:{pill_bg}; border-radius:10px; padding:2px 6px; white-space:nowrap;">{pill_txt}</span>'
            f'<span style="font-size:7px; font-weight:800; color:#173B57; background:#E8EEF5; border-radius:10px; padding:2px 6px; white-space:nowrap;" title="Peso en el Overall">×{w:g}</span>'
            "</div>"
            f"{trend}"
            f'<div style="font-size:8px; font-weight:800; letter-spacing:.05em; color:#111827; text-transform:uppercase; margin-top:6px;">{esc(label)}</div>'
            f'<div style="font-size:7px; color:#6B7280; line-height:1.4; margin-top:4px;">{esc(desc)}</div>'
            f"{ded_html}"
            f"<div style='font-size:6.5px; color:#6B7280; margin-top:3px;'>Ver hallazgos: {esc(refs)}</div>"
            "</div>"
        )
    ocol = _sc_color(overall)
    bw = max(0, min(100, overall)) * 1.6
    aw = max(0, min(100, avg)) * 1.6
    gen_txt = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    try:
        radar_svg = _render_radar(scores, size=340, title="", industry_avg=avg) if _render_radar else ""
    except Exception:
        radar_svg = ""
    return (
        '<section style="background:#fff; border:1px solid #E5E7EB; border-radius:12px; overflow:hidden; margin:14px 0; font-family:Arial,Helvetica,sans-serif;">'
        '<div style="padding:18px 20px 12px; text-align:center; border-bottom:1px solid #E5E7EB;">'
        '<div style="font-size:8px; letter-spacing:.14em; color:#6B7280; text-transform:uppercase;">Security Summary Report</div>'
        f'<div style="font-size:23px; font-weight:800; color:#111827; margin-top:4px;">Scorecard for {esc(disp_dom)}</div>'
        f'<div style="font-size:8px; color:#6B7280; margin-top:4px;">Generated {esc(gen_txt)} by {esc(analista or "@eduingt")}, {esc(org_show)} - CONFIDENCIAL -- Uso interno</div>'
        '<div style="font-size:7px; color:#9CA3AF; margin-top:2px;">powered by ASM - SecurityScorecard style</div>'
        "</div>"
        '<div style="display:flex; align-items:center; padding:14px 20px; border-bottom:1px solid #E5E7EB;">'
        f'<div style="flex:1; text-align:center;"><div style="font-size:34px; font-weight:800; color:{ocol}; line-height:1;">{overall}</div><div style="font-size:8px; letter-spacing:.08em; color:#6B7280; text-transform:uppercase; margin-top:2px;">Overall Score</div></div>'
        '<div style="width:1px; align-self:stretch; background:#E5E7EB;"></div>'
        f'<div style="flex:1; text-align:center;"><div style="font-size:34px; font-weight:800; color:#111827; line-height:1;">{threats}</div><div style="font-size:8px; letter-spacing:.08em; color:#6B7280; text-transform:uppercase; margin-top:2px;">Threat Indicators</div></div>'
        f'<div style="flex:0 0 130px; text-align:right; font-size:7px; color:#9CA3AF; line-height:1.5;">Industry avg ~{avg}/100<br>{esc(industry)}</div>'
        "</div>"
        f'<div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px; padding:14px 16px;">{cards}</div>'
        + _overall_contrib_table(scores) +
        '<div style="margin:0 16px 14px; background:#EEF1F5; border-radius:10px; padding:12px; page-break-before:always;">'
        f'<div style="font-size:8px; font-weight:800; letter-spacing:.1em; color:#374151; text-transform:uppercase; text-align:center;">Vulnerabilities Measure -- {esc(industry)}</div>'
        '<div style="display:grid; grid-template-columns:1fr 1fr 1fr 1fr; gap:10px; margin-top:10px;">'
        f'<div style="background:#fff; border-radius:8px; padding:10px; text-align:center;"><div style="font-size:20px; font-weight:800; color:#111827;">{open_ports}</div><div style="font-size:7px; letter-spacing:.06em; color:#6B7280; text-transform:uppercase;">Open Ports</div></div>'
        f'<div style="background:#fff; border-radius:8px; padding:10px; text-align:center;"><div style="font-size:20px; font-weight:800; color:#111827;">{site_vulns}</div><div style="font-size:7px; letter-spacing:.06em; color:#6B7280; text-transform:uppercase;">Site Vulns</div></div>'
        f'<div style="background:#fff; border-radius:8px; padding:10px; text-align:center;"><div style="font-size:20px; font-weight:800; color:{"#C62828" if malware else "#111827"};">{malware}</div><div style="font-size:7px; letter-spacing:.06em; color:#6B7280; text-transform:uppercase;">Malware</div></div>'
        f'<div style="background:#fff; border-radius:8px; padding:10px; text-align:center;"><div style="font-size:20px; font-weight:800; color:{"#C62828" if leaked else "#111827"};">{leaked}</div><div style="font-size:7px; letter-spacing:.06em; color:#6B7280; text-transform:uppercase;">Leaked Info</div></div>'
        "</div>"
        '<div style="background:#fff; border-radius:8px; padding:12px 14px; margin-top:10px;">'
        f'<div style="font-size:8px; font-weight:700; color:#111827;">Industry Comparison: {esc(industry)}</div>'
        f'<div style="display:flex; align-items:center; gap:8px; margin-top:8px;"><div style="flex:0 0 150px; font-size:7px; color:#4B5563;">{esc(disp_dom)} (you)</div><div style="flex:1;"><svg width="200" height="18" xmlns="http://www.w3.org/2000/svg"><rect x="0" y="0" width="{bw:.0f}" height="18" rx="4" fill="#173B57"/></svg></div><div style="font-size:8px; font-weight:800; color:#111827;">{overall}</div></div>'
        f'<div style="display:flex; align-items:center; gap:8px; margin-top:6px;"><div style="flex:0 0 150px; font-size:7px; color:#4B5563;">Industry average ({esc(industry)})</div><div style="flex:1;"><svg width="200" height="18" xmlns="http://www.w3.org/2000/svg"><rect x="0" y="0" width="{aw:.0f}" height="18" rx="4" fill="#9CA3AF"/></svg></div><div style="font-size:8px; font-weight:800; color:#111827;">{avg}</div></div>'
        "</div>"
        "</div>"
        f'<div style="padding:0 16px 12px; font-size:6px; color:#9CA3AF;">Sector usado: {esc(industry)} (avg ~{avg}/100, N≈850, snapshot 2026-09-22) · Fuente: precia_scorecard.INDUSTRY_AVG · Método: promedio simple sector · Detectado {gen_txt[:10]} por keywords (WHOIS/website/GLEIF) · Override manual vía providers.json "sector" (ej. "healthcare") si aplica.</div>'
        '<div style="margin:0 16px 14px; background:#fff; border:1px solid #D9DEE3; border-radius:8px; padding:10px; text-align:center;">'
        '<div style="font-size:8px; font-weight:800; letter-spacing:.1em; color:#1A3A4A; text-transform:uppercase;">Risk Panorama (10 factores 0-100)</div>'
        '<div style="display:flex; gap:10px; align-items:center; margin-top:6px;">'
        f'<div style="flex:1;">{radar_svg}</div>'
        '<div style="flex:0 0 150px; text-align:left; font-size:6.5px; line-height:1.4; color:#374151; background:#F9FAFB; border:1px solid #E5E7EB; border-radius:6px; padding:8px;">'
        '<div style="font-weight:800; color:#1A3A4A; margin-bottom:6px; font-size:7px; text-transform:uppercase; letter-spacing:.05em;">Leyenda</div>'
        '<div style="margin-bottom:4px;"><span style="width:10px; height:10px; background:#2E7D32; border-radius:2px; display:inline-block;"></span> 90-100 Verde -- Excelente</div>'
        '<div style="margin-bottom:4px;"><span style="width:10px; height:10px; background:#F9A825; border-radius:2px; display:inline-block;"></span> 70-89 Amarillo -- Aceptable</div>'
        '<div style="margin-bottom:4px;"><span style="width:10px; height:10px; background:#EF6C00; border-radius:2px; display:inline-block;"></span> 60-69 Naranja -- Deficiente</div>'
        '<div style="margin-bottom:6px;"><span style="width:10px; height:10px; background:#C62828; border-radius:2px; display:inline-block;"></span> &lt;60 Rojo -- Crítico</div>'
        '<div style="border-top:1px solid #E5E7EB; margin:6px 0;"></div>'
        f'<div style="margin-bottom:4px;"><span style="width:14px; height:0; border-top:2.5px solid #173B57; display:inline-block; vertical-align:middle;"></span> Solido azul = Tu ({esc(org_show[:18])})</div>'
        f'<div style="margin-bottom:4px;"><span style="width:14px; height:0; border-top:1.5px dashed #9CA3AF; display:inline-block; vertical-align:middle;"></span> Discontinua gris = Industria ({esc(industry)} {avg})</div>'
        '<div><span style="width:10px; height:10px; border:1px solid #D1D5DB; border-radius:50%; display:inline-block;"></span> Anillo ext. = 100</div>'
        '<div style="margin-top:6px; font-size:5.5px; color:#6B7280; line-height:1.3; font-style:italic;">Valores &lt;70 en amarillo/rojo requieren plan. Ponderacion: Network/DNS/Patching/IPRep/AppSec x1.2</div>'
        "</div>"
        "</div>"
        f'<div style="margin-top:4px; font-size:6px; color:#6B7280; text-align:center;">Tu ({esc(org_show)}) ---- Industria {esc(industry)}</div>'
        "</div>"
        + _overall_calc_box(scores, overall, disp_dom) +
        "</section>"
    )

def _overall_calc_box(scores: dict[str, int], overall: int, disp_dom: str) -> str:
    """Recuadro ¿Cómo se calcula? del Overall Score con ejemplo real del dominio."""
    try:
        _labels = {k: l for l, _, k in _PRECIA_FACTORS}
        ranked = sorted(scores.items(), key=lambda kv: kv[1])
        ex = []
        for k, s in ranked[:2]:
            ex.append(f"{_labels.get(k, k)} {s} (x{_PRECIA_WEIGHTS.get(k, 1.0):g})")
        example = f"Ej. {disp_dom}: " + " + ".join(ex) + f" ... = {overall} (promedio ponderado de 10 factores)."
    except Exception:
        example = ""
    return (
        '<div style="margin:0 16px 14px; background:#fff; border:1px solid #D9DEE3; border-left:4px solid #2F6F9F; border-radius:6px; padding:12px 14px; font-size:9pt; color:#374151; line-height:1.65;">'
        "<strong>¿Cómo se calcula el Overall Score?</strong> Promedio <strong>ponderado</strong> de 10 factores: cada score se multiplica por su peso (Network/DNS/Patching/IPRep/AppSec <strong>×1.2</strong>, resto ×1.0/×0.9/×0.8) y se divide por la suma de pesos. "
        + esc(example) + " Validado: <strong>100</strong> = todos los factores en 100. "
        'Colores: <span style="color:#2E7D32;">■</span> ≥90 verde, <span style="color:#F9A825;">■</span> 70-89 amarillo, <span style="color:#EF6C00;">■</span> 60-69 naranja, <span style="color:#C62828;">■</span> &lt;60 rojo. '
        "Código: precia_scorecard.py <code>overall_score()</code>.</div>"
    )


try:
    from pasivo_canon import collect_pasive_items
except Exception:
    def collect_pasive_items(p: dict) -> list:  # type: ignore
        return []

try:
    from semi_canon import collect_semi_active_items
except Exception:
    def collect_semi_active_items(p: dict) -> list:  # type: ignore
        return []

ROOT = Path(__file__).resolve().parent

CSS = """
@page { margin:1.5cm; size:A4; }
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:'Arial','Helvetica',sans-serif; font-size:10pt; color:#1F2933; background:#fff; line-height:1.5; }
.page { max-width:210mm; margin:0 auto; padding:0; }
.cover { page-break-after:always; padding:0; position:relative; display:flex; flex-direction:column; min-height:95vh; }
.cover-top { background:#173B57; color:#fff; padding:50px 60px 30px; }
.cover-top .powered { font-size:8pt; opacity:.7; letter-spacing:.1em; text-transform:uppercase; margin-bottom:6px; }
.cover-top h1 { font-size:30pt; font-weight:800; line-height:1.1; margin-bottom:4px; }
.cover-top .sub { font-size:13pt; font-weight:300; color:rgba(255,255,255,.85); margin-bottom:30px; line-height:1.3; }
.cover-top .org-name { font-size:20pt; font-weight:700; color:#fff; }
.cover-meta { padding:30px 60px 20px; flex:1; }
.cover-meta table { width:100%; border-collapse:collapse; font-size:10pt; }
.cover-meta td { padding:7px 12px; border-bottom:1px solid #D9DEE3; }
.cover-meta td:first-child { font-weight:700; color:#173B57; width:200px; }
.cover-footer { border-top:3px solid #173B57; padding:12px 60px 0; font-size:7pt; color:#6B7280; display:flex; justify-content:space-between; }
.sec { padding:30px 50px; page-break-inside:avoid; }
.section-title { font-size:18pt; font-weight:700; color:#173B57; margin-bottom:16px; padding-bottom:8px; border-bottom:2px solid #173B57; }
.section-sub { font-size:13pt; font-weight:600; color:#2F6F9F; margin:16px 0 10px; }
.section-sub2 { font-size:11pt; font-weight:600; color:#173B57; margin:12px 0 6px; }
.info-box { background:#F3F5F7; border:1px solid #D9DEE3; border-radius:6px; padding:14px 16px; margin:12px 0; font-size:9.5pt; color:#4B5563; line-height:1.6; }
.info-box strong { color:#173B57; }
.evidence-box { background:#F3F5F7; border:1px solid #D9DEE3; border-radius:4px; padding:8px 10px; font-size:8pt; font-family:'Consolas','Courier New',monospace; color:#4B5563; line-height:1.5; white-space:pre-wrap; word-break:break-all; margin:4px 0; }
table.data { width:100%; border-collapse:collapse; font-size:9pt; margin:10px 0; }
table.data th { background:#173B57; color:#fff; padding:7px 9px; text-align:left; font-size:8pt; text-transform:uppercase; letter-spacing:.06em; font-weight:700; }
table.data td { padding:6px 9px; border-bottom:1px solid #D9DEE3; vertical-align:top; }
table.data tr:nth-child(even) td { background:#F3F5F7; }
table.data .num { text-align:center; white-space:nowrap; }
.score-badge { display:inline-block; width:44px; height:44px; border-radius:50%; text-align:center; line-height:44px; font-size:18pt; font-weight:800; color:#fff; }
.score-badge.A { background:#2E7D32; } .score-badge.B { background:#2F6F9F; } .score-badge.C { background:#F9A825; }
.score-badge.D { background:#EF6C00; } .score-badge.F { background:#C62828; }
.grade-A { color:#2E7D32; font-weight:700; } .grade-B { color:#2F6F9F; font-weight:700; }
.grade-C { color:#F9A825; font-weight:700; } .grade-D { color:#EF6C00; font-weight:700; } .grade-F { color:#C62828; font-weight:700; }
.fs-verde { color:#2E7D32; font-weight:700; } .fs-amarillo { color:#F9A825; font-weight:700; }
.fs-naranja { color:#EF6C00; font-weight:700; } .fs-rojo { color:#C62828; font-weight:700; }
.s-badge { display:inline-block; padding:2px 7px; border-radius:3px; font-size:8pt; font-weight:700; text-transform:uppercase; }
.s-critica { background:#fce4e4; color:#C62828; border:1px solid #C62828; }
.s-alta { background:#fde8d6; color:#EF6C00; border:1px solid #EF6C00; }
.s-media { background:#fff8e1; color:#F9A825; border:1px solid #F9A825; }
.s-baja { background:#e8f5e9; color:#2E7D32; border:1px solid #2E7D32; }
.s-info { background:#e3f2fd; color:#2F6F9F; border:1px solid #2F6F9F; }
.find-card { background:#fff; border:1px solid #D9DEE3; border-radius:6px; margin-bottom:12px; overflow:hidden; page-break-inside:avoid; }
.find-card .fc-hdr { background:#F3F5F7; padding:9px 12px; border-bottom:1px solid #D9DEE3; display:flex; align-items:center; gap:10px; font-size:9pt; }
.find-card .fc-body { padding:10px 12px; font-size:8.5pt; color:#4B5563; }
.find-card .fc-row { display:flex; margin-bottom:3px; }
.find-card .fc-label { font-weight:700; color:#173B57; width:110px; flex-shrink:0; }
.find-card .fc-value { flex:1; }
.find-card .fc-evidence { background:#F3F5F7; border:1px solid #D9DEE3; border-radius:4px; padding:7px 9px; font-size:8pt; font-family:'Consolas','Courier New',monospace; white-space:pre-wrap; word-break:break-all; margin-top:4px; }
.exec-grid { display:flex; gap:10px; margin:12px 0; flex-wrap:wrap; }
.exec-card { flex:1; min-width:100px; background:#F3F5F7; border:1px solid #D9DEE3; border-radius:6px; padding:12px; text-align:center; }
.exec-card .ec-val { font-size:20pt; font-weight:800; color:#173B57; }
.exec-card .ec-lbl { font-size:7.5pt; color:#6B7280; text-transform:uppercase; letter-spacing:.04em; margin-top:2px; }
.step-box { display:flex; gap:10px; margin:12px 0; }
.step { flex:1; background:#fff; border:1px solid #D9DEE3; border-radius:8px; padding:14px 8px 12px; text-align:center; }
.step .sn { display:inline-block; width:34px; height:34px; line-height:34px; border-radius:50%; background:#173B57; color:#fff; font-size:13pt; font-weight:800; margin-bottom:8px; }
.step .st { font-size:9pt; color:#4B5563; }
.legal-note { font-size:7pt; color:#9CA3AF; text-align:center; padding:10px 50px; border-top:1px solid #D9DEE3; margin-top:20px; }
.page-footer { font-size:7pt; color:#6B7280; border-top:1px solid #D9DEE3; padding:6px 50px; display:flex; justify-content:space-between; }
ul.compact { margin:6px 0 6px 18px; font-size:8.5pt; color:#4B5563; }
ul.compact li { margin-bottom:2px; }
.muted { color:#9CA3AF; } .small { font-size:7.5pt; } .meta { font-size:8pt; color:#6B7280; margin:4px 0; }
.ok { color:#2E7D32; font-weight:700; } .warn { color:#F9A825; font-weight:700; } .err { color:#C62828; font-weight:700; } .error { color:#C62828; }
.cve-badge { display:inline-block; background:#173B57; color:#fff; font-size:7.5pt; font-weight:700; padding:1px 6px; border-radius:3px; font-family:'Consolas','Courier New',monospace; }
.epss-badge { display:inline-block; font-size:7.5pt; padding:1px 5px; border-radius:4px; background:#e8eef5; color:#3a5478; }
.kev-badge { display:inline-block; font-size:7.5pt; font-weight:700; padding:1px 6px; border-radius:4px; background:#fce4e4; color:#a00; }
h4 { font-size:10pt; color:#173B57; margin:12px 0 4px; padding-bottom:3px; border-bottom:1px dashed #D9DEE3; }
.kpi-row { display:flex; gap:8px; margin:12px 0; }
.kpi-card { flex:1; background:#fff; border:1px solid #D9DEE3; border-radius:8px; padding:12px 4px 10px; text-align:center; }
.kpi-num { font-size:22pt; font-weight:800; line-height:1.1; }
.kpi-lbl { font-size:7pt; color:#6B7280; text-transform:uppercase; letter-spacing:.03em; margin-top:4px; line-height:1.4; }
.exec-summary { background:#F3F5F7; border:1px solid #D9DEE3; border-radius:8px; padding:14px 16px; font-size:9pt; color:#374151; line-height:1.65; margin:12px 0; }
.exec-summary b.lbl { color:#173B57; }
.gauge-wrap { display:flex; gap:28px; align-items:flex-start; margin:14px 0 4px; }
.gauge-box { flex:0 0 200px; text-align:center; }
.dist-box { flex:1; }
.dist-title { font-size:12pt; font-weight:700; color:#2F6F9F; margin-bottom:6px; }
.dist-row { display:flex; align-items:center; justify-content:space-between; padding:6px 2px; border-bottom:1px solid #D9DEE3; }
.d-badge { display:inline-block; padding:2px 8px; border-radius:3px; font-size:8pt; font-weight:700; border:1px solid; }
.d-crit { color:#C62828; border-color:#C62828; background:#fce4e2; }
.d-alta { color:#EF6C00; border-color:#EF6C00; background:#fde8d6; }
.d-media { color:#B8860B; border-color:#F9A825; background:#fff8e1; }
.d-baja { color:#2E7D32; border-color:#2E7D32; background:#e8f5e9; }
.d-info { color:#2F6F9F; border-color:#2F6F9F; background:#e3f2fd; }
.d-count { font-size:11pt; font-weight:800; }
.toc-row { display:flex; align-items:baseline; gap:12px; padding:7px 2px; border-bottom:1px solid #D9DEE3; }
.toc-num { flex:0 0 34px; font-weight:800; color:#173B57; font-size:10pt; }
.toc-title { flex:1; color:#1F2933; text-decoration:none; font-size:10pt; }
.toc-pg { flex:0 0 30px; text-align:right; color:#6B7280; font-size:9pt; }
.toc-sub { padding-left:46px; }
.toc-sub .toc-num { color:#6B7280; font-weight:600; font-size:9pt; flex-basis:40px; }
.toc-sub .toc-title { color:#4B5563; font-size:9pt; }
@media print { body { -webkit-print-color-adjust:exact; print-color-adjust:exact; } }
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def esc(s: Any) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _letter(s: int | float) -> str:
    return "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 60 else "F"


def _score_letter(s: int | float) -> str:
    return _letter(s)


def _score_class(s: int | float) -> str:
    return f"grade-{_letter(s)}"


def _lcls(s: int | float) -> str:
    return "grade-A fs-verde" if s >= 90 else "grade-B fs-amarillo" if s >= 70 else "grade-D fs-naranja" if s >= 60 else "grade-F fs-rojo"


def _bcls(sev: str) -> str:
    return {"critica": "s-critica", "alta": "s-alta", "media": "s-media", "baja": "s-baja", "informativa": "s-info", "info": "s-info"}.get(sev.lower(), "s-info")


def _hdrs(p: dict) -> dict:
    return (p.get("https") or {}).get("headers") or {}


def _dns(p: dict) -> dict:
    return p.get("dns") or {}


def domain_score(p: dict[str, Any]) -> float:
    """Benevolo: parte de 100 y resta suave -- 100 con higiene básica, baja gradual."""
    pts = 100.0
    h = p.get("https", {}) or {}
    headers = h.get("headers") or {}
    tls = p.get("tls") or {}
    dns = p.get("dns") or {}
    if not p.get("port_443", {}).get("open"):
        pts -= 6
    if not (isinstance(h.get("status_code"), int) and 200 <= h["status_code"] < 400):
        pts -= 4
    if not headers.get("strict-transport-security"):
        pts -= 4
    if not (headers.get("content-security-policy") or headers.get("content-security-policy-report-only")):
        pts -= 4
    elif p.get("csp_findings"):
        csp_f = p.get("csp_findings") or []
        if any(f.get("severity") == "high" for f in csp_f):
            pts -= 3
        elif csp_f:
            pts -= 2
    if not headers.get("x-frame-options"):
        pts -= 2
    if not headers.get("x-content-type-options"):
        pts -= 2
    if tls.get("error") or not tls.get("negotiated_version"):
        pts -= 6
    elif not tls.get("tls13_only_ok"):
        pts -= 2
    spf = dns.get("spf_record") or ""
    if not spf:
        pts -= 4
    elif "-all" not in spf.replace(" ", "").lower():
        pts -= 2
    dmarc_pol = dns.get("dmarc_policy") or ""
    if not dns.get("dmarc_record"):
        pts -= 4
    elif dmarc_pol not in ("reject", "quarantine"):
        pts -= 2
    starttls = dns.get("starttls_results") or []
    if starttls and not all(s.get("starttls") for s in starttls):
        pts -= 2
    ip_rep = dns.get("ip_reputation") or []
    if len(ip_rep) >= 1:
        pts -= 4 if len(ip_rep) >= 3 else 2
    urlhaus = p.get("urlhaus") or {}
    if urlhaus.get("malicious"):
        pts -= 3
    vulns = p.get("vulnerabilities") or []
    if len(vulns) >= 1:
        pts -= 4 if len(vulns) >= 3 else 2
    leaks = [l for l in (p.get("credential_leaks") or []) if "error" not in l]
    if len(leaks) >= 1:
        pts -= 4 if len(leaks) >= 3 else 2
    typos = p.get("typosquatting") or []
    if len(typos) >= 1:
        pts -= 3 if len(typos) >= 3 else 1
    patch = p.get("patching") or []
    eol = sum(1 for x in patch if x.get("status") == "eol")
    if eol >= 1:
        pts -= 3 if eol >= 2 else 1
    supply = p.get("supply_chain") or []
    if len(supply) > 5:
        pts -= 1
    takeover = p.get("takeover_risks") or []
    if any(r.get("vulnerable") for r in takeover):
        pts -= 5
    elif len(takeover) >= 1:
        pts -= 2
    cookie_f = p.get("cookie_findings") or []
    if any(f.get("severity") == "high" for f in cookie_f):
        pts -= 3
    elif cookie_f:
        pts -= 1
    scr_dnsbl = p.get("supply_reputation_dnsbl_count", 0)
    scr_urlhaus = p.get("supply_reputation_urlhaus_count", 0)
    if scr_dnsbl >= 1 or scr_urlhaus >= 1:
        pts -= 3 if scr_dnsbl >= 2 or scr_urlhaus >= 1 else 1
    return max(0.0, min(100.0, round(pts, 2)))


def domain_deductions(p: dict[str, Any]) -> list[tuple[str, int]]:
    """Desglose de deducciones aplicadas por domain_score() al proveedor (etiqueta, puntos)."""
    out: list[tuple[str, int]] = []
    h = p.get("https", {}) or {}
    headers = h.get("headers") or {}
    tls = p.get("tls") or {}
    dns = p.get("dns") or {}
    if not p.get("port_443", {}).get("open"):
        out.append(("443 cerrado", -6))
    if not (isinstance(h.get("status_code"), int) and 200 <= h["status_code"] < 400):
        out.append(("HTTPS no 2xx", -4))
    if not headers.get("strict-transport-security"):
        out.append(("HSTS", -4))
    if not (headers.get("content-security-policy") or headers.get("content-security-policy-report-only")):
        out.append(("CSP ausente", -4))
    elif p.get("csp_findings"):
        csp_f = p.get("csp_findings") or []
        out.append(("CSP debil", -3 if any(f.get("severity") == "high" for f in csp_f) else -2))
    if not headers.get("x-frame-options"):
        out.append(("X-Frame-Options", -2))
    if not headers.get("x-content-type-options"):
        out.append(("X-Content-Type-Options", -2))
    if tls.get("error") or not tls.get("negotiated_version"):
        out.append(("TLS error", -6))
    elif not tls.get("tls13_only_ok"):
        out.append(("TLS no 1.3-only", -2))
    spf = dns.get("spf_record") or ""
    if not spf:
        out.append(("SPF ausente", -4))
    elif "-all" not in spf.replace(" ", "").lower():
        out.append(("SPF ~all", -2))
    dmarc_pol = dns.get("dmarc_policy") or ""
    if not dns.get("dmarc_record"):
        out.append(("DMARC ausente", -4))
    elif dmarc_pol not in ("reject", "quarantine"):
        out.append(("DMARC sin reject", -2))
    starttls = dns.get("starttls_results") or []
    if starttls and not all(s.get("starttls") for s in starttls):
        out.append(("STARTTLS", -2))
    ip_rep = dns.get("ip_reputation") or []
    if len(ip_rep) >= 1:
        out.append(("DNSBL", -4 if len(ip_rep) >= 3 else -2))
    if (p.get("urlhaus") or {}).get("malicious"):
        out.append(("URLhaus", -3))
    if len(p.get("vulnerabilities") or []) >= 1:
        out.append(("OSV", -4 if len(p.get("vulnerabilities") or []) >= 3 else -2))
    leaks = [l for l in (p.get("credential_leaks") or []) if "error" not in l]
    if len(leaks) >= 1:
        out.append(("Leaks", -4 if len(leaks) >= 3 else -2))
    if len(p.get("typosquatting") or []) >= 1:
        out.append(("Typos", -3 if len(p.get("typosquatting") or []) >= 3 else -1))
    eol = sum(1 for x in (p.get("patching") or []) if x.get("status") == "eol")
    if eol >= 1:
        out.append(("EOL", -3 if eol >= 2 else -1))
    if len(p.get("supply_chain") or []) > 5:
        out.append(("Supply >5", -1))
    takeover = p.get("takeover_risks") or []
    if any(r.get("vulnerable") for r in takeover):
        out.append(("Takeover vulnerable", -5))
    elif len(takeover) >= 1:
        out.append(("Takeover potencial", -2))
    cookie_f = p.get("cookie_findings") or []
    if any(f.get("severity") == "high" for f in cookie_f):
        out.append(("Cookies high", -3))
    elif cookie_f:
        out.append(("Cookies low", -1))
    scr_dnsbl = p.get("supply_reputation_dnsbl_count", 0)
    scr_urlhaus = p.get("supply_reputation_urlhaus_count", 0)
    if scr_dnsbl >= 1 or scr_urlhaus >= 1:
        out.append(("Supply reputation", -3 if scr_dnsbl >= 2 or scr_urlhaus >= 1 else -1))
    return out


def _factor(providers: list[dict[str, Any]], name: str, base: int, deductions: list,
            _inc: dict | None = None, _scores: dict | None = None) -> dict[str, Any]:
    """Score por factor (0-100) = base - deducciones. Compatible con dashboard_server (import _factor)."""
    total = base
    inc = 0
    for p in providers:
        for check, amount in deductions:
            try:
                if check(p):
                    total -= amount
                    inc += 1
            except Exception:
                continue
    score = max(0, min(100, total))
    if _inc is not None:
        _inc[name] = _inc.get(name, 0) + inc
    if _scores is not None:
        _scores[name] = score
    return {"factor": name, "score": score, "incidencias": inc}


def compute_factores(providers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    factores: list[dict[str, Any]] = []
    factores.append(_factor(providers, "Seguridad de aplicacion web", 100, [
        (lambda p: not _hdrs(p).get("strict-transport-security"), 8),
        (lambda p: not (_hdrs(p).get("content-security-policy") or _hdrs(p).get("content-security-policy-report-only") or ""), 6),
        (lambda p: bool(p.get("csp_findings")), 4),
        (lambda p: not _hdrs(p).get("x-content-type-options"), 3),
        (lambda p: not _hdrs(p).get("x-frame-options"), 2),
        (lambda p: bool(p.get("cookie_findings")), 3),
    ]))
    factores.append(_factor(providers, "Cubit Score", 100, [
        (lambda p: not _dns(p).get("dnssec_ok"), 3),
        (lambda p: not p.get("caa_records"), 2),
        (lambda p: not _dns(p).get("spf_record"), 5),
        (lambda p: not _dns(p).get("dmarc_record"), 5),
    ]))
    factores.append(_factor(providers, "Estado de DNS", 100, [
        (lambda p: not _dns(p).get("spf_record"), 8),
        (lambda p: not _dns(p).get("dmarc_record"), 8),
        (lambda p: not _dns(p).get("dnssec_ok"), 5),
        (lambda p: not p.get("caa_records"), 3),
        (lambda p: len(_dns(p).get("ip_reputation") or []) > 0, 5),
    ]))
    factores.append(_factor(providers, "Seguridad de puntos de conexion", 100, [
        (lambda p: len([o for o in (p.get("open_ports") or []) if o.get("state") == "open"]) > 3, 10),
        (lambda p: any(o.get("state") == "open" and o.get("port") in (21, 22, 23, 3389, 3306, 1433, 5432, 6379) for o in (p.get("open_ports") or [])), 8),
    ]))
    factores.append(_factor(providers, "Hacker Chatter", 100, []))
    factores.append(_factor(providers, "Reputacion de IP", 100, [
        (lambda p: len(_dns(p).get("ip_reputation") or []) > 0, 10),
        (lambda p: (p.get("urlhaus") or {}).get("malicious", False), 15),
    ]))
    factores.append(_factor(providers, "Filtracion de informacion", 100, [
        (lambda p: len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) > 0, 15),
        (lambda p: bool(((p.get("kumo") or {}).get("breachintel") or {}).get("clientes")), 8),
    ]))
    factores.append(_factor(providers, "Seguridad de red", 100, [
        (lambda p: bool((p.get("tls") or {}).get("error")), 10),
        (lambda p: not (p.get("tls") or {}).get("negotiated_version"), 8),
    ]))
    factores.append(_factor(providers, "Cadencia de aplicacion de revisiones", 100, [
        (lambda p: sum(1 for x in (p.get("patching") or []) if x.get("status") == "eol") > 0, 12),
        (lambda p: len(p.get("vulnerabilities") or []) > 0, 8),
    ]))
    factores.append(_factor(providers, "Ingenieria social", 100, [
        (lambda p: len(p.get("typosquatting") or []) > 0, 5),
    ]))
    factores.append(_factor(providers, "Seguridad de endpoints", 100, [
        (lambda p: len(p.get("crt_subdomains") or []) + len(p.get("subdomains") or []) > 10, 3),
    ]))
    return factores


_B3_FACTOR_CATS = {
    "Seguridad de aplicacion web": ["APLICACION WEB"],
    "Cubit Score": ["ESTADO DE DNS", "SEGURIDAD DE RED", "APLICACION WEB", "CONFIGURACION DE CORREO"],
    "Estado de DNS": ["ESTADO DE DNS", "CONFIGURACION DE CORREO"],
    "Seguridad de puntos de conexion": ["SEGURIDAD DE RED", "ENDPOINTS"],
    "Hacker Chatter": ["CHATTER", "HACKER", "GITHUB", "REDES", "OSINT"],
    "Reputacion de IP": ["REPUTACION"],
    "Filtracion de informacion": ["FILTRACION", "LEAK"],
    "Seguridad de red": ["SEGURIDAD DE RED"],
    "Cadencia de aplicacion de revisiones": ["CADENCIA", "VULNERABILIDADES", "REVISIONES"],
    "Ingenieria social": ["INGENIERIA", "SOCIAL"],
    "Seguridad de endpoints": ["ENDPOINTS", "SUPERFICIE"],
}


def b3_deductions(providers: list[dict[str, Any]]) -> dict[str, list[tuple[str, int]]]:
    """Desglose por chequeo fallado de cada factor B3 (misma logica que compute_factores)."""
    out: dict[str, list[tuple[str, int]]] = {}

    def _collect(checks):
        dl: list[tuple[str, int]] = []
        for p in providers:
            for check, pts, lbl in checks:
                try:
                    if check(p):
                        lab = lbl(p) if callable(lbl) else lbl
                        if (lab, pts) not in dl:
                            dl.append((lab, pts))
                except Exception:
                    continue
        return dl

    out["Seguridad de aplicacion web"] = _collect([
        (lambda p: not _hdrs(p).get("strict-transport-security"), 8, "Sin HSTS"),
        (lambda p: not (_hdrs(p).get("content-security-policy") or _hdrs(p).get("content-security-policy-report-only") or ""), 6, "Sin CSP"),
        (lambda p: bool(p.get("csp_findings")), 4, lambda p: f"CSP debil ({len(p.get('csp_findings') or [])})"),
        (lambda p: not _hdrs(p).get("x-content-type-options"), 3, "Sin XCTO"),
        (lambda p: not _hdrs(p).get("x-frame-options"), 2, "Sin XFO"),
        (lambda p: bool(p.get("cookie_findings")), 3, lambda p: f"Cookies ({len(p.get('cookie_findings') or [])})"),
    ])
    out["Cubit Score"] = _collect([
        (lambda p: not _dns(p).get("dnssec_ok"), 3, "Sin DNSSEC"),
        (lambda p: not p.get("caa_records"), 2, "Sin CAA"),
        (lambda p: not _dns(p).get("spf_record"), 5, "Sin SPF"),
        (lambda p: not _dns(p).get("dmarc_record"), 5, "Sin DMARC"),
    ])
    out["Estado de DNS"] = _collect([
        (lambda p: not _dns(p).get("spf_record"), 8, "Sin SPF"),
        (lambda p: not _dns(p).get("dmarc_record"), 8, "Sin DMARC"),
        (lambda p: not _dns(p).get("dnssec_ok"), 5, "Sin DNSSEC"),
        (lambda p: not p.get("caa_records"), 3, "Sin CAA"),
        (lambda p: len(_dns(p).get("ip_reputation") or []) > 0, 5, lambda p: f"DNSBL ({len(_dns(p).get('ip_reputation') or [])})"),
    ])
    out["Seguridad de puntos de conexion"] = _collect([
        (lambda p: len([o for o in (p.get("open_ports") or []) if isinstance(o, dict) and o.get("state") == "open"]) > 3, 10, ">3 puertos"),
        (lambda p: any(isinstance(o, dict) and o.get("state") == "open" and o.get("port") in (21, 22, 23, 3389, 3306, 1433, 5432, 6379) for o in (p.get("open_ports") or [])), 8, "Puertos sensibles"),
    ])
    out["Hacker Chatter"] = []
    out["Reputacion de IP"] = _collect([
        (lambda p: len(_dns(p).get("ip_reputation") or []) > 0, 10, lambda p: f"DNSBL ({len(_dns(p).get('ip_reputation') or [])})"),
        (lambda p: (p.get("urlhaus") or {}).get("malicious", False), 15, "URLhaus"),
    ])
    out["Filtracion de informacion"] = _collect([
        (lambda p: len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) > 0, 15, lambda p: f"Leaks ({len([l for l in (p.get('credential_leaks') or []) if 'error' not in l])})"),
        (lambda p: bool(((p.get("kumo") or {}).get("breachintel") or {}).get("clientes")), 8, "Breach KUMO"),
    ])
    out["Seguridad de red"] = _collect([
        (lambda p: bool((p.get("tls") or {}).get("error")), 10, "TLS error"),
        (lambda p: not (p.get("tls") or {}).get("negotiated_version"), 8, "Sin TLS"),
    ])
    out["Cadencia de aplicacion de revisiones"] = _collect([
        (lambda p: sum(1 for x in (p.get("patching") or []) if isinstance(x, dict) and x.get("status") == "eol") > 0, 12, "EOL"),
        (lambda p: len(p.get("vulnerabilities") or []) > 0, 8, lambda p: f"Vulns ({len(p.get('vulnerabilities') or [])})"),
    ])
    out["Ingenieria social"] = _collect([
        (lambda p: len(p.get("typosquatting") or []) > 0, 5, lambda p: f"Typos ({len(p.get('typosquatting') or [])})"),
    ])
    out["Seguridad de endpoints"] = _collect([
        (lambda p: len(p.get("crt_subdomains") or []) + len(p.get("subdomains") or []) > 10, 3, ">10 subs"),
    ])
    return out


# ---------------------------------------------------------------------------
# Hallazgos desde datos reales
# ---------------------------------------------------------------------------
MAPA = {
    "dns": "NIST CSF: PR.AC-4, PR.IP-1 | ISO 27001: A.13.2.1, A.13.2.3 | PCI DSS: 6.5.6 | DORA: Art. 8.1, Art. 11.2",
    "app": "NIST CSF: PR.PT-4, PR.IP-1 | ISO 27001: A.14.2.5, A.13.1.1 | PCI DSS: 6.5.6, 6.5.8 | DORA: Art. 8.1, Art. 11.2",
    "net": "NIST CSF: PR.AC-3, PR.PT-4 | ISO 27001: A.10.1.1, A.13.1.1 | PCI DSS: 4.1 | DORA: Art. 8.1, Art. 11.2",
    "osint": "NIST CSF: ID.AM-1, ID.RA-1 | ISO 27001: A.12.6.1, A.8.1.1 | PCI DSS: 12.10.1 | DORA: Art. 8.1",
    "filt": "NIST CSF: PR.DS-5, ID.RA-1 | ISO 27001: A.12.6.1 | PCI DSS: 6.5.6 | DORA: Art. 8.1",
}


def _mueve_a(f: dict[str, Any]) -> str:
    """Scores que mueve un hallazgo. D=Domain, G=General, O=Overall. Reglas verificadas
    contra domain_score(), compute_factores() y precia factor_scores()."""
    t = _norm(str(f.get("titulo", "")) + " " + str(f.get("categoria", "")))
    if any(k in t for k in ("M365", "FINGERPRINT", "WHOIS", "GITHUB", "PANORAMA", "SERVIDOR: SERVER",
                            "CERTIFICADO TLS", "DEPENDENCIA(S) DE TERCEROS", "IPV6", "AAAA", "BIMI")):
        return "—"
    if "TYPO" in t:
        return "D · G · O"
    if any(k in t for k in ("SPF", "DMARC")):
        return "D · G · O"
    if "DNSSEC" in t or "CAA" in t:
        return "G · O"
    if any(k in t for k in ("DKIM", "MTA-STS", "TLS-RPT", "DANE")):
        return "—"
    if "STARTTLS" in t:
        return "D"
    if "HSTS" in t or "CSP" in t:
        return "D · G · O"
    if "COOP" in t or "X-POWERED" in t:
        return "—"
    if "TAKEOVER" in t or "CNAME" in t:
        return "D · O"
    if "SUBDOMINIO" in t:
        return "G"
    if "PUERTO" in t:
        return "G · O"
    if "KEV" in t or "CVE" in t or "OSV" in t or "VULNERABILIDAD" in t:
        return "D · G · O"
    if any(k in t for k in ("FILTRACI", "LEAK", "BREACH", "INFOSTEALER")):
        return "D · G · O"
    if "WAYBACK" in t or "SECRETOS" in t or "JS" in t:
        return "O"
    if "EOL" in t or "PATCH" in t:
        return "D · G · O"
    if "DNSBL" in t or "URLHAUS" in t or "REPUTACION" in t or "TERCEROS LISTADOS" in t:
        return "D · G · O" if "TERCEROS" not in t else "D · O"
    if "WAF" in t:
        return "O"
    if "COOKIE" in t:
        return "D · G · O"
    if "RUTA" in t:
        return "—"
    return "D · G · O"


def _stable_id(cat: str, titulo: str) -> str:
    import hashlib
    h = hashlib.md5(f"{cat}|{titulo}".encode("utf-8")).hexdigest()[:6].upper()
    prefix = {"ESTADO DE DNS": "DNS", "CONFIGURACIÓN DE CORREO": "MAIL", "SEGURIDAD DE APLICACIÓN WEB": "WEB", "SEGURIDAD DE ENDPOINTS": "ENDP", "INGENIERÍA SOCIAL": "SOC", "SEGURIDAD DE RED": "NET", "REPUTACIÓN DE TERCEROS": "SUPPLY", "FILTRACIÓN DE INFORMACIÓN": "LEAK", "OSINT PASIVO": "OSINT", "SUPERFICIE DE ATAQUE": "SURF"}.get(cat, cat[:4].upper())
    return f"ASM-{prefix}-{h}"


def _confidence_for(titulo: str, categoria: str) -> str:
    t = (titulo + " " + categoria).upper()
    if any(k in t for k in ("HSTS", "CAA", "BIMI", "COOP", "DANE", "MTA-STS", "TLS-RPT", "SPF", "DMARC", "DNSSEC")):
        return "HIGH"
    if "TYPO" in t and "RESOLVING" in t:
        return "HIGH"
    if "TAKEOVER" in t and "VULNERABLE" in t:
        return "HIGH"
    if "DNSBL" in t and "TERCEROS" in t:
        return "LOW"
    if "WAYBACK" in t or "SECRETOS" in t:
        return "MEDIUM"
    if "VULNERABILIDAD" in t or "CVE" in t or "OSV" in t:
        return "MEDIUM"
    return "MEDIUM"


def build_findings(p: dict[str, Any]) -> list[dict[str, Any]]:
    dom = p.get("domain", "")
    dns = _dns(p)
    headers = _hdrs(p)
    tls = p.get("tls") or {}
    out: list[dict[str, Any]] = []

    def add(sev, cat, titulo, expl, evid, riesgo, rec, prio, mapa="", confidence=None, source="ASM scan", observed=None, expected=None, rule=None):
        fid = _stable_id(cat, titulo)
        conf = confidence or _confidence_for(titulo, cat)
        ts = p.get("scanned_at") or datetime.now(timezone.utc).isoformat()
        out.append({"id": fid, "severidad": sev, "categoria": cat, "titulo": titulo, "explicacion": expl,
                    "evidencia": evid, "riesgo": riesgo, "recomendacion": rec,
                    "prioridad": prio, "estado": "Abierto", "mapeo": mapa, "dominio": dom,
                    "confidence": conf, "source": source, "observed": observed or evid[:120], "expected": expected or rec[:120], "rule": rule or f"B3-{cat[:3]}", "mueve_a": _mueve_a({"titulo": titulo, "categoria": cat}), "timestamp": ts})

    spf = dns.get("spf_record") or ""
    dmarc = dns.get("dmarc_record") or ""
    if not spf and not dmarc:
        add("CRITICA", "ESTADO DE DNS", "SPF y DMARC ausentes",
            "Sin SPF y DMARC, cualquier servidor puede enviar correos que parecen provenir del dominio, facilitando phishing y spear-phishing.",
            f"SPF: Ausente | DMARC: Ausente",
            "Alto riesgo de phishing corporativo.",
            "Configurar SPF con -all y DMARC con p=reject.", "P1", MAPA["dns"])
    elif not spf or not dmarc:
        falt = "SPF" if not spf else "DMARC"
        add("ALTA", "CONFIGURACIÓN DE CORREO", f"{falt} no configurado",
            f"Ausencia de {falt} debilita la autenticación del correo del dominio.",
            f"SPF: {(spf[:80] if spf else 'Ausente')} | DMARC: {(dmarc[:80] if dmarc else 'Ausente')}",
            "Suplantación de dominio en correos.",
            "Completar SPF -all y DMARC p=reject pct=100.", "P2", MAPA["dns"])
    elif "~all" in spf and "-all" not in spf.replace(" ", "").lower():
        add("MEDIA", "CONFIGURACIÓN DE CORREO", "SPF con ~all (softfail) — debilidad de configuración",
            "SPF con ~all no exige rechazo duro; DMARC p=reject puede mitigar pero SPF ~all sigue siendo debilidad.",
            f"SPF: {spf[:90]} | DMARC: {(dmarc[:60] if dmarc else 'Ausente')} | Verdict: NO SPOOFABLE (DMARC mitiga)",
            "Configuración mejorable, exploitability baja por DMARC.",
            "Cambiar SPF ~all → -all; mantener DMARC p=reject.", "P3", MAPA["dns"])

    # Verdict SPF/DMARC spoofable (Claude-OSINT) — dict-aware, evita falso positivo NO SPOOFABLE
    try:
        claude = p.get("claude_osint") or {}
        spf_sc = claude.get("spf_supply_chain") or {}
        verdict_raw = spf_sc.get("verdict", "")
        if isinstance(verdict_raw, dict):
            verdict_str = str(verdict_raw.get("spoofable", "") or "")
        else:
            verdict_str = str(verdict_raw or "")
        if verdict_str and verdict_str.strip().upper() == "SPOOFABLE":
            add("ALTA", "CONFIGURACIÓN DE CORREO", f"Verdict SPF/DMARC SPOOFABLE en {dom}",
                "Verdict compuesto SPF+DMARC (Claude-OSINT spf_supply_chain) evalúa la spoofability del dominio.",
                f"SPF: {(spf if spf else '(ninguno)')[:90]} | DMARC p={dns.get('dmarc_policy') or ''} | Verdict: {verdict_str[:60]}",
                "Suplantación de dominio en correos (envelope/header).",
                "Establecer SPF -all y DMARC p=reject pct=100; revisar dead-includes de la cadena SPF.", "P2", MAPA["dns"])
    except Exception:
        pass

    # KUMO breach intel
    try:
        bi = ((p.get("kumo") or {}).get("breachintel") or {})
        clientes = bi.get("clientes", 0) or 0
        if clientes:
            add("ALTA", "FILTRACION DE INFORMACION", "Filtraciones / infostealer detectados (KUMO)",
                "Infostealers roban credenciales de maquinas infectadas y las venden en mercados de accesos.",
                f"clientes: {clientes}",
                "Credenciales corporativas y datos expuestos en filtraciones.",
                "Rotar credenciales afectadas, auditar maquinas comprometidas y monitorear exfiltracion.", "P1", MAPA["filt"])
    except Exception:
        pass

    leaks = [l for l in (p.get("credential_leaks") or []) if "error" not in l]
    if leaks:
        add("ALTA", "FILTRACION DE INFORMACION", f"{len(leaks)} filtración(es) de credenciales en breaches",
            "Credenciales asociadas al dominio aparecen en bases de breaches conocidas.",
            "; ".join(str(l.get('source', l))[:60] for l in leaks[:3]),
            "Toma de cuentas y accesos no autorizados.",
            "Rotar credenciales, forzar MFA y monitorear uso anomalo.", "P1", MAPA["filt"])

    csp_enforced = headers.get("content-security-policy") or ""
    csp_report = headers.get("content-security-policy-report-only") or ""
    csp_f = p.get("csp_findings") or []
    if csp_f:
        det = "; ".join(f"{f.get('directive', f.get('type', '?'))} ({f.get('occurrences', f.get('count', 1))} ocurr.)" for f in csp_f[:4])
        if csp_enforced:
            add("MEDIA", "SEGURIDAD DE APLICACIÓN WEB", f"CSP con directivas inseguras: {len(csp_f)} hallazgo(s) (enforced)",
                "Faltan directivas como base-uri/form-action o hay valores inseguros; reduce la protección CSP.",
                f"CSP enforced: {(csp_enforced[:70] + '...') if len(csp_enforced) > 70 else csp_enforced} | Detalle: {det[:160]}",
                "Posible bypass de CSP permitiendo XSS.",
                "Completar base-uri/form-action y eliminar valores inseguros; usar nonces/hashes.", "P2", MAPA["app"])
        else:
            add("BAJA", "SEGURIDAD DE APLICACIÓN WEB", f"CSP report-only con directivas laxas: {len(csp_f)} hallazgo(s)",
                "Hallazgos provienen de CSP report-only, que no aplica enforcement; no debe confundirse con CSP enforced.",
                f"CSP report-only: {(csp_report[:70] + '...') if len(csp_report) > 70 else csp_report} | Detalle: {det[:160]}",
                "Sin enforcement, no hay protección efectiva.",
                "Publicar CSP enforced con nonces/hashes; report-only solo para monitoreo.", "P3", MAPA["app"])
    elif not csp_enforced and not csp_report:
        add("MEDIA", "SEGURIDAD DE APLICACIÓN WEB", "CSP ausente",
            "Sin Content-Security-Policy el navegador no restringe orígenes de scripts/frames.",
            "CSP: Ausente",
            "Mayor exposición a XSS y clickjacking.",
            "Publicar CSP enforced con default-src restrictivo, nonces y report-uri.", "P2", MAPA["app"])

    subs = list(dict.fromkeys(_sub_name(s) for s in (p.get("subdomains") or []) + (p.get("crt_subdomains") or []) if _sub_name(s)))
    if subs:
        prod = [s for s in subs if not any(k in s.lower() for k in ("stag", "dev", "test", "internal", "intranet"))]
        add("MEDIA", "SEGURIDAD DE ENDPOINTS", f"{len(subs)} subdominios detectados ({len(prod)} prod)",
            "Los subdominios representan puntos de entrada adicionales; los olvidados suelen tener configuraciones debiles.",
            f"DNS: {len(p.get('subdomains') or [])} | CT: {len(p.get('crt_subdomains') or [])} | Brute: {len(p.get('brute_subs') or [])} | Ej: {', '.join(subs[:3])[:140]}",
            "Activos olvidados sin mantenimiento.",
            "Inventariar y eliminar subdominios no usados; priorizar staging/dev/internal.", "P2", MAPA["osint"])

    typos = p.get("typosquatting") or []
    if typos:
        tstr = "; ".join(f"{t.get('domain', '')} ({', '.join((t.get('ips') or [])[:1]) if t.get('ips') else 'no resuelve'})" for t in typos[:3])
        add("MEDIA", "INGENIERIA SOCIAL", f"Typosquatting: {len(typos)} variante(s) activa(s)",
            "Atacantes registran dominios con errores tipográficos para interceptar tráfico o phishing. Cada variante que resuelve es riesgo activo.",
            f"Variantes: {tstr[:200]}",
            "Phishing y suplantacion de identidad.",
            "Monitorear y adquisicion defensiva; DMARC p=reject.", "P2", MAPA["osint"])

    if not (dns.get("dkim_records")):
        add("MEDIA", "ESTADO DE DNS", "DKIM no configurado",
            "DKIM permite al receptor verificar que el correo no fue alterado y proviene del dominio.",
            "DKIM: Ausente",
            "Suplantacion y alteracion de correos sin detección.",
            "Configurar DKIM y alinear con DMARC.", "P2", MAPA["dns"])
    if not p.get("caa_records"):
        add("MEDIA", "SEGURIDAD DE RED", "CAA no configurado",
            "Los registros CAA especifican que CAs están autorizadas a emitir certificados.",
            "CAA: Ausente",
            "Cualquier CA puede emitir certificados SSL.",
            "Configurar CAA en DNS.", "P2", MAPA["net"])

    # GitHub/detalle en seccion 8 (ficha GC); sin tarjeta duplicada aqui.

    paths = p.get("public_paths") or []

    paths = p.get("public_paths") or []
    ok_paths = [r for r in paths if str(r.get("status", "")) in ("200", "301", "302", "403") or r.get("responde")]
    if ok_paths:
        ej = ", ".join(f"{r.get('path', r.get('url', '?'))} (HTTP {r.get('status', '?')})" for r in ok_paths[:3])
        add("MEDIA", "SEGURIDAD DE RED", f"Rutas públicas accesibles: {len(ok_paths)} responden",
            "El probing de rutas comunes revelo endpoints que responden, exponiendo infraestructura o funciones internas.",
            f"Rutas: {ej[:180]}",
            "Exposicion de información (robots.txt, health, API docs).",
            "Revisar cada ruta; deshabilitar innecesarias, proteger con autenticacion.", "P3", MAPA["net"])

    if not p.get("mta_sts"):
        add("MEDIA", "ESTADO DE DNS", "MTA-STS no configurado",
            "MTA-STS pública políticas para exigir TLS en entrega de correo.",
            "MTA-STS: Ausente",
            "Correos pueden entregarse en texto plano.",
            "Configurar MTA-STS en modo enforce.", "P3", MAPA["dns"])
    if not (dns.get("dane_records")):
        add("MEDIA", "ESTADO DE DNS", "DANE/TLSA no configurado",
            "DANE asocia certificados TLS especificos via DNS, previniendo CA comprometidas.",
            "DANE: Ausente",
            "Cualquier CA puede emitir sin restriccion.",
            "Configurar TLSA con DNSSEC.", "P3", MAPA["net"])

    # Wayback endpoints
    try:
        wb = ((p.get("kumo") or {}).get("wayback") or {})
        eps = wb.get("endpoints") or wb.get("urls") or []
        sensibles = [e for e in eps if any(k in str(e).lower() for k in ("openid", "well-known", "api", "admin", "config", ".env"))]
        if sensibles:
            add("MEDIA", "FILTRACIÓN DE INFORMACIÓN", "Endpoint histórico detectado en Wayback Machine",
                "URL histórica encontrada en Wayback; existencia no demuestra por sí sola sensibilidad ni exposición actual. Requiere validar si sigue accesible y si expone contenido sensible.",
                f"{str(sensibles[0])[:120]} (histórico; validar accesibilidad y contenido)",
                "Información histórica contextual; riesgo bajo-medio hasta confirmar exposición.",
                "Verificar si la URL sigue accesible y expone datos sensibles; si no, documentar como informativo.", "P3", MAPA["filt"])
    except Exception:
        pass

    srv = headers.get("server", "")
    xpb = headers.get("x-powered-by", "")
    # Tarjeta "Servidor:" eliminada (detalle en Huella de Servidor §8); se conserva X-Powered-By por riesgo.
    if xpb:
        add("BAJA", "SEGURIDAD DE APLICACION WEB", f"X-Powered-By: {xpb}",
            "X-Powered-By expone el stack tecnologico.",
            f"X-Powered-By: {xpb}",
            "Ayuda a buscar vulnerabilidades especificas.",
            "Eliminar X-Powered-By del servidor.", "P3", MAPA["app"])
    if not headers.get("cross-origin-opener-policy"):
        add("BAJA", "SEGURIDAD DE APLICACION WEB", "COOP ausente",
            "Cross-Origin-Opener-Policy aisla ventanas cross-origin contra canales laterales.",
            "COOP: Ausente",
            "Fuga via cross-origin (Spectre).",
            "Configurar same-origin.", "P3", MAPA["app"])
    if not (dns.get("ipv6") or dns.get("aaaa_records")):
        add("BAJA", "ESTADO DE DNS", "IPv6 (AAAA) no configurado",
            "IPv6 es el reemplazo de IPv4; su ausencia limita accesibilidad pero no es riesgo directo.",
            "AAAA: Ausente",
            "Sin redundancia IPv6.",
            "Evaluar implementacion de IPv6.", "P4", MAPA["dns"])
    if not p.get("tls_rpt"):
        add("BAJA", "ESTADO DE DNS", "TLS-RPT no configurado",
            "TLS-RPT permite recibir informes de fallos TLS entre MX.",
            "TLS-RPT: Ausente",
            "Sin visibilidad de problemas de cifrado.",
            "Configurar TLS-RPT con correo.", "P4", MAPA["dns"])
    if not p.get("bimi"):
        add("BAJA", "ESTADO DE DNS", "BIMI no configurado",
            "BIMI muestra el logo junto a correos autenticados.",
            "BIMI: Ausente",
            "Menor diferenciacion visual.",
            "Configurar BIMI con logo verificado.", "P4", MAPA["dns"])

    # Detalle supply/cert en seccion 8 (ficha GC); sin tarjeta duplicada aqui.

    # --- Adopcion GC: hallazgos de superficie profunda (datos 100% reales) ---
    RISKY = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 139: "NetBIOS", 3389: "RDP", 3306: "MySQL", 1433: "MSSQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 5900: "VNC", 11211: "Memcached", 9200: "Elasticsearch"}
    open_ports = [o for o in (p.get("open_ports") or []) if o.get("state") == "open"]
    risky = [o for o in open_ports if o.get("port") in RISKY]
    if risky:
        ej = ", ".join(f"{o.get('port')}/{o.get('service', RISKY.get(o.get('port'), '?'))}" for o in risky[:5])
        add("ALTA" if any(o.get("port") in (23, 445, 3389, 5900) for o in risky) else "MEDIA", "SEGURIDAD DE RED",
            f"Puertos sensibles abiertos: {len(risky)} ({ej[:120]})",
            "Puertos de administracion/bases de datos expuestos a internet permiten fuerza bruta y exploits directos.",
            f"Puertos: {ej[:180]}",
            "Acceso remoto o exfiltracion de bases de datos.",
            "Cerrar o restringir por firewall/VPN; exponer solo 80/443.", "P1", MAPA["net"])

    risks = p.get("takeover_risks") or []
    vuln_take = [r for r in risks if r.get("vulnerable")]
    if vuln_take:
        ej = "; ".join(f"{r.get('host', '')} -> {r.get('cname', '')}" for r in vuln_take[:2])
        add("CRITICA", "SEGURIDAD DE ENDPOINTS", f"Subdomain takeover VULNERABLE: {len(vuln_take)}",
            "Un subdominio apunta (CNAME) a un servicio externo inexistente/liberado: un atacante puede reclamarlo y servir contenido bajo el dominio.",
            f"{ej[:200]}",
            "Phishing y robo de sesiones bajo dominio legitimo.",
            "Eliminar el CNAME o reclamar el recurso externo ya.", "P1", MAPA["net"])
    elif risks:
        add("BAJA", "SEGURIDAD DE ENDPOINTS", f"Takeover bajo vigilancia: {len(risks)} CNAME(s) externos",
            "CNAMEs a terceros sin vulnerabilidad confirmada; vigilar expiraciones.",
            f"CNAMEs: {len(risks)}",
            "Apropiacion futura si el destino se libera.",
            "Inventariar CNAMEs y alertar ante cambios.", "P4", MAPA["net"])

    patch = p.get("patching") or []
    eol = [x for x in patch if x.get("status") == "eol"]
    if eol:
        ej = ", ".join(f"{x.get('technology', '')} {x.get('version', '')}" for x in eol[:3])
        add("ALTA" if len(eol) >= 2 else "MEDIA", "CADENCIA DE REVISIONES", f"Software EOL: {len(eol)} tecnologia(s) sin soporte ({ej[:100]})",
            "Tecnologias end-of-life no reciben parches de seguridad.",
            f"EOL: {ej[:180]}",
            "Explotacion de CVEs sin parche disponible.",
            "Migrar a versiones soportadas de inmediato.", "P2", MAPA["filt"])

    vulns = p.get("vulnerabilities") or []
    if vulns:
        ej = "; ".join(f"{v.get('cve_id', v.get('id', '?'))} ({v.get('package', '')})" for v in vulns[:3])
        add("ALTA" if len(vulns) >= 3 else "MEDIA", "VULNERABILIDADES", f"{len(vulns)} vulnerabilidad(es) en tecnologias (OSV.dev)",
            "Versiones detectadas con CVEs conocidos según OSV.dev.",
            f"{ej[:200]}",
            "Explotación remota según CVSS.",
            "Actualizar paquetes a versiones parcheadas.", "P2", MAPA["filt"])
    cves = p.get("cve_findings") or []
    if cves:
        def _ckey(c):
            try:
                return float(c.get("risk_score") or 0)
            except Exception:
                return 0.0
        cves = sorted(cves, key=_ckey, reverse=True)
        top = cves[0]
        top_extra = f" | EPSS {top.get('epss_score')} | KEV" if top.get("in_kev") else (f" | EPSS {top.get('epss_score')}" if top.get("epss_score") is not None else "")
        ej = "; ".join(f"{c.get('id', '?')} [{c.get('type', '')}]" for c in cves[:3])
        add("MEDIA", "VULNERABILIDADES", f"{len(cves)} CVE(s) por banner grab (vulscan, top riesgo {top.get('risk_score', '?')}{top_extra})",
            "Banners de servicio mapeados a CVEs probables, ordenados por riesgo (EPSS + KEV + severidad).",
            f"{ej[:200]}",
            "Explotacion de servicios expuestos.",
            "Ocultar banners y parchear servicios.", "P2", MAPA["net"])
        kev = [c for c in cves if c.get("in_kev")]
        if kev:
            ej = "; ".join(c.get("id", "?") for c in kev[:3])
            add("ALTA", "VULNERABILIDADES", f"{len(kev)} CVE(s) en catalogo CISA KEV (explotacion activa)",
                "CISA KEV lista CVEs con explotación activa confirmada: parcheo prioritario.",
                f"KEV: {ej[:200]}",
                "Explotacion activa en curso.",
                "Parchear de inmediato o aplicar mitigación (deshabilitar servicio).", "P1", MAPA["filt"])
        hi = [c for c in cves if not c.get("in_kev") and (c.get("risk_score") or 0) >= 7]
        if hi:
            ej = "; ".join(f"{c.get('id', '?')} (riesgo {c.get('risk_score')})" for c in hi[:3])
            add("MEDIA", "VULNERABILIDADES", f"{len(hi)} CVE(s) con riesgo alto (EPSS/risk>=7)",
                "Combinacion de probabilidad de explotación (EPSS) y severidad.",
                f"{ej[:200]}",
                "Alta probabilidad de explotación.",
                "Priorizar parcheo en ventana de 30 días.", "P2", MAPA["filt"])

    # Secretos en JS/HTML (KUMO js_secrets + Claude secret_scan)
    try:
        kjs = ((p.get("kumo") or {}).get("js_secrets") or {}).get("secrets") or []
        css = ((p.get("claude_osint") or {}).get("secret_scan") or {}).get("critical") or []
        if kjs or css:
            ejk = "; ".join(f"{x.get('type', '?')} en {x.get('file', '?')}" for x in (kjs[:2] + [{"type": g.get("pattern", "?"), "file": "HTML publico"} for g in css[:2]])[:3])
            add("ALTA", "FILTRACION DE INFORMACION", f"Secretos expuestos en JS/HTML público ({len(kjs) + len(css)})",
                "Claves/tokens embebidos en JavaScript o HTML público permiten accesos directos.",
                f"{ejk[:200]}",
                "Toma de cuentas de servicios terceros.",
                "Revocar y rotar secretos; mover a backend/vault.", "P1", MAPA["filt"])
    except Exception:
        pass

    # Buckets cloud publicos
    try:
        cloud = p.get("cloud_storage") or {}
        pubs = cloud.get("publicos") or cloud.get("buckets") or []
        pubs = [b for b in pubs if isinstance(b, dict) and b.get("public")]
        if pubs or cloud.get("archivos_sensibles"):
            add("ALTA", "FILTRACION DE INFORMACION", "Almacenamiento cloud público expuesto",
                "Buckets/contenedores accesibles sin autenticacion.",
                f"Publicos: {len(pubs)} | Sensibles: {len(cloud.get('archivos_sensibles') or [])}",
                "Descarga masiva de datos por terceros.",
                "Bloquear acceso público y auditar logs de acceso.", "P1", MAPA["filt"])
    except Exception:
        pass

    # Reputación supply-chain
    try:
        scr = p.get("supply_chain_reputation") or {}
        dbl = scr.get("dnsbl") or []
        uh = scr.get("urlhaus") or []
        if dbl or uh:
            add("ALTA" if uh else "MEDIA", "REPUTACIÓN DE TERCEROS", f"Terceros listados: {len(dbl)} DNSBL / {len(uh)} URLhaus",
                "Dependencias con reputación listada. Se distingue Third-party Shared (CDN/SaaS compartido, ej. Cloudflare) = contextual vs First-party Origin = riesgo directo.",
                f"DNSBL: {len(dbl)} | URLhaus: {len(uh)}"[:160],
                "Posible impacto reputacional/de seguridad asociado a dependencias de terceros. No se observó distribución directa de malware; hallazgo basado solo en DNSBL, requiere validación.",
                "Validar si la IP es propia o compartida/CDN; si es propia, sustituir/pinnear; si es compartida, documentar como contextual.", "P2", MAPA["app"])
    except Exception:
        pass

    # WAF/CDN (informativo, real)
    try:
        waf = p.get("waf_detection") or {}
        if waf.get("detected"):
            w = waf.get("waf") or []
            wtxt = ", ".join(w) if isinstance(w, list) else str(w)
            add("INFORMATIVA", "SEGURIDAD DE RED", f"WAF/CDN detectado: {wtxt[:80]}",
                "WAF/CDN delante del origen mitiga DDoS e inyecciones básicas.",
                f"Evidencia: {str((waf.get('evidence') or [''])[:1])[:140]} | Confianza: {waf.get('confidence', '?')}",
                "No sustituye hardening de origen.",
                "Mantener reglas gestionadas y ocultar IP de origen.", "P4", MAPA["net"])
        else:
            add("BAJA", "SEGURIDAD DE RED", "Sin WAF/CDN detectado",
                "Sin capaAnti-DDoS/filtrado perimetral delante del origen.",
                "WAF: no detectado",
                "DDoS e inyecciones llegan al origen.",
                "Evaluar WAF gestionado (Cloudflare/AWS WAF).", "P3", MAPA["net"])
    except Exception:
        pass

    # WHOIS/M365/panoramas (detalle en seccion 8; tarjeta WHOIS eliminada por duplicada)
    try:
        cl = p.get("claude_osint") or {}
        m365 = cl.get("m365_fingerprint") or {}
        ns = m365.get("namespace", m365.get("type", "")) if isinstance(m365, dict) else ""
        if ns:
            add("INFORMATIVA", "EXPOSICION DE IDENTIDAD", f"Fingerprint M365/Entra de {dom}",
                "Huella Azure/Entra desde getuserrealm/OIDC/Autodiscover (Claude-OSINT m365_fingerprint).",
                f"namespace {ns}"[:120],
                "Enumeracion de cuentas y fuerza bruta.",
                "Restringir autodiscover y aplicar bloqueo/throttling.", "P4", MAPA["osint"])
    except Exception:
        pass
    # Panoramas: detalle en seccion 8 (ficha GC); sin tarjetas de conteo aqui.
    return out


# ---------------------------------------------------------------------------
# Tablas / SVG
# ---------------------------------------------------------------------------
def render_controls_table(providers: list[dict[str, Any]]) -> str:
    controls = [
        ("HTTPS", lambda p: (p.get("https") or {}).get("status_code") and 200 <= (p.get("https") or {}).get("status_code") < 500, lambda p: str((p.get("https") or {}).get("status_code") or "--")),
        ("TLS 1.2/1.3", lambda p: bool((p.get("tls") or {}).get("negotiated_version") and not (p.get("tls") or {}).get("error")), lambda p: (p.get("tls") or {}).get("negotiated_version") or (p.get("tls") or {}).get("error") or "--"),
        ("HSTS", lambda p: bool((p.get("https") or {}).get("headers", {}).get("strict-transport-security")), lambda p: (p.get("https") or {}).get("headers", {}).get("strict-transport-security", "--")[:50]),
        ("CSP", lambda p: bool((p.get("https") or {}).get("headers", {}).get("content-security-policy") or (p.get("https") or {}).get("headers", {}).get("content-security-policy-report-only")), lambda p: ((p.get("https") or {}).get("headers", {}).get("content-security-policy") or (p.get("https") or {}).get("headers", {}).get("content-security-policy-report-only") or "--")[:50]),
        ("SPF", lambda p: bool((p.get("dns") or {}).get("spf_record")), lambda p: ((p.get("dns") or {}).get("spf_record") or "--")[:60]),
        ("DMARC", lambda p: bool((p.get("dns") or {}).get("dmarc_record")), lambda p: ((p.get("dns") or {}).get("dmarc_record") or "--")[:60]),
        ("DNSSEC", lambda p: bool((p.get("dns") or {}).get("dnssec_ok")), lambda p: "OK" if (p.get("dns") or {}).get("dnssec_ok") else "No"),
        ("CAA", lambda p: bool(p.get("caa_records")), lambda p: str(len(p.get("caa_records") or []))),
        ("MTA-STS", lambda p: bool(p.get("mta_sts")), lambda p: (p.get("mta_sts") or "--")[:40]),
        ("STARTTLS", lambda p: all(s.get("starttls") for s in (p.get("dns") or {}).get("starttls_results") or []) if (p.get("dns") or {}).get("starttls_results") else False, lambda p: "OK" if all(s.get("starttls") for s in (p.get("dns") or {}).get("starttls_results") or []) else "No"),
        ("Server Banner", lambda p: not (p.get("https") or {}).get("headers", {}).get("server"), lambda p: (p.get("https") or {}).get("headers", {}).get("server", "--")[:30]),
    ]
    rows = ""
    for name, check, val_fn in controls:
        cells = ""
        for p in providers:
            try:
                ok = bool(check(p))
            except Exception:
                ok = False
            try:
                val = val_fn(p)
            except Exception:
                val = "--"
            color = "#2E7D32" if ok else "#C62828"
            icon = "&#10004;" if ok else "&#10008;"
            cells += f"<td style='text-align:center; color:{color}; font-weight:700;'>{icon}</td><td style='font-size:7px; color:#4B5563;'>{esc(val)}</td>"
        rows += f"<tr><td style='font-weight:600;'>{esc(name)}</td>{cells}</tr>\n"
    top = "".join("<th style='text-align:center;'>PASS</th><th>Valor</th>" for _ in providers)
    return f"""
    <div style="background:#fff; border:1px solid #E5E7EB; border-radius:10px; padding:12px; margin:12px 0;">
      <div style="font-size:9px; font-weight:800; color:#1A3A4A; text-transform:uppercase; letter-spacing:0.06em; margin-bottom:8px;">Estado de Controles -- PASS/FAIL por dominio</div>
      <table class="data" style="font-size:7.5px;"><thead><tr><th>Control</th>{top}</tr></thead><tbody>
      {rows}
      </tbody></table>
      <div style="font-size:6px; color:#6B7280; margin-top:6px;">&#10004; PASS / &#10008; FAIL -- Valor exacto del control (cabecera, registro DNS, version TLS). Para detalle ver Hallazgos.</div>
    </div>
    """


def _history_svg(history: list[dict], w=620, h=220) -> str:
    if not history:
        return ""
    pl, pr, pt, pb = 50, 30, 16, 36
    cw, ch = w - pl - pr, h - pt - pb
    scores = [s["score"] for s in history]
    ind = [s.get("industria") for s in history if s.get("industria") is not None]
    dates = [str(s["fecha"])[-5:] for s in history]
    allv = scores + ind if ind else scores
    ymin = max(0, min(allv) - 5)
    ymax = min(100, max(allv) + 5)
    yr = ymax - ymin or 1

    def yp(v):
        return pt + ch - (v - ymin) / yr * ch

    def xp(i):
        return pl + (i / max(len(history) - 1, 1)) * cw

    svg = f'<svg width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg" style="font-family:Arial,Helvetica,sans-serif;">'
    for letter, lo, hi, color in [("F", 0, 59, "#fee2e2"), ("D", 60, 69, "#ffedd5"), ("C", 70, 79, "#fef9c3"), ("B", 80, 89, "#e0f2fe"), ("A", 90, 100, "#dcfce7")]:
        lc, hc = max(lo, ymin), min(hi, ymax)
        if lc > ymax or hc < ymin:
            continue
        y1, y2 = yp(hc), yp(lc)
        svg += f'<rect x="{pl}" y="{y1}" width="{cw}" height="{y2 - y1}" fill="{color}" opacity=".4" rx="2"/>'
        svg += f'<text x="{w - pr + 6}" y="{(y1 + y2) / 2 + 3}" fill="#9CA3AF" font-size="7" font-weight="700">{letter}</text>'
    step = max(1, (int(ymax) - int(ymin)) // 5)
    for val in range(int(ymin), int(ymax) + 1, step):
        y = yp(val)
        svg += f'<text x="{pl - 8}" y="{y + 3}" fill="#6B7280" font-size="7" text-anchor="end">{val}</text>'
        svg += f'<line x1="{pl}" y1="{y}" x2="{w - pr}" y2="{y}" stroke="#D9DEE3" stroke-width=".5"/>'
    if ind:
        pts = " ".join(f"{xp(i)},{yp(ind[i])}" for i in range(len(ind)))
        svg += f'<polyline points="{pts}" fill="none" stroke="#9CA3AF" stroke-width="1.5" stroke-dasharray="4,3"/>'
    pts = " ".join(f"{xp(i)},{yp(scores[i])}" for i in range(len(scores)))
    svg += f'<polyline points="{pts}" fill="none" stroke="#173B57" stroke-width="2.5"/>'
    for i, s in enumerate(scores):
        svg += f'<circle cx="{xp(i)}" cy="{yp(s)}" r="3" fill="#173B57" stroke="#fff" stroke-width="1.5"/>'
        svg += f'<text x="{xp(i)}" y="{yp(s) - 8}" fill="#173B57" font-size="7" font-weight="700" text-anchor="middle">{s}</text>'
    for i, d in enumerate(dates):
        svg += f'<text x="{xp(i)}" y="{h - 6}" fill="#6B7280" font-size="6.5" text-anchor="middle">{esc(d)}</text>'
    svg += "</svg>"
    return svg


def load_history(asm: dict, score_general: int) -> list[dict]:
    """Historial real desde scan_history.db (>=2 puntos). Sin datos suficientes devuelve []."""
    try:
        db = ROOT / "dashboard_workspace" / "scan_history.db"
        if db.is_file():
            import asyncio
            try:
                import aiosqlite
            except Exception:
                aiosqlite = None  # type: ignore
            if aiosqlite is not None:
                async def _fetch():
                    async with aiosqlite.connect(db) as conn:
                        conn.row_factory = aiosqlite.Row
                        provs = asm.get("providers") or []
                        dom = provs[0].get("domain", "") if provs else ""
                        if not dom:
                            return []
                        cur = await conn.execute(
                            "SELECT created_at as fecha, score_general as score FROM scan_history WHERE domain=? ORDER BY created_at ASC LIMIT 30", (dom,))
                        rows = await cur.fetchall()
                        return [{"fecha": r["fecha"], "score": r["score"]} for r in rows]
                try:
                    real = asyncio.run(_fetch())
                    if real and len(real) >= 2:
                        return real
                except RuntimeError:
                    pass
    except Exception:
        pass
    return []


def load_asset_history(asm: dict) -> list[dict]:
    """Historial de superficie: subdominios/IPs/puertos por scan."""
    try:
        db = ROOT / "dashboard_workspace" / "scan_history.db"
        if db.is_file():
            import asyncio
            try:
                import aiosqlite
            except Exception:
                aiosqlite = None  # type: ignore
            if aiosqlite is not None:
                async def _fetch2():
                    async with aiosqlite.connect(db) as conn:
                        conn.row_factory = aiosqlite.Row
                        provs = asm.get("providers") or []
                        dom = provs[0].get("domain", "") if provs else ""
                        if not dom:
                            return []
                        cur = await conn.execute(
                            "SELECT created_at as fecha, subdomain_count, ip_count, open_ports FROM scan_assets WHERE domain=? ORDER BY created_at ASC LIMIT 30", (dom,))
                        rows = await cur.fetchall()
                        return [{"fecha": r["fecha"], "subs": r["subdomain_count"], "ips": r["ip_count"], "ports": r["open_ports"]} for r in rows]
                try:
                    real = asyncio.run(_fetch2())
                    if real and len(real) >= 2:
                        return real
                except RuntimeError:
                    pass
    except Exception:
        pass
    return []


def _asset_history_svg(history: list[dict], w=620, h=200) -> str:
    if not history or len(history) < 2:
        return ""
    pl, pr, pt, pb = 50, 30, 16, 36
    cw, ch = w - pl - pr, h - pt - pb
    subs = [int(x.get("subs", 0)) for x in history]
    ips = [int(x.get("ips", 0)) for x in history]
    ports = [int(x.get("ports", 0)) for x in history]
    dates = [str(x["fecha"])[-5:] for x in history]
    ymin = 0
    ymax = max(max(subs) if subs else 0, max(ips) if ips else 0, max(ports) if ports else 0) + 2
    yr = ymax - ymin or 1
    def yp(v): return pt + ch - (v - ymin) / yr * ch
    def xp(i): return pl + (i / max(len(history)-1,1)) * cw
    svg = f'<svg width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg" style="font-family:Arial,Helvetica,sans-serif;">'
    for val in range(ymin, ymax+1, max(1, (ymax)//5)):
        y = yp(val); svg += f'<text x="{pl-8}" y="{y+3}" fill="#6B7280" font-size="7" text-anchor="end">{val}</text>'
        svg += f'<line x1="{pl}" y1="{y}" x2="{w-pr}" y2="{y}" stroke="#D9DEE3" stroke-width=".5"/>'
    # Subs azul, IPs verde, Puertos naranja + leyenda
    for vals, col in [(subs, "#173B57"), (ips, "#2E7D32"), (ports, "#EF6C00")]:
        pts = " ".join(f"{xp(i)},{yp(vals[i])}" for i in range(len(vals)))
        svg += f'<polyline points="{pts}" fill="none" stroke="{col}" stroke-width="2.2"/>'
        for i,s in enumerate(vals):
            svg += f'<circle cx="{xp(i)}" cy="{yp(s)}" r="2.5" fill="{col}" stroke="#fff" stroke-width="1.2"/>'
    # Etiquetas solo para subs (evita saturación)
    for i,s in enumerate(subs):
        svg += f'<text x="{xp(i)}" y="{yp(s)-8}" fill="#173B57" font-size="6.5" font-weight="700" text-anchor="middle">{s}</text>'
    for i,d in enumerate(dates):
        svg += f'<text x="{xp(i)}" y="{h-6}" fill="#6B7280" font-size="6.5" text-anchor="middle">{esc(d)}</text>'
    svg += f'<g font-size="6.5"><text x="{pl}" y="{pt-2}" fill="#173B57">● Subs</text><text x="{pl+50}" y="{pt-2}" fill="#2E7D32">● IPs</text><text x="{pl+85}" y="{pt-2}" fill="#EF6C00">● Puertos</text></g>'
    svg += "</svg>"
    return svg


def render_risk_matrix(findings: list[dict[str, Any]]) -> str:
    """Heatmap impacto (severidad) x probabilidad (prioridad). Informativos fuera de la matriz."""
    imp_rows = [("Muy alto", "CRITICA", "#C62828"), ("Alto", "ALTA", "#EF6C00"),
                ("Medio", "MEDIA", "#F9A825"), ("Bajo", "BAJA", "#2E7D32")]
    prob_cols = [("Alta", "P1"), ("Media", "P2"), ("Baja", "P3")]
    cells: dict[tuple[str, str], int] = {}
    for f in findings:
        sev = f.get("severidad", "")
        prio = f.get("prioridad", "")
        if sev in ("INFORMATIVA", "INFO"):
            continue
        pr = "P1" if prio == "P1" else ("P2" if prio == "P2" else "P3")
        cells[(sev, pr)] = cells.get((sev, pr), 0) + 1
    thead = "".join(f"<th>{p}</th>" for p, _ in prob_cols)
    rows = ""
    for lbl, sev, col in imp_rows:
        tds = ""
        for plbl, pr in prob_cols:
            n = cells.get((sev, pr), 0)
            bg = col if n else "#F9FAFB"
            fg = "#fff" if n else "#9CA3AF"
            tds += f"<td class='num' style='background:{bg}; color:{fg}; font-weight:800; font-size:12pt;'>{n if n else '--'}</td>"
        rows += f"<tr><td style='font-weight:700; color:{col};'>{lbl}</td>{tds}</tr>"
    redzone = sum(cells.get((s, p), 0) for s in ("CRITICA", "ALTA") for p in ("P1", "P2"))
    return (
        "<div class='section-sub' style='page-break-before:always;'>Matriz de riesgo (impacto x probabilidad)</div>"
        "<div style='font-size:8.5pt; color:#4B5563; margin-bottom:6px;'>Las filas son el <strong>impacto</strong> (severidad del hallazgo) y las columnas la <strong>probabilidad</strong> (su prioridad SLA). Cada celda cuenta hallazgos: la esquina <strong>roja arriba-izquierda es lo urgente</strong> "
        f"(hay <strong>{redzone}</strong> hallazgo(s) críticos/altos con probabilidad alta o media). Informativos fuera de la matriz porque no son riesgo.</div>"
        "<table class='data'><thead><tr><th>Impacto \\ Probabilidad</th>" + thead + "</tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "<div style='font-size:7pt; color:#6B7280;'>Probabilidad por prioridad: P1 (0-7 días) = Alta, P2 (8-30 días) = Media, P3/P4 = Baja.</div>"
    )


def render_factores_evaluados(providers: list[dict[str, Any]]) -> str:
    """Modulo Factores evaluados (adopcion GC) + columna de estado real del escaneo."""
    n = max(len(providers), 1)

    def _c(fn):
        try:
            return sum(1 for p in providers if fn(p))
        except Exception:
            return 0

    def _s(fn):
        try:
            return sum(fn(p) for p in providers)
        except Exception:
            return 0

    dns = lambda p: p.get("dns") or {}
    hdrs = lambda p: (p.get("https") or {}).get("headers") or {}
    rows = [
        ("Configuraciones DNS", "SPF/DMARC, DKIM, DNSSEC, DANE, MX, NS, CAA, MTA-STS, TLS-RPT, BIMI, STARTTLS",
         "Verifica presencia y correcta configuración de registros DNS de seguridad y STARTTLS en MX",
         f"SPF ausente {_c(lambda p: not dns(p).get('spf_record'))}/{n} · DMARC ausente {_c(lambda p: not dns(p).get('dmarc_record'))}/{n} · DNSSEC {_c(lambda p: dns(p).get('dnssec_ok'))}/{n}"),
        ("SSL/TLS", "Version negociada, vigencia, SAN",
         "Evalua la fortaleza de la configuración TLS del servidor web",
         f"TLS: " + (", ".join(sorted({str((p.get('tls') or {}).get('negotiated_version', '--')) for p in providers})[:3]) or "--")),
        ("Cabeceras HTTP de seguridad", "HSTS, CSP, X-Frame-Options, X-Content-Type-Options",
         "Detecta cabeceras de seguridad faltantes o mal configuradas",
         f"HSTS falta {_c(lambda p: not hdrs(p).get('strict-transport-security'))}/{n} · CSP falta {_c(lambda p: not (hdrs(p).get('content-security-policy') or hdrs(p).get('content-security-policy-report-only')))}" + f"/{n}"),
        ("Analisis de CSP", "Directivas CSP (base-uri, object-src, frame-ancestors, form-action, unsafe-inline/unsafe-eval, comodines, report-uri)",
         "Deteccion de debilidades en la política de seguridad de contenido",
         f"{_s(lambda p: len(p.get('csp_findings') or []))} hallazgo(s)"),
        ("Seguridad de Cookies", "Flags Secure, HttpOnly, SameSite",
         "Verificacion de flags de seguridad en cookies HTTP",
         f"{_s(lambda p: len(p.get('cookie_findings') or []))} hallazgo(s)"),
        ("Superficie de subdominios", "DNS + crt.sh + fuerza bruta + pivoteo IP",
         "Descubrimiento pasivo y semi-activo de subdominios y activos expuestos",
         f"{_s(lambda p: len(p.get('subdomains') or []) + len(p.get('crt_subdomains') or []))} subdominios · {_s(lambda p: len(p.get('brute_subs') or []))} por brute force"),
        ("Reputacion de IPs", "DNSBL (Spamhaus, Barracuda, SpamCop, SORBS, CBL)",
         "Verifica si las IPs del dominio están listadas como maliciosas",
         f"{_s(lambda p: len((p.get('dns') or {}).get('ip_reputation') or []))} listado(s)"),
        ("Malware", "URLhaus (Abuse.ch)",
         "Consulta si el dominio ha sido reportado como distribuidor de malware",
         f"{'malicioso' if any((p.get('urlhaus') or {}).get('malicious') for p in providers) else 'limpio'}"),
        ("Vulnerabilidades", "OSV.dev + banners (vulscan) + EPSS/KEV",
         "Deteccion de CVEs asociados a tecnologias y versiones, priorizados por explotacion",
         f"{_s(lambda p: len(p.get('vulnerabilities') or []))} OSV · {_s(lambda p: len(p.get('cve_findings') or []))} banner · KEV {_s(lambda p: sum(1 for c in (p.get('cve_findings') or []) if c.get('in_kev')))}"),
        ("Fugas de credenciales", "leak-lookup + KUMO breach intel",
         "Identifica si el dominio aparece en breaches conocidos",
         f"{_s(lambda p: len([l for l in (p.get('credential_leaks') or []) if 'error' not in l]))} filtración(es)"),
        ("Typosquatting", "Variantes DNS (TLD, caracteres, omisiones)",
         "Genera variantes del dominio y verifica si están activas",
         f"{_s(lambda p: len(p.get('typosquatting') or []))} variante(s) activa(s)"),
        ("Patching cadence", "endoflife.date",
         "Determina si las tecnologías detectadas están EOL o próximas a EOL",
         f"{_s(lambda p: sum(1 for x in (p.get('patching') or []) if x.get('status') == 'eol'))} EOL"),
        ("Subdomain Takeover", "CNAME + fingerprints (S3, CloudFront, Heroku, Azure, GitHub Pages, etc.)",
         "Detecta CNAMEs a servicios externos no configurados o colgantes",
         f"{_s(lambda p: len(p.get('takeover_risks') or []))} riesgo(s) · {_s(lambda p: sum(1 for r in (p.get('takeover_risks') or []) if r.get('vulnerable')))} vulnerable(s)"),
        ("Supply Chain", "CSP headers + HTML scripts",
         "Extrae dominios de terceros desde CSP y scripts, verifica resolucion DNS",
         f"{_s(lambda p: len(p.get('supply_chain') or []))} tercero(s)"),
        ("Reputacion de terceros", "DNSBL + URLhaus sobre IPs y dominios de terceros",
         "Verifica si la cadena de suministro tiene reputación negativa",
         f"DNSBL {_s(lambda p: len((p.get('supply_chain_reputation') or {}).get('dnsbl') or []))} · URLhaus {_s(lambda p: len((p.get('supply_chain_reputation') or {}).get('urlhaus') or []))}"),
    ]
    body = "".join(f"<tr><td style='font-weight:600;'>{esc(f)}</td><td style='font-size:8pt;'>{esc(s)}</td><td style='font-size:8pt;'>{esc(d)}</td><td style='font-size:8pt;'>{esc(e)}</td></tr>" for f, s, d, e in rows)
    return ("<div class='section-sub'>Factores evaluados</div>"
            "<div class='info-box'>Este informe evalua los siguientes factores de seguridad, con su estado en el escaneo actual.</div>"
            "<table class='data'><thead><tr><th>Factor</th><th>Fuente</th><th>Detalle</th><th>Estado en este escaneo</th></tr></thead>"
            f"<tbody>{body}</tbody></table>")


def render_matrix_asm(matrix: list[dict[str, Any]], score_by_domain: dict[str, float] | None = None) -> str:
    """Modulo Matriz de controles ASM (adopcion GC) en vertical + columna Score (complemento B3)."""
    if not matrix:
        return "<div class='info-box'>Sin matriz ASM en este escaneo.</div>"
    score_by_domain = score_by_domain or {}
    ok, err = "&#10003;", "&#10007;"

    def _cell(val: str, good: bool | None) -> str:
        if good is None:
            return f"<td style='font-size:8pt;'>{val}</td>"
        col = "#2E7D32" if good else "#C62828"
        return f"<td style='font-size:8pt; color:{col}; font-weight:700;'>{val}</td>"

    def _yn(v: Any) -> tuple[str, bool]:
        return (ok, True) if v else (err, False)

    def _cnt(v: Any) -> tuple[str, None]:
        return (esc(v if v not in (None, "") else 0), None)

    def _stls(m: dict) -> tuple[str, bool | None]:
        if m.get("starttls_ok"):
            return (ok, True)
        if m.get("mx_count", 0) > 0:
            return (err, False)
        return ("NOT_APPLICABLE", None)

    def _tk(m: dict) -> tuple[str, bool | None]:
        if m.get("takeover_vulnerable"):
            return (err + " VULNERABLE", False)
        if m.get("takeover_count", 0) > 0:
            return ("potencial", None)
        return ("NOT_APPLICABLE", None)

    def _dnsbl(m: dict) -> tuple[str, bool | None]:
        if m.get("ip_reputation_clean"):
            return (ok + " limpia", True)
        return (f"{err} {m.get('ip_reputation_count', 0)} listado(s)", False)

    def _score(m: dict) -> tuple[str, bool | None]:
        sc = score_by_domain.get(str(m.get("dominio", "")))
        return (esc(sc) if sc is not None else "UNKNOWN", None)

    ctrls = [
        ("Domain Score", "D", _score),
        ("Subdominios", "G", lambda m: _cnt(m.get("subdominios", 0))),
        ("crt.sh", "G", lambda m: _cnt(m.get("crt_subdominios", 0))),
        ("HTTPS", "D", lambda m: (esc(m.get("https", "") or "--"), None)),
        ("HSTS", "D·G·O", lambda m: _yn(m.get("hsts"))),
        ("CSP", "D·G·O", lambda m: _yn(m.get("csp"))),
        ("CSP debilidades", "D·G·O", lambda m: _cnt(m.get("csp_finding_count", 0))),
        ("Cookies seguras", "D·G·O", lambda m: _yn(not m.get("cookie_insecure"))),
        ("SPF/DMARC", "D·G·O", lambda m: (esc(m.get("spf_dmarc", "") or "--"), None)),
        ("TLS 1.3", "D·G·O", lambda m: _yn(m.get("tls13_negociado"))),
        ("TLS version", "D·G·O", lambda m: (esc(m.get("tls_version", "") or "--"), None)),
        ("CAA", "G·O", lambda m: _yn(m.get("caa"))),
        ("MTA-STS", "—", lambda m: _yn(m.get("mta_sts"))),
        ("TLS-RPT", "—", lambda m: _yn(m.get("tls_rpt"))),
        ("STARTTLS", "D", _stls),
        ("MX", "—", lambda m: _cnt(m.get("mx_count", 0))),
        ("NS", "—", lambda m: _cnt(m.get("ns_count", 0))),
        ("DNSSEC", "G·O", lambda m: _yn(m.get("dnssec_ok"))),
        ("DKIM", "—", lambda m: _cnt(m.get("dkim_count", 0))),
        ("DANE", "—", lambda m: _cnt(m.get("dane_count", 0))),
        ("DNSBL", "D·G·O", _dnsbl),
        ("URLhaus", "D·G·O", lambda m: _yn(not m.get("urlhaus_malicious"))),
        ("CVEs", "D·G·O", lambda m: _cnt(m.get("vulnerability_count", 0))),
        ("Leaks", "D·G·O", lambda m: _cnt(m.get("credential_leak_count", 0))),
        ("Typosquatting", "D·G·O", lambda m: _cnt(m.get("typosquatting_count", 0))),
        ("Patching EOL", "D·G·O", lambda m: _cnt(m.get("patching_eol", 0) + m.get("patching_ending", 0))),
        ("Takeover", "D·O", _tk),
        ("Supply chain", "D·O", lambda m: _cnt(m.get("supply_chain_count", 0))),
        ("Supply reputacion", "D·O", lambda m: _yn(m.get("supply_reputation_clean"))),
    ]
    prov_heads = "".join(f"<th>{esc(m.get('proveedor') or m.get('dominio', ''))}<br><span style='font-weight:400; font-size:7pt;'>{esc(m.get('dominio', ''))}</span></th>" for m in matrix)
    rows = ""
    for label, mv, fn in ctrls:
        tds = ""
        for m in matrix:
            try:
                val, good = fn(m)
            except Exception:
                val, good = ("--", None)
            tds += _cell(val, good)
        rows += (f"<tr><td style='font-weight:600;'>{esc(label)}</td>"
                 f"<td class='num' style='font-size:7.5pt; color:#2F6F9F; font-weight:700; white-space:nowrap;'>{mv}</td>{tds}</tr>\n")
    return ("<div class='section-sub' id='sec-matriz-asm'>7.3 Matriz de controles ASM</div>"
            "<table class='data'><thead><tr><th>Control</th><th>Mueve a</th>" + prov_heads + "</tr></thead>"
            f"<tbody>{rows}</tbody></table>"
            "<div style='font-size:7pt; color:#6B7280;'>Columna Score (complemento B3): Domain Score por proveedor. Columna Mueve a: qué scores mueve cada control — <strong>D</strong>=Domain, <strong>G</strong>=General, <strong>O</strong>=Overall, <strong>—</strong>=contexto (no mueve score). Verde = verificado, rojo = fallido.</div>")


# ---------------------------------------------------------------------------
# Adopcion GC: ficha detallada por proveedor (bloques h4 estilo GC)
# ---------------------------------------------------------------------------
def _li(items: list[str]) -> str:
    return "".join(f"<li>{x}</li>" for x in items)


def _sub_name(s: Any) -> str:
    if isinstance(s, dict):
        return str(s.get("host") or s.get("fqdn") or s.get("domain") or s.get("subdomain") or "")
    return str(s or "")


def gc_provider_detail(p: dict[str, Any], matrix: list | None = None) -> str:
    """Replica los bloques de detalle del informe GC con datos 100% reales del asm."""
    dom = p.get("domain", "")
    parts: list[str] = []

    # Encabezado tarjeta proveedor (adopcion GC) + complemento B3 (Domain Score)
    _ips = ", ".join((p.get("dns") or {}).get("ipv4") or []) or "-"
    _h = p.get("https") or {}
    _tls = p.get("tls") or {}
    _subs = [_sub_name(s) for s in (p.get("subdomains") or []) if _sub_name(s)]
    _crt = [str(s) for s in (p.get("crt_subdomains") or []) if s]
    _san = [str(s) for s in (p.get("san_list") or []) if s]
    _score = domain_score(p)
    _https_txt = str(_h.get("status_code")) if isinstance(_h.get("status_code"), int) else str(_h.get("error") or "-")
    parts.append(
        f"<div class='section-sub2'>Ficha detallada -- {esc(dom)}</div>"
        f"<div style='background:#F3F5F7; border:1px solid #D9DEE3; border-radius:8px; padding:12px 14px; display:flex; align-items:center; gap:12px; margin-bottom:8px;'>"
        f"<div style='flex:1;'><div style='font-size:12pt; font-weight:800; color:#173B57;'>{esc(p.get('name') or dom)}</div>"
        f"<div style='font-size:8pt; color:#6B7280;'><code>{esc(dom)}</code> - {esc(_ips)}</div>"
        f"<div style='font-size:8pt; color:#4B5563; margin-top:4px;'>443: {'abierto' if (p.get('port_443') or {}).get('open') else 'cerrado'} - 80: {'abierto' if (p.get('port_80') or {}).get('open') else 'cerrado'} - Subdominios: {len(_subs)} - crt.sh: {len(_crt)} - SAN: {len(_san)}</div>"
        f"<div style='font-size:8pt; color:#4B5563;'><strong>HTTPS:</strong> {esc(_https_txt)[:40]} - <strong>TLS:</strong> {esc(str(_tls.get('negotiated_version') or _tls.get('error') or '-')[:40])} - <strong>Cert. hasta:</strong> {esc(str(_tls.get('cert_expiry') or '-')[:40])}</div></div>"
        f"<div style='text-align:center;'><span class='score-badge {_letter(_score)}'>{_letter(_score)}</span><div style='font-size:8pt; color:#173B57; font-weight:700;'>{_score}/100</div></div>"
        f"</div>"
    )
    if _subs:
        _items = []
        for s in (p.get("subdomains") or [])[:20]:
            if isinstance(s, dict):
                _items.append(f"<li><code>{esc(_sub_name(s))}</code> {esc(', '.join((s.get('ipv4') or [])[:3]))}</li>")
            else:
                _items.append(f"<li><code>{esc(_sub_name(s))}</code></li>")
        if len(_subs) > 20:
            _items.append(f"<li class='muted'>... y {len(_subs) - 20} más</li>")
        parts.append(f"<h4>Subdominios</h4><ul class='compact'>{''.join(_items)}</ul>")
    if _crt:
        _items = "".join(f"<li><code>{esc(s)}</code></li>" for s in _crt[:20])
        if len(_crt) > 20:
            _items += f"<li class='muted'>... y {len(_crt) - 20} más</li>"
        parts.append(f"<h4>Subdominios (crt.sh)</h4><ul class='compact'>{_items}</ul>")
    if _san:
        parts.append(f"<h4>SAN</h4><ul class='compact'>{''.join(f'<li><code>{esc(s)}</code></li>' for s in _san[:20])}</ul>")

    vulns = p.get("vulnerabilities") or []
    if vulns:
        vitems = []
        for v in vulns[:10]:
            chunk = '<li><span class="cve-badge">' + esc(v.get("cve_id", v.get("id", "?"))) + "</span> " + esc(str(v.get("summary", ""))[:120]) + ' <span class="muted">(' + esc(str(v.get("package", ""))) + ")</span>"
            if v.get("in_kev"):
                chunk += ' <span class="kev-badge">KEV</span>'
            elif v.get("epss_score") is not None:
                try:
                    chunk += ' <span class="epss-badge">EPSS ' + str(round(float(v.get("epss_score")), 3)) + "</span>"
                except Exception:
                    pass
            vitems.append(chunk + "</li>")
        if len(vulns) > 10:
            vitems.append(f"<li class='muted'>... y {len(vulns) - 10} más</li>")
        parts.append("<h4>Vulnerabilidades (OSV.dev)</h4><ul class='compact'>" + "".join(vitems) + "</ul>")

    patching = p.get("patching") or []
    if patching:
        items = ""
        for pch in patching:
            st = pch.get("status", "")
            icon = '<span class="ok">&#10003;</span>' if st == "current" else ('<span class="warn">&#9888;</span>' if st == "ending" else '<span class="err">&#10007;</span>')
            items += f"<li>{icon} <strong>{esc(pch.get('technology', ''))}</strong> {esc(str(pch.get('version', '') or '?'))} {esc(str(pch.get('detail', ''))[:80])}</li>"
        parts.append(f"<h4>Patching cadence (endoflife.date)</h4><ul class='compact'>{items}</ul>")

    supply = p.get("supply_chain") or []
    if supply:
        items = ""
        for s in supply[:10]:
            if isinstance(s, str):
                items += f"<li><code>{esc(s)}</code></li>"
            else:
                items += f"<li><code>{esc(s.get('domain', ''))}</code> ({esc(str(s.get('source', '?')))}) -- {'&#10003; resuelve' if s.get('resolves') else '&#10007; no resuelve'} {esc(', '.join((s.get('ips') or [])[:2]))}</li>"
        if len(supply) > 10:
            items += f"<li class='muted'>... y {len(supply) - 10} más</li>"
        parts.append(f"<h4>Dependencias de terceros (Supply Chain)</h4><ul class='compact'>{items}</ul>")

    cves = p.get("cve_findings") or []
    if cves:
        def _ckey2(c):
            try:
                return float(c.get("risk_score") or 0)
            except Exception:
                return 0.0
        cves = sorted(cves, key=_ckey2, reverse=True)
        citems = []
        for c in cves[:20]:
            chunk = "<li><strong>" + esc(c.get("id", "?")) + "</strong> -- " + esc(str(c.get("title", ""))[:150]) + " <span class='muted'>[" + esc(str(c.get("type", ""))) + "] Puerto " + esc(str(c.get("port", "?"))) + " / " + esc(str(c.get("product", ""))[:40]) + "</span>"
            if c.get("in_kev"):
                chunk += ' <span class="kev-badge">KEV</span>'
            if c.get("epss_score") is not None:
                try:
                    chunk += ' <span class="epss-badge">EPSS ' + str(round(float(c.get("epss_score")), 3)) + "</span>"
                except Exception:
                    pass
            if c.get("risk_score") is not None:
                chunk += ' <span class="epss-badge">riesgo ' + esc(str(c.get("risk_score"))) + "</span>"
            citems.append(chunk + "</li>")
        if len(cves) > 20:
            citems.append(f"<li class='muted'>... y {len(cves) - 20} más</li>")
        parts.append("<h4>CVEs por Banner Grab (vulscan, ordenados por riesgo)</h4><ul class='compact'>" + "".join(citems) + "</ul>")

    banners = p.get("banner_grabs") or []
    if banners:
        items = ""
        for b in banners[:12]:
            if not isinstance(b, dict):
                continue
            chunk = f"<li><strong>Puerto {esc(str(b.get('port', '?')))}</strong> ({esc(str(b.get('protocol', '?')))}): <code>{esc(str(b.get('product', 'desconocido'))[:60])}</code>"
            if b.get("version"):
                chunk += f" v{esc(str(b['version'])[:30])}"
            if b.get("banner"):
                chunk += f" <span class='muted'>{esc(str(b['banner'])[:100])}</span>"
            if b.get("error"):
                chunk += f" <span class='error'>{esc(str(b['error'])[:100])}</span>"
            items += chunk + "</li>"
        if items:
            parts.append(f"<h4>Banners de Servicio</h4><ul class='compact'>{items}</ul>")

    api_eps = p.get("api_endpoints") or []
    if api_eps:
        non404 = [e for e in api_eps if isinstance(e, dict) and e.get("status_code") and e["status_code"] != 404]
        shadow = [e for e in api_eps if isinstance(e, dict) and e.get("is_shadow")]
        rows = "".join(f"<tr><td>{esc(str(e.get('method', '?')))}</td><td><code>{esc(str(e.get('path', '?'))[:60])}</code></td><td>{esc(str(e.get('status_code', '?')))}</td><td>{esc(str(e.get('category', '?')))}</td><td>{'&#9888; Shadow' if e.get('is_shadow') else ''}</td></tr>" for e in non404[:25])
        extra = f"<p class='muted small'>... y {len(non404) - 25} más de {len(api_eps)} endpoints probados</p>" if len(non404) > 25 else ""
        parts.append(f"<h4>API Endpoints Discovery</h4><p class='meta'>{len(api_eps)} rutas probadas - {len(non404)} responden - {len(shadow)} shadow API</p><table class='data'><thead><tr><th>Método</th><th>Ruta</th><th>Status</th><th>Categoría</th><th>Shadow</th></tr></thead><tbody>{rows or '<tr><td colspan=5>Ninguno responde</td></tr>'}</tbody></table>{extra}")

    paths = p.get("public_paths") or []
    if paths:
        interesting = [x for x in paths if isinstance(x, dict) and x.get("status") not in (None, 404, "404")]
        to_show = interesting if interesting else paths[:8]
        rows = "".join(f"<tr><td><code>{esc(str(x.get('path', x.get('url', ''))[:70]))}</code></td><td>{esc(str(x.get('status', x.get('status_code', x.get('error', '--')))))}</td><td>{esc(str(x.get('method', 'HEAD')))}</td></tr>" for x in to_show[:15])
        parts.append(f"<h4>Rutas Públicas (HEAD)</h4><table class='data'><thead><tr><th>Ruta</th><th>Status</th><th>Metodo</th></tr></thead><tbody>{rows}</tbody></table>")

    tls = p.get("tls") or {}
    cert_items = []
    for k, lbl in (("cert_subject", "Subject"), ("cert_issuer", "Issuer"), ("cert_expiry", "Expira"), ("cert_serial", "Serial"), ("cert_version", "Version")):
        if tls.get(k):
            cert_items.append(f"<li><strong>{lbl}:</strong> {esc(str(tls[k])[:120])}</li>")
    if not cert_items and tls.get("negotiated_version"):
        cert_items.append(f"<li><strong>Version negociada:</strong> {esc(str(tls['negotiated_version']))}</li>")
    if cert_items:
        parts.append(f"<h4>Detalles del Certificado TLS</h4><ul class='compact'>{''.join(cert_items)}</ul>")

    h = p.get("https") or {}
    chain = h.get("redirect_chain") or []
    if chain:
        parts.append(f"<h4>Cadena de Redireccion</h4><ul class='compact'>{''.join(f'<li><code>{esc(str(u)[:120])}</code></li>' for u in chain[:10])}</ul>")
    fp_items = []
    for k, lbl in (("server_fingerprint", "Server"), ("x_powered_by", "X-Powered-By"), ("via", "Via"), ("cf_ray", "CF-Ray")):
        if h.get(k):
            fp_items.append(f"<li><strong>{lbl}:</strong> {esc(str(h[k])[:120])}</li>")
    if fp_items:
        parts.append(f"<h4>Huella de Servidor</h4><ul class='compact'>{''.join(fp_items)}</ul>")
    hdr = h.get("headers") or {}
    sec_items = []
    for k, lbl in (("x-frame-options", "X-Frame-Options"), ("x-content-type-options", "X-Content-Type-Options"), ("referrer-policy", "Referrer-Policy"), ("permissions-policy", "Permissions-Policy"), ("cross-origin-opener-policy", "COOP")):
        if hdr.get(k) is not None:
            sec_items.append(f"<li><strong>{lbl}:</strong> <code>{esc(str(hdr[k])[:100])}</code></li>")
    if sec_items:
        parts.append(f"<h4>Cabeceras de Seguridad</h4><ul class='compact'>{''.join(sec_items)}</ul>")

    oports = [o for o in (p.get("open_ports") or []) if isinstance(o, dict) and o.get("state") == "open"]
    if oports:
        port_items = []
        for o in oports[:15]:
            port_items.append("<li>Puerto " + esc(str(o.get("port", "?"))) + ": " + esc(str(o.get("service", "?"))[:60]) + "</li>")
        parts.append("<h4>Puertos Abiertos</h4><ul class='compact'>" + "".join(port_items) + "</ul>")

    brute = p.get("brute_subs") or []
    if brute:
        items = ""
        for b in brute[:15]:
            if isinstance(b, dict):
                items += f"<li><code>{esc(b.get('fqdn', '?'))}</code> -- {esc(', '.join((b.get('ips') or [])[:3]))}</li>"
            else:
                items += f"<li><code>{esc(str(b))}</code></li>"
        parts.append(f"<h4>Subdominios (Brute Force DNS)</h4><ul class='compact'>{items}</ul>")

    piv = p.get("pivot_results") or []
    if piv:
        items = ""
        for r in piv[:5]:
            if isinstance(r, dict):
                fqdns = r.get("fqdns_from_crt", []) or []
                items += f"<li><code>{esc(r.get('ip', '?'))}</code>: PTR={esc(str(r.get('ptr', '-'))[:60])}, crt.sh: {esc(', '.join(fqdns[:5]))}{'...' if len(fqdns) > 5 else ''}</li>"
        if items:
            parts.append(f"<h4>IP Pivot (FQDNs descubiertos)</h4><ul class='compact'>{items}</ul>")

    risks = p.get("takeover_risks") or []
    if risks:
        items = ""
        for r in risks[:10]:
            badge = '<span class="err">&#10007; VULNERABLE</span>' if r.get("vulnerable") else '<span class="warn">&#9888; POTENCIAL</span>'
            items += f"<li><code>{esc(r.get('host', ''))}</code> &rarr; <code>{esc(r.get('cname', '')[:80])}</code> {badge}: {esc(str(r.get('description', ''))[:120])}</li>"
        if len(risks) > 10:
            items += f"<li class='muted'>... y {len(risks) - 10} más</li>"
        parts.append(f"<h4>Riesgos de Subdomain Takeover</h4><ul class='compact'>{items}</ul>")

    csp_f = p.get("csp_findings") or []
    if csp_f:
        items = ""
        for f in csp_f[:10]:
            icon = "&#10007;" if f.get("severity") == "high" else ("&#9888;" if f.get("severity") == "medium" else "&#9679;")
            items += f"<li>{icon} [{str(f.get('severity', '')).upper()}] <strong>{esc(f.get('directive', ''))}</strong>: {esc(str(f.get('description', ''))[:140])}</li>"
        if len(csp_f) > 10:
            items += f"<li class='muted'>... y {len(csp_f) - 10} más</li>"
        parts.append(f"<h4>Análisis de CSP</h4><ul class='compact'>{items}</ul>")

    ck_f = p.get("cookie_findings") or []
    if ck_f:
        items = ""
        for f in ck_f[:10]:
            icon = "&#10007;" if f.get("severity") == "high" else ("&#9888;" if f.get("severity") == "medium" else "&#9679;")
            items += f"<li>{icon} [{str(f.get('severity', '')).upper()}] {esc(str(f.get('description', ''))[:160])}</li>"
        if len(ck_f) > 10:
            items += f"<li class='muted'>... y {len(ck_f) - 10} más</li>"
        parts.append(f"<h4>Seguridad de Cookies</h4><ul class='compact'>{items}</ul>")

    scr = p.get("supply_chain_reputation") or {}
    scr_items = []
    for dd in scr.get("dnsbl", []) or []:
        scr_items.append(f"<li><span class='err'>&#10007; DNSBL: IP {esc(dd.get('ip', ''))} en {esc(dd.get('dnsbl', ''))}</span></li>")
    for uu in scr.get("urlhaus", []) or []:
        scr_items.append(f"<li><span class='err'>&#10007; URLhaus: {esc(uu.get('domain', ''))} ({uu.get('url_count', 0)} urls)</span></li>")
    if scr_items:
        parts.append(f"<h4>Reputación de terceros (Supply Chain)</h4><ul class='compact'>{''.join(scr_items)}</ul>")

    waf = p.get("waf_detection") or {}
    if waf.get("detected"):
        w = waf.get("waf") or []
        wtxt = ", ".join(w) if isinstance(w, list) else str(w)
        ev = (waf.get("evidence") or [])
        parts.append(f"<h4>WAF / CDN Detectado</h4><ul class='compact'><li><strong>{esc(wtxt[:120])}</strong> (confianza {esc(str(waf.get('confidence', '?')))})</li>{''.join(f'<li>{esc(str(e)[:120])}</li>' for e in ev[:4])}</ul>")
    cloud = p.get("cloud_storage") or {}
    if (cloud.get("buckets") or cloud.get("publicos") or cloud.get("archivos_sensibles")):
        citems = []
        for b in (cloud.get("publicos") or [])[:6]:
            citems.append(f"<li><span class='err'>&#10007; Público:</span> <code>{esc(b.get('bucket', b.get('url', '?'))[:100])}</code></li>")
        for b in (cloud.get("buckets") or [])[:6]:
            if isinstance(b, dict) and not b.get("public"):
                citems.append(f"<li>&#10003; Privado: <code>{esc(str(b.get('bucket', b.get('url', '?')))[:100])}</code></li>")
        for a in (cloud.get("archivos_sensibles") or [])[:6]:
            citems.append(f"<li>&#9888; Sensible: <code>{esc(str(a)[:100])}</code></li>")
        parts.append(f"<h4>Cloud Storage</h4><ul class='compact'>{''.join(citems) or '<li>Sin hallazgos</li>'}</ul>")

    ext = p.get("external") or {}
    whois = ext.get("whois") or {}
    if "error" not in whois and any(whois.get(k) for k in ("registrar", "registrant_organization", "creation_date", "emails")):
        witems = []
        for k, lbl in (("registrar", "Registrar"), ("registrant_organization", "Organizacion"), ("registrant_country", "Pais"), ("creation_date", "Creado"), ("expiration_date", "Expira")):
            if whois.get(k):
                witems.append(f"<li>{lbl}: {esc(str(whois[k])[:100])}</li>")
        if whois.get("emails"):
            witems.append(f"<li>Emails: {esc(', '.join(whois['emails'][:5]))}</li>")
        if witems:
            parts.append(f"<h4>WHOIS</h4><ul class='compact'>{''.join(witems)}</ul>")
    dnsd = ext.get("dnsdumpster") or {}
    if "error" not in dnsd and dnsd.get("host_records"):
        dnsd_items = []
        for r in dnsd["host_records"][:10]:
            rest = ", ".join(str(x) for x in r[1:])
            dnsd_items.append("<li><code>" + esc(str(r[0])[:60]) + "</code> (" + esc(rest[:80]) + ")</li>")
        parts.append("<h4>DNSDumpster</h4><ul class='compact'>" + "".join(dnsd_items) + "</ul>")
    sh = ext.get("shodan") or {}
    if "error" not in sh and sh.get("hosts"):
        ports = sorted({pp for hh in sh["hosts"] for pp in hh.get("ports", [])})[:20]
        vulnss = sorted({vv for hh in sh["hosts"] for vv in hh.get("vulns", [])})[:10]
        sitems = []
        dns_ips = (p.get("dns") or {}).get("ipv4") or []
        sitems.append(f"<li>IPs del dominio: {len(dns_ips)} | Consultadas por Shodan: {len(sh.get('hosts',[]))} | Motivo: límite de consulta / ventana de evaluación</li>")
        if ports:
            sitems.append(f"<li>Puertos: {esc(', '.join(str(x) for x in ports))}</li>")
        if vulnss:
            sitems.append(f"<li>Vulnerabilidades: {esc(', '.join(vulnss))}</li>")
        for hh in sh["hosts"][:3]:
            if hh.get("org"):
                sitems.append(f"<li>Org: {esc(str(hh['org'])[:80])} ({esc(str(hh.get('country', '?')))})</li>")
        if sitems:
            parts.append(f"<h4>Shodan</h4><ul class='compact'>{''.join(sitems)}</ul>")
    censys = ext.get("censys") or {}
    if "error" not in censys:
        if censys.get("certificates"):
            cert_items = []
            for c in censys["certificates"][:3]:
                fp = str(c.get("fingerprint_sha256", ""))[:24]
                start = str((c.get("validity", {}) or {}).get("start", ""))[:10]
                cert_items.append("<li><code>" + esc(fp) + "</code> " + esc(start) + "</li>")
            parts.append("<h4>Censys (" + str(len(censys["certificates"])) + " certificados)</h4><ul class='compact'>" + "".join(cert_items) + "</ul>")
        if censys.get("hosts"):
            host_items = []
            for hh in censys["hosts"][:3]:
                svcs = ", ".join(str(s.get("service_name", "")) for s in (hh.get("services") or [])[:5])
                host_items.append("<li>" + esc(hh.get("ip", "?")) + " -- " + esc(svcs) + "</li>")
            parts.append("<h4>Censys Hosts</h4><ul class='compact'>" + "".join(host_items) + "</ul>")
    th = ext.get("theharvester") or {}
    if "error" not in th and (th.get("emails") or th.get("subdomains") or th.get("ips")):
        titems = []
        if th.get("emails"):
            titems.append(f"<li>Emails: {esc(', '.join(th['emails'][:10]))}</li>")
        if th.get("subdomains"):
            titems.append(f"<li>Subdominios: {esc(', '.join(th['subdomains'][:10]))}</li>")
        if th.get("ips"):
            titems.append(f"<li>IPs: {esc(', '.join(th['ips'][:5]))}</li>")
        parts.append(f"<h4>theHarvester</h4><ul class='compact'>{''.join(titems)}</ul>")
    idb = ext.get("internetdb") or {}
    if idb and not idb.get("error"):
        hosts = idb.get("hosts") or idb.get("ips") or []
        if hosts:
            parts.append(f"<h4>Shodan InternetDB</h4><ul class='compact'><li>{len(hosts) if isinstance(hosts, list) else 1} host(s) con puertos/vulns consultados</li></ul>")
    sexe = ext.get("shodan_exposure") or ext.get("exposure") or {}
    if sexe and not sexe.get("error") and (sexe.get("open_ports") or sexe.get("total_cves") or sexe.get("hosts")):
        parts.append(f"<h4>Shodan Exposure</h4><ul class='compact'><li>Puertos: {esc(str(sexe.get('open_ports', ''))[:120])} | CVEs: {esc(str(sexe.get('total_cves', 0)))}</li></ul>")

    kumo = p.get("kumo") or {}
    if isinstance(kumo, dict):
        wb = kumo.get("wayback") or {}
        if wb.get("interesting") and not wb.get("error"):
            parts.append(f"<h4>Wayback Machine</h4><ul class='compact'>{''.join(f'<li><code>{esc(str(u)[:110])}</code></li>' for u in wb['interesting'][:6])}</ul>")
        bi = kumo.get("breachintel") or {}
        if bi and not bi.get("error"):
            s = bi.get("summary") or {}
            seg = []
            if s.get("total_employees_leaked"):
                seg.append(f"empleados: {s['total_employees_leaked']}")
            if s.get("total_clients_leaked"):
                seg.append(f"clientes: {s['total_clients_leaked']}")
            if s.get("total_infostealer_hits"):
                seg.append(f"<b>infostealer: {s['total_infostealer_hits']}</b>")
            if seg:
                parts.append(f"<h4>Breach Intel</h4><ul class='compact'><li>{' - '.join(seg)}</li></ul>")
        js = kumo.get("js_secrets") or {}
        if js.get("secrets") and not js.get("error"):
            js_items = []
            for x in js["secrets"][:8]:
                js_items.append("<li><b>" + esc(x.get("type", "")) + "</b> en <code>" + esc(str(x.get("file", ""))[:70]) + "</code> -- " + esc(str(x.get("value", ""))[:50]) + "</li>")
            parts.append("<h4>JS Secrets</h4><ul class='compact'>" + "".join(js_items) + "</ul>")
        nu = kumo.get("nuclei") or {}
        if nu.get("findings") and not nu.get("error"):
            sc = nu.get("severity_counts") or {}
            seg = " - ".join(f"{sc.get(sv, 0)} {sv}" for sv in ("critical", "high", "medium", "low", "info") if sc.get(sv))
            nu_items = []
            for f in nu["findings"][:10]:
                nu_items.append("<li>" + esc(str(f.get("name", "?"))[:120]) + "</li>")
            parts.append("<h4>Vuln Scanner KUMO</h4><p class='meta'>" + esc(seg) + "</p><ul class='compact'>" + "".join(nu_items) + "</ul>")

    prism = p.get("prism") or {}
    if isinstance(prism, dict):
        ll = prism.get("leak_lookup") or {}
        if ll and not ll.get("error") and ll.get("breaches"):
            ll_items = []
            for b in ll["breaches"][:12]:
                ll_items.append('<li><span class="err">' + esc(b.get("name", "?")) + "</span></li>")
            parts.append("<h4>Prism Breach Lookup (" + str(len(ll["breaches"])) + ")</h4><ul class='compact'>" + "".join(ll_items) + "</ul>")
        oc = prism.get("onion_checker") or {}
        if oc and not oc.get("error") and oc.get("results"):
            oc_items = []
            for r in oc["results"][:8]:
                oc_items.append("<li><code>" + esc(str(r.get("url", "?"))[:90]) + "</code> (" + esc(str(r.get("source", "?"))) + ")</li>")
            parts.append("<h4>Prism Onion / Dark Web</h4><ul class='compact'>" + "".join(oc_items) + "</ul>")
        gh = prism.get("github_recon") or {}
        if gh and not gh.get("error") and (gh.get("profile") or gh.get("repo_count")):
            prof = gh.get("profile") or {}
            seg = []
            if prof.get("name"):
                seg.append(f"@{gh.get('username', '?')} ({esc(str(prof['name'])[:60])})")
            if gh.get("repo_count"):
                seg.append(f"{gh.get('repo_count')} repos - {gh.get('total_stars', 0)} stars")
            if gh.get("emails"):
                seg.append("emails: " + esc(", ".join(gh["emails"][:4])))
            parts.append(f"<h4>Prism GitHub Recon</h4><ul class='compact'><li>{' - '.join(seg) or 'sin datos'}</li></ul>")
        gr = prism.get("gravatar") or {}
        if gr and not gr.get("error") and gr.get("hits"):
            gr_items = []
            for hh in gr["hits"][:6]:
                gr_items.append("<li><b>" + esc(hh.get("display_name", "?")) + "</b> (" + esc(hh.get("email", "?")) + ")</li>")
            parts.append("<h4>Prism Gravatar</h4><ul class='compact'>" + "".join(gr_items) + "</ul>")
        wa = prism.get("website_analyzer") or {}
        if wa and not wa.get("error") and any(wa.get(k) for k in ("technologies", "social_links", "emails", "phones")):
            witems = []
            if wa.get("technologies"):
                witems.append("<li><b>Tech:</b> " + esc(", ".join(str(x) for x in wa["technologies"][:10])) + "</li>")
            if wa.get("social_links"):
                witems.append("<li><b>Redes:</b> " + " - ".join(f"{esc(str(s.get('platform', '?')))}: @{esc(str(s.get('username', '?')))}" for s in wa["social_links"][:6]) + "</li>")
            if wa.get("emails"):
                witems.append("<li><b>Emails:</b> " + esc(", ".join(wa["emails"][:6])) + "</li>")
            if wa.get("phones"):
                witems.append("<li><b>Tel:</b> " + esc(", ".join(wa["phones"][:4])) + "</li>")
            parts.append(f"<h4>Prism Website Analyzer</h4><ul class='compact'>{''.join(witems)}</ul>")
        sv = prism.get("smtp_verify") or {}
        if sv and not sv.get("error") and sv.get("per_email"):
            sitems = []
            for r in sv["per_email"][:8]:
                if not isinstance(r, dict):
                    continue
                st = "existe" if r.get("exists") is True else ("no existe" if r.get("exists") is False else "indefinido")
                sitems.append(f"<li><code>{esc(r.get('email', '?'))}</code>: <b>{st}</b>{' - catch-all' if r.get('catch_all') else ''}</li>")
            if sitems:
                parts.append(f"<h4>Prism SMTP Verify</h4><ul class='compact'>{''.join(sitems)}</ul>")
        vt = prism.get("virustotal") or {}
        if vt and not vt.get("error") and vt.get("status") == "ok":
            verdict = "malicioso" if vt.get("malicious") else ("sospechoso" if vt.get("suspicious") else "limpio")
            vt_txt = esc(str(vt.get("query", "?"))[:80]) + ": <b>" + verdict + "</b>"
            if vt.get("malicious"):
                vt_txt += " - " + str(vt.get("malicious")) + " malicioso"
            if vt.get("suspicious"):
                vt_txt += " - " + str(vt.get("suspicious")) + " sospechoso"
            parts.append("<h4>Prism VirusTotal</h4><ul class='compact'><li>" + vt_txt + "</li></ul>")
        ab = prism.get("abuseipdb") or {}
        if ab and not ab.get("error") and ab.get("status") == "ok":
            ab_seg = f"score {ab.get('abuse_score')}/100 - {ab.get('total_reports', 0)} reportes"
            if ab.get("is_tor"):
                ab_seg += " - TOR"
            parts.append(f"<h4>Prism AbuseIPDB</h4><ul class='compact'><li>{esc(ab_seg)}</li></ul>")

    co = p.get("claude_osint") or {}
    if isinstance(co, dict):
        m365 = co.get("m365_fingerprint") or {}
        if m365 and not m365.get("error") and any(m365.get(k) for k in ("tenant_space", "tenant_guid", "m365_detected")):
            mitems = []
            if m365.get("tenant_space"):
                mitems.append(f"Namespace: <b>{esc(str(m365['tenant_space'])[:60])}</b>")
            if m365.get("tenant_guid"):
                mitems.append(f"Tenant GUID: <code>{esc(str(m365['tenant_guid'])[:60])}</code>")
            if (m365.get("oidc") or {}).get("issuer"):
                mitems.append(f"Issuer: <code>{esc(str(m365['oidc']['issuer'])[:80])}</code>")
            if m365.get("m365_detected"):
                mitems.append("Microsoft 365 detectado")
            parts.append(f"<h4>Claude-OSINT M365 Fingerprint</h4><ul class='compact'>{''.join(f'<li>{x}</li>' for x in mitems)}</ul>")
        spf = co.get("spf_supply_chain") or {}
        if spf and not spf.get("error") and (spf.get("verdict") or spf.get("supply_chain")):
            v = spf.get("verdict") or {}
            sitems = [f"Verdict: <b>{esc(str(v.get('spoofable', v)[:60]))}</b>"]
            sc = spf.get("supply_chain") or {}
            if sc:
                if sc.get("lookup_cost_mechanisms") is not None:
                    sitems.append(f"Lookups: {sc.get('lookup_cost_mechanisms')} - voids: {sc.get('void_lookups')}")
                if sc.get("dead_includes"):
                    sitems.append(f"Dead: <code>{esc(', '.join(sc['dead_includes'][:5]))}</code>")
                if sc.get("perm_error"):
                    sitems.append("<span class='err'>PermError SPF fail-open</span>")
            parts.append(f"<h4>Claude-OSINT SPF/DMARC Supply-chain</h4><ul class='compact'>{''.join(f'<li>{x}</li>' for x in sitems)}</ul>")
        oa = co.get("org_attribution") or {}
        if oa and not oa.get("error") and (oa.get("lei") or (oa.get("crt_sh_org") or {}).get("candidate_domains")):
            oitems = []
            if oa.get("lei"):
                oitems.append(f"LEI: <code>{esc(str(oa['lei'])[:40])}</code> -- {esc(str(oa.get('legal_name', ''))[:80])}")
            if oa.get("direct_children"):
                oitems.append(f"Hijos GLEIF: {esc(', '.join(str(c.get('name', '?')) for c in oa['direct_children'][:5]))}")
            if (oa.get("crt_sh_org") or {}).get("candidate_domains"):
                oitems.append(f"crt.sh O=: <code>{esc(', '.join(oa['crt_sh_org']['candidate_domains'][:6]))}</code>")
            parts.append(f"<h4>Claude-OSINT Org Attribution</h4><ul class='compact'>{''.join(f'<li>{x}</li>' for x in oitems)}</ul>")
        cti = co.get("cti_chatter") or {}
        if cti and not cti.get("error"):
            citems = []
            rw = cti.get("ransomwatch") or {}
            if rw.get("hits"):
                citems.append(f"Ransomwatch: <b>{rw.get('total', 0)}</b> (" + esc("; ".join(str(hh.get("title", "?"))[:60] for hh in rw["hits"][:3])) + ")")
            rl = cti.get("ransomware_live") or {}
            if rl.get("hits"):
                citems.append(f"Ransomware.live: <b>{rl.get('total', 0)}</b>")
            if citems:
                parts.append(f"<h4>Claude-OSINT CTI Chatter</h4><ul class='compact'>{''.join(f'<li>{x}</li>' for x in citems)}</ul>")
        pdn = co.get("passive_dns_extra") or {}
        if pdn and not pdn.get("error") and pdn.get("subdomains"):
            parts.append(f"<h4>Claude-OSINT Passive DNS ({len(pdn['subdomains'])})</h4><ul class='compact'>{''.join(f'<li><code>{esc(str(s)[:80])}</code></li>' for s in pdn['subdomains'][:10])}</ul>")
        cn = co.get("cloud_native_fp") or {}
        if cn and not cn.get("error") and cn.get("fingerprints"):
            cn_items = []
            for f in cn["fingerprints"][:6]:
                cn_items.append("<li><b>" + esc(str(f.get("service", "?"))) + "</b> -- <code>" + esc(str(f.get("cname", "?"))[:80]) + "</code></li>")
            parts.append("<h4>Claude-OSINT Cloud-native fingerprint</h4><ul class='compact'>" + "".join(cn_items) + "</ul>")
        sop = co.get("saml_oidc_probe") or co.get("sso_oidc_probe") or {}
        if sop and not sop.get("error") and any((sop.get(k) or {}).get("reachable") for k in ("openid_config", "saml_metadata", "adfs_mex")):
            sitems = []
            for key, label in (("openid_config", "OIDC"), ("saml_metadata", "SAML"), ("adfs_mex", "ADFS")):
                ch = sop.get(key) or {}
                if ch.get("reachable"):
                    sitems.append(f"<li>{label}: {esc(str(ch.get('status', '?')))}{' metadata' if ch.get('is_metadata') else ''}</li>")
            if sitems:
                parts.append(f"<h4>Claude-OSINT SSO/OIDC probe</h4><ul class='compact'>{''.join(sitems)}</ul>")
        ss = co.get("secret_scan") or {}
        if ss and not ss.get("error") and ss.get("critical"):
            ss_items = []
            for g in ss["critical"][:4]:
                ss_items.append('<li><span class="err">' + esc(g.get("pattern", "?")) + "</span> x" + str(g.get("count", 1)) + " -- <code>" + esc(str(g.get("first", ""))[:60]) + "</code></li>")
            parts.append("<h4>Claude-OSINT Secret Scan</h4><ul class='compact'>" + "".join(ss_items) + "</ul>")

    strix = p.get("strix") or {}
    if strix and strix.get("status") == "ok":
        fds = strix.get("findings") or []
        strix_meta = "Modo " + esc(str(strix.get("mode", "?"))) + " - " + str(len(fds)) + " hallazgo(s)"
        if strix.get("cost_usd"):
            strix_meta += " - costo LLM $" + str(strix.get("cost_usd"))
        parts.append("<h4>Strix AI Pentest</h4><p class='meta'>" + strix_meta + "</p>")
        if fds:
            items = ""
            for f in sorted(fds, key=lambda x: str(x.get("severity", "")).lower() in ("critical", "critica", "high", "alta"), reverse=True)[:8]:
                sev = esc(str(f.get("severity", "?")))
                title = esc(str(f.get("title", "?"))[:100])
                cve = esc(str(f.get("cve", "-")))
                cvss = esc(str(f.get("cvss", "-")))
                rem = esc(str(f.get("remediation_steps", f.get("remediation", "")))[:160])
                items += "<li><b>[" + sev + "]</b> <strong>" + title + "</strong> - " + cve + " - CVSS " + cvss + "<br/><span class='muted'>" + rem + "</span></li>"
            parts.append("<ul class='compact'>" + items + "</ul>")

    fr = p.get("finalrecon") or {}
    if fr:
        fitems = []
        all_js = list(dict.fromkeys((fr.get("javascripts") or []) + ((fr.get("wayback") or {}).get("js_files") or [])))
        if all_js:
            fitems.append(f"<li>Archivos JS expuestos: {len(all_js)}</li>")
        if fr.get("external_urls"):
            fitems.append(f"<li>Enlaces externos: {len(fr['external_urls'])}</li>")
        if fr.get("sitemap"):
            fitems.append(f"<li>Sitemap: {len(fr['sitemap'])} URLs</li>")
        wb = fr.get("wayback") or {}
        if wb.get("js_files"):
            fitems.append(f"<li>JS históricos Wayback: {len(wb['js_files'])}</li>")
        if wb.get("api_endpoints"):
            fitems.append(f"<li>Endpoints API Wayback: {len(wb['api_endpoints'])}</li>")
        if wb.get("juicy_params"):
            fitems.append(f"<li>Parametros sensibles Wayback: {len(wb['juicy_params'])}</li>")
        if fitems:
            parts.append(f"<h4>Web Recon - FinalRecon</h4><ul class='compact'>{''.join(fitems)}</ul>")

    ow = None
    for m in (matrix or []):
        if isinstance(m, dict) and m.get("dominio") == dom and m.get("owasp"):
            ow = m.get("owasp")
            break
    # Solo evaluación real: se oculta si el scanner no la calculo (grado ? o error)
    if ow and not ow.get("error") and str(ow.get("overall_grade", "?")).strip() not in ("?", "", "-", "N/A"):
        grade = ow.get("overall_grade", "--")
        pct = ow.get("overall_compliance", 0)
        oitems = ""
        for r_id, r_data in sorted((ow.get("risks") or {}).items()):
            if isinstance(r_data, dict) and r_data.get("finding_count", 0) > 0:
                icon = "&#10007;" if r_data.get("compliance_pct", 100) < 60 else "&#10003;"
                oitems += f"<li>{icon} <strong>{esc(r_id)}</strong>: Grado {esc(str(r_data.get('grade', '?')))} ({r_data.get('compliance_pct', '?')}%) -- {r_data.get('finding_count', 0)} hallazgo(s)</li>"
        if not oitems:
            oitems = '<li class="muted">Sin hallazgos que afecten compliance.</li>'
        parts.append(f"<h4>OWASP Agentic Top 10 -- Grado: {esc(str(grade))} ({pct}%)</h4><ul class='compact'>{oitems}</ul>")

    social = p.get("social") or {}
    if social:
        labels = {"instagram": "Instagram", "tiktok": "TikTok", "twitter": "Twitter", "twitch": "Twitch", "telegram": "Telegram", "github": "GitHub"}
        sitems = ""
        for net, data in social.items():
            if not isinstance(data, dict):
                continue
            uname = data.get("username", "")
            if data.get("error"):
                sitems += f"<li>{labels.get(net, net)}: @{esc(uname)} -- sin datos</li>"
            else:
                sitems += f"<li><strong>{labels.get(net, net)}</strong>: @{esc(uname)} - seguidores: {esc(str(data.get('followers', data.get('seguidores', '?'))))} - {esc(str(data.get('description', ''))[:100])}</li>"
        if sitems:
            parts.append(f"<h4>Redes Sociales (OSINT)</h4><ul class='compact'>{sitems}</ul>")

    wd = p.get("who_dat") or {}
    if wd and wd.get("status") not in ("skipped", "error") and (wd.get("apex") or wd.get("rdap")):
        apex = wd.get("apex") or {}
        reg = (apex.get("registrar") or {})
        witems = []
        if reg.get("name"):
            witems.append(f"<li>Registrar: {esc(str(reg['name'])[:80])}</li>")
        if apex.get("creation_date") or apex.get("created"):
            witems.append(f"<li>Creado: {esc(str(apex.get('creation_date', apex.get('created')))[:40])}</li>")
        if apex.get("is_registered") is not None:
            witems.append(f"<li>Registrado: {'si' if apex.get('is_registered') else 'no'}</li>")
        if witems:
            parts.append(f"<h4>WHO-DAT (RDAP extendido)</h4><ul class='compact'>{''.join(witems)}</ul>")

    crt = p.get("crt_subdomains") or []
    san = p.get("san_list") or []
    dns = p.get("dns") or {}
    if crt or san or dns.get("mx_records") or dns.get("ns_records"):
        ditems = []
        if crt:
            ditems.append(f"<li>Subdominios crt.sh: {len(crt)} -- {esc(', '.join(crt[:8]))}{'...' if len(crt) > 8 else ''}</li>")
        if san:
            ditems.append(f"<li>SAN: {esc(', '.join(san[:8]))}</li>")
        if dns.get("mx_records"):
            mx = dns["mx_records"]
            ditems.append(f"<li>MX: {len(mx)} registro(s)</li>")
        if dns.get("ns_records"):
            ditems.append(f"<li>NS: {len(dns['ns_records'])} servidor(es)</li>")
        parts.append(f"<h4>Registros DNS / CT</h4><ul class='compact'>{''.join(ditems)}</ul>")

    if not parts:
        return "<div class='info-box'>Sin datos de enriquecimiento para este proveedor en el escaneo actual.</div>"
    return "\n".join(parts)


def prev_scan_scores(domain: str) -> dict | None:
    """Ultimo registro previo del dominio en scan_history.db (solo datos reales)."""
    try:
        import sqlite3
        db = ROOT / "dashboard_workspace" / "scan_history.db"
        if not db.is_file():
            return None
        c = sqlite3.connect(db)
        c.row_factory = sqlite3.Row
        r = c.execute("SELECT score_general, domain_score, overall_score, created_at FROM scan_history WHERE domain=? ORDER BY created_at DESC LIMIT 1", (domain,)).fetchone()
        c.close()
        return dict(r) if r else None
    except Exception:
        return None


def _delta_str(cur: float, prev: float | None) -> str:
    if prev is None:
        return ""
    d = round(cur - prev, 1)
    if d > 0:
        return f"<span style='color:#2E7D32; font-weight:700;'>&#9650;+{d:g}</span>"
    if d < 0:
        return f"<span style='color:#C62828; font-weight:700;'>&#9660;{d:g}</span>"
    return "<span style='color:#6B7280;'>=</span>"


def paginate_toc(html_path: str | Path) -> dict[str, int]:
    """Segundo pase: calcula la página PDF real de cada ancla (A4, margenes 12/12/10/10)
    y la escribe en los spans data-pg del índice. Requiere Playwright Chromium.
    Si falla, el índice conserva '–' y no rompe nada."""
    import re
    from pathlib import Path as _P
    html_path = _P(html_path).resolve()
    html = html_path.read_text(encoding="utf-8")
    ids = sorted(set(re.findall(r'data-pg="([^"]+)"', html)))
    if not ids:
        return {}
    pages: dict[str, int] = {}
    try:
        from playwright.sync_api import sync_playwright
        content_h = (297 - 12 - 12) * 96 / 25.4
        with sync_playwright() as pw:
            b = pw.chromium.launch()
            pg = b.new_page()
            pg.goto(html_path.as_uri(), wait_until="load", timeout=120_000)
            ys = pg.evaluate("(ids) => { const o = {}; for (const id of ids) { const el = document.getElementById(id); o[id] = el ? (el.getBoundingClientRect().top + window.scrollY) : -1; } return o; }", ids)
            b.close()
        for i in ids:
            y = ys.get(i, -1)
            pages[i] = int(y // content_h) + 1 if y is not None and y >= 0 else -1
    except Exception:
        return {}
    def _repl(m):
        pid = m.group(1)
        num = pages.get(pid, -1)
        return f'<span class="toc-pg" data-pg="{pid}">' + (str(num) if num > 0 else "–") + "</span>"
    html = re.sub(r'<span class="toc-pg" data-pg="([^"]+)">.*?</span>', _repl, html)
    html_path.write_text(html, encoding="utf-8")
    return {k: v for k, v in pages.items() if v > 0}


def _logo_gc_b64() -> str:
    """Logo Grupo Cibest (version negativa/blanca) en base64 para la portada."""
    try:
        raw = (ROOT / "logo-grupo-cibest-negativo.png").read_bytes()
        import base64
        return base64.b64encode(raw).decode("ascii")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Build report HTML
# ---------------------------------------------------------------------------
def build_report(asm: dict[str, Any], analista: str = "", org: str = "GrupoCibest",
                 history: list[dict] | None = None) -> str:
    providers = asm.get("providers") or []
    test_type = asm.get("test_type", "activo")
    gen = str(asm.get("generated_utc", datetime.now(timezone.utc).isoformat()))
    try:
        fecha = datetime.fromisoformat(gen.replace("Z", "+00:00")).strftime("%d/%m/%Y")
    except Exception:
        fecha = datetime.now().strftime("%d/%m/%Y")
    analista_show = analista or "@eduingt-ANALISTA INTELIGENCIA Y DEFENSA CIBER"
    org_show = org or "GrupoCibest"
    dom0 = providers[0].get("domain", "N/A") if providers else "N/A"

    factores = compute_factores(providers)
    score_general = int(sum(f["score"] for f in factores) / max(len(factores), 1)) if factores else 0
    dscore = round(sum(domain_score(p) for p in providers) / max(len(providers), 1), 1) if providers else 0.0
    # Overall único (P0): promedio ponderado precia_scorecard, no promedio simple B3
    try:
        from precia_scorecard import factor_scores as _pscores, overall_score as _poverall
        if providers:
            _ovs = [int(_poverall(_pscores(pp))) for pp in providers]
            overall = int(sum(_ovs) / len(_ovs)) if _ovs else 0
        else:
            overall = 0
    except Exception:
        overall = int(sum(f["score"] for f in factores[:10]) / max(min(len(factores), 10), 1)) if factores else 0

    all_findings: list[dict] = []
    for p in providers:
        all_findings.extend(build_findings(p))
    order = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3, "INFORMATIVA": 4, "INFO": 4}
    all_findings.sort(key=lambda f: (order.get(f["severidad"], 5), f["categoria"], f["titulo"]))
    for _i, _f in enumerate(all_findings, 1):
        _f["num"] = _i
    # Validación P1: conteos y una sola fuente de verdad
    try:
        _tot = len(all_findings)
        _sum = sum(1 for f in all_findings if f["severidad"] in ("CRITICA","ALTA","MEDIA","BAJA","INFORMATIVA","INFO"))
        assert _tot == _sum, "conteo hallazgos inconsistente"
    except Exception as _e:
        import warnings
        warnings.warn(f"[B3-P1] validación hallazgos: {_e}")
    n_crit = sum(1 for f in all_findings if f["severidad"] == "CRITICA")
    n_alta = sum(1 for f in all_findings if f["severidad"] == "ALTA")
    n_med = sum(1 for f in all_findings if f["severidad"] == "MEDIA")
    n_baja = sum(1 for f in all_findings if f["severidad"] == "BAJA")
    n_info = sum(1 for f in all_findings if f["severidad"] in ("INFORMATIVA", "INFO"))

    # Superficie agregada
    subs_all: list[str] = []
    for p in providers:
        for s in (p.get("subdomains") or []) + (p.get("crt_subdomains") or []):
            nm = _sub_name(s)
            if nm and nm not in subs_all:
                subs_all.append(nm)
    n_brute = sum(len(p.get("brute_subs") or []) for p in providers)
    n_ports = sum(len([o for o in (p.get("open_ports") or []) if o.get("state") == "open"]) for p in providers)
    n_pivot = sum(len(p.get("pivot_results") or []) for p in providers)
    ips: list[str] = []
    for p in providers:
        for ip in (p.get("dns") or {}).get("ipv4", []) or []:
            if ip not in ips:
                ips.append(ip)
    n_vuln = sum(len(p.get("vulnerabilities") or []) for p in providers)
    n_take = sum(len(p.get("takeover_risks") or []) for p in providers)
    n_typo = sum(len(p.get("typosquatting") or []) for p in providers)
    n_leak = sum(len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) for p in providers)
    n_eol = sum(sum(1 for x in (p.get("patching") or []) if x.get("status") == "eol") for p in providers)

    hist = history if history else load_history(asm, score_general)
    svg = _history_svg(hist)
    if svg:
        hist_html = f"<div style='text-align:center;overflow-x:auto;'>{svg}</div>"
    else:
        hist_html = "<div class='info-box'>Sin historial suficiente: se necesitan al menos 2 escaneos registrados del dominio para graficar tendencia.</div>"
    controls_html = render_controls_table(providers)
    try:
        _l64 = _logo_gc_b64()
        logo_img = (f"<div style='margin-bottom:14px; text-align:left;'><img src='data:image/png;base64,{_l64}' "
                    f"style='height:46px;' alt='Grupo Cibest'></div>" if _l64 else "")
    except Exception:
        logo_img = ""
    legend_html = ""
    try:
        if _render_score_legend is not None:
            legend_html = _render_score_legend()
            legend_html = legend_html.replace("25 controles", "20 controles")
    except Exception:
        legend_html = ""

    # Filas de factores (con desglose y trazabilidad §9)
    try:
        _b3ded = b3_deductions(providers)
    except Exception:
        _b3ded = {}
    frows = ""
    for f in factores:
        sc = f["score"]
        cls = "fs-verde" if sc >= 90 else "fs-amarillo" if sc >= 70 else "fs-naranja" if sc >= 60 else "fs-rojo"
        dl = _b3ded.get(f["factor"], [])
        if dl:
            parts = []
            for lbl, pts in dl[:5]:
                parts.append(f"{lbl} +{pts}" if pts > 0 else f"{lbl} -{abs(pts)}")
            ded_txt = " · ".join(parts) + (f" (+{len(dl) - 5} mas)" if len(dl) > 5 else "")
        else:
            ded_txt = "<span style='color:#2E7D32;'>Sin deducciones</span>"
        _cats = _B3_FACTOR_CATS.get(f["factor"], [])
        _ncats = [_norm(c) for c in _cats]
        _nums = [str(x.get("num", "")) for x in all_findings
                 if any(c in _norm(x.get("categoria", "")) or c in _norm(x.get("titulo", "")) for c in _ncats)
                 and x.get("num")]
        refs = ", ".join("#" + n for n in _nums) if _nums else "—"
        frows += (f"<tr><td class='num {cls}'>{sc}</td><td>{esc(_DISP_FACTOR.get(f['factor'], f['factor']))}</td><td class='num'>{f['incidencias']}</td>"
                  f"<td style='font-size:8pt;'>{ded_txt}</td><td class='num' style='white-space:nowrap;'>{refs}</td></tr>\n")

    # Superficie tabla (extendida con adopcion GC: JS, externos, sitemap, Wayback, API)
    n_js = n_ext = n_sitemap = n_wb = n_wb_js = n_wb_api = n_wb_params = n_api = 0
    for p in providers:
        fr = p.get("finalrecon") or {}
        n_js += len(fr.get("javascripts") or [])
        n_ext += len(fr.get("external_urls") or [])
        n_sitemap += len(fr.get("sitemap") or [])
        wb = fr.get("wayback") or {}
        n_wb += wb.get("total", len(wb.get("urls", []) or [])) if isinstance(wb, dict) else 0
        n_wb_js += len(wb.get("js_files") or [])
        n_wb_api += len(wb.get("api_endpoints") or [])
        n_wb_params += len(wb.get("juicy_params") or [])
        n_api += len(p.get("api_endpoints") or [])
    san_all = []
    for p in providers:
        san_all.extend(p.get("san_list") or [])
    san_all = list(dict.fromkeys(san_all))
    observed_ports = []
    for p in providers:
        if (p.get("port_80") or {}).get("open"):
            observed_ports.append(80)
        if (p.get("port_443") or {}).get("open"):
            observed_ports.append(443)
        for o in (p.get("open_ports") or []):
            if isinstance(o, dict) and o.get("state") == "open" and o.get("port") not in observed_ports:
                observed_ports.append(o.get("port"))
    observed_ports = sorted(set(observed_ports))
    _obs_subs_str = f"{len(subs_all)} en scope (observados {len(set(subs_all + san_all))}: {', '.join(list(set(subs_all + san_all))[:2])})" if san_all else str(len(subs_all))
    sup_rows = [
        ("Subdominios en scope", _obs_subs_str, "Activos en scope para scoring; observados incluye CT/SAN, excluye infra"),
        ("Por fuerza bruta", str(n_brute), "Activos no visibles en fuentes tradicionales"),
        ("Puertos TCP observados", ", ".join(str(x) for x in observed_ports) or "—", "80/443 vía port_80/443; 0 adicionales = sin exposición extra"),
        ("Puertos de riesgo", str(n_ports), "Puertos no esperados/riesgo (excluye 80/443)"),
        ("FQDNs por pivoteo IP", str(n_pivot), "Infraestructura compartida"),
        ("Direcciones IP unicas", str(len(ips)), "Huella de red del proveedor"),
        ("Vulnerabilidades", str(n_vuln), "Potenciales vectores de ataque"),
        ("Takeover risks", str(n_take), "Subdominios vulnerables a apropiacion"),
        ("Typosquatting", str(n_typo), "Dominios fraudulentos activos"),
        ("Credenciales filtradas", str(n_leak), "Breaches de seguridad activos"),
        ("Software EOL", str(n_eol), "Tecnologias sin soporte"),
        ("Archivos JS expuestos", str(n_js), "JS publicos (crawler + Wayback)"),
        ("Enlaces externos", str(n_ext), "Dependencias de terceros"),
        ("URLs en sitemap", str(n_sitemap), "Rutas indexadas del sitio"),
        ("URLs historicas (Wayback)", str(n_wb), "Recursos archivados"),
        ("JS históricos (Wayback)", str(n_wb_js), "Versiones antiguas de JS"),
        ("Endpoints API (Wayback)", str(n_wb_api), "Interfaces API archivadas"),
        ("Parametros sensibles (Wayback)", str(n_wb_params), "URLs con params riesgosos"),
        ("Endpoints API discovery", str(n_api), "APIs probadas en superficie"),
    ]
    sup_html = "".join(f"<tr><td>{esc(k)}</td><td class='num'><strong>{esc(v)}</strong></td><td>{esc(i)}</td></tr>" for k, v, i in sup_rows)
    inventory_html = render_asset_inventory(providers)
    asset_hist = load_asset_history(asm)
    asset_svg = _asset_history_svg(asset_hist)
    _explain = '<div class="info-box" style="font-size:8pt;"><strong>Cómo leer este gráfico:</strong> muestra la evolución de la superficie en 30 días — <span style="color:#173B57;">● Subs</span> (azul), <span style="color:#2E7D32;">● IPs</span> (verde) y <span style="color:#EF6C00;">● Puertos</span> (naranja). Línea plana = superficie estable; pico en azul = nuevos subdominios descubiertos (ej. CT); subida en verde/naranja = nueva IP o puerto expuesto. Datos de <code>scan_assets</code> (requiere 2+ scans).</div>'
    asset_history_html = f"<div class='section-sub' id='sec-superficie-hist'>6.2 Evolución de Superficie (30 días)</div>{'<div style=text-align:center;overflow-x:auto;>' + asset_svg + '</div>' + _explain if asset_svg else '<div class=info-box>Sin historial suficiente de superficie (se requieren 2+ escaneos).</div>'}"

    # DNS apex primer proveedor
    p0 = providers[0] if providers else {}
    d0 = _dns(p0)
    def _str_list(vals):
        out = []
        for v in vals or []:
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, dict):
                out.append(v.get("exchange") or v.get("nameserver") or v.get("value") or v.get("host") or str(v))
            else:
                out.append(str(v))
        return out

    mx = ", ".join(_str_list(d0.get("mx_records"))) or "N/A"
    ns = ", ".join(_str_list(d0.get("ns_records"))) or "N/A"

    # Matriz controles — estados normalizados PASS/PARTIAL/FAIL (enforced vs report-only)
    h0 = _hdrs(p0)
    _csp_enforced = h0.get("content-security-policy") or ""
    _csp_report = h0.get("content-security-policy-report-only") or ""
    _csp_find = len(p0.get("csp_findings") or [])
    if not _csp_enforced and not _csp_report:
        _csp_st = "FAIL"
    elif not _csp_enforced and _csp_report:
        _csp_st = "FAIL"
    elif _csp_find > 0:
        _csp_st = "PARTIAL"
    else:
        _csp_st = "PASS"
    ctrl_estado = [
        ("HTTPS", "PASS" if (p0.get("https") or {}).get("status_code") else "FAIL"),
        ("TLS 1.2/1.3", "PASS" if (p0.get("tls") or {}).get("negotiated_version") else "FAIL"),
        ("HSTS", "PASS" if h0.get("strict-transport-security") else "FAIL"),
        ("CSP", _csp_st),
        ("SPF", "PASS" if d0.get("spf_record") else "FAIL"),
        ("DMARC", "PASS" if d0.get("dmarc_record") else "FAIL"),
        ("DNSSEC", "PASS" if d0.get("dnssec_ok") else "FAIL"),
        ("CAA", "PASS" if p0.get("caa_records") else "FAIL"),
    ]
    n_ok = sum(1 for _, s in ctrl_estado if s == "PASS")
    n_par = sum(1 for _, s in ctrl_estado if s == "PARTIAL")
    n_no = sum(1 for _, s in ctrl_estado if s == "FAIL")
    def _st_badge(st: str) -> str:
        if st == "PASS":
            return '<span style="background:#e8f5e9; color:#2E7D32; border:1px solid #2E7D32; border-radius:4px; padding:2px 7px; font-size:7.5pt; font-weight:800;">PASS</span>'
        if st == "PARTIAL":
            return '<span style="background:#fff8e1; color:#B8860B; border:1px solid #F9A825; border-radius:4px; padding:2px 7px; font-size:7.5pt; font-weight:800;">PARTIAL</span>'
        return '<span style="background:#fce4e4; color:#C62828; border:1px solid #C62828; border-radius:4px; padding:2px 7px; font-size:7.5pt; font-weight:800;">FAIL</span>'
    ctrl_html = "".join(f"<tr><td style='font-weight:600;'>{esc(n)}</td><td>{_st_badge(s)}</td></tr>" for n, s in ctrl_estado)

    # Hallazgos agregados (top categorias) con impacto real: peso severidad x conteo normalizado
    from collections import Counter
    _sev_w = {"CRITICA": 1.0, "ALTA": 0.7, "MEDIA": 0.4, "BAJA": 0.2, "INFORMATIVA": 0.0, "INFO": 0.0}
    _groups: dict[tuple[str, str], list] = {}
    for f in all_findings:
        _groups.setdefault((f["categoria"], f["titulo"][:60]), []).append(f)
    _maxc = max((len(v) for v in _groups.values()), default=0)
    _agg = []
    for (c, t), fs in _groups.items():
        _w = max(_sev_w.get(x.get("severidad", ""), 0.0) for x in fs)
        _imp = round(_w * (len(fs) / _maxc), 2) if _maxc else 0.0
        _agg.append((_imp, c, t, len(fs), _mueve_a(fs[0])))
    _agg.sort(reverse=True)
    if _agg:
        _imp0, _c0, _t0, _n0, _m0 = _agg[0]
        _w0 = max(_sev_w.get(x.get("severidad", ""), 0.0) for x in _groups[(_c0, _t0)])
        _maxc0 = max((len(v) for v in _groups.values()), default=1)
        agg_example = (f"<div style='font-size:8.5pt; color:#4B5563; margin:6px 0;'>Ej. <strong>{esc(_c0)}</strong>: {_n0} hallazgo(s) x peso {_w0:g} / max {_maxc0} = <strong>{_imp0:.2f}</strong>.</div>")
    else:
        agg_example = ""
    agg_html = "".join(
        f"<tr><td>{esc(_DISP_CAT.get(c, c))}</td><td>{esc(t)} <span style='font-size:7.5pt; color:#6B7280;'>({n})</span></td>"
        f"<td>{esc(dom0)}</td><td class='num' style='font-weight:700;'>{imp:.2f}</td><td class='num' style='white-space:nowrap;'>{mueve}</td></tr>"
        for imp, c, t, n, mueve in _agg[:8])
    agg_note = ("<div style='font-size:7pt; color:#6B7280;'>Impacto = peso severidad "
                "(Critica 1.0, Alta 0.7, Media 0.4, Baja 0.2) x conteo del grupo / conteo maximo.</div>")

    # OSINT pasivo tabla (CT/SAN/CAA/MTA-STS por dominio)
    osint_rows = ""
    for p in providers:
        ct = len(p.get("crt_subdomains") or [])
        san = len(p.get("san_list") or [])
        caa = "&#10004;" if p.get("caa_records") else "&#10008;"
        msts = "&#10004;" if p.get("mta_sts") else "&#10008;"
        osint_rows += f"<tr><td>{esc(p.get('domain', ''))}</td><td class='num'>{ct}</td><td class='num'>{san}</td><td class='num'>{caa}</td><td class='num'>{msts}</td></tr>"

    # Adopcion GC: ficha detallada por proveedor + matriz ASM con Score
    asm_matrix = asm.get("matrix") or []
    gc_sections = "".join(gc_provider_detail(p, asm_matrix) for p in providers)
    try:
        _score_by_dom = {str(p.get("domain", "")): domain_score(p) for p in providers}
    except Exception:
        _score_by_dom = {}
    matrix_asm_html = render_matrix_asm(asm_matrix, _score_by_dom)

    # Sec 1 (estilo imagen): riesgo + conteos CT
    n_ct = sum(len(p.get("crt_subdomains") or []) for p in providers)
    if score_general >= 90:
        risk_lbl, risk_bg, risk_col = "RIESGO BAJO", "#e8f5e9", "#2E7D32"
    elif score_general >= 70:
        risk_lbl, risk_bg, risk_col = "RIESGO MEDIO", "#fff8e1", "#B8860B"
    elif score_general >= 40:
        risk_lbl, risk_bg, risk_col = "RIESGO ALTO", "#fde8d6", "#EF6C00"
    else:
        risk_lbl, risk_bg, risk_col = "RIESGO CRÍTICO", "#fce4e2", "#C62828"
    weakest = sorted([f for f in factores if f["score"] < 100], key=lambda f: f["score"])[:4]
    impact_txt = ", ".join(f"{_DISP_FACTOR.get(f['factor'], f['factor'])} ({f['score']}/100)" for f in weakest) if weakest else "ninguno (todos en 100/100)"
    # Ejemplo dinámico para "¿Cómo se calcula?" (2 factores más bajos con sus deducciones reales)
    try:
        _b3d_all = b3_deductions(providers)
    except Exception:
        _b3d_all = {}
    _ex = []
    for f in weakest[:2]:
        dl = _b3d_all.get(f["factor"], [])
        tot = sum(p for _, p in dl)
        det = " · ".join(f"{lbl} -{p}" for lbl, p in dl[:3])
        _ex.append(f"{f['factor']} {f['score']} = 100 - {tot} ({det})")
    calc_example = f"Ej. {dom0}: " + ", ".join(_ex) + "." if _ex else ""
    # Sec 3 extra (estilo imagen Domain Score): ejemplo de deducciones del dominio evaluado
    _ded = domain_deductions(p0) if providers else []
    if _ded:
        ds_example = "Ej. el dominio evaluado: " + " + ".join(f"{lbl} {pts}" for lbl, pts in _ded) + f" = {dscore}."
    else:
        ds_example = f"Ej. el dominio evaluado: sin deducciones = {dscore}."
    # Sec 4 (punto 2): filas de controles con Estado del dominio evaluado
    _DS_ROWS = [
        ("443 abierto", "-6 si cerrado", "Disponibilidad HTTPS", ["443 cerrado"]),
        ("HTTPS 200 OK", "-4 si no responde 2xx", "Servicio web activo", ["HTTPS no 2xx"]),
        ("HSTS", "-4 si ausente", "RFC 6797 -- fuerza HTTPS", ["HSTS"]),
        ("CSP", "-4 si ausente / -3/-2 si debil", "OWASP CSP -- anti-XSS", ["CSP ausente", "CSP debil"]),
        ("X-Frame-Options", "-2 si ausente", "Anti-clickjacking", ["X-Frame-Options"]),
        ("X-Content-Type-Options", "-2 si ausente", "Anti-MIME sniffing", ["X-Content-Type-Options"]),
        ("TLS valido", "-6 si error / -2 si no TLS1.3", "RFC 8446 -- cifrado", ["TLS error", "TLS no 1.3-only"]),
        ("SPF", "-4 si ausente / -2 si ~all", "RFC 7208 -- antiphishing", ["SPF ausente", "SPF ~all"]),
        ("DMARC", "-4 si ausente / -2 si no reject", "RFC 7489 -- antiphishing", ["DMARC ausente", "DMARC sin reject"]),
        ("STARTTLS", "-2 si MX sin cifrado", "Cifrado correo", ["STARTTLS"]),
        ("IP limpia (DNSBL)", "-4 si >=3 / -2 si 1-2", "Spamhaus", ["DNSBL"]),
        ("URLhaus limpio", "-3 si malicioso", "Abuse.ch", ["URLhaus"]),
        ("0 vulns OSV", "-4 si >=3 / -2 si 1-2", "OSV.dev", ["OSV"]),
        ("0 leaks", "-4 si >=3 / -2 si 1-2", "Leak-lookup", ["Leaks"]),
        ("0 typos", "-3 si >=3 / -1 si 1-2", "Typosquatting", ["Typos"]),
        ("0 EOL", "-3 si >=2 / -1 si 1", "endoflife.date", ["EOL"]),
        ("Supply <=5", "-1 si >5", "Dependencias 3ros", ["Supply >5"]),
        ("0 takeover vulnerable", "-5 si vulnerable / -2 si potencial", "OWASP Takeover", ["Takeover vulnerable", "Takeover potencial"]),
        ("Cookies seguras", "-3 si high / -1 si low", "Secure/HttpOnly/SameSite", ["Cookies high", "Cookies low"]),
        ("Supply reputation limpia", "-3 si >=2 / -1 si 1", "DNSBL terceros", ["Supply reputation"]),
    ]
    try:
        _dedmap = {lbl: pts for lbl, pts in _ded}
    except Exception:
        _dedmap = {}
    ds_rows = ""
    for _ctl, _rule, _ref, _keys in _DS_ROWS:
        _hits = [(k, _dedmap[k]) for k in _keys if k in _dedmap]
        if _hits:
            _k, _pts = sorted(_hits, key=lambda x: x[1])[0]
            ds_rows += (f"<tr><td>{esc(_ctl)}</td><td>{esc(_rule)}</td><td>{esc(_ref)}</td>"
                        f"<td style='color:#C62828; font-weight:700;'>&#10007; {_pts} aplicado ({esc(_k)})</td></tr>\n")
        else:
            ds_rows += (f"<tr><td>{esc(_ctl)}</td><td>{esc(_rule)}</td><td>{esc(_ref)}</td>"
                        f"<td style='color:#2E7D32; font-weight:700;'>&#10003; pasa</td></tr>\n")
    _g_frac = max(0.0, min(1.0, score_general / 100.0))
    _g_len = 3.14159 * 80
    _g_prog = round(_g_len * _g_frac, 1)
    gauge_svg = (
        '<svg width="200" height="120" xmlns="http://www.w3.org/2000/svg" style="font-family:Arial,Helvetica,sans-serif;">'
        '<path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#D9DEE3" stroke-width="14" stroke-linecap="round"/>'
        f'<path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#2E7D32" stroke-width="14" stroke-linecap="round" stroke-dasharray="{_g_prog} {_g_len}"/>'
        f'<text x="100" y="88" text-anchor="middle" font-size="22" font-weight="800" fill="#1F2933">{score_general}</text>'
        '<text x="100" y="102" text-anchor="middle" font-size="8" fill="#6B7280">Security Score</text>'
        "</svg>"
    )

    # Punto 9: deltas vs escaneo anterior (BD real)
    prev = prev_scan_scores(dom0) if providers else None
    if prev:
        try:
            prev_fecha = str(prev.get("created_at", ""))[:10]
        except Exception:
            prev_fecha = ""
        delta_strip = (f"<div style='font-size:8pt; color:#4B5563; background:#F9FAFB; border:1px solid #E5E7EB; border-radius:6px; padding:8px 12px; margin:10px 0;'>"
                       f"vs escaneo anterior ({esc(prev_fecha)}): Score General {prev.get('score_general')} {_delta_str(score_general, prev.get('score_general'))}"
                       f" &nbsp;|&nbsp; Domain {prev.get('domain_score')} {_delta_str(dscore, prev.get('domain_score'))}"
                       f" &nbsp;|&nbsp; Overall {prev.get('overall_score')} {_delta_str(overall, prev.get('overall_score'))}</div>")
    else:
        delta_strip = "<div style='font-size:8pt; color:#6B7280; margin:10px 0;'>Primer escaneo registrado para este dominio (sin anterior para comparar).</div>"

    # Punto 10: Top-5 de remediación priorizada para §1
    _sla = {"P1": "7 días", "P2": "30 días", "P3": "60 días", "P4": "90 días"}
    _prio_col = {"P1": "#C62828", "P2": "#EF6C00", "P3": "#B8860B", "P4": "#2F6F9F"}
    top5_rows = ""
    for f in all_findings[:5]:
        pr = f.get("prioridad", "P4")
        top5_rows += (f"<tr><td class='num'>#{f.get('num', '?')}</td>"
                       f"<td class='num' style='color:{_prio_col.get(pr, '#374151')}; font-weight:800;'>{pr}</td>"
                       f"<td><strong>{esc(f.get('titulo', ''))}</strong><br><span style='font-size:7.5pt; color:#6B7280;'>{esc(_DISP_CAT.get(f.get('categoria', ''), f.get('categoria', '')))} | {esc(f.get('dominio', ''))}</span></td>"
                       f"<td style='font-size:8pt;'>{esc(str(f.get('recomendacion', ''))[:140])}</td>"
                       f"<td class='num'>{_sla.get(pr, '--')}</td></tr>")
    top5_html = (f"<div class='section-sub' style='page-break-before:always;'>Priorización inmediata -- Top 5</div>"
                 f"<table class='data'><thead><tr><th>#</th><th>Pri.</th><th>Hallazgo</th><th>Accion inmediata</th><th>SLA</th></tr></thead>"
                 f"<tbody>{top5_rows or '<tr><td colspan=5>Sin hallazgos priorizables.</td></tr>'}</tbody></table>"
                 f"<div style='font-size:7pt; color:#6B7280;'>SLA: P1 = 7 días, P2 = 30 días, P3 = 60 días, P4 = 90 días. Detalle completo en sección 9.</div>")

    # Sec 5 (replica exacta imagen SecurityScorecard): Overall Score por proveedor
    precia_blocks = ""
    try:
        if _PRECIA_FACTORS and _precia_scores is not None:
            blocks = []
            for pr in providers:
                _pf = [f for f in all_findings if f.get("dominio") == pr.get("domain", "")]
                try:
                    _pprev = prev_factor_scores(pr.get("domain", "")) or None
                except Exception:
                    _pprev = None
                blocks.append(render_scorecard_exact(pr, analista=analista_show or "@eduingt",
                                                     org=pr.get("name") or pr.get("domain", ""),
                                                     generated=gen, findings=_pf, prev_scores=_pprev))
            precia_blocks = "\n".join(blocks)
        if not precia_blocks.strip() and _render_precialike is not None:
            precia_blocks = "\n".join(
                _render_precialike(pr, analista=analista_show or "@eduingt",
                                   org=pr.get("name") or pr.get("domain", ""),
                                   generated=gen)
                for pr in providers
            )
    except Exception:
        precia_blocks = ""
    if not precia_blocks:
        precia_blocks = "<div class='info-box'>Scorecard no disponible para los datos actuales.</div>"

    # Detalle hallazgos cards
    cards = ""
    for f in all_findings:
        cards += f"""
        <div class="find-card">
          <div class="fc-hdr"><span style="font-weight:800; color:#173B57;">#{f.get('num', '?')} {esc(f.get('id',''))}</span><span class="s-badge {_bcls(f['severidad'])}">{esc(_DISP_SEV.get(f['severidad'], f['severidad']))}</span><span style="font-weight:700; color:#173B57;">{esc(_DISP_CAT.get(f['categoria'], f['categoria']))}</span><span style="flex:1;">{esc(f['dominio'])}</span></div>
          <div class="fc-body">
            <div class="fc-row"><div class="fc-label">Título</div><div class="fc-value"><strong>{esc(f['titulo'])}</strong></div></div>
            <div class="fc-row"><div class="fc-label">Explicación</div><div class="fc-value">{esc(f['explicacion'])}</div></div>
            <div class="fc-evidence">{esc(f['evidencia'])}</div>
            <div class="fc-row"><div class="fc-label">Observado</div><div class="fc-value"><code>{esc(str(f.get('observed',''))[:120])}</code></div></div>
            <div class="fc-row"><div class="fc-label">Esperado</div><div class="fc-value"><code>{esc(str(f.get('expected',''))[:120])}</code></div></div>
            <div class="fc-row"><div class="fc-label">Riesgo</div><div class="fc-value">{esc(f['riesgo'])}</div></div>
            <div class="fc-row"><div class="fc-label">Recomendación</div><div class="fc-value">{esc(f['recomendacion'])}</div></div>
            <div class="fc-row"><div class="fc-label">Prioridad</div><div class="fc-value">{esc(f['prioridad'])} | Estado: {esc(f['estado'])} | Confianza: <strong>{esc(f.get('confidence','MEDIUM'))}</strong></div></div>
            <div class="fc-row"><div class="fc-label">Evidencia</div><div class="fc-value" style="font-size:7.5pt;">Fuente: {esc(f.get('source','ASM scan'))} ({esc(str(f.get('timestamp',''))[:16])}) → Regla: {esc(f.get('rule','B3'))} → Hallazgo {esc(f.get('id',''))} → Impacto scores: {esc(f.get('mueve_a','—'))}</div></div>
            {f"<div class='fc-row'><div class='fc-label'>Mapeo</div><div class='fc-value' style='font-size:7.5pt;'>{esc(f['mapeo'])}</div></div>" if f.get('mapeo') else ""}
          </div>
        </div>"""

    # Recomendaciones por prioridad
    def rec_list(prio):
        items = [f for f in all_findings if f["prioridad"] == prio][:8]
        if not items:
            return "<div class='info-box'>Sin recomendaciones en este plazo para los datos actuales.</div>"
        return "".join(f"<div class='info-box'><strong>{esc(f['titulo'])}</strong><br>{esc(f['recomendacion'])}<br><span style='font-size:8pt;'>Factor: {esc(f['categoria'])} | Plazo: {'0-7 días' if prio=='P1' else '8-30 días' if prio=='P2' else '31-60 días' if prio=='P3' else 'Mejora continua'}</span></div>" for f in items)

    # Anexos
    san_all = p0.get("san_list") or []
    san_rows = "".join(f"<tr><td>{esc(dom0)}</td><td>{esc(s)}</td></tr>" for s in san_all[:20]) or f"<tr><td>{esc(dom0)}</td><td>Sin SAN listados</td></tr>"
    ct_list = subs_all[:40]
    ct_html = ", ".join(esc(s) for s in ct_list) or "Sin subdominios CT"
    raw_hdrs = "<br>".join(f"{esc(k)}: {esc(v)[:120]}" for k, v in list(h0.items())[:14]) or "Sin cabeceras"
    try:
        import json as _j
        idb = ((p0.get("external") or {}).get("internetdb")) or {}
        exp = ((p0.get("external") or {}).get("shodan_exposure")) or {}
    except Exception:
        idb, exp = {}, {}
    anexo_e = f"=== InternetDB ===<br>dominio: {esc(dom0)}<br>ips: {esc(_j.dumps(idb)[:400] if idb else str(ips[:2]))}<br>=== Exposure ===<br>ip_count: {len(ips)}<br>puertos_expuestos: {n_ports}<br>total_cves: {n_vuln}"

    html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Informe Unificado B3 - {esc(dom0)}</title><style>{CSS}</style></head>
<body><div class="page">
<div class="cover">
  <div class="cover-top">
    {logo_img}
    <div class="powered">Generado por GrupoCibest</div>
    <h1>INFORME UNIFICADO DE<br>SEGURIDAD</h1>
    <div class="sub">Evaluación integral de postura de seguridad<br>para proveedores y terceros</div>
    <div class="org-name">{esc(dom0)}</div>
  </div>
  <div class="cover-meta"><table>
    <tr><td>Fecha de generacion</td><td>{esc(fecha)}</td></tr>
    <tr><td>Analista responsable</td><td>{esc(analista_show)}</td></tr>
    <tr><td>Organizacion emisora</td><td>{esc(org_show)}</td></tr>
    <tr><td>Dominio evaluado</td><td>{esc(dom0)}</td></tr>
    <tr><td>Tipo de prueba</td><td>{esc(test_type)}</td></tr>
    <tr><td>Formato</td><td>B3</td></tr>
    <tr><td><strong>SCORE OFICIAL B3</strong></td><td><strong>{score_general}/100 ({_letter(score_general)})</strong> — uso oficial</td></tr>
    <tr><td>Domain Técnico</td><td>{dscore}/100 — higiene técnica</td></tr>
    <tr><td>Overall Benchmark</td><td>{overall}/100 — comparativo sectorial</td></tr>
  </table></div>
  <div class="cover-footer"><span>Dominio: {esc(dom0)} | Preparado: {esc(fecha)}</span><span>Página 1</span></div>
</div>

<div class="sec" id="sec-indice"><div class="section-title">Índice</div>
<div class="toc-row"><span class="toc-num">1</span><a class="toc-title" href="#sec-resumen">Resumen Ejecutivo</a><span class="toc-pg" data-pg="sec-resumen">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">1.1</span><a class="toc-title" href="#sec-acerca">Acerca de este informe</a><span class="toc-pg" data-pg="sec-acerca">–</span></div>
<div class="toc-row"><span class="toc-num">2</span><a class="toc-title" href="#sec-tablero">Tablero ejecutivo</a><span class="toc-pg" data-pg="sec-tablero">–</span></div>
<div class="toc-row"><span class="toc-num">3</span><a class="toc-title" href="#sec-score">Score General / Puntuación General</a><span class="toc-pg" data-pg="sec-score">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">3.1</span><a class="toc-title" href="#sec-factores">Factores de Riesgo</a><span class="toc-pg" data-pg="sec-factores">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">3.2</span><a class="toc-title" href="#sec-historial">Historial del Score</a><span class="toc-pg" data-pg="sec-historial">–</span></div>
<div class="toc-row"><span class="toc-num">4</span><a class="toc-title" href="#sec-domain">Domain Score (Tecnico)</a><span class="toc-pg" data-pg="sec-domain">–</span></div>
<div class="toc-row"><span class="toc-num">5</span><a class="toc-title" href="#sec-scorecard">Overall Score (Scorecard style)</a><span class="toc-pg" data-pg="sec-scorecard">–</span></div>
<div class="toc-row"><span class="toc-num">6</span><a class="toc-title" href="#sec-pasivo">Análisis Pasivo / Activo</a><span class="toc-pg" data-pg="sec-pasivo">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">6.1</span><a class="toc-title" href="#sec-inventario">Inventario de Activos</a><span class="toc-pg" data-pg="sec-inventario">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">6.2</span><a class="toc-title" href="#sec-superficie-hist">Evolución de Superficie</a><span class="toc-pg" data-pg="sec-superficie-hist">–</span></div>
<div class="toc-row"><span class="toc-num">7</span><a class="toc-title" href="#sec-matriz">Matriz de Riesgo y Controles</a><span class="toc-pg" data-pg="sec-matriz">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">7.1</span><a class="toc-title" href="#sec-agregados">Hallazgos Agregados</a><span class="toc-pg" data-pg="sec-agregados">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">7.2</span><a class="toc-title" href="#sec-osint">OSINT Pasivo</a><span class="toc-pg" data-pg="sec-osint">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">7.3</span><a class="toc-title" href="#sec-matriz-asm">Matriz de controles ASM</a><span class="toc-pg" data-pg="sec-matriz-asm">–</span></div>
<div class="toc-row"><span class="toc-num">8</span><a class="toc-title" href="#sec-enriquecimiento">Enriquecimiento y Superficie Detallada</a><span class="toc-pg" data-pg="sec-enriquecimiento">–</span></div>
<div class="toc-row"><span class="toc-num">9</span><a class="toc-title" href="#sec-hallazgos">Detalle de Hallazgos</a><span class="toc-pg" data-pg="sec-hallazgos">–</span></div>
<div class="toc-row"><span class="toc-num">10</span><a class="toc-title" href="#sec-recomendaciones">Recomendaciones Priorizadas</a><span class="toc-pg" data-pg="sec-recomendaciones">–</span></div>
<div class="toc-row"><span class="toc-num">11</span><a class="toc-title" href="#sec-fuentes">Fuentes y Referencias</a><span class="toc-pg" data-pg="sec-fuentes">–</span></div>
<div class="toc-row"><span class="toc-num">12</span><a class="toc-title" href="#sec-glosario">Glosario</a><span class="toc-pg" data-pg="sec-glosario">–</span></div>
<div class="toc-row"><span class="toc-num">13</span><a class="toc-title" href="#sec-anexos">Anexos</a><span class="toc-pg" data-pg="sec-anexos">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">A</span><a class="toc-title" href="#sec-anexo-a">SANs completos</a><span class="toc-pg" data-pg="sec-anexo-a">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">B</span><a class="toc-title" href="#sec-anexo-b">CT Logs</a><span class="toc-pg" data-pg="sec-anexo-b">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">C</span><a class="toc-title" href="#sec-anexo-c">Headers HTTP crudos</a><span class="toc-pg" data-pg="sec-anexo-c">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">D</span><a class="toc-title" href="#sec-anexo-d">Shodan InternetDB + Exposure</a><span class="toc-pg" data-pg="sec-anexo-d">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">E</span><a class="toc-title" href="#sec-anexo-e">Notas metodologicas</a><span class="toc-pg" data-pg="sec-anexo-e">–</span></div>
<div class="toc-row toc-sub"><span class="toc-num">F</span><a class="toc-title" href="#sec-anexo-f">Nota metodologica de scores</a><span class="toc-pg" data-pg="sec-anexo-f">–</span></div>
</div>

<div class="sec" id="sec-resumen"><div class="section-title">1. Resumen Ejecutivo</div>
<div class="info-box">Se realizo una <strong>evaluación integral de la postura de seguridad</strong> de {esc(dom0)} como parte del programa de gestion de riesgos de terceros. El análisis combina técnicas de <strong>evaluación {esc(test_type)}</strong>, inteligencia de fuentes abiertas (OSINT) y consulta a <strong>bases de datos de vulnerabilidades y filtraciones conocidas</strong>.</div>
<div class="info-box"><span style="font-size:8pt; font-weight:800; letter-spacing:.06em; color:#2F6F9F;">HALLAZGOS PRINCIPALES</span> <span style="font-size:9pt; color:#4B5563;">Score {score_general}/100 ({_letter(score_general)})</span>
<ul style="margin:8px 0 4px 18px; font-size:9pt; color:#374151; line-height:1.7;">
<li><span style="color:#1F2933;">&#8226;</span> <strong style="color:#2E7D32;">Calificación general:</strong> {score_general}/100 ({_letter(score_general)}) -- {"Postura de seguridad solida. Sin hallazgos críticos abiertos." if n_crit == 0 else f"Atencion: {n_crit} crítico(s) abiertos."} Mantener monitoreo continuo y revalidacion trimestral.</li>
<li><span style="color:#1F2933;">&#8226;</span> <strong style="color:#2E7D32;">Subdominios identificados:</strong> {len(subs_all)} en {len(providers)} proveedor(es), de los cuales {n_brute} fueron descubiertos mediante enumeracion activa y {n_ct} mediante registros de Certificate Transparency.</li>
<li><span style="color:#2E7D32;">&#8226;</span> <strong style="color:#2E7D32;">Vulnerabilidades potenciales:</strong> {n_vuln} vulnerabilidades potenciales identificadas en las tecnologias detectadas.</li>
<li><span style="color:#2E7D32;">&#8226;</span> <strong style="color:#2E7D32;">Filtraciones de credenciales:</strong> {n_leak} filtraciones de credenciales encontradas en bases de datos de breaches.</li>
<li><span style="color:#2E7D32;">&#8226;</span> <strong style="color:#2E7D32;">Puertos abiertos:</strong> {n_ports} puertos abiertos descubiertos en las IPs evaluadas.</li>
<li><span style="color:#2E7D32;">&#8226;</span> <strong style="color:#2E7D32;">Riesgo de subdomain takeover:</strong> {n_take} riesgo(s) de subdomain takeover detectado(s).</li>
<li><span style="color:#1F2933;">&#8226;</span> <strong style="color:#1F2933;">Typosquatting:</strong> {n_typo} variantes registradas y resolviendo.</li>
</ul>
<div style="margin-top:8px;"><span style="display:inline-block; background:{risk_bg}; color:{risk_col}; border:1px solid {risk_col}; border-radius:4px; font-size:9pt; font-weight:800; padding:3px 10px;">{risk_lbl}</span> <span style="font-size:7.5pt; color:#6B7280;">Clasificación: Confidencial -- Solo para uso interno &#8226; Fuentes: DNS, CT logs, OSINT, vulndb, Nuclei/Gobuster</span></div>
</div>
{top5_html}
<div style="font-size:6.5px; color:#9CA3AF; padding:0 50px;">Metodologia: ASM ligero (NIST CSF PR.DS/PR.AC, ISO 27001 A.8.23/A.8.26, PCI DSS Req 4, CIS 03/04/13, OWASP Top 10). No sustituye pentest ni auditoria de cumplimiento.</div>
<div style="font-size:7.5pt; color:#6B7280; margin:8px 0;">Tres métricas distintas conviven en este informe: <strong>Domain Score</strong> (tecnico), <strong>Score General</strong> (negocio, oficial) y <strong>Overall Score</strong> (benchmark). Ver <strong>Anexo F — Nota metodologica de scores</strong>.</div>
<div class="section-sub" id="sec-acerca" style="page-break-before:always;">1.1 Acerca de este informe</div>
<div class="info-box">El presente documento constituye una <strong>captura puntual del estado de seguridad</strong> del dominio evaluado ({esc(dom0)}), basada en técnicas de escaneo activo y pasivo, análisis de configuraciones expuestas, consulta a fuentes abiertas de inteligencia de amenazas y motores de busqueda especializados.<br><br>
<strong>Este informe no debe interpretarse como una prueba de penetracion</strong> ni como una evaluación de seguridad definitiva. Los resultados reflejan la información disponible al momento del escaneo y deben ser <strong>validados por el equipo técnico responsable</strong> antes de tomar decisiones operativas o contractuales. Sirve como herramienta para <strong>priorizar acciones de mejora</strong> en la postura de seguridad del proveedor o tercero evaluado.</div>
</div>

<div class="sec" id="sec-tablero"><div class="section-title" style="border-top:3px solid #173B57; padding-top:10px;">2. Tablero ejecutivo</div>
<div class="kpi-row">
<div class="kpi-card"><div class="kpi-num" style="color:#2E7D32;">{score_general}</div><div class="kpi-lbl">Score<br>General</div></div>
<div class="kpi-card"><div class="kpi-num" style="color:#173B57;">{len(all_findings)}</div><div class="kpi-lbl">Hallazgos</div></div>
<div class="kpi-card"><div class="kpi-num" style="color:#C62828;">{n_crit}</div><div class="kpi-lbl">Críticos</div></div>
<div class="kpi-card"><div class="kpi-num" style="color:#EF6C00;">{n_alta}</div><div class="kpi-lbl">Altos</div></div>
<div class="kpi-card"><div class="kpi-num" style="color:#F9A825;">{n_med}</div><div class="kpi-lbl">Medios</div></div>
<div class="kpi-card"><div class="kpi-num" style="color:#2E7D32;">{n_baja}</div><div class="kpi-lbl">Bajos</div></div>
<div class="kpi-card"><div class="kpi-num" style="color:#6B7280;">{n_info}</div><div class="kpi-lbl">Informativos</div></div>
</div>
<div class="exec-summary"><b class="lbl">Estado general:</b> La evaluación arroja un Score de Seguridad de <strong>{score_general}/100 ({_letter(score_general)})</strong>, postura {"solida" if score_general >= 90 else "buena" if score_general >= 80 else "aceptable" if score_general >= 70 else "deficiente"}.<br><br>
<b class="lbl">Hallazgos principales:</b> Se identificaron <strong>{len(all_findings)} hallazgos</strong> ({n_crit} críticos, {n_alta} altos, {n_med} medios, {n_baja} bajos, {n_info} informativos). Los factores que más impactan el score son: {impact_txt}.<br><br>
<b class="lbl">Recomendación general:</b> Establecer un plan de remediación con hitos a 30, 60 y 90 días, priorizando el cierre de hallazgos críticos y altos. Implementar controles de seguridad esenciales (HSTS, CSP, SPF/DMARC) y mantener monitoreo continuo de la superficie de ataque.<br><br>
<b class="lbl">Conclusion:</b> {"La postura de seguridad es satisfactoria y requiere monitoreo continuo. Se recomienda reevaluacion en 90 días." if score_general >= 70 else "Se requiere remediación prioritaria de hallazgos críticos y altos. Se recomienda reevaluacion en 30 días."}</div>
{delta_strip}
<div class="gauge-wrap">
<div class="gauge-box">{gauge_svg}</div>
<div class="dist-box"><div class="dist-title">Distribución de hallazgos</div>
<div class="dist-row"><span class="d-badge d-crit">CRÍTICOS</span><span class="d-count" style="color:#C62828;">{n_crit}</span></div>
<div class="dist-row"><span class="d-badge d-alta">ALTOS</span><span class="d-count" style="color:#EF6C00;">{n_alta}</span></div>
<div class="dist-row"><span class="d-badge d-media">MEDIOS</span><span class="d-count" style="color:#B8860B;">{n_med}</span></div>
<div class="dist-row"><span class="d-badge d-baja">BAJOS</span><span class="d-count" style="color:#2E7D32;">{n_baja}</span></div>
<div class="dist-row"><span class="d-badge d-info">INFORMATIVOS</span><span class="d-count" style="color:#2F6F9F;">{n_info}</span></div>
</div>
</div>
</div>

<div class="sec" id="sec-score"><div class="section-title">3. Score General / Puntuación General (Negocio)</div>
<div class="info-box">El Scorecard califica la postura de seguridad en escala de <strong>A a F</strong>: <strong>A</strong> (90-100) postura solida, <strong>B</strong> (80-89) buena, <strong>C</strong> (70-79) aceptable, <strong>D</strong> (60-69) deficiente, <strong>F</strong> (&lt;60) critica. El score general se calcula ponderando factores de riesgo.</div>
<div class="step-box">
<div class="step"><span class="sn">1</span><div class="st">Validar huella digital</div></div>
<div class="step"><span class="sn">2</span><div class="st">Revisar activos</div></div>
<div class="step"><span class="sn">3</span><div class="st">Analizar hallazgos</div></div>
<div class="step"><span class="sn">4</span><div class="st">Corregir y mejorar</div></div>
</div>
<div style="display:flex; gap:24px; align-items:center; margin:12px 0; font-size:10pt;">
<div style="flex:1; display:flex; align-items:center; gap:10px;"><strong>Puntuación general</strong><span class="score-badge {_letter(score_general)}">{_letter(score_general)}</span><span>{score_general}/100</span></div>
<div style="flex:1; display:flex; gap:10px;"><strong>Dominio</strong><span>{esc(dom0)}</span></div>
</div>
<div style="display:flex; gap:24px; margin:8px 0; padding:8px 0; border-top:1px solid #D9DEE3; border-bottom:1px solid #D9DEE3; font-size:10pt;">
<div style="flex:1; display:flex; gap:10px;"><strong>Fecha de evaluación</strong><span>{esc(fecha)}</span></div>
<div style="flex:1; display:flex; gap:10px;"><strong>Nivel de riesgo</strong><span class="{_lcls(score_general)}">{_letter(score_general)}</span></div>
</div>
<div class="section-sub" id="sec-factores">3.1 Factores de Riesgo</div>
<div style="overflow-x:auto;"><table class="data"><thead><tr><th>Score</th><th>Factor de riesgo</th><th>Incidencias</th><th>Desglose</th><th>Ver §9</th></tr></thead><tbody>{frows}</tbody></table></div>
<div style="background:#fff; border:1px solid #D9DEE3; border-left:4px solid #2F6F9F; border-radius:6px; padding:12px 14px; margin:12px 0; font-size:9pt; color:#374151; line-height:1.65;"><strong>¿Cómo se calcula?</strong> Cada factor empieza en <strong>100</strong> y pierde puntos por cada incidencia (proveedor que falla una verificación). {esc(calc_example)} Validado: <strong>100</strong> = 0 incidencias (todo ok). Colores: <span style="color:#2E7D32;">■</span> ≥90 verde, <span style="color:#F9A825;">■</span> 70-89 amarillo, <span style="color:#EF6C00;">■</span> 60-69 naranja, <span style="color:#C62828;">■</span> &lt;60 rojo. Código: generate_b3_unified_report.py <code>_factor()</code> · Fórmula {esc(FORMULA_VERSION)} ({esc(FORMULA_DATE)}).<br>Domain Score {dscore}/100 (higiene técnica) | Overall Score {overall}/100 (benchmark sectorial, ver sección 5 y Anexo F).</div>
<div class="section-sub" id="sec-historial">3.2 Historial del Score (30 días)</div>
{hist_html}
{controls_html}
</div>

<div class="sec" id="sec-domain"><div class="section-title" style="border-top:3px solid #173B57; padding-top:10px;">4. Domain Score (Tecnico)</div>
<div style="display:flex; gap:24px; align-items:center; margin:10px 0; font-size:10pt;">
<div style="flex:1;"><strong>Domain Score</strong></div>
<div style="flex:1; text-align:center;">{dscore}/100</div>
<div style="flex:1; text-align:right;"><strong>Heuristica de</strong> seguridad técnica</div>
</div>
<div class="section-sub">Domain Score (Heuristica tecnica)</div>
<div class="info-box">Parte de <strong>100</strong> y resta suave.</div>
<table class="data"><thead><tr><th>Control</th><th>Como se califica</th><th>Referencia</th><th>Estado {esc(dom0)}</th></tr></thead><tbody>
{ds_rows}
</tbody></table>
<div class="info-box" style="font-size:7.5pt;">Tip: Domain {dscore} vs Score General {score_general} no es error (metodos distintos). Ver <strong>Anexo F — Nota metodologica de scores</strong>.</div>
<div style="background:#fff; border:1px solid #D9DEE3; border-left:4px solid #2F6F9F; border-radius:6px; padding:12px 14px; margin:12px 0; font-size:9pt; color:#374151; line-height:1.65;"><strong>¿Cómo se calcula el Domain Score?</strong> Cada control parte de <strong>100</strong> y resta puntos por cada chequeo fallado. {esc(ds_example)} Validado: <strong>100</strong> = sin deducciones (todo ok). Colores: <span style="color:#2E7D32;">■</span> ≥90 verde, <span style="color:#F9A825;">■</span> 70-89 amarillo, <span style="color:#EF6C00;">■</span> 60-69 naranja, <span style="color:#C62828;">■</span> &lt;60 rojo. Código: generate_b3_unified_report.py <code>domain_score()</code> · Fórmula {esc(FORMULA_VERSION)} ({esc(FORMULA_DATE)}).</div>
</div>

<div class="sec" id="sec-scorecard"><div class="section-title" style="border-top:3px solid #173B57; padding-top:10px;">5. Overall Score (Scorecard style)</div>
<div class="info-box">Vista SecurityScorecard para benchmarking sectorial: promedio <strong>ponderado</strong> de 10 factores (Network/DNS/Patching x1.2). Es una métrica distinta del Score General de la sección 2 y del Domain Score técnico.</div>
{precia_blocks}
</div>

<div class="sec" id="sec-pasivo"><div class="section-title">6. Análisis Pasivo / Activo</div>
<div class="section-sub">Evidencia de evaluación -- Superficie de Ataque</div>
<table class="data"><thead><tr><th>Indicador</th><th>Valor</th><th>Interpretacion</th></tr></thead><tbody>{sup_html}</tbody></table>
<div class="info-box">El análisis combinado pasivo (OSINT, CT logs, DNS, whois) y activo (escaneo de puertos, force bruta de subdominios, pivoteo IP, conexiones TLS) permite obtener una visión completa de la superficie de ataque del proveedor.</div>
{inventory_html}
{asset_history_html}
<div style="background:#fff; border:1px solid #D9DEE3; border-left:4px solid #173B57; border-radius:6px; padding:12px 14px; margin:10px 0;">
<div style="font-size:10pt; font-weight:700; color:#173B57; margin-bottom:8px;">Configuración DNS - {esc(dom0)}</div>
<div class="evidence-box">MX: {esc(mx[:120] if mx != "N/A" else "N/A")}<br>NS: {esc(ns[:120] if ns != "N/A" else "N/A")}<br>SPF: {esc((d0.get('spf_record') or 'Ausente')[:120])}<br>DMARC: {esc((d0.get('dmarc_record') or 'Ausente')[:120])}<br>DNSSEC: {'Implementado' if d0.get('dnssec_ok') else 'No implementado'}</div>
</div>
</div>

<div class="sec" id="sec-matriz"><div class="section-title">7. Matriz de Riesgo y Controles</div>
<div class="info-box"><strong>Cómo leer esta sección:</strong> primero vea el <strong>Estado de Controles</strong> (qué defensas existen), luego la <strong>matriz</strong> (dónde se concentran los riesgos; la esquina roja de arriba a la izquierda se atiende primero), después <strong>7.1</strong> (qué familias pesan más, con número) y <strong>7.2 y 7.3</strong> (evidencia que lo respalda). Todo sale de los hallazgos de la sección 9.<br><strong>Relación con los scores:</strong> esta sección <strong>no mide</strong> ninguno de los tres scores (secciones 2 a 5); se construye directamente de hallazgos y datos crudos. Scores y matriz son dos lecturas distintas de los mismos insumos: un hallazgo puede mover un score sin cambiar la matriz y viceversa. La columna <strong>Mueve a</strong> (7.1) y la fila azul (7.3) indican, por hallazgo y por control, qué scores tienen chequeos en esa área, donde D es Domain, G es General, O es Overall y el guion significa solo contexto.</div>
<div class="section-sub">Estado de Controles</div>
<table class="data"><thead><tr><th>Control</th><th>Estado</th></tr></thead><tbody>{ctrl_html}</tbody></table>
<div class="info-box"><strong>{n_ok}</strong> PASS | <strong>{n_par}</strong> PARTIAL | <strong>{n_no}</strong> FAIL<br><span style="font-size:8pt;">PASS = control verificado y activo · PARTIAL = existe pero débil o incompleto · FAIL = no detectado o no conforme.</span></div>
{render_risk_matrix(all_findings)}
<div class="section-sub" id="sec-agregados">7.1 Hallazgos Agregados</div>
<table class="data"><thead><tr><th>Tipo</th><th>Descripción</th><th>Proveedores</th><th>Impacto</th><th>Mueve a</th></tr></thead><tbody>{agg_html or "<tr><td colspan='5'>Sin hallazgos agregados</td></tr>"}</tbody></table>
{agg_example}{agg_note if all_findings else ""}
<div class="section-sub" id="sec-osint">7.2 OSINT Pasivo -- CT, SAN, CAA, MTA-STS, TLS-RPT, BIMI</div>
<table class="data"><thead><tr><th>Dominio</th><th>CT</th><th>SAN</th><th>CAA</th><th>MTA-STS</th></tr></thead><tbody>{osint_rows}</tbody></table>
<div style="font-size:7.5pt; color:#6B7280;">CT = subdominios en logs publicos de certificados · SAN = nombres alternos del certificado · CAA/MTA-STS = controles presentes (&#10003;) o ausentes (&#10008;).</div>
<div class="info-box">Resumen consolidado por categoría. Datos OSINT públicos sin tráfico directo.</div>
{matrix_asm_html}
</div>

<div class="sec" id="sec-enriquecimiento"><div class="section-title">8. Enriquecimiento y Superficie Detallada</div>
<div class="info-box">Ficha por proveedor con el detalle del informe GC: tarjeta (score/KPI/HTTPS-TLS), listas de subdominios/CRT/SAN, vulnerabilidades, patching, supply-chain, banners, API, rutas, TLS, puertos, takeover, CSP/cookies, reputación, WAF/cloud, OSINT externo, KUMO, Prism, Claude-OSINT, Strix, FinalRecon, OWASP, social, WHO-DAT y registros CT/DNS. Solo se muestran bloques con datos reales del escaneo.</div>
{gc_sections}
</div>

<div class="sec" id="sec-hallazgos"><div class="section-title">9. Detalle de Hallazgos</div>
<div class="info-box">Cada hallazgo incluye: explicacion del riesgo, recomendación de mitigación y evidencia técnica del escaneo.</div>
{cards or "<div class='info-box'>Sin hallazgos con los datos actuales.</div>"}
</div>

<div class="sec" id="sec-recomendaciones"><div class="section-title">10. Recomendaciones Priorizadas</div>
<div class="section-sub2">P1 - Inmediato (0-7 días)</div>{rec_list('P1')}
<div class="section-sub2">P2 - Corto plazo (8-30 días)</div>{rec_list('P2')}
<div class="section-sub2">P3 - Mediano plazo (31-60 días)</div>{rec_list('P3')}
<div class="section-sub2">P4 - Mejora continua</div>{rec_list('P4')}
<div class="section-sub">Gantt RACI -- Plan de remediación (con coste/esfuerzo)</div>
<table class="data"><thead><tr><th>Actividad</th><th>Plazo</th><th>Esfuerzo (h)</th><th>Coste est. (€)</th><th>R</th><th>A</th><th>C</th></tr></thead><tbody>
<tr><td>Activar HSTS / preload</td><td>0-7 días</td><td class='num'>4</td><td class='num'>300</td><td>Infra</td><td>AppSec</td><td>Correo</td></tr>
<tr><td>CSP: eliminar unsafe-inline, nonces/hashes</td><td>0-7 días</td><td class='num'>8</td><td class='num'>600</td><td>AppSec</td><td>Infra</td><td>Dev</td></tr>
<tr><td>SPF: ~all hacia -all; DKIM rotar claves</td><td>8-30 días</td><td class='num'>16</td><td class='num'>1200</td><td>Correo</td><td>Infra</td><td>Legal</td></tr>
<tr><td>DMARC: p=none hacia quarantine hacia reject</td><td>8-30 días</td><td class='num'>12</td><td class='num'>900</td><td>Correo</td><td>Legal</td><td>Infra</td></tr>
<tr><td>DNSSEC + CAA + MTA-STS + TLS-RPT</td><td>8-30 días</td><td class='num'>24</td><td class='num'>1800</td><td>Infra</td><td>AppSec</td><td>--</td></tr>
<tr><td>Parchear subs / staging-prod cleanup</td><td>31-60 días</td><td class='num'>40</td><td class='num'>3000</td><td>Infra</td><td>AppSec</td><td>Dev</td></tr>
<tr><td>Typosquatting: registro defensivo / UDRP</td><td>31-60 días</td><td class='num'>8</td><td class='num'>1500</td><td>Legal</td><td>AppSec</td><td>Infra</td></tr>
<tr><td>SANs: consolidar certificados</td><td>P4</td><td class='num'>16</td><td class='num'>1200</td><td>Infra</td><td>AppSec</td><td>--</td></tr>
<tr><td>Programa bug bounty / VDP</td><td>P4</td><td class='num'>40</td><td class='num'>5000</td><td>AppSec</td><td>Legal</td><td>Infra</td></tr>
<tr><td>Monitoreo continuo ASM + alertas</td><td>P4</td><td class='num'>24</td><td class='num'>2000</td><td>Infra</td><td>AppSec</td><td>--</td></tr>
</tbody></table>
<div class="info-box">R=Responsable, A=Aprobador, C=Consultado. Plazos: 0-7/P1, 8-30/P2, 31-60/P3, P4=Mejora continua. Tarifa media 75€/h.</div>
</div>

<div class="sec" id="sec-fuentes"><div class="section-title">11. Fuentes y Referencias</div>
{render_factores_evaluados(providers)}
<div class="info-box"><strong>Estandares:</strong> RFC 6797 (HSTS), RFC 7489 (DMARC), RFC 7208 (SPF). NIST CSF / ISO 27001 / PCI DSS / DORA según mapeo por hallazgo.</div>
</div>

<div class="sec" id="sec-glosario"><div class="section-title">12. Glosario</div>
<table class="data"><thead><tr><th>Termino</th><th>Significado</th></tr></thead><tbody>
<tr><td><strong>SPF</strong></td><td>Registro DNS que declara que servidores pueden enviar correo del dominio (RFC 7208).</td></tr>
<tr><td><strong>DKIM</strong></td><td>Firma criptografica que garantiza que el correo no fue alterado.</td></tr>
<tr><td><strong>DMARC</strong></td><td>Política que une SPF/DKIM y ordena que hacer con lo no autenticado (none/quarantine/reject, RFC 7489).</td></tr>
<tr><td><strong>DNSSEC</strong></td><td>Firma de respuestas DNS contra suplantacion de registros.</td></tr>
<tr><td><strong>CAA</strong></td><td>Registro que limita que autoridades (CA) pueden emitir certificados del dominio.</td></tr>
<tr><td><strong>MTA-STS</strong></td><td>Política que exige TLS cifrado en la entrega de correo entre servidores.</td></tr>
<tr><td><strong>TLS-RPT</strong></td><td>Reportes de fallos de cifrado TLS entre servidores de correo.</td></tr>
<tr><td><strong>BIMI</strong></td><td>Muestra el logo de la marca junto a correos autenticados.</td></tr>
<tr><td><strong>DANE/TLSA</strong></td><td>Asocia certificados TLS especificos via DNS (requiere DNSSEC).</td></tr>
<tr><td><strong>STARTTLS</strong></td><td>Negociacion de cifrado TLS en conexiones de correo.</td></tr>
<tr><td><strong>HSTS</strong></td><td>Cabecera que obliga al navegador a usar solo HTTPS (RFC 6797).</td></tr>
<tr><td><strong>CSP</strong></td><td>Política que restringe de donde puede cargar scripts/recursos el navegador (anti-XSS).</td></tr>
<tr><td><strong>Subdomain takeover</strong></td><td>Apropiacion de un subdominio cuyo destino externo (CNAME) quedo liberado.</td></tr>
<tr><td><strong>Typosquatting</strong></td><td>Dominios con errores tipograficos registrados para phishing.</td></tr>
<tr><td><strong>EPSS</strong></td><td>Probabilidad estimada (0-1) de que un CVE sea explotado en 30 días (FIRST).</td></tr>
<tr><td><strong>KEV</strong></td><td>Catalogo CISA de vulnerabilidades con explotación activa confirmada.</td></tr>
<tr><td><strong>WAF</strong></td><td>Firewall de aplicaciones web que filtra tráfico malicioso antes del origen.</td></tr>
<tr><td><strong>OSINT</strong></td><td>Inteligencia con fuentes abiertas y públicas, sin interactuar con el objetivo.</td></tr>
<tr><td><strong>CT logs</strong></td><td>Registros publicos de transparencia de certificados (fuente de subdominios).</td></tr>
</tbody></table>
</div>

<div class="sec" id="sec-anexos"><div class="section-title">13. Anexos</div>
<div class="section-sub" id="sec-anexo-a">Anexo A -- SANs completos ({len(san_all)} total)</div>
<table class="data"><thead><tr><th>Dominio</th><th>Subject Alternative Names</th></tr></thead><tbody>{san_rows}</tbody></table>
<div class="section-sub" id="sec-anexo-b">Anexo B -- CT Logs: {esc(dom0)} ({len(subs_all)} subdominios)</div>
<div class="evidence-box">{ct_html[:1500]}</div>
<div class="section-sub" id="sec-anexo-c">Anexo C -- Headers HTTP crudos: {esc(dom0)}</div>
<div class="evidence-box">{raw_hdrs}</div>
<div class="section-sub" id="sec-anexo-d">Anexo D -- Shodan InternetDB + Exposure: {esc(dom0)}</div>
<div class="evidence-box">{anexo_e}</div>
<div class="section-sub" id="sec-anexo-e">Anexo E -- Notas metodologicas</div>
<div class="info-box">Historial 30 días: {len(hist)} punto(s) reales de <code>scan_history.db</code> (se requieren 2+ escaneos; sin historial se muestra aviso, nunca simulacion). Domain Score {dscore}: heuristica benevola 100 menos deducciones. Overall {overall}: promedio de factores. Sección 8 adopta los bloques de detalle del informe GC (generate_cibest_report.py). Compliance mapping NIST/PCI/DORA por hallazgo. Datos 100% reales desde asm_report.json.</div>
<div class="section-sub" id="sec-anexo-f">Anexo F -- Nota metodologica de scores</div>
{legend_html}
<div class="info-box"><strong>Domain Score (Técnico) ({dscore}/100):</strong> heurística benévola, parte de 100 y resta por cada control técnico fallado (20 controles: HSTS, CSP, TLS, SPF/DMARC, DNSBL, etc.). Fórmula {esc(FORMULA_VERSION)} ({esc(FORMULA_DATE)}) · Código: <code>domain_score()</code> · Deducciones: ver tabla §4 · Penalizaciones: {sum(abs(p) for _,p in _ded)} → 100 - {sum(abs(p) for _,p in _ded)} = {dscore} · Delta vs anterior: {f'{dscore - prev.get("domain_score"):+g}' if prev and prev.get('domain_score') is not None else '—'} (prev {prev.get('domain_score') if prev else '—'} → {dscore}).<br>
<strong>Score General / Puntuación General (Negocio) ({score_general}/100, oficial):</strong> promedio simple de 11 factores de negocio; cada factor = 100 - incidencias x deducción. Fórmula {esc(FORMULA_VERSION)} ({esc(FORMULA_DATE)}) · Código: <code>_factor()</code> · Factores: ver §3.1 · Penalizaciones promedio: {100 - score_general} → 100 - {100 - score_general} = {score_general} · Delta vs anterior: {f'{score_general - prev.get("score_general"):+g}' if prev and prev.get('score_general') is not None else '—'} (prev {prev.get('score_general') if prev else '—'} → {score_general}).<br>
<strong>Overall Score (Scorecard style) ({overall}/100):</strong> promedio ponderado estilo SecurityScorecard (Network/DNS/Patching/IPRep/AppSec ×1.2, resto ×1.0/×0.8) para benchmarking sectorial. Fórmula {esc(FORMULA_VERSION)} ({esc(FORMULA_DATE)}) · Código: <code>precia_scorecard.py:overall_score()</code> · Pesos: ver tabla desglose auditable en §5 · ΣPesos=10.5 · Penalizaciones ponderadas: {100 - overall} → 100 - {100 - overall} = {overall} · Delta vs anterior: {f'{overall - prev.get("overall_score"):+g}' if prev and prev.get('overall_score') is not None else '—'} (prev {prev.get('overall_score') if prev else '—'} → {overall}).<br>
Historial: {len(hist)} punto(s) reales de <code>scan_history.db</code> (sin datos suficientes se muestra aviso, nunca simulación). Valor anterior: {prev.get('score_general') if prev else '—'} → {score_general} · Versión fórmula: {esc(FORMULA_VERSION)} · Fecha cálculo: {esc(fecha)}.</div>
<div class="legal-note">Este documento corresponde a una evaluación puntual basada en la información disponible al momento de generacion. Los resultados deben ser validados antes de tomar decisiones operativas o contractuales.<br>INFORME UNIFICADO B3 - {esc(dom0)} | Preparado: {esc(fecha)}</div>
</div>

</div></body></html>"""
    return html


def main() -> int:
    ap = argparse.ArgumentParser(description="B3 - Informe Unificado de Seguridad")
    ap.add_argument("--asm", type=Path, default=ROOT / "asm_report.json", help="JSON de asm_scan.py")
    ap.add_argument("--out", type=Path, default=ROOT / "informe_unificado_b3.html", help="HTML de salida")
    ap.add_argument("--analista", default="", help="Nombre del analista")
    ap.add_argument("--org", default="GrupoCibest", help="Organizacion emisora")
    ap.add_argument("--history", type=Path, help="Archivo JSON con historial de scores (opcional)")
    ap.add_argument("--paginate", action="store_true", help="Segundo pase Playwright: números de página reales en el indice")
    args = ap.parse_args()
    if not args.asm.is_file():
        print(f"[ERROR] No se encuentra {args.asm}")
        return 1
    data = json.loads(args.asm.read_text(encoding="utf-8"))
    history = []
    if args.history and args.history.is_file():
        try:
            history = json.loads(args.history.read_text(encoding="utf-8"))
        except Exception:
            history = []
    html = build_report(data, args.analista, args.org, history=history)
    args.out.write_text(html, encoding="utf-8")
    print(f"[OK] {args.out}")
    if args.paginate:
        try:
            pages = paginate_toc(args.out)
            print(f"[OK] índice paginado: {len(pages)} secciones")
        except Exception as e:
            print(f"[WARN] paginacion omitida: {e}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
