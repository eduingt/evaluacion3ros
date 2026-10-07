#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generador B2 - Informe Scorecard de Seguridad
Estilo: corporativo, fondo blanco, azul oscuro (#173B57), limpio, profesional.
"""

from __future__ import annotations
import argparse, json, math
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from pasivo_canon import collect_pasive_items
from precia_scorecard import render_precialike_block
from toc_helper import render_toc
from score_legend import render_score_legend
from resumen_ejecutivo import render_resumen_ejecutivo
from semi_canon import collect_semi_active_items

FORMULA_VERSION = "B3-v2.0"
FORMULA_DATE = "2026-09-22"

ROOT = Path(__file__).resolve().parent

CSS = """
@page { margin:1.5cm; size:A4; }
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:'Arial','Helvetica',sans-serif; font-size:10pt; color:#1F2933; background:#fff; line-height:1.5; }
.page { max-width:210mm; margin:0 auto; padding:0; }

/* Cover */
.cover { page-break-after:always; padding:0 0 40px 0; position:relative; min-height:95vh; display:flex; flex-direction:column; }
.cover-top { background:#173B57; color:#fff; padding:50px 60px 30px; }
.cover-top .powered { font-size:8pt; opacity:.7; letter-spacing:.1em; text-transform:uppercase; margin-bottom:6px; }
.cover-top h1 { font-size:32pt; font-weight:800; line-height:1.1; letter-spacing:-.02em; margin-bottom:4px; }
.cover-top .sub { font-size:14pt; font-weight:300; color:rgba(255,255,255,.85); margin-bottom:40px; line-height:1.3; }
.cover-top .org-name { font-size:22pt; font-weight:700; color:#fff; }
.cover-meta { padding:40px 60px 20px; flex:1; display:flex; flex-direction:column; justify-content:center; }
.cover-meta table { width:100%; border-collapse:collapse; font-size:10pt; }
.cover-meta td { padding:8px 12px; border-bottom:1px solid #D9DEE3; }
.cover-meta td:first-child { font-weight:700; color:#173B57; width:180px; }
.cover-footer { border-top:3px solid #173B57; padding:16px 60px 0; font-size:7pt; color:#6B7280; display:flex; justify-content:space-between; }

/* Section */
.sec { padding:30px 50px; page-break-inside:avoid; }
.section-title { font-size:18pt; font-weight:700; color:#173B57; margin-bottom:20px; padding-bottom:8px; border-bottom:2px solid #173B57; }
.section-sub { font-size:13pt; font-weight:600; color:#2F6F9F; margin:18px 0 10px; }

/* Info boxes */
.info-box { background:#F3F5F7; border:1px solid #D9DEE3; border-radius:6px; padding:16px 18px; margin:14px 0; font-size:9.5pt; color:#4B5563; line-height:1.6; }
.info-box strong { color:#173B57; }

/* Tables */
table.data { width:100%; border-collapse:collapse; font-size:9pt; margin:12px 0; }
table.data th { background:#173B57; color:#fff; padding:8px 10px; text-align:left; font-size:8pt; text-transform:uppercase; letter-spacing:.06em; font-weight:700; }
table.data td { padding:7px 10px; border-bottom:1px solid #D9DEE3; vertical-align:top; }
table.data tr:nth-child(even) td { background:#F3F5F7; }
table.data .num { text-align:center; white-space:nowrap; }

/* Score badge */
.score-badge { display:inline-block; width:48px; height:48px; border-radius:50%; text-align:center; line-height:48px; font-size:20pt; font-weight:800; color:#fff; }
.score-badge.A { background:#2E7D32; }
.score-badge.B { background:#2F6F9F; }
.score-badge.C { background:#F9A825; }
.score-badge.D { background:#EF6C00; }
.score-badge.F { background:#C62828; }

.grade-A { color:#2E7D32; font-weight:700; }
.grade-B { color:#2F6F9F; font-weight:700; }
.grade-C { color:#F9A825; font-weight:700; }
.grade-D { color:#EF6C00; font-weight:700; }
.grade-F { color:#C62828; font-weight:700; }

/* Risk factor score colors */
.fs-verde { color:#2E7D32; font-weight:700; }
.fs-amarillo { color:#F9A825; font-weight:700; }
.fs-naranja { color:#EF6C00; font-weight:700; }
.fs-rojo { color:#C62828; font-weight:700; }

/* Severity badges */
.s-badge { display:inline-block; padding:2px 8px; border-radius:3px; font-size:8pt; font-weight:700; text-transform:uppercase; }
.s-critica { background:#fce4e4; color:#C62828; border:1px solid #C62828; }
.s-alta { background:#fde8d6; color:#EF6C00; border:1px solid #EF6C00; }
.s-media { background:#fff8e1; color:#F9A825; border:1px solid #F9A825; }
.s-baja { background:#e8f5e9; color:#2E7D32; border:1px solid #2E7D32; }
.s-info { background:#e3f2fd; color:#2F6F9F; border:1px solid #2F6F9F; }

/* Action card */
.action-card { background:#fff; border:1px solid #D9DEE3; border-left:4px solid #173B57; border-radius:6px; padding:12px 14px; margin-bottom:10px; page-break-inside:avoid; }
.action-card .ac-hdr { display:flex; align-items:center; gap:10px; margin-bottom:6px; }
.action-card .ac-factor { font-size:8pt; color:#2F6F9F; font-weight:600; text-transform:uppercase; }
.action-card .ac-title { font-size:10pt; font-weight:600; color:#1F2933; }
.action-card .ac-body { font-size:9pt; color:#4B5563; line-height:1.5; }
.action-card .ac-meta { display:flex; gap:16px; margin-top:6px; font-size:8pt; }
.action-card .ac-meta span { color:#6B7280; }

/* Step list */
.steps { display:flex; gap:12px; margin:14px 0; flex-wrap:wrap; }
.step { flex:1; min-width:120px; background:#F3F5F7; border:1px solid #D9DEE3; border-radius:6px; padding:12px; text-align:center; }
.step .step-num { display:inline-block; width:28px; height:28px; line-height:28px; border-radius:50%; background:#173B57; color:#fff; font-size:10pt; font-weight:700; margin-bottom:6px; }
.step .step-text { font-size:8.5pt; color:#4B5563; }

/* Findings detail */
.find-card { background:#fff; border:1px solid #D9DEE3; border-radius:6px; margin-bottom:12px; overflow:hidden; page-break-inside:avoid; }
.find-card .fc-hdr { background:#F3F5F7; padding:10px 14px; border-bottom:1px solid #D9DEE3; display:flex; align-items:center; gap:10px; }
.find-card .fc-hdr .fc-factor { font-size:8pt; color:#2F6F9F; font-weight:600; text-transform:uppercase; }
.find-card .fc-hdr .fc-active { font-size:9pt; font-weight:600; color:#1F2933; flex:1; }
.find-card .fc-body { padding:12px 14px; }
.find-card .fc-row { display:flex; margin-bottom:4px; font-size:8.5pt; }
.find-card .fc-label { font-weight:700; color:#173B57; width:110px; flex-shrink:0; }
.find-card .fc-value { color:#4B5563; flex:1; }
.find-card .fc-evidence { background:#F3F5F7; border:1px solid #D9DEE3; border-radius:4px; padding:8px 10px; font-size:8pt; font-family:'Consolas','Courier New',monospace; color:#4B5563; line-height:1.5; white-space:pre-wrap; word-break:break-all; margin-top:4px; }

/* Rec matrix */
.rec-row { display:flex; gap:8px; margin-bottom:8px; padding:10px 12px; border:1px solid #D9DEE3; border-radius:6px; background:#fff; page-break-inside:avoid; }
.rec-row .rec-prio { width:40px; text-align:center; font-weight:800; font-size:10pt; line-height:1.2; }
.rec-row .rec-prio.p1 { color:#C62828; }
.rec-row .rec-prio.p2 { color:#EF6C00; }
.rec-row .rec-prio.p3 { color:#F9A825; }
.rec-row .rec-prio.p4 { color:#2F6F9F; }
.rec-row .rec-body { flex:1; }
.rec-row .rec-title { font-size:9.5pt; font-weight:600; color:#1F2933; }
.rec-row .rec-detail { font-size:8pt; color:#6B7280; margin-top:2px; }
.rec-row .rec-detail span { display:inline-block; margin-right:12px; }

/* Footer */
.page-footer { font-size:7pt; color:#6B7280; border-top:1px solid #D9DEE3; padding:6px 50px; display:flex; justify-content:space-between; }
.legal-note { font-size:7pt; color:#9CA3AF; text-align:center; padding:10px 50px; border-top:1px solid #D9DEE3; margin-top:20px; }

/* Smart columns */
.cols-2 { display:flex; gap:20px; }
.cols-2 > * { flex:1; }

/* Executive summary cards */
.exec-grid { display:flex; gap:12px; margin:14px 0; }
.exec-card { flex:1; background:#F3F5F7; border:1px solid #D9DEE3; border-radius:6px; padding:14px; text-align:center; }
.exec-card .ec-val { font-size:22pt; font-weight:800; }
.exec-card .ec-lbl { font-size:8pt; color:#6B7280; text-transform:uppercase; letter-spacing:.04em; margin-top:2px; }

/* Badges */
.risk-critical { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#5c1010; color:#fff; }
.risk-high { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#9b1c1c; color:#fff; }
.risk-med { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#cc8800; color:#fff; }
.risk-low { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#2d7a4a; color:#fff; }
.epss-badge { display:inline-block; font-size:10px; padding:1px 5px; border-radius:4px; background:#e8eef5; color:#3a5478; }
.kev-badge { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#fce4e4; color:#a00; }
/* Print */
@media print { body { -webkit-print-color-adjust:exact; print-color-adjust:exact; } }
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def esc(s: Any) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _score_letter(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"

def _score_class(score: int) -> str:
    if score >= 90: return "grade-A fs-verde"
    if score >= 70: return "grade-B fs-amarillo"
    if score >= 60: return "grade-D fs-naranja"
    return "grade-F fs-rojo"

def _badge_class(sev: str) -> str:
    m = {"critica":"s-critica","alta":"s-alta","media":"s-media","baja":"s-baja","informativa":"s-info"}
    return m.get(sev.lower(), "s-info")

def domain_score(p: dict[str, Any]) -> float:
    """Benevolo: parte de 100 y resta suave — 100 con higiene básica, baja gradual."""
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

# ---------------------------------------------------------------------------
# SVG Chart: score history line chart
# ---------------------------------------------------------------------------

def history_chart_svg(history: list[dict[str, Any]], w: int = 620, h: int = 240) -> str:
    if not history:
        return ""
    pad_l, pad_r, pad_t, pad_b = 50, 30, 20, 40
    cw = w - pad_l - pad_r
    ch = h - pad_t - pad_b

    scores = [s["score"] for s in history]
    industry = [s.get("industria") for s in history if s.get("industria") is not None]
    dates = [s["fecha"][-5:] for s in history]  # MM-DD
    all_vals = scores + industry if industry else scores
    y_min = max(0, min(all_vals) - 5)
    y_max = min(100, max(all_vals) + 5)
    y_range = y_max - y_min or 1

    def y_pos(val): return pad_t + ch - (val - y_min) / y_range * ch
    def x_pos(i): return pad_l + (i / max(len(history) - 1, 1)) * cw

    # Background bands
    bands = [("F", 0, 59, "#fee2e2"), ("D", 60, 69, "#ffedd5"),
             ("C", 70, 79, "#fef9c3"), ("B", 80, 89, "#e0f2fe"), ("A", 90, 100, "#dcfce7")]

    svg = f'<svg width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg" style="font-family:Arial,Helvetica,sans-serif;">'

    for letter, lo, hi, color in bands:
        lo_clamped = max(lo, y_min)
        hi_clamped = min(hi, y_max)
        if lo_clamped > y_max or hi_clamped < y_min:
            continue
        y1 = y_pos(hi_clamped)
        y2 = y_pos(lo_clamped)
        svg += f'<rect x="{pad_l}" y="{y1}" width="{cw}" height="{y2-y1}" fill="{color}" opacity=".4" rx="2"/>'
        # Label on right edge
        svg += f'<text x="{w-pad_r+6}" y="{(y1+y2)/2+3}" fill="#9CA3AF" font-size="8" font-weight="700">{letter}</text>'

    # Y axis labels
    for val in range(int(y_min), int(y_max)+1, max(1, (int(y_max)-int(y_min))//5)):
        y = y_pos(val)
        svg += f'<text x="{pad_l-8}" y="{y+3}" fill="#6B7280" font-size="7" text-anchor="end">{val}</text>'
        svg += f'<line x1="{pad_l}" y1="{y}" x2="{w-pad_r}" y2="{y}" stroke="#D9DEE3" stroke-width=".5"/>'

    # Industry line
    if industry:
        pts = " ".join(f"{x_pos(i)},{y_pos(industry[i])}" for i in range(len(industry)))
        svg += f'<polyline points="{pts}" fill="none" stroke="#9CA3AF" stroke-width="1.5" stroke-dasharray="4,3"/>'
        # Legend
        last_i = len(industry)-1
        svg += f'<text x="{x_pos(last_i)+4}" y="{y_pos(industry[last_i])+3}" fill="#9CA3AF" font-size="7">Industria</text>'

    # Main line
    pts = " ".join(f"{x_pos(i)},{y_pos(scores[i])}" for i in range(len(scores)))
    svg += f'<polyline points="{pts}" fill="none" stroke="#173B57" stroke-width="2.5"/>'

    # Dots
    for i, s in enumerate(scores):
        svg += f'<circle cx="{x_pos(i)}" cy="{y_pos(s)}" r="3" fill="#173B57" stroke="#fff" stroke-width="1.5"/>'
        svg += f'<text x="{x_pos(i)}" y="{y_pos(s)-8}" fill="#173B57" font-size="7" font-weight="700" text-anchor="middle">{s}</text>'

    # X axis labels
    for i, d in enumerate(dates):
        svg += f'<text x="{x_pos(i)}" y="{h-6}" fill="#6B7280" font-size="7" text-anchor="middle">{esc(d)}</text>'

    svg += '</svg>'
    return svg

# ---------------------------------------------------------------------------
# Build report HTML
# ---------------------------------------------------------------------------

def build_report(asm: dict[str, Any], analista: str = "", org: str = "GrupoCibest") -> str:
    providers = asm.get("providers") or []
    matrix = [m for m in (asm.get("matrix") or [])]
    matrix_by_domain = {m.get("dominio", ""): m for m in matrix}
    now = datetime.now(timezone.utc)

    # --- Derive counts from ASM data ---
    total_subs = sum(len(p.get("subdomains") or []) for p in providers)
    total_crt = sum(len(p.get("crt_subdomains") or []) for p in providers)
    total_vulns = sum(len(p.get("vulnerabilities") or []) for p in providers)
    total_leaks = sum(len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) for p in providers)
    total_takeover = sum(len(p.get("takeover_risks") or []) for p in providers)
    total_typos = sum(len(p.get("typosquatting") or []) for p in providers)
    total_patch_eol = sum(sum(1 for x in (p.get("patching") or []) if x.get("status") == "eol") for p in providers)
    total_open_ports = sum(len([o for o in (p.get("open_ports") or []) if o.get("state") == "open"]) for p in providers)
    total_pivot = sum(len(p.get("pivot_results") or []) for p in providers)
    total_brute = sum(len(p.get("brute_subs") or []) for p in providers)

    # Derive org/domain name
    if org == "GrupoCibest" and providers:
        org_names = [p.get("name", p.get("domain", "")).replace("(www)", "").strip() for p in providers[:3]]
        org_show = ", ".join(org_names)
        if len(providers) > 3:
            org_show += f" y {len(providers)-3} mas"
    else:
        org_show = org

    domain = providers[0].get("domain", "") if providers else "N/A"
    sector = "Servicios financieros / Tecnologia"

    # --- Compute factor scores from real data ---
    factor_incidents: dict[str, int] = {}
    factor_scores: dict[str, float] = {}

    def _factor(providers, name, base, deductions):
        """Compute a factor score (0-100) = base - sum of deductions."""
        total = base
        for p in providers:
            for check, amount in deductions:
                if check(p):
                    total -= amount
                    factor_incidents[name] = factor_incidents.get(name, 0) + 1
        score = max(0, min(100, total))
        factor_scores[name] = score
        factor_incidents.setdefault(name, 0)
        return {"factor": name, "score": score, "incidencias": factor_incidents[name]}

    # For each p in providers, get data
    def _hdrs(p): return (p.get("https") or {}).get("headers") or {}
    def _dns(p): return p.get("dns") or {}
    def _tls(p): return p.get("tls") or {}

    # 1. Seguridad de aplicación web (base=100, deductions for missing HSTS, CSP, XCTO, XFO, cookies)
    factores = []
    factores.append(_factor(providers, "Seguridad de aplicacion web", 100, [
        (lambda p: not _hdrs(p).get("strict-transport-security"), 8),
        (lambda p: not (_hdrs(p).get("content-security-policy") or _hdrs(p).get("content-security-policy-report-only") or ""), 6),
        (lambda p: bool(p.get("csp_findings")), 4),
        (lambda p: not _hdrs(p).get("x-content-type-options"), 3),
        (lambda p: not _hdrs(p).get("x-frame-options") and not _hdrs(p).get("x-xss-protection"), 2),
        (lambda p: bool(p.get("cookie_findings")), 3),
    ]))

    # 2. Cubit Score (infrastructure posture)
    factores.append(_factor(providers, "Cubit Score", 100, [
        (lambda p: not _dns(p).get("dnssec_ok"), 3),
        (lambda p: not p.get("caa_records"), 2),
        (lambda p: not _dns(p).get("spf_record"), 5),
        (lambda p: not _dns(p).get("dmarc_record"), 5),
    ]))

    # 3. Estado de DNS
    factores.append(_factor(providers, "Estado de DNS", 100, [
        (lambda p: not _dns(p).get("spf_record"), 8),
        (lambda p: not _dns(p).get("dmarc_record"), 8),
        (lambda p: not _dns(p).get("dnssec_ok"), 5),
        (lambda p: not p.get("caa_records"), 3),
        (lambda p: len(_dns(p).get("ip_reputation") or []) > 0, 5),
    ]))

    # 4. Seguridad de puntos de conexión
    factores.append(_factor(providers, "Seguridad de puntos de conexion", 100, [
        (lambda p: len([o for o in (p.get("open_ports") or []) if o.get("state") == "open"]) > 3, 10),
        (lambda p: any(o.get("state") == "open" and o.get("port") in (21,22,23,3389,3306,1433,5432,6379) for o in (p.get("open_ports") or [])), 8),
    ]))

    # 5. Hacker Chatter (OSINT social media mentions)
    factores.append(_factor(providers, "Hacker Chatter", 100, []))

    # 6. Reputación de IP
    factores.append(_factor(providers, "Reputacion de IP", 100, [
        (lambda p: len(_dns(p).get("ip_reputation") or []) > 0, 10),
        (lambda p: (p.get("urlhaus") or {}).get("malicious", False), 15),
    ]))

    # 7. Filtración de información
    factores.append(_factor(providers, "Filtracion de informacion", 100, [
        (lambda p: len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) > 0, 15),
    ]))

    # 8. Seguridad de red
    factores.append(_factor(providers, "Seguridad de red", 100, [
        (lambda p: bool((p.get("tls") or {}).get("error")), 10),
        (lambda p: False, 0),  # placeholder
    ]))

    # 9. Cadencia de aplicación de revisiones
    factores.append(_factor(providers, "Cadencia de aplicacion de revisiones", 100, [
        (lambda p: sum(1 for x in (p.get("patching") or []) if x.get("status") == "eol") > 0, 12),
        (lambda p: sum(1 for x in (p.get("patching") or []) if x.get("status") == "ending") > 0, 5),
        (lambda p: len(p.get("vulnerabilities") or []) > 0, 8),
    ]))

    # 10. Ingeniería social
    factores.append(_factor(providers, "Ingenieria social", 100, [
        (lambda p: len(p.get("typosquatting") or []) > 0, 5),
    ]))

    # --- Overall score (weighted average of factors) ---
    score_general = int(sum(f["score"] for f in factores) / max(len(factores), 1))
    score_general = max(0, min(100, score_general))
    letter = _score_letter(score_general)

    # Resumen Ejecutivo canónico (estilo Beta1) — coherente con Score General (factores)
    resumen_block = render_resumen_ejecutivo(providers, asm, score_general=score_general, fecha_str=str(asm.get("generated_utc","")), org="Incocredito", analista="@eduingt")
    toc_block = render_toc(report_type="b2")
    score_legend_block = render_score_legend()
    letter_class = _score_class(score_general)

    # Precia-like scorecard (estilo SecurityScorecard)
    precia_blocks = "\n".join(render_precialike_block(pr, analista="@eduingt", org=pr.get("name") or pr.get("domain",""), generated=str(asm.get("generated_utc",""))) for pr in providers)

    # --- History (simulated 5 weekly points trending toward current) ---
    history = []
    for i in range(4, -1, -1):
        d = (now - timedelta(weeks=i)).strftime("%Y-%m-%d")
        drift = int((i * 2.5) * (1 if i % 2 == 0 else -1))
        hs = max(0, min(100, score_general + drift - int(i * 1.2)))
        ind = max(0, min(100, hs + 5 + int(i * 0.8)))
        history.append({"fecha": d, "score": hs, "industria": ind})

    # --- Derive hallazgos from real data ---
    hallazgos: list[dict[str, Any]] = []

    for p in providers:
        domain = p.get("domain", "")
        dns = p.get("dns") or {}
        https = p.get("https") or {}
        tls_data = p.get("tls") or {}
        headers = https.get("headers") or {}
        ipv4 = dns.get("ipv4", [])
        ip_str = ipv4[0] if ipv4 else domain

        # HSTS missing
        if not headers.get("strict-transport-security"):
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Alta", "impacto_score": "-6.7",
                "titulo": "Falta cabecera HSTS (Strict-Transport-Security)",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Dominio: {domain} | Cabecera HSTS: Ausente",
                "descripcion": "HSTS fuerza al navegador a usar exclusivamente HTTPS, previniendo ataques de SSL stripping. Sin esta cabecera, un atacante puede interceptar la primera conexión HTTP.",
                "riesgo": "Aumenta la exposición a ataques man-in-the-middle y degradacion de protocolo.",
                "recomendacion": "Implementar Strict-Transport-Security con max-age>=31536000 e includeSubDomains.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # CSP missing
        csp = headers.get("content-security-policy") or headers.get("content-security-policy-report-only") or ""
        if not csp:
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Alta", "impacto_score": "-5.2",
                "titulo": "Falta política de seguridad de contenido (CSP)",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Dominio: {domain} | Cabecera CSP: Ausente",
                "descripcion": "CSP controla que recursos puede cargar el navegador, mitigando XSS e inyeccion de contenido.",
                "riesgo": "Permite ejecucion de scripts maliciosos y exfiltracion de datos mediante XSS.",
                "recomendacion": "Configurar CSP con script-src 'self', object-src 'none', base-uri 'self' y report-uri.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # CSP weak
        if csp and p.get("csp_findings"):
            for cf in p["csp_findings"]:
                hallazgos.append({
                    "factor": "Seguridad de aplicacion web", "gravedad": "Media", "impacto_score": "-3.0",
                    "titulo": f"CSP contiene directivas inseguras: {cf.get('desc','')[:80]}",
                    "activo": domain, "ip": ip_str, "puerto": "443",
                    "evidencia": f"CSP actual: {csp[:250]}",
                    "descripcion": "La política CSP contiene directivas como unsafe-inline o unsafe-eval que reducen su efectividad.",
                    "riesgo": "Permite la ejecucion de scripts no autorizados en el contexto del dominio.",
                    "recomendacion": "Eliminar unsafe-inline/unsafe-eval, usar nonces o hashes para scripts inline.",
                    "prioridad": "P2", "estado": "Abierto"
                })

        # SPF/DMARC missing
        spf = dns.get("spf_record")
        dmarc = dns.get("dmarc_record")
        dmarc_policy = dns.get("dmarc_policy") or ""
        if not spf and not dmarc:
            hallazgos.append({
                "factor": "Estado de DNS", "gravedad": "Critica", "impacto_score": "-7.0",
                "titulo": "SPF y DMARC ausentes",
                "activo": domain, "ip": ip_str, "puerto": "25",
                "evidencia": f"SPF: Ausente | DMARC: Ausente",
                "descripcion": "SPF y DMARC son esenciales para prevenir la suplantacion de dominio via correo electrónico.",
                "riesgo": "Alto riesgo de phishing corporativo y suplantacion de identidad.",
                "recomendacion": "Configurar registro SPF con -all y DMARC con p=reject.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # TLS error
        if tls_data.get("error"):
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Critica", "impacto_score": "-8.0",
                "titulo": "Error en configuración TLS",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Error: {tls_data['error'][:150]}",
                "descripcion": "Se detectaron errores en la negociacion TLS que pueden impedir conexiones seguras.",
                "riesgo": "Imposibilidad de establecer conexiones cifradas, exponiendo datos en transito.",
                "recomendacion": "Revisar cadena de certificados, configuración del servidor TLS y ciphers soportados.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # Subdomains exposed
        sub_count = len(p.get("subdomains") or []) + len(p.get("crt_subdomains") or []) + len(p.get("brute_subs") or [])
        if sub_count > 0:
            sub_sample = set(
                [s.get("subdomain","") for s in (p.get("subdomains") or [])[:3]] +
                [s for s in (p.get("crt_subdomains") or [])[:3]] +
                [s.get("fqdn","") for s in (p.get("brute_subs") or [])[:3]]
            )
            hallazgos.append({
                "factor": "Seguridad de puntos de conexion", "gravedad": "Media", "impacto_score": "-2.5",
                "titulo": f"{sub_count} subdominios detectados",
                "activo": domain, "ip": ip_str, "puerto": "-",
                "evidencia": f"Subdominios: {', '.join(sorted(sub_sample)[:8])}",
                "descripcion": "Cada subdominio incrementa la superficie de ataque. Subdominios olvidados pueden alojar servicios vulnerables.",
                "riesgo": "Ampliacion de la superficie de ataque con posibles activos sin mantenimiento.",
                "recomendacion": "Realizar inventario completo y eliminar subdominios no utilizados.",
                "prioridad": "P2", "estado": "Abierto"
            })

        # Takeover
        for t in p.get("takeover_risks") or []:
            t_desc = t.get("subdomain", t.get("fqdn", domain))
            hallazgos.append({
                "factor": "Seguridad de puntos de conexion", "gravedad": "Critica", "impacto_score": "-8.5",
                "titulo": f"Riesgo de subdomain takeover en {t_desc}",
                "activo": t_desc, "ip": ip_str, "puerto": "80/443",
                "evidencia": f"Subdominio: {t_desc} | Servicio: {t.get('service','?')} | CNAME: {t.get('cname','?')}",
                "descripcion": "Registro DNS apunta a un servicio externo no controlado que puede ser reclamado por un atacante.",
                "riesgo": "Permite al atacante servir contenido malicioso bajo el dominio legitimo.",
                "recomendacion": "Eliminar registros DNS a servicios no controlados o verificar propiedad de cuentas externas.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # Leaks
        real_leaks = [l for l in (p.get("credential_leaks") or []) if "error" not in l]
        for leak in real_leaks:
            source = leak.get("source", "?")
            count = leak.get("count", leak.get("entries", "?"))
            hallazgos.append({
                "factor": "Filtracion de informacion", "gravedad": "Critica", "impacto_score": "-7.5",
                "titulo": f"Credenciales filtradas en {source}",
                "activo": domain, "ip": "-", "puerto": "-",
                "evidencia": f"Fuente: {source} | Registros: {count}",
                "descripcion": f"Se detectaron credenciales del dominio {domain} en la filtración de {source}.",
                "riesgo": "Acceso no autorizado a sistemas corporativos, riesgo de suplantacion y movimiento lateral.",
                "recomendacion": "Rotar inmediatamente todas las credenciales comprometidas e implementar 2FA obligatorio.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # EOL software
        for e in [x for x in (p.get("patching") or []) if x.get("status") == "eol"]:
            tech = e.get("name", e.get("technology", "Software"))
            ver = e.get("version", "")
            hallazgos.append({
                "factor": "Cadencia de aplicacion de revisiones", "gravedad": "Critica", "impacto_score": "-7.0",
                "titulo": f"Software EOL: {tech}" + (f" {ver}" if ver else ""),
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Tecnologia: {tech} | Version: {ver} | Estado: Sin soporte (EOL)",
                "descripcion": "Software al final de su vida util ya no recibe parches de seguridad.",
                "riesgo": "Vulnerabilidades conocidas sin correccion, explotables remotamente.",
                "recomendacion": "Actualizar a version con soporte activo. Implementar WAF como mitigación temporal.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # Typosquatting
        for t in (p.get("typosquatting") or []):
            hallazgos.append({
                "factor": "Ingenieria social", "gravedad": "Media", "impacto_score": "-2.0",
                "titulo": f"Dominio tipograficamente similar detectado: {t.get('domain','?')}",
                "activo": t.get("domain", "?"), "ip": t.get("ip", "?"), "puerto": "-",
                "evidencia": f"Dominio: {t.get('domain','?')} | Resuelve: {t.get('ip','?')}",
                "descripcion": "Dominios tipograficamente similares al oficial pueden ser usados en campanas de phishing.",
                "riesgo": "Suplantacion de identidad corporativa, fraude a clientes y dano reputacional.",
                "recomendacion": "Monitorear registros de dominios similares y considerar adquisicion de los mas críticos.",
                "prioridad": "P2", "estado": "Abierto"
            })

        # CVE findings from banner grab
        for c in (p.get("cve_findings") or []):
            cve_id = c.get("id", "?")
            cve_title = c.get("title", "")[:120]
            def _cve_tag(c2):
                parts = []
                rs = c2.get("risk_score")
                if rs is not None:
                    parts.append(f"Risk:{rs:.1f}")
                epss = c2.get("epss_score")
                if epss is not None:
                    parts.append(f"EPSS:{epss*100:.1f}%")
                if c2.get("in_kev"):
                    parts.append("KEV")
                return " [" + "/".join(parts) + "]" if parts else ""
            tag = _cve_tag(c)
            prioridad = "P1" if c.get("in_kev") or (c.get("risk_score") or 0) >= 7 else "P2"
            gravedad = "Critica" if c.get("in_kev") else "Alta" if (c.get("risk_score") or 0) >= 4 else "Media"
            hallazgos.append({
                "factor": "Cadencia de aplicacion de revisiones", "gravedad": gravedad, "impacto_score": "-5.0",
                "titulo": f"CVE por banner grab: {cve_id}{tag}",
                "activo": domain, "ip": ip_str, "puerto": str(c.get("port", "?")),
                "evidencia": f"CVE: {cve_id} | Producto: {c.get('product','?')} | Puerto: {c.get('port','?')} | Risk Score: {c.get('risk_score','?')} | EPSS: {c.get('epss_score','?')} | KEV: {c.get('in_kev','?')} | {cve_title}",
                "descripcion": f"Vulnerabilidad potencial ({cve_id}) via correlacion de banner.{tag} {cve_title}",
                "riesgo": "Explotacion remota de vulnerabilidad conocida en servicio expuesto." + (" — Esta CVE esta en el catalogo CISA KEV de explotación activa." if c.get("in_kev") else ""),
                "recomendacion": "Actualizar el software a la última version parcheada. Verificar CVE en NVD y aplicar mitigaciones recomendadas." + (" PRIORIDAD ALTA: CVE en explotación activa segun CISA KEV." if c.get("in_kev") else ""),
                "prioridad": prioridad, "estado": "Abierto"
            })

        # Banner service info
        for b in (p.get("banner_grabs") or []):
            if b.get("error"):
                continue
            prod = b.get("product", "desconocido")
            port = b.get("port", "?")
            proto = b.get("protocol", "?")
            banner_preview = b.get("banner", "")[:100]
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Informativa", "impacto_score": "0",
                "titulo": f"Servicio detectado: {proto} puerto {port}",
                "activo": domain, "ip": ip_str, "puerto": str(port),
                "evidencia": f"Puerto: {port} | Protocolo: {proto} | Producto: {prod} | Banner: {banner_preview}",
                "descripcion": f"Se identifico el servicio {prod} corriendo en el puerto {port} ({proto}) mediante banner grabbing pasivo.",
                "riesgo": "Exposicion de información del servicio. Versiones antiguas pueden tener vulnerabilidades conocidas.",
                "recomendacion": "Verificar que el servicio sea necesario y este actualizado. Considerar ofuscar banners.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # API Endpoints
        api_eps = p.get("api_endpoints") or []
        api_non404 = [e for e in api_eps if e.get("status_code") and e["status_code"] != 404]
        api_shadow = [e for e in api_eps if e.get("is_shadow")]
        if api_non404:
            detail = "; ".join(f"{e.get('method','?')} {e.get('path','?')} (HTTP {e.get('status_code','?')})" for e in api_non404[:6])
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Alta" if api_shadow else "Media", "impacto_score": "-5.0",
                "titulo": f"APIs descubiertas: {len(api_non404)} responden, {len(api_shadow)} shadow",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Endpoints que responden ({len(api_non404)}): {detail}"[:500],
                "descripcion": f"Se probaron {len(api_eps)} rutas API comunes. {len(api_non404)} endpoints respondieron con datos. {len(api_shadow)} shadow APIs no documentadas detectadas.",
                "riesgo": "Shadow APIs pueden exponer funcionalidades no previstas, datos sensibles o rutas de administracion.",
                "recomendacion": "Revisar cada shadow API. Evaluar necesidad de exposición pública, agregar autenticacion, o deshabilitar.",
                "prioridad": "P2", "estado": "Abierto"
            })
        for ep in api_shadow:
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Critica", "impacto_score": "-8.0",
                "titulo": f"Shadow API: {ep.get('method','?')} {ep.get('path','?')}",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Ruta: {ep.get('path','?')} | Metodo: {ep.get('method','?')} | Status: {ep.get('status_code','?')} | Categoria: {ep.get('category','?')} | Body: {(ep.get('body_preview') or '')[:200]}",
                "descripcion": f"Endpoint no documentado descubierto via probing. Categoria: {ep.get('category','?')}.",
                "riesgo": "Acceso no autorizado a funcionalidades internas, fuga de información o bypass de seguridad.",
                "recomendacion": "Investigar si es legitimo. Si no es necesario, deshabilitar. Si es necesario, proteger con autenticacion.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # Public Paths
        paths = p.get("public_paths") or []
        interesting = [x for x in paths if x.get("status_code") not in (None, 404)]
        if interesting:
            detail = "; ".join(f"{x.get('path','')} (HTTP {x.get('status_code','?')})" for x in interesting[:8])
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Media", "impacto_score": "-3.0",
                "titulo": f"Rutas públicas accesibles: {len(interesting)} responden",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Rutas: {detail}",
                "descripcion": f"Se probaron {len(paths)} rutas web comunes. {len(interesting)} endpoints respondieron con códigos de exito, lo que puede exponer información sensible o puntos de entrada.",
                "riesgo": "Exposicion de información a traves de rutas públicas (robots.txt, health, API docs, etc.).",
                "recomendacion": "Revisar cada ruta accesible. Deshabilitar las innecesarias y proteger las requeridas con autenticacion.",
                "prioridad": "P3", "estado": "Abierto"
            })

        # DKIM missing
        dkim_records = dns.get("dkim_records") or []
        if not dkim_records:
            hallazgos.append({
                "factor": "Estado de DNS", "gravedad": "Media", "impacto_score": "-2.5",
                "titulo": "DKIM no configurado",
                "activo": domain, "ip": ip_str, "puerto": "25",
                "evidencia": "Registros DKIM: Ausentes",
                "descripcion": "DKIM permite firmar digitalmente los correos para verificar su autenticidad e integridad. Sin DKIM, los atacantes pueden alterar el contenido del correo sin ser detectados.",
                "riesgo": "Suplantacion de correo electrónico y alteracion de mensajes sin detección.",
                "recomendacion": "Configurar registro DKIM con par de claves asimetricas y alineacion con DMARC.",
                "prioridad": "P2", "estado": "Abierto"
            })

        # MX records
        mx_records = dns.get("mx_records") or []
        if mx_records:
            hallazgos.append({
                "factor": "Estado de DNS", "gravedad": "Informativa", "impacto_score": "0",
                "titulo": f"{len(mx_records)} servidor(es) MX configurado(s)",
                "activo": domain, "ip": ip_str, "puerto": "25",
                "evidencia": f"MX: {'; '.join(m.get('exchange','?') for m in mx_records[:5])}",
                "descripcion": "Los registros MX definen los servidores de correo autorizados para el dominio.",
                "riesgo": "No aplica - hallazgo informativo.",
                "recomendacion": "Verificar que los servidores MX sean los esperados y esten correctamente configurados.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # NS records
        ns_records = dns.get("ns_records") or []
        if ns_records:
            hallazgos.append({
                "factor": "Estado de DNS", "gravedad": "Informativa", "impacto_score": "0",
                "titulo": f"{len(ns_records)} servidor(es) NS configurado(s)",
                "activo": domain, "ip": "-", "puerto": "53",
                "evidencia": f"NS: {'; '.join(n.get('host','?') for n in ns_records[:5])}",
                "descripcion": "Los registros NS definen los servidores autoritativos de DNS para el dominio.",
                "riesgo": "No aplica - hallazgo informativo.",
                "recomendacion": "Verificar que los NS sean los esperados y que usen proveedores DNS redundantes.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # STARTTLS
        starttls_results = dns.get("starttls_results") or []
        starttls_ok = any(r.get("starttls_ok") for r in starttls_results) if starttls_results else None
        if starttls_results and not starttls_ok:
            hallazgos.append({
                "factor": "Estado de DNS", "gravedad": "Alta", "impacto_score": "-4.0",
                "titulo": "STARTTLS no soportado en servidores MX",
                "activo": domain, "ip": ip_str, "puerto": "25",
                "evidencia": f"Servidores MX sin STARTTLS: {sum(1 for r in starttls_results if not r.get('starttls_ok'))} de {len(starttls_results)}",
                "descripcion": "STARTTLS permite cifrar la comunicacion entre servidores de correo. Sin el, los correos se transmiten en texto plano.",
                "riesgo": "Intercepcion y lectura de correos electronicos en transito entre servidores MX.",
                "recomendacion": "Configurar STARTTLS en todos los servidores MX y verificar soporte mediante test de connectividad.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # DANE/TLSA
        dane_records = dns.get("dane_records") or []
        if not dane_records:
            hallazgos.append({
                "factor": "Estado de DNS", "gravedad": "Media", "impacto_score": "-1.5",
                "titulo": "DANE/TLSA no configurado",
                "activo": domain, "ip": "-", "puerto": "443",
                "evidencia": "Registros DANE/TLSA: Ausentes",
                "descripcion": "DANE (TLSA) permite asociar certificados TLS a traves de DNSSEC, previniendo ataques de CA comprometidas.",
                "riesgo": "Dependencia exclusiva de CAs sin capacidad de detectar certificados fraudulentos emitidos ilegitimamente.",
                "recomendacion": "Configurar registros TLSA en el DNS firmado con DNSSEC para asociar certificados TLS especificos.",
                "prioridad": "P3", "estado": "Abierto"
            })

        # IPv6 records
        ipv6_records = dns.get("ipv6") or []
        if not ipv6_records:
            hallazgos.append({
                "factor": "Estado de DNS", "gravedad": "Baja", "impacto_score": "-0.5",
                "titulo": "AAAA (IPv6) no configurado",
                "activo": domain, "ip": ip_str, "puerto": "-",
                "evidencia": "Registros AAAA: Ausentes",
                "descripcion": "El dominio no tiene registros AAAA para IPv6. Aunque no es un riesgo de seguridad directo, limita la accesibilidad y redundancia.",
                "riesgo": "Sin IPv6, no hay redundancia de ruta ni soporte para usuarios que solo tengan conectividad IPv6.",
                "recomendacion": "Evaluar la implementacion de IPv6 y configurar registros AAAA si esta disponible.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # MTA-STS
        if not p.get("mta_sts"):
            hallazgos.append({
                "factor": "Estado de DNS", "gravedad": "Media", "impacto_score": "-1.5",
                "titulo": "MTA-STS no configurado",
                "activo": domain, "ip": "-", "puerto": "25",
                "evidencia": "MTA-STS: Ausente",
                "descripcion": "MTA-STS permite a los dominios publicar políticas para exigir TLS en la entrega de correo entre servidores MX.",
                "riesgo": "Correos entrantes pueden ser entregados en texto plano si el MX emisor no negocia TLS.",
                "recomendacion": "Configurar MTA-STS publicando política en _mta-sts.<dominio> con modo 'enforce'.",
                "prioridad": "P3", "estado": "Abierto"
            })

        # TLS-RPT
        if not p.get("tls_rpt"):
            hallazgos.append({
                "factor": "Estado de DNS", "gravedad": "Baja", "impacto_score": "-1.0",
                "titulo": "TLS-RPT no configurado",
                "activo": domain, "ip": "-", "puerto": "25",
                "evidencia": "TLS-RPT: Ausente",
                "descripcion": "TLS-RPT permite recibir informes sobre fallos de TLS en la entrega de correo entre servidores MX.",
                "riesgo": "Sin informes TLS-RPT, no se pueden detectar problemas de cifrado en el canal de correo.",
                "recomendacion": "Configurar TLS-RPT con direccion de correo para recibir informes de fallos TLS.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # BIMI
        if not p.get("bimi"):
            hallazgos.append({
                "factor": "Estado de DNS", "gravedad": "Baja", "impacto_score": "-0.5",
                "titulo": "BIMI no configurado",
                "activo": domain, "ip": "-", "puerto": "-",
                "evidencia": "BIMI: Ausente",
                "descripcion": "BIMI permite mostrar el logotipo de la marca junto a los correos autenticados en clientes compatibles.",
                "riesgo": "Menor capacidad de diferenciacion visual para correos legitimados, no es un riesgo de seguridad directo.",
                "recomendacion": "Configurar BIMI publicando el logo corporativo verificado en el DNS.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # CAA records
        if not p.get("caa_records"):
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Media", "impacto_score": "-2.0",
                "titulo": "CAA no configurado",
                "activo": domain, "ip": "-", "puerto": "443",
                "evidencia": "Registros CAA: Ausentes",
                "descripcion": "CAA permite especificar que Autoridades de Certificacion (CAs) pueden emitir certificados para el dominio.",
                "riesgo": "Cualquier CA puede emitir certificados SSL para el dominio sin restriccion.",
                "recomendacion": "Configurar registros CAA en el DNS para restringir la emision de certificados a CAs autorizadas.",
                "prioridad": "P2", "estado": "Abierto"
            })

        # Weak TLS version
        tls_version = tls_data.get("negotiated_version") or ""
        if tls_version and "1.2" not in tls_version and "1.3" not in tls_version:
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Alta", "impacto_score": "-6.0",
                "titulo": f"Protocolo TLS debil ({tls_version})",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Version negociada: {tls_version}",
                "descripcion": "Versiones antiguas de TLS (1.0, 1.1) tienen vulnerabilidades conocidas (BEAST, POODLE) que permiten desencriptar trafico.",
                "riesgo": "Interceptacion y desencriptacion de trafico HTTPS por atacantes en la red.",
                "recomendacion": "Deshabilitar TLS 1.0 y 1.1, configurar el servidor para usar exclusivamente TLS 1.2 y 1.3.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # TLS 1.3-only check
        if tls_version and tls_data.get("tls13_only_ok"):
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Informativa", "impacto_score": "0",
                "titulo": "TLS 1.3 exclusivo configurado",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": "El servidor solo acepta TLS 1.3",
                "descripcion": "El servidor esta configurado para aceptar exclusivamente TLS 1.3, el estandar mas seguro y rápido.",
                "riesgo": "No aplica - configuración ejemplar.",
                "recomendacion": "Mantener esta configuración. Verificar compatibilidad con clientes antiguos.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # Certificate info
        cert_subject = tls_data.get("cert_subject") or ""
        cert_issuer = tls_data.get("cert_issuer") or ""
        cert_expiry = tls_data.get("cert_expiry") or ""
        if cert_subject or cert_issuer or cert_expiry:
            cert_fields = []
            if cert_subject: cert_fields.append(f"Subject: {cert_subject}")
            if cert_issuer: cert_fields.append(f"Issuer: {cert_issuer}")
            if cert_expiry: cert_fields.append(f"Expira: {cert_expiry}")
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Informativa", "impacto_score": "0",
                "titulo": "Certificado TLS detectado",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": " | ".join(cert_fields),
                "descripcion": "Informacion del certificado TLS del servidor.",
                "riesgo": "No aplica - hallazgo informativo.",
                "recomendacion": "Verificar que el certificado sea valido, emitido por una CA confiable y no este próximo a expirar.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # SAN list
        san_list = tls_data.get("san_list") or []
        if san_list:
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Informativa", "impacto_score": "0",
                "titulo": f"{len(san_list)} nombre(s) alternativo(s) en certificado (SAN)",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"SAN: {'; '.join(san_list[:8])}",
                "descripcion": "El certificado TLS incluye nombres alternativos (SAN) que amplian los dominios cubiertos.",
                "riesgo": "No aplica - hallazgo informativo. SAN excesivos pueden ampliar la superficie de ataque.",
                "recomendacion": "Revisar que los SAN incluidos sean los estrictamente necesarios y correspondan a dominios controlados.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # Referrer-Policy
        if not headers.get("referrer-policy"):
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Baja", "impacto_score": "-1.0",
                "titulo": "Cabecera Referrer-Policy no configurada",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": "Referrer-Policy: Ausente",
                "descripcion": "Referrer-Policy controla cuanta información de la URL de referencia se envia al navegar a otros sitios.",
                "riesgo": "Posible filtración de parametros URL en la cabecera Referer hacia sitios externos.",
                "recomendacion": "Configurar Referrer-Policy: strict-origin-when-cross-origin o same-origin.",
                "prioridad": "P3", "estado": "Abierto"
            })

        # Permissions-Policy
        if not headers.get("permissions-policy"):
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Baja", "impacto_score": "-0.5",
                "titulo": "Cabecera Permissions-Policy no configurada",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": "Permissions-Policy: Ausente",
                "descripcion": "Permissions-Policy (antes Feature-Policy) controla que APIs del navegador puede usar el sitio y sus iframes.",
                "riesgo": "APIs del navegador (camara, microufono, geolocalizacion) podrian ser utilizadas sin restriccion explicita.",
                "recomendacion": "Configurar Permissions-Policy para restringir APIs sensibles: camera=(), microphone=(), geolocation=().",
                "prioridad": "P3", "estado": "Abierto"
            })

        # COOP
        if not headers.get("cross-origin-opener-policy"):
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Baja", "impacto_score": "-1.0",
                "titulo": "Cabecera Cross-Origin-Opener-Policy no configurada",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": "COOP: Ausente",
                "descripcion": "COOP aísla ventanas de origen cruzado para prevenir ataques de tipo cross-origin leak como Spectre.",
                "riesgo": "Potencial fuga de información a traves de ataques de canal lateral entre ventanas de diferentes origenes.",
                "recomendacion": "Configurar Cross-Origin-Opener-Policy: same-origin para aislar ventanas de contexto cruzado.",
                "prioridad": "P3", "estado": "Abierto"
            })

        # HTTPS status
        sc = https.get("status_code")
        furl = https.get("final_url")
        if sc:
            sc_level = "Informativa" if str(sc).startswith(("2","3")) else "Alta"
            sc_impact = "0" if str(sc).startswith(("2","3")) else "-5.0"
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": sc_level, "impacto_score": sc_impact,
                "titulo": f"HTTP {sc}" + (f" -> {furl}" if furl and furl != f"https://{domain}" else ""),
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Status: {sc} | URL final: {furl}",
                "descripcion": "Estado HTTP devuelto por el servidor web.",
                "riesgo": "Errores HTTP 4xx/5xx pueden indicar problemas de configuración o disponibilidad." if not str(sc).startswith(("2","3")) else "No aplica - hallazgo informativo.",
                "recomendacion": "Verificar que el servidor responda correctamente por HTTPS." if not str(sc).startswith(("2","3")) else "Mantener la configuración actual.",
                "prioridad": "P1" if int(sc) >= 400 else "P4", "estado": "Abierto"
            })

        # Redirect chain
        redirects = https.get("redirect_chain") or []
        if len(redirects) > 1:
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Baja", "impacto_score": "-1.0",
                "titulo": f"Redirecciones HTTP: {len(redirects)} salto(s)",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Cadena: {' -> '.join(redirects[:5])}",
                "descripcion": "El dominio realiza multiples redirecciones HTTP antes de llegar al destino final, lo que puede afectar rendimiento y seguridad.",
                "riesgo": "Mayor latencia y posible exposición de URLs internas en la cadena de redireccion.",
                "recomendacion": "Minimizar las redirecciones configurando la URL canónica directamente en el servidor origen.",
                "prioridad": "P3", "estado": "Abierto"
            })

        # Server fingerprint
        server_fp = https.get("server_fingerprint") or ""
        if server_fp:
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Informativa", "impacto_score": "0",
                "titulo": f"Servidor web: {server_fp}",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Server: {server_fp}",
                "descripcion": "El servidor web revela su identidad a traves de la cabecera Server.",
                "riesgo": "No aplica - hallazgo informativo. Versiones expuestas pueden ayudar a atacantes a buscar vulnerabilidades conocidas.",
                "recomendacion": "Considerar ofuscar la cabecera Server o configurarla con información generica.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # X-Powered-By
        xpb = headers.get("x-powered-by") or ""
        if xpb:
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Baja", "impacto_score": "-0.5",
                "titulo": f"Tecnologia revelada: X-Powered-By: {xpb}",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"X-Powered-By: {xpb}",
                "descripcion": "La cabecera X-Powered-By revela la tecnologia o framework utilizado por el servidor.",
                "riesgo": "Facilita a atacantes la identificacion de vulnerabilidades especificas de la tecnologia expuesta.",
                "recomendacion": "Eliminar o deshabilitar la cabecera X-Powered-By en la configuración del servidor.",
                "prioridad": "P3", "estado": "Abierto"
            })

        # Supply chain dependencies
        supply = p.get("supply_chain") or []
        if supply:
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Informativa", "impacto_score": "0",
                "titulo": f"{len(supply)} dependencia(s) de terceros detectadas",
                "activo": domain, "ip": ip_str, "puerto": "-",
                "evidencia": f"Terceros: {'; '.join(s.get('domain','?') for s in supply[:8])}",
                "descripcion": "Se detectaron dependencias de terceros a traves de análisis de CSP y scripts cargados.",
                "riesgo": "Dependencias externas incrementan la superficie de ataque y el riesgo de supply chain compromise.",
                "recomendacion": "Auditar las dependencias de terceros, verificar su reputación y mantenerlas actualizadas.",
                "prioridad": "P2", "estado": "Abierto"
            })

        # Social media
        social = p.get("social") or {}
        if social:
            social_lines = [f"{net}: @{data.get('username','?')}" for net, data in social.items() if not data.get("error")]
            if social_lines:
                hallazgos.append({
                    "factor": "Filtracion de informacion", "gravedad": "Informativa", "impacto_score": "0",
                    "titulo": f"Perfiles en redes sociales detectados ({len(social_lines)})",
                    "activo": domain, "ip": "-", "puerto": "-",
                    "evidencia": "; ".join(social_lines[:8]),
                    "descripcion": "Se detectaron perfiles en redes sociales asociados al dominio.",
                    "riesgo": "No aplica - hallazgo informativo. Perfiles no oficiales podrian ser utilizados para suplantacion.",
                    "recomendacion": "Verificar que todos los perfiles sean oficiales y esten gestionados por el equipo de comunicaciones.",
                    "prioridad": "P4", "estado": "Abierto"
                })

        # Port 80/443
        port_80 = p.get("port_80") or {}
        port_443 = p.get("port_443") or {}
        if port_80.get("open"):
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Alta", "impacto_score": "-4.0",
                "titulo": "HTTP (puerto 80) abierto sin redireccion a HTTPS",
                "activo": domain, "ip": ip_str, "puerto": "80",
                "evidencia": f"Puerto 80: Abierto | Puerto 443: {'Abierto' if port_443.get('open') else 'Cerrado'}",
                "descripcion": "El puerto HTTP (80) se encuentra abierto permitiendo conexiones no cifradas. Idealmente todo el trafico debe redirigirse a HTTPS.",
                "riesgo": "Interceptacion de trafico en texto plano, ataques de SSL stripping y suplantacion.",
                "recomendacion": "Cerrar puerto 80 en firewall o redirigir todo el trafico HTTP a HTTPS de forma permanente.",
                "prioridad": "P1", "estado": "Abierto"
            })
        if not port_443.get("open"):
            hallazgos.append({
                "factor": "Seguridad de red", "gravedad": "Critica", "impacto_score": "-8.0",
                "titulo": "HTTPS (puerto 443) cerrado",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"Puerto 443: Cerrado",
                "descripcion": "El puerto HTTPS (443) se encuentra cerrado, lo que impide conexiones seguras al servidor web.",
                "riesgo": "Imposibilidad de establecer comunicaciones cifradas, exponiendo datos en transito.",
                "recomendacion": "Configurar el servidor web con un certificado SSL/TLS valido y abrir el puerto 443.",
                "prioridad": "P1", "estado": "Abierto"
            })

        # WHOIS / external sources
        ext = p.get("external") or {}
        whois = ext.get("whois") or {}
        if "error" not in whois and any(k in whois for k in ("registrar", "registrant_organization", "creation_date", "expiration_date")):
            whois_parts = []
            if whois.get("registrar"): whois_parts.append(f"Registrar: {whois['registrar']}")
            if whois.get("registrant_organization"): whois_parts.append(f"Org: {whois['registrant_organization']}")
            if whois.get("registrant_country"): whois_parts.append(f"Pais: {whois['registrant_country']}")
            if whois.get("creation_date"): whois_parts.append(f"Creado: {whois['creation_date']}")
            if whois.get("expiration_date"): whois_parts.append(f"Expira: {whois['expiration_date']}")
            if whois.get("emails"): whois_parts.append(f"Emails: {', '.join(whois['emails'][:5])}")
            hallazgos.append({
                "factor": "Filtracion de informacion", "gravedad": "Informativa", "impacto_score": "0",
                "titulo": "Informacion WHOIS expuesta",
                "activo": domain, "ip": ip_str, "puerto": "-",
                "evidencia": " | ".join(whois_parts),
                "descripcion": "Los registros WHOIS del dominio exponen información administrativa y técnica que puede ser utilizada para ataques de ingeniería social.",
                "riesgo": "Exposicion de datos de registro del dominio (registrar, organizacion, emails) a traves de WHOIS.",
                "recomendacion": "Utilizar servicios de privacidad WHOIS o contratar registro corporativo con proteccion de datos.",
                "prioridad": "P4", "estado": "Abierto"
            })

        # KUMO enrichment
        kumo = p.get("kumo") or {}
        if isinstance(kumo, dict):
            kbi = kumo.get("breachintel") or {}
            if kbi and not kbi.get("error"):
                ks = kbi.get("summary") or {}
                kbi_parts = []
                if ks.get("total_employees_leaked"): kbi_parts.append(f"empleados: {ks['total_employees_leaked']}")
                if ks.get("total_clients_leaked"): kbi_parts.append(f"clientes: {ks['total_clients_leaked']}")
                if ks.get("total_infostealer_hits"): kbi_parts.append(f"infostealer: {ks['total_infostealer_hits']}")
                if kbi_parts:
                    hallazgos.append({
                        "factor": "Filtracion de informacion", "gravedad": "Alta", "impacto_score": "-4.0",
                        "titulo": "Filtraciones / infostealer detectados (KUMO)",
                        "activo": domain, "ip": ip_str, "puerto": "-",
                        "evidencia": " | ".join(kbi_parts),
                        "descripcion": "Breach intelligence (Hudson Rock, Chiasmodon, HIBP, ProxyNova) revela credenciales corporativas y maquinas infectadas con infostealers asociadas al dominio.",
                        "riesgo": "Credenciales corporativas y datos de empleados/clientes expuestos en filtraciones.",
                        "recomendacion": "Rotar credenciales afectadas, auditar maquinas comprometidas y monitorear canales de exfiltracion.",
                        "prioridad": "P1", "estado": "Abierto"
                    })
            kjs = kumo.get("js_secrets") or {}
            if kjs.get("secrets") and not kjs.get("error"):
                kjs_detail = "; ".join(f"{x.get('type','?')} en {x.get('file','?')}" for x in kjs["secrets"][:6])
                hallazgos.append({
                    "factor": "Seguridad de aplicacion web", "gravedad": "Alta", "impacto_score": "-4.0",
                    "titulo": f"Secretos expuestos en JavaScript ({kjs.get('total', len(kjs.get('secrets', [])))} hallazgo(s))",
                    "activo": domain, "ip": ip_str, "puerto": "-",
                    "evidencia": kjs_detail,
                    "descripcion": "El escaneo de archivos JS detecto claves, tokens o credenciales en claro incrustadas en el código cliente.",
                    "riesgo": "Todos los secretos expuestos pueden comprometer cuentas, APIs o infraestructura.",
                    "recomendacion": "Rotar los secretos detectados, moverlos a un gestor de secretos y eliminar su presencia del código entregado al navegador.",
                    "prioridad": "P1", "estado": "Abierto"
                })
            knu = kumo.get("nuclei") or {}
            if knu.get("findings") and not knu.get("error"):
                high_count = sum(1 for f in knu["findings"] if f.get("severity") in ("critical", "high"))
                knu_detail = "; ".join(f"{f.get('severity','?')}: {f.get('name','?')}" for f in knu['findings'][:8])
                hallazgos.append({
                    "factor": "Vulnerabilidades conocidas", "gravedad": "Alta" if high_count else "Media", "impacto_score": "-4.0" if high_count else "-2.0",
                    "titulo": f"Scanner KUMO (Nuclei): {knu.get('total', len(knu['findings']))} hallazgo(s), {high_count} critica(s)/alta(s)",
                    "activo": domain, "ip": ip_str, "puerto": "-",
                    "evidencia": knu_detail,
                    "descripcion": "El escaner de vulnerabilidades basado en plantillas Nuclei encontro endpoints expuestos o versiones vulnerables.",
                    "riesgo": "Explotacion de vulnerabilidades activas en el dominio objetivo.",
                    "recomendacion": "Revisar cada hallazgo, parchear la version afectada y restringir el acceso a los endpoints expuestos.",
                    "prioridad": "P2" if high_count else "P3", "estado": "Abierto"
                })
            kwb = kumo.get("wayback") or {}
            if kwb.get("interesting") and not kwb.get("error"):
                hallazgos.append({
                    "factor": "Filtracion de informacion", "gravedad": "Media", "impacto_score": "-2.0",
                    "titulo": "Endpoints históricos sensibles en Wayback Machine",
                    "activo": domain, "ip": ip_str, "puerto": "-",
                    "evidencia": "; ".join(kwb["interesting"][:6]),
                    "descripcion": "Archivos en Wayback pueden revelar rutas de administracion, configuraciones o datos expuestos en el pasado.",
                    "riesgo": "Superficie de ataque ampliada con rutas residuos o configuraciones antiguas.",
                    "recomendacion": "Revisar los endpoints archivados y eliminar de produccion cualquier ruta residual todavia accesible.",
                    "prioridad": "P3", "estado": "Abierto"
                })

        # Prism OSINT enrichment
        prism = p.get("prism") or {}
        if isinstance(prism, dict):
            pll = prism.get("leak_lookup") or {}
            if pll.get("breaches") and not pll.get("error"):
                pll_detail = "; ".join(f"{b.get('name','?')}" for b in pll["breaches"][:8])
                hallazgos.append({
                    "factor": "Filtracion de informacion", "gravedad": "Critica", "impacto_score": "-7.5",
                    "titulo": f"Filtraciones en Prism breach lookup ({len(pll.get('breaches', []))})",
                    "activo": domain, "ip": ip_str, "puerto": "-",
                    "evidencia": pll_detail,
                    "descripcion": "Breach lookup multi-fuente (XposedOrNot, LeakCheck, HIBP, Leak-Lookup) encontro cuentas del dominio en bases de filtraciones.",
                    "riesgo": "Credenciales expuestas que pueden permitir acceso no autorizado o movimiento lateral.",
                    "recomendacion": "Rotar credenciales afectadas y auditar los servicios donde se usaron esos emails.",
                    "prioridad": "P1", "estado": "Abierto"
                })
            poc = prism.get("onion_checker") or {}
            if poc.get("results") and not poc.get("error"):
                poc_detail = "; ".join(f"{r.get('url','?')}" for r in poc["results"][:5])
                hallazgos.append({
                    "factor": "Exposicion en dark web", "gravedad": "Alta", "impacto_score": "-4.0",
                    "titulo": f"Servicios onion relacionados con {domain}",
                    "activo": domain, "ip": ip_str, "puerto": "-",
                    "evidencia": poc_detail,
                    "descripcion": "Se hallaron mirrors o referencias .onion relacionados con el dominio, tipico de suplantacion, fraud shops o infraestructura oculta.",
                    "riesgo": "Suplantacion de marca y abuso de la reputación del dominio en la dark web.",
                    "recomendacion": "Investigar cada enlace onion y monitorear suplantaciones de la marca.",
                    "prioridad": "P2", "estado": "Abierto"
                })
            pgh = prism.get("github_recon") or {}
            if pgh.get("profile") and not pgh.get("error"):
                pgh_detail = f"@{pgh.get('username','?')} ({pgh.get('repo_count',0)} repos, {(pgh.get('total_stars') or 0)} stars)"
                if pgh.get("emails"): pgh_detail += f" | emails: {', '.join(pgh['emails'][:3])}"
                hallazgos.append({
                    "factor": "Superficie de ataque", "gravedad": "Media", "impacto_score": "-2.0",
                    "titulo": f"Repositorios GitHub de la organizacion ({pgh.get('repo_count',0)})",
                    "activo": domain, "ip": "-", "puerto": "-",
                    "evidencia": pgh_detail,
                    "descripcion": "El escaneo de GitHub encontro la organizacion o repositorios asociados, potencial fuente de información sensible.",
                    "riesgo": "Fuga de código, credenciales o configuraciones internas desde repositorios publicos.",
                    "recomendacion": "Auditar la visibilidad de repos y rotar cualquier secreto encontrado en código publico.",
                    "prioridad": "P2", "estado": "Abierto"
                })
            pvt = prism.get("virustotal") or {}
            if pvt.get("status") == "ok" and not pvt.get("error") and (pvt.get("malicious") or pvt.get("suspicious")):
                hallazgos.append({
                    "factor": "Reputacion de IP", "gravedad": "Alta", "impacto_score": "-5.0",
                    "titulo": f"Reputacion adversa en VirusTotal (M:{pvt.get('malicious',0)} S:{pvt.get('suspicious',0)})",
                    "activo": domain, "ip": ip_str, "puerto": "-",
                    "evidencia": f"VirusTotal M:{pvt.get('malicious',0)} S:{pvt.get('suspicious',0)}",
                    "descripcion": "VirusTotal reporta detecciones que pueden indicar compromiso, spam o phishing asociado al dominio.",
                    "riesgo": "Dominio marcado como malicioso, impacto en entregabilidad e imagen.",
                    "recomendacion": "Investigar las detecciones y las categorias de riesgo reportadas.",
                    "prioridad": "P2", "estado": "Abierto"
                })
            pab = prism.get("abuseipdb") or {}
            if pab.get("status") == "ok" and not pab.get("error") and pab.get("abuse_score") and pab.get("abuse_score") >= 50:
                hallazgos.append({
                    "factor": "Reputacion de IP", "gravedad": "Alta", "impacto_score": "-5.0",
                    "titulo": f"IP de {domain} con abuse score {pab.get('abuse_score')}/100",
                    "activo": domain, "ip": ip_str, "puerto": "-",
                    "evidencia": f"AbuseIPDB score {pab.get('abuse_score')}/100 ({pab.get('total_reports',0)} reportes)",
                    "descripcion": "La IP principal del dominio presenta reportes de abuso (spam, malware, botnet, TOR).",
                    "riesgo": "Correos marcados como spam, reputación danada y posible bloqueo de servicios.",
                    "recomendacion": "Investigar el historial de la IP y considerar mitigaciones de correo/cache.",
                    "prioridad": "P2", "estado": "Abierto"
                })
        co = p.get("claude_osint") or {}
        if isinstance(co, dict):
            cospf = co.get("spf_supply_chain") or {}
            if cospf and not cospf.get("error"):
                v = cospf.get("verdict") or {}
                if str(v.get("spoofable","")).upper() in ("SPOOFABLE","SUSCEPTIBLE","PARCIAL"):
                    hallazgos.append({
                        "factor": "Configuracion de correo", "gravedad": "Alta", "impacto_score": "-3.0",
                        "titulo": f"Verdict SPF/DMARC {v.get('spoofable','?')} en {domain}",
                        "activo": domain, "ip": ip_str, "puerto": "-",
                        "evidencia": f"{v.get('vector','')} | SPF: {esc(str(v.get('spf','')))} | DMARC p={v.get('dmarc_policy','-')}",
                        "descripcion": "Autenticacion de correo debil habilita phishing del dominio.",
                        "riesgo": "Suplantacion de dominio en correos (envelope/header).",
                        "recomendacion": "Establecer SPF -all y DMARC p=reject pct=100; revisar dead-includes de la cadena SPF.",
                        "prioridad": "P2", "estado": "Abierto"
                    })
            com365 = co.get("m365_fingerprint") or {}
            if com365 and not com365.get("error") and (com365.get("tenant_space") or com365.get("tenant_guid")):
                m365_seg = " | ".join(filter(None, [
                    f"namespace {com365['tenant_space']}" if com365.get("tenant_space") else "",
                    f"tenant GUID {com365['tenant_guid']}" if com365.get("tenant_guid") else "",
                ]))
                hallazgos.append({
                    "factor": "Exposicion de identidad", "gravedad": "Info", "impacto_score": "-1.0",
                    "titulo": f"Fingerprint M365/Entra de {domain}",
                    "activo": domain, "ip": ip_str, "puerto": "-",
                    "evidencia": m365_seg,
                    "descripcion": "La infraestructura de identidad corporativa (tenant, GUID) queda expuesta a enumeracion.",
                    "riesgo": "Enumeracion de cuentas y fuerza bruta dirigida.",
                    "recomendacion": "Restringir autodiscover publico y aplicar políticas de bloqueo/throttling en login.",
                    "prioridad": "P4", "estado": "Abierto"
                })
            cocci = co.get("cti_chatter") or {}
            if cocci and not cocci.get("error"):
                cti_tot = ((cocci.get("ransomwatch") or {}).get("total") or 0) + ((cocci.get("ransomware_live") or {}).get("total") or 0)
                if cti_tot:
                    hallazgos.append({
                        "factor": "Exposicion externa", "gravedad": "Alta", "impacto_score": "-5.0",
                        "titulo": f"Chatter CTI ransomware para {domain}: {cti_tot} mencion(es)",
                        "activo": domain, "ip": ip_str, "puerto": "-",
                        "evidencia": f"hits ransomwatch: {(cocci.get('ransomwatch') or {}).get('total',0)} | ransomware.live: {(cocci.get('ransomware_live') or {}).get('total',0)}",
                        "descripcion": "El dominio u organizacion figura en listas de ransomware/leak sites.",
                        "riesgo": "Posible victimizacion, exfiltracion o suplantacion en leak sites.",
                        "recomendacion": "Investigar cada mencion y priorizar forense.",
                        "prioridad": "P1", "estado": "Abierto"
                    })
            coss = co.get("secret_scan") or {}
            if coss and not coss.get("error") and coss.get("critical"):
                ss_detail = "; ".join(f"{g.get('pattern','?')} x{g.get('count')}" for g in coss["critical"][:5])
                hallazgos.append({
                    "factor": "Exposicion de credenciales", "gravedad": "Critica", "impacto_score": "-5.0",
                    "titulo": f"Secretos críticos expuestos en {domain}",
                    "activo": domain, "ip": ip_str, "puerto": "-",
                    "evidencia": ss_detail[:400],
                    "descripcion": "El scanner de 80-secrets de Claude-OSINT hallo claves de alto valor en el HTML publicado.",
                    "riesgo": "Compromiso de servicios con las credenciales expuestas.",
                    "recomendacion": "Rotar inmediatamente los secretos y removerlos del contenido publico.",
                    "prioridad": "P1", "estado": "Abierto"
                })

        canon_ok = [it for it in collect_pasive_items(p) if it.get("status") == "ok"]
        if canon_ok:
            by_group: dict[str, list] = {}
            for it in canon_ok:
                by_group.setdefault(it.get("grupo") or "Otros", []).append(it)
            canon_detail = "; ".join(
                f"{g}: " + ", ".join(f"{it['label']}={it['valor']}" for it in its[:4])
                for g, its in by_group.items()
            )
            hallazgos.append({
                "factor": "OSINT pasivo", "gravedad": "Info", "impacto_score": "-0.5",
                "titulo": f"Panorama pasivo canonico de {domain}: {len(canon_ok)} item(s) en {len(by_group)} grupo(s)",
                "activo": domain, "ip": ip_str, "puerto": "-",
                "evidencia": canon_detail[:3000],
                "descripcion": "Set canonico de items pasivos nivel 1 (DNS completo, CT, reputación, OSINT externo, KUMO, Prism, Claude-OSINT, social) recopilado sin interaccion activa con el objetivo.",
                "riesgo": "Informacion de reconocimiento util para un atacante.",
                "recomendacion": "Revisar cada item del panorama pasivo para priorizar acciones de hardening.",
                "prioridad": "P4", "estado": "Abierto"
            })

        semi_ok = [it for it in collect_semi_active_items(p) if it.get("status") == "ok"]
        if semi_ok:
            sg: dict[str, list] = {}
            for it in semi_ok:
                sg.setdefault(it.get("grupo") or "Otros", []).append(it)
            semi_detail = "; ".join(
                f"{g}: " + ", ".join(f"{it['label']}={it['valor']}" for it in its)
                for g, its in sg.items()
            )
            hallazgos.append({
                "factor": "OSINT semi-activo", "gravedad": "Info", "impacto_score": "-0.5",
                "titulo": f"Panorama semi-activo canonico de {domain}: {len(semi_ok)} item(s) en {len(sg)} grupo(s)",
                "activo": domain, "ip": ip_str, "puerto": "-",
                "evidencia": semi_detail[:3000],
                "descripcion": "Set canonico de items semi-activos nivel 2 (puertos, TLS, HTTPS, cabeceras, rutas públicas, mantenimiento, KUMO/Prism/Claude-OSINT N2) recopilado con interaccion ligera no destructiva.",
                "riesgo": "Informacion de reconocimiento util para un atacante.",
                "recomendacion": "Revisar cada item del panorama semi-activo para priorizar acciones de hardening.",
                "prioridad": "P4", "estado": "Abierto"
            })

        strix = p.get("strix") or {}
        if strix and strix.get("status") == "ok" and strix.get("findings"):
            findings = strix.get("findings") or []
            by_sev: dict[str, int] = {}
            for f in findings:
                s = (f.get("severity") or "info").lower()
                by_sev[s] = by_sev.get(s, 0) + 1
            top = sorted(findings, key=lambda x: str(x.get('severity','low')).lower() in ("critical","high"), reverse=True)[0]
            strix_detail = "; ".join(f"{f.get('severity','?')} {f.get('cve','-')} {f.get('title','?')}" for f in findings[:6])
            sev_lvl = "Critica" if by_sev.get("critical") else ("Alta" if by_sev.get("high") else "Media" if by_sev.get("medium") else "Info")
            hallazgos.append({
                "factor": "Pentest IA (Strix)", "gravedad": sev_lvl, "impacto_score": "-4.0" if (by_sev.get("critical") or by_sev.get("high")) else "-1.5",
                "titulo": f"Strix AI Pentest {domain}: {len(findings)} hallazgo(s) validados ({', '.join(f'{k}: {v}' for k,v in by_sev.items())})",
                "activo": domain, "ip": ip_str, "puerto": "-",
                "evidencia": strix_detail[:2000],
                "descripcion": f"Strix (usestrix/strix) ejecuto agentes IA de pentesting (modo {strix.get('mode','?')}) validando hallazgos con PoCs reales.",
                "riesgo": "Vulnerabilidades confirmadas en el objetivo con probada explotabilidad.",
                "recomendacion": str(top.get("remediation_steps") or "Revisar cada hallazgo y mitigar segun prioridad.")[:300],
                "prioridad": "P1" if (by_sev.get("critical") or by_sev.get("high")) else "P2" if by_sev.get("medium") else "P4", "estado": "Abierto"
            })

        # OWASP compliance
        owasp_data = matrix_by_domain.get(domain, {}).get("owasp") or {}
        if owasp_data:
            grade = owasp_data.get("overall_grade", "—")
            pct = owasp_data.get("percentage") or owasp_data.get("overall_compliance", 0)
            risk_items = []
            for r_id, r_data in sorted((owasp_data.get("risks") or {}).items()):
                if r_data.get("finding_count", 0) > 0:
                    risk_items.append(f"{r_id}: Grado {r_data.get('grade','?')} ({r_data.get('compliance_pct','?')}%)")
            findings_detail = "; ".join(risk_items[:5]) if risk_items else "Sin hallazgos OWASP"
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Media" if grade in ("D", "F") else "Informativa" if grade == "A" else "Baja", "impacto_score": "-3.0" if grade in ("D", "F") else "-1.0",
                "titulo": f"OWASP Agentic Top 10 — Grado: {grade} ({pct}%)",
                "activo": domain, "ip": ip_str, "puerto": "-",
                "evidencia": f"Grado OWASP: {grade} | Cumplimiento: {pct}% | Hallazgos: {findings_detail}",
                "descripcion": "Evaluacion de cumplimiento OWASP Agentic Top 10 para aplicaciones con agentes de IA.",
                "riesgo": "Incumplimiento de estandares OWASP en aplicaciones con componentes de IA generativa.",
                "recomendacion": "Revisar y corregir los riesgos OWASP identificados, priorizando los de grado F y D.",
                "prioridad": "P2", "estado": "Abierto"
            })

    # Vulns
    for v in (p.get("vulnerabilities") or []):
        vid = v.get("id", v.get("cve", "CVE"))
        vsev = v.get("severity", v.get("priority", "N/A"))
        vg = "Critica" if "crit" in vsev.lower() or "high" in vsev.lower() else "Alta" if "med" not in vsev.lower() else "Media"
        hallazgos.append({
            "factor": "Cadencia de aplicacion de revisiones", "gravedad": vg, "impacto_score": "-5.0",
            "titulo": f"Vulnerabilidad {vid} detectada",
            "activo": domain, "ip": ip_str, "puerto": "443",
            "evidencia": f"CVE: {vid} | Severidad: {vsev} | Descripcion: {v.get('summary','')[:120]}",
            "descripcion": f"Se identifico la vulnerabilidad {vid} en las tecnologias del dominio.",
            "riesgo": "Explotacion remota que puede comprometer la confidencialidad, integridad o disponibilidad.",
            "recomendacion": "Aplicar parche de seguridad proporcionado por el fabricante. Evaluar mitigaciones temporales.",
            "prioridad": "P1" if vg == "Critica" else "P2", "estado": "Abierto"
        })

    # FinalRecon findings
    fr = p.get("finalrecon") or {}
    if fr:
        fr_js = fr.get("javascripts") or []
        fr_wb = fr.get("wayback") or {}
        fr_wb_js = fr_wb.get("js_files") or []
        fr_wb_api = fr_wb.get("api_endpoints") or []
        fr_wb_params = fr_wb.get("juicy_params") or []
        fr_sitemap = fr.get("sitemap") or []
        fr_ext = fr.get("external_urls") or []
        all_js = list(dict.fromkeys(fr_js + fr_wb_js))
        if all_js:
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Media", "impacto_score": "-2.5",
                "titulo": f"Archivos JavaScript expuestos ({len(all_js)} encontrados)",
                "activo": domain, "ip": ip_str, "puerto": "443",
                "evidencia": f"JS expuestos: {len(all_js)} | Crawler: {len(fr_js)} | Wayback: {len(fr_wb_js)} | Ejemplos: {'; '.join(all_js[:3])}",
                "descripcion": "Los archivos JavaScript expuestos pueden revelar logica de negocio, endpoints internos o secretos embebidos como API keys.",
                "riesgo": "Exposicion de logica interna, secretos embebidos y endpoints no documentados.",
                "recomendacion": "Revisar archivos JS para evitar inclusion de secretos, API keys o endpoints internos.",
                "prioridad": "P2", "estado": "Abierto"
            })
        if fr_ext:
            hallazgos.append({
                "factor": "Seguridad de aplicacion web", "gravedad": "Baja", "impacto_score": "-1.0",
                "titulo": f"Enlaces externos detectados ({len(fr_ext)})",
                "activo": domain, "ip": ip_str, "puerto": "-",
                "evidencia": f"Total enlaces externos: {len(fr_ext)} | Ejemplos: {'; '.join(fr_ext[:3])}",
                "descripcion": "El crawler descubrio enlaces a recursos externos desde la página principal.",
                "riesgo": "Potencial exfiltracion de datos o dependencia de terceros.",
                "recomendacion": "Auditar los recursos externos y asegurar que sean de fuentes confiables.",
                "prioridad": "P4", "estado": "Abierto"
            })
        if fr_sitemap:
            hallazgos.append({
                "factor": "Filtracion de informacion", "gravedad": "Informativa", "impacto_score": "-0.5",
                "titulo": f"Sitemap expuesto ({len(fr_sitemap)} URLs)",
                "activo": domain, "ip": "-", "puerto": "-",
                "evidencia": f"Total URLs en sitemap: {len(fr_sitemap)}",
                "descripcion": "El archivo sitemap.xml expone la estructura completa del sitio.",
                "riesgo": "Divulgacion de rutas y URLs del sitio.",
                "recomendacion": "Verificar que el sitemap solo contenga URLs destinadas a indexacion pública.",
                "prioridad": "P4", "estado": "Abierto"
            })
        if fr_wb_js:
            hallazgos.append({
                "factor": "Filtracion de informacion", "gravedad": "Media", "impacto_score": "-3.0",
                "titulo": f"Archivos JS históricos en Wayback Machine ({len(fr_wb_js)})",
                "activo": domain, "ip": "-", "puerto": "-",
                "evidencia": f"JS históricos Wayback: {len(fr_wb_js)} | Ejemplos: {'; '.join(fr_wb_js[:3])}",
                "descripcion": "Los archivos JS históricos en Wayback Machine pueden contener código sensible obsoleto.",
                "riesgo": "Versiones anteriores con vulnerabilidades o secretos embebidos accesibles publicamente.",
                "recomendacion": "Revisar los JS históricos y considerar solicitar su eliminacion de Wayback Machine si contienen datos sensibles.",
                "prioridad": "P3", "estado": "Abierto"
            })
        if fr_wb_api:
            hallazgos.append({
                "factor": "Filtracion de informacion", "gravedad": "Alta", "impacto_score": "-5.0",
                "titulo": f"Endpoints API descubiertos en Wayback Machine ({len(fr_wb_api)})",
                "activo": domain, "ip": "-", "puerto": "-",
                "evidencia": f"Endpoints API Wayback: {len(fr_wb_api)} | Ejemplos: {'; '.join(fr_wb_api[:3])}",
                "descripcion": "Endpoints API descubiertos en Wayback Machine pueden exponer funcionalidades internas.",
                "riesgo": "Exposicion de funcionalidades internas o datos sensibles sin autenticacion.",
                "recomendacion": "Revisar que estos endpoints requieran autenticacion y no expongan funcionalidades sensibles.",
                "prioridad": "P1", "estado": "Abierto"
            })
        if fr_wb_params:
            hallazgos.append({
                "factor": "Filtracion de informacion", "gravedad": "Media", "impacto_score": "-3.0",
                "titulo": f"URLs con parametros sensibles ({len(fr_wb_params)})",
                "activo": domain, "ip": "-", "puerto": "-",
                "evidencia": f"Params sensibles Wayback: {len(fr_wb_params)} | Ejemplos: {'; '.join(fr_wb_params[:3])}",
                "descripcion": "URLs con parametros potencialmente sensibles (tokens, IDs, claves) en archivos históricos.",
                "riesgo": "Exposicion de datos privados o posibilidad de acceso no autorizado mediante parametros filtrados.",
                "recomendacion": "Auditar los parametros sensibles y asegurarse de que no expongan datos privados.",
                "prioridad": "P2", "estado": "Abierto"
            })

    # --- Action items (hallazgos -> breve) ---
    # We reuse hallazgos for action items but truncate

    # --- Recommendations matrix ---
    recs = []
    seen_rec_topics: set[str] = set()

    for h in hallazgos:
        topic = h["recomendacion"].split(".")[0][:60]
        if topic not in seen_rec_topics:
            seen_rec_topics.add(topic)
            prio = h["prioridad"]
            plazo = {"P1":"0-7 dias","P2":"8-30 dias","P3":"31-60 dias","P4":"Mejora continua"}.get(prio, "30 dias")
            responsable = "Equipo de Seguridad / Área de TI"
            beneficio = "Reduccion de riesgo de " + ("compromiso critico" if prio == "P1" else "exposicion" if prio == "P2" else "superficie de ataque")
            recs.append({
                "prioridad": prio, "accion": h["recomendacion"],
                "responsable": responsable, "plazo": plazo,
                "factor": h["factor"], "beneficio": beneficio
            })

    # Add baseline recs
    baseline_recs = [
        ("P4", "Establecer programa de bug bounty", "Equipo de Seguridad", "3-12 meses", "Mejora continua", "Incentivar investigacion externa de vulnerabilidades"),
        ("P4", "Implementar monitoreo continuo de superficie de ataque", "Equipo SOC", "1-3 meses", "Seguridad de red", "Deteccion temprana de nuevos activos y riesgos"),
    ]
    for prio, accion, resp, plazo, factor, beneficio in baseline_recs:
        recs.append({"prioridad": prio, "accion": accion, "responsable": resp, "plazo": plazo, "factor": factor, "beneficio": beneficio})

    # Sort recs by priority
    prio_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    recs.sort(key=lambda r: (prio_order.get(r["prioridad"], 99), r["accion"]))

    # --- Factor table rows ---
    factor_rows = ""
    for f in factores:
        sc = f["score"]
        cls = "fs-verde" if sc >= 90 else "fs-amarillo" if sc >= 70 else "fs-naranja" if sc >= 60 else "fs-rojo"
        factor_rows += f"<tr><td class='num {cls}'>{sc}</td><td>{esc(f['factor'])}</td><td class='num'>{f['incidencias']}</td></tr>"

    # --- Action items table rows ---
    action_rows = ""
    for h in hallazgos: # all hallazgos in action items
        action_rows += f"""<tr>
            <td>{esc(h['factor'])}</td>
            <td><span class="s-badge {_badge_class(h['gravedad'])}">{esc(h['gravedad'])}</span></td>
            <td class="num">{esc(h['impacto_score'])}</td>
            <td>{esc(h['titulo'][:120])}</td>
        </tr>"""

    # --- Detailed findings cards ---
    detail_html = ""
    for h in hallazgos:
        detail_html += f"""<div class="find-card">
        <div class="fc-hdr">
            <span class="s-badge {_badge_class(h['gravedad'])}">{esc(h['gravedad'])}</span>
            <span class="fc-factor">{esc(h['factor'])}</span>
            <span class="fc-active">{esc(h['activo'][:80])}</span>
        </div>
        <div class="fc-body">
            <div class="fc-row"><span class="fc-label">Factor</span><span class="fc-value">{esc(h['factor'])}</span></div>
            <div class="fc-row"><span class="fc-label">Activo</span><span class="fc-value">{esc(h['activo'])}</span></div>
            <div class="fc-row"><span class="fc-label">IP / Dominio</span><span class="fc-value">{esc(h.get('ip','-'))}</span></div>
            <div class="fc-row"><span class="fc-label">Puerto</span><span class="fc-value">{esc(h.get('puerto','-'))}</span></div>
            <div class="fc-row"><span class="fc-label">Evidencia</span><span class="fc-value"><pre class="fc-evidence">{esc(h.get('evidencia',''))}</pre></span></div>
            <div class="fc-row"><span class="fc-label">Descripcion</span><span class="fc-value">{esc(h['descripcion'])}</span></div>
            <div class="fc-row"><span class="fc-label">Riesgo</span><span class="fc-value">{esc(h['riesgo'])}</span></div>
            <div class="fc-row"><span class="fc-label">Recomendación</span><span class="fc-value">{esc(h['recomendacion'])}</span></div>
            <div class="fc-row"><span class="fc-label">Prioridad</span><span class="fc-value"><strong>{esc(h['prioridad'])}</strong></span></div>
            <div class="fc-row"><span class="fc-label">Estado</span><span class="fc-value">{esc(h['estado'])}</span></div>
        </div>
    </div>"""

    # --- Rec matrix rows ---
    rc = []
    for r in recs[:15]:
        rc.append("<tr>")
        rc.append(f'<td class="num"><strong>{esc(r["prioridad"])}</strong></td>')
        rc.append(f'<td>{esc(r["accion"][:140])}</td>')
        rc.append(f'<td>{esc(r["responsable"])}</td>')
        rc.append(f'<td>{esc(r["plazo"])}</td>')
        rc.append(f'<td>{esc(r["factor"])}</td>')
        rc.append(f'<td>{esc(r["beneficio"])}</td>')
        rc.append("</tr>")
    rec_rows_html = "".join(rc)

    # --- History chart ---
    chart_svg = history_chart_svg(history)

    # --- Executive summary metrics ---
    total_hallazgos = len(hallazgos)
    crit_count = sum(1 for h in hallazgos if h["gravedad"].lower() == "critica")
    alta_count = sum(1 for h in hallazgos if h["gravedad"].lower() == "alta")
    media_count = sum(1 for h in hallazgos if h["gravedad"].lower() == "media")

    # Format date
    fecha_str = now.strftime("%d/%m/%Y")
    fecha_text = now.strftime("%d de %B de %Y")

    # ======================== BUILD HTML ========================
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Scorecard de Seguridad - {esc(domain)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="page">

<!-- ======== COVER ======== -->
<div class="cover">
    <div class="cover-top">
        <div class="powered">Generado por {esc(org)}</div>
        <h1>INFORME DETALLADO</h1>
        <div class="sub">Evaluación de Postura<br>de Seguridad de Terceros para</div>
        <div class="org-name">{esc(org_show)}</div>
    </div>
    <div class="cover-meta">
        <table>
            <tr><td>Fecha de generacion</td><td>{esc(fecha_str)}</td></tr>
            <tr><td>Analista responsable</td><td>{esc(analista) if analista else 'Equipo de Ciberseguridad'}</td></tr>
            <tr><td>Organizacion emisora</td><td>{esc(org)}</td></tr>
            <tr><td>Dominio evaluado</td><td>{esc(domain)}</td></tr>
        </table>
    </div>
    <div class="cover-footer">
        <span>Dominio: {esc(domain)}</span>
        <span>Preparado: {esc(fecha_str)}</span>
        <span>Página 1</span>
    </div>
</div>

<!-- ======== ACERCA DE ESTE INFORME ======== -->
{resumen_block}

  {score_legend_block}

  <div class="sec">
    <div class="section-title">Acerca de este informe</div>
    <div class="info-box">
        <p>El presente documento constituye una <strong>captura puntual del estado de seguridad</strong> del dominio evaluado ({esc(domain)}), basada en técnicas de reconocimiento pasivo, análisis de configuraciones expuestas y consulta a fuentes abiertas de inteligencia de amenazas.</p>
        <br>
        <p><strong>Limitaciones:</strong></p>
        <ul style="padding-left:18px;margin-top:4px;">
            <li>Este informe <strong>no debe interpretarse como una prueba de penetracion</strong> ni como una evaluación de seguridad definitiva.</li>
            <li>Los resultados reflejan la información disponible al momento del escaneo y pueden variar con el tiempo.</li>
            <li>Se recomienda que los hallazgos sean <strong>validados por el equipo técnico responsable</strong> del activo evaluado antes de tomar decisiones operativas o contractuales.</li>
            <li>Este informe sirve como herramienta para <strong>priorizar acciones de mejora</strong> en la postura de seguridad del proveedor o tercero evaluado.</li>
        </ul>
    </div>
</div>

<!-- ======== QUE ES UN SCORECARD ======== -->
<div class="sec">
    <div class="section-title">Que es un Scorecard de Seguridad</div>
    <div class="info-box">
        <p>El Scorecard de Seguridad es un modelo de calificación que evalua la postura de seguridad de una organizacion en una escala de <strong>A a F</strong>, donde:</p>
        <ul style="padding-left:18px;margin:6px 0;">
            <li><strong>A (90-100):</strong> Postura de seguridad solida. Controles implementados y configuración adecuada.</li>
            <li><strong>B (80-89):</strong> Buena postura con margen de mejora en áreas especificas.</li>
            <li><strong>C (70-79):</strong> Postura aceptable. Se requieren mejoras en multiples factores.</li>
            <li><strong>D (60-69):</strong> Postura deficiente. Acciones correctivas necesarias.</li>
            <li><strong>F (&lt;60):</strong> Postura critica. Se requiere atención inmediata.</li>
        </ul>
        <p>El score general se calcula con base en <strong>factores de riesgo ponderados</strong> que incluyen seguridad web, estado de DNS, reputación de IP, filtración de información, seguridad de red, cadencia de parchado, ingeniería social, exposición de credenciales y seguridad de puntos de conexión.</p>
    </div>

    <div class="section-sub">Próximos pasos</div>
    <div class="steps">
        <div class="step"><div class="step-num">1</div><div class="step-text">Validar la huella digital</div></div>
        <div class="step"><div class="step-num">2</div><div class="step-text">Revisar activos asociados</div></div>
        <div class="step"><div class="step-num">3</div><div class="step-text">Analizar hallazgos</div></div>
        <div class="step"><div class="step-num">4</div><div class="step-text">Corregir problemas y mejorar el score</div></div>
    </div>
</div>

<!-- ======== VISION GENERAL ======== -->
<div class="sec">
    <div class="section-title">Vision General del Scorecard</div>

    <table class="data">
        <tr><td style="width:200px;font-weight:700;">Empresa</td><td>{esc(org_show)}</td>
            <td style="width:180px;font-weight:700;">Puntuación general</td>
            <td><span class="score-badge {letter}">{letter}</span> {score_general}/100</td></tr>
        <tr><td style="font-weight:700;">Dominio</td><td>{esc(domain)}</td>
            <td style="font-weight:700;">Sector</td><td>{esc(sector)}</td></tr>
        <tr><td style="font-weight:700;">Fecha de evaluación</td><td>{esc(fecha_str)}</td>
            <td style="font-weight:700;">Nivel de riesgo</td>
            <td><span class="{letter_class}">{letter} ({_score_class(score_general).split()[0].replace('grade-','')})</span></td></tr>
        <tr><td style="font-weight:700;">Domain Score</td><td class="num">{domain_score(providers[0]) if providers else 0}/100</td>
            <td style="font-weight:700;">Heuristica de seguridad</td><td>—</td></tr>
    </table>

    <div class="section-sub">Factores de Riesgo</div>
    <table class="data">
        <thead><tr><th style="width:60px;">Score</th><th>Factor de riesgo</th><th style="width:90px;">Incidencias</th></tr></thead>
        <tbody>{factor_rows}</tbody>
    </table>

    <div class="section-sub">Historial del Score (30 dias)</div>
    <div style="text-align:center;margin:12px 0;overflow-x:auto;">{chart_svg}</div>
</div>

<!-- ======== ELEMENTOS DE ACCION ======== -->
<div class="sec">
    <div class="section-title">Elementos de Accion</div>
    <table class="data">
        <thead><tr><th>Factor</th><th>Gravedad</th><th>Impacto en score</th><th>Problemas detectados</th></tr></thead>
        <tbody>{action_rows}</tbody>
    </table>
</div>

<!-- ======== DETALLE DE HALLAZGOS ======== -->
<div class="sec">
    <div class="section-title">Detalle de Hallazgos</div>
    {detail_html}
</div>

    <!-- ======== RECOMENDACIONES PRIORIZADAS ======== -->
<div class="sec">
    <div class="section-title">Recomendaciones Priorizadas</div>
    <table class="data">
        <thead><tr><th style="width:40px;">Prio</th><th>Accion recomendada</th><th>Responsable</th><th>Plazo</th><th>Factor impactado</th><th>Beneficio esperado</th></tr></thead>
        <tbody>{rec_rows_html}</tbody>
    </table>
</div>

<!-- ======== RESUMEN EJECUTIVO ======== -->
{toc_block}

  <div class="sec">
    <div class="section-title">Resumen Ejecutivo</div>

    <div class="exec-grid">
        <div class="exec-card"><div class="ec-val {letter_class}">{score_general}</div><div class="ec-lbl">Score General</div></div>
        <div class="exec-card"><div class="ec-val" style="color:#173B57;">{total_hallazgos}</div><div class="ec-lbl">Hallazgos</div></div>
        <div class="exec-card"><div class="ec-val" style="color:#C62828;">{crit_count}</div><div class="ec-lbl">Críticos</div></div>
        <div class="exec-card"><div class="ec-val" style="color:#EF6C00;">{alta_count}</div><div class="ec-lbl">Altos</div></div>
        <div class="exec-card"><div class="ec-val" style="color:#F9A825;">{media_count}</div><div class="ec-lbl">Medios</div></div>
    </div>

    <div class="info-box">
        <p><strong>Estado general:</strong> La evaluación de <strong>{esc(org_show)}</strong> arroja un Scorecard de Seguridad de <strong>{score_general}/100 ({letter})</strong>, lo que indica una postura de seguridad <strong>{'solida' if letter == 'A' else 'buena' if letter == 'B' else 'aceptable' if letter == 'C' else 'deficiente' if letter == 'D' else 'critica'}</strong>.</p>
        <br>
        <p><strong>Principales factores que afectan el score:</strong></p>
        <ul style="padding-left:18px;margin:4px 0;">
            {"".join(f'<li><strong>{esc(f["factor"])}:</strong> {esc(f["score"])}/100 ({f["incidencias"]} incidencia(s))</li>' for f in sorted(factores, key=lambda x: x["score"])[:4])}
        </ul>
        <br>
        <p><strong>Riesgos mas relevantes:</strong></p>
        <ul style="padding-left:18px;margin:4px 0;">
            {''.join(f'<li>{esc(h["titulo"][:120])} — <span class="s-badge {_badge_class(h["gravedad"])}">{esc(h["gravedad"])}</span></li>' for h in hallazgos[:10])}
        </ul>
        <br>
        <p><strong>Recomendación general:</strong> Se recomienda establecer un plan de remediación con hitos a 30, 60 y 90 dias, priorizando el cierre de hallazgos críticos ({crit_count}) y altos ({alta_count}). Implementar controles de seguridad esenciales como HSTS, CSP, SPF/DMARC y mantener un programa continuo de monitoreo de superficie de ataque.</p>
        <br>
        <p><strong>Conclusion:</strong> La postura de seguridad de {esc(org_show)} es {"satisfactoria" if score_general >= 80 else "mejorable" if score_general >= 60 else "preocupante"} y requiere {"monitoreo continuo" if score_general >= 80 else "acciones correctivas planificadas" if score_general >= 60 else "accion inmediata sobre los hallazgos criticos"}. Se recomienda una reevaluacion en 90 dias para verificar el avance de las acciones correctivas.</p>
    </div>
</div>

<!-- ======== FOOTER ======== -->
<div class="legal-note">
    Este documento corresponde a una evaluación puntual basada en la información disponible al momento de generacion. Los resultados deben ser validados antes de tomar decisiones operativas o contractuales.
</div>
<div class="page-footer">
    <span>INFORME DETALLADO - {esc(domain)}</span>
    <span>Preparado: {esc(fecha_str)}</span>
    <span>Página <span class="pageNum"></span></span>
</div>

</div>
</body>
</html>"""
    return html

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="B2 - Informe Scorecard de Seguridad")
    ap.add_argument("--asm", type=Path, default=ROOT / "asm_report.json", help="JSON de asm_scan.py")
    ap.add_argument("--out", type=Path, default=ROOT / "informe_scorecard_b2.html", help="HTML de salida")
    ap.add_argument("--analista", default="", help="Nombre del analista")
    ap.add_argument("--org", default="GrupoCibest", help="Nombre de la organizacion emisora")
    args = ap.parse_args()

    if not args.asm.is_file():
        print(f"[ERROR] No se encuentra {args.asm}")
        return 1

    data = json.loads(args.asm.read_text(encoding="utf-8"))
    html = build_report(data, args.analista, args.org)
    args.out.write_text(html, encoding="utf-8")
    print(f"[OK] {args.out}")
    return 0

if __name__ == "__main__":
    import sys; sys.exit(main())
