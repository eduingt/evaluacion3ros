#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Informe Ejecutivo de Ciberseguridad - Evaluación de Postura de Seguridad de Terceros
Estilo: oscuro corporativo, acentos rojos, diseno profesional para exportacion PDF.
Genera HTML listo para Playwright -> PDF.
"""

from __future__ import annotations
import argparse, json, math, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pasivo_canon import collect_pasive_items
from precia_scorecard import render_precialike_block
from score_legend import render_score_legend
from resumen_ejecutivo import render_resumen_ejecutivo
from semi_canon import collect_semi_active_items

FORMULA_VERSION = "B3-v2.0"
FORMULA_DATE = "2026-09-22"

ROOT = Path(__file__).resolve().parent

def esc(s: Any) -> str:
    if s is None:
        return ""
    s = str(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def severity_color(s: str) -> str:
    m = {"critico":"#C62828","alto":"#EF6C00","media":"#F9A825","bajo":"#A7F3D0","info":"#9CA3AF"}
    return m.get(s.lower(), "#9CA3AF")

def grade_color(pct: float) -> str:
    if pct >= 80: return "#173B57"
    if pct >= 60: return "#6B7280"
    return "#D1D5DB"

def bar_chart_svg(items: list[tuple[str, float, str]], w: int = 500, h_per: int = 30, label_w: int = 160) -> str:
    n = len(items)
    h = n * h_per + 20
    bars: list[str] = []
    max_v = max((v for _, v, _ in items), default=1)
    for i, (label, val, color) in enumerate(items):
        pw = (val / max_v) * (w - label_w - 60)
        y = 10 + i * h_per
        bars.append(f'<text x="5" y="{y+14}" fill="#173B57" font-family="sans-serif" font-size="12">{esc(label)}</text>')
        bars.append(f'<rect x="{label_w}" y="{y+2}" width="{pw}" height="20" rx="3" fill="{color}" opacity="0.9"/>')
        bars.append(f'<text x="{label_w + pw + 6}" y="{y+14}" fill="#6B7280" font-family="sans-serif" font-size="11">{val:.1f}</text>')
    return f'<svg width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg">{"".join(bars)}</svg>'

def donut_svg(segments: list[tuple[str, float, str]], size: int = 220, inner_r: float = 0.6) -> str:
    cx = cy = size // 2
    r = size // 2 - 10
    total = sum(v for _, v, _ in segments) or 1
    paths: list[str] = []
    ang = -90
    for label, val, color in segments:
        frac = val / total
        a2 = ang + 360 * frac
        sr = math.radians(ang)
        er = math.radians(a2)
        sx = cx + r * math.cos(sr)
        sy = cy + r * math.sin(sr)
        ex = cx + r * math.cos(er)
        ey = cy + r * math.sin(er)
        large = 1 if (a2 - ang) > 180 else 0
        paths.append(f'<path d="M{cx},{cy} L{sx:.1f},{sy:.1f} A{r},{r} 0 {large},1 {ex:.1f},{ey:.1f} Z" fill="{color}" stroke="#ffffff" stroke-width="1.5"/>')
        ang = a2
    ir = r * inner_r
    paths.append(f'<circle cx="{cx}" cy="{cy}" r="{ir}" fill="#ffffff"/>')
    paths.append(f'<text x="{cx}" y="{cy-4}" fill="#173B57" font-family="sans-serif" font-size="13" text-anchor="middle" font-weight="700">{total:.0f}</text>')
    paths.append(f'<text x="{cx}" y="{cy+10}" fill="#6B7280" font-family="sans-serif" font-size="9" text-anchor="middle">hallazgos</text>')

    legend_y = size + 10
    legend_items: list[str] = []
    for i, (label, val, color) in enumerate(segments):
        lx = 10 + (i % 3) * 160
        ly = legend_y + (i // 3) * 18
        legend_items.append(f'<rect x="{lx}" y="{ly}" width="10" height="10" fill="{color}" rx="2"/>')
        legend_items.append(f'<text x="{lx+14}" y="{ly+9}" fill="#6B7280" font-family="sans-serif" font-size="10">{esc(label)} ({val:.0f})</text>')
    return f'<svg width="{size}" height="{size + legend_y + 20}" xmlns="http://www.w3.org/2000/svg">{"".join(paths)}{"".join(legend_items)}</svg>'

def gauge_svg(score: float, size: int = 220) -> str:
    cx = cy = size // 2
    r = size // 2 - 20
    ang = 180 + score * 1.8
    sr = math.radians(180)
    er = math.radians(ang)
    sx = cx + r * math.cos(sr)
    sy = cy + r * math.sin(sr)
    ex = cx + r * math.cos(er)
    ey = cy + r * math.sin(er)

    color = grade_color(score)
    bg = f'<path d="M{sx:.1f},{sy:.1f} A{r},{r} 0 0,1 {cx},{cy-r*2+2}" fill="none" stroke="#E5E7EB" stroke-width="12" stroke-linecap="round"/>'
    fg = f'<path d="M{sx:.1f},{sy:.1f} A{r},{r} 0 0,1 {ex:.1f},{ey:.1f}" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round"/>'
    txt = f'<text x="{cx}" y="{cy-4}" fill="#173B57" font-family="sans-serif" font-size="28" text-anchor="middle" font-weight="800">{score:.1f}</text>'
    lbl = f'<text x="{cx}" y="{cy+14}" fill="#6B7280" font-family="sans-serif" font-size="11" text-anchor="middle">Security Trust Score</text>'
    return f'<svg width="{size}" height="{size//2+30}" xmlns="http://www.w3.org/2000/svg">{bg}{fg}{txt}{lbl}</svg>'

def risk_matrix_svg() -> str:
    rows = 5
    cols = 5
    cell = 50
    gap = 2
    w = cols * (cell + gap) + 60
    h = rows * (cell + gap) + 60
    labels = ["Muy Baja","Baja","Media","Alta","Muy Alta"]
    colors_5x5 = [
        ["#f2f2f2","#E5E7EB","#D1D5DB","#9CA3AF","#6B7280"],
        ["#E5E7EB","#D1D5DB","#9CA3AF","#6B7280","#374151"],
        ["#D1D5DB","#9CA3AF","#6B7280","#374151","#1F2933"],
        ["#9CA3AF","#6B7280","#374151","#1F2933","#1F2933"],
        ["#6B7280","#374151","#1F2933","#1F2933","#173B57"],
    ]
    rects: list[str] = []
    for r in range(rows):
        for c in range(cols):
            x = 50 + c * (cell + gap)
            y = 10 + (rows - 1 - r) * (cell + gap)
            clr = colors_5x5[r][c]
            rects.append(f'<rect x="{x}" y="{y}" width="{cell}" height="{cell}" rx="4" fill="{clr}" stroke="#F3F5F7" stroke-width="1"/>')
        rects.append(f'<text x="5" y="{y + cell//2 + 4}" fill="#6B7280" font-family="sans-serif" font-size="10" text-anchor="end">{esc(labels[rows-1-r])}</text>')
    for c in range(cols):
        x = 50 + c * (cell + gap) + cell // 2
        rects.append(f'<text x="{x}" y="{h-8}" fill="#6B7280" font-family="sans-serif" font-size="10" text-anchor="middle">{esc(labels[c])}</text>')
    rects.append(f'<text x="10" y="{h//2}" fill="#6B7280" font-family="sans-serif" font-size="11" text-anchor="middle" transform="rotate(-90,10,{h//2})">Probabilidad</text>')
    rects.append(f'<text x="{w//2}" y="{h-35}" fill="#6B7280" font-family="sans-serif" font-size="11" text-anchor="middle">Impacto</text>')
    return f'<svg width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg">{"".join(rects)}</svg>'

CSS = """
:root {
  --bg-body: #ffffff;
  --bg-card: #f3f5f7;
  --bg-card-alt: #e8f5e9;
  --border: #d9dee3;
  --text: #1f2933;
  --text-muted: #4b5563;
  --accent: #173B57;
  --accent2: #2F6F9F;
  --good: #2E7D32;
  --warn: #F9A825;
  --bad: #C62828;
  --info: #6b7280;
  --font: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
}
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg-body); color:var(--text); font-family:var(--font); font-size:14px; line-height:1.6; }
.page { max-width:900px; margin:0 auto; padding:0; }
.sec { padding:40px 48px; border-bottom:1px solid var(--border); }
.sec:last-child { border-bottom:none; }

/* Cover */
.cover { padding:80px 48px 60px; min-height:100vh; display:flex; flex-direction:column; justify-content:center; position:relative; }
.cover::before { content:''; position:absolute; top:0; left:0; width:100%; height:4px; background:var(--accent); }
.cover::after { content:''; position:absolute; bottom:0; left:0; width:100%; height:2px; background:var(--accent); }
.cover .tag { color:var(--text-muted); font-size:13px; text-transform:uppercase; letter-spacing:.12em; font-weight:600; margin-bottom:16px; }
.cover h1 { font-size:2.4rem; font-weight:800; line-height:1.15; margin-bottom:8px; letter-spacing:-.02em; }
.cover h2 { font-size:1.1rem; font-weight:400; color:var(--text-muted); margin-bottom:32px; line-height:1.4; }
.cover .meta { font-size:13px; color:var(--text-muted); line-height:1.8; margin-top:auto; padding-top:40px; border-top:1px solid var(--accent); }
.cover .meta strong { color:var(--text); }
.cover .accent-line { width:80px; height:3px; background:var(--accent); margin:24px 0; }

/* TOC */
.toc { padding:40px 48px; }
.toc h2 { color:var(--text); font-size:1.1rem; text-transform:uppercase; letter-spacing:.08em; margin-bottom:20px; }
.toc-item { display:flex; padding:6px 0; border-bottom:1px solid var(--border); font-size:14px; }
.toc-item .num { color:var(--accent); font-weight:600; width:40px; flex-shrink:0; }
.toc-item .title { color:var(--text); flex:1; }
.toc-item .page { color:var(--text-muted); font-size:12px; }
.toc-sub { padding-left:40px; font-size:13px; }

/* Section titles */
.sec-title { display:flex; align-items:center; gap:16px; margin-bottom:24px; }
.sec-title .sn { font-size:1.5rem; font-weight:800; color:var(--accent); line-height:1; }
.sec-title .st { font-size:1.2rem; font-weight:700; color:var(--text); }
.sec-title .line { flex:1; height:1px; background:var(--accent); opacity:.3; }
.sec-sub { font-size:1rem; font-weight:600; color:var(--text); margin:20px 0 12px; text-transform:uppercase; letter-spacing:.04em; }

/* Tables */
table.data { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:20px; }
table.data th { background:#173B57; border:1px solid #173B57; padding:8px 10px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:#ffffff; font-weight:600; }
table.data td { border:1px solid #D9DEE3; padding:7px 10px; vertical-align:top; }
table.data tr:hover td { background:var(--bg-card-alt); }
table.data .num { text-align:right; white-space:nowrap; }

/* Risk level badges */
.r-badge { display:inline-block; padding:2px 10px; border-radius:3px; font-size:11px; font-weight:700; text-transform:uppercase; }
.r-crítico { background:#173B57; color:#ffffff; border:1px solid #173B57; }
.r-alto { background:#1F2933; color:#ffffff; border:1px solid #1F2933; }
.r-medio { background:#D1D5DB; color:#ffffff; border:1px solid #D1D5DB; }
.r-bajo { background:#E5E7EB; color:#2F6F9F; border:1px solid #D1D5DB; }
.r-info { background:#f2f2f2; color:#6B7280; border:1px solid #D1D5DB; }

/* Status indicators */
.s-implemented { color:#173B57; font-weight:700; }
.s-parcial { color:#6B7280; font-weight:600; }
.s-no { color:#173B57; font-weight:800; }
.s-expuesto { color:#173B57; font-weight:800; }

/* Recommendation cards */
.rec-card { background:var(--bg-card); border:1px solid var(--border); border-left:3px solid var(--accent); border-radius:6px; padding:14px 16px; margin-bottom:10px; }
.rec-card .rec-num { font-size:11px; color:var(--text-muted); font-weight:700; }
.rec-card .rec-title { font-size:14px; font-weight:600; color:var(--text); margin:4px 0; }
.rec-card .rec-desc { font-size:13px; color:var(--text-muted); line-height:1.5; }
.rec-card .rec-prio { display:inline-block; font-size:10px; padding:2px 8px; border-radius:3px; margin-top:6px; text-transform:uppercase; font-weight:600; }
.prio-alta { background:#173B57; color:#ffffff; border:1px solid #173B57; }
.prio-media { background:#D1D5DB; color:#ffffff; border:1px solid #D1D5DB; }
.prio-baja { background:#f2f2f2; color:#6B7280; border:1px solid #D1D5DB; }

/* Narrative box */
.narrative { background:var(--bg-card); border:1px solid var(--border); border-radius:8px; padding:16px 18px; margin:16px 0; color:var(--text-muted); font-size:13px; line-height:1.7; }
.narrative strong { color:var(--text); }

/* Bullet lists */
ul.compact { list-style:none; padding:0; margin:8px 0; }
ul.compact li { padding:4px 0 4px 20px; position:relative; font-size:13px; color:var(--text-muted); }
ul.compact li::before { content:"▸"; position:absolute; left:0; color:var(--accent); font-weight:700; }

/* Footer */
.footer { text-align:center; font-size:11px; color:var(--text-muted); border-top:1px solid var(--accent); padding:12px 0; margin-top:0; }

/* Back cover */
.back-cover { padding:80px 48px; min-height:60vh; display:flex; flex-direction:column; justify-content:center; align-items:center; text-align:center; }
.back-cover::before { content:''; position:absolute; top:0; left:0; width:100%; height:2px; background:var(--accent); }
.back-cover h2 { font-size:1.1rem; font-weight:700; color:var(--text); margin-bottom:4px; }
.back-cover .sub { color:var(--text-muted); font-size:13px; margin-bottom:24px; }
.back-cover .conf { font-size:11px; color:var(--text-muted); max-width:400px; line-height:1.6; padding:16px; border:1px solid var(--accent); border-radius:8px; }
.back-cover .accent-line { width:60px; height:2px; background:var(--accent); margin:16px auto; }

/* Page number */
.page-num { text-align:center; font-size:10px; color:#D1D5DB; padding:8px; border-top:1px solid #E5E7EB; }

/* Finding detail cards */
.f-card { background:var(--bg-card); border:1px solid var(--border); border-radius:8px; margin-bottom:14px; overflow:hidden; }
.f-hdr { display:flex; align-items:center; gap:8px; padding:10px 14px; background:#f2f2f2; border-bottom:1px solid var(--border); }
.f-title { font-size:14px; font-weight:600; padding:10px 14px 0; color:var(--text); }
.f-body { padding:10px 14px 14px; }
.f-section { margin-top:8px; }
.f-label { display:block; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.04em; color:var(--text); margin-bottom:3px; }
.f-text { font-size:12px; color:var(--text-muted); line-height:1.6; margin:0; }
.f-evidence { background:#fafafa; border:1px solid #E5E7EB; border-radius:4px; padding:8px 10px; font-size:11px; font-family:'Consolas','Courier New',monospace; color:#2F6F9F; line-height:1.5; white-space:pre-wrap; word-break:break-all; margin:0; }
.f-lvl { margin-left:auto; font-size:10px!important; }

/* Badges */
.risk-critical { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#173B57; color:#fff; }
.risk-high { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#1F2933; color:#fff; }
.risk-med { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#9CA3AF; color:#fff; }
.risk-low { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#D9DEE3; color:#333; }
.epss-badge { display:inline-block; font-size:10px; padding:1px 5px; border-radius:4px; background:#f2f2f2; color:#555; }
.kev-badge { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#173B57; color:#fff; }
/* Print */
@media print { body { background:#ffffff!important; } .sec { break-inside:avoid; page-break-inside:avoid; } }
"""

def domain_score(p: dict[str, Any]) -> float:
    """Heurística 0–100 de seguridad del dominio."""
    pts = 0.0
    h = p.get("https", {}) or {}
    headers = h.get("headers") or {}
    tls = p.get("tls") or {}
    dns = p.get("dns") or {}
    if p.get("port_443", {}).get("open"):
        pts += 8
    if p.get("port_80", {}).get("open"):
        pts += 2
    if isinstance(h.get("status_code"), int) and 200 <= h["status_code"] < 400:
        pts += 18
    if headers.get("strict-transport-security"):
        pts += 12
    if headers.get("content-security-policy") or headers.get("content-security-policy-report-only"):
        pts += 10
    if headers.get("x-frame-options"):
        pts += 6
    if headers.get("x-content-type-options"):
        pts += 4
    if tls.get("negotiated_version") and not tls.get("error"):
        pts += 14
    if tls.get("tls13_only_ok"):
        pts += 6
    if dns.get("spf_record") and "-all" in str(dns["spf_record"]).replace(" ", "").lower():
        pts += 10
    elif dns.get("spf_record"):
        pts += 5
    if dns.get("dmarc_policy") in ("reject", "quarantine"):
        pts += 10
    elif dns.get("dmarc_policy"):
        pts += 5
    starttls = dns.get("starttls_results") or []
    if starttls and all(s.get("starttls") for s in starttls):
        pts += 5
    elif starttls:
        pts += 1
    ip_reputation = dns.get("ip_reputation") or []
    if not ip_reputation:
        pts += 8
    elif len(ip_reputation) <= 2:
        pts += 4
    urlhaus = p.get("urlhaus") or {}
    if not urlhaus.get("malicious"):
        pts += 5
    elif urlhaus.get("error"):
        pts += 1
    vulns = p.get("vulnerabilities") or []
    if not vulns:
        pts += 8
    elif len(vulns) <= 3:
        pts += 4
    leaks = p.get("credential_leaks") or []
    valid_leaks = [l for l in leaks if "error" not in l]
    if not valid_leaks:
        pts += 6
    elif len(valid_leaks) <= 2:
        pts += 3
    typos = p.get("typosquatting") or []
    if not typos:
        pts += 6
    elif len(typos) <= 2:
        pts += 3
    patch = p.get("patching") or []
    eol_count = sum(1 for x in patch if x.get("status") == "eol")
    if eol_count == 0:
        pts += 5
    elif eol_count <= 1:
        pts += 2
    supply = p.get("supply_chain") or []
    if not supply:
        pts += 4
    elif len(supply) <= 5:
        pts += 2
    takeover = p.get("takeover_risks") or []
    vulnerable = any(r.get("vulnerable") for r in takeover)
    if not takeover:
        pts += 6
    elif not vulnerable:
        pts += 3
    csp_f = p.get("csp_findings") or []
    if not csp_f:
        pts += 5
    return min(pts, 100.0)

def build_report(asm: dict[str, Any], analista: str = "", org: str = "Informe") -> str:
    providers = asm.get("providers") or []
    matrix = asm.get("matrix") or []
    matrix_by_domain = {m.get("dominio", ""): m for m in matrix}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # --- Derived counts ---
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

    domains_list = ", ".join(p.get("domain", "") for p in providers[:3])
    if len(providers) > 3:
        domains_list += f" y {len(providers)-3} mas"

    # Derive scanned org from provider names if org is default
    if org == "Informe" and providers:
        org_names = [p.get("name", p.get("domain", "")).replace("(www)", "").strip() for p in providers[:3]]
        org = ", ".join(org_names)
        if len(providers) > 3:
            org += f" y {len(providers)-3} mas"

    # --- Derive real risk findings per provider ---
    all_risks: list[dict[str, Any]] = []
    cat_config = cat_exposure = cat_email = cat_app = cat_infra = cat_web = cat_info = 0
    rid_counter = 0

    def _sev_label(prob: int, imp: int) -> str:
        return "CRITICO" if prob * imp >= 15 else "ALTO" if prob * imp >= 10 else "MEDIO" if prob * imp >= 6 else "BAJO"

    for p in providers:
        domain = p.get("domain", "")
        dns = p.get("dns") or {}
        https = p.get("https") or {}
        tls_data = p.get("tls") or {}
        headers = https.get("headers") or {}
        csp_findings = p.get("csp_findings") or []
        vulnerabilities = p.get("vulnerabilities") or []
        takeover_risks = p.get("takeover_risks") or []
        cred_leaks = p.get("credential_leaks") or []
        typos = p.get("typosquatting") or []
        patching = p.get("patching") or []
        open_ports = p.get("open_ports") or []
        subdomains = p.get("subdomains") or []
        crt_subs = p.get("crt_subdomains") or []
        brute_subs = p.get("brute_subs") or []

        # HSTS
        hsts_val = headers.get("strict-transport-security")
        if not hsts_val and providers:
            rid_counter += 1
            sev = _sev_label(3, 4)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Falta de HSTS en {domain}",
                "prob": 3, "imp": 4, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "HSTS (Strict-Transport-Security) obliga a los navegadores a comunicarse exclusivamente por HTTPS, previniendo ataques de degradacion SSL stripping y asegurando que todas las conexiones sean cifradas.",
                "recommendation": "Implementar la cabecera HTTP Strict-Transport-Security con un max-age minimo de 31536000 segundos (1 anio) e incluir la directiva includeSubDomains.",
                "evidence": f"Dominio: {domain} | Cabecera HSTS: Ausente | Cabeceras HTTP disponibles: {esc(str({k: v for k, v in sorted(headers.items()) if k in ('server','x-powered-by','content-type')})[:200])}"
            }); cat_config += 1

        # CSP
        csp = headers.get("content-security-policy") or headers.get("content-security-policy-report-only") or ""
        if not csp:
            rid_counter += 1; sev = _sev_label(3, 3)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"CSP ausente en {domain}",
                "prob": 3, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Content-Security-Policy es un mecanismo de seguridad crítico que controla que recursos (scripts, estilos, imagenes) puede cargar el navegador, mitigando ataques XSS, clickjacking e inyeccion de datos.",
                "recommendation": "Configurar CSP con directivas restrictivas: script-src 'self', object-src 'none', base-uri 'self', y utilizar report-uri o report-to para monitoreo.",
                "evidence": f"Dominio: {domain} | Cabecera CSP: Ausente"
            }); cat_app += 1
        elif csp_findings:
            weak_desc = "; ".join(f.get("desc", "")[:80] for f in csp_findings[:3])
            rid_counter += 1; sev = _sev_label(3, 3)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"CSP debil en {domain}: {weak_desc[:100]}",
                "prob": 3, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "La política CSP detectada presenta debilidades que reducen su efectividad como mecanismo de defensa contra XSS y otros ataques de inyeccion de contenido.",
                "recommendation": "Revisar las directivas CSP debiles: eliminar unsafe-inline, unsafe-eval, reducir wildcards en script-src, y agregar report-uri para monitorear violaciones.",
                "evidence": f"Dominio: {domain} | CSP actual: {esc(str(csp)[:300])} | Hallazgos: {esc(weak_desc[:200])}"
            }); cat_app += 1

        # Cookie Findings
        cookie_findings = p.get("cookie_findings") or []
        for ck in cookie_findings:
            ck_name = ck.get("name", "?")
            ck_domain = ck.get("domain", "")
            ck_secure = ck.get("secure", True)
            ck_httponly = ck.get("httponly", True)
            ck_samesite = ck.get("samesite", "")
            ck_issue = ck.get("issue", "")
            sev = "MEDIO" if not ck_secure or not ck_httponly else "BAJO"
            rid_counter += 1
            issue_parts = []
            if not ck_secure: issue_parts.append("Sin flag Secure")
            if not ck_httponly: issue_parts.append("Sin flag HttpOnly")
            if ck_samesite and ck_samesite.lower() not in ("strict", "lax", "none"): issue_parts.append(f"SameSite debil ({ck_samesite})")
            if ck_issue: issue_parts.append(ck_issue[:80])
            issue_str = "; ".join(issue_parts) if issue_parts else "Configuracion insegura"
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Cookie insegura '{ck_name}' en {domain}",
                "prob": 2 if not ck_secure else 1, "imp": 3 if not ck_secure else 2,
                "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": f"La cookie '{ck_name}' tiene problemas de seguridad: {issue_str}. Las cookies sin flags Secure o HttpOnly pueden ser interceptadas o accedidas mediante XSS.",
                "recommendation": "Configurar las cookies con flags Secure=True, HttpOnly=True y SameSite=Lax o Strict segun el caso de uso.",
                "evidence": f"Dominio: {domain} | Cookie: {ck_name} | Domain: {ck_domain} | Secure: {ck_secure} | HttpOnly: {ck_httponly} | SameSite: {ck_samesite} | Issue: {ck_issue}"
            }); cat_web += 1

        # SPF/DMARC
        spf = dns.get("spf_record")
        dmarc = dns.get("dmarc_record")
        dmarc_policy = dns.get("dmarc_policy") or ""
        if not spf and not dmarc:
            rid_counter += 1; sev = _sev_label(4, 3)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"SPF y DMARC ausentes en {domain}",
                "prob": 4, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "SPF y DMARC son mecanismos de autenticacion de correo que previenen la suplantacion de dominio (spoofing). Sin ellos, los atacantes pueden enviar correos fraudulentos que parecen provenir del dominio.",
                "recommendation": "Configurar registro SPF con mecanismo -all (hard fail) y DMARC con política p=reject, incluyendo rua para recibir informes agregados.",
                "evidence": f"Dominio: {domain} | SPF: Ausente | DMARC: Ausente"
            }); cat_email += 1
        elif not dmarc or dmarc_policy != "reject":
            rid_counter += 1; sev = _sev_label(4, 3)
            dmarc_info = dmarc or "Ausente"
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"DMARC sin política de rechazo en {domain}",
                "prob": 4, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "DMARC con política diferente a p=reject permite que los correos fraudulentos que fallan autenticacion SPF/DKIM aun sean entregados en lugar de ser rechazados, reduciendo la proteccion contra phishing.",
                "recommendation": "Actualizar DMARC a política p=reject una vez verificada la alineacion SPF/DKIM de todos los remitentes legitimos.",
                "evidence": f"Dominio: {domain} | DMARC actual: {esc(str(dmarc_info)[:200])} | Política: {esc(dmarc_policy)} | SPF: {esc(spf[:200]) if spf else 'Ausente'}"
            }); cat_email += 1
        elif not spf:
            rid_counter += 1; sev = _sev_label(3, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"SPF ausente en {domain}",
                "prob": 3, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "SPF especifica que servidores estan autorizados a enviar correo en nombre del dominio. Su ausencia permite que cualquier servidor envie correos fraudulentos.",
                "recommendation": "Configurar registro SPF con todos los remitentes autorizados y mecanismo -all para rechazar envios no autorizados.",
                "evidence": f"Dominio: {domain} | SPF: Ausente | DMARC: {esc(str(dmarc)[:200]) if dmarc else 'Ausente'}"
            }); cat_email += 1

        # TLS
        tls_version = tls_data.get("negotiated_version") or ""
        if tls_data.get("error"):
            rid_counter += 1; sev = _sev_label(3, 5)
            err_msg = tls_data["error"][:100]
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Error TLS en {domain}",
                "prob": 3, "imp": 5, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Errores en la negociacion TLS pueden indicar configuración incorrecta del certificado o del servidor, permitiendo conexiones no seguras o interceptacion de trafico.",
                "recommendation": "Revisar la configuración TLS del servidor, verificar la cadena de certificados y asegurar que soporte TLS 1.2 o superior.",
                "evidence": f"Dominio: {domain} | Error TLS: {esc(err_msg)}"
            }); cat_infra += 1
        elif tls_version and "1.2" not in tls_version and "1.3" not in tls_version:
            rid_counter += 1; sev = _sev_label(2, 5)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"TLS debil ({tls_version}) en {domain}",
                "prob": 2, "imp": 5, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Versiones antiguas de TLS (1.0, 1.1) tienen vulnerabilidades conocidas como BEAST, POODLE y Lucky13 que permiten a un atacante desencriptar trafico.",
                "recommendation": "Deshabilitar TLS 1.0 y 1.1, configurar el servidor para usar exclusivamente TLS 1.2 y 1.3.",
                "evidence": f"Dominio: {domain} | Version negociada: {esc(tls_version)} | Certificado: {esc(str(tls_data.get('cert_subject',''))[:100])}"
            }); cat_infra += 1

        # Port 80 open
        port80 = p.get("port_80") or {}
        if port80.get("open"):
            rid_counter += 1; sev = "BAJO"
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"HTTP (puerto 80) abierto sin redireccion en {domain}",
                "prob": 2, "imp": 1, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "El puerto HTTP 80 se encuentra abierto. Lo ideal es redirigir inmediatamente a HTTPS (puerto 443) para evitar que los usuarios naveguen en texto plano y sean vulnerables a ataques de intermediario (MITM).",
                "recommendation": "Redirigir todo el trafico HTTP del puerto 80 a HTTPS (301 Moved Permanently) y considerar cerrar el puerto 80 si no es necesario.",
                "evidence": f"Dominio: {domain} | Puerto 80: Abierto"
            }); cat_web += 1

        # Subdomain exposure
        sub_count = len(subdomains) + len(crt_subs) + len(brute_subs)
        if sub_count > 0:
            rid_counter += 1; sev = _sev_label(3, 3)
            sub_list = ", ".join(sorted(set(
                [s.get("subdomain", "") for s in subdomains[:5]] +
                [s for s in crt_subs[:5]] +
                [s.get("fqdn", "") for s in brute_subs[:5]]
            )))
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"{sub_count} subdominios expuestos en {domain}",
                "prob": 3, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Cada subdominio descubierto amplia la superficie de ataque. Subdominios olvidados o sin mantenimiento pueden alojar aplicaciones vulnerables o paneles administrativos expuestos.",
                "recommendation": "Realizar un inventario completo de subdominios, eliminar los no utilizados y asegurar que todos tengan configuración de seguridad uniforme.",
                "evidence": f"Dominio: {domain} | Subdominios activos (DNS): {len(subdomains)} | CT logs: {len(crt_subs)} | Fuerza bruta: {len(brute_subs)} | Muestra: {esc(sub_list[:300])}"
            }); cat_exposure += 1

        # Takeover
        for t in takeover_risks:
            t_desc = t.get("subdomain", t.get("fqdn", "")) or domain
            t_service = t.get("service", t.get("fingerprint", "servicio externo"))
            t_cname = t.get("cname", "")
            rid_counter += 1; sev = _sev_label(2, 5)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Riesgo de takeover en {t_desc}",
                "prob": 2, "imp": 5, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Un subdominio takeover ocurre cuando un registro DNS apunta a un servicio externo (S3, CloudFront, Heroku, etc.) que ya no esta siendo utilizado, permitiendo que un atacante lo reclame y sirva contenido malicioso.",
                "recommendation": "Eliminar o actualizar los registros DNS que apuntan a servicios externos no controlados, o verificar que las cuentas en dichos servicios esten activas.",
                "evidence": f"Subdominio: {esc(t_desc)} | Servicio: {esc(str(t_service)[:150])}" + (f" | CNAME: {esc(t_cname)}" if t_cname else "")
            }); cat_exposure += 1

        # Open ports
        open_list = [o for o in open_ports if o.get("state") == "open"]
        if len(open_list) > 3:
            ports_desc = "; ".join(f"{o.get('port','?')}/{o.get('service','?')}" for o in open_list)
            rid_counter += 1; sev = _sev_label(3, 4)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"{len(open_list)} puertos abiertos en {domain}",
                "prob": 3, "imp": 4, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Puertos abiertos adicionales a los estrictamente necesarios (80/443) exponen servicios que pueden tener vulnerabilidades, configuraciones por defecto o credenciales debiles.",
                "recommendation": "Cerrar todo puerto no esencial mediante reglas de firewall. Para puertos administrativos, restringir acceso solo a IPs autorizadas via VPN o lista blanca.",
                "evidence": f"IP: {esc(next(iter(dns.get('ipv4', [])), domain))} | Puertos abiertos: {esc(ports_desc[:400])}"
            }); cat_infra += 1

        # EOL
        for e in [x for x in patching if x.get("status") == "eol"]:
            tech = e.get("name", e.get("technology", "Software"))
            tech_version = e.get("version", "")
            rid_counter += 1; sev = _sev_label(4, 5)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Software EOL en {domain}: {tech}" + (f" {tech_version}" if tech_version else ""),
                "prob": 4, "imp": 5, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Software que ha llegado al final de su vida util (EOL) ya no recibe parches de seguridad, dejando vulnerabilidades conocidas sin corregir que pueden ser explotadas.",
                "recommendation": "Actualizar el software identificado a una version con soporte activo. Si no es posible, implementar medidas compensatorias como WAF, segmentacion de red y monitoreo intensivo.",
                "evidence": f"Dominio: {domain} | Tecnologia: {esc(tech)}" + (f" | Version: {esc(tech_version)}" if tech_version else "") + f" | Estado: EOL"
            }); cat_infra += 1

        # Credential leaks
        real_leaks = [l for l in cred_leaks if "error" not in l]
        if real_leaks:
            leak_details = "; ".join(f"{l.get('source','?')}: {l.get('count',l.get('entries','?'))} registros" for l in real_leaks[:3])
            rid_counter += 1; sev = _sev_label(3, 5)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Credenciales filtradas de {domain} en {len(real_leaks)} breach(es)",
                "prob": 3, "imp": 5, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Credenciales de empleados, usuarios o sistemas filtradas en breaches conocidos representan un riesgo crítico de acceso no autorizado, especialmente si las contraseñas son reutilizadas.",
                "recommendation": "Rotar inmediatamente todas las credenciales comprometidas, implementar autenticacion multifactor (2FA) obligatoria y educar a los usuarios sobre higiene de contraseñas.",
                "evidence": f"Dominio: {domain} | Fuentes de brecha: {esc(leak_details[:400])}"
            }); cat_config += 1

        # WHOIS / External
        ext_data = p.get("external") or {}
        whois = ext_data.get("whois") or {}
        if whois:
            whois_org = whois.get("org", whois.get("organization", ""))
            whois_email = whois.get("email", whois.get("abuse_email", ""))
            whois_country = whois.get("country", "")
            whois_created = whois.get("created", whois.get("creation_date", ""))
            whois_parts = []
            if whois_org: whois_parts.append(f"Org: {whois_org}")
            if whois_email: whois_parts.append(f"Email: {whois_email}")
            if whois_country: whois_parts.append(f"Pais: {whois_country}")
            if whois_created: whois_parts.append(f"Creado: {whois_created}")
            rid_counter += 1; sev = "INFO"
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Registro WHOIS disponible para {domain}",
                "prob": 0, "imp": 0, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Los datos WHOIS proporcionan información de registro del dominio que puede ser util para verificar la titularidad y gestion del activo.",
                "recommendation": "Verificar que los datos WHOIS esten actualizados y considerar privacidad de registro si se exponen datos personales.",
                "evidence": f"Dominio: {domain} | {' | '.join(whois_parts)}"
            }); cat_info += 1

        # KUMO enrichment (breachintel / js_secrets / nuclei / wayback)
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
                    rid_counter += 1; sev = _sev_label(4, 4)
                    all_risks.append({
                        "id": f"R-{rid_counter:02d}",
                        "desc": f"Filtraciones / infostealer detectados para {domain} (KUMO)",
                        "prob": 4, "imp": 4, "level": sev, "cls": f"r-{sev.lower()}",
                        "explanation": "Breach intelligence (Hudson Rock, Chiasmodon, HIBP, ProxyNova) revela credenciales corporativas y maquinas infectadas con infostealers asociadas al dominio.",
                        "recommendation": "Rotar credenciales afectadas, auditar las maquinas comprometidas y monitorear los canales de exfiltracion.",
                        "evidence": f"Dominio: {domain} | {' | '.join(kbi_parts)}"
                    }); cat_exposure += 1
            kjs = kumo.get("js_secrets") or {}
            if kjs.get("secrets") and not kjs.get("error"):
                kjs_detail = "; ".join(f"{x.get('type','?')} en {x.get('file','?')}" for x in kjs["secrets"][:6])
                rid_counter += 1; sev = _sev_label(4, 4)
                all_risks.append({
                    "id": f"R-{rid_counter:02d}",
                    "desc": f"Secretos expuestos en JavaScript de {domain} ({kjs.get('total', len(kjs.get('secrets', [])))} hallazgo(s))",
                    "prob": 4, "imp": 4, "level": sev, "cls": f"r-{sev.lower()}",
                    "explanation": "El escaneo de archivos JS detecto claves, tokens o credenciales en claro incrustadas en el código cliente.",
                    "recommendation": "Rotar los secretos detectados, moverlos a un gestor de secretos y eliminar su presencia del código entregado al navegador.",
                    "evidence": f"Dominio: {domain} | {esc(kjs_detail[:400])}"
                }); cat_exposure += 1
            knu = kumo.get("nuclei") or {}
            if knu.get("findings") and not knu.get("error"):
                high_risk = [f for f in knu["findings"] if f.get("severity") in ("critical", "high")]
                if high_risk:
                    knu_detail = "; ".join(f"{f.get('severity','?')}: {f.get('name','?')}" for f in high_risk[:8])
                    rid_counter += 1; sev = _sev_label(4, 4)
                    all_risks.append({
                        "id": f"R-{rid_counter:02d}",
                        "desc": f"Vulnerabilidades activas detectadas en {domain} por scanner KUMO ({len(high_risk)} critica(s)/alta(s))",
                        "prob": 4, "imp": 4, "level": sev, "cls": f"r-{sev.lower()}",
                        "explanation": "El escaner de vulnerabilidades basado en plantillas Nuclei encontro endpoints expuestos o versiones vulnerables en el dominio.",
                        "recommendation": "Revisar cada hallazgo, parchear la version afectada y restringir el acceso a los endpoints expuestos.",
                        "evidence": f"Dominio: {domain} | {esc(knu_detail[:400])}"
                    }); cat_exposure += 1
            kwb = kumo.get("wayback") or {}
            if kwb.get("interesting") and not kwb.get("error"):
                kwb_detail = "; ".join(kwb["interesting"][:6])
                rid_counter += 1; sev = "MED"
                all_risks.append({
                    "id": f"R-{rid_counter:02d}",
                    "desc": f"Endpoints históricos sensibles en Wayback Machine para {domain}",
                    "prob": 2, "imp": 3, "level": sev, "cls": "r-med",
                    "explanation": "Archivos en Wayback pueden revelar rutas de administracion, configuraciones o datos expuestos en el pasado que amplian la superficie de ataque.",
                    "recommendation": "Revisar los endpoints archivados y eliminar de produccion cualquier ruta residual todavia accesible.",
                    "evidence": f"Dominio: {domain} | {esc(kwb_detail[:400])}"
                }); cat_exposure += 1

        # Prism OSINT enrichment (breach / onion / github / gravatar / smtp / vt / abuse)
        prism = p.get("prism") or {}
        if isinstance(prism, dict):
            pll = prism.get("leak_lookup") or {}
            if pll.get("breaches") and not pll.get("error"):
                pll_detail = "; ".join(f"{b.get('name','?')}" for b in pll["breaches"][:10])
                rid_counter += 1
                all_risks.append({
                    "id": f"R-{rid_counter:02d}",
                    "desc": f"Filtraciones detectadas para {domain} en Prism breach lookup ({len(pll.get('breaches', []))})",
                    "prob": 4, "imp": 4, "level": _sev_label(4, 4), "cls": "r-critico",
                    "explanation": "Breach lookup multi-fuente (XposedOrNot, LeakCheck, HIBP, Leak-Lookup) encontro cuentas del dominio en bases de filtraciones.",
                    "recommendation": "Rotar credenciales afectadas y auditar los servicios donde se usaron esos emails.",
                    "evidence": f"Dominio: {domain} | {esc(pll_detail[:400])}"
                }); cat_exposure += 1
            poc = prism.get("onion_checker") or {}
            if poc.get("results") and not poc.get("error"):
                poc_detail = "; ".join(f"{r.get('url','?')}" for r in poc["results"][:6])
                rid_counter += 1
                all_risks.append({
                    "id": f"R-{rid_counter:02d}",
                    "desc": f"Servicios onion relacionados con {domain} en índices dark web",
                    "prob": 3, "imp": 3, "level": "ALTO", "cls": "r-alto",
                    "explanation": "Se hallaron mirrors o referencias .onion relacionados con el dominio, tipico de suplantacion, fraud shops o infraestructura oculta.",
                    "recommendation": "Investigar cada enlace onion y monitorear suplantaciones de la marca.",
                    "evidence": f"Dominio: {domain} | {esc(poc_detail[:400])}"
                }); cat_exposure += 1
            pgr = prism.get("gravatar") or {}
            if pgr.get("hits") and not pgr.get("error"):
                pgr_detail = "; ".join(f"{h.get('display_name','?')} ({h.get('email','?')})" for h in pgr["hits"][:6])
                rid_counter += 1
                all_risks.append({
                    "id": f"R-{rid_counter:02d}",
                    "desc": f"Perfiles por email (Gravatar) vinculados a {domain}",
                    "prob": 2, "imp": 2, "level": "INFO", "cls": "r-info",
                    "explanation": "Emails del dominio tienen perfiles Gravatar con cuentas vinculadas, lo que expone identidad de las personas.",
                    "recommendation": "Revisar la exposición de correos corporativos vinculados a cuentas públicas.",
                    "evidence": f"Dominio: {domain} | {esc(pgr_detail[:400])}"
                }); cat_info += 1
            pvt = prism.get("virustotal") or {}
            if pvt.get("status") == "ok" and not pvt.get("error") and (pvt.get("malicious") or pvt.get("suspicious")):
                rid_counter += 1
                all_risks.append({
                    "id": f"R-{rid_counter:02d}",
                    "desc": f"Reputacion adversa de {domain} en VirusTotal (M:{pvt.get('malicious',0)} S:{pvt.get('suspicious',0)})",
                    "prob": 4, "imp": 3, "level": _sev_label(4, 3), "cls": "r-critico",
                    "explanation": "VirusTotal reporta detecciones que pueden indicar compromiso, spam o phishing asociado al dominio.",
                    "recommendation": "Investigar las detecciones y las categorias de riesgo reportadas.",
                    "evidence": f"Dominio: {domain} | VirusTotal M:{pvt.get('malicious',0)} S:{pvt.get('suspicious',0)}"
                }); cat_exposure += 1
            pab = prism.get("abuseipdb") or {}
            if pab.get("status") == "ok" and not pab.get("error") and pab.get("abuse_score") and pab.get("abuse_score") >= 50:
                rid_counter += 1
                all_risks.append({
                    "id": f"R-{rid_counter:02d}",
                    "desc": f"IP de {domain} con abuse score {pab.get('abuse_score')}/100 en AbuseIPDB",
                    "prob": 4, "imp": 3, "level": _sev_label(4, 3), "cls": "r-critico",
                    "explanation": "La IP principal del dominio presenta reportes de abuso (spam, malware, botnet, TOR).",
                    "recommendation": "Investigar el historial de la IP y considerar mitigaciones de correo/cache.",
                    "evidence": f"Dominio: {domain} | AbuseIPDB score {pab.get('abuse_score')}/100 ({pab.get('total_reports',0)} reportes)"
                }); cat_exposure += 1
        co = p.get("claude_osint") or {}
        if isinstance(co, dict):
            com365 = co.get("m365_fingerprint") or {}
            if com365 and not com365.get("error"):
                m365_seg = []
                if com365.get("tenant_space"): m365_seg.append(f"namespace {com365['tenant_space']}")
                if com365.get("tenant_guid"): m365_seg.append(f"tenant GUID {com365['tenant_guid']}")
                if com365.get("m365_detected"): m365_seg.append("M365 detectado")
                if m365_seg:
                    rid_counter += 1
                    all_risks.append({
                        "id": f"R-{rid_counter:02d}",
                        "desc": f"Fingerprint Microsoft 365/Entra para {domain}",
                        "prob": 2, "imp": 2, "level": "INFO", "cls": "r-info",
                        "explanation": "La huella de tenant Azure/Entra (namespace, GUID, OIDC issuer) expone infraestructura de identidad corporativa util para enumeracion de cuentas.",
                        "recommendation": "Confirmar que el tenant corresponda al proveedor y restringir autoconfiguracion autodiscover pública.",
                        "evidence": f"Dominio: {domain} | {esc(' | '.join(m365_seg))}"
                    }); cat_info += 1
            cospf = co.get("spf_supply_chain") or {}
            if cospf and not cospf.get("error"):
                v = cospf.get("verdict") or {}
                if str(v.get("spoofable","")).upper() in ("SPOOFABLE","SUSCEPTIBLE","PARCIAL"):
                    rid_counter += 1
                    sev = _sev_label(3, 3)
                    all_risks.append({
                        "id": f"R-{rid_counter:02d}",
                        "desc": f"Verdict SPF/DMARC {v.get('spoofable','?')} para {domain}",
                        "prob": 3, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                        "explanation": f"Autenticacion de correo debil: {v.get('vector','')}",
                        "recommendation": "Establecer SPF con -all y DMARC p=reject pct=100; revisar muertos en la cadena SPF.",
                        "evidence": f"Dominio: {domain} | {esc(v.get('vector',''))}"
                    }); cat_exposure += 1
            cocci = co.get("cti_chatter") or {}
            if cocci and not cocci.get("error"):
                cti_tot = ((cocci.get("ransomwatch") or {}).get("total") or 0) + ((cocci.get("ransomware_live") or {}).get("total") or 0)
                if cti_tot:
                    rid_counter += 1
                    sev = _sev_label(4, 4)
                    all_risks.append({
                        "id": f"R-{rid_counter:02d}",
                        "desc": f"Chatter CTI (ransomware/leak sites) para {domain}: {cti_tot} mencion(es)",
                        "prob": 4, "imp": 4, "level": sev, "cls": f"r-{sev.lower()}",
                        "explanation": "El dominio u organizacion aparece en listas de ransomware/leak sites, indicando posible victimizacion o suplantacion.",
                        "recommendation": "Investigar cada mencion, priorizar forense si hubo exfiltracion.",
                        "evidence": f"Dominio: {domain} | hits ransomware: {cti_tot}"
                    }); cat_exposure += 1
            coss = co.get("secret_scan") or {}
            if coss and not coss.get("error") and coss.get("critical"):
                ss_detail = "; ".join(f"{g.get('pattern','?')} x{g.get('count')}" for g in coss["critical"][:5])
                rid_counter += 1
                sev = _sev_label(4, 4)
                all_risks.append({
                    "id": f"R-{rid_counter:02d}",
                    "desc": f"Secretos críticos expuestos en HTML de {domain}",
                    "prob": 4, "imp": 4, "level": sev, "cls": f"r-{sev.lower()}",
                    "explanation": "El patron de 80-secrets de Claude-OSINT hallo claves de alto valor en el HTML publicado.",
                    "recommendation": "Rotar inmediatamente los secretos detectados y removerlos del contenido publico.",
                    "evidence": f"Dominio: {domain} | {esc(ss_detail[:400])}"
                }); cat_exposure += 1

        canon_ok = [it for it in collect_pasive_items(p) if it.get("status") == "ok"]
        if canon_ok:
            by_group: dict[str, list] = {}
            for it in canon_ok:
                by_group.setdefault(it.get("grupo") or "Otros", []).append(it)
            canon_detail = "; ".join(
                f"{g}: " + ", ".join(f"{it['label']}={it['valor']}" for it in its[:4])
                for g, its in by_group.items()
            )
            rid_counter += 1
            all_risks.append({
                "id": f"R-{rid_counter:02d}",
                "desc": f"Panorama pasivo canonico de {domain}: {len(canon_ok)} item(s) en {len(by_group)} grupo(s)",
                "prob": 2, "imp": 2, "level": "INFO", "cls": "r-info",
                "explanation": "Set canonico de items pasivos nivel 1 (DNS completo, CT, reputación, OSINT externo, KUMO, Prism, Claude-OSINT, social) recopilado sin interaccion activa con el objetivo.",
                "recommendation": "Revisar cada item del panorama pasivo para priorizar acciones de hardening.",
                "evidence": f"Dominio: {domain} | {esc(canon_detail[:3000])}"
            }); cat_info += 1

        semi_ok = [it for it in collect_semi_active_items(p) if it.get("status") == "ok"]
        if semi_ok:
            sg: dict[str, list] = {}
            for it in semi_ok:
                sg.setdefault(it.get("grupo") or "Otros", []).append(it)
            semi_detail = "; ".join(
                f"{g}: " + ", ".join(f"{it['label']}={it['valor']}" for it in its)
                for g, its in sg.items()
            )
            rid_counter += 1
            all_risks.append({
                "id": f"R-{rid_counter:02d}",
                "desc": f"Panorama semi-activo canonico de {domain}: {len(semi_ok)} item(s) en {len(sg)} grupo(s)",
                "prob": 2, "imp": 2, "level": "INFO", "cls": "r-info",
                "explanation": "Set canonico de items semi-activos nivel 2 (puertos, TLS, HTTPS, cabeceras, rutas públicas, mantenimiento, KUMO/Prism/Claude-OSINT N2) recopilado con interaccion ligera no destructiva.",
                "recommendation": "Revisar cada item del panorama semi-activo para priorizar acciones de hardening.",
                "evidence": f"Dominio: {domain} | {esc(semi_detail[:3000])}"
            }); cat_info += 1

        strix = p.get("strix") or {}
        if strix and strix.get("status") == "ok" and strix.get("findings"):
            findings = strix.get("findings") or []
            by_sev: dict[str, int] = {}
            for f in findings:
                s = (f.get("severity") or "info").lower()
                by_sev[s] = by_sev.get(s, 0) + 1
            top = sorted(findings, key=lambda x: str(x.get('severity','low')).lower() in ("critical","high"), reverse=True)[0]
            strix_detail = "; ".join(
                f"{f.get('severity','?')} {f.get('cve','-')} {f.get('title','?')}" for f in findings[:6]
            )
            rid_counter += 1
            sev_lvl = "CRITICA" if by_sev.get("critical") else ("ALTA" if by_sev.get("high") else "MEDIA" if by_sev.get("medium") else "INFO")
            all_risks.append({
                "id": f"R-{rid_counter:02d}",
                "desc": f"Strix AI Pentest {domain}: {len(findings)} hallazgo(s) validados ({', '.join(f'{k}: {v}' for k,v in by_sev.items())})",
                "prob": 3 if by_sev.get("high") else 2, "imp": 3 if by_sev.get("high") else 2, "level": sev_lvl, "cls": f"r-{sev_lvl.lower()}",
                "explanation": "Strix (usestrix/strix) ejecuto agentes IA de pentesting contra el objetivo validando hallazgos con PoCs reales (modo " + str(strix.get("mode","?")) + ").",
                "recommendation": str(top.get("remediation_steps") or "Revisar cada hallazgo y mitigar segun prioridad.")[:300],
                "evidence": f"Dominio: {domain} | {esc(strix_detail[:2000])}"
            }); 
            if by_sev.get("high") or by_sev.get("critical"):
                cat_exposure += 1
            else:
                cat_info += 1

        if typos:
            typos_detail = "; ".join(f"{t.get('domain','?')} (resuelve: {t.get('ip','?')})" for t in typos[:5])
            rid_counter += 1; sev = _sev_label(3, 3)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Typosquatting detectado para {domain}: {len(typos)} variante(s)",
                "prob": 3, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Dominios con nombres tipograficamente similares al dominio legitimo pueden ser utilizados para campanas de phishing, suplantacion de identidad o distribucion de malware.",
                "recommendation": "Monitorear continuamente registros de dominios similares, considerar la adquisicion de los mas críticos e implementar accion legal contra uso malicioso comprobado.",
                "evidence": f"Dominio original: {domain} | Variantes detectadas: {esc(typos_detail[:400])}"
            }); cat_exposure += 1

        # CVE findings from banner grab
        cve_f = p.get("cve_findings") or []
        if cve_f:
            def _cve_tag(c):
                parts = []
                rs = c.get("risk_score")
                if rs is not None:
                    parts.append(f"Risk:{rs:.1f}")
                epss = c.get("epss_score")
                if epss is not None:
                    parts.append(f"EPSS:{epss*100:.1f}%")
                if c.get("in_kev"):
                    parts.append("KEV")
                return " [" + "/".join(parts) + "]" if parts else ""
            cve_detail = "; ".join(f"{c.get('id','?')} ({c.get('product','?')}:{c.get('port','?')}{_cve_tag(c)})" for c in cve_f[:8])
            kev_count = sum(1 for c in cve_f if c.get("in_kev"))
            extra = ""
            if kev_count:
                extra = f" | {kev_count} en CISA KEV"
            rid_counter += 1; sev = _sev_label(3, 3)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"CVEs potenciales ({len(cve_f)}) en {domain} via banner grab{extra}",
                "prob": 3, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Mediante banner grabbing se identificaron servicios cuyas versiones coinciden con vulnerabilidades conocidas en bases de datos públicas (CVE, Exploit-DB, VulDB). El enriquecimiento EPSS indica probabilidad de explotación y CISA KEV senala vulnerabilidades siendo activamente explotadas. Estos hallazgos requieren verificacion manual para confirmar explotabilidad.",
                "recommendation": "Priorizar CVEs con riesgo compuesto alto (EPSS alto + KEV + severidad). Verificar manualmente cada uno en NVD, aplicar parches disponibles, o implementar mitigaciones como WAF, ACLs de red y segmentacion.",
                "evidence": f"Dominio: {domain} | Coincidencias: {esc(cve_detail[:600])}"
            }); cat_infra += 1

        # URLhaus (per-domain)
        urlhaus = p.get("urlhaus") or {}
        if urlhaus.get("malicious"):
            urlhaus_urls = urlhaus.get("urls") or []
            rid_counter += 1; sev = _sev_label(4, 4)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"URLhaus: dominio malicioso en {domain} ({len(urlhaus_urls)} URL(s))",
                "prob": 4, "imp": 4, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "El dominio ha sido reportado en URLhaus como distribuidor de malware o URLs maliciosas, lo que indica compromiso activo o abuso del dominio para actividades ilegales.",
                "recommendation": "Investigar inmediatamente el origen del reporte, escanear el dominio en busca de malware, y coordinar con el equipo de seguridad para la limpieza.",
                "evidence": f"Dominio: {domain} | URLs maliciosas: {len(urlhaus_urls)} | Error: {urlhaus.get('error', 'N/A')}" + (f" | URLs: {'; '.join(urlhaus_urls[:5])}" if urlhaus_urls else "")
            }); cat_infra += 1

        # Banner service info
        banners = p.get("banner_grabs") or []
        for b in banners:
            if b.get("error"):
                continue
            prod = b.get("product", "desconocido")
            port = b.get("port", "?")
            proto = b.get("protocol", "?")
            rid_counter += 1; sev = _sev_label(1, 1)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Servicio expuesto: {proto} puerto {port} ({prod})",
                "prob": 1, "imp": 1, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "El banner grabbing permite identificar servicios y versiones en puertos abiertos. Esta información es valiosa para un atacante que busca vulnerabilidades especificas.",
                "recommendation": "Evaluar si el servicio es necesario. Mantenerlo actualizado y configurar banners genericos que no revelen versiones.",
                "evidence": f"Dominio: {domain} | Puerto: {port} | Servicio: {proto} | Producto: {prod}"
            }); cat_infra += 1

        # API Endpoints
        api_eps = p.get("api_endpoints") or []
        api_non404 = [e for e in api_eps if e.get("status_code") and e["status_code"] != 404]
        api_shadow = [e for e in api_eps if e.get("is_shadow")]
        if api_non404:
            rid_counter += 1; sev = _sev_label(3, 2) if api_shadow else _sev_label(2, 1)
            total = len(api_eps)
            detail = "; ".join(f"{e.get('method','?')} {e.get('path','?')} (HTTP {e.get('status_code','?')})" for e in api_non404[:8])
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Endpoints API descubiertos: {len(api_non404)} responden ({len(api_shadow)} shadow) en {domain}",
                "prob": 3 if api_shadow else 2, "imp": 2 if api_shadow else 1, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Se descubrieron endpoints API mediante probing de rutas comunes. Los endpoints categorizados como shadow API no estan documentados ni son esperados en servicios publicos, lo que indica posibles shadow APIs, endpoints legacy, o rutas de administracion expuestas.",
                "recommendation": "Revisar cada shadow API, evaluar si debe estar expuesta, agregar autenticacion si es necesaria, o deshabilitar rutas no utilizadas.",
                "evidence": f"Dominio: {domain} | Total rutas probadas: {total} | Responden: {len(api_non404)} | Shadow: {len(api_shadow)} | Detalle: {esc(detail[:500])}"
            }); cat_infra += 1
        for ep in api_shadow:
            rid_counter += 1; sev = _sev_label(3, 3)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Shadow API: {ep.get('method','?')} {ep.get('path','?')} (HTTP {ep.get('status_code','?')})",
                "prob": 3, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Endpoint no documentado que responde con datos. Los atacantes pueden descubrir shadow APIs mediante fuzzing de rutas comunes y explotarlas para acceder a funcionalidades no previstas.",
                "recommendation": "Investigar si el endpoint es legitimo. Si no es necesario, deshabilitarlo. Si es necesario, protegerlo con autenticacion y monitoreo.",
                "evidence": f"Dominio: {domain} | Ruta: {ep.get('path','?')} | Metodo: {ep.get('method','?')} | Status: {ep.get('status_code','?')} | Categoria: {ep.get('category','?')} | Body: {(ep.get('body_preview') or '')[:200]}"
            }); cat_infra += 1

        # Public Paths
        paths = p.get("public_paths") or []
        interesting = [x for x in paths if x.get("status_code") not in (None, 404)]
        if interesting:
            rid_counter += 1; sev = _sev_label(2, 1)
            detail = "; ".join(f"{x.get('path','')} (HTTP {x.get('status_code','?')})" for x in interesting[:8])
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Rutas públicas accesibles: {len(interesting)} responden en {domain}",
                "prob": 2, "imp": 1, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Se encontraron rutas web públicas accesibles que pueden exponer información sensible (robots.txt, security.txt, health endpoints, esquemas API) o servir como punto de entrada para ataques.",
                "recommendation": "Revisar cada ruta accesible. Deshabilitar las innecesarias y proteger las requeridas con autenticacion.",
                "evidence": f"Dominio: {domain} | Rutas: {esc(detail[:500])}"
            }); cat_infra += 1

        # STARTTLS
        starttls_results = dns.get("starttls_results") or []
        starttls_ok = any(r.get("starttls_ok") for r in starttls_results) if starttls_results else None
        if starttls_results and not starttls_ok:
            rid_counter += 1; sev = _sev_label(3, 3)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"STARTTLS no soportado en MX para {domain}",
                "prob": 3, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "STARTTLS permite cifrar la comunicacion entre servidores de correo. Sin el, los correos se transmiten en texto plano y pueden ser interceptados.",
                "recommendation": "Configurar STARTTLS en todos los servidores MX y verificar soporte mediante test de conectividad.",
                "evidence": f"Dominio: {domain} | MX sin STARTTLS: {sum(1 for r in starttls_results if not r.get('starttls_ok'))} de {len(starttls_results)}"
            }); cat_email += 1

        # DANE/TLSA
        dane_records = dns.get("dane_records") or []
        if not dane_records:
            rid_counter += 1; sev = _sev_label(2, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"DANE/TLSA no configurado en {domain}",
                "prob": 2, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "DANE (TLSA) permite asociar certificados TLS a traves de DNSSEC, previniendo ataques de CA comprometidas.",
                "recommendation": "Configurar registros TLSA en el DNS firmado con DNSSEC para asociar certificados TLS especificos.",
                "evidence": f"Dominio: {domain} | Registros DANE/TLSA: Ausentes"
            }); cat_infra += 1

        # IPv6
        ipv6_records = dns.get("ipv6") or []
        if not ipv6_records:
            rid_counter += 1; sev = _sev_label(1, 1)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"IPv6 (AAAA) no configurado en {domain}",
                "prob": 1, "imp": 1, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "El dominio no tiene registros AAAA para IPv6. Aunque no es un riesgo de seguridad directo, limita la accesibilidad.",
                "recommendation": "Evaluar la implementacion de IPv6 y configurar registros AAAA si esta disponible.",
                "evidence": f"Dominio: {domain} | Registros AAAA: Ausentes"
            }); cat_infra += 1

        # MTA-STS
        if not p.get("mta_sts"):
            rid_counter += 1; sev = _sev_label(2, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"MTA-STS no configurado en {domain}",
                "prob": 2, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "MTA-STS permite a los dominios publicar políticas para exigir TLS en la entrega de correo entre servidores MX.",
                "recommendation": "Configurar MTA-STS publicando política en _mta-sts.<dominio> con modo 'enforce'.",
                "evidence": f"Dominio: {domain} | MTA-STS: Ausente"
            }); cat_email += 1

        # TLS-RPT
        if not p.get("tls_rpt"):
            rid_counter += 1; sev = _sev_label(1, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"TLS-RPT no configurado en {domain}",
                "prob": 1, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "TLS-RPT permite recibir informes sobre fallos de TLS en la entrega de correo entre servidores MX.",
                "recommendation": "Configurar TLS-RPT con direccion de correo para recibir informes de fallos TLS.",
                "evidence": f"Dominio: {domain} | TLS-RPT: Ausente"
            }); cat_email += 1

        # BIMI
        if not p.get("bimi"):
            rid_counter += 1; sev = _sev_label(1, 1)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"BIMI no configurado en {domain}",
                "prob": 1, "imp": 1, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "BIMI permite mostrar el logotipo de la marca junto a los correos autenticados en clientes compatibles.",
                "recommendation": "Configurar BIMI publicando el logo corporativo verificado en el DNS.",
                "evidence": f"Dominio: {domain} | BIMI: Ausente"
            }); cat_email += 1

        # SAN list
        san_list = tls_data.get("san_list") or []
        if san_list:
            rid_counter += 1; sev = _sev_label(1, 1)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"{len(san_list)} SAN(s) en certificado de {domain}",
                "prob": 1, "imp": 1, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "El certificado TLS incluye nombres alternativos (SAN). SAN excesivos amplian la superficie de ataque.",
                "recommendation": "Revisar que los SAN incluidos sean los estrictamente necesarios.",
                "evidence": f"Dominio: {domain} | SAN: {'; '.join(san_list[:8])}"
            }); cat_infra += 1

        # Certificate issuer/expiry
        cert_subject = tls_data.get("cert_subject") or ""
        cert_issuer = tls_data.get("cert_issuer") or ""
        cert_expiry = tls_data.get("cert_expiry") or ""
        if cert_subject or cert_issuer or cert_expiry:
            rid_counter += 1; sev = _sev_label(1, 1)
            cert_detail_parts = []
            if cert_subject: cert_detail_parts.append(f"CN: {cert_subject}")
            if cert_issuer: cert_detail_parts.append(f"Emitido por: {cert_issuer}")
            if cert_expiry: cert_detail_parts.append(f"Expira: {cert_expiry}")
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Certificado TLS detectado en {domain}",
                "prob": 1, "imp": 1, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Informacion del certificado TLS del servidor. Verificar su validez y fecha de expiracion.",
                "recommendation": "Verificar que el certificado sea valido, emitido por una CA confiable y no este próximo a expirar.",
                "evidence": f"Dominio: {domain} | {' | '.join(cert_detail_parts)}"
            }); cat_infra += 1

        # Referrer-Policy
        if not headers.get("referrer-policy"):
            rid_counter += 1; sev = _sev_label(1, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Referrer-Policy ausente en {domain}",
                "prob": 1, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Referrer-Policy controla cuanta información de la URL de referencia se envia al navegar a otros sitios.",
                "recommendation": "Configurar Referrer-Policy: strict-origin-when-cross-origin o same-origin.",
                "evidence": f"Dominio: {domain} | Referrer-Policy: Ausente"
            }); cat_config += 1

        # Permissions-Policy
        if not headers.get("permissions-policy"):
            rid_counter += 1; sev = _sev_label(1, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Permissions-Policy ausente en {domain}",
                "prob": 1, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Permissions-Policy controla que APIs del navegador puede usar el sitio y sus iframes.",
                "recommendation": "Configurar Permissions-Policy para restringir APIs sensibles: camera=(), microphone=(), geolocation=().",
                "evidence": f"Dominio: {domain} | Permissions-Policy: Ausente"
            }); cat_config += 1

        # COOP
        if not headers.get("cross-origin-opener-policy"):
            rid_counter += 1; sev = _sev_label(1, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Cross-Origin-Opener-Policy ausente en {domain}",
                "prob": 1, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "COOP aisla ventanas de origen cruzado para prevenir ataques de tipo cross-origin leak como Spectre.",
                "recommendation": "Configurar Cross-Origin-Opener-Policy: same-origin para aislar ventanas de contexto cruzado.",
                "evidence": f"Dominio: {domain} | COOP: Ausente"
            }); cat_config += 1

        # Redirect chain
        redirects = https.get("redirect_chain") or []
        if len(redirects) > 1:
            rid_counter += 1; sev = _sev_label(1, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Redirecciones HTTP en {domain}: {len(redirects)} salto(s)",
                "prob": 1, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Multiples redirecciones HTTP pueden afectar rendimiento y exponer URLs internas.",
                "recommendation": "Minimizar las redirecciones configurando la URL canonica directamente en el servidor origen.",
                "evidence": f"Dominio: {domain} | Cadena: {' -> '.join(redirects[:5])}"
            }); cat_infra += 1

        # X-Powered-By
        xpb = headers.get("x-powered-by") or ""
        if xpb:
            rid_counter += 1; sev = _sev_label(1, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Tecnologia revelada en {domain}: {xpb}",
                "prob": 1, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "La cabecera X-Powered-By revela la tecnologia o framework utilizado por el servidor.",
                "recommendation": "Eliminar o deshabilitar la cabecera X-Powered-By en la configuración del servidor.",
                "evidence": f"Dominio: {domain} | X-Powered-By: {xpb}"
            }); cat_config += 1

        # Supply chain dependencies
        supply = p.get("supply_chain") or []
        if supply:
            rid_counter += 1; sev = _sev_label(2, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Dependencias de terceros en {domain}: {len(supply)}",
                "prob": 2, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Dependencias externas incrementan la superficie de ataque y el riesgo de supply chain compromise.",
                "recommendation": "Auditar las dependencias de terceros, verificar su reputación y mantenerlas actualizadas.",
                "evidence": f"Dominio: {domain} | Terceros: {'; '.join(s.get('domain','?') for s in supply[:8])}"
            }); cat_app += 1

        # OWASP Compliance
        owasp_data = matrix_by_domain.get(domain, {}).get("owasp") or {}
        if owasp_data:
            owasp_grade = owasp_data.get("overall_grade", "N/A")
            owasp_pct = owasp_data.get("percentage", owasp_data.get("overall_compliance", 0))
            owasp_findings = owasp_data.get("findings") or []
            rid_counter += 1; sev = "INFO"
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"OWASP Compliance Grade: {owasp_grade} ({owasp_pct}%) en {domain}",
                "prob": 0, "imp": 0, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": f"Evaluacion OWASP del dominio con calificación {owasp_grade} ({owasp_pct}%) y {len(owasp_findings)} hallazgos identificados.",
                "recommendation": "Revisar los hallazgos OWASP detallados y priorizar la correccion de los de alto riesgo.",
                "evidence": f"Dominio: {domain} | Grade: {owasp_grade} | Compliance: {owasp_pct}% | Hallazgos: {len(owasp_findings)}"
            }); cat_info += 1

        # Social media
        social = p.get("social") or {}
        if social:
            social_lines = [f"{net}: @{data.get('username','?')}" for net, data in social.items() if not data.get("error")]
            if social_lines:
                rid_counter += 1; sev = _sev_label(1, 1)
                all_risks.append({
                    "id": f"R-{rid_counter:02d}", "desc": f"Perfiles redes sociales detectados para {domain} ({len(social_lines)})",
                    "prob": 1, "imp": 1, "level": sev, "cls": f"r-{sev.lower()}",
                    "explanation": "Perfiles en redes sociales asociados al dominio. Perfiles no oficiales podrian ser utilizados para suplantacion.",
                    "recommendation": "Verificar que todos los perfiles sean oficiales y esten gestionados por el equipo de comunicaciones.",
                    "evidence": f"Dominio: {domain} | {'; '.join(social_lines[:8])}"
                }); cat_exposure += 1


    # Vulns
    for v in vulnerabilities:
        vid = v.get("id", v.get("cve", "CVE"))
        v_severity = v.get("severity", v.get("priority", "N/A"))
        v_desc = v.get("summary", v.get("description", ""))[:120]
        rid_counter += 1; sev = _sev_label(3, 4)
        all_risks.append({
            "id": f"R-{rid_counter:02d}", "desc": f"Vulnerabilidad {vid} en {domain}",
            "prob": 3, "imp": 4, "level": sev, "cls": f"r-{sev.lower()}",
            "explanation": f"Vulnerabilidad conocida ({vid}) identificada en las tecnologias utilizadas por el dominio. {esc(v_desc)}",
            "recommendation": "Aplicar el parche de seguridad proporcionado por el fabricante. Si no esta disponible, implementar mitigaciones temporales como reglas de WAF o segmentacion.",
            "evidence": f"Dominio: {domain} | CVE: {esc(vid)} | Severidad: {esc(str(v_severity))} | Descripcion: {esc(v_desc)}"
        }); cat_app += 1

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
            rid_counter += 1; sev = _sev_label(2, 3)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Archivos JavaScript expuestos en {domain} ({len(all_js)})",
                "prob": 2, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Los archivos JavaScript expuestos pueden revelar logica de negocio, endpoints internos o secretos embebidos como API keys o tokens de acceso.",
                "recommendation": "Revisar archivos JS para evitar inclusion de secretos, API keys o endpoints internos. Considerar ofuscacion y SRI.",
                "evidence": f"Dominio: {domain} | JS expuestos: {len(all_js)} | Crawler: {len(fr_js)} | Wayback: {len(fr_wb_js)}"
            }); cat_app += 1
        if fr_ext:
            rid_counter += 1; sev = _sev_label(1, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Enlaces externos detectados en {domain} ({len(fr_ext)})",
                "prob": 1, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Los enlaces externos en la página web pueden revelar relaciones con terceros, CDNs o servicios externos que amplian la superficie de ataque.",
                "recommendation": "Auditar los recursos externos y asegurar que sean de fuentes confiables.",
                "evidence": f"Dominio: {domain} | Enlaces externos: {len(fr_ext)} | Ejemplos: {'; '.join(fr_ext[:3])}"
            }); cat_exposure += 1
        if fr_sitemap:
            rid_counter += 1; sev = _sev_label(1, 2)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Sitemap expuesto en {domain} ({len(fr_sitemap)} URLs)",
                "prob": 1, "imp": 2, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "El sitemap.xml expone todas las rutas del sitio, facilitando el reconocimiento a atacantes que pueden usar esta información para mapear la aplicacion.",
                "recommendation": "Verificar que el sitemap solo contenga URLs destinadas a indexacion pública.",
                "evidence": f"Dominio: {domain} | URLs en sitemap: {len(fr_sitemap)}"
            }); cat_exposure += 1
        if fr_wb_js:
            rid_counter += 1; sev = _sev_label(2, 3)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"JS históricos en Wayback Machine para {domain} ({len(fr_wb_js)})",
                "prob": 2, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Los archivos JS históricos en Wayback Machine pueden contener código sensible obsoleto o versiones anteriores con vulnerabilidades que ya no existen en la version actual.",
                "recommendation": "Revisar los JS históricos y considerar solicitar su eliminacion de Wayback Machine si contienen datos sensibles.",
                "evidence": f"Dominio: {domain} | JS históricos Wayback: {len(fr_wb_js)}"
            }); cat_exposure += 1
        if fr_wb_api:
            rid_counter += 1; sev = _sev_label(3, 4)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Endpoints API en Wayback Machine para {domain} ({len(fr_wb_api)})",
                "prob": 3, "imp": 4, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "Endpoints API descubiertos en Wayback Machine pueden exponer funcionalidades internas o datos sensibles sin autenticacion.",
                "recommendation": "Revisar que estos endpoints requieran autenticacion y no expongan funcionalidades sensibles.",
                "evidence": f"Dominio: {domain} | Endpoints API Wayback: {len(fr_wb_api)} | Ejemplos: {'; '.join(fr_wb_api[:3])}"
            }); cat_app += 1
        if fr_wb_params:
            rid_counter += 1; sev = _sev_label(2, 3)
            all_risks.append({
                "id": f"R-{rid_counter:02d}", "desc": f"Parametros sensibles en Wayback Machine para {domain} ({len(fr_wb_params)})",
                "prob": 2, "imp": 3, "level": sev, "cls": f"r-{sev.lower()}",
                "explanation": "URLs con parametros potencialmente sensibles (tokens, IDs, claves) en archivos históricos pueden exponer datos privados o permitir acceso no autorizado.",
                "recommendation": "Auditar los parametros sensibles y asegurarse de que no expongan datos privados o permitan acceso no autorizado.",
                "evidence": f"Dominio: {domain} | Params sensibles Wayback: {len(fr_wb_params)} | Ejemplos: {'; '.join(fr_wb_params[:3])}"
            }); cat_app += 1

    # Sort by severity (CRITICO first)
    sev_order = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3}
    all_risks.sort(key=lambda r: (sev_order.get(r["level"], 99), r["id"]))

    # Detailed findings cards HTML (with explanation, recommendation, evidence)
    detail_cards = ""
    for r in all_risks:
        detail_cards += f"""<div class="f-card">
        <div class="f-hdr">
            <span class="f-id r-badge {r['cls']}">{esc(r['id'])}</span>
            <span class="f-lvl r-badge {r['cls']}">{esc(r['level'])}</span>
            <span style="margin-left:12px;font-size:11px;color:var(--text-muted);">Prob: {r['prob']}/5 &nbsp;|&nbsp; Impacto: {r['imp']}/5</span>
        </div>
        <div class="f-title">{esc(r['desc'][:200])}</div>
        <div class="f-body">
            <div class="f-section"><span class="f-label">Explicacion</span><p class="f-text">{esc(r['explanation'])}</p></div>
            <div class="f-section"><span class="f-label">Recomendación</span><p class="f-text">{esc(r['recommendation'])}</p></div>
            <div class="f-section"><span class="f-label">Evidencia</span><pre class="f-evidence">{esc(r['evidence'])}</pre></div>
        </div>
    </div>"""

    # Critical-analysis narrative based on actual top risks
    crit_risks = [r for r in all_risks if r["level"] == "CRITICO"]
    high_risks = [r for r in all_risks if r["level"] == "ALTO"]
    if crit_risks:
        analysis_note = (
            f"El riesgo <strong>{crit_risks[0]['id']} ({crit_risks[0]['desc'][:100]})</strong> representa la amenaza mas inmediata. "
            f"Se identificaron <strong>{len(crit_risks)} riesgo(s) crítico(s)</strong> y "
            f"<strong>{len(high_risks)} alto(s)</strong> que requieren atención prioritaria."
        )
    else:
        analysis_note = (
            f"No se identificaron riesgos críticos. "
            f"Se identificaron <strong>{len(high_risks)} riesgo(s) alto(s)</strong> que requieren atención."
        )

    # Bar chart: aggregate top risk categories
    bar_agg: dict[str, float] = {}
    for r in all_risks:
        key = r["desc"].split(":")[0].split(" en ")[0][:50]
        bar_agg[key] = bar_agg.get(key, 0) + (r["prob"] * r["imp"]) / 5.0
    bar_sorted = sorted(bar_agg.items(), key=lambda x: -x[1])[:6]
    bar_palette = ["#173B57", "#2F6F9F", "#2E7D32", "#F9A825", "#EF6C00", "#D9DEE3"]
    bar_items = [(k, min(v, 5.0), bar_palette[i % 6]) for i, (k, v) in enumerate(bar_sorted)]

    # Donut: distribution by category
    cat_map = {k: v for k, v in [("Configuracion", cat_config), ("Exposicion", cat_exposure),
                                  ("Correo", cat_email), ("Aplicacion", cat_app),
                                  ("Infraestructura", cat_infra), ("Web", cat_web),
                                  ("Info", cat_info)] if v > 0}
    if not cat_map:
        cat_map = {"Configuracion": 0}
    ccolors = {"Configuracion": "#374151", "Exposicion": "#173B57", "Correo": "#6B7280",
               "Aplicacion": "#9CA3AF", "Infraestructura": "#1F2933", "Web": "#D1D5DB",
               "Info": "#D9DEE3"}
    distrib_segments = [(k, float(v), ccolors.get(k, "#64748b")) for k, v in cat_map.items()]

    # --- Controls derived from real data ---
    def _ctrl_state(p, name):
        d = p.get("dns") or {}; h = (p.get("https") or {}).get("headers") or {}; t = p.get("tls") or {}
        if name == "HTTPS":
            sc = (p.get("https") or {}).get("status_code")
            return "PASS" if sc and 200 <= sc < 500 else "FAIL"
        if name == "TLS 1.2/1.3":
            tv = t.get("negotiated_version") or ""
            return "PASS" if "1.3" in tv or "1.2" in tv else ("Error" if t.get("error") else "FAIL")
        if name == "HSTS":
            return "PASS" if h.get("strict-transport-security") else "FAIL"
        if name == "CSP":
            c = h.get("content-security-policy") or h.get("content-security-policy-report-only") or ""
            if not c: return "No implementado"
            return "PARTIAL" if p.get("csp_findings") else "PASS"
        if name == "SPF":
            s = d.get("spf_record")
            if not s: return "No implementado"
            return "PASS" if "-all" in s or "~all" in s else "PARTIAL"
        if name == "DMARC":
            dm = d.get("dmarc_record")
            if not dm: return "No implementado"
            return "PASS" if d.get("dmarc_policy") == "reject" else "PARTIAL"
        if name == "DNSSEC":
            return "PASS" if d.get("dnssec_ok") else "FAIL"
        if name == "CAA":
            return "PASS" if p.get("caa_records") else "FAIL"
        if name == "Server Banner":
            fp = h.get("server_fingerprint", "") or (p.get("https") or {}).get("server_fingerprint", "") or ""
            return "Expuesto" if fp else "No detectado"
        return "No verificado"

    def _consensus(states):
        if all(s == "PASS" for s in states): return "PASS", " control implementado en todos los activos"
        if any(s == "FAIL" for s in states): return "FAIL", " ausente en al menos un activo"
        if any(s == "Error" for s in states): return "Error", " con errores en algunos activos"
        return "Parcial", " implementacion inconsistente entre activos"

    control_defs = ["HTTPS", "TLS 1.2/1.3", "HSTS", "CSP", "SPF", "DMARC", "DNSSEC", "CAA", "Server Banner"]
    control_items = []
    for cname in control_defs:
        states = [_ctrl_state(p, cname) for p in providers if p]
        state, obs_suffix = _consensus(states)
        control_items.append((cname, state, f"{cname}{obs_suffix}"))

    ctrl_implemented = sum(1 for _, s, _ in control_items if s == "PASS")
    ctrl_parcial = sum(1 for _, s, _ in control_items if "Parcial" in s)
    ctrl_no = sum(1 for _, s, _ in control_items if "No" in s or "Expuesto" in s or "Error" in s)

    ctrl_rows = ""
    for cname, cstatus, cobs in control_items:
        cls = "s-implementado" if cstatus == "PASS" else "s-parcial" if cstatus == "PARTIAL" else "s-no" if "No" in cstatus else "s-expuesto"
        ctrl_rows += f"<tr><td>{esc(cname)}</td><td class='{cls}'>{esc(cstatus)}</td><td>{esc(cobs)}</td></tr>"

    # Build provider IPs set
    all_ips: set[str] = set()
    for p in providers:
        for ip in (p.get("dns") or {}).get("ipv4") or []:
            all_ips.add(ip)

    # --- Compute security score ---
    score = 100.0
    for p in providers:
        dns = p.get("dns") or {}
        https = p.get("https") or {}
        hdrs = https.get("headers") or {}
        tls_data = p.get("tls") or {}
        if not hdrs.get("strict-transport-security"): score -= 8
        csp = hdrs.get("content-security-policy") or hdrs.get("content-security-policy-report-only") or ""
        if not csp: score -= 5
        if csp and p.get("csp_findings"): score -= 3
        if not dns.get("spf_record"): score -= 5
        if not dns.get("dmarc_record"): score -= 5
        if not dns.get("dnssec_ok"): score -= 3
        if not p.get("caa_records"): score -= 2
        if tls_data.get("error"): score -= 5
        score -= len(p.get("vulnerabilities") or []) * 3
        score -= sum(1 for x in (p.get("patching") or []) if x.get("status") == "eol") * 8
        score -= sum(1 for l in (p.get("credential_leaks") or []) if "error" not in l) * 6
        score -= len(p.get("takeover_risks") or []) * 5
        open_list = [o for o in (p.get("open_ports") or []) if o.get("state") == "open"]
        if len(open_list) > 2: score -= (len(open_list) - 2) * 2
        score -= len(p.get("typosquatting") or []) * 2
        if not hdrs.get("x-content-type-options"): score -= 2
        if not hdrs.get("x-frame-options") and not hdrs.get("x-xss-protection"): score -= 2
    score = max(0, min(100, int(score)))

    # Resumen Ejecutivo canónico (estilo Beta1) — usa mismo score que Security Trust Score
    resumen_block = render_resumen_ejecutivo(providers, asm, score_general=score, fecha_str=str(asm.get("generated_utc","")), org="Incocredito", analista="@eduingt")

    
    score_legend_block = render_score_legend()    # Precia-like scorecard (estilo SecurityScorecard)
    precia_blocks = "\n".join(render_precialike_block(pr, analista="@eduingt", org=pr.get("name") or pr.get("domain",""), generated=str(asm.get("generated_utc",""))) for pr in providers)

    score_interpretation = (
        "Postura de seguridad critica, se requiere atención inmediata" if score < 30 else
        "Postura de seguridad deficiente, se requieren mejoras urgentes" if score < 50 else
        "Postura de seguridad por debajo del promedio del sector" if score < 70 else
        "Postura de seguridad aceptable con margen de mejora" if score < 85 else
        "Postura de seguridad solida"
    )

    indicators = [
        ("Security Trust Score", f"{score}/100", score_interpretation),
        ("Domain Score heuristico", f"{int(sum(domain_score(pr) for pr in providers) / max(len(providers), 1))}/100" if providers else "N/A", "Heuristica de seguridad del dominio promedio"),
        ("Subdominios totales", str(total_subs + total_crt + total_brute), "Superficie de ataque digital"),
        ("Puertos abiertos", str(total_open_ports), "Servicios expuestos a internet"),
        ("Vulnerabilidades", str(total_vulns), "Potenciales vectores de ataque"),
    ]
    if total_leaks:
        indicators.append(("Credenciales filtradas", str(total_leaks), "Brechas de seguridad activas"))
    if total_takeover:
        indicators.append(("Riesgos de takeover", str(total_takeover), "Subdominios vulnerables a apropiacion"))

    # --- Recommendations derived from actual findings ---
    recs_urgent: list[tuple[str, str, str]] = []
    recs_strategic: list[tuple[str, str, str]] = []
    recs_improve: list[tuple[str, str, str]] = []

    # DMARC
    dmarc_missing = any(not (p.get("dns") or {}).get("dmarc_record") for p in providers)
    dmarc_not_reject = any(((p.get("dns") or {}).get("dmarc_policy") or "") != "reject" for p in providers if (p.get("dns") or {}).get("dmarc_record"))
    if dmarc_missing or dmarc_not_reject:
        recs_urgent.append((
            "Implementar política DMARC estricta (p=reject)",
            "Configurar DMARC con política de rechazo y monitoreo de informes para prevenir suplantacion de dominio.",
            "ALTA"
        ))

    # HSTS
    hsts_missing = any(not (((p.get("https") or {}).get("headers") or {}).get("strict-transport-security")) for p in providers)
    if hsts_missing:
        recs_urgent.append((
            "Configurar HSTS en todos los dominios",
            "Implementar Strict-Transport-Security con max-age suficiente para mitigar ataques SSL stripping.",
            "ALTA"
        ))

    # EOL
    eol_found = any(x.get("status") == "eol" for p in providers for x in (p.get("patching") or []))
    if eol_found:
        recs_urgent.append((
            "Actualizar software con versiones EOL",
            "Identificar y actualizar todas las tecnologias que han llegado al final de su vida util. Priorizar las expuestas a internet.",
            "ALTA"
        ))

    # Credential leaks
    if total_leaks:
        recs_urgent.append((
            "Gestionar filtraciones de credenciales",
            f"Se detectaron {total_leaks} filtraciones en breaches conocidos. Rotar credenciales comprometidas e implementar 2FA.",
            "ALTA"
        ))

    # Takeover
    if total_takeover:
        recs_urgent.append((
            "Mitigar riesgos de subdomain takeover",
            "Eliminar o asegurar registros DNS que apuntan a servicios externos no controlados.",
            "ALTA"
        ))

    # CSP
    csp_missing = any(not (((p.get("https") or {}).get("headers") or {}).get("content-security-policy") or ((p.get("https") or {}).get("headers") or {}).get("content-security-policy-report-only")) for p in providers)
    csp_weak = any(p.get("csp_findings") for p in providers)
    if csp_missing or csp_weak:
        recs_strategic.append((
            "Implementar CSP estricta",
            "Configurar Content-Security-Policy con directivas restrictivas para mitigar XSS y ataques de inyeccion.",
            "MEDIA"
        ))

    # Open ports
    excessive_ports = any(len([o for o in (p.get("open_ports") or []) if o.get("state") == "open"]) > 3 for p in providers)
    if excessive_ports:
        recs_strategic.append((
            "Reducir superficie de puertos expuestos",
            "Restringir el acceso a servicios administrativos solo a IPs autorizadas mediante firewalls o VPN.",
            "MEDIA"
        ))

    # DNSSEC
    dnssec_missing = any(not (p.get("dns") or {}).get("dnssec_ok") for p in providers)
    if dnssec_missing:
        recs_strategic.append((
            "Implementar DNSSEC",
            "Firmar las zonas DNS para evitar envenenamiento de cache y redirecciones maliciosas.",
            "MEDIA"
        ))

    # SPF
    spf_missing = any(not (p.get("dns") or {}).get("spf_record") for p in providers)
    if spf_missing:
        recs_strategic.append((
            "Configurar registro SPF con hard fail",
            "Implementar SPF con mecanismo -all para evitar la suplantacion desde servidores no autorizados.",
            "MEDIA"
        ))

    # Typosquatting
    if total_typos:
        recs_strategic.append((
            "Monitorear y gestionar typosquatting",
            f"Se detectaron {total_typos} dominios tipograficamente similares. Considerar adquisicion o accion legal.",
            "MEDIA"
        ))

    # Always add baseline improvements
    recs_improve.append((
        "Establecer programa de bug bounty",
        "Incentivar la divulgacion responsable de vulnerabilidades por parte de investigadores externos.",
        "BAJA"
    ))
    recs_improve.append((
        "Implementar monitoreo continuo de superficie de ataque",
        "Establecer revisión periodica de la huella digital y detección temprana de nuevos activos.",
        "MEDIA"
    ))
    recs_improve.append((
        "Desarrollar plan de respuesta a incidentes para terceros",
        "Definir procedimientos claros para la gestion de incidentes que involucren proveedores.",
        "MEDIA"
    ))

    def render_recs(recs: list[tuple[str, str, str]]) -> str:
        out = ""
        for i, (title, desc, prio) in enumerate(recs):
            p_cls = f"prio-{prio.lower()}"
            out += f"""<div class="rec-card">
                <div class="rec-num">Recomendación #{i+1}</div>
                <div class="rec-title">{esc(title)}</div>
                <div class="rec-desc">{esc(desc)}</div>
                <span class="rec-prio {p_cls}">{esc(prio)}</span>
            </div>"""
        return out

    # Sources
    sources = [
        ("Datos tecnicos", "Escaneo ASM directo, registros DNS, cabeceras HTTP, análisis TLS, CT logs"),
        ("OSINT", "Shodan, Censys, DNSDumpster, theHarvester, whois"),
        ("Reputacion", "DNSBL, URLhaus, leak-lookup, CVE/NVD, OSV.dev"),
        ("Marcos de referencia", "NIST CSF, ISO/IEC 27001, CIS Controls, OWASP Top 10, MITRE ATT&CK"),
        ("Estandares", "RFC 6797 (HSTS), RFC 7489 (DMARC), RFC 7208 (SPF), RFC 8461 (MTA-STS)"),
        ("Herramientas", "Nuclei (ProjectDiscovery), Shodan CLI, Censys CLI, webtech, PDQ/ASM"),
    ]
    sources_html = "".join(f"<tr><td><strong>{esc(s[0])}</strong></td><td>{esc(s[1])}</td></tr>" for s in sources)

    # Build HTML document -------------------------------------------------
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Evaluación de Postura de Seguridad de Terceros</title>
<style>{CSS}</style>
</head>
<body>
<div class="page">

<!-- ======== PORTADA ======== -->
<div class="cover">
    <div class="tag">Documento Clasificado</div>
    <h1>Evaluación de Postura<br>de Seguridad de Terceros</h1>
    <h2>Informe Ejecutivo</h2>
    <div class="accent-line"></div>
    <div class="meta">
        <strong>Realizado por:</strong> {esc(analista)}<br>
        <strong>Objetivo:</strong> {esc(domains_list)}<br>
        <strong>Organizacion:</strong> {esc(org)}<br>
        <strong>Fecha:</strong> {esc(now.split()[0])}<br>
        <strong>Fuentes:</strong> Fuentes propias, OSINT, registros DNS, CT logs, bases de datos de vulnerabilidades<br>
        <strong>Clasificación:</strong> Confidencial - Solo para uso interno
    </div>
</div>

<!-- ======== TOC ======== -->
<div class="toc">
    <h2>Índice</h2>
    <div class="toc-item"><span class="num">1</span><span class="title">Resumen Ejecutivo</span><span class="page">3</span></div>
    <div class="toc-item"><span class="num">2</span><span class="title">Análisis de Riesgos</span><span class="page">4</span></div>
    <div class="toc-sub toc-item"><span class="num">2.1</span><span class="title">Riesgos Identificados</span><span class="page">4</span></div>
    <div class="toc-sub toc-item"><span class="num">2.2</span><span class="title">Matriz de Probabilidad e Impacto</span><span class="page">5</span></div>
    <div class="toc-sub toc-item"><span class="num">2.3</span><span class="title">Evaluación de Superficie de Ataque</span><span class="page">5</span></div>
    <div class="toc-item"><span class="num">3</span><span class="title">Recomendaciones</span><span class="page">6</span></div>
    <div class="toc-sub toc-item"><span class="num">3.1</span><span class="title">Acciones Prioritarias (0-30 dias)</span><span class="page">6</span></div>
    <div class="toc-sub toc-item"><span class="num">3.2</span><span class="title">Acciones Estrategicas (1-3 meses)</span><span class="page">6</span></div>
    <div class="toc-sub toc-item"><span class="num">3.3</span><span class="title">Mejora Continua (3-12 meses)</span><span class="page">7</span></div>
    <div class="toc-item"><span class="num">4</span><span class="title">Estado de Seguridad Actual</span><span class="page">7</span></div>
    <div class="toc-sub toc-item"><span class="num">4.1</span><span class="title">Postura de Seguridad Actual</span><span class="page">7</span></div>
    <div class="toc-sub toc-item"><span class="num">4.2</span><span class="title">Indicadores de Riesgo Agregados</span><span class="page">8</span></div>
    <div class="toc-item"><span class="num">5</span><span class="title">Conclusiones</span><span class="page">8</span></div>
    <div class="toc-item"><span class="num">6</span><span class="title">Fuentes y Referencias</span><span class="page">9</span></div>
</div>

<!-- ======== 1. RESUMEN EJECUTIVO ======== -->
{resumen_block}

  {score_legend_block}

  <div class="sec">
    <div class="sec-title"><span class="sn">01</span><span class="st">Resumen Ejecutivo</span><span class="line"></span></div>
    <div class="narrative">
        <p>Se realizo una evaluación integral de la postura de seguridad de <strong>{esc(domains_list)}</strong> como parte del programa de gestion de riesgos de terceros. El análisis combina técnicas de evaluación activa y pasiva, inteligencia de fuentes abiertas (OSINT) y consulta a bases de datos de vulnerabilidades y filtraciones conocidas.</p>
        <br>
        <p><strong>Hallazgos principales:</strong></p>
        <ul class="compact">
            <li>Se identificaron <strong>{total_subs + total_crt}</strong> subdominios en {len(providers)} proveedor(es), de los cuales <strong>{total_subs}</strong> fueron descubiertos mediante enumeracion activa y <strong>{total_crt}</strong> mediante registros de Certificate Transparency.</li>
            <li><strong>{total_vulns}</strong> vulnerabilidades potenciales identificadas en las tecnologias detectadas.</li>
            <li><strong>{total_leaks}</strong> filtraciones de credenciales encontradas en bases de datos de breaches.</li>
            <li><strong>{total_open_ports}</strong> puertos abiertos descubiertos en las IPs evaluadas.</li>
            <li><strong>{total_takeover}</strong> riesgo(s) de subdomain takeover detectado(s).</li>
            <li><strong>{total_typos}</strong> variantes de typosquatting registradas y resolviendo.</li>
        </ul>
        <br>
        <p><strong>Calificación general: {score}/100</strong> — {esc(score_interpretation)}. Se requiere atención inmediata en los hallazgos de prioridad critica y alta.</p>
    </div>
</div>

<!-- ======== 2. ANÁLISIS DE RIESGOS ======== -->
<div class="sec">
    <div class="sec-title"><span class="sn">02</span><span class="st">Análisis de Riesgos</span><span class="line"></span></div>

    <!-- 2.1 Riesgos Identificados -->
    <div class="sec-sub">2.1 Riesgos Identificados</div>
    <div class="narrative">
        <p><strong>Análisis de riesgos críticos:</strong> {analysis_note}</p>
    </div>
    <div style="margin-bottom:8px;font-size:12px;color:var(--text-muted);">Cada hallazgo incluye explicacion detallada, recomendación de mitigación y evidencia técnica del escaneo.</div>
    {detail_cards}

    <!-- 2.2 Matriz de Riesgo -->
    <div class="sec-sub">2.2 Matriz de Probabilidad e Impacto</div>
    <div style="text-align:center;margin:16px 0;">{risk_matrix_svg()}</div>

    <!-- 2.3 Superficie de Ataque -->
    <div class="sec-sub">2.3 Evaluación de Superficie de Ataque</div>
    <table class="data">
        <thead><tr><th>Indicador</th><th>Valor</th><th>Interpretacion</th></tr></thead>
        <tbody>
            <tr><td>Subdominios identificados</td><td class="num">{total_subs + total_crt}</td><td>Superficie de ataque amplia; se recomienda revisión y consolidacion</td></tr>
            <tr><td>Subdominios por fuerza bruta</td><td class="num">{sum(len(p.get("brute_subs") or []) for p in providers)}</td><td>Activos descubiertos no visibles en fuentes tradicionales</td></tr>
            <tr><td>Puertos abiertos</td><td class="num">{total_open_ports}</td><td>Servicios expuestos que requieren justificacion y hardening</td></tr>
            <tr><td>FQDNs descubiertos por pivoteo IP</td><td class="num">{total_pivot}</td><td>Infraestructura compartida con otros dominios o servicios</td></tr>
            <tr><td>Direcciones IP unicas</td><td class="num">{len(all_ips)}</td><td>Huella de red del proveedor en el rango evaluado</td></tr>
            <tr><td>Posibles vectores de exposición</td><td colspan="2">Entornos de desarrollo, paneles de administracion, sistemas de monitoreo, VPN, acceso remoto sin 2FA</td></tr>
        </tbody>
    </table>

    <div style="text-align:center;margin:16px 0;">
        <p style="color:var(--text-muted);font-size:13px;margin-bottom:8px;">Distribucion de Hallazgos por Categoria</p>
        {donut_svg(distrib_segments)}
    </div>
</div>

<!-- ======== 3. RECOMENDACIONES ======== -->
<div class="sec">
    <div class="sec-title"><span class="sn">03</span><span class="st">Recomendaciones</span><span class="line"></span></div>

    <div class="sec-sub">3.1 Acciones Prioritarias (0-30 dias)</div>
    {render_recs(recs_urgent)}

    <div class="sec-sub">3.2 Acciones Estrategicas (1-3 meses)</div>
    {render_recs(recs_strategic)}

    <div class="sec-sub">3.3 Mejora Continua (3-12 meses)</div>
    {render_recs(recs_improve)}

    <div style="margin-top:16px;">
        <p style="color:var(--text-muted);font-size:13px;">Gráfico de criticidad de riesgos identificados (ordenados por nivel de riesgo agregado):</p>
        <div style="margin:12px 0;">{bar_chart_svg(bar_items, w=600, h_per=34, label_w=200)}</div>
    </div>
</div>

<!-- ======== 4. ESTADO DE SEGURIDAD ACTUAL ======== -->
<div class="sec">
    <div class="sec-title"><span class="sn">04</span><span class="st">Estado de Seguridad Actual</span><span class="line"></span></div>

    <div class="sec-sub">4.1 Postura de Seguridad Actual</div>
    <table class="data">
        <thead><tr><th>Control</th><th>Estado</th><th>Observacion</th></tr></thead>
        <tbody>{ctrl_rows}</tbody>
    </table>

    <div style="text-align:center;margin:12px 0;display:flex;gap:20px;justify-content:center;">
        <div style="flex:1;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;">
            <div style="font-size:1.8rem;font-weight:800;color:#173B57;">{ctrl_implemented}</div>
            <div style="font-size:12px;color:var(--text-muted);">Implementados</div>
        </div>
        <div style="flex:1;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;">
            <div style="font-size:1.8rem;font-weight:800;color:#6B7280;">{ctrl_parcial}</div>
            <div style="font-size:12px;color:var(--text-muted);">Parciales</div>
        </div>
        <div style="flex:1;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;">
            <div style="font-size:1.8rem;font-weight:800;color:#C62828;">{ctrl_no}</div>
            <div style="font-size:12px;color:var(--text-muted);">Ausentes/Expuestos</div>
        </div>
    </div>

    <div class="sec-sub">4.2 Indicadores de Riesgo Agregados</div>
    <table class="data">
        <thead><tr><th>Indicador</th><th>Valor</th><th>Interpretacion</th></tr></thead>
        <tbody>
            {"".join(f'<tr><td><strong>{esc(i[0])}</strong></td><td class="num">{esc(i[1])}</td><td>{esc(i[2])}</td></tr>' for i in indicators)}
        </tbody>
    </table>

    <div style="text-align:center;margin:12px 0;">{gauge_svg(float(score))}</div>
</div>

<!-- ======== 5. CONCLUSIONES ======== -->
<div class="sec">
    <div class="sec-title"><span class="sn">05</span><span class="st">Conclusiones</span><span class="line"></span></div>
    <div class="narrative">
        <p>Como resultado del análisis integral de la postura de seguridad de <strong>{esc(domains_list)}</strong>, se presentan las siguientes conclusiones:</p>
        <br>
        <ol style="color:var(--text-muted);font-size:13px;line-height:1.8;padding-left:20px;">
            <li><strong>Riesgo General:</strong> El tercero evaluado presenta un nivel de riesgo <strong>{'ALTO' if score < 50 else 'MEDIO' if score < 75 else 'BAJO'}</strong> con un Security Trust Score de {score}/100, indicando deficiencias significativas en controles de seguridad fundamentales.</li>
            <li><strong>Principales Debilidades:</strong> Ausencia de políticas DMARC estrictas, falta de HSTS en multiples propiedades, software con versiones EOL expuesto a internet, y multiples filtraciones de credenciales en breaches conocidos.</li>
            <li><strong>Principales Fortalezas:</strong> Implementacion básica de HTTPS y TLS en la mayoria de los activos, presencia de registros SPF (aunque sin hard fail), y detección temprana de anomalias mediante monitoreo continuo.</li>
            <li><strong>Recomendación de Seguimiento:</strong> Se recomienda establecer un plan de remediación con hitos a 30, 90 y 180 dias, priorizando el cierre de vulnerabilidades criticas y laimplementacion de controles de seguridad esenciales. Se sugiere una reevaluacion a los 90 dias para verificar el avance.</li>
        </ol>
    </div>
</div>

<!-- ======== 6. FUENTES Y REFERENCIAS ======== -->
<div class="sec">
    <div class="sec-title"><span class="sn">06</span><span class="st">Fuentes y Referencias</span><span class="line"></span></div>
    <table class="data">
        <thead><tr><th>Categoria</th><th>Descripcion</th></tr></thead>
        <tbody>{sources_html}</tbody>
    </table>
</div>

<!-- ======== CONTRAPORTADA ======== -->
<div class="back-cover">
    <div class="accent-line"></div>
    <h2>Evaluación de Postura de Seguridad de Terceros</h2>
    <div class="sub">Informe Ejecutivo</div>
    <div style="margin:16px 0;color:var(--text-muted);font-size:13px;line-height:1.8;">
        <strong>Activo evaluado:</strong> {esc(domains_list)}<br>
        <strong>Organizacion:</strong> {esc(org)}<br>
        <strong>Fecha:</strong> {esc(now.split()[0])}<br>
        <strong>Version:</strong> beta1
    </div>
    <div class="conf">
        CONFIDENCIALIDAD: Este documento contiene información sensible de seguridad. Su distribucion esta restringida al personal autorizado de {esc(org)} y del tercero evaluado. No debe ser compartido, reproducido ni divulgado sin autorizacion expresa.
    </div>
    <div class="accent-line"></div>
    <div style="margin-top:32px;font-size:11px;color:#9CA3AF;">Grupo Cibest &middot; powered by @eduingt &middot; Informe generado el {esc(now.split()[0])}</div>
</div>

</div>
</body>
</html>"""
    return html

def main() -> int:
    ap = argparse.ArgumentParser(description="Informe Ejecutivo beta1 - Evaluación de Postura de Seguridad de Terceros")
    ap.add_argument("--asm", type=Path, default=ROOT / "asm_report.json", help="JSON de asm_scan.py")
    ap.add_argument("--out", type=Path, default=ROOT / "informe_beta1.html", help="HTML de salida")
    ap.add_argument("--analista", default="", help="Nombre del analista")
    ap.add_argument("--org", default="Incocredito", help="Nombre de la organizacion")
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
    sys.exit(main())
