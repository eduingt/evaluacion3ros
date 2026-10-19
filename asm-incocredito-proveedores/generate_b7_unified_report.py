#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B7 - Informe Detallado estilo SecurityScorecard (homologacion visual total).
Replica la estructura del Detailed Report SSC: portada, Que es, Proximos pasos,
Vision general (10 factores + historial 30d vs industria), Elementos de accion
(impacto decimal por issue), 10 modulos con severidad ALTA/MEDIA/BAJA, evidencia
forense por hallazgo (DOMINIO|URL|SHA-256|SERIAL|EVIDENCIA + fecha de ultima
observacion) y nota legal.

Scoring propio (no es calificacion oficial SSC): reutiliza precia_scorecard
(factor_scores 0-100 + overall promedio simple v3.0) y anade IMPACT_MAP decimal por regla
para la columna IMPACTO EN EL SCORE. Datos 100% reales desde asm_report.json;
sin datos observados -> modulo limpio ("No se encontro ningun problema"); solo datos del escaneo.
"""

from __future__ import annotations
import argparse
import html
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import oasm_enrich as _oasm
except Exception:
    _oasm = None

try:
    import easyeasm_enrich as _eeasm
except Exception:
    _eeasm = None

try:
    import scorecard_enrich as _sc
except Exception:
    _sc = None

try:
    import origin_ip as _origin
except Exception:
    _origin = None

try:
    import dns_extra as _dnsx
except Exception:
    _dnsx = None

try:
    import hotlist as _hotlist
except Exception:
    _hotlist = None

try:
    import xorcism_enrich as _xen
except Exception:
    _xen = None

try:
    import rengine_enrich as _rng
except Exception:
    _rng = None

FORMULA_VERSION = "B7-v2.0"

FORMULA_DATE = "2026-10-11"

ROOT = Path(__file__).resolve().parent

try:
    from precia_scorecard import (
        FACTOR_DEFS as _PRECIA_FACTORS,
        INDUSTRY_AVG as _INDUSTRY_AVG,
        factor_scores as _precia_scores,
        overall_score as _precia_overall,
        detect_industry as _precia_industry,
    )
except Exception:
    _PRECIA_FACTORS, _INDUSTRY_AVG = [], {}
    _precia_scores = _precia_overall = _precia_industry = None  # type: ignore

try:
    from toc_helper import render_toc as _render_toc
except Exception:
    _render_toc = None  # type: ignore

SSC_FACTORS = [
    ("appsec", "SEGURIDAD DE APLICACIÓN WEB",
     "Utiliza inteligencia de amenazas sobre vulnerabilidades conocidas: CVE whitehat, "
     "exploits blackhat y hallazgos indexados por buscadores. Mide la probabilidad de una "
     "filtración en la aplicación web y detecta defacements, versiones obsoletas y cabeceras inseguras."),
    ("cubit", "CUBIT SCORE",
     "Módulo de higiene que verifica buenas prácticas básicas: HSTS, CSP, XFO, SPF, DMARC, "
     "DNSSEC, CAA, MTA-STS y TLS vigente. Mide la disciplina de configuración de la empresa."),
    ("dns", "ESTADO DE DNS",
     "Mide el estado y la configuración del DNS: registros SPF/DMARC/DKIM, DNSSEC, CAA y "
     "ausencia de eventos maliciosos en el historial pasivo. Verifica la protección anti-spoofing del correo."),
    ("endpoint", "SEGURIDAD DE PUNTOS DE CONEXIÓN",
     "Rastrea subdominios y puntos de entrada (takeovers, brute force, certificados) para "
     "identificar versiones obsoletas o exposiciones que permitan ataques del lado del cliente."),
    ("chatter", "HACKER CHATTER",
     "Sistema de recolección de menciones en foros, IRC, redes y repositorios públicos. "
     "Clasifica indicadores (ransomware, CTI) que mencionen a la empresa o sus dominios."),
    ("iprep", "REPUTACIÓN DE IP",
     "Cruza las IPs de la empresa con DNSBL, URLhaus y reputación de red. La cantidad y "
     "duración de listados determina el indicador clave de amenaza del módulo."),
    ("leak", "FILTRACIÓN DE INFORMACIÓN",
     "Usa leaks observados y breach intel para identificar credenciales comprometidas en "
     "circulación: filtraciones masivas públicas e intercambios entre atacantes."),
    ("network", "SEGURIDAD DE RED",
     "Comprueba puertos abiertos de alto riesgo, servicios inseguros (FTP/RDP/DNS/proxy), "
     "TLS débil y certificados inválidos. Un puerto mal configurado es la puerta entre el "
     "atacante y la red interna."),
    ("patching", "CADENCIA DE APLICACIÓN DE REVISIONES",
     "Analiza la rapidez de reacción ante vulnerabilidades: CVEs observados en servicios, "
     "tecnologías EOL y comparación contra el ritmo de parcheo esperado."),
    ("social", "INGENIERÍA SOCIAL",
     "Mide la susceptibilidad a ingeniería social dirigida mediante typosquatting "
     "registrado contra la marca y exposición en redes y filtraciones públicas."),
]

GRADE_COLORS = {"A": "#34A853", "B": "#F29900", "C": "#F06030", "D": "#E53935", "F": "#B71C1C"}
SEV_COLORS = {"ALTA": "#E53935", "MEDIA": "#F29900", "BAJA": "#C9A227"}
SEV_BG = {"ALTA": "#FDECEA", "MEDIA": "#FFF4E5", "BAJA": "#FFFBEB"}


def esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=False)


def grade_of(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def hex_grade(letter: str, size: int = 56, font: int = 24) -> str:
    c = GRADE_COLORS.get(letter, "#9AA0A6")
    return (
        f'<span class="hex" style="width:{size}px; height:{int(size*1.1)}px; '
        f'font-size:{font}px; background:{c};">{esc(letter)}</span>'
    )


def sev_bars(sev: str) -> str:
    n = {"ALTA": 3, "MEDIA": 2, "BAJA": 1}.get(sev, 1)
    c = SEV_COLORS.get(sev, "#9AA0A6")
    bars = "".join(
        f'<span class="bar" style="height:{6 + i * 5}px; background:{c if i < n else "#D5D9DE"};"></span>'
        for i in range(3)
    )
    return f'<span class="bars">{bars}</span>'


SECTOR_ES = {"Financial Services": "SERVICIOS FINANCIEROS", "Banking": "SERVICIOS FINANCIEROS",
               "Insurance": "SEGUROS", "Healthcare": "SALUD", "Telecommunications": "TELECOMUNICACIONES",
               "Technology": "TECNOLOGIA", "Retail": "COMERCIO", "Manufacturing": "MANUFACTURA",
               "Energy & Utilities": "ENERGIA", "Government": "GOBIERNO",
               "Education": "EDUCACION", "Professional Services": "SERVICIOS PROFESIONALES"}


def fmt_impact(impact: float, tiny: bool = False) -> str:
    if tiny:
        return "&lt;-0.1"
    return f"{impact:.1f}"


def fmt_utc_stamp(raw: str, now: datetime) -> str:
    try:
        dt = datetime.strptime(str(raw)[:19], "%Y-%m-%d %H:%M:%S")
        return f"las {dt.strftime('%H:%M:%S')} UTC del {fecha_larga(dt)}"
    except Exception:
        return f"las {now.strftime('%H:%M:%S')} UTC del {fecha_larga(now)}"


def fecha_larga(dt: datetime) -> str:
    meses = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
             "agosto", "septiembre", "octubre", "noviembre", "diciembre"]
    return f"{dt.day} de {meses[dt.month - 1]} de {dt.year}"


CSS = """
@page {
  size: A4;
  margin: 18mm 14mm 20mm 14mm;
  @top-left {
    content: "Grupo Cibest   con la tecnología de SecurityScorecard";
    font-family: Arial, Helvetica, sans-serif; font-size: 7pt; color: #6B7280;
  }
  @top-right {
    content: "Informe detallado de " var(--ssc-dom) " - Preparado el " var(--ssc-fecha) "  |  " counter(page) " de " counter(pages);
    font-family: Arial, Helvetica, sans-serif; font-size: 7pt; color: #111827;
  }
  @bottom-center {
    content: "Análisis de opinión sobre riesgos futuros de seguridad relativos a la fecha indicada; no constituye pentest ni evaluación final. Uso interno confidencial. (c) 2026 GrupoCibest. Fórmula " var(--ssc-formula) ".";
    font-family: Arial, Helvetica, sans-serif; font-size: 5pt; color: #9AA0A6;
    white-space: normal; text-align: center;
  }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Arial, Helvetica, sans-serif; color: #111827; background: #fff;
       font-size: 10pt; line-height: 1.55; }
.cover { page-break-after:always; padding:0; position:relative; display:flex; flex-direction:column; min-height:95vh; }
.cover-top { background:#173B67; color:#fff; padding:50px 60px 30px; }
.cover-top .powered { font-size:8pt; opacity:.7; letter-spacing:.1em; text-transform:uppercase; margin-bottom:6px; }
.cover-top h1 { font-size:30pt; font-weight:800; line-height:1.1; margin-bottom:4px; }
.cover-top .sub { font-size:13pt; font-weight:300; color:rgba(255,255,255,.85); margin-bottom:30px; line-height:1.3; }
.cover-top .org-name { font-size:20pt; font-weight:700; color:#fff; }
.cover-meta { padding:30px 60px 20px; flex:1; }
.cover-meta table { width:100%; border-collapse:collapse; font-size:10pt; }
.cover-meta td { padding:7px 12px; border-bottom:1px solid #D9DEE3; }
.cover-meta td:first-child { font-weight:700; color:#173B67; width:200px; }
.cover-footer { border-top:3px solid #173B67; padding:12px 60px 0; font-size:7pt; color:#6B7280; display:flex; justify-content:space-between; }
h2.sec { font-size: 22pt; font-weight: 700; margin: 0 0 12px; }
h3.mod { font-size: 17pt; font-weight: 400; margin: 0; text-transform: uppercase; letter-spacing: .01em; }
.mod-head { display: flex; align-items: center; gap: 12px; margin: 8mm 0 5mm; }
.mod-head .score { font-size: 13pt; color: #6B7280; font-weight: 400; }
.hex { display: inline-flex; align-items: center; justify-content: center; color: #fff;
       font-weight: 800; clip-path: polygon(50% 0, 100% 25%, 100% 75%, 50% 100%, 0 75%, 0 25%); flex-shrink: 0; }
.bars { display: inline-flex; align-items: flex-end; gap: 2px; margin-right: 6px; vertical-align: -2px; }
.bar { display: inline-block; width: 4px; border-radius: 1px; }
.meta { display: flex; gap: 40px; color: #6B7280; font-size: 10pt; margin: 4px 0 6mm; }
.meta b { color: #6B7280; font-weight: 400; }
.factors { display: grid; grid-template-columns: 1fr 1fr; column-gap: 26px; }
.frow { display: flex; align-items: center; gap: 8px; padding: 5px 0; border-bottom: 1px solid #EEF0F3; }
.frow .fname { font-size: 9.5pt; font-weight: 700; flex: 1; }
.frow .fscore { font-size: 9pt; color: #6B7280; }
.frow .finc { font-size: 8pt; color: #9AA0A6; margin-left: auto; white-space: nowrap; }
table.ev { width: 100%; border-collapse: collapse; font-size: 8.5pt; margin: 3mm 0 5mm; }
table.ev th { background: #F1F3F6; color: #374151; text-align: left; padding: 6px 8px;
              font-size: 8pt; font-weight: 700; text-transform: uppercase; }
table.ev td { padding: 5px 8px; border-bottom: 1px solid #EEF0F3; vertical-align: top; word-break: break-word; }
table.ev tr.alt td { background: #FAFBFC; }
table.act { width: 100%; border-collapse: collapse; font-size: 9pt; margin: 4mm 0; }
table.act th { background: #F1F3F6; padding: 7px 10px; font-size: 8.5pt; text-transform: uppercase; text-align: left; }
table.act td { padding: 7px 10px; border-bottom: 1px solid #EEF0F3; vertical-align: top; }
table.act tr.grp td { background: #FAFBFC; font-weight: 700; }
.impact { color: #E53935; font-size: 15pt; font-weight: 400; white-space: nowrap; }
.impact small { font-size: 8pt; color: #111827; font-weight: 400; }
.sevbox { border: 1px solid #D9DEE3; border-radius: 6px; padding: 10px 12px; margin: 4mm 0; }
.sevrow { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }
.sevcol { border-radius: 5px; padding: 8px 10px; font-size: 8.5pt; }
.sevcol .t { font-weight: 800; font-size: 8.5pt; margin-bottom: 4px; }
.sevcol .n { color: #6B7280; font-size: 8pt; }
.issue { margin: 6mm 0 2mm; }
.issue-head { display: flex; align-items: baseline; gap: 8px; border-bottom: 1px solid #E5E7EB; padding-bottom: 2mm; }
.issue-head h4 { font-size: 13pt; font-weight: 700; flex: 1; }
.twocol { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin: 3mm 0; font-size: 9pt; }
.twocol h5 { font-size: 10pt; margin-bottom: 2mm; }
.twocol ul { margin-left: 16px; }
.evidence { font-size: 8pt; color: #4B5563; background: #FAFBFC; padding: 2px 8px; }
.nres { font-size: 11pt; margin: 5mm 0 1mm; }
.nodata { background: #F7F8FA; color: #9AA0A6; text-align: center; font-size: 15pt;
          padding: 10mm 0; border-radius: 6px; margin: 5mm 0; }
.steps { background: #F1F3F6; border-radius: 8px; padding: 8mm 10mm; display: grid;
         grid-template-columns: 1fr 1fr; gap: 8mm; align-items: center; margin: 5mm 0; }
.grade-now { text-align: center; font-size: 9pt; color: #374151; }
.next { font-size: 13pt; font-weight: 700; }
ol.how { margin: 4mm 0 4mm 6mm; font-size: 9.5pt; }
ol.how li { margin-bottom: 3mm; }
.help { display: grid; grid-template-columns: 200px 1fr; gap: 10mm; border-top: 1px solid #D9DEE3;
        margin-top: 6mm; padding-top: 5mm; }
.help h3 { font-size: 20pt; font-weight: 400; line-height: 1.2; }
.legal { font-size: 9pt; }
.legal p { margin-bottom: 3mm; }
.footer-note { font-size: 7pt; color: #6B7280; margin-top: 4mm; }
.pb { page-break-before: always; }
.avoid { page-break-inside: avoid; }
a { color: #2B5CE6; text-decoration: none; }
.hist-legend { display: flex; gap: 12mm; justify-content: center; font-size: 9pt; margin-top: 2mm; }
.sw { display: inline-block; width: 10px; height: 10px; margin-right: 4px; vertical-align: baseline; }
"""


def ssc_css_vars(domain: str, fecha_corta: str) -> str:
    return (
        f'<style>:root{{--ssc-dom:"{esc(domain)}"; --ssc-fecha:"{esc(fecha_corta)}"; '
        f'--ssc-formula:"{FORMULA_VERSION}";}}</style>'
    )


def _logo_gc_b64() -> str:
    """Logo Grupo Cibest (version negativa/blanca) en base64 para la portada."""
    try:
        raw = (ROOT / "logo-grupo-cibest-negativo.png").read_bytes()
        import base64
        return base64.b64encode(raw).decode("ascii")
    except Exception:
        return ""


def render_cover(company: str, domain: str, fecha_corta: str, fecha_larga: str,
                 analista: str, email: str, org: str, utc_stamp: str,
                 overall: int, letter: str, sector: str, incidences: int) -> str:
    _l64 = _logo_gc_b64()
    logo_img = (f"<div style='margin-bottom:14px; text-align:left;'><img src='data:image/png;base64,{_l64}' "
                f"style='height:46px;' alt='Grupo Cibest'></div>" if _l64 else "")
    return f"""
<div class="cover">
  <div class="cover-top">
    {logo_img}
    <div class="powered">Generado por GrupoCibest</div>
    <h1>INFORME DETALLADO DE<br>SEGURIDAD</h1>
    <div class="sub">Evaluación de postura de seguridad<br>estilo Scorecard (homologado SSC)</div>
    <div class="org-name">{esc(domain)}</div>
  </div>
  <div class="cover-meta"><table>
    <tr><td>Fecha de generación</td><td>{esc(fecha_larga)}</td></tr>
    <tr><td>Analista responsable</td><td>{esc(analista) if analista else "—"}</td></tr>
    <tr><td>Organización emisora</td><td>{esc(org)}</td></tr>
    <tr><td>Dominio evaluado</td><td>{esc(domain)}</td></tr>
    <tr><td>Sector</td><td>{esc(sector)}</td></tr>
    <tr><td><strong>OVERALL SCORE</strong></td><td><strong>{overall}/100 ({esc(letter)})</strong> benchmark B7 comparativo sectorial</td></tr>
    <tr><td>Threat indicators</td><td>{incidences} hallazgo(s) con impacto decimal</td></tr>
    <tr><td>Captura</td><td>{esc(utc_stamp)}</td></tr>
  </table></div>
  <div class="cover-footer"><span>Dominio: {esc(domain)} | Preparado: {esc(fecha_larga)}</span><span>Página 1</span></div>
</div>
"""


def render_about() -> str:
    return """
<div class="pb">
  <h2 class="sec" id="sec-b7about" style="font-size:13pt;">Que es este Scorecard?</h2>
  <p>Servicio de calificacion de seguridad con sistema de letras de la <b>A</b> (maxima) a la
  <b>F</b> (minima) para la seguridad general y 10 factores de riesgo. Una empresa con C, D o F
  tiene 5,4 veces mas probabilidades de sufrir una filtracion importante que una con A o B.
  Factores como seguridad de aplicaciones y cadencia de parches multiplican hasta por diez la
  probabilidad de filtracion al pasar de A a F.</p>
  <div class="next" style="margin-top:8mm;">Proximos pasos: <span id="next-grade">Conseguir (A)</span></div>
  <div class="steps">
    <div class="grade-now" id="now-box"></div>
    <div class="grade-now"><div style="font-size:9pt;">El Score futuro<br>de esta empresa</div>
      <div style="margin-top:3mm;">__HEXA__</div></div>
  </div>
  <ol class="how">
    <li><b>Cree una cuenta / programe monitoreo.</b> Este archivo es un momento puntual; el valor
    esta en el monitoreo continuo, el historial y la re-evaluacion tras remediar.</li>
    <li><b>Valide su huella digital.</b> Revise los activos atribuidos (IPs, subdominios, ASN) y
    reporte los que no le pertenezcan: afectan directamente la calificacion.</li>
    <li><b>Examine los hallazgos.</b> Investigue con sus equipos la seccion Elementos de accion,
    ordenada por impacto en el score: cada decima cuenta.</li>
    <li><b>Corrija y mejore su Score.</b> Remedie, documente controles compensatorios y vuelva a
    medir. SLA sugerido: criticos 0-7 dias, altos 8-30, medios 31-60.</li>
  </ol>
  <div class="help">
    <h3>Estamos aqui para ayudarle</h3>
    <p>La remediacion se gestiona por criticidad e impacto. Si necesita ayuda, contacte a su
    analista de seguridad o mesa de ayuda.</p>
  </div>
</div>
"""


def history_from_db(domain: str, days: int = 30) -> list[dict[str, Any]]:
    try:
        db = ROOT / "dashboard_workspace" / "scan_history.db"
        if not db.is_file():
            return []
        c = sqlite3.connect(db)
        rows = c.execute(
            "SELECT created_at, overall_score FROM scan_history WHERE domain=? "
            "AND created_at >= datetime('now', ? || ' days') ORDER BY created_at ASC",
            (domain, f"-{days}"),
        ).fetchall()
        c.close()
        return [{"fecha": r[0], "score": float(r[1])} for r in rows]
    except Exception:
        return []


def render_history_svg(hist: list[dict[str, Any]], industry_avg: int | None, color: str) -> str:
    W, H, PL, PT = 640, 260, 44, 10
    bands = [(90, 100, "A", "#34A853"), (80, 90, "B", "#F29900"), (70, 80, "C", "#F06030"),
             (60, 70, "D", "#E53935"), (0, 60, "F", "#B71C1C")]
    def yp(s: float) -> float:
        s = max(0, min(100, s))
        return PT + (H - PT - 20) * (1 - s / 100)
    svg = [f'<svg width="{W}" height="{H + 34}" xmlns="http://www.w3.org/2000/svg" '
           'style="font-family:Arial,Helvetica,sans-serif;">']
    for lo, hi, letter, col in bands:
        svg.append(f'<line x1="{PL}" y1="{yp(hi):.0f}" x2="{W}" y2="{yp(hi):.0f}" stroke="#E5E7EB" stroke-width="1"/>')
        svg.append(f'<text x="8" y="{(yp(hi) + yp(max(lo, hi - 10))) / 2 + 3:.0f}" font-size="10" fill="{col}">{letter}</text>')
        if lo == 0:
            svg.append(f'<text x="30" y="{yp(0) + 3:.0f}" font-size="9" fill="#9AA0A6">0</text>')
            svg.append(f'<text x="24" y="{yp(60) + 3:.0f}" font-size="9" fill="#9AA0A6">60</text>')
            svg.append(f'<text x="24" y="{yp(70) + 3:.0f}" font-size="9" fill="#9AA0A6">70</text>')
            svg.append(f'<text x="24" y="{yp(80) + 3:.0f}" font-size="9" fill="#9AA0A6">80</text>')
            svg.append(f'<text x="24" y="{yp(90) + 3:.0f}" font-size="9" fill="#9AA0A6">90</text>')
            svg.append(f'<text x="20" y="{yp(100) + 3:.0f}" font-size="9" fill="#9AA0A6">100</text>')
    n = len(hist)
    if n >= 1:
        xs = [PL + (W - PL - 10) * (i / max(1, n - 1) if n > 1 else 0.5) for i in range(n)]
        pts = " ".join(f"{x:.0f},{yp(h['score']):.0f}" for x, h in zip(xs, hist))
        svg.append(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="2"/>')
        for x, h in zip(xs, hist):
            svg.append(f'<circle cx="{x:.0f}" cy="{yp(h["score"]):.0f}" r="3" fill="{color}"/>')
        step = max(1, n // 6)
        for i in range(0, n, step):
            lbl = str(hist[i]["fecha"])[:10]
            svg.append(f'<text x="{xs[i]:.0f}" y="{H + 14:.0f}" font-size="9" fill="#374151" text-anchor="middle">{esc(lbl)}</text>')
            svg.append(f'<line x1="{xs[i]:.0f}" y1="{PT}" x2="{xs[i]:.0f}" y2="{H}" stroke="#E5E7EB" stroke-dasharray="4,3"/>')
    if industry_avg is not None:
        ia = max(0, min(100, industry_avg))
        svg.append(f'<line x1="{PL}" y1="{yp(ia):.0f}" x2="{W}" y2="{yp(ia):.0f}" stroke="#8FA8D8" stroke-width="2"/>')
    svg.append("</svg>")
    return "".join(svg)


def _render_oasm_block_b7(p: dict[str, Any], domain: str, overall: int,
                          issues: list[dict[str, Any]], hist: list[dict[str, Any]]) -> str:
    if _oasm is None:
        return ""
    counts = _oasm.counts_from_findings(issues, key="sev")
    assets = _oasm.asset_count(p)
    dns = p.get("dns") or {}
    cur = {
        "overall_score": overall,
        "score_general": overall,
        "domain_score": None,
        "subdomains": len(p.get("subdomains") or []) + len(p.get("crt_subdomains") or []),
        "ips": len(dns.get("ipv4") or []),
        "ports": len(p.get("open_ports") or []),
        "findings": len(issues),
    }
    prev = _oasm.previous_snapshot(domain)
    trend_hist = _oasm.load_history(domain, 90, "overall_score") or hist or []
    return (
        '<div class="pb" style="page-break-before:always;">'
        '<h2 class="sec" id="sec-b7oasm">Enriquecimiento OASM: Score 0-10, comparativa y tendencia</h2>'
        + _oasm.render_score_header(counts, assets)
        + '<div class="avoid">' + _oasm.render_comparison_block(domain, cur, prev) + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + _oasm.render_trend_block(trend_hist) + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + _oasm.render_lifecycle_block(domain, issues) + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_eeasm.render_asset_change_block(domain, p) if _eeasm is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_eeasm.render_permutation_block(domain, p) if _eeasm is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_sc.render_provider_scorecard_block(domain, p) if _sc is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_sc.render_toolchain_scorecard_block() if _sc is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_hotlist.render_hotlist_block(domain, p) if _hotlist is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_origin.render_origin_block(domain, p) if _origin is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_dnsx.render_dns_extra_block(domain, p) if _dnsx is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_xen.render_fusion_block(domain, p) if _xen is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_xen.render_ctem_block(domain, p) if _xen is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_xen.render_insurance_block(domain, p) if _xen is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_xen.render_pqc_block(domain, p) if _xen is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_xen.render_ransomware_block(domain, p) if _xen is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_rng.render_gf_block(domain, p) if _rng is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_rng.render_interesting_block(domain, p) if _rng is not None else "") + '</div>'
        + '<div class="avoid" style="margin-top:4mm;">' + (_rng.render_webports_block(domain, p) if _rng is not None else "") + '</div>'
        + '</div>'
    )


def render_overview(company: str, domain: str, sector: str, overall: int,
                    scores: dict[str, int], incidences: dict[str, int],
                    hist: list[dict[str, Any]], industry_avg: int | None) -> str:
    letter = grade_of(overall)
    col = GRADE_COLORS[letter]
    left, right = [], []
    for i, (key, name, _desc) in enumerate(SSC_FACTORS):
        s = int(scores.get(key, 100))
        n = int(incidences.get(key, 0))
        gl = grade_of(s)
        inc = "0 NINGUNA INCIDENCIA" if n == 0 else (f"{n} INCIDENCIA" if n == 1 else f"{n} INCIDENCIAS")
        cell = (f'<div class="frow">{hex_grade(gl, 26, 12)}'
                f'<span class="fscore">{s}</span>'
                f'<span class="fname">{esc(name)}</span>'
                f'<span class="finc">{inc}</span></div>')
        (left if i < 5 else right).append(cell)
    hist_html = render_history_svg(hist, industry_avg, col) if len(hist) >= 2 else (
        '<div class="nodata" style="font-size:11pt; padding:6mm 0;">Se requieren 2+ escaneos '
        "para el historial de 30 dias (solo datos del escaneo).</div>"
    )
    return f"""
<div class="pb" style="page-break-before:always;">
  <h2 class="sec" id="sec-b7overview">Vision general del Scorecard</h2>
  <div class="mod-head">{hex_grade(letter, 54, 24)}
    <div><div style="font-size:17pt;">{esc(company)}</div>
    <div style="color:#6B7280; font-size:11pt;">Puntuación de seguridad: {overall}</div></div>
  </div>
  <div class="meta"><span><b>DOMINIO:</b> {esc(domain)}</span><span><b>SECTOR:</b> {esc(sector)}</span></div>
  <h3 class="mod" style="font-size:13pt; text-transform:none; margin-bottom:2mm;">Factores de Riesgo de Overall Score</h3>
  <div class="factors avoid"><div>{"".join(left)}</div><div>{"".join(right)}</div></div>
  <div style="page-break-before:always;"></div><h2 class="sec" id="sec-b7hist" style="margin-top:8mm;">Historial del Score en los últimos 30 días / Overall Score</h2>
  <p style="font-size:9pt;">Los picos representan mejoras y corrección de incidencias; las caídas,
  configuraciones erróneas o actividad prolongada de malware.</p>
  <div style="margin-top:3mm;">{hist_html}</div>
  <div class="hist-legend"><span><span class="sw" style="background:{col};"></span>{esc(domain)}</span>
  {f'<span><span class="sw" style="background:#8FA8D8;"></span>Our Industry ({industry_avg})</span>' if industry_avg is not None else '<span style="color:#9AA0A6;">Our Industry (sector sin referencia)</span>'}</div>
</div>
"""

def _norm(s: Any) -> str:
    import unicodedata
    return unicodedata.normalize("NFKD", str(s or "")).encode("ASCII", "ignore").decode("ASCII").upper()


def _observed(p: dict[str, Any]) -> str:
    return str(p.get("scanned_at") or "")[:16] or "—"


def _first_ipv4(p: dict[str, Any]) -> str:
    ips = (p.get("dns") or {}).get("ipv4") or []
    return str(ips[0]) if ips else "—"


def _headers(p: dict[str, Any]) -> dict[str, str]:
    h = (p.get("https") or {}).get("headers") or {}
    return {str(k).lower(): str(v) for k, v in h.items()}


def _final_url(p: dict[str, Any]) -> str:
    return str((p.get("https") or {}).get("final_url") or f"https://{p.get('domain', '')}/")


def _fetch_external_scripts(domain: str) -> list[str]:
    try:
        import requests
        for verify in (True, False):
            try:
                r = requests.get(f"https://{domain}/", timeout=8, verify=verify,
                                 headers={"User-Agent": "ASM-B7/report"})
                if r.status_code >= 400 or not r.text:
                    continue
                out = []
                for m in re.finditer(r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>", r.text, re.I):
                    tag = m.group(0)
                    if "integrity" not in tag.lower():
                        out.append(m.group(1)[:120])
                return out[:8]
            except Exception:
                continue
    except Exception:
        pass
    return []


def _typo_spf_missing(typos: list[dict[str, Any]]) -> list[str]:
    """Solo ausencia confirmada: si el DNS no responde, no se afirma nada."""
    missing: list[str] = []
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.lifetime = 5
        for t in typos[:10]:
            dom = t.get("domain") if isinstance(t, dict) else str(t)
            if not dom:
                continue
            try:
                txts = [str(r).strip('"') for r in res.resolve(dom, "TXT")]
            except Exception:
                continue
            if not any(x.startswith("v=spf1") for x in txts):
                missing.append(dom)
    except Exception:
        pass
    return missing


def _parse_csp(csp: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in (csp or "").split(";"):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        out[toks[0].lower()] = toks[1:]
    return out


def _parse_hsts(v: str) -> dict[str, Any]:
    low = v.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    return {"max_age": int(m.group(1)) if m else 0,
            "subdomains": "includesubdomains" in low,
            "preload": "preload" in low,
            "multiple": low.count("max-age") > 1}


def collect_issues(p: dict[str, Any]) -> list[dict[str, Any]]:
    """Catalogo SSC homologado: cada issue trae factor, severidad, impacto
    decimal, descripcion, recomendacion y tabla de evidencia forense."""
    dom = p.get("domain", "")
    obs = _observed(p)
    issues: list[dict[str, Any]] = []

    def add(key: str, factor: str, sev: str, impact: float, title: str,
            desc: str, reco: list[str], cols: list[str], rows: list[list[str]],
            tiny: bool = False) -> None:
        if not rows:
            return
        issues.append({"key": key, "factor": factor, "sev": sev, "impact": impact,
                       "tiny": tiny, "title": title, "desc": desc, "reco": reco,
                       "cols": cols, "rows": rows, "domain": dom})

    H = _headers(p)
    csp_raw = H.get("content-security-policy", "")
    CSP = _parse_csp(csp_raw)
    final = _final_url(p)

    # ---------- APPLICATION SECURITY ----------
    if not csp_raw:
        add("csp_missing", "appsec", "BAJA", -0.8,
            "Falta la política de seguridad de contenido (PSC)",
            "Sin PSC los atacantes pueden inyectar scripts (XSS), alterar datos, secuestrar "
            "clics y cargar contenido inseguro; aumenta accesos no autorizados y exposición de datos.",
            ["Implemente la PSC vía encabezados HTTP", "Defina script-src/style-src/img-src de confianza",
             "Use nonce/hash para inline", "Endurezca gradualmente y monitoree violaciones"],
            ["DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[dom, "https", "1", final, obs]])
    else:
        txt = _norm(csp_raw)
        if "UNSAFE-INLINE" in txt or "UNSAFE-EVAL" in txt:
            add("csp_unsafe", "appsec", "BAJA", -1.1,
                "La política de seguridad de los contenidos contiene la directiva 'unsafe'",
                "'unsafe-inline'/'unsafe-eval' expanden la superficie XSS y permiten ejecución de "
                "código en el dominio confiable; socavan la protección prevista de la PSC.",
                ["Especifique orígenes confiables en script-src/style-src", "Elimine unsafe-eval",
                 "Use nonce/hash", "CSP estricta y minimalista"],
                ["DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[dom, "https", "1", final, obs]])
        broad_vals = {"*", "http:", "https:", "data:", "http://", "https://",
                      "http://*", "https://*"}
        watched = [w.strip().lower().rstrip(";") for d in ("script-src", "object-src", "default-src")
                   for w in CSP.get(d, [])]
        if any(w in broad_vals for w in watched):
            add("csp_broad", "appsec", "BAJA", -0.1,
                "La politica de seguridad de contenido contiene directivas amplias",
                "Valores como *, http: o data: permiten cargar recursos de casi cualquier origen, "
                "incluidos dominios maliciosos; se pierde la protección anti-XSS.",
                ["Dominios exactos en script-src/style-src", "Minimice comodines", "Use HTTPS y nonce/hash"],
                ["DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[dom, "https", "1", final, obs]])
    fa = CSP.get("frame-ancestors", [])
    if not fa and not H.get("x-frame-options"):
        add("framing", "appsec", "BAJA", -0.4,
            "El sitio no aplica las prácticas recomendadas para evitar la incrustación de contenido malintencionado",
            "Sin frame-ancestors ni X-Frame-Options cualquiera puede embeber la página en iframes: "
            "clickjacking, accesos no autorizados y robo de datos.",
            ["Agregue frame-ancestors 'self' o 'none' a la CSP",
             "Respalde con X-Frame-Options: SAMEORIGIN o DENY"],
            ["DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[dom, "https", "1", final, obs]])
    hsts_raw = H.get("strict-transport-security", "")
    if not hsts_raw:
        add("hsts_missing", "appsec", "BAJA", -0.1,
            "El sitio web no implementa las practicas recomendadas de HSTS",
            "Sin HSTS hay degradacion de protocolo y secuestro de cookies (MITM); los navegadores "
            "no imponen HTTPS y la comunicacion puede interceptarse y manipularse.",
            ["Implemente HSTS", "max-age=31536000; includeSubDomains", "Cada recurso via HTTPS",
             "Pruebe la aplicacion"],
            ["ANÁLISIS", "DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [["no_hsts", dom, "https", "1", final, obs]])
    else:
        hs = _parse_hsts(hsts_raw)
        weak = []
        if hs["multiple"]:
            weak.append("hsts_multiple")
        if 0 < hs["max_age"] < 31536000:
            weak.append("hsts_age_too_short")
        if not hs["subdomains"]:
            weak.append("hsts_missing_subdomain")
        for w in weak:
            add(f"hsts_{w}", "appsec", "BAJA", -0.1,
                "Política HSTS débil o incompleta",
                f"Hallazgo {w}: max-age={hs['max_age']}, includeSubDomains={'sí' if hs['subdomains'] else 'no'}. "
                "Una política corta, sin subdominios o duplicada deja ventanas de degradación a HTTP.",
                ["max-age=31536000; includeSubDomains", "Un solo encabezado HSTS canónico"],
                ["ANÁLISIS", "DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[w, dom, "https", "1", final, obs]])
    xcto = H.get("x-content-type-options", "")
    if not xcto:
        add("xcto_missing", "appsec", "BAJA", -0.1,
            "El sitio web no implementa las prácticas recomendadas de X-Content-Type-Options",
            "Sin 'nosniff' los navegadores interpretan contenido por heurística (MIME sniffing) y "
            "pueden ejecutar scripts maliciosos: XSS por confusión de tipos.",
            ["Agregue X-Content-Type-Options: nosniff", "Complemente con PSC"],
            ["ANÁLISIS", "DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[f"x_content_type_options_missing", dom, "https", "1", final, obs]])
    elif len({x.strip().lower() for x in xcto.split(",") if x.strip()}) > 1 or xcto.count("nosniff") > 1:
        add("xcto_multiple", "appsec", "BAJA", -0.1,
            "Encabezado X-Content-Type-Options múltiple o inconsistente",
            f"Se observaron valores en conflicto ({xcto[:80]}); la protección nosniff queda ambigua.",
            ["Un solo valor canónico: nosniff"],
            ["ANÁLISIS", "DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [["x_content_type_options_multiple", dom, "https", "1", final, obs]])
    chain = (p.get("https") or {}).get("redirect_chain") or []
    chain_txt = " ".join(str(x) for x in chain)
    if "http://" in chain_txt.replace("https://", ""):
        steps = [str(x)[:100] for x in chain[:2]]
        add("redirect_http", "appsec", "MEDIA", -1.9,
            "La cadena de redirección contiene HTTP",
            "Pasos sin cifrar exponen datos a interceptación y redirecciones a destinos inseguros "
            "(phishing, MITM).",
            ["Cada eslabón en HTTPS", "Rutas relativas", "HSTS en la cadena completa"],
            ["DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "URL INICIAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[dom, "https", "1", final, steps[0] if steps else "—", obs]])
    p80 = (p.get("port_80") or {}).get("open")
    https_ok = bool((p.get("https") or {}).get("https_ok")) or final.startswith("https")
    if p80 and not https_ok:
        add("no_https", "appsec", "BAJA", -1.0,
            "El sitio no aplica HTTPS",
            "Sin HTTPS los datos viajan legibles: interceptación, suplantación y manipulación; los "
            "navegadores advierten y los buscadores penalizan.",
            ["Certificado válido y redirección HTTP->HTTPS", "HSTS"],
            ["DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[dom, "http", "1", f"http://{dom}/", obs]])
    fp = str((p.get("https") or {}).get("server_fingerprint") or "")
    cloud = p.get("cloud_storage") or {}
    if "amazons3" in _norm(fp) or (cloud.get("publicos") or cloud.get("buckets")):
        add("object_storage", "appsec", "BAJA", -0.1,
            "Sitio alojado en almacenamiento de objetos",
            "Object storage es para contenido estático; permisos mal configurados exponen datos y "
            "ata la disponibilidad a un tercero.",
            ["ACL estrictas", "Cifrado", "CDN", "Multi-region"],
            ["ANÁLISIS", "DOMINIO", "ESQUEMA", "OBSERVACIONES", "URL FINAL", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [["server_header_is_amazon_s3" if "amazons3" in _norm(fp) else "object_storage",
              dom, "https", "1", final, obs]], tiny=True)
    for c in (p.get("cookie_findings") or []):
        t = _norm(str(c.get("title", "")) + " " + str(c.get("rule", "")) + " " + str(c))
        if "SECURE" in t and ("FALTA" in t or "MISSING" in t or "SIN" in t or "NO " in t):
            add("cookie_secure", "appsec", "ALTA", -8.3,
                'Falta el atributo "Secure" en la cookie de sesión',
                "La cookie viaja también por HTTP y puede interceptarse en redes no seguras: secuestro "
                "de sesión y acceso no autorizado.",
                ["HTTPS en el sitio completo", "Atributo secure explícito", "Cookies de sesión en servidor"],
                ["DOMINIO", "URL", "OBSERVACIONES", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[dom, final, "1", obs]])
            break
    scripts = _fetch_external_scripts(dom) if dom else []
    if scripts:
        add("sri_missing", "appsec", "ALTA", -3.6,
            "Implementación insegura de la integridad de recursos secundarios (SRI)",
            "Scripts externos sin hash de integridad pueden manipularse en origen: inyección de "
            "código, XSS y robo de datos.",
            ["Hashes SRI en cada recurso externo", "Rotación de hashes", "CSP restrictiva", "Auditorías"],
            ["DOMINIO", "ESQUEMA", "OBSERVACIONES", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[dom, "https", str(len(scripts)), obs]])
        issues[-1]["ev_rows"] = [[s] for s in scripts]

    # ---------- CUBIT (higiene) ----------
    dns = p.get("dns") or {}
    if not dns.get("dnssec_ok"):
        add("cubit_dnssec", "cubit", "BAJA", -0.1, "Sin DNSSEC",
            "Respuestas DNS sin firma: suplantación de registros posible.",
            ["Firme la zona con DNSSEC"],
            ["DOMINIO", "FECHA DE ÚLTIMA OBSERVACIÓN"], [[dom, obs]])
    if not p.get("caa_records"):
        add("cubit_caa", "cubit", "BAJA", -0.1, "Sin registros CAA",
            "Cualquier CA puede emitir certificados del dominio.",
            ["Registro CAA con sus CA autorizadas"],
            ["DOMINIO", "FECHA DE ÚLTIMA OBSERVACIÓN"], [[dom, obs]])
    if not p.get("mta_sts"):
        add("cubit_mtasts", "cubit", "BAJA", -0.1, "Sin MTA-STS",
            "Entrega de correo sin TLS impuesto entre servidores.",
            ["Política MTA-STS + TLS-RPT"],
            ["DOMINIO", "FECHA DE ÚLTIMA OBSERVACIÓN"], [[dom, obs]])

    # ---------- DNS ----------
    if not dns.get("spf_record"):
        add("spf_missing", "dns", "BAJA", -0.1, "Falta el registro de SPF",
            "Sin SPF cualquiera puede falsificar el dominio: phishing, spam y daño reputacional; "
            "los legítimos pueden rebotar.",
            ["Registro SPF con remitentes autorizados", "DMARC estricta", "DKIM", "Revisión periódica"],
            ["DOMINIO", "FECHA DE ÚLTIMA OBSERVACIÓN"], [[dom, obs]])
    _mx_txt = ", ".join(m.get("exchange", "") for m in (dns.get("mx_records") or []) if isinstance(m, dict))[:90]
    if (dns.get("mx_records") or []) and not dns.get("dmarc_record"):
        add("dmarc_missing", "dns", "BAJA", -0.5, "Falta el registro DMARC",
            "Con correo en uso (MX) y sin DMARC no hay política ni reportes contra spoofing del dominio.",
            ["Inventariar remitentes legítimos", "DMARC p=none con rua/ruf", "Avanzar a quarantine y luego reject"],
            ["DOMINIO", "MX", "FECHA DE ÚLTIMA OBSERVACIÓN"], [[dom, _mx_txt or "—", obs]])
    if (dns.get("mx_records") or []) and not dns.get("dkim_records"):
        add("dkim_missing", "dns", "BAJA", -0.3, "Sin DKIM publicado",
            "Con correo en uso (MX) y sin selectores DKIM los mensajes no van firmados.",
            ["Publicar selectores DKIM del proveedor de correo", "Rotar claves"],
            ["DOMINIO", "MX", "FECHA DE ÚLTIMA OBSERVACIÓN"], [[dom, _mx_txt or "—", obs]])
    typos = [t for t in (p.get("typosquatting") or []) if isinstance(t, dict) and t.get("domain")]
    no_spf = _typo_spf_missing(typos) if typos else []
    if no_spf:
        add("spf_typo", "dns", "BAJA", -0.1, "Dominios lookalike sin SPF",
            "Typosquats del dominio sin SPF listos para phishing con remitente falsificado.",
            ["Monitoreo de lookalikes", "Registro defensivo/UDRP", "SPF+DMARC donde controle"],
            ["DOMINIO", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[t, obs] for t in no_spf[:10]])

    # ---------- ENDPOINT ----------
    for t in (p.get("takeover_risks") or []):
        if isinstance(t, dict) and t.get("vulnerable"):
            add("takeover", "endpoint", "MEDIA", -1.0, "Subdomain takeover posible",
                f"Subdominio {t.get('subdomain', '?')} apunta a recurso liberado: un atacante puede "
                "tomarlo y servir contenido bajo su marca.",
                ["Elimine CNAME huérfanos", "Reclame o libere el recurso"],
                ["SUBDOMINIO", "DESTINO", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[str(t.get("subdomain", "?")), str(t.get("cname", t.get("target", "?")))[:60], obs]])
            break

    # ---------- CHATTER ----------
    try:
        cti = ((p.get("claude_osint") or {}).get("cti_chatter")) or {}
        rw = ((cti.get("ransomwatch") or {}).get("total", 0)) if isinstance(cti, dict) else 0
        rl = ((cti.get("ransomware_live") or {}).get("total", 0)) if isinstance(cti, dict) else 0
        if (rw + rl) > 0:
            add("cti", "chatter", "BAJA", -0.1,
                "Menciones en fuentes CTI (ransomware)",
                f"{rw + rl} mencion(es) en monitores de ransomware: exposición reputacional a revisar.",
                ["Valide si el activo es propio", "Correlacione con incidentes"],
                ["DOMINIO", "OBSERVACIONES", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[dom, str(rw + rl), obs]])
    except Exception:
        pass

    # ---------- IP REPUTATION ----------
    for rep in ((p.get("dns") or {}).get("ip_reputation") or [])[:5]:
        if isinstance(rep, dict) and rep.get("dnsbl"):
            add(f"dnsbl_{rep.get('ip', '')}_{rep.get('dnsbl', '')}", "iprep", "BAJA", -0.5,
                "IP listada en DNSBL",
                f"La IP {rep.get('ip', '?')} aparece en {rep.get('dnsbl', '?')}: riesgo de bloqueo de "
                "correo y clasificación de abuso.",
                ["Investigue la causa (spam/malware)", "Solicite deslistado", "Endurezca el host"],
                ["DIRECCION IP", "LISTA", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[str(rep.get("ip", "?")), str(rep.get("dnsbl", "?")), obs]])
    uh = p.get("urlhaus") or {}
    if isinstance(uh, dict) and uh.get("malicious"):
        add("urlhaus", "iprep", "MEDIA", -1.0, "URL maliciosa reportada (URLhaus)",
            "El dominio/IP distribuye o aloja malware según URLhaus.",
            ["Limpie el recurso", "Rote credenciales", "Solicite baja del listado"],
            ["DOMINIO", "FECHA DE ÚLTIMA OBSERVACIÓN"], [[dom, obs]])
    scr = p.get("supply_chain_reputation") or {}
    _sdnsbl = [e for e in (scr.get("dnsbl") or []) if isinstance(e, dict) and e.get("dnsbl")]
    _suh = [e for e in (scr.get("urlhaus") or []) if isinstance(e, dict)]
    if _sdnsbl or _suh:
        _srows = []
        for e in (_sdnsbl[:4] + _suh[:2]):
            _srows.append([str(e.get("ip") or e.get("host") or e.get("url", "?"))[:40],
                           str(e.get("dnsbl") or e.get("list") or "URLhaus")[:40], obs])
        add("supply_reputation", "iprep", "BAJA", -0.3,
            "Terceros listados en DNSBL/URLhaus",
            "Dependencias de terceros aparecen en listas de reputación: valide titularidad y "
            "corrobore; shared sin corroboración es contextual, no riesgo directo del proveedor.",
            ["Valide ownership (whois/ASN)", "Corrobore con URLhaus/VT", "Documente shared como contextual"],
            ["IP/URL", "LISTA", "FECHA DE ÚLTIMA OBSERVACIÓN"], _srows)

    # ---------- INFO LEAK ----------
    leaks = [l for l in (p.get("credential_leaks") or []) if isinstance(l, dict) and "error" not in l]
    if leaks:
        rows = []
        for l in leaks[:6]:
            dato = l.get("email") or l.get("username") or l.get("user") or l.get("value") or "credencial"
            rows.append([dom, str(dato)[:40], str(l.get("breach", l.get("source", "breach")))[:40], obs])
        add("creds", "leak", "BAJA", -0.1, "Credenciales en riesgo (hasta 120 dias)",
            "Credenciales asociadas a cuentas del dominio vistas en logs de infostealers o "
            "filtraciones: venta o acceso a activos del dominio.",
            ["Rote credenciales", "MFA", "Revise logins fallidos (MITRE ATT&CK)"],
            ["DOMINIO", "USUARIO", "FUENTE", "FECHA DE ÚLTIMA OBSERVACIÓN"], rows)
    try:
        bi = (((p.get("kumo") or {}).get("breachintel") or {}).get("summary")) or {}
        if int(bi.get("total_employees_leaked", 0) or 0) > 0:
            add("breachintel", "leak", "BAJA", -0.1, "Empleados en filtraciones conocidas",
                f"{bi.get('total_employees_leaked')} empleado(s) en breaches: {', '.join((bi.get('breach_names') or [])[:3])}.",
                ["Rote y MFA", "Concientizacion anti-reuso"],
                ["DOMINIO", "OBSERVACIONES", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[dom, str(bi.get("total_employees_leaked")), obs]])
    except Exception:
        pass

    # ---------- NETWORK ----------
    tls = p.get("tls") or {}
    ver = str(tls.get("negotiated_version") or "")
    if ver and ver not in ("TLSv1.2", "TLSv1.3"):
        add("tls_weak", "network", "ALTA", -10.0, "El servicio SSL/TLS admite un protocolo debil",
            f"Version negociada {ver}: MITM, secuestro de sesion y descifrado posibles.",
            ["Solo TLS 1.2+ con suites solidas", "Actualice librerias", "Autenticacion mutua donde aplique"],
            ["OBJETIVO", "PUERTO", "OBSERVACIONES", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[_first_ipv4(p), "443", "1", obs]])
    ports = [o for o in (p.get("open_ports") or []) if isinstance(o, dict) and o.get("state") == "open"]
    svc_map = {21: ("ftp", "Se ha observado un servicio FTP", "MEDIA", -5.9,
                      "FTP expone archivos a fuerza bruta, DoS y exfiltracion; considere SFTP o lista blanca."),
               23: ("telnet", "Servicio Telnet expuesto", "MEDIA", -4.0,
                    "Telnet transmite credenciales en claro: deshabilitelo o cierrelo."),
               3389: ("rdp", "Se ha observado un servicio RDP", "MEDIA", -4.0,
                       "RDP publico = ransomware y fuerza bruta: VPN o lista blanca."),
               53: ("dns", "Servidor DNS accesible", "MEDIA", -1.0,
                    "DNS mal configurado permite redireccion maliciosa y DDoS: firewall + DNSSEC.")}
    for o in ports:
        try:
            pn = int(o.get("port", 0))
        except Exception:
            continue
        blob = _norm(f"{o.get('service', '')} {o.get('banner', '')} {o.get('product', '')}")
        if pn in svc_map:
            k, title, sev, imp, desc = svc_map[pn]
            add(f"svc_{k}_{pn}", "network", sev, imp, title, desc,
                ["Retire de Internet si es posible", "Lista blanca de IPs", "Audite configuracion"],
                ["NOMBRE DE PRODUCTO", "DIRECCION IP", "PUERTO", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[str(o.get("product", o.get("service", k)))[:40], _first_ipv4(p), str(pn), obs]])
        elif pn in (8080, 3128, 8000, 8888) or "proxy" in blob:
            add(f"proxy_{pn}", "network", "MEDIA", -1.0, "Servicio proxy HTTP detectado",
                "Un proxy intermediario puede interceptar credenciales y trafico si se compromete.",
                ["HTTPS extremo a extremo", "Autenticacion fuerte", "Parche y audite el proxy"],
                ["NOMBRE DE PRODUCTO", "DIRECCION IP", "PUERTO", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[str(o.get("product", o.get("service", "http-proxy")))[:40], _first_ipv4(p), str(pn), obs]])
    exp = str(tls.get("cert_expiry") or "").replace("GMT", "").strip()
    try:
        exp_dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y") if exp else None
        if exp_dt and exp_dt.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            fp = str(tls.get("cert_serial", ""))[:24]
            add("cert_expired", "network", "BAJA", -1.0, "El certificado ha caducado",
                "Los clientes TLS rechazan la conexion; renueve o desmantele el servicio.",
                ["Confirme uso", "Nuevo certificado con su CA", "Politica de renovacion"],
                ["OBJETIVO", "HUELLA DIGITAL SHA-256", "SERIAL NUMBER", "OBSERVACIONES", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[_first_ipv4(p), "—", fp, "1", obs]])
    except Exception:
        pass
    if tls.get("cert_issuer") and tls.get("cert_subject") and \
            _norm(tls.get("cert_issuer")) == _norm(tls.get("cert_subject")):
        add("cert_selfsigned", "network", "BAJA", -0.7, "El certificado es autofirmado",
            "Fuera del trust store: los clientes no conectan y hay riesgo MITM.",
            ["Certificado de CA publica o desmantele"],
            ["OBJETIVO", "OBSERVACIONES", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[_first_ipv4(p), "1", obs]])

    # ---------- PATCHING ----------
    vulns: list[dict[str, Any]] = []
    for v in (p.get("vulnerabilities") or []) + (p.get("cve_findings") or []):
        if isinstance(v, dict):
            vulns.append(v)
    try:
        for v in (((p.get("nuclei") or {}).get("findings")) or []):
            if isinstance(v, dict):
                vulns.append(v)
    except Exception:
        pass
    for v in vulns[:12]:
        sev_raw = _norm(v.get("severity", "") or v.get("severidad", ""))
        cid = str(v.get("cve", v.get("id", v.get("name", "CVE"))) or "CVE")[:24]
        if "CRIT" in sev_raw:
            sv, imp = "MEDIA", -1.8
        elif "HIGH" in sev_raw or "ALTA" in sev_raw:
            sv, imp = "MEDIA", -0.4
        elif "MED" in sev_raw:
            sv, imp = "BAJA", -0.2
        else:
            sv, imp = "BAJA", -0.1
        add(f"cve_{cid}", "patching", sv, imp,
            f"Vulnerabilidad {cid} en servicio (ultima observacion)",
            f"{str(v.get('description', v.get('desc', 'CVE en software expuesto')))[:180]}",
            ["Parchee/actualice", "Actualizaciones automaticas", "Monitoree NVD/EPSS"],
            ["VULNERABILIDAD", "DIRECCION IP", "PUERTO", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[cid, _first_ipv4(p), str(v.get("port", "443")), obs]])
    for t in (p.get("patching") or [])[:4]:
        if isinstance(t, dict) and t.get("status") == "eol":
            add(f"eol_{t.get('technology', '')}", "patching", "BAJA", -0.7,
                f"Tecnologia sin soporte (EOL): {t.get('technology', '?')}",
                "Sin parches del fabricante: explotacion conocida probable.",
                ["Migree a version soportada", "Controles compensatorios"],
                ["TECNOLOGIA", "VERSION", "FECHA DE ÚLTIMA OBSERVACIÓN"],
                [[str(t.get("technology", "?")), str(t.get("version", "—")), obs]])

    # ---------- SOCIAL ----------
    if typos:
        add("typo", "social", "BAJA", -0.1, "Dominios lookalike registrados (typosquatting)",
            "Dominios con errores tipograficos listos para phishing contra su marca.",
            ["Monitoreo continuo", "Registro defensivo/UDRP"],
            ["DOMINIO", "FECHA DE ÚLTIMA OBSERVACIÓN"],
            [[str(t.get("domain", "?")), obs] for t in typos[:10]])
    # ---------- STRIX (pentest autonomo con IA) ----------
    strix = p.get("strix") or {}
    if strix.get("status") == "ok":
        _sv = {"critical": ("ALTA", -3.0), "high": ("ALTA", -3.0),
               "medium": ("MEDIA", -1.5), "low": ("BAJA", -0.8), "info": ("BAJA", -0.1)}
        for f in (strix.get("findings") or [])[:10]:
            if not isinstance(f, dict):
                continue
            sk = str(f.get("severity", "info")).lower()
            sev, imp = _sv.get(sk, ("BAJA", -0.1))
            vid = str(f.get("id") or "STRIX")[:24]
            cve = str(f.get("cve") or "-")
            cvss = str(f.get("cvss") or "-")
            cwe = str(f.get("cwe") or "-")
            endpoint = str(f.get("endpoint") or dom)
            steps = f.get("remediation_steps")
            if isinstance(steps, list) and steps:
                reco = [str(s)[:200] for s in steps[:4]]
            else:
                reco = ["Aplicar la remediacion indicada por Strix"]
            ev = str(f.get("evidence") or f.get("technical_analysis") or "")[:300]
            add("strix_" + vid, "appsec", sev, imp,
                f"Pentest IA (Strix): {str(f.get('title') or 'hallazgo')[:90]}",
                f"Hallazgo {sk.upper()} del pentest autonomo con IA sobre {endpoint}"
                + (f" (CVSS {cvss})" if cvss != "-" else "")
                + (f" - {cve}" if cve != "-" else "")
                + (f" - {cwe}" if cwe != "-" else "") + ".",
                reco,
                ["DOMINIO", "ID", "SEVERIDAD", "CVSS", "CVE", "CWE", "CONFIANZA", "ESFUERZO", "EVIDENCIA"],
                [[dom, vid, sk.upper(), cvss, cve, cwe, str(f.get("confidence") or "-"),
                  str(f.get("fix_effort") or "-"), ev]])
    return issues


def issues_by_factor(issues: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {k: [] for k, _, _ in SSC_FACTORS}
    for i in issues:
        out.setdefault(i["factor"], []).append(i)
    for v in out.values():
        v.sort(key=lambda x: (x["impact"], x["title"]))
    return out

def render_action_items(by_factor: dict[str, list[dict[str, Any]]]) -> str:
    names = {k: n for k, n, _ in SSC_FACTORS}
    rows = []
    for key, name, _ in SSC_FACTORS:
        items = by_factor.get(key, [])
        if not items:
            continue
        rows.append(
            f'<tr class="grp"><td>{esc(name.title())}</td><td></td><td></td><td></td></tr>')
        for it in items:
            rows.append(
                f'<tr><td></td><td>{sev_bars(it["sev"])}</td>'
                f'<td class="impact" style="font-size:12pt;">{fmt_impact(it["impact"], it.get("tiny", False))}</td>'
                f'<td><b>{esc(it["title"])}</b> {(_oasm.render_finding_badges(it) if _oasm else "")}. {esc(it["desc"])}</td></tr>')
    body = "".join(rows) if rows else (
        "<tr><td colspan='4' style='text-align:center; color:#9AA0A6;'>No se encontró ningún problema</td></tr>")
    return f"""
<div class="pb">
  <h2 class="sec" id="sec-b7action">Elementos de accion</h2>
  <table class="act"><thead><tr><th style="width:22%;">Factor</th><th style="width:10%;">Gravedad</th>
  <th style="width:16%;">Impacto en el Score</th><th>Problemas detectados</th></tr></thead>
  <tbody>{body}</tbody></table>
</div>
"""


def render_evidence_table(it: dict[str, Any]) -> str:
    th = "".join(f"<th>{esc(c)}</th>" for c in it["cols"])
    trs = []
    for i, r in enumerate(it["rows"]):
        tds = "".join(f"<td>{esc(c)}</td>" for c in r)
        trs.append(f"<tr{' class=alt' if i % 2 else ''}>{tds}</tr>")
    extra = ""
    for er in it.get("ev_rows", [])[:6]:
        extra += f"<tr><td colspan='{len(it['cols'])}' class='evidence'>Evidence: {esc(er[0])}</td></tr>"
    return (f"<div class='nres'>{len(it['rows'])} fila(s) de evidencia (1 hallazgo = 1 incidencia)</div>"
            f"<table class='ev'><thead><tr>{th}</tr></thead><tbody>{''.join(trs)}{extra}</tbody></table>")


def render_module(key: str, name: str, desc: str, score: int,
                   items: list[dict[str, Any]]) -> str:
    letter = grade_of(score)
    cnt = {"ALTA": 0, "MEDIA": 0, "BAJA": 0}
    for it in items:
        cnt[it["sev"]] = cnt.get(it["sev"], 0) + 1
    boxes = []
    for sev in ("ALTA", "MEDIA", "BAJA"):
        inner = "<br>".join(
            f"{esc(it['title'])} <b style='float:right;'>{len(it['rows'])}</b>" for it in items if it["sev"] == sev
        ) or f"<span class='n'>No hay problemas de gravedad {'alta' if sev == 'ALTA' else 'media' if sev == 'MEDIA' else 'baja'} para {esc(name)}</span>"
        boxes.append(
            f"<div class='sevcol' style='background:{SEV_BG[sev]};'>{sev_bars(sev)}"
            f"<span class='t'>GRAVEDAD {sev}</span><div style='margin-top:2mm;'>{inner}</div></div>")
    if not items:
        detail = '<div class="nodata">No se encontró ningún problema</div>'
    else:
        parts = []
        for it in items:
            reco = "".join(f"<li>{esc(r)}</li>" for r in it["reco"])
            parts.append(
                f"<div class='issue avoid'><div class='issue-head'>{sev_bars(it['sev'])}"
                f"<h4>{esc(it['title'])}</h4>"
                f"<span class='impact'>{fmt_impact(it['impact'], it.get('tiny', False))} "
                f"<small>IMPACTO EN EL SCORE</small></span></div>"
                f"<p style='margin:2mm 0;'>{esc(it['desc'])}</p>"
                f"<div class='twocol'><div><h5>Descripción</h5><p>{esc(it['desc'])}</p></div>"
                f"<div><h5>Recomendación</h5><ul>{reco}</ul></div></div>"
                f"{render_evidence_table(it)}</div>")
        detail = "".join(parts)
    return f"""
<div class="pb">
  <div class="mod-head">{hex_grade(letter, 44, 19)}<span class="score">{score}</span>
    <h3 class="mod" id="sec-b7mod-{esc(key)}">{esc(name)}</h3></div>
  <p>{esc(desc)}</p>
  <div class="sevbox avoid"><div class="sevrow">{"".join(boxes)}</div></div>
  {detail}
</div>
"""


def render_legal(company: str) -> str:
    return f"""
<div class="pb legal">
  <h2 class="sec" id="sec-b7legal" style="font-size:15pt;">Nota legal</h2>
  <p>Los analisis, calificaciones y declaraciones de este documento son opiniones sobre riesgos
  futuros relativos de seguridad a la fecha indicada; no constituyen hechos historicos, recomendaciones
  de negocio ni avales de exactitud. Formula {FORMULA_VERSION}: 10 factores 0-100 con impacto
  decimal por hallazgo; sin datos observados el modulo se reporta limpio; solo se usa lo medido en el escaneo.</p>
  <p>Las calificaciones no sustituyen el juicio del usuario; cada una pondera como un factor mas en
  sus decisiones. Tras remediar, vuelva a medir para actualizar el Score.</p>
  <p>INFORME DETALLADO B7 - {esc(company)} | (c) 2026 GrupoCibest. Derechos reservados.</p>
</div>
"""


def b7_provider_scores(p: dict[str, Any], matrix: list | None = None) -> dict[str, Any]:
    """Motor B7 por proveedor (reutilizable por B6): base precia + issues con
    impacto decimal (incl. OWASP Agentic/Web) -> scores, incidencias y overall."""
    try:
        base = dict(_precia_scores(p)) if _precia_scores else {}
    except Exception:
        base = {}
    for k, _, _ in SSC_FACTORS:
        base.setdefault(k, 100)
    domain = str(p.get("domain", "—"))
    issues = collect_issues(p)
    for m in (matrix or []):
        if isinstance(m, dict) and (m.get("dominio") == domain or m.get("domain") == domain):
            for key, label in (("owasp", "OWASP Agentic Top 10"), ("owasp_web", "OWASP Web Top 10 (2025)")):
                ow = m.get(key) or {}
                if ow and not ow.get("error") and str(ow.get("overall_grade", "?")).strip() not in ("?", "", "-", "N/A"):
                    grade = ow.get("overall_grade", "--")
                    pct = ow.get("overall_compliance", 0)
                    det = "; ".join(
                        f"{rid} {rd.get('grade', '?')} ({rd.get('compliance_pct', '?')}%)"
                        for rid, rd in sorted((ow.get("risks") or {}).items())
                        if isinstance(rd, dict) and rd.get("finding_count", 0) > 0
                    ) or "Sin hallazgos que afecten compliance"
                    sev = "ALTA" if grade in ("F", "D") else "MEDIA" if grade == "C" else "BAJA"
                    imp = -3.0 if grade in ("F", "D") else (-1.5 if grade == "C" else -0.5)
                    issues.append({"key": key + "_b7", "factor": "appsec", "sev": sev, "impact": imp,
                                   "tiny": False,
                                   "title": f"{label} — Grado {grade} ({pct}%)",
                                   "desc": f"Evaluacion {label} del dominio con cumplimiento {pct}%. Riesgos afectados: {det}.",
                                   "reco": ["Revisar los riesgos con grado F y D",
                                            "Corregir cabeceras/TLS/DNS que bajan compliance",
                                            "Re-escanear para verificar remediacion"],
                                   "cols": ["DOMINIO", "MARCO", "GRADO", "CUMPLIMIENTO", "RIESGOS AFECTADOS"],
                                   "rows": [[domain, label, str(grade), f"{pct}%", det[:300]]]})
            break
    by_factor = issues_by_factor(issues)
    scores = {}
    for k, _, _ in SSC_FACTORS:
        deduc = sum(i["impact"] for i in by_factor.get(k, []))
        scores[k] = max(0, min(100, round(base.get(k, 100) + deduc)))
    try:
        overall = int(_precia_overall(scores)) if _precia_overall else int(sum(scores.values()) / max(len(scores), 1))
    except Exception:
        overall = 0
    incidences = {k: len(by_factor.get(k, [])) for k, _, _ in SSC_FACTORS}
    return {"scores": scores, "by_factor": by_factor, "issues": issues,
            "base": base, "overall": overall, "incidences": incidences}


def render_toc_b7() -> str:
    if _render_toc is None:
        return ""
    sections: list[tuple[str, str, str]] = [
        ("1", "Acerca de este informe", "sec-b7about"),
        ("2", "Visión general del Scorecard", "sec-b7overview"),
        ("2.1", "Historial del Score (30 días)", "sec-b7hist"),
        ("2.2", "Enriquecimiento OASM (Score 0-10, tendencia)", "sec-b7oasm"),
        ("3", "Elementos de acción", "sec-b7action"),
        ("4", "Detalle por factor", f"sec-b7mod-{SSC_FACTORS[0][0]}"),
    ]
    for i, (key, name, _desc) in enumerate(SSC_FACTORS, start=1):
        sections.append((f"4.{i}", name.title(), f"sec-b7mod-{key}"))
    sections.append(("5", "Nota legal", "sec-b7legal"))
    return _render_toc(sections, title="Índice",
                       subtitle="Tabla de contenido — haga clic para navegar")


def build_report(asm: dict[str, Any], analista: str = "", email: str = "",
                 org: str = "GrupoCibest") -> str:
    providers = asm.get("providers") or []
    p = providers[0] if providers else {"domain": "—", "name": "—"}
    domain = str(p.get("domain", "—"))
    company = str(p.get("name", "") or domain)
    now = datetime.now(timezone.utc)
    fecha_corta = f"{now.month}/{now.day}/{str(now.year)[2:]}"
    _b7r = b7_provider_scores(p, asm.get("matrix"))
    base, issues, by_factor = _b7r["base"], _b7r["issues"], _b7r["by_factor"]
    scores, overall, incidences = _b7r["scores"], _b7r["overall"], _b7r["incidences"]
    industry_avg = 88
    try:
        sector_en = str(_precia_industry(p)) if _precia_industry else "—"
    except Exception:
        sector_en = "—"
    sector = SECTOR_ES.get(sector_en, sector_en.upper() if sector_en != "—" else "DESCONOCIDO")
    industry_avg = (_INDUSTRY_AVG or {}).get(sector_en) if _INDUSTRY_AVG else None
    hist = history_from_db(domain)
    utc_stamp = fmt_utc_stamp(str(asm.get("generated_utc") or ""), now)
    cover = render_cover(company, domain, fecha_corta, fecha_larga(now), analista, email, org, utc_stamp,
                         int(overall), grade_of(overall), sector, len(issues))
    about = render_about().replace("__HEXA__", hex_grade("A", 64, 30))
    target_letter = grade_of(overall)
    about = about.replace('id="next-grade">Conseguir (A)',
                          f'id="next-grade">{"Permanecer en (A)" if target_letter == "A" else "Conseguir (A)"}')
    about = about.replace('id="now-box"></div>',
                          f'id="now-box">El Score general de esta empresa<br>{hex_grade(target_letter, 64, 30)}</div>')
    overview = render_overview(company, domain, sector, overall, scores, incidences, hist, industry_avg)
    oasm_block = _render_oasm_block_b7(p, domain, overall, issues, hist)
    action = render_action_items(by_factor)
    mods = "".join(render_module(k, n, d, int(scores.get(k, 100)), by_factor.get(k, []))
                   for k, n, d in SSC_FACTORS)
    legal = render_legal(company)
    toc = render_toc_b7()
    return (f"<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>"
            f"<title>Informe Detallado B7 - {esc(domain)}</title>"
            f"{ssc_css_vars(domain, fecha_corta)}<style>{CSS}</style></head><body>"
            f"{cover}{toc}{about}{overview}{oasm_block}{action}{mods}{legal}"
            f"<div class='footer-note'>Formula {FORMULA_VERSION} ({FORMULA_DATE}) · "
            f"Score por factor = base precia + suma de impactos decimales (min 0) · Overall promedio simple v3.0 · "
            f"{len(issues)} hallazgo(s) con impacto decimal · {overall}/100 ({target_letter}) · "
            f"Datos 100% observados del escaneo ASM (no es calificacion oficial SSC).</div>"
            "</body></html>")


def main() -> int:
    ap = argparse.ArgumentParser(description="B7 - Informe Detallado estilo SSC (homologacion visual)")
    ap.add_argument("--asm", type=Path, default=ROOT / "asm_report.json")
    ap.add_argument("--out", type=Path, default=ROOT / "informe_unificado_b7.html")
    ap.add_argument("--analista", default="")
    ap.add_argument("--email", default="")
    ap.add_argument("--org", default="GrupoCibest")
    args = ap.parse_args()
    if not args.asm.is_file():
        print(f"[ERROR] No se encuentra {args.asm}")
        return 1
    data = json.loads(args.asm.read_text(encoding="utf-8"))
    args.out.write_text(build_report(data, args.analista, args.email, args.org), encoding="utf-8")
    print(f"[OK] {args.out}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())


