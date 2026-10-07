#!/usr/bin/env python3
"""
score_legend.py — Bloque de aclaración B5 (Factor Score abolido).
B4 opera con 2 scores: Domain Score (Técnico) + Puntuación Global (oficial, ponderado).
Factor Score (10 factores, B3) legado — abolido en B4, se muestra atenuado.

- Domain Score (Técnico)          → heurística 25 controles (HSTS, CSP, TLS, SPF/DMARC, etc.) 0-100
- Puntuación Global (Scorecard)     → promedio PONDERADO de 10 factores SecurityScorecard 0-100 — oficial B5
- Factor Score (Negocio, B3)       → promedio simple 10 factores — legado, abolido en B4

Uso:
  from score_legend import render_score_legend
  html += render_score_legend()
"""
from __future__ import annotations

def render_score_legend() -> str:
    return """
    <div style="background:#F9FAFB; border:1px solid #E5E7EB; border-left:4px solid #2563EB; border-radius:8px; padding:10px 12px; margin:12px 0; font-family:Arial,Helvetica,sans-serif;">
      <div style="font-size:8px; font-weight:800; letter-spacing:0.08em; color:#1A3A4A; text-transform:uppercase; margin-bottom:6px;">Aclaración — No son el mismo número</div>
      <div style="display:flex; gap:10px; flex-wrap:wrap; font-size:7.5px; line-height:1.5; color:#374151;">
        <div style="flex:1 1 160px; background:#fff; border:1px solid #E5E7EB; border-radius:6px; padding:8px;">
          <div style="font-weight:800; color:#111827;">Domain Score <span style="font-weight:400; color:#6B7280;">(Técnico)</span></div>
          <div>Heurística de <b>25 controles</b> visibles (HSTS, CSP, TLS 1.3, SPF <code>-all</code>, DMARC, STARTTLS, DNSSEC, etc.). Capado a 100. Ej.: <b>100.0/100</b></div>
          <div style="color:#6B7280; font-style:italic; margin-top:4px;">Mide higiene técnica externa.</div>
        </div>
        <div style="flex:1 1 160px; background:#fff; border:1px solid #E5E7EB; border-radius:6px; padding:8px; opacity:0.6;">
          <div style="font-weight:800; color:#9CA3AF;">Factor Score / Puntuación General <span style="font-weight:400; color:#9CA3AF;">(Negocio) — Legado B3, abolido en B4</span></div>
          <div style="color:#9CA3AF;">Promedio simple de <b>10 factores</b> (cada factor 0-100 = 100 - incidencias×2). Ej.: <b>98/100</b></div>
          <div style="color:#9CA3AF; font-style:italic; margin-top:4px;">B3 oficial — <b>abolido en B4</b>.</div>
        </div>
        <div style="flex:1 1 160px; background:#fff; border:1px solid #E5E7EB; border-radius:6px; padding:8px;">
          <div style="font-weight:800; color:#111827;">Puntuación Global <span style="font-weight:400; color:#6B7280;">(Scorecard)</span></div>
          <div>Promedio <b>ponderado</b> de <b>10 factores</b> estilo SecurityScorecard (Network/DNS/Patching×1.2). Ej.: <b>87-98/100</b></div>
          <div style="color:#1A3A4A; font-style:italic; margin-top:4px; font-weight:700;">Es el <b>oficial B5</b> (gauge, grado A-F, “Estado general”) — benchmarking sectorial.</div>
        </div>
      </div>
      <div style="font-size:6.5px; color:#6B7280; margin-top:8px; border-top:1px solid #E5E7EB; padding-top:6px;">
        <b>Calificación general</b> y <b>Estado general</b> usan la <b>Puntuación Global</b> — por eso deben coincidir. <b>Domain Score</b> y <b>Puntuación Global</b> son métricas distintas con distinta fórmula; verlas diferentes no es error.
      </div>
    </div>
    """
