#!/usr/bin/env python3
"""
toc_helper.py — Índice / Tabla de Contenido para todos los informes.
Diseño unificado, numeración real del informe, líderes punteados y anclas clickeables.
Sin números de página estimados (evita desajuste). Tipología: navy #1A3A4A, gris #6B7280.
"""
from __future__ import annotations
import html as _html

def _esc(s) -> str:
    return _html.escape(str(s), quote=True)

# Mapeo por tipo de informe — debe coincidir con los id="..." reales del HTML
TOC_BY_REPORT = {
    "tpra": [
        ("1", "Resumen de evaluación", "resumen"),
        ("2", "Hallazgos agregados", "reglas"),
        ("3", "Puntuaciones indicativas", "puntuaciones"),
        ("4", "Matriz de controles (ASM)", "matriz"),
        ("5", "Superficie de ataque por proveedor", "superficie"),
        ("6", "Puertos observados (80 / 443)", "puertos"),
        ("7", "OSINT pasivo — CT, SAN, CAA, MTA-STS", "osint"),
        ("8", "CVEs frecuentes en ransomware", "ransomware"),
        ("9", "Hallazgos de vulnerabilidad", "vulns"),
    ],
    "b3": [
        ("1", "Acerca de este informe", "sec-acerca-de-este-informe"),
        ("2", "Resumen Ejecutivo", "sec-resumen-ejecutivo"),
        ("3", "Score General / Puntuación General (Negocio)", "sec-scorecard-de-seguridad"),
        ("4", "Análisis Pasivo / Activo", "sec-analisis-pasivo-activo"),
        ("5", "Matriz de Riesgo y Controles", "sec-matriz-de-riesgo-y-controles"),
        ("6", "Detalle de Hallazgos", "sec-detalle-de-hallazgos"),
        ("7", "Recomendaciones Priorizadas", "sec-recomendaciones-priorizadas"),
        ("8", "Fuentes y Referencias", "sec-fuentes-y-referencias"),
        ("9", "Anexos", "sec-anexos"),
    ],
        "a1": [
        ("1", "Resumen Ejecutivo", "sec-resumen-ejecutivo"),
        ("2", "Acerca de este informe", "sec-acerca-de-este-informe"),
        ("3", "Vision General del Scorecard", "sec-vision-general-del-scorecard"),
        ("4", "Factores de Riesgo", "sec-factores-de-riesgo"),
        ("5", "Historial del Score (30 dias)", "sec-historial-del-score-30-dias"),
        ("6", "Elementos de Accion", "sec-elementos-de-accion"),
    ],
    "b2": [
        ("1", "Resumen Ejecutivo", "sec-resumen-ejecutivo"),
        ("2", "Score General y Factores", "sec-score-general-y-factores"),
        ("3", "Hallazgos Detallados", "sec-hallazgos-detallados"),
        ("4", "Recomendaciones Priorizadas", "sec-recomendaciones-priorizadas"),
        ("5", "Conclusiones", "sec-conclusiones"),
    ],
    "beta1": [
        ("1", "Resumen Ejecutivo", "sec-resumen-ejecutivo"),
        ("2", "Análisis de Riesgos", "sec-analisis-de-riesgos"),
        ("2.1", "Riesgos Identificados", "sec-riesgos-identificados"),
        ("2.2", "Matriz de Probabilidad e Impacto", "sec-matriz-de-probabilidad-e-impacto"),
        ("2.3", "Evaluación de Superficie de Ataque", "sec-evaluacion-de-superficie-de-ataque"),
        ("3", "Recomendaciones", "sec-recomendaciones"),
        ("4", "Estado de Seguridad Actual", "sec-estado-de-seguridad-actual"),
        ("5", "Conclusiones", "sec-conclusiones"),
        ("6", "Fuentes y Referencias", "sec-fuentes-y-referencias"),
    ],
    "ppasivo": [
        ("1", "Resumen Ejecutivo (Pasivo)", "sec-resumen-ejecutivo-pasivo"),
        ("2", "Métricas Clave", "sec-metricas-clave"),
        ("3", "Puntajes por Factor (Pasivo)", "sec-puntajes-por-factor-pasivo"),
        ("4", "Hallazgos Detallados", "sec-hallazgos-detallados"),
        ("5", "Superficie de Ataque", "sec-superficie-de-ataque"),
        ("6", "Fuentes y Referencias", "sec-fuentes-y-referencias"),
    ],
    "default": [
        ("1", "Resumen Ejecutivo", "sec-resumen-ejecutivo"),
        ("2", "Análisis de Riesgos", "sec-analisis-de-riesgos"),
        ("3", "Recomendaciones", "sec-recomendaciones"),
        ("4", "Estado de Seguridad Actual", "sec-estado-de-seguridad-actual"),
        ("5", "Conclusiones", "sec-conclusiones"),
        ("6", "Fuentes y Referencias", "sec-fuentes-y-referencias"),
    ],
}

def render_toc(sections: list[tuple[str,str]] | list[tuple[str,str,str]] | None = None, title: str = "Índice", subtitle: str = "Tabla de contenido — haga clic para navegar", report_type: str = "default") -> str:
    """
    sections: lista de (num, titulo) o (num, titulo, anchor). Si None, usa DEFAULT por report_type.
    report_type: clave para TOC_BY_REPORT cuando sections es None.
    """
    if sections is None:
        sections = TOC_BY_REPORT.get(report_type, TOC_BY_REPORT["default"])
    # Normalizar a (num, titulo, anchor)
    norm = []
    for item in sections:
        if len(item) == 3:
            num, title_text, anchor = item
        else:
            num, title_text = item
            anchor = title_text.lower().replace(" ", "-").replace("á","a").replace("é","e").replace("í","i").replace("ó","o").replace("ú","u").replace("ñ","n")
            anchor = "".join(c for c in anchor if c.isalnum() or c in "-_")
            anchor = f"sec-{anchor}"
        norm.append((num, title_text, anchor))
    items = ""
    for num, title_text, anchor in norm:
        is_sub = "." in num
        items += f'<a href="#{anchor}" class="{"toc-sub" if is_sub else "toc-item"}" style="display:flex; align-items:baseline; gap:10px; padding:7px 0; border-bottom:1px solid #F3F4F6; text-decoration:none; color:inherit;">'
        items += f'<span style="width:42px; flex-shrink:0; font-weight:700; color:#1A3A4A; font-size:9px;">{num}</span>'
        items += f'<span style="flex:1; color:#1F2933; font-size:9px; font-weight:{"600" if not is_sub else "400"};">{_esc(title_text)}</span>'
        items += f'<span style="flex:1; border-bottom:1px dotted #D1D5DB; margin:0 8px; height:0; align-self:center;"></span>'
        items += f'<span style="width:16px; text-align:right; color:#9CA3AF; font-size:7px;">›</span>'
        items += '</a>\n'
    return f"""
<div class="toc" id="toc" style="background:#fff; border:1px solid #E5E7EB; border-radius:12px; padding:18px 20px; margin:18px 0; page-break-after:always; font-family:Arial,Helvetica,sans-serif;">
  <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:10px; border-bottom:2px solid #1A3A4A; padding-bottom:8px;">
    <h2 style="margin:0; font-size:14px; font-weight:800; color:#1A3A4A; letter-spacing:0.06em; text-transform:uppercase;">{_esc(title)}</h2>
    <span style="font-size:7px; color:#6B7280; letter-spacing:0.08em; text-transform:uppercase;">{_esc(subtitle)}</span>
  </div>
  {items}
  <div style="margin-top:10px; padding:8px 10px; background:#F9FAFB; border:1px solid #E5E7EB; border-radius:8px; font-size:6.5px; color:#6B7280; line-height:1.4;">
    <b>Tip:</b> Cada entrada es clickeable y lleva a su sección. Use <code>Ctrl+F</code> para buscar dentro del informe.
  </div>
</div>
<style>
  .toc a:hover {{ background:#F9FAFB; border-radius:6px; }}
  .toc-sub {{ padding-left:22px !important; }}
  @media print {{ .toc {{ page-break-after: always; }} }}
</style>
"""
