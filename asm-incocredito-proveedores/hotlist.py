#!/usr/bin/env python3
"""
Hotlist de activos riesgosos (inspirado en el Hotlist Builder de reconFTW).

Sintetiza los hallazgos ya recolectados por el escaneo (CVEs, takeover,
credenciales, typosquatting, cabeceras/cookies, puertos, WAF, cadena de
suministro, transferencia de zona e IP de origen expuesta) en un ranking
unico de los activos/hallazgos de mayor riesgo, con un score compuesto
0-100. Puro Python/estandar: degrada a vacio, nunca lanza.
"""

from __future__ import annotations

import html
from typing import Any

_SEV_POINTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 0.5,
}

_ES_TO_EN = {
    "critica": "critical", "crítica": "critical", "critical": "critical",
    "alta": "high", "high": "high",
    "media": "medium", "medium": "medium",
    "baja": "low", "low": "low",
    "info": "info", "informativa": "info",
}

_SEV_COLOR = {
    "critical": "#B71C1C",
    "high": "#E64A19",
    "medium": "#F29900",
    "low": "#F9A825",
    "info": "#607D8B",
}

_RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 3306: "MySQL",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
    9200: "Elasticsearch", 11211: "Memcached", 1433: "MSSQL", 5985: "WinRM",
    5986: "WinRM-TLS", 2375: "Docker", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def _norm_sev(sev: Any) -> str:
    s = str(sev or "info").strip().lower()
    return _ES_TO_EN.get(s, s if s in _SEV_POINTS else "info")


def _pts(sev: Any) -> float:
    return _SEV_POINTS.get(_norm_sev(sev), 0.5)


def _item(asset: str, category: str, severity: Any, detail: str,
          score: float | None = None) -> dict[str, Any]:
    sev = _norm_sev(severity)
    s = round(score, 1) if score is not None else round(_pts(sev) * 10.0, 1)
    return {
        "asset": asset,
        "category": category,
        "severity": sev,
        "score": max(0.0, min(100.0, s)),
        "detail": (detail or "")[:240],
    }


def _extract(provider: dict[str, Any]) -> list[dict[str, Any]]:
    dom = provider.get("domain", "N/A")
    items: list[dict[str, Any]] = []

    # CVEs (banner grab) y vulnerabilidades OSV
    for v in (provider.get("cve_findings") or []):
        if not isinstance(v, dict):
            continue
        cid = v.get("cve") or v.get("id") or v.get("template") or "CVE"
        port = v.get("port")
        sev = v.get("severity") or v.get("cvss_severity") or "high"
        score = None
        cvss = v.get("cvss") or v.get("cvss_score")
        try:
            if cvss is not None:
                score = float(cvss) * 10.0
        except Exception:
            score = None
        detail = f"{cid}" + (f" (puerto {port})" if port else "")
        title = v.get("title") or v.get("description")
        if title:
            detail += f" -- {str(title)[:120]}"
        items.append(_item(f"{dom}:{port or ''}".rstrip(":"), "Vulnerabilidad (CVE)", sev, detail, score))

    for v in (provider.get("vulnerabilities") or []):
        if not isinstance(v, dict):
            continue
        vid = v.get("id") or v.get("osv_id") or v.get("cve") or "OSV"
        sev = v.get("severity") or "medium"
        items.append(_item(v.get("package") or dom, "Dependencia vulnerable", sev,
                           f"{vid} {str(v.get('summary') or '')[:140]}"))

    # Subdomain takeover
    for t in (provider.get("takeover_risks") or []):
        if not isinstance(t, dict):
            continue
        host = t.get("host") or t.get("subdomain") or t.get("fqdn") or dom
        prov = t.get("provider") or t.get("service") or t.get("fingerprint") or "?"
        items.append(_item(host, "Subdomain takeover", t.get("severity") or "high",
                           f"CNAME colgante hacia {prov}"))

    # Credenciales filtradas
    for c in (provider.get("credential_leaks") or []):
        if not isinstance(c, dict):
            continue
        email = c.get("email") or c.get("user") or c.get("account") or "?"
        src = c.get("source") or c.get("breach") or "?"
        items.append(_item(email, "Fuga de credenciales", c.get("severity") or "high",
                           f"Origen: {src}"))

    # Typosquatting
    for t in (provider.get("typosquatting") or []):
        if not isinstance(t, dict):
            continue
        d = t.get("domain") or t.get("fqdn") or "?"
        items.append(_item(d, "Typosquatting", t.get("severity") or "medium",
                           f"Distancia={t.get('distance', '?')} resolucion={t.get('resolves', '?')}"))

    # CSP
    for c in (provider.get("csp_findings") or []):
        if not isinstance(c, dict):
            continue
        items.append(_item(dom, "Cabeceras / CSP", c.get("severity") or "medium",
                           str(c.get("issue") or c.get("detail") or c.get("type") or "CSP debil")))

    # Cookies
    for c in (provider.get("cookie_findings") or []):
        if not isinstance(c, dict):
            continue
        items.append(_item(dom, "Cookies", c.get("severity") or "medium",
                           str(c.get("issue") or c.get("detail") or c.get("name") or "Cookie sin flags")))

    # Puertos riesgosos abiertos
    for p in (provider.get("open_ports") or []):
        if not isinstance(p, dict):
            continue
        if not p.get("open"):
            continue
        try:
            port = int(p.get("port"))
        except Exception:
            continue
        if port in _RISKY_PORTS:
            sev = "high" if port in (445, 3389, 3306, 5432, 6379, 27017, 9200, 2375, 5985, 5986) else "medium"
            items.append(_item(f"{dom}:{port}", "Puerto expuesto", sev,
                               f"{_RISKY_PORTS[port]} alcanzable ({p.get('service') or 'servicio'})",
                               _sev_points_override(sev)))

    # Ausencia de WAF/CDN
    waf = provider.get("waf_detection") or {}
    if isinstance(waf, dict) and waf and not waf.get("detected"):
        items.append(_item(dom, "Sin WAF/CDN", "medium",
                           "No se detecto proteccion WAF/CDN frente al host publico"))

    # Transferencia de zona (AXFR)
    zt = provider.get("zone_transfer") or {}
    if isinstance(zt, dict) and zt.get("vulnerable"):
        items.append(_item(dom, "Transferencia de zona (AXFR)", "high",
                           f"AXFR permitido desde {zt.get('ns', '?')} ({zt.get('ip', '?')}); "
                           f"{len(zt.get('records') or [])} registros expuestos"))

    # IP de origen expuesta tras CDN/WAF
    oi = provider.get("origin_ips") or {}
    if isinstance(oi, dict) and oi.get("exposed"):
        cands = ", ".join(str(c.get("ip")) for c in (oi.get("origin_candidates") or [])[:3])
        items.append(_item(dom, "IP de origen expuesta", "high",
                           f"Posible backend tras CDN/WAF: {cands or '?'}"))

    # Cadena de suministro
    for s in (provider.get("supply_chain") or []):
        if not isinstance(s, dict):
            continue
        items.append(_item(dom, "Cadena de suministro", s.get("severity") or "medium",
                           str(s.get("issue") or s.get("detail") or s.get("name") or "Tercero sin control")))

    return items


def _sev_points_override(sev: str) -> float:
    return _pts(sev) * 10.0


def build_hotlist(provider: dict[str, Any]) -> dict[str, Any]:
    """Construye el hotlist a partir de un proveedor (dict de asm_report)."""
    if not isinstance(provider, dict):
        return {"items": [], "count": 0, "exposure": 0.0}
    try:
        items = _extract(provider)
    except Exception:
        return {"items": [], "count": 0, "exposure": 0.0}
    items.sort(key=lambda i: (-i["score"], i["category"], i["asset"]))
    top = items[:12]
    scores = [i["score"] for i in items]
    exposure = 0.0
    if scores:
        exposure = round(min(100.0, scores[0] * 0.5 + sum(scores[1:6]) * 0.1), 1)
    return {
        "items": top,
        "count": len(items),
        "exposure": exposure,
        "by_category": _by_category(items),
    }


def _by_category(items: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        out[i["category"]] = out.get(i["category"], 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _esc(s: Any) -> str:
    return html.escape(str(s), quote=True)


def render_hotlist_block(domain: str, provider: dict[str, Any]) -> str:
    """Bloque HTML del hotlist para B5/B6/B7. '' si no hay hallazgos."""
    hl = provider.get("hotlist") if isinstance(provider, dict) else None
    if not isinstance(hl, dict) or not hl.get("items"):
        try:
            hl = build_hotlist(provider)
        except Exception:
            return ""
    items = hl.get("items") or []
    if not items:
        return ""
    exposure = hl.get("exposure", 0.0)
    count = hl.get("count", len(items))
    try:
        exp_c = "#B71C1C" if exposure >= 60 else ("#F29900" if exposure >= 30 else "#1B5E20")
    except Exception:
        exp_c = "#607D8B"
    rows = []
    for it in items:
        color = _SEV_COLOR.get(it.get("severity", "info"), "#607D8B")
        rows.append(
            "<tr>"
            f"<td style=\"font-family:monospace;font-size:8px;\">{_esc(it.get('asset'))}</td>"
            f"<td style=\"font-size:8px;\">{_esc(it.get('category'))}</td>"
            f"<td style=\"color:{color};font-weight:bold;font-size:8px;text-transform:uppercase;\">"
            f"{_esc(it.get('severity'))}</td>"
            f"<td style=\"text-align:right;font-family:monospace;font-size:8px;\">{it.get('score')}</td>"
            f"<td style=\"font-size:8px;\">{_esc(it.get('detail'))}</td>"
            "</tr>"
        )
    return (
        "<h4 style=\"margin:6px 0 3px;\">Activos de mayor riesgo (Hotlist)</h4>"
        f"<p style=\"font-size:8.5px;margin:2px 0;\">"
        f"Exposicion estimada: <b style=\"color:{exp_c};\">{exposure}/100</b> &middot; "
        f"hallazgos priorizados: <b>{count}</b></p>"
        "<table style=\"width:100%;border-collapse:collapse;\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">"
        "<thead><tr style=\"background:#EEEEEE;\">"
        "<th style=\"font-size:8px;text-align:left;\">Activo</th>"
        "<th style=\"font-size:8px;text-align:left;\">Categoria</th>"
        "<th style=\"font-size:8px;text-align:left;\">Severidad</th>"
        "<th style=\"font-size:8px;text-align:right;\">Score</th>"
        "<th style=\"font-size:8px;text-align:left;\">Detalle</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
