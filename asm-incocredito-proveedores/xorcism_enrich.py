#!/usr/bin/env python3
"""
Enriquecimiento inspirado en XORCISM-AI/XORCISM (5 capacidades adaptadas a ASM externo).

- A. Fusion (fusion.ts): score compuesto 0-100 por CVE (risk + EPSS + KEV + exploit
  publico + exposicion de red) + ventana de parcheo (horas/dias/semanas).
- B. Taxonomia CTEM (ctem.ts): clasifica los hallazgos ya recolectados en las 8
  categorias CTEM (BND/CRD/DOM/EXP/INF/RAN/SRC) + rollup Discover/Prioritize/Remediate.
- C. Cyber Insurance Readiness (insurance.ts): checklist de controles observables
  externamente (met/partial/gap) y el resto "no observable" (attest).
- D. Madurez PQC (pqcmm.ts): nivel post-cuantico acotado a lo observable en TLS.
- E. Impacto $ ransomware (ransomware.ts/fairmam.ts): estimacion FAIR simplificada
  (SLE/ALE) a partir de la exposicion priorizada.

Puro Python/estandar: sin red, sin dependencias. Degrada a vacio, nunca lanza.
"""

from __future__ import annotations

import html
import re
from typing import Any

_CVE_RX = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)

_SEV_POINTS: dict[str, float] = {
    "critical": 10.0, "critica": 10.0, "crítica": 10.0,
    "high": 7.0, "alta": 7.0,
    "medium": 4.0, "media": 4.0,
    "low": 2.0, "baja": 2.0,
    "info": 0.5,
}

_SEV_COLOR = {
    "critical": "#B71C1C", "high": "#E64A19",
    "medium": "#F29900", "low": "#F9A825", "info": "#607D8B",
}

_RISKY_PORTS = {
    21, 23, 445, 3389, 3306, 5432, 5900, 6379, 27017, 9200,
    11211, 1433, 5985, 5986, 2375, 8080, 8443,
}


def _esc(s: Any) -> str:
    return html.escape(str(s), quote=True)


def _norm_sev(sev: Any) -> str:
    s = str(sev or "info").strip().lower()
    return s if s in _SEV_POINTS else "info"


# --------------------------------------------------------------------------- #
#  A. Fusion score + Top Exposures                                            #
# --------------------------------------------------------------------------- #
def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _fnum(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _fusion_window(kev: bool, epss: float, is_exploit: bool, risk: float) -> str:
    if kev or (is_exploit and epss >= 0.5):
        return "horas"
    if is_exploit or epss >= 0.1 or risk >= 7.0:
        return "dias"
    return "semanas"


def _fusion_priority(score: float, kev: bool) -> str:
    if kev or score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _fusion_items(provider: dict[str, Any]) -> list[dict[str, Any]]:
    dom = provider.get("domain", "N/A")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for v in (provider.get("cve_findings") or []) + (provider.get("vulnerabilities") or []):
        if not isinstance(v, dict):
            continue
        cid = str(v.get("id") or v.get("cve") or v.get("osv_id") or "").strip()
        m = _CVE_RX.search(cid) or _CVE_RX.search(str(v.get("title") or ""))
        key = (m.group(0).upper() if m else cid) or str(len(out))
        if key in seen:
            continue
        seen.add(key)
        risk = _fnum(v.get("risk_score") or v.get("cvss") or v.get("cvss_score"))
        if risk <= 1.0 and _fnum(v.get("cvss")) > 0:
            risk = _fnum(v.get("cvss"))
        epss = _fnum(v.get("epss_score"))
        kev = bool(v.get("in_kev"))
        is_exploit = str(v.get("type", "")).lower() == "exploit"
        port = _int(v.get("port"))
        network_exposed = port in _RISKY_PORTS
        score = risk * 6.0 + (20.0 if kev else 0.0) + (10.0 if is_exploit else 0.0) + epss * 15.0
        if network_exposed:
            score += 5.0
        score = round(max(0.0, min(100.0, score)), 1)
        out.append({
            "id": key,
            "asset": f"{dom}:{port}" if port else dom,
            "riskscore": round(risk, 1),
            "epss": round(epss, 3),
            "kev": kev,
            "exploit": is_exploit,
            "port": port or None,
            "score": score,
            "priority": _fusion_priority(score, kev),
            "window": _fusion_window(kev, epss, is_exploit, risk),
            "title": str(v.get("title") or "")[:140],
        })
    out.sort(key=lambda i: (-i["score"], i["id"]))
    return out


def build_fusion(provider: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(provider, dict):
        return {"items": [], "count": 0, "exposure": 0.0, "by_priority": {}, "by_window": {}}
    try:
        items = _fusion_items(provider)
    except Exception:
        return {"items": [], "count": 0, "exposure": 0.0, "by_priority": {}, "by_window": {}}
    by_priority: dict[str, int] = {}
    by_window: dict[str, int] = {}
    for i in items:
        by_priority[i["priority"]] = by_priority.get(i["priority"], 0) + 1
        by_window[i["window"]] = by_window.get(i["window"], 0) + 1
    scores = [i["score"] for i in items]
    exposure = 0.0
    if scores:
        exposure = round(min(100.0, scores[0] * 0.5 + sum(scores[1:6]) * 0.1), 1)
    return {
        "items": items[:12],
        "count": len(items),
        "exposure": exposure,
        "by_priority": by_priority,
        "by_window": by_window,
    }


def render_fusion_block(domain: str, provider: dict[str, Any]) -> str:
    fx = provider.get("fusion") if isinstance(provider, dict) else None
    if not isinstance(fx, dict) or not fx.get("items"):
        try:
            fx = build_fusion(provider)
        except Exception:
            return ""
    items = fx.get("items") or []
    if not items:
        return ""
    exposure = fx.get("exposure", 0.0)
    count = fx.get("count", len(items))
    exp_c = "#B71C1C" if exposure >= 60 else ("#F29900" if exposure >= 30 else "#1B5E20")
    rows = []
    for it in items:
        color = _SEV_COLOR.get(it.get("priority", "info"), "#607D8B")
        flags = []
        if it.get("kev"):
            flags.append("KEV")
        if it.get("exploit"):
            flags.append("EXP")
        rows.append(
            "<tr>"
            f"<td style=\"font-family:monospace;font-size:8px;\">{_esc(it.get('id'))}</td>"
            f"<td style=\"font-family:monospace;font-size:8px;\">{_esc(it.get('asset'))}</td>"
            f"<td style=\"text-align:right;font-family:monospace;font-size:8px;\">{it.get('riskscore')}</td>"
            f"<td style=\"text-align:right;font-family:monospace;font-size:8px;\">{it.get('epss')}</td>"
            f"<td style=\"font-size:8px;\">{_esc('/'.join(flags) or '-')}</td>"
            f"<td style=\"color:{color};font-weight:bold;font-size:8px;text-transform:uppercase;\">"
            f"{_esc(it.get('priority'))}</td>"
            f"<td style=\"font-size:8px;\">{_esc(it.get('window'))}</td>"
            f"<td style=\"text-align:right;font-family:monospace;font-size:8px;\">{it.get('score')}</td>"
            "</tr>"
        )
    wins = ", ".join(f"{k}={v}" for k, v in sorted(fx.get("by_window", {}).items()))
    return (
        "<h4 style=\"margin:6px 0 3px;\">Fusion score y exposiciones prioritarias (XORCISM)</h4>"
        f"<p style=\"font-size:8.5px;margin:2px 0;\">"
        f"Exposicion fusionada: <b style=\"color:{exp_c};\">{exposure}/100</b> &middot; "
        f"exposiciones: <b>{count}</b>"
        + (f" &middot; ventanas de parcheo: <b>{_esc(wins)}</b>" if wins else "")
        + "</p>"
        "<table style=\"width:100%;border-collapse:collapse;\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">"
        "<thead><tr style=\"background:#EEEEEE;\">"
        "<th style=\"font-size:8px;text-align:left;\">ID</th>"
        "<th style=\"font-size:8px;text-align:left;\">Activo</th>"
        "<th style=\"font-size:8px;text-align:right;\">Risk</th>"
        "<th style=\"font-size:8px;text-align:right;\">EPSS</th>"
        "<th style=\"font-size:8px;text-align:left;\">Flags</th>"
        "<th style=\"font-size:8px;text-align:left;\">Prioridad</th>"
        "<th style=\"font-size:8px;text-align:left;\">Parcheo</th>"
        "<th style=\"font-size:8px;text-align:right;\">Fusion</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


# --------------------------------------------------------------------------- #
#  B. Taxonomia CTEM                                                          #
# --------------------------------------------------------------------------- #
_CTEM_CATS = [
    ("BND", "Boundary"),
    ("DOM", "Domain"),
    ("CRD", "Credential"),
    ("EXP", "Exploitation"),
    ("INF", "Infrastructure"),
    ("RAN", "Ransomware"),
    ("SRC", "Supply Chain"),
]


def _ctem_exposures(provider: dict[str, Any]) -> list[dict[str, Any]]:
    dom = provider.get("domain", "N/A")
    out: list[dict[str, Any]] = []

    def add(cat: str, title: str, sev: str, count: int, evidence: str) -> None:
        out.append({
            "category": cat, "title": title, "severity": _norm_sev(sev),
            "count": count, "evidence": evidence[:180], "asset": dom,
        })

    open_ports = [p for p in (provider.get("open_ports") or []) if isinstance(p, dict) and p.get("open")]
    risky = [p for p in open_ports if _int(p.get("port")) in _RISKY_PORTS]
    if risky:
        add("BND", "Puertos de servicio expuestos", "high", len(risky),
            "puertos: " + ", ".join(str(p.get("port")) for p in risky[:8]))
    waf = provider.get("waf_detection") or {}
    if isinstance(waf, dict) and waf and not waf.get("detected"):
        add("BND", "Sin proteccion WAF/CDN", "medium", 1, "host publico sin WAF/CDN detectado")

    takeover = provider.get("takeover_risks") or []
    typos = provider.get("typosquatting") or []
    zt = provider.get("zone_transfer") or {}
    zt_hit = 1 if (isinstance(zt, dict) and zt.get("vulnerable")) else 0
    dom_count = len(takeover) + len(typos) + zt_hit
    if dom_count:
        add("DOM", "Riesgos de dominio/DNS", "high" if takeover else "medium", dom_count,
            f"takeover={len(takeover)} typosquatting={len(typos)} axfr={zt_hit}")

    leaks = provider.get("credential_leaks") or []
    if leaks:
        add("CRD", "Credenciales filtradas", "high", len(leaks),
            "emails/cuentas expuestas en filtraciones")

    cves = provider.get("cve_findings") or []
    kev = [c for c in cves if isinstance(c, dict) and c.get("in_kev")]
    if cves:
        add("EXP", "Vulnerabilidades explotables", "critical" if kev else "high", len(cves),
            f"CVE={len(cves)} KEV={len(kev)}")

    cs = provider.get("cloud_storage") or {}
    origin = provider.get("origin_ips") or {}
    inf_count = 0
    inf_ev = []
    if isinstance(cs, dict) and (cs.get("publicos") or cs.get("archivos_sensibles")):
        inf_count += 1
        inf_ev.append(f"buckets publicos={len(cs.get('publicos') or [])}")
    if isinstance(origin, dict) and origin.get("exposed"):
        inf_count += 1
        inf_ev.append("IP de origen tras CDN")
    if inf_count:
        add("INF", "Infraestructura expuesta", "high", inf_count, "; ".join(inf_ev))

    ran_flags = []
    if kev:
        ran_flags.append(f"KEV={len(kev)}")
    ran_ports = [p for p in risky if _int(p.get("port")) in (445, 3389)]
    if ran_ports:
        ran_flags.append("RDP/SMB expuesto")
    if ran_flags:
        add("RAN", "Superficie de ransomware", "high", len(ran_flags), ", ".join(ran_flags))

    sc = provider.get("supply_chain") or []
    scorecard = provider.get("scorecard") or {}
    src_count = len(sc)
    src_ev = [f"terceros={len(sc)}"] if sc else []
    if isinstance(scorecard, dict) and scorecard.get("overall_score") is not None:
        src_count += 1
        src_ev.append(f"scorecard={scorecard.get('overall_score')}")
    if src_count:
        add("SRC", "Cadena de suministro", "medium", src_count, ", ".join(src_ev))

    return out


def build_ctem(provider: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(provider, dict):
        return {"exposures": [], "total": 0, "by_category": {}, "rollup": {}}
    try:
        exposures = _ctem_exposures(provider)
    except Exception:
        return {"exposures": [], "total": 0, "by_category": {}, "rollup": {}}
    by_category: dict[str, int] = {}
    for e in exposures:
        by_category[e["category"]] = by_category.get(e["category"], 0) + 1
    prioritize = sum(1 for e in exposures if e["severity"] in ("critical", "high"))
    rollup = {
        "Discover": len(exposures),
        "Prioritize": prioritize,
        "Remediate": len(by_category),
    }
    return {
        "exposures": exposures,
        "total": len(exposures),
        "by_category": by_category,
        "rollup": rollup,
    }


_CAT_LABEL = dict(_CTEM_CATS)


def render_ctem_block(domain: str, provider: dict[str, Any]) -> str:
    ct = provider.get("ctem") if isinstance(provider, dict) else None
    if not isinstance(ct, dict) or not ct.get("exposures"):
        try:
            ct = build_ctem(provider)
        except Exception:
            return ""
    exposures = ct.get("exposures") or []
    if not exposures:
        return ""
    rollup = ct.get("rollup", {})
    cats = " &middot; ".join(
        f"{_esc(_CAT_LABEL.get(k, k))}: <b>{v}</b>" for k, v in ct.get("by_category", {}).items()
    )
    rows = []
    for e in exposures:
        color = _SEV_COLOR.get(e.get("severity", "info"), "#607D8B")
        rows.append(
            "<tr>"
            f"<td style=\"font-family:monospace;font-size:8px;\">{_esc(e.get('category'))}</td>"
            f"<td style=\"font-size:8px;\">{_esc(e.get('title'))}</td>"
            f"<td style=\"color:{color};font-weight:bold;font-size:8px;text-transform:uppercase;\">"
            f"{_esc(e.get('severity'))}</td>"
            f"<td style=\"text-align:right;font-family:monospace;font-size:8px;\">{e.get('count')}</td>"
            f"<td style=\"font-size:8px;\">{_esc(e.get('evidence'))}</td>"
            "</tr>"
        )
    return (
        "<h4 style=\"margin:6px 0 3px;\">Clasificacion CTEM de exposiciones</h4>"
        f"<p style=\"font-size:8.5px;margin:2px 0;\">"
        f"Ciclo: Discover <b>{rollup.get('Discover', 0)}</b> &middot; "
        f"Prioritize <b>{rollup.get('Prioritize', 0)}</b> &middot; "
        f"Remediate <b>{rollup.get('Remediate', 0)}</b></p>"
        + (f"<p style=\"font-size:8px;margin:2px 0;\">{cats}</p>" if cats else "")
        + "<table style=\"width:100%;border-collapse:collapse;\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">"
        "<thead><tr style=\"background:#EEEEEE;\">"
        "<th style=\"font-size:8px;text-align:left;\">Cat</th>"
        "<th style=\"font-size:8px;text-align:left;\">Exposicion</th>"
        "<th style=\"font-size:8px;text-align:left;\">Severidad</th>"
        "<th style=\"font-size:8px;text-align:right;\">N</th>"
        "<th style=\"font-size:8px;text-align:left;\">Evidencia</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


# --------------------------------------------------------------------------- #
#  C. Cyber Insurance Readiness                                               #
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
#  D. Madurez PQC                                                             #
# --------------------------------------------------------------------------- #
_PQC_LEVELS = {
    0: ("Desconocido", "Sin TLS observable"),
    1: ("Legacy", "TLS 1.0/1.1 (sin soporte de intercambio post-cuantico)"),
    2: ("Transicion", "TLS 1.2 (hibridacion PQC no garantizada)"),
    3: ("Aware", "TLS 1.3 (soporta intercambio hibrido PQC en implementaciones modernas)"),
}


def build_pqc(provider: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(provider, dict):
        return {"level": 0, "label": "", "evidence": "", "note": ""}
    tls = provider.get("tls") or {}
    version = str((tls or {}).get("negotiated_version") or "")
    if "1.3" in version:
        level = 3
    elif "1.2" in version:
        level = 2
    elif "1.0" in version or "1.1" in version:
        level = 1
    else:
        level = 0
    label, ev = _PQC_LEVELS[level]
    return {
        "level": level,
        "label": label,
        "evidence": f"{ev}; negociado={version or 'n/d'}",
        "note": "El key-exchange/cifrado no se captura en el probe TLS; nivel acotado a la version negociada.",
    }


def render_pqc_block(domain: str, provider: dict[str, Any]) -> str:
    pq = provider.get("pqc") if isinstance(provider, dict) else None
    if not isinstance(pq, dict) or not pq.get("label"):
        try:
            pq = build_pqc(provider)
        except Exception:
            return ""
    if not pq.get("label"):
        return ""
    color = "#1B5E20" if pq.get("level", 0) >= 3 else ("#F29900" if pq.get("level") == 2 else "#B71C1C")
    return (
        "<h4 style=\"margin:6px 0 3px;\">Madurez post-cuantica (PQC) desde TLS</h4>"
        f"<p style=\"font-size:8.5px;margin:2px 0;\">"
        f"Nivel: <b style=\"color:{color};\">{_esc(pq.get('label'))} ({pq.get('level')}/3)</b> &middot; "
        f"{_esc(pq.get('evidence'))}</p>"
        f"<p style=\"font-size:8px;margin:2px 0;color:#607D8B;\">{_esc(pq.get('note'))}</p>"
    )


# --------------------------------------------------------------------------- #
#  E. Impacto $ ransomware (FAIR simplificado)                                #
# --------------------------------------------------------------------------- #
_BASE_ASSET_VALUE = 25000.0  # USD heuristico por activo expuesto


def build_ransomware(provider: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(provider, dict):
        return {"sle": 0.0, "aro": 0.0, "ale": 0.0, "factors": [], "groups": 0, "note": ""}
    fusion = provider.get("fusion")
    if not isinstance(fusion, dict):
        fusion = build_fusion(provider)
    ct = provider.get("ctem")
    if not isinstance(ct, dict):
        ct = build_ctem(provider)

    cves = provider.get("cve_findings") or []
    kev = sum(1 for c in cves if isinstance(c, dict) and c.get("in_kev"))
    open_ports = [p for p in (provider.get("open_ports") or []) if isinstance(p, dict) and p.get("open")]
    ran_ports = sum(1 for p in open_ports if _int(p.get("port")) in (445, 3389))
    assets = len(provider.get("subdomains") or []) + len(provider.get("crt_subdomains") or []) + 1
    exposure = _fnum(fusion.get("exposure"))

    factors = []
    if kev:
        factors.append(f"KEV={kev}")
    if ran_ports:
        factors.append(f"RDP/SMB={ran_ports}")
    ran_hits = 1 if "RAN" in (ct.get("by_category") or {}) else 0
    if ran_hits:
        factors.append("superficie RAN")

    sev_factor = min(1.0, 0.2 + (exposure / 100.0) * 0.8)
    sle = round(_BASE_ASSET_VALUE * max(1, assets) * sev_factor, 2)
    aro = round(min(0.5, 0.05 + (exposure / 100.0) * 0.45), 3)
    ale = round(sle * aro, 2)

    co = provider.get("claude_osint") or {}
    chatter = co.get("cti_chatter") if isinstance(co, dict) else None
    groups = 0
    if isinstance(chatter, dict):
        groups = len(chatter.get("ransomware") or chatter.get("ransomware_hits") or [])

    return {
        "sle": sle,
        "aro": aro,
        "ale": ale,
        "factors": factors,
        "groups": groups,
        "assets": assets,
        "note": "Estimacion ilustrativa (FAIR simplificado); no usa FinancialValue contractual.",
    }


def render_ransomware_block(domain: str, provider: dict[str, Any]) -> str:
    rw = provider.get("ransomware") if isinstance(provider, dict) else None
    if not isinstance(rw, dict) or not rw.get("sle"):
        try:
            rw = build_ransomware(provider)
        except Exception:
            return ""
    if not rw.get("sle"):
        return ""
    factors = ", ".join(rw.get("factors") or []) or "-"
    return (
        "<h4 style=\"margin:6px 0 3px;\">Impacto financiero ransomware (FAIR simplificado)</h4>"
        f"<p style=\"font-size:8.5px;margin:2px 0;\">"
        f"SLE: <b>${rw.get('sle'):,.0f}</b> &middot; "
        f"ARO: <b>{rw.get('aro')}</b> &middot; "
        f"ALE: <b style=\"color:#B71C1C;\">${rw.get('ale'):,.0f}</b></p>"
        f"<p style=\"font-size:8px;margin:2px 0;\">Activos: {rw.get('assets')} &middot; "
        f"Factores: {_esc(factors)}"
        + (f" &middot; grupos ransomware en chatter: {rw.get('groups')}" if rw.get("groups") else "")
        + f"</p><p style=\"font-size:8px;margin:2px 0;color:#607D8B;\">{_esc(rw.get('note'))}</p>"
    )


# --------------------------------------------------------------------------- #
#  Builders agregados                                                         #
# --------------------------------------------------------------------------- #
def build_xorcism(provider: dict[str, Any]) -> dict[str, Any]:
    """Construye los 5 bloques. Nunca lanza: cada sub-builder degrada a vacio."""
    if not isinstance(provider, dict):
        return {"fusion": {}, "ctem": {}, "insurance": {}, "pqc": {}, "ransomware": {}}
    out: dict[str, Any] = {}
    for key, fn in (
        ("fusion", build_fusion),
        ("ctem", build_ctem),
        ("insurance", build_insurance),
        ("pqc", build_pqc),
        ("ransomware", build_ransomware),
    ):
        try:
            out[key] = fn(provider)
        except Exception:
            out[key] = {}
    return out


def build_insurance(provider: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(provider, dict):
        return {"controls": [], "met": 0, "partial": 0, "gap": 0, "attest": 0, "score": 0.0}
    try:
        dns = provider.get("dns") or {}
        tls = provider.get("tls") or {}
        https = provider.get("https") or {}
        headers = (https.get("headers") or {}) if isinstance(https, dict) else {}
        cves = provider.get("cve_findings") or []
        kev = sum(1 for c in cves if isinstance(c, dict) and c.get("in_kev"))
        waf = provider.get("waf_detection") or {}
        sc = provider.get("scorecard") or {}

        spf = dns.get("spf_record")
        dmarc = dns.get("dmarc_record")
        dmarc_pol = str(dns.get("dmarc_policy") or "").lower()
        if spf and dmarc and dmarc_pol in ("reject", "quarantine"):
            email = "met"
        elif spf or dmarc:
            email = "partial"
        else:
            email = "gap"

        version = str(tls.get("negotiated_version") or "")
        if "1.3" in version or "1.2" in version:
            tls_st = "met"
        elif version:
            tls_st = "gap"
        else:
            tls_st = "gap"

        if not cves:
            patch = "met"
        elif kev == 0:
            patch = "partial"
        else:
            patch = "gap"

        waf_st = "met" if (isinstance(waf, dict) and waf.get("detected")) else "gap"

        hsts = str(headers.get("strict-transport-security") or "")
        xfo = str(headers.get("x-frame-options") or "")
        csp = str(headers.get("content-security-policy") or "")
        n_ok = sum(1 for h in (hsts, xfo, csp) if h)
        hygiene = "met" if n_ok == 3 else ("partial" if n_ok >= 1 else "gap")

        sc_score = sc.get("overall_score") if isinstance(sc, dict) else None
        if sc_score is None:
            supply = "attest"
        elif _fnum(sc_score) >= 6:
            supply = "met"
        elif _fnum(sc_score) >= 4:
            supply = "partial"
        else:
            supply = "gap"

        controls = [
            {"name": "Autenticacion de correo (SPF/DMARC)", "status": email,
             "evidence": f"SPF={'si' if spf else 'no'} DMARC={'si' if dmarc else 'no'} policy={dmarc_pol or 'n/d'}"},
            {"name": "Cifrado en transito (TLS 1.2+)", "status": tls_st,
             "evidence": f"negociado={version or 'n/d'}"},
            {"name": "Gestion de parches (CISA KEV)", "status": patch,
             "evidence": f"CVE={len(cves)} KEV={kev}"},
            {"name": "Proteccion perimetral (WAF/CDN)", "status": waf_st,
             "evidence": "WAF/CDN detectado" if waf_st == "met" else "sin WAF/CDN detectado"},
            {"name": "Higiene de cabeceras (HSTS/XFO/CSP)", "status": hygiene,
             "evidence": f"{n_ok}/3 cabeceras presentes"},
            {"name": "Cadena de suministro (OpenSSF Scorecard)", "status": supply,
             "evidence": f"score={sc_score if sc_score is not None else 'sin datos'}"},
            {"name": "MFA / EDR / Backups", "status": "attest",
             "evidence": "No observable externamente (requiere atestacion del proveedor)"},
        ]
    except Exception:
        return {"controls": [], "met": 0, "partial": 0, "gap": 0, "attest": 0, "score": 0.0}

    met = sum(1 for c in controls if c["status"] == "met")
    partial = sum(1 for c in controls if c["status"] == "partial")
    gap = sum(1 for c in controls if c["status"] == "gap")
    attest = sum(1 for c in controls if c["status"] == "attest")
    observable = met + partial + gap
    score = round((met + partial * 0.5) / observable * 100.0, 1) if observable else 0.0
    return {"controls": controls, "met": met, "partial": partial, "gap": gap,
            "attest": attest, "score": score}


_INS_STATUS = {
    "met": ("MET", "#1B5E20"),
    "partial": ("PARCIAL", "#F29900"),
    "gap": ("GAP", "#B71C1C"),
    "attest": ("NO OBSERVABLE", "#607D8B"),
}


def render_insurance_block(domain: str, provider: dict[str, Any]) -> str:
    ins = provider.get("insurance") if isinstance(provider, dict) else None
    if not isinstance(ins, dict) or not ins.get("controls"):
        try:
            ins = build_insurance(provider)
        except Exception:
            return ""
    controls = ins.get("controls") or []
    if not controls:
        return ""
    score = ins.get("score", 0.0)
    sc_c = "#1B5E20" if score >= 70 else ("#F29900" if score >= 40 else "#B71C1C")
    rows = []
    for c in controls:
        label, color = _INS_STATUS.get(c.get("status", "attest"), ("?", "#607D8B"))
        rows.append(
            "<tr>"
            f"<td style=\"font-size:8px;\">{_esc(c.get('name'))}</td>"
            f"<td style=\"color:{color};font-weight:bold;font-size:8px;text-transform:uppercase;\">{label}</td>"
            f"<td style=\"font-size:8px;\">{_esc(c.get('evidence'))}</td>"
            "</tr>"
        )
    return (
        "<h4 style=\"margin:6px 0 3px;\">Preparacion para ciberseguro (controles observables)</h4>"
        f"<p style=\"font-size:8.5px;margin:2px 0;\">"
        f"Cumplimiento observable: <b style=\"color:{sc_c};\">{score}%</b> &middot; "
        f"met <b>{ins.get('met', 0)}</b> &middot; parcial <b>{ins.get('partial', 0)}</b> &middot; "
        f"gap <b>{ins.get('gap', 0)}</b> &middot; no observable <b>{ins.get('attest', 0)}</b></p>"
        "<table style=\"width:100%;border-collapse:collapse;\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">"
        "<thead><tr style=\"background:#EEEEEE;\">"
        "<th style=\"font-size:8px;text-align:left;\">Control</th>"
        "<th style=\"font-size:8px;text-align:left;\">Estado</th>"
        "<th style=\"font-size:8px;text-align:left;\">Evidencia</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
