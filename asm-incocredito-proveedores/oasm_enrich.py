#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""oasm_enrich - enriquecimientos estilo OASM (open-asm) compartidos por B5/B6/B7.

Modulo puro stdlib. Degrada a vacio/no-op cuando no hay scan_history.db o datos.
Expone: score 0-10 (formula OASM), riskLevel, distribucion/barra de severidad,
comparativa vs escaneo anterior, bloque de tendencia y enriquecimiento de hallazgos.
"""
from __future__ import annotations
import html
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "dashboard_workspace" / "scan_history.db"

SEV_KEYS = ("critical", "high", "medium", "low", "info")
SEV_WEIGHT = {"critical": 5.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.5}
SEV_ES = {"critical": "CRITICO", "high": "ALTO", "medium": "MEDIO",
          "low": "BAJO", "info": "INFORMATIVO"}
SEV_COLOR = {"critical": "#B71C1C", "high": "#E53935", "medium": "#F29900",
             "low": "#1976D2", "info": "#9AA0A6"}

_ES_MAP = {
    "CRITICA": "critical", "CRITICAL": "critical", "CRITICO": "critical",
    "ALTA": "high", "HIGH": "high", "ALTO": "high",
    "MEDIA": "medium", "MEDIUM": "medium", "MEDIO": "medium",
    "BAJA": "low", "LOW": "low", "BAJO": "low",
    "INFORMATIVA": "info", "INFORMATIVO": "info", "INFORMATION": "info",
    "INFO": "info", "NONE": "info", "N/A": "info", "": "info",
}


def _esc(s: Any) -> str:
    return html.escape(str(s))


def canon_severity(value: Any) -> str:
    return _ES_MAP.get(str(value or "").strip().upper(), "info")


def severity_counts(values) -> dict[str, float]:
    out = {k: 0 for k in SEV_KEYS}
    for v in values:
        out[canon_severity(v)] += 1
    return out


def counts_from_findings(findings, key: str = "severidad") -> dict[str, float]:
    vals = [(f or {}).get(key) if isinstance(f, dict) else f for f in (findings or [])]
    return severity_counts(vals)


def security_score(counts: dict[str, Any], total_assets: int) -> float:
    """Formula OASM (statistic.service.ts) en escala 0-10 (mayor = mas seguro)."""
    if total_assets <= 0:
        return 10.0
    vul_risk = sum(SEV_WEIGHT.get(k, 0.0) * float(counts.get(k, 0) or 0) for k in SEV_KEYS)
    r_vuln = min(10.0, vul_risk / float(total_assets))
    r_asset = min(10.0, float(total_assets) / 100.0)
    return round(max(0.0, 10.0 - (0.3 * r_asset + 0.7 * r_vuln)), 1)


def risk_level(counts: dict[str, Any]) -> str:
    c = float(counts.get("critical", 0) or 0)
    h = float(counts.get("high", 0) or 0)
    m = float(counts.get("medium", 0) or 0)
    if c >= 1:
        return "critical"
    if (c + h) >= 5:
        return "high"
    if (c + h) >= 2 or m >= 1:
        return "medium"
    if float(counts.get("low", 0) or 0) >= 1:
        return "low"
    return "info"


def severity_distribution(counts: dict[str, Any]) -> list[dict[str, Any]]:
    total = sum(float(counts.get(k, 0) or 0) for k in SEV_KEYS)
    rows = []
    for k in SEV_KEYS:
        n = float(counts.get(k, 0) or 0)
        rows.append({"severity": k, "count": n,
                     "percent": round(100.0 * n / total, 1) if total else 0.0,
                     "color": SEV_COLOR[k]})
    return rows


def asset_count(p: dict[str, Any]) -> int:
    """Proxy de totalAssets de OASM: IPs + subdominios + CT + servicios."""
    p = p or {}
    dns = p.get("dns") or {}
    ips = set(str(x) for x in (dns.get("ipv4") or []))
    subs = set()
    for s in (p.get("subdomains") or []):
        h = (s.get("host") or s.get("name") or s.get("subdomain") or s.get("domain")
             if isinstance(s, dict) else s)
        if h:
            subs.add(str(h))
    crt = set(str(x) for x in (p.get("crt_subdomains") or []))
    ports = p.get("open_ports") or []
    return len(ips) + len(subs) + len(crt) + len(ports)


def _connect():
    if not DB_PATH.is_file():
        return None
    try:
        c = sqlite3.connect(DB_PATH)
        c.row_factory = sqlite3.Row
        return c
    except Exception:
        return None


def load_history(domain: str, days: int = 90,
                 column: str = "overall_score") -> list[dict[str, Any]]:
    col = column if column in ("overall_score", "score_general", "domain_score") else "overall_score"
    c = _connect()
    if c is None:
        return []
    try:
        rows = c.execute(
            f"SELECT created_at, {col} AS score FROM scan_history WHERE domain=? "
            "AND created_at >= datetime('now', ? || ' days') ORDER BY created_at ASC",
            (domain, f"-{int(days)}"),
        ).fetchall()
        return [{"fecha": str(r[0]), "score": float(r[1] or 0)} for r in rows]
    except Exception:
        return []
    finally:
        c.close()


def previous_snapshot(domain: str) -> dict[str, Any] | None:
    """Ultimo escaneo registrado del dominio (scan_history + factores + assets)."""
    c = _connect()
    if c is None:
        return None
    try:
        r = c.execute(
            "SELECT id, domain, score_general, domain_score, overall_score, scan_type, created_at "
            "FROM scan_history WHERE domain=? ORDER BY created_at DESC LIMIT 1",
            (domain,),
        ).fetchone()
        if not r:
            return None
        snap = dict(r)
        sid = snap.get("id")
        snap["factors"] = {}
        try:
            for fr in c.execute(
                "SELECT factor_key, score, incidences FROM scan_factors WHERE scan_id=?",
                (sid,),
            ).fetchall():
                snap["factors"][str(fr[0])] = {"score": int(fr[1] or 0),
                                               "incidences": int(fr[2] or 0)}
        except Exception:
            pass
        snap["assets"] = {}
        try:
            ar = c.execute(
                "SELECT subdomain_count, ip_count, open_ports FROM scan_assets "
                "WHERE scan_id=? ORDER BY id DESC LIMIT 1", (sid,),
            ).fetchone()
            if ar:
                snap["assets"] = {"subdomains": int(ar[0] or 0), "ips": int(ar[1] or 0),
                                  "ports": int(ar[2] or 0)}
        except Exception:
            pass
        return snap
    except Exception:
        return None
    finally:
        c.close()


def delta(cur: float | None, prev: float | None) -> dict[str, Any]:
    if cur is None or prev is None:
        return {"abs": None, "pct": None, "dir": "na"}
    d = round(float(cur) - float(prev), 2)
    pct = round(100.0 * d / float(prev), 1) if prev else None
    return {"abs": d, "pct": pct, "dir": "up" if d > 0 else ("down" if d < 0 else "flat")}


def trend_direction(scores: list[float]) -> str:
    """MEJORA / EMPEORA / ESTABLE (umbral 20% entre primer y ultimo score)."""
    if len(scores) < 2 or not scores[0]:
        return "ESTABLE"
    ch = (float(scores[-1]) - float(scores[0])) / float(scores[0])
    if ch >= 0.2:
        return "MEJORA"
    if ch <= -0.2:
        return "EMPEORA"
    return "ESTABLE"


def delta_html(d: dict[str, Any], good_dir: str = "up") -> str:
    if d.get("abs") is None:
        return "<span style='color:#9AA0A6;'>--</span>"
    a = d["abs"]
    if a == 0:
        return "<span style='color:#6B7280;'>=</span>"
    pct = d.get("pct")
    suffix = f" ({pct:+.1f}%)" if pct is not None else ""
    arrow = "\u25B2" if a > 0 else "\u25BC"
    sign = "+" if a > 0 else ""
    improved = (a > 0) if good_dir == "up" else (a < 0)
    col = "#2E7D32" if improved else "#C62828"
    return f"<span style='color:{col}; font-weight:700;'>{arrow}{sign}{a:g}{suffix}</span>"


def render_score_badge(score: float) -> str:
    col = ("#2E7D32" if score >= 8 else "#7CB342" if score >= 6.5 else
           "#F29900" if score >= 5 else "#E53935" if score >= 3 else "#B71C1C")
    return (f"<span style='display:inline-block; min-width:62px; text-align:center; "
            f"background:{col}; color:#fff; font-weight:800; font-size:15pt; border-radius:8px; "
            f"padding:2px 10px;'>{score:g}<span style='font-size:8pt; font-weight:600;'> /10</span></span>")


def render_risk_badge(level: str) -> str:
    col = SEV_COLOR.get(level, "#9AA0A6")
    return (f"<span style='background:{col}; color:#fff; font-weight:700; font-size:8pt; "
            f"border-radius:4px; padding:1px 7px;'>{_esc(SEV_ES.get(level, level.upper()))}</span>")


def render_stacked_bar(counts: dict[str, Any]) -> str:
    dist = severity_distribution(counts)
    total = sum(r["count"] for r in dist)
    if not total:
        return "<div style='font-size:8pt; color:#9AA0A6;'>Sin hallazgos registrados.</div>"
    segs = []
    for r in dist:
        if r["count"] <= 0:
            continue
        segs.append(
            f"<div style='flex:{max(r['percent'], 4)} 0 0; background:{r['color']}; color:#fff; "
            f"font-size:7.5pt; text-align:center; padding:2px 0; white-space:nowrap;' "
            f"title='{SEV_ES[r['severity']]}: {int(r['count'])} ({r['percent']}%)'>"
            f"{int(r['count'])} ({r['percent']}%)</div>")
    return (f"<div style='display:flex; width:100%; border-radius:5px; overflow:hidden; "
            f"border:1px solid #E5E7EB;'>{''.join(segs)}</div>")


def render_severity_legend(counts: dict[str, Any]) -> str:
    chips = []
    for r in severity_distribution(counts):
        chip = (f"<span style='display:inline-flex; align-items:center; gap:4px; margin-right:10px; "
                f"font-size:8pt;'><span style='width:10px; height:10px; border-radius:2px; "
                f"background:{r['color']}; display:inline-block;'></span>"
                f"{_esc(SEV_ES[r['severity']])}: <b>{int(r['count'])}</b> ({r['percent']}%)</span>")
        chips.append(chip)
    return f"<div style='margin-top:2mm;'>{''.join(chips)}</div>"


def render_score_header(counts: dict[str, Any], assets: int, title: str = "Security Score (0-10)") -> str:
    score = security_score(counts, assets)
    total = int(sum(float(counts.get(k, 0) or 0) for k in SEV_KEYS))
    return f"""
<div class="oasm-score" style="border:1px solid #E5E7EB; border-radius:8px; padding:4mm; margin:3mm 0; background:#FBFCFE;">
  <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
    <div style="font-weight:800; color:#173B57; font-size:11pt;">{_esc(title)}</div>
    {render_score_badge(score)}
    <div>{render_risk_badge(risk_level(counts))}<span style="font-size:8pt; color:#6B7280; margin-left:6px;">{total} hallazgo(s) / {assets} activo(s)</span></div>
  </div>
  <div style="margin-top:3mm;">{render_stacked_bar(counts)}</div>
  {render_severity_legend(counts)}
</div>
"""


def render_comparison_block(domain: str, current: dict[str, Any],
                            prev: dict[str, Any] | None = None) -> str:
    """Tabla comparativa vs escaneo anterior. current: {score_general, domain_score,
    overall_score, subdomains, ips, ports, findings}. Los None se muestran como '--'."""
    if prev is None:
        prev = previous_snapshot(domain)
    if not prev:
        return ("<div style='font-size:8.5pt; color:#9AA0A6;'>Sin escaneo anterior registrado "
                "para este dominio (primer escaneo del historial).</div>")
    fecha = _esc(str(prev.get("created_at", ""))[:16])
    pa = prev.get("assets") or {}

    def r(label: str, cval, pval, good: str = "up", pct_ok: bool = True) -> str:
        d = delta(cval, pval)
        cv = "--" if cval is None else f"{cval:g}" if isinstance(cval, (int, float)) else _esc(cval)
        pv = "--" if pval is None else f"{pval:g}" if isinstance(pval, (int, float)) else _esc(pval)
        return (f"<tr><td>{_esc(label)}</td><td style='text-align:right;'>{cv}</td>"
                f"<td style='text-align:right;'>{pv}</td>"
                f"<td style='text-align:right;'>{delta_html(d, good)}</td></tr>")

    rows = [
        r("Overall Score", current.get("overall_score"), prev.get("overall_score"), "up"),
        r("Factor Score", current.get("score_general"), prev.get("score_general"), "up"),
        r("Domain Score", current.get("domain_score"), prev.get("domain_score"), "up"),
        r("Subdominios", current.get("subdomains"), pa.get("subdomains"), "down"),
        r("IPs", current.get("ips"), pa.get("ips"), "down"),
        r("Puertos abiertos", current.get("ports"), pa.get("ports"), "down"),
        r("Hallazgos", current.get("findings"), prev.get("findings"), "down"),
    ]
    cur_assets = sum(int(current.get(k) or 0) for k in ("subdomains", "ips", "ports"))
    prev_assets = sum(int(pa.get(k) or 0) for k in ("subdomains", "ips", "ports"))
    rows.append(r("Superficie (activos)", cur_assets, prev_assets, "down"))
    return f"""
<h4 style="margin:3mm 0 1mm;">Comparativa vs escaneo anterior ({fecha})</h4>
<div style="overflow-x:auto;"><table class="data" style="font-size:8pt; width:100%;">
<thead><tr><th>M&eacute;trica</th><th style="text-align:right;">Actual</th>
<th style="text-align:right;">Anterior</th><th style="text-align:right;">Delta</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
"""


def render_trend_block(history: list[dict[str, Any]], title: str = "Tendencia del Score") -> str:
    if len(history) < 2:
        return ("<div style='font-size:8.5pt; color:#9AA0A6;'>Se requieren 2+ escaneos para "
                "la tendencia (solo datos del escaneo actual disponibles).</div>")
    scores = [float(h.get("score", 0)) for h in history]
    last7 = scores[-7:]
    last30 = scores[-30:]
    avg7 = round(sum(last7) / len(last7), 1) if last7 else 0.0
    avg30 = round(sum(last30) / len(last30), 1) if last30 else 0.0
    avgpw = round(len(scores) / max(1.0, len(scores) / 2.0), 2)
    direction = trend_direction(scores)
    dcol = {"MEJORA": "#2E7D32", "EMPEORA": "#C62828"}.get(direction, "#6B7280")
    first, last = scores[0], scores[-1]
    overall_d = delta(last, first)
    n = len(scores)
    w, hgt, pad = 640, 150, 24
    lo, hi = min(scores), max(scores)
    if hi == lo:
        hi, lo = hi + 1, lo - 1

    def xp(i: int) -> float:
        return pad + (w - 2 * pad) * (i / max(1, n - 1))

    def yp(s: float) -> float:
        return pad + (hgt - 2 * pad) * (1 - (s - lo) / (hi - lo))

    pts = " ".join(f"{xp(i):.0f},{yp(s):.0f}" for i, s in enumerate(scores))
    dots = "".join(f"<circle cx='{xp(i):.0f}' cy='{yp(s):.0f}' r='2.5' fill='#173B57'/>"
                   for i, s in enumerate(scores))
    svg = (f"<svg width='{w}' height='{hgt}' xmlns='http://www.w3.org/2000/svg' "
           f"style='max-width:100%;'><polyline points='{pts}' fill='none' stroke='#173B57' "
           f"stroke-width='2'/><!-- -->{dots}</svg>")
    return f"""
<h4 style="margin:3mm 0 1mm;">{_esc(title)}</h4>
<div style="font-size:8.5pt;">
  <b>Escaneos:</b> {n} &middot; <b>Prom. &uacute;lt. 7:</b> {avg7:g} &middot;
  <b>Prom. &uacute;lt. 30:</b> {avg30:g} &middot;
  <b>Tendencia:</b> <span style="color:{dcol}; font-weight:700;">{direction}</span>
  ({delta_html(overall_d, 'up')})
</div>
<div style="margin-top:2mm;">{svg}</div>
"""


def finding_enrichment(f: dict[str, Any]) -> dict[str, Any]:
    f = f or {}
    return {
        "cve": f.get("cve") or f.get("id") or f.get("cve_id"),
        "cvss": f.get("cvss") or f.get("cvss_score"),
        "cvss_vector": f.get("cvss_vector") or f.get("vector"),
        "cwe": f.get("cwe") or f.get("cwe_id"),
        "epss": f.get("epss_score", f.get("epss")),
        "kev": bool(f.get("in_kev") or f.get("kev")),
    }


def render_finding_badges(f: dict[str, Any],
                          lifecycle: dict[str, dict[str, Any]] | None = None,
                          domain: str | None = None) -> str:
    """Badges inline (sin depender de CSS): KEV / CVSS / EPSS / CWE / vector CVSS / ciclo de vida."""
    e = finding_enrichment(f)
    chips = []
    base = ("display:inline-block; font-size:7.5pt; padding:1px 5px; border-radius:4px; "
            "margin:0 3px 0 0;")
    if e["kev"]:
        chips.append(f"<span style='{base} background:#fce4e4; color:#a00; font-weight:700;'>KEV</span>")
    if e["cvss"] not in (None, "", "-"):
        chips.append(f"<span style='{base} background:#e3f2fd; color:#0d47a1;'>CVSS {_esc(e['cvss'])}</span>")
    if e["epss"] is not None:
        try:
            chips.append(f"<span style='{base} background:#e8eef5; color:#3a5478;'>EPSS {round(float(e['epss']), 3)}</span>")
        except Exception:
            chips.append(f"<span style='{base} background:#e8eef5; color:#3a5478;'>EPSS {_esc(e['epss'])}</span>")
    if e["cwe"]:
        chips.append(f"<span style='{base} background:#f3e5f5; color:#4a148c;'>{_esc(e['cwe'])}</span>")
    if e["cvss_vector"]:
        chips.append(f"<span style='{base} background:#f5f5f5; color:#424242; font-family:monospace;'>{_esc(e['cvss_vector'])}</span>")
    lb = render_lifecycle_badge(f, lifecycle, domain)
    if lb:
        chips.append(lb)
    return "".join(chips)


# ---------------------------------------------------------------------------
# Ciclo de vida de hallazgos (1a / ultima vista) -> tabla finding_lifecycle
# Escritura (record_findings) solo la hace dashboard_server.py, una vez por
# escaneo; los generadores son de solo lectura.
# ---------------------------------------------------------------------------
LIFECYCLE_DDL = """
CREATE TABLE IF NOT EXISTS finding_lifecycle (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    severity TEXT,
    title TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(domain, finding_key)
)
"""

_LC_CACHE: dict[str, dict[str, dict[str, Any]]] = {}


def _connect_rw():
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(DB_PATH)
        c.row_factory = sqlite3.Row
        c.execute(LIFECYCLE_DDL)
        c.execute("CREATE INDEX IF NOT EXISTS idx_finding_lifecycle_domain "
                  "ON finding_lifecycle(domain)")
        c.commit()
        return c
    except Exception:
        return None


def finding_key(f: dict[str, Any]) -> str:
    """Identidad estable de un hallazgo entre escaneos (prioriza IDs estables)."""
    f = f or {}
    cve = f.get("cve") or f.get("cve_id")
    if cve:
        return f"cve:{str(cve).strip().upper()}"
    key = f.get("key")
    if key:
        return f"rule:{f.get('factor', '')}:{key}"
    fid = f.get("id")
    if fid:
        return f"id:{fid}"
    title = f.get("titulo") or f.get("title")
    if title:
        slug = "".join(ch if ch.isalnum() else "-" for ch in str(title).lower()).strip("-")
        return f"title:{slug[:80]}"
    return ""


def _finding_domain(f: dict[str, Any], default: str = "") -> str:
    f = f or {}
    return str(f.get("dominio") or f.get("domain") or default or "")


def _finding_severity(f: dict[str, Any]) -> str:
    f = f or {}
    return canon_severity(f.get("severidad") or f.get("sev") or f.get("severity"))


def _finding_title(f: dict[str, Any]) -> str:
    f = f or {}
    return str(f.get("titulo") or f.get("title") or f.get("summary") or "")[:300]


def record_findings(domain: str, findings, when: Any = None) -> int:
    """Registra/actualiza 1a y ultima vista de cada hallazgo (dedup por clave)."""
    findings = list(findings or [])
    if not findings:
        return 0
    ts = str(when) if when else datetime.now(timezone.utc).isoformat()
    c = _connect_rw()
    if c is None:
        return 0
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for f in findings:
        k = finding_key(f)
        if not k:
            continue
        dom = _finding_domain(f, domain) or str(domain or "")
        seen[(dom, k)] = {"severity": _finding_severity(f), "title": _finding_title(f)}
    try:
        for (dom, k), meta in seen.items():
            c.execute(
                "INSERT INTO finding_lifecycle"
                "(domain,finding_key,severity,title,first_seen,last_seen,seen_count) "
                "VALUES(?,?,?,?,?,?,1) "
                "ON CONFLICT(domain,finding_key) DO UPDATE SET "
                "last_seen=excluded.last_seen, "
                "seen_count=finding_lifecycle.seen_count+1, "
                "severity=excluded.severity, title=excluded.title",
                (dom, k, meta["severity"], meta["title"], ts, ts),
            )
        c.commit()
        _LC_CACHE.pop(str(domain or ""), None)
        return len(seen)
    except Exception:
        return 0
    finally:
        c.close()


def load_finding_lifecycle(domain: str | None = None,
                           refresh: bool = False) -> dict[str, dict[str, Any]]:
    """Devuelve {finding_key: registro} del dominio (o de todos si domain=None)."""
    if domain and not refresh and domain in _LC_CACHE:
        return _LC_CACHE[domain]
    c = _connect()
    if c is None:
        return {} if not domain else _LC_CACHE.get(domain, {})
    try:
        q = ("SELECT finding_key, domain, severity, title, first_seen, last_seen, seen_count "
             "FROM finding_lifecycle ")
        if domain:
            rows = c.execute(q + "WHERE domain=? ORDER BY seen_count DESC, last_seen DESC",
                             (domain,)).fetchall()
        else:
            rows = c.execute(q + "ORDER BY seen_count DESC, last_seen DESC").fetchall()
        out = {str(r["finding_key"]): dict(r) for r in rows}
        if domain:
            _LC_CACHE[domain] = out
        return out
    except Exception:
        return {} if not domain else _LC_CACHE.get(domain, {})
    finally:
        c.close()


def _fmt_day(ts: Any) -> str:
    return str(ts or "")[:10]


def render_lifecycle_badge(f: dict[str, Any], lifecycle: dict[str, dict[str, Any]] | None = None,
                           domain: str | None = None) -> str:
    """Chip con la 1a y ultima vista de un hallazgo ('nuevo' si seen_count<=1)."""
    key = finding_key(f)
    if not key:
        return ""
    if lifecycle is None:
        dom = domain or _finding_domain(f)
        if not dom:
            return ""
        lifecycle = load_finding_lifecycle(dom)
    rec = (lifecycle or {}).get(key)
    if not rec:
        return ""
    n = int(rec.get("seen_count") or 1)
    first = _fmt_day(rec.get("first_seen"))
    last = _fmt_day(rec.get("last_seen"))
    base = ("display:inline-block; font-size:7.5pt; padding:1px 5px; border-radius:4px; "
            "margin:0 3px 0 0;")
    if n <= 1:
        return (f"<span style='{base} background:#fff3e0; color:#e65100; font-weight:700;' "
                f"title='Primera y unica observacion: {_esc(first)}'>1a vista {_esc(first)}</span>")
    return (f"<span style='{base} background:#e8f5e9; color:#1b5e20;' "
            f"title='1a vista {_esc(first)} - ult. vista {_esc(last)}'>"
            f"1a {_esc(first)} - ult {_esc(last)} ({n}x)</span>")


def render_lifecycle_block(domain: str, findings=None,
                           title: str = "Ciclo de vida de hallazgos (1a / ultima vista)") -> str:
    """Tabla de hallazgos rastreados con su 1a/ultima vista y recurrencia."""
    lc = load_finding_lifecycle(domain)
    if not lc:
        return ("<div style='font-size:8.5pt; color:#9AA0A6;'>Sin historial de ciclo de vida "
                "para este dominio (se registra en cada escaneo del dashboard).</div>")
    keys = None
    if findings:
        keys = {finding_key(f) for f in findings if finding_key(f)}
    rows = [(k, r) for k, r in lc.items() if keys is None or k in keys]
    if not rows:
        return "<div style='font-size:8.5pt; color:#9AA0A6;'>Sin hallazgos rastreados.</div>"
    rows.sort(key=lambda kr: (int(kr[1].get("seen_count") or 1),
                              str(kr[1].get("last_seen") or "")), reverse=True)
    nuevo = sum(1 for _, r in rows if int(r.get("seen_count") or 1) <= 1)
    trs = []
    for _k, r in rows:
        n = int(r.get("seen_count") or 1)
        sev = canon_severity(r.get("severity"))
        col = SEV_COLOR.get(sev, "#9AA0A6")
        tag = "NUEVO" if n <= 1 else f"{n}x"
        tagcol = "#E65100" if n <= 1 else "#2E7D32"
        trs.append(
            f"<tr><td><span style='background:{col}; color:#fff; font-size:7pt; border-radius:3px; "
            f"padding:0 5px;'>{_esc(SEV_ES.get(sev, sev))}</span></td>"
            f"<td>{_esc(str(r.get('title') or ''))}</td>"
            f"<td style='text-align:center;'><b style='color:{tagcol};'>{tag}</b></td>"
            f"<td style='text-align:right;'>{_esc(_fmt_day(r.get('first_seen')))}</td>"
            f"<td style='text-align:right;'>{_esc(_fmt_day(r.get('last_seen')))}</td></tr>")
    return f"""
<h4 style="margin:3mm 0 1mm;">{_esc(title)}</h4>
<div style="font-size:8.5pt; margin-bottom:1mm;">{len(rows)} hallazgo(s) rastreado(s) &middot;
<span style="color:#E65100; font-weight:700;">{nuevo}</span> nuevo(s) este escaneo.</div>
<div style="overflow-x:auto;"><table class="data" style="font-size:8pt; width:100%;">
<thead><tr><th>Severidad</th><th>Hallazgo</th><th style="text-align:center;">Veces</th>
<th style="text-align:right;">1a vista</th><th style="text-align:right;">Ult. vista</th></tr></thead>
<tbody>{''.join(trs)}</tbody></table></div>
"""
