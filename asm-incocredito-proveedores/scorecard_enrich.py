#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scorecard_enrich - postura de supply chain con OpenSSF Scorecard.

Consume la API REST keyless (https://api.scorecard.dev/projects/github.com/<owner>/<repo>)
para enriquecer los informes con dos bloques:
  * por proveedor (opt-in: campo `github` en providers.json), y
  * del toolchain del propio ASM (proyectos externos/vendorizados).

Modulo stdlib. Degrada a vacio cuando no hay red, cache ni datos: nunca lanza.
Cache en disco con TTL en dashboard_workspace/scorecard_cache.json.
"""
from __future__ import annotations
import html
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CACHE_FILE = ROOT / "dashboard_workspace" / "scorecard_cache.json"
API = "https://api.scorecard.dev/projects/github.com/{owner}/{repo}"

TTL = 7 * 24 * 3600
TIMEOUT = 6.0
USER_AGENT = "ASM-Informe-Proveedores/1.0 (+scorecard-enrich)"

TOOLCHAIN_PROJECTS: list[dict[str, str]] = [
    {"repo": "NovaCode37/Prism-platform", "label": "Prism-platform (OSINT vendorizado)"},
    {"repo": "elementalsouls/Claude-OSINT", "label": "Claude-OSINT (vendorizado)"},
    {"repo": "evyatarmeged/Raccoon", "label": "Raccoon (WAF/CDN + cloud storage)"},
    {"repo": "projectdiscovery/nuclei", "label": "nuclei (binario externo)"},
    {"repo": "OJ/gobuster", "label": "gobuster (binario externo)"},
    {"repo": "usestrix/strix", "label": "Strix (agente IA pentest)"},
    {"repo": "psf/requests", "label": "requests (dependencia de runtime)"},
    {"repo": "rthalley/dnspython", "label": "dnspython (dependencia de runtime)"},
]

_MEM: dict[str, dict[str, Any]] = {}

_GOOD = "#1B5E20"
_BAD = "#B71C1C"
_MID = "#F29900"


def _esc(s: Any) -> str:
    return html.escape(str(s))


def _enabled() -> bool:
    return os.environ.get("ASM_SCORECARD_DISABLE", "").strip().lower() not in ("1", "true", "yes")


def parse_repo(spec: Any) -> tuple[str, str] | None:
    """Acepta 'owner/repo', URL completa o con .git/; devuelve (owner, repo)."""
    if not spec:
        return None
    s = str(spec).strip().rstrip("/")
    if s.startswith("http://") or s.startswith("https://"):
        parts = s.split("/")
        if len(parts) < 5 or "github" not in parts[2]:
            return None
        owner, repo = parts[3], parts[4]
    else:
        parts = [p for p in s.split("/") if p]
        if len(parts) < 2:
            return None
        owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None
    return owner, repo


def _risk(score: float) -> tuple[str, str]:
    if score < 2.5:
        return "CRITICO", _BAD
    if score < 5.0:
        return "ALTO", _BAD
    if score < 7.5:
        return "MEDIO", _MID
    return "BAJO", _GOOD


def _load_cache() -> dict[str, Any]:
    try:
        if CACHE_FILE.is_file():
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(data, dict) and isinstance(data.get("entries"), dict):
                return data
    except Exception:
        pass
    return {"entries": {}}


def _save_cache(cache: dict[str, Any]) -> None:
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _trim(payload: dict[str, Any], owner: str, repo: str) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for c in (payload.get("checks") or []):
        if not isinstance(c, dict):
            continue
        checks.append({
            "name": c.get("name") or "",
            "score": c.get("score"),
            "reason": (c.get("reason") or "")[:400],
            "doc": ((c.get("documentation") or {}).get("url") or ""),
        })
    return {
        "repo": f"{owner}/{repo}",
        "score": payload.get("score"),
        "date": payload.get("date") or "",
        "scorecard_version": ((payload.get("scorecard") or {}).get("version") or ""),
        "checks": checks,
    }


def scorecard_repo(owner: str, repo: str, *, allow_network: bool = True, ttl: int = TTL) -> dict[str, Any]:
    key = f"{owner}/{repo}"
    now = time.time()
    if key in _MEM:
        return _MEM[key]

    cache = _load_cache()
    ent = cache["entries"].get(key)
    if isinstance(ent, dict) and ent.get("data") and (now - float(ent.get("ts") or 0)) < ttl:
        _MEM[key] = ent["data"]
        return ent["data"]

    if not allow_network or not _enabled():
        data = ent.get("data") if isinstance(ent, dict) else None
        result = data or {"repo": key, "error": "sin datos (sin red o deshabilitado)"}
        _MEM[key] = result
        return result

    try:
        req = urllib.request.Request(API.format(owner=owner, repo=repo), headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        result = _trim(payload or {}, owner, repo)
        cache["entries"][key] = {"ts": now, "data": result}
        _save_cache(cache)
        _MEM[key] = result
        return result
    except urllib.error.HTTPError as e:
        result = {"repo": key, "error": f"HTTP {e.code}"}
    except Exception as e:
        result = {"repo": key, "error": f"error: {type(e).__name__}"}
    _MEM[key] = result
    return result


def _aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [r for r in results if isinstance(r.get("score"), (int, float))]
    if not scored:
        return {"count": 0, "scored": 0, "mean": None, "failing": []}
    mean = sum(float(r["score"]) for r in scored) / len(scored)
    failing: list[dict[str, Any]] = []
    for r in scored:
        for c in (r.get("checks") or []):
            sc = c.get("score")
            if isinstance(sc, (int, float)) and 0 <= sc < 5:
                failing.append({"repo": r["repo"], "name": c.get("name"), "score": sc})
    failing.sort(key=lambda x: float(x.get("score") or 0))
    return {"count": len(results), "scored": len(scored), "mean": round(mean, 1), "failing": failing}


def provider_scorecard(provider: Any) -> dict[str, Any]:
    """Enriquecimiento opt-in por proveedor: usa provider['github'] (str o lista)."""
    if not isinstance(provider, dict):
        return {}
    raw = provider.get("github")
    if not raw:
        return {}
    specs = raw if isinstance(raw, list) else [raw]
    results: list[dict[str, Any]] = []
    for spec in specs:
        parsed = parse_repo(spec)
        if not parsed:
            continue
        results.append(scorecard_repo(parsed[0], parsed[1]))
    if not results:
        return {}
    return {"repos": results, "aggregate": _aggregate(results)}


def toolchain_scorecard(*, allow_network: bool = False) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for proj in TOOLCHAIN_PROJECTS:
        parsed = parse_repo(proj.get("repo"))
        if not parsed:
            continue
        data = dict(scorecard_repo(parsed[0], parsed[1], allow_network=allow_network))
        data["label"] = proj.get("label") or data.get("repo")
        results.append(data)
    return {"projects": results, "aggregate": _aggregate(results)}


def warm_toolchain() -> None:
    """Pre-carga el cache del toolchain (best-effort, desde asm_scan)."""
    if not _enabled():
        return
    toolchain_scorecard(allow_network=True)


def _table(rows: list[list[str]], headers: list[str]) -> str:
    th = "".join(
        f'<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #ccc;'
        f'font-size:8.5pt;background:#f2f2f2;">{_esc(h)}</th>' for h in headers
    )
    trs = []
    for row in rows:
        tds = "".join(
            f'<td style="padding:3px 8px;border-bottom:1px solid #eee;font-size:8.5pt;vertical-align:top;">{c}</td>'
            for c in row
        )
        trs.append(f"<tr>{tds}</tr>")
    return (
        '<table style="width:100%;border-collapse:collapse;margin:2mm 0;">'
        f"<thead><tr>{th}</tr></thead><tbody>{''.join(trs)}</tbody></table>"
    )


def _score_cell(score: Any) -> str:
    if not isinstance(score, (int, float)):
        return '<span style="color:#9AA0A6;">sin dato</span>'
    label, color = _risk(float(score))
    return f'<b style="color:{color};">{float(score):.1f}</b> <span style="color:{color};font-size:7.5pt;">{label}</span>'


def _checks_cell(data: dict[str, Any], limit: int = 6) -> str:
    checks = [c for c in (data.get("checks") or []) if isinstance(c.get("score"), (int, float)) and c["score"] >= 0]
    checks.sort(key=lambda c: float(c["score"]))
    low = [c for c in checks if float(c["score"]) < 5]
    if not low:
        return '<span style="color:#1B5E20;">sin checks en rojo</span>'
    items = ", ".join(f"{_esc(c['name'])} ({float(c['score']):.0f})" for c in low[:limit])
    extra = f" +{len(low) - limit} mas" if len(low) > limit else ""
    return f'<span style="color:#B71C1C;">{items}{extra}</span>'


def render_provider_scorecard_block(domain: str, provider: dict[str, Any]) -> str:
    """Bloque por proveedor; devuelve '' si no hay datos."""
    data = (provider or {}).get("scorecard") or {}
    repos = data.get("repos") or []
    if not any(isinstance(r.get("score"), (int, float)) for r in repos if isinstance(r, dict)):
        return ""
    rows = []
    for r in repos:
        if r.get("error"):
            rows.append([_esc(r.get("repo")), '<span style="color:#9AA0A6;">n/d</span>',
                         _esc(r.get("error")), ""])
            continue
        rows.append([_esc(r.get("repo")), _score_cell(r.get("score")),
                     _esc(r.get("date") or ""), _checks_cell(r)])
    agg = data.get("aggregate") or {}
    resumen = ""
    if agg.get("mean") is not None:
        resumen = (
            f'<p style="font-size:8.5pt;margin:2mm 0;">Score medio del repositorio: '
            f'<b>{agg["mean"]:.1f}</b>/10 sobre {agg.get("scored", 0)} repo(s).</p>'
        )
    return (
        '<div style="border:1px solid #ddd;border-radius:4px;padding:3mm;margin:2mm 0;background:#fafafa;">'
        '<h4 style="margin:0 0 2mm 0;font-size:9.5pt;">OpenSSF Scorecard (repositorio del proveedor)</h4>'
        f'{resumen}'
        + _table(rows, ["Repositorio", "Score", "Fecha", "Checks en rojo"])
        + '<p style="font-size:7.5pt;color:#666;margin:1mm 0 0 0;">Fuente: api.scorecard.dev (keyless). '
          'Evalua la postura del repositorio (CI, dependencias fijadas, ramas, releases), no la superficie web.</p>'
        "</div>"
    )


def render_toolchain_scorecard_block(title: str = "Postura de supply chain del toolchain (OpenSSF Scorecard)") -> str:
    """Bloque del toolchain; lee solo cache en disco (sin red). Devuelve '' si no hay datos."""
    data = toolchain_scorecard(allow_network=False)
    projects = [p for p in (data.get("projects") or []) if isinstance(p.get("score"), (int, float))]
    if not projects:
        return ""
    projects.sort(key=lambda p: float(p["score"]))
    rows = [[_esc(p.get("label") or p.get("repo")), _esc(p.get("repo")),
             _score_cell(p.get("score")), _checks_cell(p)] for p in projects]
    agg = data.get("aggregate") or {}
    resumen = ""
    if agg.get("mean") is not None:
        label, color = _risk(float(agg["mean"]))
        resumen = (
            f'<p style="font-size:8.5pt;margin:2mm 0;">Score medio del toolchain: '
            f'<b style="color:{color};">{agg["mean"]:.1f}</b>/10 ({label}) sobre {agg.get("scored", 0)} '
            f'proyecto(s); {len(agg.get("failing") or [])} check(s) en rojo.</p>'
        )
    return (
        '<div style="border:1px solid #ddd;border-radius:4px;padding:3mm;margin:2mm 0;background:#fafafa;">'
        f'<h4 style="margin:0 0 2mm 0;font-size:9.5pt;">{_esc(title)}</h4>'
        f'{resumen}'
        + _table(rows, ["Componente externo", "Repositorio", "Score", "Checks en rojo"])
        + '<p style="font-size:7.5pt;color:#666;margin:1mm 0 0 0;">Fuente: api.scorecard.dev (keyless). '
          'Proyectos externos/binarios y dependencias de runtime usados por este pipeline.</p>'
        "</div>"
    )
