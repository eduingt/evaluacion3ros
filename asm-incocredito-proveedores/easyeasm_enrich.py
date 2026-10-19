#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""easyeasm_enrich - deteccion de cambios de activos entre escaneos (estilo EasyEASM).

EasyEASM (g0ldencybersec/EasyEASM) enumera activos vivos y alerta sobre dominios
nuevos/perdidos entre ejecuciones (diff contra el CSV previo + webhook Slack/Discord).
Este modulo replica esa idea dentro de los informes B5/B6/B7: lee el asm_report.json
del escaneo anterior del mismo dominio desde scan_history.asm_json_path, extrae los
hosts (subdominios + CT) y los compara con los del escaneo actual.

Modulo puro stdlib. Degrada a vacio/no-op cuando no hay scan_history.db, no hay
escaneo previo o el JSON no es accesible.
"""
from __future__ import annotations
import html
import json
from pathlib import Path
from typing import Any

import oasm_enrich as _oasm

ROOT = Path(__file__).resolve().parent

_NEW_STYLE = "background:#e8f5e9; color:#1b5e20;"
_LOST_STYLE = "background:#fdecea; color:#b71c1c;"


def _esc(s: Any) -> str:
    return html.escape(str(s))


def _norm(host: Any) -> str:
    h = str(host or "").strip().lower().rstrip(".")
    return h


def _host_of(s: Any) -> Any:
    if isinstance(s, dict):
        return (s.get("host") or s.get("name") or s.get("subdomain")
                or s.get("domain") or s.get("fqdn"))
    return s


def asset_hosts(p: dict[str, Any]) -> set[str]:
    """Hosts de la superficie (subdominios + CT), normalizados y sin duplicados."""
    p = p or {}
    out: set[str] = set()
    for key in ("subdomains", "crt_subdomains"):
        for s in (p.get(key) or []):
            h = _norm(_host_of(s))
            if h:
                out.add(h)
    return out


def _load_provider(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        fp = Path(str(path))
        if not fp.is_absolute():
            fp = ROOT / fp
        if not fp.is_file():
            return None
        data = json.loads(fp.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None
    providers = (data or {}).get("providers") or []
    if not providers:
        return None
    return providers[0] if isinstance(providers[0], dict) else None


def previous_asm(domain: str) -> dict[str, Any] | None:
    """Escaneo anterior del dominio: {path, created_at, provider} o None."""
    c = _oasm._connect()
    if c is None:
        return None
    try:
        r = c.execute(
            "SELECT asm_json_path, created_at FROM scan_history WHERE domain=? "
            "ORDER BY created_at DESC, id DESC LIMIT 1",
            (domain,),
        ).fetchone()
        if not r:
            return None
        prov = _load_provider(r[0])
        if prov is None:
            return None
        return {"path": str(r[0]), "created_at": str(r[1] or ""), "provider": prov}
    except Exception:
        return None
    finally:
        c.close()


def diff_hosts(current, previous) -> dict[str, Any]:
    cur = set(x for x in (current or []) if x)
    prev = set(x for x in (previous or []) if x)
    return {
        "new": sorted(cur - prev),
        "lost": sorted(prev - cur),
        "common": len(cur & prev),
        "current_total": len(cur),
        "previous_total": len(prev),
    }


def _rows(hosts: list[str], style: str, tag: str, limit: int = 50) -> str:
    trs = []
    for h in hosts[:limit]:
        trs.append(
            f"<tr><td><span style='{style} font-size:7pt; border-radius:3px; padding:0 5px; "
            f"font-weight:700;'>{tag}</span></td><td style='font-family:monospace;'>{_esc(h)}</td></tr>")
    if len(hosts) > limit:
        trs.append(f"<tr><td></td><td style='color:#9AA0A6;'>... y {len(hosts) - limit} m&aacute;s</td></tr>")
    return "".join(trs)


def render_permutation_block(domain: str, provider: dict[str, Any],
                             title: str = "Subdominios por permutaci&oacute;n DNS (alterx-lite)") -> str:
    """Bloque HTML con subdominios descubiertos por permutacion de nombres conocidos.

    Alimentado por `alterx_perm` (nivel >= 2). Devuelve "" si el escaneo no corrio
    permutaciones o no hallo nada, para no ensuciar los informes pasivos.
    """
    p = provider or {}
    rows = [r for r in (p.get("perm_subs") or []) if isinstance(r, dict)]
    if not rows:
        return ""
    wildcard = bool(p.get("perm_wildcard"))
    body = []
    for r in rows[:50]:
        fqdn = _esc(r.get("fqdn") or r.get("subdomain") or "")
        ips = ", ".join(str(i) for i in (r.get("ips") or [])[:4]) or "-"
        cname = _esc(r.get("cname") or "")
        src = _esc(r.get("source") or "permutation")
        extra = f" &rarr; {cname}" if cname else ""
        body.append(
            f"<tr><td><span style='{_NEW_STYLE} font-size:7pt; border-radius:3px; padding:0 5px; "
            f"font-weight:700;'>NUEVO</span></td>"
            f"<td style='font-family:monospace;'>{fqdn}</td>"
            f"<td style='font-family:monospace; font-size:7.5pt;'>{_esc(ips)}{extra}</td>"
            f"<td style='color:#5f6368; font-size:7.5pt;'>{src}</td></tr>")
    if len(rows) > 50:
        body.append(f"<tr><td></td><td style='color:#9AA0A6;'>... y {len(rows) - 50} m&aacute;s</td><td></td><td></td></tr>")
    wc_note = ("<div style='font-size:8pt; color:#b26a00; margin-top:1mm;'>Wildcard DNS detectado en el "
               "dominio: se descartaron coincidencias que resuelven al mismo comod&iacute;n.</div>") if wildcard else ""
    return f"""
<h4 style="margin:3mm 0 1mm;">{title}</h4>
<div style="font-size:8.5pt; margin-bottom:1mm;">{len(rows)} host(s) no visibles en fuentes pasivas ni en el
brute de wordlist, derivados de los nombres ya conocidos del dominio.</div>
<div style="overflow-x:auto;"><table class="data" style="font-size:8pt; width:100%;">
<thead><tr><th></th><th>FQDN</th><th>IP / CNAME</th><th>Origen</th></tr></thead>
<tbody>{''.join(body)}</tbody></table></div>{wc_note}
"""


def render_asset_change_block(domain: str, provider: dict[str, Any],
                              title: str = "Cambios de activos vs escaneo anterior (estilo EasyEASM)") -> str:
    """Bloque HTML con activos nuevos y desaparecidos frente al escaneo previo."""
    prev = previous_asm(domain)
    if not prev:
        return ("<div style='font-size:8.5pt; color:#9AA0A6;'>Sin escaneo anterior registrado "
                "para este dominio: la deteccion de cambios de activos se activa a partir del "
                "segundo escaneo del dashboard.</div>")
    cur_hosts = asset_hosts(provider)
    prev_hosts = asset_hosts(prev.get("provider") or {})
    d = diff_hosts(cur_hosts, prev_hosts)
    fecha = _esc(str(prev.get("created_at", ""))[:16])
    n_new, n_lost = len(d["new"]), len(d["lost"])

    if not n_new and not n_lost:
        return f"""
<h4 style="margin:3mm 0 1mm;">{_esc(title)}</h4>
<div style="font-size:8.5pt; margin-bottom:1mm;">Sin cambios en la superficie de activos
({d['common']} host(s) en com&uacute;n) respecto al escaneo del {fecha}.</div>
"""

    body = []
    if n_new:
        body.append(
            f"<div style='margin-top:2mm; font-weight:700; color:#1b5e20; font-size:9pt;'>"
            f"Activos nuevos ({n_new})</div>"
            f"<div style='overflow-x:auto;'><table class='data' style='font-size:8pt; width:100%;'>"
            f"<tbody>{_rows(d['new'], _NEW_STYLE, 'NUEVO')}</tbody></table></div>")
    if n_lost:
        body.append(
            f"<div style='margin-top:2mm; font-weight:700; color:#b71c1c; font-size:9pt;'>"
            f"Activos que desaparecieron ({n_lost})</div>"
            f"<div style='overflow-x:auto;'><table class='data' style='font-size:8pt; width:100%;'>"
            f"<tbody>{_rows(d['lost'], _LOST_STYLE, 'PERDIDO')}</tbody></table></div>")

    return f"""
<h4 style="margin:3mm 0 1mm;">{_esc(title)}</h4>
<div style="font-size:8.5pt; margin-bottom:1mm;">
{d['current_total']} activo(s) actuales &middot;
<span style="color:#1b5e20; font-weight:700;">{n_new} nuevo(s)</span> &middot;
<span style="color:#b71c1c; font-weight:700;">{n_lost} desaparecido(s)</span> &middot;
{d['common']} en com&uacute;n (ref. {fecha})
</div>
{''.join(body)}
"""
