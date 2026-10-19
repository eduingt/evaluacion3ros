#!/usr/bin/env python3
"""
Recon DNS adicional (inspirado en reconFTW/Amass):

- check_zone_transfer(domain): intenta un AXFR contra los NS del dominio.
  Un AXFR exitoso expone la zona completa -> hallazgo de alta severidad.
- discover_noerror(domain, labels): descubre nombres que existen (rcode
  NOERROR) aunque no tengan registro A (p.ej. delegaciones NS/SOA/CNAME/TXT),
  tecnica pasiva que crt.sh/brute no capturan.

Requiere dnspython (ya en requirements). Degrada a vacio, nunca lanza.
"""

from __future__ import annotations

import concurrent.futures
import html
from typing import Any

import dns.exception
import dns.query
import dns.resolver
import dns.zone

TIMEOUT = 5.0

# Etiquetas adicionales tipicas de delegacion/infra que suelen existir sin A.
NOERROR_LABELS: tuple[str, ...] = (
    "_dmarc", "_domainkey", "autodiscover", "enterpriseregistration",
    "enterpriseenrollment", "lyncdiscover", "sip", "_sipfederationtls._tcp",
    "_sip._tcp", "selector1._domainkey", "selector2._domainkey",
    "default._domainkey", "dkim._domainkey", "_acme-challenge", "_mta-sts",
    "_smtp._tls", "_dmarc2", "autoconfig", "whm", "cpanel", "webdisk",
    "cpcalendars", "cpcontacts", "ftp", "ns1", "ns2", "origin", "direct",
    "backend", "lb", "internal", "staging", "dev", "test", "sso", "idp",
    "adfs", "sts", "gitlab", "git", "jira", "confluence", "intranet",
)


def _resolve_ns(domain: str, timeout: float = TIMEOUT) -> list[str]:
    try:
        ans = dns.resolver.resolve(domain, "NS", lifetime=timeout)
        return sorted({str(r.target).rstrip(".") for r in ans})
    except Exception:
        return []


def check_zone_transfer(domain: str, timeout: float = TIMEOUT) -> dict[str, Any]:
    """Intenta AXFR en los NS del dominio. vulnerable=True si alguno lo permite."""
    result: dict[str, Any] = {
        "domain": domain,
        "attempted": [],
        "vulnerable": False,
        "records": [],
        "ns_count": 0,
    }
    ns_records = _resolve_ns(domain, timeout)
    result["ns_count"] = len(ns_records)
    if not ns_records:
        result["error"] = "NS no resueltos"
        return result
    for ns in ns_records:
        result["attempted"].append(ns)
        try:
            ips = [str(r) for r in dns.resolver.resolve(ns, "A", lifetime=timeout)]
        except Exception:
            continue
        for ip in ips[:2]:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ip, domain, lifetime=timeout))
            except Exception:
                continue
            names = []
            for node in sorted(zone.nodes.keys()):
                rel = str(node)
                fqdn = domain if rel == "@" else f"{rel}.{domain}"
                names.append(fqdn)
            result["vulnerable"] = True
            result["ns"] = ns
            result["ip"] = ip
            result["records"] = names[:300]
            return result
    return result


def _classify(host: str, timeout: float) -> dict[str, Any] | None:
    """Devuelve un item si el nombre existe (NOERROR), None si NXDOMAIN/timeout."""
    for rtype in ("A", "AAAA"):
        try:
            ans = dns.resolver.resolve(host, rtype, lifetime=timeout)
            ips = [str(r) for r in ans][:5]
            return {"fqdn": host, "type": rtype, "detail": ",".join(ips)}
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            continue
        except (dns.resolver.Timeout, dns.exception.Timeout):
            continue
        except Exception:
            continue
    for rtype in ("NS", "SOA", "CNAME", "TXT", "MX"):
        try:
            ans = dns.resolver.resolve(host, rtype, lifetime=timeout)
            vals = [str(r).rstrip(".") for r in ans][:3]
            return {"fqdn": host, "type": rtype, "detail": " ".join(vals)[:180]}
        except dns.resolver.NXDOMAIN:
            return None
        except Exception:
            continue
    return None


def discover_noerror(domain: str, labels: list[str] | None = None,
                     max_workers: int = 30, timeout: float = TIMEOUT) -> list[dict[str, Any]]:
    """Nombres que responden NOERROR (existen) incluso sin registro A."""
    base = NOERROR_LABELS if labels is None else tuple(labels)
    hosts = []
    seen: set[str] = set()
    for lab in base:
        lab = str(lab).strip().lower().strip(".")
        if not lab:
            continue
        host = f"{lab}.{domain}"
        if host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    out: list[dict[str, Any]] = []
    if not hosts:
        return out
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_classify, h, timeout): h for h in hosts}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    item = fut.result()
                except Exception:
                    continue
                if item:
                    out.append(item)
    except Exception:
        return out
    out.sort(key=lambda i: i["fqdn"])
    return out


def run_dns_extra(domain: str, do_axfr: bool = True,
                  do_noerror: bool = True, labels: list[str] | None = None) -> dict[str, Any]:
    """Wrapper tolerante usado por el escaneo."""
    data: dict[str, Any] = {"domain": domain}
    if do_axfr:
        try:
            data["zone_transfer"] = check_zone_transfer(domain)
        except Exception:
            data["zone_transfer"] = {}
    if do_noerror:
        try:
            data["noerror_subs"] = discover_noerror(domain, labels=labels)
        except Exception:
            data["noerror_subs"] = []
    return data


def _esc(s: Any) -> str:
    return html.escape(str(s), quote=True)


def render_dns_extra_block(domain: str, provider: dict[str, Any]) -> str:
    """Bloque HTML (AXFR + NOERROR) para B5/B6/B7. '' si no hay datos."""
    if not isinstance(provider, dict):
        return ""
    zt = provider.get("zone_transfer") or {}
    noerror = provider.get("noerror_subs") or []
    if not (isinstance(zt, dict) and zt.get("vulnerable")) and not noerror:
        return ""
    parts = ['<h4 style="margin:6px 0 3px;">Recon DNS adicional (AXFR / NOERROR)</h4>']
    if isinstance(zt, dict) and zt.get("vulnerable"):
        recs = zt.get("records") or []
        parts.append(
            '<p style="font-size:8.5px;margin:2px 0;">'
            '<b style="color:#B71C1C;">AXFR permitido</b> desde '
            f'{_esc(zt.get("ns", "?"))} ({_esc(zt.get("ip", "?"))}) &middot; '
            f'{len(recs)} registros de zona expuestos. '
            'Un AXFR publico revela la topologia interna completa del dominio.</p>'
        )
        if recs:
            shown = "".join(f"<li>{_esc(r)}</li>" for r in recs[:40])
            parts.append(
                f'<ul style="font-size:8px;columns:2;margin:2px 0 4px;">{shown}</ul>'
            )
    else:
        n = zt.get("ns_count") if isinstance(zt, dict) else 0
        parts.append(
            f'<p style="font-size:8.5px;margin:2px 0;">AXFR: no permitido '
            f'({n or 0} NS probados).</p>'
        )
    if noerror:
        parts.append(
            f'<p style="font-size:8.5px;margin:2px 0;">Nombres existentes sin registro A '
            f'(delegaciones/servicios), via NOERROR: <b>{len(noerror)}</b></p>'
        )
        rows = "".join(
            f"<tr><td style=\"font-family:monospace;font-size:8px;\">{_esc(i.get('fqdn'))}</td>"
            f"<td style=\"font-size:8px;\">{_esc(i.get('type'))}</td>"
            f"<td style=\"font-size:8px;\">{_esc(i.get('detail'))}</td></tr>"
            for i in noerror[:30]
        )
        parts.append(
            '<table style="width:100%;border-collapse:collapse;" border="1" cellspacing="0" cellpadding="3">'
            '<thead><tr style="background:#EEEEEE;">'
            '<th style="font-size:8px;text-align:left;">Nombre</th>'
            '<th style="font-size:8px;text-align:left;">Tipo</th>'
            '<th style="font-size:8px;text-align:left;">Detalle</th>'
            '</tr></thead><tbody>' + rows + '</tbody></table>'
        )
    return "".join(parts)
