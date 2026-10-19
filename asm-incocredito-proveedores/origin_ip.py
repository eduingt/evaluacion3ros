#!/usr/bin/env python3
"""
Descubrimiento de IP de origen tras CDN/WAF (heuristico, keyless).

Inspirado en hakoriginfinder (reconFTW): cuando el host publico esta tras un
CDN/WAF (Cloudflare, Akamai, Fastly, CloudFront, etc.), el backend real suele
quedar expuesto en subdominios auxiliares (direct/origin/backend, correo, VPN,
cpanel...) o en CNAMEs no-CDN. Este modulo recolecta IPs candidatas desde DNS
y datos OSINT ya obtenidos y marca como `exposed` cuando encuentra IPs que no
pertenecen a un CDN conocido.

Puro Python + dnspython. Degrada a vacio, nunca lanza.
"""

from __future__ import annotations

import html
import re
from typing import Any

import dns.resolver

TIMEOUT = 4.0

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Sufijos de CNAME pertenecientes a CDN/WAF conocidos.
CDN_SUFFIXES: tuple[str, ...] = (
    "cloudflare.net", "cloudflare.com", "cdn.cloudflare.net",
    "akamai.net", "akamaiedge.net", "akamaitechnologies.com", "akamaized.net",
    "edgesuite.net", "edgekey.net", "edgecastcdn.net",
    "fastly.net", "fastlylb.net", "fastly-edge.com",
    "cloudfront.net", "amazonaws.com", "awsdns", "elb.amazonaws.com",
    "azureedge.net", "azurefd.net", "trafficmanager.net", "cloudapp.azure.com",
    "t-msedge.net", "msedge.net", "azure.com",
    "llnwd.net", "llcdn.org", "cachefly.net", "cdn77.org",
    "stackpathdns.com", "stackpathcdn.com", "incapdns.net", "impervadns.net",
    "netlify.app", "netlify.com", "vercel.app", "herokuapp.com",
    "b-cdn.net", "bunnycdn.com", "bunny.net", "hwcdn.net",
    "alicdn.com", "ks-cdn.com", "wscloudcdn.com", "wscdns.com",
    "googleusercontent.com", "googlehosted.com", "gvt1.com", "gstatic.com",
    "cloudflarestream.com", "sucuri.net", "cdn77.net",
)

# Etiquetas que sugieren backend/origen real (no CDN).
ORIGIN_LABELS: tuple[str, ...] = (
    "direct", "origin", "backend", "back", "app", "internal", "intranet",
    "ftp", "mail", "smtp", "webmail", "cpanel", "whm", "webdisk",
    "vpn", "remote", "dev", "staging", "test", "uat", "jenkins",
    "gitlab", "git", "sso", "idp", "adfs", "autodiscover", "autoconfig",
    "secure", "portal", "admin", "api", "ns1", "ns2", "mx",
)


def _is_cdn_name(name: str) -> bool:
    n = str(name or "").lower().rstrip(".")
    return any(n == s or n.endswith("." + s) or n.endswith(s) for s in CDN_SUFFIXES)


def _resolve_a(host: str, timeout: float = TIMEOUT) -> list[str]:
    try:
        ans = dns.resolver.resolve(host, "A", lifetime=timeout)
        return [str(r) for r in ans]
    except Exception:
        return []


def _resolve_cname(host: str, timeout: float = TIMEOUT) -> str | None:
    try:
        ans = dns.resolver.resolve(host, "CNAME", lifetime=timeout)
        return str(ans[0].target).rstrip(".")
    except Exception:
        return None


def _dnsdumpster_ips(external_data: dict[str, Any]) -> list[str]:
    dd = (external_data or {}).get("dnsdumpster") or {}
    if not isinstance(dd, dict):
        return []
    ips: list[str] = []
    for key in ("host_records", "dns_servers", "mx_records"):
        for row in (dd.get(key) or []):
            cells = row if isinstance(row, list) else [row]
            for cell in cells:
                for m in _IPV4_RE.findall(str(cell)):
                    ips.append(m)
    return ips


def discover_origin_ips(domain: str, main_ips: list[str] | None = None,
                        cnames: list[str] | None = None,
                        external_data: dict[str, Any] | None = None,
                        timeout: float = TIMEOUT) -> dict[str, Any]:
    """Recolecta IPs candidatas a ser el origen real detras de CDN/WAF."""
    main = {str(ip) for ip in (main_ips or [])}
    cn = [str(c).rstrip(".").lower() for c in (cnames or []) if c]
    cdn_fronted = bool(cn) and any(_is_cdn_name(c) for c in cn)

    candidates: dict[str, dict[str, Any]] = {}

    def add(ip: str, source: str, via: str) -> None:
        ip = str(ip).strip()
        if not ip or ip in main:
            return
        if ip in candidates:
            if source not in candidates[ip]["sources"]:
                candidates[ip]["sources"].append(source)
            return
        candidates[ip] = {"ip": ip, "sources": [source], "via": via}

    # 1) CNAMEs no-CDN ya observados
    for c in cn:
        if not _is_cdn_name(c):
            for ip in _resolve_a(c, timeout):
                add(ip, "cname_direct", c)

    # 2) Subdominios con pinta de origen
    for lab in ORIGIN_LABELS:
        host = f"{lab}.{domain}"
        ips = _resolve_a(host, timeout)
        if not ips:
            continue
        cname = _resolve_cname(host, timeout)
        if cname and _is_cdn_name(cname):
            continue
        for ip in ips:
            add(ip, "hint_subdomain", host)

    # 3) dnsdumpster (OSINT) si esta disponible
    for ip in _dnsdumpster_ips(external_data or {}):
        add(ip, "dnsdumpster", "OSINT")

    origin_candidates = sorted(candidates.values(), key=lambda c: c["ip"])
    result: dict[str, Any] = {
        "domain": domain,
        "cdn_fronted": cdn_fronted,
        "cdn": [c for c in cn if _is_cdn_name(c)],
        "main_ips": sorted(main),
        "origin_candidates": origin_candidates,
        "exposed": bool(cdn_fronted and origin_candidates),
    }
    return result


def run_origin(domain: str, main_ips: list[str] | None = None,
               cnames: list[str] | None = None,
               external_data: dict[str, Any] | None = None,
               waf_data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Wrapper tolerante usado por el escaneo."""
    try:
        data = discover_origin_ips(domain, main_ips, cnames, external_data)
    except Exception:
        return {}
    if isinstance(waf_data, dict) and waf_data.get("detected"):
        data["waf_detected"] = waf_data.get("detected")
        if not data.get("cdn") and waf_data.get("waf"):
            data["cdn"] = [waf_data.get("waf")]
    return data


def _esc(s: Any) -> str:
    return html.escape(str(s), quote=True)


def render_origin_block(domain: str, provider: dict[str, Any]) -> str:
    """Bloque HTML (IP de origen tras CDN/WAF) para B5/B6/B7. '' si no aplica."""
    if not isinstance(provider, dict):
        return ""
    oi = provider.get("origin_ips") or {}
    if not isinstance(oi, dict) or not oi.get("origin_candidates"):
        return ""
    cands = oi.get("origin_candidates") or []
    cdn = ", ".join(str(c) for c in (oi.get("cdn") or [])) or "CDN/WAF"
    if oi.get("exposed"):
        head = (
            f'<b style="color:#B71C1C;">Posible IP de origen expuesta</b> tras {_esc(cdn)}: '
            f'{len(cands)} candidato(s) fuera de la infraestructura CDN. '
            'Un atacante podria contactar el backend directamente y evadir el WAF.</p>'
        )
    else:
        head = (
            f'<b>{_esc(cdn)}</b> fronting detectado; sin IP de origen '
            f'expuesta en el muestreo keyless ({len(cands)} candidato(s) informativo(s)).</p>'
        )
    rows = "".join(
        f"<tr><td style=\"font-family:monospace;font-size:8px;\">{_esc(c.get('ip'))}</td>"
        f"<td style=\"font-size:8px;\">{_esc(', '.join(c.get('sources') or []))}</td>"
        f"<td style=\"font-size:8px;\">{_esc(c.get('via'))}</td></tr>"
        for c in cands[:15]
    )
    return (
        '<h4 style="margin:6px 0 3px;">IP de origen tras CDN/WAF</h4>'
        f'<p style="font-size:8.5px;margin:2px 0;">{head}</p>'
        '<table style="width:100%;border-collapse:collapse;" border="1" cellspacing="0" cellpadding="3">'
        '<thead><tr style="background:#EEEEEE;">'
        '<th style="font-size:8px;text-align:left;">IP candidata</th>'
        '<th style="font-size:8px;text-align:left;">Fuente</th>'
        '<th style="font-size:8px;text-align:left;">Via</th>'
        '</tr></thead><tbody>' + rows + '</tbody></table>'
    )
