"""Detección ligera de WAF / CDN a partir de cabeceras HTTP y registros CNAME.

Adaptado de Raccoon (raccoon_src/lib/waf.py, licencia MIT) a la convención
de módulos auxiliares del proyecto ASM. No requiere nmap: usa únicamente la
respuesta HTTP ya obtenida (headers) y el DNS CNAME del dominio.
"""

from __future__ import annotations

from typing import Any

import requests

USER_AGENT = "ASM-Incocredito-Proveedores/1.0 (+research)"
TIMEOUT = 10


# Firmas por cabecera / valor presente en la respuesta 200 del apex.
# (presencia_header, headers_exactos, pistas_valor, headers_valor_exigidos)
_SIGNATURES: tuple[tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]], ...] = (
    ("Cloudflare", ("CF-RAY",), ("cloudflare",), ()),
    ("CloudFront", ("X-Amz-Cf-Id", "X-Amz-Cf-Pop"), ("cloudfront", "amazonaws.com"), ("Via", "X-cache")),
    ("Incapsula", ("X-Iinfo",), ("incap", "incapsula"), ("X-CDN",)),
    ("Imperva", ("X-Iinfo",), ("incapsula", "imperva"), ()),
    ("Akamai", ("X-Akamai-Transformed", "X-True-IP"), ("akamaiedge", "akamai", "edgesuite"), ("Via",)),
    ("Sucuri", ("X-Sucuri-ID", "X-Sucuri-Cache"), ("sucuri",), ()),
    ("AWS WAF / Shield", ("X-Amzn-Trace-Id",), ("awswaf",), ()),
    ("F5 BIG-IP / ASM", ("X-F5-Auth", "X-ASM-Policy"), ("bigip", "trafficshield"), ()),
    ("Barracuda", ("X-Barracuda-*",), ("barracuda",), ()),
    ("Citrix NetScaler / ADC", ("NS-Cache",), ("netscaler",), ()),
    ("Fastly", (), ("fastly",), ("X-Served-By",)),
    ("Stack Path", (), ("stackpath",), ("X-Served-By",)),
    ("EdgeCast", (), ("edgecast",), ("X-EC",)),
    ("MaxCDN", (), ("netdna", "maxcdn"), ("Server",)),
    ("Reblaze", (), ("reblaze",), ("Server",)),
    ("Distil Networks", ("X-Distil-CS",), ("distil",), ()),
)

# Mapeo de CNAME hacia proveedor WAF/CDN (clasificación previa al request).
_CNAME_MAP: tuple[tuple[str, str], ...] = (
    ("incapdns", "Incapsula"),
    ("impervadns", "Imperva"),
    ("edgekey", "Akamai"),
    ("akamai", "Akamai"),
    ("edgesuite", "Akamai"),
    ("distil", "Distil Networks"),
    ("cloudfront", "CloudFront"),
    ("netdna-cdn", "MaxDNL"),
    ("pantheon", "Pantheon"),
    ("sucuri", "Sucuri"),
    ("stackpath", "Stack Path"),
    ("fastly", "Fastly"),
    ("cloudflare", "Cloudflare"),
)

_HDR_EXACT: tuple[str, ...] = (
    "via", "x-cache", "server", "set-cookie", "x-served-by",
    "x-framework", "x-powered-by", "x-iinfo", "x-cdn", "x-amzn-trace-id",
)


def detect_waf(
    domain: str,
    status_code: int | None,
    headers: dict[str, Any] | None,
    cnames: list[str] | None = None,
) -> dict[str, Any]:
    """Devuelve dict con 'present', 'detections' (lista de proveedores) y 'evidence'.

    Solo usa la respuesta ya captura posteriormente por probe_https, más el
    CNAME si está disponible. No emite requests nuevos.
    """
    user_agent = USER_AGENT
    headers = headers or {}
    cnames = cnames or []

    found: list[str] = []
    evidence: list[str] = []

    # 1) Detección por CNAME (pasivo, sin request).
    for sub, provider in _CNAME_MAP:
        for cname in cnames:
            if sub in cname.lower():
                if provider not in found:
                    found.append(provider)
                evidence.append(f"CNAME {cname}")
                break

    # 2) Detección por cabeceras de la respuesta del apex.
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    server_val = lowered.get("server", "").lower()

    for waf_name, exact_headers, value_hints, value_required_headers in _SIGNATURES:
        hit = False
        # Cabeceras cuya mera presencia indica el WAF (ej. CF-RAY, X-Iinfo).
        for key in exact_headers:
            if key.lower() in lowered:
                hit = True
                evidence.append(f"Header {key}")
                break
        if not hit and value_required_headers:
            # Cabeceras genéricas (Via, X-cache, Server) que solo cuentan si
            # su valor contiene la pista del proveedor.
            for key in value_required_headers:
                val = lowered.get(key.lower(), "")
                if any(hint in val.lower() for hint in value_hints):
                    hit = True
                    evidence.append(f"Header {key} value: {val}")
                    break
        if not hit and not value_required_headers:
            # Fallback sobre el valor de Server solo si no exigimos valor.
            if any(hint in server_val for hint in value_hints):
                hit = True
                evidence.append(f"Server value: {server_val}")
        if hit and waf_name not in found:
            found.append(waf_name)

    return {
        "domain": domain,
        "waf": found,
        "detected": bool(found),
        "evidence": evidence[:12],
        "confidence": "high" if found else "none",
    }