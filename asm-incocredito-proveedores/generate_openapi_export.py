#!/usr/bin/env python3
"""
Genera un archivo OpenAPI 3.0 (JSON) a partir de asm_report.json.
Convierte endpoints descubiertos, vulnerabilidades y hallazgos de seguridad
en una especificación OpenAPI importable por ZAP, Burp, Postman, etc.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _build_security_schemes(p: dict[str, Any]) -> dict[str, dict[str, Any]]:
    schemes: dict[str, dict[str, Any]] = {}
    tls = p.get("tls") or {}
    if tls.get("negotiated_version") and not tls.get("error"):
        schemes["TLS"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": f"TLS {tls.get('negotiated_version', 'unknown')}",
            "description": "Conexión TLS negociada automáticamente",
        }
    h = p.get("https", {}).get("headers") or {}
    if h.get("authorization") or h.get("www-authenticate"):
        schemes["Auth"] = {
            "type": "http",
            "scheme": "bearer",
            "description": "Autenticación detectada en cabeceras HTTP",
        }
    return schemes


def _build_paths(providers: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    paths: dict[str, dict[str, Any]] = {}

    for p in providers:
        domain = p.get("domain", "unknown")
        api_eps = p.get("api_endpoints") or []

        for ep in api_eps:
            path = ep.get("path", "/")
            method = (ep.get("method", "get") or "get").lower()
            sc = ep.get("status_code")
            ct = ep.get("content_type") or "application/json"

            if path not in paths:
                paths[path] = {}

            # Skip if method already defined for this path
            if method in paths[path]:
                continue

            resp: dict[str, Any] = {"description": f"HTTP {sc}" if sc else "Sin respuesta"}
            if sc:
                resp["content"] = {ct: {"schema": {"type": "object"}}}

            operation: dict[str, Any] = {
                "operationId": f"{method.replace(' ', '_')}_{path.replace('/', '_').strip('_')}_{domain.replace('.', '_')}",
                "summary": ep.get("description", f"Endpoint {method.upper()} {path}"),
                "description": f"Descubierto en {domain} | Categoría: {ep.get('category', '?')} | Shadow API: {ep.get('is_shadow', False)}",
                "parameters": [
                    {
                        "name": "Accept",
                        "in": "header",
                        "schema": {"type": "string"},
                        "description": "Tipo de contenido aceptado",
                    }
                ],
                "responses": {
                    str(sc or 200): resp,
                    "default": {"description": "Respuesta inesperada"},
                },
                "tags": [domain, f"shadow:{ep.get('is_shadow', False)}"],
            }

            if ep.get("body_preview"):
                operation["x-body-preview"] = ep["body_preview"]
            if ep.get("is_shadow"):
                operation["x-shadow-api"] = True
            if ep.get("category"):
                operation["x-category"] = ep["category"]

            paths[path][method] = operation

    # Add security findings as synthetic endpoints for visibility
    for p in providers:
        domain = p.get("domain", "unknown")
        cves = p.get("cve_findings") or []
        if cves:
            path = "/x-asm/vulnerabilities"
            if path not in paths:
                paths[path] = {}
            if "get" not in paths[path]:
                cve_list = [{"cve": c.get("id"), "risk": c.get("risk_score"), "kev": c.get("in_kev")} for c in cves[:20]]
                paths[path]["get"] = {
                    "operationId": f"list_vulnerabilities_{domain.replace('.', '_')}",
                    "summary": f"Vulnerabilidades detectadas en {domain}",
                    "description": f"{len(cves)} CVE(s) encontrados por banner grab. Los CVEs marcados como KEV están en explotación activa.",
                    "parameters": [],
                    "responses": {"200": {"description": f"{len(cves)} vulnerabilidades", "content": {"application/json": {"schema": {"type": "array", "items": {"type": "object", "properties": {"cve": {"type": "string"}, "risk": {"type": "number"}, "kev": {"type": "boolean"}}}}}}}},
                    "tags": [domain, "security"],
                    "x-cve-count": len(cves),
                    "x-kev-count": sum(1 for c in cves if c.get("in_kev")),
                }

    return paths


def build_openapi_spec(asm: dict[str, Any], title: str = "ASM - Incocredito Proveedores", version: str = "1.0.0") -> dict[str, Any]:
    providers = asm.get("providers") or []
    gen_time = asm.get("generated_utc", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    # Collect all domains as servers
    servers = []
    for p in providers:
        domain = p.get("domain", "")
        if domain:
            servers.append({"url": f"https://{domain}", "description": p.get("name", domain)})

    paths = _build_paths(providers)

    # Security schemes from first provider with TLS
    security_schemes: dict[str, Any] = {}
    for p in providers:
        schemes = _build_security_schemes(p)
        security_schemes.update(schemes)

    spec: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": title,
            "description": "Especificación OpenAPI generada automáticamente desde escaneo ASM de proveedores Incocredito. Incluye endpoints descubiertos, shadow APIs, vulnerabilidades y configuración de seguridad.",
            "version": version,
            "x-generated-at": gen_time,
            "x-provider-count": len(providers),
            "x-total-endpoints": sum(len(p.get("api_endpoints") or []) for p in providers),
            "x-total-cves": sum(len(p.get("cve_findings") or []) for p in providers),
        },
        "servers": servers,
        "paths": paths,
        "components": {"securitySchemes": security_schemes} if security_schemes else {},
        "tags": [
            {"name": p.get("domain", p.get("name", "?")), "description": f"{p.get('name', '?')} — {p.get('domain', '?')}"}
            for p in providers
        ],
        "x-asm-metadata": {
            "generated_utc": gen_time,
            "provider_count": len(providers),
            "endpoint_count": sum(len(p.get("api_endpoints") or []) for p in providers),
            "shadow_api_count": sum(sum(1 for e in p.get("api_endpoints") or [] if e.get("is_shadow")) for p in providers),
            "total_cves": sum(len(p.get("cve_findings") or []) for p in providers),
            "total_kev": sum(sum(1 for c in p.get("cve_findings") or [] if c.get("in_kev")) for p in providers),
        },
    }

    return spec


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera export OpenAPI 3.0 desde asm_report.json")
    parser.add_argument("--input", default=ROOT / "asm_report.json", type=Path, help="Ruta a asm_report.json")
    parser.add_argument("--output", default=ROOT / "asm_openapi.json", type=Path, help="Ruta de salida OpenAPI JSON")
    parser.add_argument("--title", default="ASM - Incocredito Proveedores", help="Título de la especificación")
    parser.add_argument("--version", default="1.0.0", help="Versión de la especificación")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: no se encuentra {args.input}")
        raise SystemExit(1)

    asm = json.loads(args.input.read_text(encoding="utf-8"))
    spec = build_openapi_spec(asm, title=args.title, version=args.version)
    args.output.write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
    endpoint_count = spec["info"]["x-total-endpoints"]
    cve_count = spec["info"]["x-total-cves"]
    print(f"OpenAPI 3.0 exportado a {args.output}")
    print(f"  Proveedores: {spec['info']['x-provider-count']}")
    print(f"  Endpoints:   {endpoint_count}")
    print(f"  Shadow APIs: {spec['x-asm-metadata']['shadow_api_count']}")
    print(f"  CVEs totales: {cve_count}")
    print(f"  KEV:         {spec['x-asm-metadata']['total_kev']}")


if __name__ == "__main__":
    main()
