#!/usr/bin/env python3
"""
Genera un archivo SARIF 2.1 (JSON) a partir de asm_report.json.
Compatible con GitHub Advanced Security, Code Scanning, y otras
herramientas de análisis de seguridad que soportan SARIF.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _cve_to_result(cve: dict[str, Any], domain: str, run_id: int) -> dict[str, Any]:
    cve_id = cve.get("id", "CVE-unknown")
    title = cve.get("title", "")[:200]
    risk = cve.get("risk_score")
    epss = cve.get("epss_score")
    in_kev = cve.get("in_kev", False)
    port = cve.get("port", "?")
    product = cve.get("product", "?")

    if in_kev or (risk and risk >= 7):
        level = "error"
    elif risk and risk >= 4:
        level = "warning"
    else:
        level = "note"

    message_text = f"{cve_id}: {title} (Producto: {product}, Puerto: {port})"
    if in_kev:
        message_text += " [CISA KEV - EXPLOTACION ACTIVA]"
    if epss is not None:
        message_text += f" [EPSS: {epss*100:.1f}%]"

    return {
        "ruleId": f"CVE/{cve_id}",
        "ruleIndex": run_id,
        "level": level,
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"https://{domain}"},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "cve": cve_id,
            "port": port,
            "product": product,
            "risk_score": risk,
            "epss_score": epss,
            "in_kev": in_kev,
            "domain": domain,
        },
    }


def _issue_to_result(issue: dict[str, Any], domain: str, rule_prefix: str) -> dict[str, Any] | None:
    desc = issue.get("desc", issue.get("description", ""))
    sev = issue.get("level", issue.get("gravedad", "medium")).lower()
    level = SEVERITY_MAP.get(sev, "warning")

    return {
        "ruleId": f"{rule_prefix}/{issue.get('id', 'unknown')}",
        "ruleIndex": 0,
        "level": level,
        "message": {"text": desc[:500]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"https://{domain}"},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "domain": domain,
            "evidence": issue.get("evidence", "")[:300],
            "recommendation": issue.get("recommendation", "")[:300],
        },
    }


def build_sarif_log(asm: dict[str, Any]) -> dict[str, Any]:
    providers = asm.get("providers") or []
    gen_time = asm.get("generated_utc", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    rules: list[dict[str, Any]] = [
        {
            "id": "CVE/banner-grab",
            "name": "CVE por Banner Grab",
            "shortDescription": {"text": "Correlación de banners de servicio con bases de datos de vulnerabilidades (CVE, Exploit-DB, VulDB)."},
            "fullDescription": {"text": "Mediante banner grabbing pasivo se identificaron versiones de software que coinciden con vulnerabilidades conocidas. Los resultados se enriquecen con EPSS (probabilidad de explotación) y CISA KEV (explotación activa)."},
            "defaultConfiguration": {"level": "warning"},
            "properties": {"precision": "medium", "tags": ["security", "cve", "vulnerability"]},
        },
        {
            "id": "SHADOW/api",
            "name": "Shadow API",
            "shortDescription": {"text": "Endpoint API no documentado ni esperado en servicios públicos."},
            "fullDescription": {"text": "Se detectaron endpoints API que responden con datos (status 200, 401, 403) pero no corresponden a documentación pública conocida. Pueden ser shadow APIs, endpoints legacy, o rutas de administración expuestas."},
            "defaultConfiguration": {"level": "warning"},
            "properties": {"precision": "medium", "tags": ["security", "shadow-api", "attack-surface"]},
        },
        {
            "id": "TLS/security",
            "name": "Hallazgo TLS",
            "shortDescription": {"text": "Problemas de configuración TLS detectados."},
            "fullDescription": {"text": "Problemas de configuración TLS incluyendo versiones obsoletas, certificados expirados o configuraciones inseguras."},
            "defaultConfiguration": {"level": "warning"},
            "properties": {"precision": "high", "tags": ["security", "tls"]},
        },
    ]
    rule_idx = 0
    rule_map: dict[str, int] = {}
    for r in rules:
        rule_map[r["id"]] = rule_idx
        rule_idx += 1

    results: list[dict[str, Any]] = []

    for p in providers:
        domain = p.get("domain", "unknown")

        # CVE findings
        for cve in p.get("cve_findings") or []:
            result = _cve_to_result(cve, domain, rule_map.get("CVE/banner-grab", 0))
            if result:
                results.append(result)

        # API endpoints (shadow APIs)
        for ep in p.get("api_endpoints") or []:
            if ep.get("is_shadow"):
                sc = ep.get("status_code")
                method = ep.get("method", "GET")
                path = ep.get("path", "/")
                cat = ep.get("category", "unknown")
                results.append({
                    "ruleId": "SHADOW/api",
                    "ruleIndex": rule_map.get("SHADOW/api", 0),
                    "level": "warning",
                    "message": {"text": f"Shadow API: {method} {path} ({cat}, HTTP {sc}) en {domain}. Descripción: {ep.get('description', '?')}"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"https://{domain}{path}"}, "region": {"startLine": 1}}}],
                    "properties": {"domain": domain, "path": path, "method": method, "category": cat},
                })

        # TLS issues
        tls = p.get("tls") or {}
        if tls.get("error"):
            results.append({
                "ruleId": "TLS/security",
                "ruleIndex": rule_map.get("TLS/security", 0),
                "level": "error",
                "message": {"text": f"Error TLS en {domain}: {tls['error'][:200]}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"https://{domain}"}, "region": {"startLine": 1}}}],
                "properties": {"domain": domain, "error": tls["error"]},
            })
        elif tls.get("negotiated_version") and "1.2" not in str(tls.get("negotiated_version", "")):
            results.append({
                "ruleId": "TLS/security",
                "ruleIndex": rule_map.get("TLS/security", 0),
                "level": "warning",
                "message": {"text": f"Versión TLS potencialmente insegura en {domain}: {tls.get('negotiated_version', '?')}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"https://{domain}"}, "region": {"startLine": 1}}}],
                "properties": {"domain": domain, "tls_version": tls.get("negotiated_version")},
            })

    log: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ASM-Informe-Proveedores",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/anomalyco/asm-informe-proveedores",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "generated_utc": gen_time,
                    "provider_count": len(providers),
                    "total_findings": len(results),
                    "cve_count": sum(len(p.get("cve_findings") or []) for p in providers),
                    "shadow_api_count": sum(sum(1 for e in p.get("api_endpoints") or [] if e.get("is_shadow")) for p in providers),
                },
            }
        ],
    }

    return log


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera export SARIF 2.1 desde asm_report.json")
    parser.add_argument("--input", default=ROOT / "asm_report.json", type=Path, help="Ruta a asm_report.json")
    parser.add_argument("--output", default=ROOT / "asm_sarif.json", type=Path, help="Ruta de salida SARIF JSON")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: no se encuentra {args.input}")
        raise SystemExit(1)

    asm = json.loads(args.input.read_text(encoding="utf-8"))
    log = build_sarif_log(asm)
    args.output.write_text(json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8")

    props = log["runs"][0]["properties"]
    print(f"SARIF 2.1 exportado a {args.output}")
    print(f"  Proveedores:   {props['provider_count']}")
    print(f"  Hallazgos:     {props['total_findings']}")
    print(f"  CVEs:          {props['cve_count']}")
    print(f"  Shadow APIs:   {props['shadow_api_count']}")


if __name__ == "__main__":
    main()
