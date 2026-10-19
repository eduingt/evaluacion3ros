#!/usr/bin/env python3
"""
Genera un documento OpenVEX 0.2.0 (JSON) a partir de asm_report.json.
Complementa generate_sarif_export.py: SARIF lista hallazgos, VEX declara
explotabilidad (affected / not_affected / fixed / under_investigation).

Referencia: https://github.com/openvex/spec (Apache-2.0) y skill hve-core
.github/skills/security/vex/SKILL.md (playbooks CC-BY-4.0).
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent

VEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
VEX_AUTHOR = "ASM-Informe-Proveedores"


def _purl(domain: str) -> str:
    safe = domain.strip().lower().replace(" ", "-")
    return f"pkg:generic/asm-provider@{safe}"


def _cve_statement(cve: dict[str, Any], domain: str, doc_id: str, now: str) -> dict[str, Any]:
    cve_id = cve.get("id", "CVE-unknown")
    risk = cve.get("risk_score")
    in_kev = bool(cve.get("in_kev", False))
    epss = cve.get("epss_score")
    product = cve.get("product", "?")
    port = cve.get("port", "?")

    vuln_id = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if str(cve_id).startswith("CVE-") else cve_id

    if in_kev or (isinstance(risk, (int, float)) and risk >= 7.0):
        status = "affected"
        stmt: dict[str, Any] = {
            "vulnerability": {"@id": vuln_id},
            "products": [{"@id": _purl(domain)}],
            "status": status,
            "action_statement": (
                f"Priorizar remediacion en {domain} (producto {product}, puerto {port}). "
                + ("CISA KEV confirma explotacion activa. " if in_kev else "")
                + (f"EPSS {epss * 100:.1f}%. " if isinstance(epss, (int, float)) else "")
                + "Actualizar/aislar el servicio y verificar con re-escaneo."
            ),
        }
    elif isinstance(risk, (int, float)) and risk >= 4.0:
        stmt = {
            "vulnerability": {"@id": vuln_id},
            "products": [{"@id": _purl(domain)}],
            "status": "under_investigation",
            "impact_statement": (
                f"Hallazgo de severidad media en {domain} pendiente de confirmar alcanzabilidad "
                f"(producto {product}, puerto {port})."
            ),
        }
    else:
        stmt = {
            "vulnerability": {"@id": vuln_id},
            "products": [{"@id": _purl(domain)}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
            "impact_statement": (
                f"Banner coincide con base de CVE pero sin evidencia de ruta alcanzable en {domain} "
                f"(producto {product}, puerto {port}). Requiere validacion manual."
            ),
        }
    stmt["@id"] = f"{doc_id}#{cve_id}-{domain}"
    stmt["last_updated"] = now
    return stmt


def build_vex_doc(asm: dict[str, Any]) -> dict[str, Any]:
    providers = asm.get("providers") or []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_id = f"https://asm.local/vex/{asm.get('generated_utc', now)}"
    statements: list[dict[str, Any]] = []
    counts = {"affected": 0, "not_affected": 0, "under_investigation": 0, "fixed": 0}

    for p in providers:
        domain = p.get("domain", "unknown")
        for cve in p.get("cve_findings") or []:
            st = _cve_statement(cve, domain, doc_id, now)
            statements.append(st)
            counts[st["status"]] = counts.get(st["status"], 0) + 1

    return {
        "@context": VEX_CONTEXT,
        "@id": doc_id,
        "author": VEX_AUTHOR,
        "timestamp": now,
        "version": 1,
        "statements": statements,
        "properties": {
            "generated_utc": asm.get("generated_utc", now),
            "provider_count": len(providers),
            "statement_count": len(statements),
            "counts": counts,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera export OpenVEX 0.2.0 desde asm_report.json")
    parser.add_argument("--input", default=ROOT / "asm_report.json", type=Path)
    parser.add_argument("--output", default=ROOT / "asm_vex.json", type=Path)
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: no se encuentra {args.input}")
        raise SystemExit(1)

    asm = json.loads(args.input.read_text(encoding="utf-8"))
    doc = build_vex_doc(asm)
    args.output.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    props = doc["properties"]
    print(f"VEX exportado a {args.output}")
    print(f"  Proveedores: {props['provider_count']}")
    print(f"  Statements:  {props['statement_count']} {props['counts']}")


if __name__ == "__main__":
    main()
