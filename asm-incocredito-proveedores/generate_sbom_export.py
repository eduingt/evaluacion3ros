#!/usr/bin/env python3
"""
Genera un SBOM CycloneDX del producto ASM (no del escaneo) a partir de
requirements.txt + requirements-dashboard.txt y del inventario vendorizado.

Referencia: skill hve-core supply-chain-security (NTIA SBOM minimum elements,
SLSA, OpenSSF Scorecard). El SBOM describe el producto; por eso no varia por
escaneo y el dashboard lo sirve como descarga estatica generada al vuelo.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent

SPEC_VERSION = "1.5"
TOOL_NAME = "ASM-Informe-Proveedores"

VENDORED: list[dict[str, Any]] = [
    {"name": "prism_osint", "version": "2.6", "type": "library",
     "description": "Prism-platform OSINT Toolkit vendorizado",
     "external": "https://github.com/NovaCode37/Prism-platform"},
    {"name": "claude_osint_scripts", "version": "1.0", "type": "library",
     "description": "Capacidades keyless de Claude-OSINT vendorizadas",
     "external": "https://github.com/elementalsouls/Claude-OSINT"},
    {"name": "kumo", "version": "1.0", "type": "library",
     "description": "KUMO-Domain-Recon-Tool integrado (wayback, breach intel, nuclei)",
     "external": "KUMO-Domain-Recon-Tool"},
    {"name": "raccoon-derived", "version": "1.0", "type": "library",
     "description": "Deteccion WAF/CDN y cloud storage adaptada de Raccoon (MIT)",
     "external": "https://github.com/evyatarmeged/Raccoon"},
    {"name": "FinalRecon", "version": "1.0", "type": "application",
     "description": "Escanner externo CLI (subdominios, correos, DNS, GeoIP)",
     "external": "FinalRecon"},
    {"name": "nuclei", "version": "1.0", "type": "application",
     "description": "Binario externo via nuclei_integration",
     "external": "https://github.com/projectdiscovery/nuclei"},
    {"name": "gobuster", "version": "1.0", "type": "application",
     "description": "Binario externo via gobuster_integration",
     "external": "https://github.com/OJ/gobuster"},
    {"name": "strix", "version": "1.0", "type": "application",
     "description": "Agente IA de pentesting externo (requiere Docker + LLM key)",
     "external": "https://github.com/usestrix/strix"},
]


def _parse_requirements(path: Path) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    if not path.is_file():
        return components
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)==([^;,\s]+)", line)
        if not m:
            continue
        name = re.sub(r"\[.*\]", "", m.group(1))
        version = m.group(2)
        components.append({
            "bom-ref": f"pkg:pypi/{name}@{version}",
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
        })
    return components


def build_sbom_doc() -> dict[str, Any]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    components = _parse_requirements(ROOT / "requirements.txt")
    components += _parse_requirements(ROOT / "requirements-dashboard.txt")
    for v in VENDORED:
        components.append({
            "bom-ref": f"pkg:generic/{v['name']}@{v['version']}",
            "type": v["type"],
            "name": v["name"],
            "version": v["version"],
            "description": v["description"],
            "externalReferences": [{"type": "website", "url": v["external"]}],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"name": TOOL_NAME}],
        },
        "components": components,
        "properties": {
            "component_count": len(components),
            "pypi_count": sum(1 for c in components if c.get("purl", "").startswith("pkg:pypi/")),
            "vendored_count": len(VENDORED),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera SBOM CycloneDX del producto ASM")
    parser.add_argument("--output", default=ROOT / "asm_sbom.json", type=Path)
    args = parser.parse_args()
    doc = build_sbom_doc()
    args.output.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"SBOM CycloneDX exportado a {args.output}")
    print(f"  Componentes: {doc['properties']['component_count']} "
          f"(pypi {doc['properties']['pypi_count']}, vendorizados {doc['properties']['vendored_count']})")


if __name__ == "__main__":
    main()
