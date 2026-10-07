# nuclei_integration.py — Integración de Nuclei (ProjectDiscovery) para escaneo de vulnerabilidades.
# Requiere binario `nuclei` en PATH (https://github.com/projectdiscovery/nuclei).
# Plantillas: usa -t con tags (cves, vulnerabilities, misconfigurations, exposures, technologies, etc.)
#
# Uso desde asm_scan._scan_provider:
#   import nuclei_integration
#   nuclei_data = nuclei_integration.run_for_level(domain, test_level)
#
# NIVELES:
#   pasivo (1)       -> NO EJECUTA (nuclei es activo por naturaleza)
#   semi-activo (2)  -> plantillas "safe" solamente (technologies, exposures, misconfigurations sin exploit)
#   activo (3)       -> cves + vulnerabilities + misconfigurations + exposures + technologies
#   invasivo (4)     -> todas las plantillas + plantillas custom + rate limiting más agresivo

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("nuclei_integration")


def _find_nuclei_bin() -> str | None:
    """Busca el binario nuclei en PATH o ubicaciones comunes."""
    # 1. PATH actual
    bin_path = shutil.which("nuclei")
    if bin_path:
        return bin_path
    # 2. Go default bin directory
    go_bin = Path.home() / "go" / "bin" / "nuclei.exe"
    if go_bin.exists():
        return str(go_bin)
    # 3. GOPATH/bin
    gopath = os.environ.get("GOPATH")
    if gopath:
        gopath_bin = Path(gopath) / "bin" / "nuclei.exe"
        if gopath_bin.exists():
            return str(gopath_bin)
    return None


def _find_templates_dir() -> Path:
    """Busca el directorio de plantillas nuclei."""
    # 1. Default location
    default = Path.home() / "nuclei-templates"
    if default.exists():
        return default
    # 2. Go path
    go_templates = Path.home() / "go" / "nuclei-templates"
    if go_templates.exists():
        return go_templates
    return default


NUCLEI_BIN = _find_nuclei_bin()
NUCLEI_TEMPLATES_DIR = _find_templates_dir()

# Tags de plantillas por nivel (evita plantillas destructivas en niveles bajos)
LEVEL_TAGS: dict[int, list[str]] = {
    1: [],  # pasivo: no ejecuta
    2: ["technologies", "exposures", "misconfigurations"],  # semi-activo: solo info-gathering y config checks
    3: ["cves", "vulnerabilities", "misconfigurations", "exposures", "technologies", "takeovers"],  # activo
    4: ["cves", "vulnerabilities", "misconfigurations", "exposures", "technologies", "takeovers", "fuzzing", "generic"],  # invasivo
}

# Excluir plantillas peligrosas/destructivas en todos los niveles
EXCLUDE_TAGS = ["dos", "rce", "intrusive", "exploit"]

# Rate limits por nivel (requests/second)
LEVEL_RATE_LIMIT: dict[int, int] = {
    1: 0,
    2: 10,
    3: 25,
    4: 50,
}

# Timeouts por nivel (segundos)
LEVEL_TIMEOUT: dict[int, int] = {
    1: 0,
    2: 60,
    3: 180,
    4: 300,
}

# Severidad mínima por nivel (para filtrar ruido)
LEVEL_MIN_SEVERITY: dict[int, list[str]] = {
    1: [],
    2: ["info", "low", "medium", "high", "critical"],
    3: ["low", "medium", "high", "critical"],
    4: ["medium", "high", "critical"],
}


def _build_nuclei_cmd(domain: str, test_level: int, output_file: Path) -> list[str]:
    """Construye comando nuclei para el nivel dado."""
    if test_level < 2:
        return []

    tags = LEVEL_TAGS.get(test_level, LEVEL_TAGS[3])
    rate = LEVEL_RATE_LIMIT.get(test_level, 25)
    timeout = LEVEL_TIMEOUT.get(test_level, 180)
    min_sev = LEVEL_MIN_SEVERITY.get(test_level, ["low", "medium", "high", "critical"])

    cmd = [
        str(NUCLEI_BIN),
        "-u", f"https://{domain}",
        "-jsonl",  # JSON lines output
        "-o", str(output_file),
        "-rate-limit", str(rate),
        "-timeout", str(timeout),
        "-retries", "1",
        "-silent",
        "-no-color",
    ]

    # Tags a incluir
    for tag in tags:
        cmd.extend(["-tags", tag])

    # Tags a excluir
    for tag in EXCLUDE_TAGS:
        cmd.extend(["-exclude-tags", tag])

    # Severidad mínima
    if min_sev:
        cmd.extend(["-severity", ",".join(min_sev)])

    # Plantillas custom si existen en directorio local
    custom_templates = Path(__file__).parent / "nuclei_templates"
    if custom_templates.exists():
        cmd.extend(["-t", str(custom_templates)])

    return cmd


def _parse_nuclei_output(output_file: Path) -> list[dict[str, Any]]:
    """Parsea salida JSONL de nuclei."""
    findings: list[dict[str, Any]] = []
    if not output_file.exists():
        return findings

    try:
        with output_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    # Normalizar campos clave
                    finding = {
                        "template_id": entry.get("template-id") or entry.get("templateID"),
                        "template_name": entry.get("info", {}).get("name"),
                        "severity": entry.get("info", {}).get("severity", "info").lower(),
                        "type": entry.get("info", {}).get("type", ""),
                        "description": entry.get("info", {}).get("description", "")[:200],
                        "matched_at": entry.get("matched-at") or entry.get("host"),
                        "extracted_results": entry.get("extracted-results") or [],
                        "curl_command": entry.get("curl-command"),
                        "tags": entry.get("info", {}).get("tags", []),
                        "reference": entry.get("info", {}).get("reference", []),
                        "classification": entry.get("info", {}).get("classification", {}),
                        "matcher_name": entry.get("matcher-name"),
                        "_raw": entry,  # mantener original para debug
                    }
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        log.warning("Error parseando salida nuclei: %s", e)

    return findings


def run_nuclei(domain: str, test_level: int) -> dict[str, Any]:
    """Ejecuta nuclei contra el dominio y retorna hallazgos normalizados."""
    if test_level < 2:
        return {"level": test_level, "status": "skipped", "reason": "nivel pasivo: nuclei no se ejecuta", "findings": []}

    if not NUCLEI_BIN:
        return {"level": test_level, "status": "error", "error": "binario 'nuclei' no encontrado en PATH", "findings": []}

    # Verificar plantillas actualizadas
    if not NUCLEI_TEMPLATES_DIR.exists():
        log.warning("Directorio de plantillas nuclei no encontrado en %s. Ejecute 'nuclei -update-templates'", NUCLEI_TEMPLATES_DIR)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as tmp:
        output_path = Path(tmp.name)

    try:
        cmd = _build_nuclei_cmd(domain, test_level, output_path)
        if not cmd:
            return {"level": test_level, "status": "skipped", "findings": []}

        log.info("Ejecutando nuclei nivel %d en %s (tags: %s)", test_level, domain, LEVEL_TAGS.get(test_level))
        start = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=LEVEL_TIMEOUT.get(test_level, 180) + 30)
        elapsed = time.time() - start

        if result.returncode not in (0, 1):  # nuclei retorna 1 cuando hay hallazgos
            log.warning("nuclei exit code %d: %s", result.returncode, result.stderr[:200])
            return {"level": test_level, "status": "error", "error": f"exit_code={result.returncode}: {result.stderr[:200]}", "findings": [], "elapsed_seconds": round(elapsed, 1)}

        findings = _parse_nuclei_output(output_path)

        # Resumen por severidad
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        return {
            "level": test_level,
            "status": "ok",
            "elapsed_seconds": round(elapsed, 1),
            "total_findings": len(findings),
            "severity_counts": sev_counts,
            "findings": findings[:200],  # limitar para no saturar JSON
            "command": " ".join(cmd[:10]) + " ...",
        }

    except subprocess.TimeoutExpired:
        return {"level": test_level, "status": "timeout", "error": f"timeout {LEVEL_TIMEOUT.get(test_level, 180)}s", "findings": []}
    except Exception as e:
        log.warning("Error ejecutando nuclei: %s", e)
        return {"level": test_level, "status": "error", "error": str(e), "findings": []}
    finally:
        try:
            output_path.unlink(missing_ok=True)
        except Exception:
            pass


def run_for_level(domain: str, test_level: int) -> dict[str, Any]:
    """Punto de entrada principal llamado desde asm_scan."""
    return run_nuclei(domain, test_level)