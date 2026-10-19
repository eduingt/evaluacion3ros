# strix_integration.py — Integración tolerance de Strix (usestrix/strix), agente IA de pentesting.
# https://github.com/usestrix/strix — CLI Python>=3.12, requerimiento Docker corriendo + LLM API key
# (STRIX_LLM + LLM_API_KEY). NO existe modo pasivo: es una herramienta activa.
#
# Por nivel de test (patrón heredable de KUMO/Prism/Claude-OSINT):
#   pasivo (1)      -> no corre (no aplica por diseño)  -> {"status": "skipped", ...}
#   semi-activo (2) -> strix --scan-mode quick
#   activo (3)      -> strix --scan-mode standard
#   invasivo (4)    -> strix --scan-mode deep
#
# Si no hay binario strix / Docker / LLM API key -> SKIPPED tolerante (no rompe asm_scan).
# Salida: dict con resumen, modo, hallazgos (vulnerabilities.json) y resumen ejecutivo (run.json).

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import llm_guardrails

STRIX_MODES = {1: None, 2: "quick", 3: "standard", 4: "deep"}
STRIX_RUN_DIR = Path("strix_runs")


def _check_environment() -> list[str]:
    """Devuelve lista de requisitos faltantes (dos largos)."""
    missing: list[str] = []
    if shutil.which("strix") is None:
        missing.append("binario strix no encontrado (pipx install strix-agent, requiere Python>=3.12)")
    if not os.environ.get("STRIX_LLM"):
        missing.append("variable STRIX_LLM (modelo LiteLLM, ej openai/gpt-5.4)")
    if not os.environ.get("LLM_API_KEY"):
        missing.append("variable LLM_API_KEY (API key del proveedor LLM)")
    if shutil.which("docker") is None:
        missing.append("docker no disponible")
    return missing


def _runs_base(workdir: str | None = None) -> Path:
    base = Path(workdir) if workdir else Path.cwd()
    return base / STRIX_RUN_DIR


def _latest_run_dir(workdir: str | None = None) -> Path | None:
    """Directorio de run mas reciente.

    Strix nombra los runs ``strix_runs/<run-name>`` (no necesariamente ``run-*``);
    la deteccion real es cualquier subcarpeta con ``run.json``, ordenada por el
    mtime de ese archivo (Strix lo reescribe en cada cambio de estado)."""
    base = _runs_base(workdir)
    if not base.is_dir():
        return None
    candidates = [c for c in base.iterdir() if (c / "run.json").is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda c: (c / "run.json").stat().st_mtime)


def _count_sarif_results(run_dir: Path) -> int:
    """Cuenta resultados en ``findings.sarif`` (SARIF 2.1.0) si Strix lo genero."""
    path = run_dir / "findings.sarif"
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    return sum(len(r.get("results") or []) for r in (data.get("runs") or []) if isinstance(r, dict))


def _severity_breakdown(findings: list[dict[str, Any]]) -> tuple[dict[str, int], float]:
    by_sev: dict[str, int] = {}
    cvss_max = 0.0
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        try:
            cvss = float(f.get("cvss") or 0)
        except (TypeError, ValueError):
            cvss = 0.0
        cvss_max = max(cvss_max, cvss)
    return by_sev, cvss_max


def _parse_vulnerabilities(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "vulnerabilities.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [r for r in data if isinstance(r, dict)]


def _parse_run_record(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "run.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _sev_rank(sev: str) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 1, "informational": 1}
    return order.get((sev or "").lower(), 0)


def summarize_strix(strix: dict[str, Any]) -> dict[str, Any]:
    """Reduce el dict strix del provider a un resumen para vistas compactas."""
    if not isinstance(strix, dict) or strix.get("status") != "ok":
        return {"status": strix.get("status", "missing")}
    findings = strix.get("findings") or []
    by_sev, cvss_max = _severity_breakdown(findings)
    return {
        "status": "ok",
        "count": len(findings),
        "by_severity": by_sev,
        "cvss_max": cvss_max,
        "top_cve": [f.get("cve") for f in findings[:5] if f.get("cve")],
        "top_cwe": [f.get("cwe") for f in findings[:5] if f.get("cwe")],
        "llm_cost_usd": strix.get("cost_usd") or llm_guardrails.cost_usd(strix),
    }


def run_strix(domain: str, test_level: int = 3, workdir: str | None = None) -> dict[str, Any]:
    """Ejecuta strix (si está disponible) para un dominio según el nivel de test."""
    base = dict(domain=domain, test_level=test_level, source="strix (usestrix/strix) AI pentest")

    mode = STRIX_MODES.get(test_level)
    if mode is None:
        return {**base, "status": "skipped", "reason": "strix no aplica en nivel pasivo (requiere interaccion activa)"}

    missing = _check_environment()
    if missing:
        return {**base, "status": "skipped", "missing": missing, "mode": mode,
                "reason": "strix no ejecutable en este entorno: " + " | ".join(missing)}

    budget = llm_guardrails.budget_usd()  # LLM10: tope de consumo por escaneo
    run_dir_before = _latest_run_dir(workdir)
    cmd = ["strix", "-n", "--target", f"https://{domain}", "--scan-mode", mode,
           "--max-budget", str(budget)]
    env = dict(os.environ)
    env.setdefault("STRIX_TELEMETRY", "0")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60 * 45,
                              cwd=workdir, env=env)
    except subprocess.TimeoutExpired:
        return {**base, "status": "error", "mode": mode, "error": "strix excedio el timeout de 45 min"}
    except OSError as exc:
        return {**base, "status": "error", "mode": mode, "error": f"no se pudo lanzar strix: {exc}"}

    run_dir = _latest_run_dir(workdir)
    if run_dir is not None and run_dir != run_dir_before:
        findings = _parse_vulnerabilities(run_dir)
        run_record = _parse_run_record(run_dir)
        by_sev, cvss_max = _severity_breakdown(findings)
        result = {
            **base,
            "status": "ok",
            "mode": mode,
            "exit_code": proc.returncode,
            # Strix: 0 = limpio, 1 = error fatal, 2 = vulnerabilidades encontradas.
            "findings_found": bool(findings) or proc.returncode == 2,
            "run_status": run_record.get("status"),
            "started_at": run_record.get("start_time"),
            "ended_at": run_record.get("end_time"),
            "targets": [t.get("original") for t in (run_record.get("targets_info") or [])
                        if isinstance(t, dict) and t.get("original")],
            "instruction": run_record.get("user_instruction") or run_record.get("instruction"),
            "findings": findings,
            "findings_count": len(findings),
            "by_severity": by_sev,
            "cvss_max": cvss_max,
            "cost_usd": llm_guardrails.cost_usd({"run_record": run_record}),
            "sarif_results": _count_sarif_results(run_dir),
            "run_record": run_record,
            "run_dir": str(run_dir),
            "stdout_truncated": llm_guardrails.redact((proc.stdout or "")[-1500:]),
            "stderr_truncated": llm_guardrails.redact((proc.stderr or "")[-1000:]),
        }
        result["guardrails"] = llm_guardrails.assess(result)
        return result

    return {**base, "status": "error", "mode": mode, "exit_code": proc.returncode,
            "error": llm_guardrails.redact("strix termino sin generar run_dir (revisa stdout)"),
            "stdout_truncated": llm_guardrails.redact((proc.stdout or "")[-1500:]),
            "stderr_truncated": llm_guardrails.redact((proc.stderr or "")[-1000:])}


def _top_findings(strix: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    findings = strix.get("findings") or []
    return sorted(findings, key=lambda f: (_sev_rank(f.get("severity")), float(f.get("cvss") or 0)), reverse=True)[:limit]


if __name__ == "__main__":
    dom = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    lvl = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    result = run_strix(dom, lvl)
    print(json.dumps(result, ensure_ascii=False, indent=1)[:2000])