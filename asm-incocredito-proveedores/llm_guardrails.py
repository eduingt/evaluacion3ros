#!/usr/bin/env python3
"""
Guardarrailes minimos para el agente IA Strix, mapeados a OWASP LLM Top 10 2025.

- LLM10 (Unbounded Consumption): presupuesto USD por escaneo via STRIX_BUDGET_USD.
- LLM06 (Excessive Agency): el modo del agente solo depende del nivel de test
  (pasivo=sin ejecucion, semi=quick, activo=standard, invasivo=deep).
- LLM02 (Sensitive Information Disclosure): redaccion de secretos en los
  stdout/stderr/errores que terminan en asm_report.json.

Referencia: skill hve-core owasp-llm (OWASP Top 10 for LLM Applications 2025).
"""

from __future__ import annotations

import os
import re
from typing import Any

DEFAULT_BUDGET_USD = 5.0
ALLOWED_MODES: dict[int, str | None] = {1: None, 2: "quick", 3: "standard", 4: "deep"}

_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{8,}"),
    re.compile(r"(?i)(api[_-]?key|llm[_-]?api[_-]?key)\s*[:=]\s*['\"]?[^'\"\s,}]{4,}['\"]?"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
]


def budget_usd() -> float:
    try:
        return max(0.0, float(os.environ.get("STRIX_BUDGET_USD", DEFAULT_BUDGET_USD)))
    except (TypeError, ValueError):
        return DEFAULT_BUDGET_USD


def redact(text: str | None) -> str:
    """Redacta secretos con pinta de API key/token. Nunca falla."""
    if not text:
        return ""
    out = str(text)
    key = os.environ.get("LLM_API_KEY", "")
    if key and len(key) >= 4:
        out = out.replace(key, "[REDACTED]")
    for pat in _SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def cost_usd(strix: dict[str, Any]) -> float:
    """Costo LLM del run. Strix persiste ``run.json`` -> ``llm_usage.cost``
    (``total_cost_usd`` se mantiene como fallback tolerante)."""
    try:
        if strix.get("cost_usd") is not None:
            return float(strix.get("cost_usd") or 0)
        usage = (strix.get("run_record") or {}).get("llm_usage") or {}
        return float(usage.get("cost", usage.get("total_cost_usd", 0)) or 0)
    except (TypeError, ValueError):
        return 0.0


def assess(strix: dict[str, Any]) -> dict[str, Any]:
    """Veredicto de guardarrailes sobre un resultado de run_strix. Solo lectura."""
    if not isinstance(strix, dict):
        return {"over_budget": False, "cost_usd": 0.0, "budget_usd": budget_usd(), "mode_allowed": False}
    budget = budget_usd()
    cost = cost_usd(strix)
    expected = ALLOWED_MODES.get(strix.get("test_level"), None)
    mode = strix.get("mode")
    return {
        "over_budget": cost > budget,
        "cost_usd": cost,
        "budget_usd": budget,
        "mode_allowed": (mode == expected) if expected is not None else (mode is None),
        "llm10": "Unbounded Consumption",
        "llm06": "Excessive Agency",
        "llm02": "Sensitive Information Disclosure",
    }
