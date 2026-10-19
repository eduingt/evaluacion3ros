#!/usr/bin/env python3
"""
Severidades canonicas del proyecto, alineadas a hve-core
security-reviewer-formats/severity-definitions.md (MIT, microsoft/hve-core).

CRITICAL: explotacion inmediata lleva a compromiso total o exfiltracion.
HIGH: requiere minimos prerrequisitos e impacto significativo.
MEDIUM: requiere condiciones especificas pero degrada la seguridad.
LOW: explotacion dificil o impacto limitado.
"""

from __future__ import annotations

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_DEFINITIONS: dict[str, str] = {
    "CRITICAL": "Explotacion inmediata lleva a compromiso total o exfiltracion de datos.",
    "HIGH": "Explotacion con minimos prerrequisitos e impacto significativo.",
    "MEDIUM": "Requiere condiciones especificas pero degrada la seguridad.",
    "LOW": "Explotacion dificil o impacto limitado.",
    "INFO": "Informativo, sin impacto directo.",
}

SARIF_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

ES_TO_EN = {
    "critica": "critical",
    "alta": "high",
    "media": "medium",
    "baja": "low",
    "info": "info",
}


def normalize(sev: str) -> str:
    s = (sev or "info").strip().lower()
    s = ES_TO_EN.get(s, s)
    return s if s in SARIF_LEVEL_MAP else "info"


def sarif_level(sev: str) -> str:
    return SARIF_LEVEL_MAP[normalize(sev)]


def rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(normalize(sev).upper())
    except ValueError:
        return len(SEVERITY_ORDER) - 1
