#!/usr/bin/env python3
"""Harness Atheris para los parsers puros de generate_dast_config.

Objetivo: _get_targets / _get_context_paths / _get_cve_context consumen
asm_report.json (entrada no confiable si el informe viene de terceros).
Sin atheris instalado, ejecuta los seeds de fuzz/corpus/ directamente
(modo smoke local). En CI, atheris hace fuzzing real con esos seeds.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generate_dast_config import (  # noqa: E402
    _get_context_paths,
    _get_cve_context,
    _get_targets,
)

try:
    import atheris  # noqa: F401
except ImportError:
    atheris = None


def TestOneInput(data: bytes) -> None:
    try:
        obj = json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        return
    if not isinstance(obj, dict):
        return
    targets = _get_targets(obj)
    for t in targets:
        if isinstance(t, dict):
            _get_context_paths(obj, t.get("domain", ""))
    providers = obj.get("providers")
    if isinstance(providers, list):
        for p in providers:
            if not isinstance(p, dict):
                continue
            cves = p.get("cve_findings")
            if isinstance(cves, list):
                for c in cves:
                    if isinstance(c, dict):
                        _get_cve_context(c)


def main() -> None:
    import atheris as atheris_mod

    atheris_mod.Setup(sys.argv, TestOneInput)
    atheris_mod.Fuzz()


if __name__ == "__main__":
    if atheris is None:
        corpus = Path(__file__).resolve().parent / "corpus"
        seeds = sorted(corpus.glob("*.json"))
        if not seeds:
            print("sin seeds en fuzz/corpus/")
            raise SystemExit(1)
        for s in seeds:
            TestOneInput(s.read_bytes())
            print(f"seed OK: {s.name}")
    else:
        main()
