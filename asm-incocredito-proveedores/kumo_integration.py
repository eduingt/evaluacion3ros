# kumo_integration.py — Integración selectiva del framework "KUMO Domain-Recon-Tool"
# (https://github.com/karim852/KUMO-Domain-Recon-Tool, MIT) para enriquecer el escaneo ASM.
# Solo se ejecutan los módulos de valor incremental (los que no existen en el pipeline
# propio: DNS/SSL/headers/ports/subdomains/WAF/cloud/intdb/api se mantienen en asm_scan).
#
# Uso desde asm_scan._scan_provider:
#   import kumo_integration
#   kumo_data = kumo_integration.run_for_level(domain, test_level)
#
# NIVELES:
#   pasivo (1)     -> wayback · breachintel · email_harvest     (OSINT, no tocan el host)
#   semi-activo(2) -> + robots · favicon                        (GETs livianos al dominio)
#   activo/invasivo(3/4) -> + js_secrets · content_intel · api_fuzzer · nuclei (sondas HTTP)

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

import kumo_engine

log = logging.getLogger("kumo_integration")

# Módulos (claves de kumo_engine.ALL_MODULES) por nivel mínimo de prueba.
LEVEL_MODULES: dict[int, list[str]] = {
    1: ["wayback", "breachintel", "email_harvest"],
    2: ["wayback", "breachintel", "email_harvest", "robots", "favicon"],
    3: ["wayback", "breachintel", "email_harvest", "robots", "favicon",
        "js_secrets", "content_intel", "api_fuzzer", "nuclei"],
}

# Timeout global por módulo (segundos). Los más pesados son wayback y nuclei.
MODULE_TIMEOUT: dict[str, float] = {
    "wayback": 25.0,
    "breachintel": 20.0,
    "email_harvest": 20.0,
    "robots": 12.0,
    "favicon": 12.0,
    "js_secrets": 20.0,
    "content_intel": 20.0,
    "api_fuzzer": 20.0,
    "nuclei": 120.0,
}

DEFAULT_TIMEOUT = 30.0


def _run_one(module_key: str, domain: str) -> dict:
    entry = kumo_engine.ALL_MODULES.get(module_key)
    if not entry:
        return {"module": module_key, "error": "modulo desconocido"}
    _desc, func = entry
    try:
        result = func(domain)
        if not isinstance(result, dict):
            result = {"result": result}
        result.setdefault("module", module_key)
        result.setdefault("source", f"KUMO {module_key}")
        return result
    except Exception as exc:  # noqa: BLE001 - tolerante: el pipeline no debe caer por un módulo
        return {"module": module_key, "error": str(exc)}


def run_for_level(domain: str, test_level: int) -> dict:
    """Ejecuta los módulos KUMO del nivel dado en paralelo con hard timeout total."""
    modules = LEVEL_MODULES.get(test_level)
    if modules is None:
        modules = LEVEL_MODULES[min(max(1, test_level), 3)]
    out: dict = {"domain": domain, "level": test_level}
    # Paralelo con shutdown no bloqueante: no esperar hilos colgados (wayback/hunter lento)
    ex = ThreadPoolExecutor(max_workers=len(modules))
    try:
        futs = {ex.submit(_run_one, k, domain): k for k in modules}
        for fut, k in list(futs.items()):
            try:
                out[k] = fut.result(timeout=MODULE_TIMEOUT.get(k, DEFAULT_TIMEOUT) + 5)
            except FutureTimeout:
                out[k] = {"module": k, "error": f"timeout {MODULE_TIMEOUT.get(k, DEFAULT_TIMEOUT):.0f}s (outer)"}
                try:
                    fut.cancel()
                except Exception:
                    pass
            except Exception as exc:
                out[k] = {"module": k, "error": str(exc)}
    finally:
        # No bloquear pipeline por hilos colgados (web.archive.org / hunter.io lentos)
        try:
            ex.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            ex.shutdown(wait=False)
    return out