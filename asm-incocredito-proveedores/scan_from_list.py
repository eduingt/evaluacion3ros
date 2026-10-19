#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modulo de escaneo por lista TXT de dominios.

Lee un archivo de texto con un dominio por linea (ignora lineas vacias,
comentarios con # o ;), genera el providers.json, ejecuta asm_scan.py y
genera todos los informes (SOCRadar, Bancolombia, Cibest, Scor3Bank,
Beta1, B2, B3, PA, Ppasivo) en la carpeta de salida indicada.

Ejemplos:
    python scan_from_list.py --list dominios.txt
    python scan_from_list.py --list dominios.txt --out salida --no-subdomains
    python scan_from_list.py --list dominios.txt --reports socradar,ppasivo
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable

DEFAULT_REPORTS = [
    "socradar",
    "bancolombia",
    "cibest",
    "scor3bank",
    "beta1",
    "b2",
    "b3",
    "pa",
    "ppasivo",
]

REPORT_CMD = {
    "socradar": (
        "generate_socradar_style_report.py",
        ["--asm", "{json}", "--out", "{html}", "--title", "TPRA - {domain}", "--subtitle", "ASM - lista de dominios"],
    ),
    "bancolombia": (
        "generate_bancolombia_report.py",
        ["--asm", "{json}", "--out", "{html}"],
    ),
    "cibest": (
        "generate_cibest_report.py",
        ["--asm", "{json}", "--out", "{html}"],
    ),
    "scor3bank": (
        "generate_scor3bank_report.py",
        ["--asm", "{json}", "--out", "{html}"],
    ),
    "beta1": (
        "generate_beta1_report.py",
        ["--asm", "{json}", "--out", "{html}", "--analista", "Equipo de Ciberseguridad", "--org", "Informe"],
    ),
    "b2": (
        "generate_b2_scorecard_report.py",
        ["--asm", "{json}", "--out", "{html}", "--analista", "Equipo de Ciberseguridad", "--org", "Informe"],
    ),
    "b5": (
        "generate_b5_unified_report.py",
        ["--asm", "{json}", "--out", "{html}", "--analista", "Equipo de Ciberseguridad", "--org", "Informe"],
    ),
    "pa": (
        "generate_asm_passive_active_report.py",
        ["--asm", "{json}", "--out", "{html}"],
    ),
    "ppasivo": (
        "generate_ppasivo_report.py",
        ["--input", "{json}", "--output", "{html}", "--org", "Informe"],
    ),
}

REPORT_FILES = {
    "socradar": "informe_socradar.html",
    "bancolombia": "informe_bancolombia.html",
    "cibest": "informe_grupocibest.html",
    "scor3bank": "informe_scor3bank.html",
    "beta1": "informe_beta1.html",
    "b2": "informe_scorecard_b2.html",
    "b5": "informe_unificado_b5.html",
    "pa": "informe_pasivo_activo.html",
    "ppasivo": "informe_ppasivo.html",
}


def read_domains_from_txt(path: Path) -> list[str]:
    """Lee dominios del TXT. Una linea por dominio; ignora blancos y comentarios."""
    domains: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("#", ";", "//")):
            continue
        domain = line.lower().rstrip(".").strip()
        if re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", domain) and len(domain) <= 253:
            domains.append(domain)
    return domains


def build_providers(domains: list[str]) -> list[dict[str, str]]:
    """Genera la estructura providers.json a partir de la lista de dominios."""
    seen: set[str] = set()
    providers: list[dict[str, str]] = []
    for dom in domains:
        if dom in seen:
            continue
        seen.add(dom)
        safe = re.sub(r"[^\w.-]+", "_", dom).strip("._-")
        providers.append(
            {
                "id": f"{safe}",
                "name": dom.replace("www.", "").title(),
                "domain": dom,
            }
        )
    return providers


def run(cmd: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=1800)


def main() -> int:
    ap = argparse.ArgumentParser(description="Escaneo ASM por lista TXT de dominios.")
    ap.add_argument("--list", type=Path, required=True, help="Archivo TXT con un dominio por linea")
    ap.add_argument("--out", type=Path, default=ROOT / "salida_lista", help="Carpeta de salida")
    ap.add_argument("--reports", default=",".join(DEFAULT_REPORTS), help="Informes a generar (coma). Default: todos")
    ap.add_argument("--no-subdomains", action="store_true", help="Omitir enumeracion DNS de subdominios")
    ap.add_argument("--no-public-paths", action="store_true", help="Omitir sondas HEAD a rutas publicas")
    args = ap.parse_args()

    if not args.list.is_file():
        print(f"ERROR: no se encuentra la lista {args.list}")
        return 1

    domains = read_domains_from_txt(args.list)
    if not domains:
        print("ERROR: la lista no contiene dominios validos.")
        return 1

    out_dir = args.out.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    providers = build_providers(domains)

    pfile = out_dir / "providers.json"
    pfile.write_text(json.dumps(providers, indent=2, ensure_ascii=False), encoding="utf-8")

    out_json = out_dir / "asm_report.json"
    out_html = out_dir / "asm_report.html"
    out_dash = out_dir / "asm_dashboard.html"

    print(f"[scan_from_list] Dominios leidos: {len(domains)}")
    for d in domains:
        print(f"  - {d}")

    cmd_asm = [PY, str(ROOT / "asm_scan.py"), "--providers", str(pfile), "--out-json", str(out_json), "--out-html", str(out_html), "--out-dashboard", str(out_dash)]
    if args.no_subdomains:
        cmd_asm.append("--no-subdomains")
    if args.no_public_paths:
        cmd_asm.append("--no-public-paths")

    print("[scan_from_list] Ejecutando asm_scan.py ...")
    r = run(cmd_asm)
    if r.stdout:
        print(r.stdout.rstrip()[-4000:])
    if r.stderr:
        print(r.stderr.rstrip()[-2000:], file=sys.stderr)
    if r.returncode != 0:
        print("ERROR: asm_scan.py fallo.", file=sys.stderr)
        return r.returncode

    if not out_json.is_file():
        print("ERROR: no se genero asm_report.json", file=sys.stderr)
        return 1

    selected = [s.strip().lower() for s in args.reports.split(",") if s.strip().lower() in REPORT_CMD]
    for name in selected:
        script, tmpl = REPORT_CMD[name]
        html_path = out_dir / REPORT_FILES[name]
        cmd = [PY, str(ROOT / script)]
        for a in tmpl:
            cmd.append(a.replace("{json}", str(out_json)).replace("{html}", str(html_path)).replace("{domain}", domains[0]))
        print(f"[scan_from_list] Generando informe: {name}")
        r = run(cmd)
        if r.returncode == 0:
            print(f"  OK -> {html_path}")
        else:
            print(f"  ERROR ({name}): {(r.stderr or r.stdout or '')[-500:]}")
            continue

    print("[scan_from_list] Finalizado.")
    print(f"  JSON: {out_json}")
    print(f"  HTML: {out_html}")
    print(f"  Dashboard: {out_dash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
