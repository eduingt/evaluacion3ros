#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Panel web local: dominio -> asm_scan + informe HTML -> PDF.
Cada escaneo se guarda en dashboard_workspace/history/<scan_id>/ (historial descargable).

  pip install -r requirements-dashboard.txt
  playwright install chromium
  python dashboard_server.py

Abrir http://127.0.0.1:8765
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse
import log_utils

import aiosqlite

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

WORKDIR = Path(__file__).resolve().parent
LAST = WORKDIR / "dashboard_workspace" / "last"
HISTORY = WORKDIR / "dashboard_workspace" / "history"
INDEX_FILE = HISTORY / "index.json"
STATIC_DASH = WORKDIR / "static" / "dashboard.html"
META_FILE = LAST / "meta.json"

MAX_HISTORY_ITEMS = 80
SCAN_ID_RE = re.compile(r"^[0-9]{8}_[0-9]{6}_[A-Za-z0-9_.-]+$")

DB_PATH = WORKDIR / "dashboard_workspace" / "scan_history.db"

SCAN_JOBS: dict[str, dict] = {}


async def init_db() -> None:
    """Inicializa la base de datos SQLite para historial de escaneos."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                score_general INTEGER NOT NULL,
                domain_score REAL NOT NULL,
                overall_score REAL NOT NULL,
                scan_type TEXT NOT NULL,
                asm_json_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                subdomain_count INTEGER NOT NULL,
                ip_count INTEGER NOT NULL,
                open_ports INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_domain_date ON scan_history(domain, created_at DESC)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_assets_domain ON scan_assets(domain, created_at DESC)")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_factors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                factor_key TEXT NOT NULL,
                factor_label TEXT NOT NULL,
                score INTEGER NOT NULL,
                incidences INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_factors_domain ON scan_factors(domain, created_at DESC)")
        await db.commit()


async def save_scan_history(
    domain: str,
    score_general: int,
    domain_score: float,
    overall_score: float,
    scan_type: str,
    asm_json_path: str
) -> None:
    """Guarda un registro de escaneo en la base de datos."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO scan_history (domain, score_general, domain_score, overall_score, scan_type, asm_json_path)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (domain, score_general, domain_score, overall_score, scan_type, asm_json_path))
        await db.commit()


async def save_factor_history(
    scan_id: str,
    domain: str,
    scores: dict,
    incidences: dict | None = None,
) -> None:
    """Guarda los 10 factores precia de un escaneo (solo datos reales)."""
    incidences = incidences or {}
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executemany("""
            INSERT INTO scan_factors (scan_id, domain, factor_key, factor_label, score, incidences)
            VALUES (?, ?, ?, ?, ?, ?)
        """, [(scan_id, domain, k, k, int(v), int(incidences.get(k, 0))) for k, v in (scores or {}).items()])
        await db.commit()


async def get_scan_history(domain: str, days: int = 30) -> list[dict]:
    """Obtiene el historial de escaneos para un dominio en los últimos N días."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT created_at as fecha, score_general as score, domain_score, overall_score
            FROM scan_history
            WHERE domain = ? AND created_at >= datetime('now', ? || ' days')
            ORDER BY created_at ASC
        """, (domain, f"-{days}"))
        rows = await cursor.fetchall()
        return [{"fecha": r["fecha"], "score": r["score"],
                 "domain_score": r["domain_score"], "overall_score": r["overall_score"]} for r in rows]


def run_job_bg(job_id: str, domains: list[str], test_type: str) -> None:
    """Corre el pipeline de escaneo en un thread de background y guarda el resultado en SCAN_JOBS."""

    def _runner() -> None:
        job = SCAN_JOBS[job_id]
        try:
            result = asyncio.run(run_scan_batch_pipeline(domains, test_type))
            job["result"] = result
            job["status"] = "done"
        except asyncio.CancelledError:
            job["status"] = "cancelled"
            job["error"] = "cancelado"
        except Exception as e:  # noqa: BLE001
            job["status"] = "error"
            job["error"] = str(e)
        finally:
            job["finished_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    t = threading.Thread(target=_runner, daemon=True, name=f"scan-{job_id}")
    t.start()


def normalize_domain(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    if "://" in s:
        u = urlparse(s)
        s = u.netloc or u.path.split("/")[0]
    s = s.split("/")[0].strip().lower().rstrip(".")
    return s


def valid_domain(d: str) -> bool:
    if not d or len(d) > 253:
        return False
    if ".." in d or d.startswith(".") or d.endswith("."):
        return False
    return bool(re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", d, re.I))


def safe_scan_id_part(domain: str) -> str:
    s = re.sub(r"[^\w.-]+", "_", domain).strip("._-")
    return (s[:60] if s else "host") or "host"


def allocate_scan_dir(domain: str) -> tuple[str, Path]:
    HISTORY.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = f"{ts}_{safe_scan_id_part(domain)}"
    scan_id = base
    n = 2
    out = HISTORY / scan_id
    while out.exists():
        scan_id = f"{base}_{n}"
        out = HISTORY / scan_id
        n += 1
    out.mkdir(parents=True, exist_ok=False)
    return scan_id, out


def _history_dir(scan_id: str) -> Path:
    if not SCAN_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    d = (HISTORY / scan_id).resolve()
    try:
        d.relative_to(HISTORY.resolve())
    except ValueError:
        raise HTTPException(400, "Invalid path") from None
    return d


def write_index(items: list[dict[str, str]]) -> None:
    HISTORY.mkdir(parents=True, exist_ok=True)
    INDEX_FILE.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")


def list_history_from_disk() -> list[dict[str, str]]:
    """Historial desde carpetas con meta.json (mas nuevo primero). Siempre refleja el disco."""
    if not HISTORY.is_dir():
        return []
    rows: list[tuple[float, dict[str, str]]] = []
    for p in HISTORY.iterdir():
        if not p.is_dir():
            continue
        sid = p.name
        if not SCAN_ID_RE.match(sid):
            continue
        meta = p / "meta.json"
        if not meta.is_file():
            continue
        try:
            m = json.loads(meta.read_text(encoding="utf-8"))
            created = str(m.get("created_utc", ""))
            dom = str(m.get("domain", ""))
            mtime = p.stat().st_mtime
            rows.append((mtime, {"scan_id": sid, "domain": dom, "created_utc": created}))
        except Exception:
            continue
    rows.sort(key=lambda x: -x[0])
    return [r[1] for r in rows]


def sync_history_index() -> list[dict[str, str]]:
    """Alinear index.json con el disco y recortar a MAX_HISTORY_ITEMS (borra carpetas viejas)."""
    items = list_history_from_disk()
    while len(items) > MAX_HISTORY_ITEMS:
        old = items.pop()
        oid = old.get("scan_id")
        if oid and SCAN_ID_RE.match(oid):
            shutil.rmtree(HISTORY / oid, ignore_errors=True)
    write_index(items)
    return items


def rebuild_index_from_disk() -> None:
    """Mantener compatibilidad con arranque: siempre sincronizar desde disco."""
    sync_history_index()


def mirror_to_last(scan_dir: Path, domain: str, scan_id: str) -> None:
    if LAST.exists():
        for old in list(LAST.iterdir()):
            if old.is_file():
                old.unlink()
            elif old.is_dir():
                shutil.rmtree(old, ignore_errors=True)
    else:
        LAST.mkdir(parents=True, exist_ok=True)
    for f in scan_dir.iterdir():
        if f.is_file():
            shutil.copy2(f, LAST / f.name)
    META_FILE.write_text(
        json.dumps({"domain": domain, "scan_id": scan_id}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


async def pdf_from_html(html_path: Path, pdf_path: Path, log: logging.Logger) -> None:
    html_path = html_path.resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    uri = html_path.as_uri()

    loop = asyncio.get_event_loop()
    candidates: list[str | None] = [
        shutil.which("msedge"),
        shutil.which("microsoft-edge"),
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ]
    for edge in candidates:
        if not edge or not Path(edge).is_file():
            continue
        try:
            r = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    [
                        edge,
                        "--headless=new",
                        "--disable-gpu",
                        "--no-sandbox",
                        "--no-pdf-header-footer",
                        f"--print-to-pdf={pdf_path}",
                        uri,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    cwd=str(WORKDIR),
                ),
            )
            if r.returncode == 0 and pdf_path.is_file() and pdf_path.stat().st_size > 100:
                log.info("PDF OK (Edge): %s", edge)
                return
            err = (r.stderr or "")[:200]
            log.warning("Edge rc=%d err=%s", r.returncode, err)
        except Exception as e:
            log.warning("Edge exception: %s", e)

    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(uri, wait_until="load", timeout=120_000)
            await page.pdf(
                path=str(pdf_path),
                format="A4",
                print_background=True,
                margin={"top": "12mm", "bottom": "12mm", "left": "10mm", "right": "10mm"},
            )
            await browser.close()
        if pdf_path.is_file() and pdf_path.stat().st_size > 100:
            log.info("PDF OK (Playwright Chromium async).")
            return
        log.error("Playwright: PDF vacio o invalido.")
    except ImportError:
        log.error("Instala: pip install playwright && playwright install chromium")
    except Exception as e:
        log.error("Playwright: %s", e)

    raise RuntimeError(
        "No PDF. Install Playwright (playwright install chromium) or use Microsoft Edge."
    )


async def run_scan_pipeline(domain: str, test_type: str = "activo") -> dict[str, str]:
    """Escanea un unico dominio (compatibilidad con /api/scan)."""
    return await run_scan_batch_pipeline([domain], test_type)


async def run_scan_batch_pipeline(domains: list[str], test_type: str = "activo") -> dict[str, str]:
    """Escanea una lista de dominios (desde TXT o formulario)."""
    label = domains[0] if len(domains) == 1 else f"lista_{len(domains)}_dominios"
    scan_id, out_dir = allocate_scan_dir(label)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    log = log_utils.scan_logger(scan_id, out_dir)
    log.info("=== Pipeline start: domains=%d scan_id=%s ===", len(domains), scan_id)

    prov = [
        {
            "id": f"scan-{i + 1}",
            "name": d.replace("www.", "").title(),
            "domain": d,
        }
        for i, d in enumerate(domains)
    ]
    pfile = out_dir / "providers.json"
    pfile.write_text(json.dumps(prov, indent=2, ensure_ascii=False), encoding="utf-8")

    out_json = out_dir / "asm_report.json"
    out_html = out_dir / "asm_report.html"
    out_dash = out_dir / "asm_dashboard.html"
    informe_html = out_dir / "informe_tpra_estilo_socradar.html"
    informe_pdf = out_dir / "informe_tpra_estilo_socradar.pdf"

    py = sys.executable
    asm_py = WORKDIR / "asm_scan.py"
    gen_py = WORKDIR / "generate_socradar_style_report.py"

    cmd_asm = [
        py,
        str(asm_py),
        "--providers",
        str(pfile),
        "--out-json",
        str(out_json),
        "--out-html",
        str(out_html),
        "--out-dashboard",
        str(out_dash),
        "--no-subdomains",
        "--no-public-paths",
        "--test-type",
        test_type,
    ]
    log.info("Running asm_scan.py ...")
    secs_per_domain = {"pasivo": 180, "semi-activo": 240, "activo": 360, "invasivo": 540}.get(test_type, 180)
    scan_secs = int(120 + secs_per_domain * len(domains))
    log.info("Scan timeout for %d domains (%s): %ss", len(domains), test_type, scan_secs)
    try:
        r1 = subprocess.run(cmd_asm, cwd=str(WORKDIR), capture_output=True, text=True, timeout=scan_secs,
                            errors="replace")
    except subprocess.TimeoutExpired as texc:
        partial = (texc.stdout or "")[-6000:] if isinstance(texc.stdout, str) else (texc.stdout or b"")[-6000:].decode("utf-8", "replace")
        partial_err = (texc.stderr or "")[-3000:] if isinstance(texc.stderr, str) else (texc.stderr or b"")[-3000:].decode("utf-8", "replace")
        shutil.rmtree(out_dir, ignore_errors=True)
        raise RuntimeError(
            f"asm_scan.py TIMEOUT after {scan_secs}s ({len(domains)} dominios). "
            f"\nSTDOUT(parcial):\n{partial}\nSTDERR(parcial):\n{partial_err}"
        ) from texc
    if r1.stdout:
        log.info("asm_scan stdout:\n%s", r1.stdout.rstrip()[-4000:])
    if r1.stderr:
        log.warning("asm_scan stderr:\n%s", r1.stderr.rstrip()[-2000:])
    if r1.returncode != 0:
        shutil.rmtree(out_dir, ignore_errors=True)
        raise RuntimeError(f"asm_scan.py failed, exit {r1.returncode}\nSTDERR: {(r1.stderr or '')[-2000:]}\nSTDOUT: {(r1.stdout or '')[-2000:]}")

    cmd_gen = [
        py,
        str(gen_py),
        "--asm",
        str(out_json),
        "--out",
        str(informe_html),
        "--title",
        f"TPRA - {label}",
        "--subtitle",
        "ASM - panel local",
    ]
    log.info("Building HTML report ...")
    r2 = subprocess.run(cmd_gen, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r2.stderr:
        log.warning("report stderr:\n%s", r2.stderr.rstrip()[-1500:])
    if r2.returncode != 0:
        shutil.rmtree(out_dir, ignore_errors=True)
        raise RuntimeError(f"generate_socradar_style_report.py failed, exit {r2.returncode}\nSTDERR: {(r2.stderr or '')[-2000:]}\nSTDOUT: {(r2.stdout or '')[-2000:]}")

    cibest_py = WORKDIR / "generate_cibest_report.py"
    cibest_html = out_dir / "informe_grupocibest.html"
    cibest_pdf = out_dir / "informe_grupocibest.pdf"
    cmd_cibest = [py, str(cibest_py), "--asm", str(out_json), "--out", str(cibest_html)]
    log.info("Building Cibest report ...")
    r3 = subprocess.run(cmd_cibest, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r3.returncode == 0:
        try:
            await pdf_from_html(cibest_html, cibest_pdf, log)
        except Exception as e:
            log.warning("Cibest PDF skipped: %s", e)
    else:
        log.warning("Cibest report skipped: %s", (r3.stderr or "")[-500:])

    bancolombia_py = WORKDIR / "generate_bancolombia_report.py"
    bancolombia_html = out_dir / "informe_bancolombia.html"
    bancolombia_pdf = out_dir / "informe_bancolombia.pdf"
    cmd_bancolombia = [py, str(bancolombia_py), "--asm", str(out_json), "--out", str(bancolombia_html)]
    log.info("Building Bancolombia report ...")
    r4 = subprocess.run(cmd_bancolombia, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r4.returncode == 0:
        try:
            await pdf_from_html(bancolombia_html, bancolombia_pdf, log)
        except Exception as e:
            log.warning("Bancolombia PDF skipped: %s", e)
    else:
        log.warning("Bancolombia report skipped: %s", (r4.stderr or "")[-500:])

    scor3bank_py = WORKDIR / "generate_scor3bank_report.py"
    scor3bank_html = out_dir / "informe_scor3bank.html"
    scor3bank_pdf = out_dir / "informe_scor3bank.pdf"
    cmd_scor3bank = [py, str(scor3bank_py), "--asm", str(out_json), "--out", str(scor3bank_html)]
    log.info("Building SCOR3BANK report ...")
    r5 = subprocess.run(cmd_scor3bank, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r5.returncode == 0:
        try:
            await pdf_from_html(scor3bank_html, scor3bank_pdf, log)
        except Exception as e:
            log.warning("SCOR3BANK PDF skipped: %s", e)
    else:
        log.warning("SCOR3BANK report skipped: %s", (r5.stderr or "")[-500:])

    log.info("P/A (Pasivo/Activo) report disabled per request - not generated.")

    beta1_py = WORKDIR / "generate_beta1_report.py"
    beta1_html = out_dir / "informe_beta1.html"
    beta1_pdf = out_dir / "informe_beta1.pdf"
    cmd_beta1 = [py, str(beta1_py), "--asm", str(out_json), "--out", str(beta1_html), "--analista", "Equipo de Ciberseguridad", "--org", "GrupoCibest"]
    log.info("Building BETA1 report ...")
    r7 = subprocess.run(cmd_beta1, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r7.returncode == 0:
        try:
            await pdf_from_html(beta1_html, beta1_pdf, log)
        except Exception as e:
            log.warning("BETA1 PDF skipped: %s", e)
    else:
        log.warning("BETA1 report skipped: %s", (r7.stderr or "")[-500:])

    b2_py = WORKDIR / "generate_b2_scorecard_report.py"
    b2_html = out_dir / "informe_scorecard_b2.html"
    b2_pdf = out_dir / "informe_scorecard_b2.pdf"
    cmd_b2 = [py, str(b2_py), "--asm", str(out_json), "--out", str(b2_html), "--analista", "Equipo de Ciberseguridad", "--org", "GrupoCibest"]
    log.info("Building B2 Scorecard report ...")
    r8 = subprocess.run(cmd_b2, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r8.returncode == 0:
        try:
            await pdf_from_html(b2_html, b2_pdf, log)
        except Exception as e:
            log.warning("B2 PDF skipped: %s", e)
    else:
        log.warning("B2 report skipped: %s", (r8.stderr or "")[-500:])

    b3_py = WORKDIR / "generate_b3_unified_report.py"
    b3_html = out_dir / "informe_unificado_b3.html"
    b3_pdf = out_dir / "informe_unificado_b3.pdf"
    cmd_b3 = [py, str(b3_py), "--asm", str(out_json), "--out", str(b3_html), "--analista", "@eduingt-ANALISTA INTELIGENCIA Y DEFENSA CIBER", "--org", "GrupoCibest"]
    log.info("Building B3 Unificado report ...")
    r9 = subprocess.run(cmd_b3, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r9.returncode == 0:
        try:
            from generate_b3_unified_report import paginate_toc
            paginate_toc(str(b3_html))
        except Exception as e:
            log.warning("B3 TOC pagination skipped: %s", e)
        try:
            await pdf_from_html(b3_html, b3_pdf, log)
        except Exception as e:
            log.warning("B3 PDF skipped: %s", e)
    else:
        log.warning("B3 report skipped: %s", (r9.stderr or "")[-500:])

    b4_py = WORKDIR / "generate_b4_unified_report.py"
    b4_html = out_dir / "informe_unificado_b4.html"
    b4_pdf = out_dir / "informe_unificado_b4.pdf"
    cmd_b4 = [py, str(b4_py), "--asm", str(out_json), "--out", str(b4_html), "--analista", "@eduingt-ANALISTA INTELIGENCIA Y DEFENSA CIBER", "--org", "GrupoCibest"]
    log.info("Building B4 Unificado report (Overall absorbe Score General) ...")
    r_b4 = subprocess.run(cmd_b4, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r_b4.returncode == 0:
        try:
            from generate_b4_unified_report import paginate_toc as paginate_toc_b4
            paginate_toc_b4(str(b4_html))
        except Exception as e:
            log.warning("B4 TOC pagination skipped: %s", e)
        try:
            await pdf_from_html(b4_html, b4_pdf, log)
        except Exception as e:
            log.warning("B4 PDF skipped: %s", e)
    else:
        log.warning("B4 report skipped: %s", (r_b4.stderr or "")[-500:])

    b5_py = WORKDIR / "generate_b5_unified_report.py"
    b5_html = out_dir / "informe_unificado_b5.html"
    b5_pdf = out_dir / "informe_unificado_b5.pdf"
    cmd_b5 = [py, str(b5_py), "--asm", str(out_json), "--out", str(b5_html), "--analista", "@eduingt-ANALISTA INTELIGENCIA Y DEFENSA CIBER", "--org", "GrupoCibest"]
    log.info("Building B5 Unificado report (base B3) ...")
    r_b5 = subprocess.run(cmd_b5, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r_b5.returncode == 0:
        try:
            from generate_b5_unified_report import paginate_toc as paginate_toc_b5
            paginate_toc_b5(str(b5_html))
        except Exception as e:
            log.warning("B5 TOC pagination skipped: %s", e)
        try:
            await pdf_from_html(b5_html, b5_pdf, log)
        except Exception as e:
            log.warning("B5 PDF skipped: %s", e)
    else:
        log.warning("B5 report skipped: %s", (r_b5.stderr or "")[-500:])

    b6_py = WORKDIR / "generate_b6_unified_report.py"
    b6_html = out_dir / "informe_unificado_b6.html"
    b6_pdf = out_dir / "informe_unificado_b6.pdf"
    cmd_b6 = [py, str(b6_py), "--asm", str(out_json), "--out", str(b6_html), "--analista", "@eduingt-ANALISTA INTELIGENCIA Y DEFENSA CIBER", "--org", "GrupoCibest"]
    log.info("Building B6 Unificado report (base B5) ...")
    r_b6 = subprocess.run(cmd_b6, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r_b6.returncode == 0:
        try:
            from generate_b6_unified_report import paginate_toc as paginate_toc_b6
            paginate_toc_b6(str(b6_html))
        except Exception as e:
            log.warning("B6 TOC pagination skipped: %s", e)
        try:
            await pdf_from_html(b6_html, b6_pdf, log)
        except Exception as e:
            log.warning("B6 PDF skipped: %s", e)
    else:
        log.warning("B6 report skipped: %s", (r_b6.stderr or "")[-500:])

    b7_py = WORKDIR / "generate_b7_unified_report.py"
    b7_html = out_dir / "informe_unificado_b7.html"
    b7_pdf = out_dir / "informe_unificado_b7.pdf"
    cmd_b7 = [py, str(b7_py), "--asm", str(out_json), "--out", str(b7_html), "--analista", "@eduingt-ANALISTA INTELIGENCIA Y DEFENSA CIBER", "--org", "GrupoCibest"]
    log.info("Building B7 Detallado SSC-style report ...")
    r_b7 = subprocess.run(cmd_b7, cwd=str(WORKDIR), capture_output=True, text=True, timeout=180)
    if r_b7.returncode == 0:
        try:
            await pdf_from_html(b7_html, b7_pdf, log)
        except Exception as e:
            log.warning("B7 PDF skipped: %s", e)
    else:
        log.warning("B7 report skipped: %s", (r_b7.stderr or "")[-500:])

    ppasivo_py = WORKDIR / "generate_ppasivo_report.py"
    ppasivo_html = out_dir / "informe_ppasivo.html"
    ppasivo_pdf = out_dir / "informe_ppasivo.pdf"
    cmd_ppasivo = [py, str(ppasivo_py), "--input", str(out_json), "--output", str(ppasivo_html)]
    log.info("Building Ppasivo report ...")
    r10 = subprocess.run(cmd_ppasivo, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r10.returncode == 0:
        try:
            await pdf_from_html(ppasivo_html, ppasivo_pdf, log)
        except Exception as e:
            log.warning("Ppasivo PDF skipped: %s", e)
    else:
        log.warning("Ppasivo report skipped: %s", (r10.stderr or "")[-500:])

    log.info("Building PDF ...")
    try:
        await pdf_from_html(informe_html, informe_pdf, log)
    except Exception:
        shutil.rmtree(out_dir, ignore_errors=True)
        raise

    meta = {"domain": label, "scan_id": scan_id, "created_utc": created}
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    sync_history_index()
    mirror_to_last(out_dir, label, scan_id)

    # Save scan history to SQLite DB (solo datos reales del escaneo)
    try:
        asm_data = json.loads(out_json.read_text(encoding="utf-8"))
        providers = asm_data.get("providers") or []
        if providers:
            p = providers[0]
            from generate_b3_unified_report import domain_score, compute_factores
            dscore = domain_score(p)
            factores = compute_factores(providers)
            score_general = int(sum(f["score"] for f in factores) / max(len(factores), 1)) if factores else 0
            from precia_scorecard import factor_scores as _pscores, overall_score as _poverall
            overall = float(_poverall(_pscores(p)))

            await save_scan_history(
                domain=p.get("domain", label),
                score_general=score_general,
                domain_score=dscore,
                overall_score=overall,
                scan_type=test_type,
                asm_json_path=str(out_json)
            )
            try:
                from precia_scorecard import factor_incidences as _pinc
                await save_factor_history(
                    scan_id=scan_id,
                    domain=p.get("domain", label),
                    scores=_pscores(p),
                    incidences=_pinc(p),
                )
            except Exception as fe:
                log.warning("Failed to save factor history: %s", fe)
            try:
                sub_cnt = len((p.get("subdomains") or []) + (p.get("crt_subdomains") or []))
                ip_cnt = len((p.get("dns") or {}).get("ipv4") or [])
                open_cnt = len([o for o in (p.get("open_ports") or []) if isinstance(o, dict) and o.get("state") == "open"])
                async with aiosqlite.connect(DB_PATH) as adb:
                    await adb.execute("INSERT INTO scan_assets (scan_id, domain, subdomain_count, ip_count, open_ports) VALUES (?,?,?,?,?)",
                                      (scan_id, p.get("domain", label), sub_cnt, ip_cnt, open_cnt))
                    await adb.commit()
            except Exception as ae:
                log.warning("Failed to save asset history: %s", ae)
    except Exception as e:
        log.warning("Failed to save scan history: %s", e)

    log.info("=== Pipeline complete ===")
    scan_log_txt = (out_dir / "scan.log").read_text(encoding="utf-8").strip() if (out_dir / "scan.log").is_file() else ""

    base = f"/api/history/{scan_id}"
    return {
        "scan_id": scan_id,
        "domain": label,
        "created_utc": created,
        "log": scan_log_txt,
        "pdf_url": f"{base}/pdf",
        "html_url": f"{base}/html",
        "pdf_grupocibest_url": f"{base}/pdf-grupocibest",
        "pdf_bancolombia_url": f"{base}/pdf-bancolombia",
        "pdf_scor3bank_url": f"{base}/pdf-scor3bank",
        "pdf_beta1_url": f"{base}/pdf-beta1",
        "pdf_b2_url": f"{base}/pdf-b2",
        "pdf_b3_url": f"{base}/pdf-b3",
        "html_b3_url": f"{base}/html-b3",
        "pdf_b4_url": f"{base}/pdf-b4",
        "html_b4_url": f"{base}/html-b4",
        "pdf_b5_url": f"{base}/pdf-b5",
        "html_b5_url": f"{base}/html-b5",
        "pdf_b6_url": f"{base}/pdf-b6",
        "html_b6_url": f"{base}/html-b6",
        "pdf_b7_url": f"{base}/pdf-b7",
        "html_b7_url": f"{base}/html-b7",
        "pdf_ppasivo_url": f"{base}/pdf-ppasivo",
        "html_ppasivo_url": f"{base}/html-ppasivo",
    }


app = FastAPI(title="ASM Dashboard", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3001", "http://localhost:3001", "http://127.0.0.1:3000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup() -> None:
    log_utils.setup()
    rebuild_index_from_disk()
    await init_db()


@app.get("/")
def index() -> HTMLResponse:
    if not STATIC_DASH.is_file():
        raise HTTPException(500, "Missing static/dashboard.html")
    try:
        html = STATIC_DASH.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        html = STATIC_DASH.read_text(encoding="utf-8", errors="replace")
    return HTMLResponse(
        content=html,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"},
    )


class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    test_type: str = Field("activo", pattern=r"^(pasivo|semi-activo|activo|invasivo)$")


@app.post("/api/scan")
async def api_scan(body: ScanRequest) -> dict:
    domain = normalize_domain(body.domain)
    if not domain:
        raise HTTPException(400, "Empty domain")
    if not valid_domain(domain):
        raise HTTPException(400, "Invalid domain")
    job_id = uuid.uuid4().hex[:12]
    SCAN_JOBS[job_id] = {
        "status": "running",
        "kind": "scan",
        "domains": [domain],
        "test_type": body.test_type,
        "result": None,
        "error": None,
        "started_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    run_job_bg(job_id, [domain], body.test_type)
    return {"job_id": job_id, "status": "running", "domain": domain, "test_type": body.test_type}


def parse_domains_txt(text: str) -> list[str]:
    """Extrae dominios validos desde un TXT. Una linea por dominio; ignora comentarios."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        dom = normalize_domain(line)
        if valid_domain(dom) and dom not in out:
            out.append(dom)
    return out


@app.post("/api/scan-batch")
async def api_scan_batch(
    file: UploadFile = File(...),
    test_type: str = Form("activo"),
) -> dict:
    if test_type not in ("pasivo", "semi-activo", "activo", "invasivo"):
        raise HTTPException(400, "test_type invalido")
    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1", errors="replace")
    domains = parse_domains_txt(text)
    if not domains:
        raise HTTPException(400, "El archivo no contiene dominios validos.")

    job_id = uuid.uuid4().hex[:12]
    SCAN_JOBS[job_id] = {
        "status": "running",
        "kind": "batch",
        "domains": domains,
        "test_type": test_type,
        "result": None,
        "error": None,
        "started_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    run_job_bg(job_id, domains, test_type)
    return {"job_id": job_id, "status": "running", "scanned": len(domains), "test_type": test_type}


@app.get("/api/scan/{job_id}")
def api_scan_status(job_id: str) -> JSONResponse:
    job = SCAN_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Job no encontrado")
    payload = {"job_id": job_id, "status": job["status"], "kind": job.get("kind"),
               "domains": job.get("domains"), "test_type": job.get("test_type"),
               "started_utc": job.get("started_utc"), "finished_utc": job.get("finished_utc")}
    if job["status"] == "done":
        payload["result"] = job["result"]
    if job["status"] == "error":
        payload["error"] = job["error"]
    return JSONResponse(payload)


@app.post("/api/history/{scan_id}/delete")
def api_delete_history(scan_id: str) -> JSONResponse:
    if not SCAN_ID_RE.match(scan_id):
        raise HTTPException(400, "scan_id invalido")
    d = HISTORY / scan_id
    if not d.is_dir():
        raise HTTPException(404, "Escaneo no encontrado")
    try:
        shutil.rmtree(d, ignore_errors=True)
        sync_history_index()
        return JSONResponse(content={"ok": True, "deleted": scan_id})
    except Exception as e:
        raise HTTPException(500, str(e)) from e


@app.get("/api/history")
def api_history() -> JSONResponse:
    items = sync_history_index()
    enriched = []
    for it in items:
        sid = it.get("scan_id", "")
        if not sid or not SCAN_ID_RE.match(sid):
            continue
        d = HISTORY / sid
        enriched.append(
            {
                **it,
                "has_pdf": (d / "informe_tpra_estilo_socradar.pdf").is_file(),
                "has_beta1_pdf": (d / "informe_beta1.pdf").is_file(),
                "has_b2_pdf": (d / "informe_scorecard_b2.pdf").is_file(),
                "has_b3_pdf": (d / "informe_unificado_b3.pdf").is_file(),
                "has_b3_html": (d / "informe_unificado_b3.html").is_file(),
                "has_b4_pdf": (d / "informe_unificado_b4.pdf").is_file(),
                "has_b4_html": (d / "informe_unificado_b4.html").is_file(),
                "has_b5_pdf": (d / "informe_unificado_b5.pdf").is_file(),
                "has_b5_html": (d / "informe_unificado_b5.html").is_file(),
                "has_b6_pdf": (d / "informe_unificado_b6.pdf").is_file(),
                "has_b6_html": (d / "informe_unificado_b6.html").is_file(),
                "has_b7_pdf": (d / "informe_unificado_b7.pdf").is_file(),
                "has_b7_html": (d / "informe_unificado_b7.html").is_file(),
                "has_ppasivo_pdf": (d / "informe_ppasivo.pdf").is_file(),
                "has_html": (d / "informe_tpra_estilo_socradar.html").is_file(),
                "pdf_url": f"/api/history/{sid}/pdf",
                "html_url": f"/api/history/{sid}/html",
            }
        )
    return JSONResponse(
        content={"items": enriched},
        headers={"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"},
    )


@app.get("/api/history/{domain}/scores")
async def api_scan_history(domain: str, days: int = 30):
    """Historial de scores para un dominio (últimos N días)."""
    try:
        history = await get_scan_history(domain, days)
        return JSONResponse(
            content={"domain": domain, "days": days, "history": history},
            headers={"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"},
        )
    except Exception as e:
        raise HTTPException(500, f"Error fetching history: {e}")


def _meta_domain() -> str:
    if not META_FILE.is_file():
        return "scan"
    try:
        return str(json.loads(META_FILE.read_text(encoding="utf-8")).get("domain", "scan"))
    except Exception:
        return "scan"


@app.get("/api/download/pdf")
def download_pdf() -> FileResponse:
    p = LAST / "informe_tpra_estilo_socradar.pdf"
    if not p.is_file():
        raise HTTPException(404, "No PDF yet. Run a scan first.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_tpra_{safe}.pdf")


@app.get("/api/download/pdf-grupocibest")
def download_pdf_grupocibest() -> FileResponse:
    p = WORKDIR / "informe_grupocibest.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF no disponible. Ejecuta: python generate_cibest_report.py")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_grupocibest_{safe}.pdf")


@app.get("/api/download/pdf-bancolombia")
def download_pdf_bancolombia() -> FileResponse:
    p = WORKDIR / "informe_bancolombia.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF no disponible. Ejecuta: python generate_bancolombia_report.py")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_bancolombia_{safe}.pdf")


@app.get("/api/download/pdf-scor3bank")
def download_pdf_scor3bank() -> FileResponse:
    p = WORKDIR / "informe_scor3bank.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF no disponible. Ejecuta: python generate_scor3bank_report.py")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_scor3bank_{safe}.pdf")


@app.get("/api/download/pdf-beta1")
def download_pdf_beta1() -> FileResponse:
    p = LAST / "informe_beta1.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF beta1 no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_beta1_{safe}.pdf")


@app.get("/api/download/pdf-b2")
def download_pdf_b2() -> FileResponse:
    p = LAST / "informe_scorecard_b2.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B2 (Scorecard) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b2_scorecard_{safe}.pdf")


@app.get("/api/download/pdf-b3")
def download_pdf_b3() -> FileResponse:
    p = LAST / "informe_unificado_b3.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B3 (Unificado) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b3_unificado_{safe}.pdf")


@app.get("/api/download/html-b3")
def download_html_b3() -> FileResponse:
    p = LAST / "informe_unificado_b3.html"
    if not p.is_file():
        raise HTTPException(404, "HTML B3 (Unificado) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_b3_unificado_{safe}.html")


@app.get("/api/download/pdf-b4")
def download_pdf_b4() -> FileResponse:
    p = LAST / "informe_unificado_b4.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B4 (Unificado) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b4_unificado_{safe}.pdf")


@app.get("/api/download/html-b4")
def download_html_b4() -> FileResponse:
    p = LAST / "informe_unificado_b4.html"
    if not p.is_file():
        raise HTTPException(404, "HTML B4 (Unificado) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_b4_unificado_{safe}.html")


@app.get("/api/download/pdf-b5")
def download_pdf_b5() -> FileResponse:
    p = LAST / "informe_unificado_b5.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B5 (Unificado) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b5_unificado_{safe}.pdf")


@app.get("/api/download/html-b5")
def download_html_b5() -> FileResponse:
    p = LAST / "informe_unificado_b5.html"
    if not p.is_file():
        raise HTTPException(404, "HTML B5 (Unificado) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_b5_unificado_{safe}.html")


@app.get("/api/download/pdf-b6")
def download_pdf_b6() -> FileResponse:
    p = LAST / "informe_unificado_b6.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B6 (Unificado) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b6_unificado_{safe}.pdf")


@app.get("/api/download/html-b6")
def download_html_b6() -> FileResponse:
    p = LAST / "informe_unificado_b6.html"
    if not p.is_file():
        raise HTTPException(404, "HTML B6 (Unificado) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_b6_unificado_{safe}.html")


@app.get("/api/download/pdf-b7")
def download_pdf_b7() -> FileResponse:
    p = LAST / "informe_unificado_b7.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B7 (Detallado SSC) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b7_detallado_{safe}.pdf")


@app.get("/api/download/html-b7")
def download_html_b7() -> FileResponse:
    p = LAST / "informe_unificado_b7.html"
    if not p.is_file():
        raise HTTPException(404, "HTML B7 (Detallado SSC) no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_b7_detallado_{safe}.html")


@app.get("/api/download/pdf-ppasivo")
def download_pdf_ppasivo() -> FileResponse:
    p = LAST / "informe_ppasivo.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF Ppasivo no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_ppasivo_{safe}.pdf")


@app.get("/api/download/html-ppasivo")
def download_html_ppasivo() -> FileResponse:
    p = LAST / "informe_ppasivo.html"
    if not p.is_file():
        raise HTTPException(404, "HTML Ppasivo no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_ppasivo_{safe}.html")


@app.get("/api/download/html")
def download_html() -> FileResponse:
    p = LAST / "informe_tpra_estilo_socradar.html"
    if not p.is_file():
        raise HTTPException(404, "No HTML report.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_tpra_{safe}.html")


@app.get("/api/history/{scan_id}/pdf")
def history_pdf(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_tpra_estilo_socradar.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF not found for this scan.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_tpra_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/pdf-grupocibest")
def history_pdf_grupocibest(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_grupocibest.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF ver.grupocibest no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_grupocibest_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/pdf-bancolombia")
def history_pdf_bancolombia(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_bancolombia.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF ver.bancolombia no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_bancolombia_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/pdf-scor3bank")
def history_pdf_scor3bank(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_scor3bank.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF ver.scor3bank no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_scor3bank_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/pdf-beta1")
def history_pdf_beta1(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_beta1.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF beta1 no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_beta1_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/pdf-b2")
def history_pdf_b2(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_scorecard_b2.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B2 (Scorecard) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b2_scorecard_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/pdf-b3")
def history_pdf_b3(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_unificado_b3.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B3 (Unificado) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b3_unificado_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/html-b3")
def history_html_b3(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_unificado_b3.html"
    if not p.is_file():
        raise HTTPException(404, "HTML B3 (Unificado) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_b3_unificado_{dom}_{scan_id}.html")


@app.get("/api/history/{scan_id}/pdf-b4")
def history_pdf_b4(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_unificado_b4.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B4 (Unificado) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b4_unificado_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/html-b4")
def history_html_b4(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_unificado_b4.html"
    if not p.is_file():
        raise HTTPException(404, "HTML B4 (Unificado) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_b4_unificado_{dom}_{scan_id}.html")




@app.get("/api/history/{scan_id}/pdf-b5")
def history_pdf_b5(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_unificado_b5.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B5 (Unificado) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b5_unificado_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/html-b5")
def history_html_b5(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_unificado_b5.html"
    if not p.is_file():
        raise HTTPException(404, "HTML B5 (Unificado) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_b5_unificado_{dom}_{scan_id}.html")


@app.get("/api/history/{scan_id}/pdf-b6")
def history_pdf_b6(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_unificado_b6.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B6 (Unificado) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b6_unificado_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/html-b6")
def history_html_b6(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_unificado_b6.html"
    if not p.is_file():
        raise HTTPException(404, "HTML B6 (Unificado) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_b6_unificado_{dom}_{scan_id}.html")


@app.get("/api/history/{scan_id}/pdf-b7")
def history_pdf_b7(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_unificado_b7.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF B7 (Detallado SSC) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_b7_detallado_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/html-b7")
def history_html_b7(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_unificado_b7.html"
    if not p.is_file():
        raise HTTPException(404, "HTML B7 (Detallado SSC) no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_b7_detallado_{dom}_{scan_id}.html")


@app.get("/api/history/{scan_id}/pdf-ppasivo")
def history_pdf_ppasivo(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_ppasivo.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF Ppasivo no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_ppasivo_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/html-ppasivo")
def history_html_ppasivo(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_ppasivo.html"
    if not p.is_file():
        raise HTTPException(404, "HTML Ppasivo no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_ppasivo_{dom}_{scan_id}.html")


@app.get("/api/history/{scan_id}/html")
def history_html(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_tpra_estilo_socradar.html"
    if not p.is_file():
        raise HTTPException(404, "HTML not found.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_tpra_{dom}_{scan_id}.html")


CONFIG_FILE = WORKDIR / "integrations_config.json"

@app.get("/api/config")
def get_config() -> JSONResponse:
    if not CONFIG_FILE.is_file():
        raise HTTPException(404, "integrations_config.json not found")
    raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    safe = {"version": raw.get("version", 1), "integrations": []}
    for integ in raw.get("integrations", []):
        entry = {k: integ[k] for k in ("id","name","description","category","enabled","needs_key") if k in integ}
        entry["has_binary"] = integ.get("needs_binary", None) is not None
        if integ.get("needs_binary"):
            import shutil
            entry["binary_found"] = shutil.which(integ["needs_binary"]) is not None
        if integ.get("needs_key"):
            env_val = os.environ.get(integ["key_id"], "")
            entry["key_configured"] = bool(env_val)
            if integ.get("key_id2"):
                env_val2 = os.environ.get(integ["key_id2"], "")
                entry["key_configured"] = entry["key_configured"] and bool(env_val2)
        safe["integrations"].append(entry)
    return JSONResponse(content=safe, headers={"Cache-Control": "no-store"})

class ConfigUpdate(BaseModel):
    key: str = ""
    key2: str = ""

@app.put("/api/config/{integration_id}")
def put_config(integration_id: str, body: ConfigUpdate) -> JSONResponse:
    if not CONFIG_FILE.is_file():
        raise HTTPException(404, "integrations_config.json not found")
    raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    found = None
    for integ in raw.get("integrations", []):
        if integ["id"] == integration_id:
            found = integ
            break
    if not found:
        raise HTTPException(404, f"Integration '{integration_id}' not found")
    if found.get("needs_key"):
        key_id = found["key_id"]
        if body.key:
            os.environ[key_id] = body.key
            found["_key"] = body.key
            log.info("Config %s: %s updated", integration_id, key_id)
        if found.get("key_id2") and body.key2:
            os.environ[found["key_id2"]] = body.key2
            found["_key2"] = body.key2
            log.info("Config %s: %s updated", integration_id, found["key_id2"])
        CONFIG_FILE.write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    return JSONResponse(content={"status": "ok", "id": integration_id})


def main() -> None:
    import argparse
    import os

    import uvicorn

    ap = argparse.ArgumentParser(description="Panel ASM local (escaneo + PDF).")
    ap.add_argument(
        "--host",
        default=os.environ.get("ASM_DASHBOARD_HOST", "127.0.0.1"),
        help="127.0.0.1 = solo esta maquina. 0.0.0.0 = toda la interfaz (riesgo).",
    )
    ap.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("ASM_DASHBOARD_PORT", "8765")),
    )
    ap.add_argument("--ssl", action="store_true", help="Habilitar HTTPS con cert.pem/key.pem")
    args = ap.parse_args()
    proto = "https" if args.ssl else "http"
    print(f"Panel ASM: {proto}://{args.host}:{args.port}/")
    if args.host == "0.0.0.0":
        print("ADVERTENCIA: escuchando en todas las interfaces.")
    ssl_kw = {}
    if args.ssl:
        ssl_kw = {"ssl_certfile": str(WORKDIR / "cert.pem"), "ssl_keyfile": str(WORKDIR / "key.pem")}
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", **ssl_kw)


if __name__ == "__main__":
    main()
