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

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import log_utils

from fastapi import FastAPI, HTTPException
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


def pdf_from_html(html_path: Path, pdf_path: Path, log: logging.Logger) -> None:
    html_path = html_path.resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    uri = html_path.as_uri()

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
            r = subprocess.run(
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
            )
            if r.returncode == 0 and pdf_path.is_file() and pdf_path.stat().st_size > 100:
                log.info("PDF OK (Edge): %s", edge)
                return
            err = (r.stderr or "")[:200]
            log.warning("Edge rc=%d err=%s", r.returncode, err)
        except Exception as e:
            log.warning("Edge exception: %s", e)

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(uri, wait_until="load", timeout=120_000)
            page.pdf(
                path=str(pdf_path),
                format="A4",
                print_background=True,
                margin={"top": "12mm", "bottom": "12mm", "left": "10mm", "right": "10mm"},
            )
            browser.close()
        if pdf_path.is_file() and pdf_path.stat().st_size > 100:
            log.info("PDF OK (Playwright Chromium).")
            return
        log.error("Playwright: PDF vacio o invalido.")
    except ImportError:
        log.error("Instala: pip install playwright && playwright install chromium")
    except Exception as e:
        log.error("Playwright: %s", e)

    raise RuntimeError(
        "No PDF. Install Playwright (playwright install chromium) or use Microsoft Edge."
    )


def run_scan_pipeline(domain: str) -> dict[str, str]:
    scan_id, out_dir = allocate_scan_dir(domain)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    log = log_utils.scan_logger(scan_id, out_dir)
    log.info("=== Pipeline start: domain=%s scan_id=%s ===", domain, scan_id)

    prov = [{"id": "scan-target", "name": domain, "domain": domain}]
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
    ]
    log.info("Running asm_scan.py ...")
    r1 = subprocess.run(cmd_asm, cwd=str(WORKDIR), capture_output=True, text=True, timeout=600)
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
        f"TPRA - {domain}",
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
            pdf_from_html(cibest_html, cibest_pdf, log)
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
            pdf_from_html(bancolombia_html, bancolombia_pdf, log)
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
            pdf_from_html(scor3bank_html, scor3bank_pdf, log)
        except Exception as e:
            log.warning("SCOR3BANK PDF skipped: %s", e)
    else:
        log.warning("SCOR3BANK report skipped: %s", (r5.stderr or "")[-500:])

    pa_py = WORKDIR / "generate_asm_passive_active_report.py"
    pa_html = out_dir / "informe_pasivo_activo.html"
    pa_pdf = out_dir / "informe_pasivo_activo.pdf"
    cmd_pa = [py, str(pa_py), "--asm", str(out_json), "--out", str(pa_html)]
    log.info("Building Pasivo/Activo report ...")
    r6 = subprocess.run(cmd_pa, cwd=str(WORKDIR), capture_output=True, text=True, timeout=120)
    if r6.returncode == 0:
        try:
            pdf_from_html(pa_html, pa_pdf, log)
        except Exception as e:
            log.warning("Pasivo/Activo PDF skipped: %s", e)
    else:
        log.warning("Pasivo/Activo report skipped: %s", (r6.stderr or "")[-500:])

    log.info("Building PDF ...")
    try:
        pdf_from_html(informe_html, informe_pdf, log)
    except Exception:
        shutil.rmtree(out_dir, ignore_errors=True)
        raise

    meta = {"domain": domain, "scan_id": scan_id, "created_utc": created}
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    sync_history_index()
    mirror_to_last(out_dir, domain, scan_id)

    log.info("=== Pipeline complete ===")
    scan_log_txt = (out_dir / "scan.log").read_text(encoding="utf-8").strip() if (out_dir / "scan.log").is_file() else ""

    base = f"/api/history/{scan_id}"
    return {
        "scan_id": scan_id,
        "domain": domain,
        "created_utc": created,
        "log": scan_log_txt,
        "pdf_url": f"{base}/pdf",
        "json_url": f"{base}/json",
        "html_url": f"{base}/html",
        "pdf_grupocibest_url": f"{base}/pdf-grupocibest",
        "pdf_bancolombia_url": f"{base}/pdf-bancolombia",
        "pdf_scor3bank_url": f"{base}/pdf-scor3bank",
        "pdf_pasivo_activo_url": f"{base}/pdf-pasivo-activo",
        "html_pasivo_activo_url": f"{base}/html-pasivo-activo",
    }


app = FastAPI(title="ASM Dashboard", version="1.0")


@app.on_event("startup")
def _startup() -> None:
    log_utils.setup()
    rebuild_index_from_disk()


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


@app.post("/api/scan")
def api_scan(body: ScanRequest) -> dict:
    domain = normalize_domain(body.domain)
    if not domain:
        raise HTTPException(400, "Empty domain")
    if not valid_domain(domain):
        raise HTTPException(400, "Invalid domain")
    try:
        return run_scan_pipeline(domain)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e)) from e


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
                "has_pa_pdf": (d / "informe_pasivo_activo.pdf").is_file(),
                "has_json": (d / "asm_report.json").is_file(),
                "has_html": (d / "informe_tpra_estilo_socradar.html").is_file(),
                "pdf_url": f"/api/history/{sid}/pdf",
                "json_url": f"/api/history/{sid}/json",
                "html_url": f"/api/history/{sid}/html",
            }
        )
    return JSONResponse(
        content={"items": enriched},
        headers={"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"},
    )


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


@app.get("/api/download/pdf-pasivo-activo")
def download_pdf_pasivo_activo() -> FileResponse:
    p = LAST / "informe_pasivo_activo.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF no disponible. Ejecuta un escaneo primero.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_pasivo_activo_{safe}.pdf")


@app.get("/api/download/json")
def download_json() -> FileResponse:
    p = LAST / "asm_report.json"
    if not p.is_file():
        raise HTTPException(404, "No JSON.")
    safe = re.sub(r"[^\w.-]+", "_", _meta_domain())[:80]
    return FileResponse(p, media_type="application/json", filename=f"asm_report_{safe}.json")


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


@app.get("/api/history/{scan_id}/pdf-pasivo-activo")
def history_pdf_pasivo_activo(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_pasivo_activo.pdf"
    if not p.is_file():
        raise HTTPException(404, "PDF pasivo/activo no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/pdf", filename=f"asm_pasivo_activo_{dom}_{scan_id}.pdf")


@app.get("/api/history/{scan_id}/html-pasivo-activo")
def history_html_pasivo_activo(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "informe_pasivo_activo.html"
    if not p.is_file():
        raise HTTPException(404, "HTML pasivo/activo no encontrado.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="text/html; charset=utf-8", filename=f"informe_pasivo_activo_{dom}_{scan_id}.html")


@app.get("/api/history/{scan_id}/json")
def history_json(scan_id: str) -> FileResponse:
    d = _history_dir(scan_id)
    p = d / "asm_report.json"
    if not p.is_file():
        raise HTTPException(404, "JSON not found.")
    dom = safe_scan_id_part(
        str(json.loads((d / "meta.json").read_text(encoding="utf-8")).get("domain", scan_id))
    )[:60]
    return FileResponse(p, media_type="application/json", filename=f"asm_report_{dom}_{scan_id}.json")


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
