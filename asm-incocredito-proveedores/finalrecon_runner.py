from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_FR_DIR: Path | None = None


def _log(msg: str) -> None:
    print(f"[finalrecon] {msg}")


def _find_finalrecon() -> Path | None:
    candidates = [
        Path(__file__).resolve().parent.parent / "FinalRecon",
        Path(__file__).resolve().parent / "FinalRecon",
        Path.home() / "FinalRecon",
    ]
    for c in candidates:
        if (c / "finalrecon.py").exists():
            return c
    return None


def run_finalrecon(
    domain: str,
    modules: list[str] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    global _FR_DIR
    if _FR_DIR is None:
        _FR_DIR = _find_finalrecon()
    if _FR_DIR is None:
        return {"error": "FinalRecon no encontrado", "skipped": True}

    default_modules = ["--crawl", "--wayback", "--sub"]
    modules = modules or default_modules

    tmpdir = Path(tempfile.mkdtemp(prefix="fr_"))
    out_dir = tmpdir / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    url = f"https://{domain}" if not domain.startswith("http") else domain
    cmd = [
        sys.executable,
        str(_FR_DIR / "finalrecon.py"),
        "--url", url,
        "-nb",
        "-T", "20",
        "-cd", str(out_dir) + "\\",
        "-of", "fr_result",
    ] + modules

    env = os.environ.copy()
    env["HOME"] = str(_FR_DIR)
    env["PYTHONIOENCODING"] = "utf-8"

    try:
        _log(f"Running FinalRecon for {domain}")
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=False,
            timeout=timeout,
            env=env,
            cwd=str(_FR_DIR),
        )
        _log(f"Exit code: {proc.returncode}")
    except subprocess.TimeoutExpired:
        _log(f"Timeout after {timeout}s")
        return {"error": f"Timeout after {timeout}s"}
    except Exception as e:
        _log(f"Error: {e}")
        return {"error": str(e)}

    result = _parse_output(out_dir / "fr_result")
    result["modules"] = modules
    result["scanned_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return result


def _parse_output(out_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}

    if not out_path.exists():
        return {"error": f"Output dir not found: {out_path}"}

    _parse_file(out_path / "headers.txt", result, "headers")
    _parse_file(out_path / "css.txt", result, "css")
    _parse_file(out_path / "javascripts.txt", result, "javascripts")
    _parse_file(out_path / "internal_urls.txt", result, "internal_urls")
    _parse_file(out_path / "external_urls.txt", result, "external_urls")
    _parse_file(out_path / "images.txt", result, "images")
    _parse_file(out_path / "robots.txt", result, "robots")
    _parse_file(out_path / "sitemap.txt", result, "sitemap")
    _parse_file(out_path / "urls_inside_sitemap.txt", result, "urls_inside_sitemap")
    _parse_file(out_path / "urls_inside_js.txt", result, "urls_inside_js")
    _parse_file(out_path / "subdomains.txt", result, "subdomains")
    _parse_file(out_path / "wayback_urls.txt", result, "wayback")
    _parse_file(out_path / "wayback_urls_raw.txt", result, "wayback_raw")
    _parse_file(out_path / "dir_enum.txt", result, "directory_enum")

    _parse_crawl_stats(out_path, result)

    return result


def _parse_file(filepath: Path, result: dict, key: str) -> None:
    if not filepath.exists():
        return
    try:
        lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
        clean = [l.strip() for l in lines if l.strip() and not l.startswith("total_urls_") and not l.startswith("Title ") and not l.startswith("Total Unique")]
        if key == "headers":
            parsed_headers = {}
            for line in clean:
                if ":" in line:
                    k, _, v = line.partition(":")
                    parsed_headers[k.strip()] = v.strip()
            result[key] = parsed_headers
        elif key == "wayback":
            sections = _parse_wayback_sections(lines)
            result[key] = sections
        elif key == "wayback_raw":
            raw_urls = [l for l in clean if l.startswith("http")]
            result["wayback_raw_urls"] = raw_urls
        else:
            urls = [l for l in clean if l.startswith("http")]
            result[key] = urls
    except Exception as e:
        _log(f"Error parsing {filepath.name}: {e}")


def _parse_wayback_sections(lines: list[str]) -> dict[str, Any]:
    sections: dict[str, Any] = {}
    current_section = "stats"
    stats: dict[str, str] = {}
    section_data: list[str] = []

    for line in lines:
        if line.startswith("===") and line.endswith("==="):
            if current_section and section_data:
                if current_section == "stats":
                    for s in section_data:
                        if ":" in s:
                            k, _, v = s.partition(":")
                            stats[k.strip()] = v.strip()
                else:
                    sections[current_section] = [l for l in section_data if l.startswith("http")]
            current_section = line.strip("= ").lower().replace(" ", "_")
            section_data = []
        else:
            stripped = line.strip()
            if stripped:
                section_data.append(stripped)

    if current_section and section_data:
        if current_section == "stats":
            for s in section_data:
                if ":" in s:
                    k, _, v = s.partition(":")
                    stats[k.strip()] = v.strip()
        else:
            sections[current_section] = [l for l in section_data if l.startswith("http")]

    if "Total URLs" not in stats:
        all_urls = sections.get("js_files", []) + sections.get("api_endpoints", []) + sections.get("juicy_params", []) + sections.get("sensitive_extensions", [])
        stats["Total URLs"] = str(len(all_urls))
    if "JS files" not in stats:
        stats["JS files"] = str(len(sections.get("js_files", [])))
    if "API endpoints" not in stats:
        stats["API endpoints"] = str(len(sections.get("api_endpoints", [])))
    if "Interesting params" not in stats:
        stats["Interesting params"] = str(len(sections.get("juicy_params", [])))
    if "Sensitive extensions" not in stats:
        stats["Sensitive extensions"] = str(len(sections.get("sensitive_extensions", [])))

    sections["stats"] = stats
    return sections


def _parse_crawl_stats(out_path: Path, result: dict) -> None:
    wayback_file = out_path / "wayback_urls.txt"
    if wayback_file.exists():
        try:
            lines = wayback_file.read_text(encoding="utf-8", errors="replace").splitlines()
            stats = {}
            for line in lines:
                m = re.match(r"^(total_urls_\w+|Total Unique Links Extracted|Title)\s*:\s*(.+)", line)
                if m:
                    stats[m.group(1).strip()] = m.group(2).strip()
            if stats:
                result["crawl_stats"] = stats
        except Exception:
            pass


def run_all(domain: str) -> dict[str, Any]:
    return run_finalrecon(domain)


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "www.incocredito.com.co"
    result = run_all(domain)
    import json
    print(json.dumps(result, indent=2, ensure_ascii=False))
