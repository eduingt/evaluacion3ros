# gobuster_integration.py — Integración de Gobuster (OJ/gobuster) para descubrimiento de contenido web.
# Requiere binario `gobuster` en PATH (https://github.com/OJ/gobuster).
# Modos: dir (directorios/archivos), dns (subdominios), vhost (virtual hosts).
#
# Uso desde asm_scan._scan_provider:
#   import gobuster_integration
#   gobuster_data = gobuster_integration.run_for_level(domain, test_level)
#
# NIVELES:
#   pasivo (1)       -> NO EJECUTA (gobuster es activo por naturaleza)
#   semi-activo (2)  -> modo dir con wordlist pequeña (common.txt), solo extensiones web comunes, status 200/301/302/403
#   activo (3)       -> modo dir + modo dns (subdominios) con wordlist media, más extensiones
#   invasivo (4)     -> modo dir + dns + vhost con wordlist grande (raft-large), todas las extensiones, recursivo

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

log = logging.getLogger("gobuster_integration")


def _find_gobuster_bin() -> str | None:
    """Busca el binario gobuster en PATH o ubicaciones comunes."""
    bin_path = shutil.which("gobuster")
    if bin_path:
        return bin_path
    go_bin = Path.home() / "go" / "bin" / "gobuster.exe"
    if go_bin.exists():
        return str(go_bin)
    gopath = os.environ.get("GOPATH")
    if gopath:
        gopath_bin = Path(gopath) / "bin" / "gobuster.exe"
        if gopath_bin.exists():
            return str(gopath_bin)
    return None


GOBUSTER_BIN = _find_gobuster_bin()

# Wordlists por nivel (rutas relativas a directorio wordlists de gobuster o absolutas)
# Se asume que gobuster viene con wordlists en /usr/share/wordlists/ o similar
WORDLISTS_DIR = Path("/usr/share/wordlists") if Path("/usr/share/wordlists").exists() else Path.home() / "wordlists"

# Claves de wordlists por nivel (se resuelven en runtime con _ensure_wordlist)
LEVEL_WORDLIST_KEYS: dict[int, dict[str, str]] = {
    1: {},  # pasivo: no ejecuta
    2: {
        "dir": "common.txt",
        "dns": "",
    },
    3: {
        "dir": "directory-list-2.3-medium.txt",
        "dns": "subdomains-top1million-5000.txt",
    },
    4: {
        "dir": "directory-list-2.3-big.txt",
        "dns": "subdomains-top1million-110000.txt",
        "vhost": "subdomains-top1million-110000.txt",
    },
}


def _resolve_wordlists(level: int) -> dict[str, str]:
    """Resuelve las wordlists para un nivel dado en runtime."""
    keys = LEVEL_WORDLIST_KEYS.get(level, {})
    resolved = {}
    for mode, key in keys.items():
        if key:
            resolved[mode] = _ensure_wordlist(key)
        else:
            resolved[mode] = ""
    return resolved

# Extensiones por nivel
LEVEL_EXTENSIONS: dict[int, str] = {
    1: "",
    2: "php,html,js,json,xml,txt,asp,aspx,jsp",
    3: "php,html,js,json,xml,txt,asp,aspx,jsp,do,action,cfm,pl,py,rb,sh,bak,old,orig,swp,tmp,log,conf,config,ini,env,yml,yaml",
    4: "php,html,js,json,xml,txt,asp,aspx,jsp,do,action,cfm,pl,py,rb,sh,bak,old,orig,swp,tmp,log,conf,config,ini,env,yml,yaml,zip,tar,gz,rar,7z,sql,db,sqlite,mdb",
}

# Status codes de interés
LEVEL_STATUS_CODES: dict[int, str] = {
    1: "",
    2: "200,201,204,301,302,307,308,401,403,405,500",
    3: "200,201,204,301,302,307,308,401,403,405,500,502,503",
    4: "200,201,204,301,302,307,308,400,401,403,405,500,502,503",
}

# Timeouts por nivel (segundos)
LEVEL_TIMEOUT: dict[int, int] = {
    1: 0,
    2: 60,
    3: 180,
    4: 300,
}

# Threads por nivel
LEVEL_THREADS: dict[int, int] = {
    1: 0,
    2: 10,
    3: 30,
    4: 50,
}


# URLs de wordlists comunes para auto-descarga
WORDLIST_URLS = {
    "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    "directory-list-2.3-medium.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "directory-list-2.3-big.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-big.txt",
    "subdomains-top1million-5000.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    "subdomains-top1million-110000.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
}


def _ensure_wordlist(name: str) -> str:
    """Asegura que la wordlist existe, descargándola si es necesario."""
    # Buscar en ubicaciones comunes
    search_paths = [
        WORDLISTS_DIR / "dirb" / name,
        WORDLISTS_DIR / "dirbuster" / name,
        WORDLISTS_DIR / "seclists" / "Discovery" / "Web-Content" / name,
        WORDLISTS_DIR / "seclists" / "Discovery" / "DNS" / name,
        Path.home() / "wordlists" / name,
        Path.home() / "wordlists" / "seclists" / "Discovery" / "Web-Content" / name,
        Path.home() / "wordlists" / "seclists" / "Discovery" / "DNS" / name,
    ]
    for p in search_paths:
        if p.exists():
            return str(p)
    
    # Auto-descargar a directorio local
    local_dir = Path(__file__).parent / "wordlists"
    local_dir.mkdir(exist_ok=True)
    local_path = local_dir / name
    
    if local_path.exists():
        return str(local_path)
    
    url = WORDLIST_URLS.get(name)
    if not url:
        return ""
    
    try:
        log.info("Descargando wordlist %s...", name)
        import urllib.request
        urllib.request.urlretrieve(url, local_path)
        if local_path.exists() and local_path.stat().st_size > 100:
            log.info("Wordlist %s descargada (%d bytes)", name, local_path.stat().st_size)
            return str(local_path)
    except Exception as e:
        log.warning("Error descargando wordlist %s: %s", name, e)
    return ""


def _find_wordlist(path_str: str) -> str:
    """Busca wordlist en ubicaciones comunes."""
    if not path_str:
        return ""
    p = Path(path_str)
    if p.exists():
        return str(p)

    # Buscar en ubicaciones alternativas
    alt_paths = [
        Path("/usr/share/wordlists") / p.name,
        Path("/usr/share/seclists") / p.name,
        Path.home() / "wordlists" / p.name,
        Path("/opt/wordlists") / p.name,
    ]
    for alt in alt_paths:
        if alt.exists():
            return str(alt)
    return ""


def _run_gobuster_dir(domain: str, test_level: int) -> dict[str, Any]:
    """Ejecuta gobuster dir (directorios/archivos)."""
    wls = _resolve_wordlists(test_level)
    wl = wls.get("dir", "")
    if not wl:
        return {"mode": "dir", "status": "skipped", "reason": "wordlist no encontrada", "findings": []}

    extensions = LEVEL_EXTENSIONS.get(test_level, "")
    status_codes = LEVEL_STATUS_CODES.get(test_level, "")
    threads = LEVEL_THREADS.get(test_level, 10)
    timeout = LEVEL_TIMEOUT.get(test_level, 60)

    cmd = [
        str(GOBUSTER_BIN),
        "dir",
        "-u", f"https://{domain}",
        "-w", wl,
        "-t", str(threads),
        "-timeout", f"{timeout}s",
        "-k",  # skip SSL verification
        "-q",  # quiet
        "-o", "-",  # stdout
    ]
    if extensions:
        cmd.extend(["-x", extensions])
    if status_codes:
        cmd.extend(["-s", status_codes])

    # Recursivo solo en nivel invasivo
    if test_level >= 4:
        cmd.append("-r")

    try:
        log.info("Ejecutando gobuster dir nivel %d en %s (wordlist: %s)", test_level, domain, Path(wl).name)
        start = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        elapsed = time.time() - start

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            # Formato típico: /path (Status: 200) [Size: 1234]
            parts = line.split()
            if len(parts) >= 2:
                path = parts[0]
                status = ""
                size = ""
                for p in parts[1:]:
                    if p.startswith("(Status:"):
                        status = p.replace("(Status:", "").replace(")", "")
                    elif p.startswith("[Size:"):
                        size = p.replace("[Size:", "").replace("]", "")
                findings.append({
                    "path": path,
                    "status_code": int(status) if status.isdigit() else None,
                    "size": int(size) if size.isdigit() else None,
                    "url": f"https://{domain}{path}",
                })

        return {
            "mode": "dir",
            "status": "ok" if result.returncode == 0 else "partial",
            "elapsed_seconds": round(elapsed, 1),
            "wordlist": Path(wl).name,
            "total_findings": len(findings),
            "findings": findings[:300],
        }
    except subprocess.TimeoutExpired:
        return {"mode": "dir", "status": "timeout", "error": f"timeout {timeout}s", "findings": []}
    except Exception as e:
        log.warning("Error en gobuster dir: %s", e)
        return {"mode": "dir", "status": "error", "error": str(e), "findings": []}


def _run_gobuster_dns(domain: str, test_level: int) -> dict[str, Any]:
    """Ejecuta gobuster dns (subdominios)."""
    wls = _resolve_wordlists(test_level)
    wl = wls.get("dns", "")
    if not wl:
        return {"mode": "dns", "status": "skipped", "reason": "wordlist no encontrada", "findings": []}

    threads = LEVEL_THREADS.get(test_level, 10)
    timeout = LEVEL_TIMEOUT.get(test_level, 60)

    cmd = [
        str(GOBUSTER_BIN),
        "dns",
        "-d", domain,
        "-w", wl,
        "-t", str(threads),
        "-timeout", f"{timeout}s",
        "-q",
        "-o", "-",
    ]

    # Resolver wildcard
    if test_level >= 3:
        cmd.append("--wildcard")

    try:
        log.info("Ejecutando gobuster dns nivel %d en %s (wordlist: %s)", test_level, domain, Path(wl).name)
        start = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        elapsed = time.time() - start

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            # Formato típico: Found: sub.domain.com (IP: 1.2.3.4)
            if line.startswith("Found:"):
                parts = line.split()
                if len(parts) >= 2:
                    subdomain = parts[1]
                    ip = ""
                    if "(IP:" in line:
                        ip = line.split("(IP:")[1].split(")")[0]
                    findings.append({
                        "subdomain": subdomain,
                        "ip": ip,
                    })

        return {
            "mode": "dns",
            "status": "ok" if result.returncode == 0 else "partial",
            "elapsed_seconds": round(elapsed, 1),
            "wordlist": Path(wl).name,
            "total_findings": len(findings),
            "findings": findings[:500],
        }
    except subprocess.TimeoutExpired:
        return {"mode": "dns", "status": "timeout", "error": f"timeout {timeout}s", "findings": []}
    except Exception as e:
        log.warning("Error en gobuster dns: %s", e)
        return {"mode": "dns", "status": "error", "error": str(e), "findings": []}


def _run_gobuster_vhost(domain: str, test_level: int) -> dict[str, Any]:
    """Ejecuta gobuster vhost (virtual hosts)."""
    if test_level < 4:
        return {"mode": "vhost", "status": "skipped", "reason": "solo nivel invasivo", "findings": []}

    wls = _resolve_wordlists(test_level)
    wl = wls.get("vhost", "")
    if not wl:
        return {"mode": "vhost", "status": "skipped", "reason": "wordlist no encontrada", "findings": []}

    threads = LEVEL_THREADS.get(test_level, 10)
    timeout = LEVEL_TIMEOUT.get(test_level, 60)

    cmd = [
        str(GOBUSTER_BIN),
        "vhost",
        "-u", f"https://{domain}",
        "-w", wl,
        "-t", str(threads),
        "-timeout", f"{timeout}s",
        "-k",
        "-q",
        "-o", "-",
    ]

    try:
        log.info("Ejecutando gobuster vhost nivel %d en %s (wordlist: %s)", test_level, domain, Path(wl).name)
        start = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        elapsed = time.time() - start

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            if line.startswith("Found:"):
                parts = line.split()
                if len(parts) >= 2:
                    vhost = parts[1]
                    size = ""
                    for p in parts[2:]:
                        if p.startswith("Size:"):
                            size = p.replace("Size:", "")
                    findings.append({
                        "vhost": vhost,
                        "size": int(size) if size.isdigit() else None,
                    })

        return {
            "mode": "vhost",
            "status": "ok" if result.returncode == 0 else "partial",
            "elapsed_seconds": round(elapsed, 1),
            "wordlist": Path(wl).name,
            "total_findings": len(findings),
            "findings": findings[:200],
        }
    except subprocess.TimeoutExpired:
        return {"mode": "vhost", "status": "timeout", "error": f"timeout {timeout}s", "findings": []}
    except Exception as e:
        log.warning("Error en gobuster vhost: %s", e)
        return {"mode": "vhost", "status": "error", "error": str(e), "findings": []}


def run_for_level(domain: str, test_level: int) -> dict[str, Any]:
    """Punto de entrada principal: ejecuta modos según nivel."""
    if test_level < 2:
        return {"domain": domain, "level": test_level, "status": "skipped", "reason": "nivel pasivo: gobuster no se ejecuta", "modes": {}}

    if not GOBUSTER_BIN:
        return {"domain": domain, "level": test_level, "status": "error", "error": "binario 'gobuster' no encontrado en PATH", "modes": {}}

    out: dict[str, Any] = {"domain": domain, "level": test_level, "modes": {}}

    # Modo dir: siempre en niveles >= 2
    out["modes"]["dir"] = _run_gobuster_dir(domain, test_level)

    # Modo dns: niveles >= 3
    if test_level >= 3:
        out["modes"]["dns"] = _run_gobuster_dns(domain, test_level)

    # Modo vhost: solo nivel 4
    if test_level >= 4:
        out["modes"]["vhost"] = _run_gobuster_vhost(domain, test_level)

    # Estado global
    statuses = [m.get("status") for m in out["modes"].values() if m.get("status") not in ("skipped",)]
    if not statuses:
        out["status"] = "skipped"
    elif all(s in ("ok", "partial") for s in statuses):
        out["status"] = "ok"
    elif any(s in ("ok", "partial") for s in statuses):
        out["status"] = "partial"
    else:
        out["status"] = "error"

    return out