"""Detección de almacenamiento en la nube (buckets S3, CloudFront, CDN) a
partir del HTML del sitio, y comprobación de permisos públicos.

Adaptado de Raccoon (raccoon_src/lib/storage_explorer.py, licencia MIT) a la
convención del proyecto ASM. No requiere xmltodict: el listado XML de un bucket
S3 se interpreta con regex simples, evitando dependencias extra.
"""

from __future__ import annotations

import re
from typing import Any

import requests
from bs4 import BeautifulSoup

USER_AGENT = "ASM-Incocredito-Proveedores/1.0 (+research)"
TIMEOUT = 10

_BASE_S3_URL = "s3.amazonaws.com"

# Patrones clave de archivo sensible (subset representativo, ligero).
_SENSITIVE_HINTS: tuple[str, ...] = (
    ".git/", ".gitignore", ".env", ".htpasswd", "backup", "backups",
    "credential", "credentials", "database.sql", "dump", "secrets", "secret",
    "keys.json", "config.json", ".DS_Store", "password", "wp-config",
)


def _is_s3_or_cdn_url(src: str, domain: str) -> bool:
    s = src.lower()
    if "s3" in s and "amazonaws" in s:
        return True
    if "cloudfront.net" in s:
        return True
    if "amazonaws.com" in s:
        return True
    if f"cdn.{domain.lower()}" in s:
        return True
    if s.startswith("http") and ("blob.core.windows.net" in s or "storage.googleapis.com" in s or "storage.cloud.google.com" in s):
        return True
    return False


def _is_amazon_s3(resp: requests.Response) -> bool:
    return (resp.headers.get("Server") or "") == "AmazonS3"


def _bucket_base(url: str) -> str:
    parts = [p for p in url.split("/") if p]
    scheme = "https" if url.lower().startswith("https") else "http"
    return f"{scheme}//{'/'.join(parts[:1])}" if len(parts) >= 1 else url


def _sensitive_match(key: str) -> str | None:
    kl = key.lower()
    for hint in _SENSITIVE_HINTS:
        if hint in kl:
            return hint
    return None


def _scan_bucket_listing(xml_text: str) -> list[str]:
    keys = re.findall(r"<Key>([^<]+)</Key>", xml_text)
    return [k for k in keys if _sensitive_match(k) or k.lower().endswith((".json", ".sql", ".env", ".bak", ".zip", ".tar", ".dump"))]


def scan_cloud_storage(
    domain: str,
    html: str | None,
    cnames: list[str] | None = None,
) -> dict[str, Any]:
    """Devuelve dict con 'buckets' hallados, 'publicos', 'archivos_sensibles'."""
    cnames = cnames or []
    candidates: set[str] = set()

    # 1) Buckets/cdn inferidos del CNAME.
    for cname in cnames:
        cl = cname.lower()
        if "cloudfront" in cl or "s3" in cl or "amazonaws" in cl or "cdn" in cl or "storage" in cl:
            if cname.startswith(("http://", "https://")):
                candidates.add(cname)
            else:
                candidates.add(f"https://{cname}")

    # 2) Buckets/cdn inferidos de las URLs de recursos del HTML.
    if html:
        try:
            soup = BeautifulSoup(html or "", "html.parser")
            for img in soup.select("img[src]"):
                src = img.get("src") or ""
                if _is_s3_or_cdn_url(src, domain):
                    candidates.add(src if src.startswith("http") else f"https://{domain.rstrip('/')}/{src.lstrip('/')}")
        except Exception:
            pass

    results: list[dict[str, Any]] = []
    for url in sorted(candidates):
        base = _bucket_base(url)
        entry: dict[str, Any] = {"url": url, "server": None, "status_code": None, "public": False, "sensitive_files": []}
        try:
            r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, allow_redirects=True)
            entry["status_code"] = r.status_code
            entry["server"] = r.headers.get("Server", "")
            entry["content_type"] = (r.headers.get("Content-Type") or "").split(";")[0].strip()
            if _is_amazon_s3(r):
                entry["exists"] = True
                # Público solo si el listado XML es accesible (200). Un 403
                # significa bucket existente pero con permisos restringidos.
                if r.status_code == 200 and "application/xml" in (r.headers.get("Content-Type") or ""):
                    entry["public"] = True
                    entry["sensitive_files"] = _scan_bucket_listing(r.text)
            elif r.status_code == 200:
                # CloudFront / CDN públicos con listado visible.
                ct = (r.headers.get("Content-Type") or "").lower()
                if "application/xml" in ct or r.status_code == 200:
                    entry["public"] = True
        except requests.exceptions.RequestException as e:
            entry["error"] = str(e)[:150]
        results.append(entry)

    return {
        "domain": domain,
        "buckets": results,
        "publicos": [b for b in results if b.get("public")],
        "archivos_sensibles": [b["sensitive_files"] for b in results if b.get("sensitive_files")],
    }