from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

WHO_DAT_BASE_URL = os.environ.get("WHO_DAT_BASE_URL", "https://who-dat.as93.net")
WHO_DAT_TIMEOUT = 15
USER_AGENT = "ASM-Incocredito-Proveedores/1.0 (+research; who-dat-integration)"


def _get_who_dat_url(endpoint: str) -> str:
    base = WHO_DAT_BASE_URL.rstrip("/")
    return f"{base}{endpoint}"


def run_who_dat_single(domain: str) -> dict[str, Any]:
    """Consulta who-dat para un solo dominio (RDAP + WHOIS normalizado)."""
    url = _get_who_dat_url(f"/v1/whois/{domain}")
    try:
        r = requests.get(url, timeout=WHO_DAT_TIMEOUT, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200:
            data = r.json()
            data["_source"] = "who-dat"
            data["_queried_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            return data
        return {"domain": domain, "error": f"HTTP {r.status_code}", "status_code": r.status_code}
    except requests.exceptions.Timeout:
        return {"domain": domain, "error": "timeout"}
    except requests.exceptions.RequestException as e:
        return {"domain": domain, "error": str(e)}


def run_who_dat_bulk(domains: list[str]) -> dict[str, Any]:
    """Consulta who-dat para múltiples dominios (endpoint /multi). Máx 10 por defecto."""
    if not domains:
        return {"results": []}
    url = _get_who_dat_url("/multi")
    params = {"domains": ",".join(domains[:10])}
    try:
        r = requests.get(url, params=params, timeout=WHO_DAT_TIMEOUT, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200:
            data = r.json()
            data["_source"] = "who-dat"
            data["_queried_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            return data
        return {"error": f"HTTP {r.status_code}", "status_code": r.status_code}
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def normalize_who_dat_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Normaliza resultado who-dat a formato consistente para reportes."""
    if not raw or "error" in raw:
        return raw

    normalized: dict[str, Any] = {
        "domain": raw.get("domain"),
        "is_registered": raw.get("isRegistered"),
        "registrar": raw.get("registrar"),
        "creation_date": raw.get("createdDate"),
        "expiration_date": raw.get("expiresDate"),
        "updated_date": raw.get("updatedDate"),
        "name_servers": raw.get("nameServers") or [],
        "status": raw.get("status") or [],
        "dnssec": raw.get("dnssec"),
        "registrant": {
            "organization": raw.get("registrant", {}).get("organization"),
            "name": raw.get("registrant", {}).get("name"),
            "email": raw.get("registrant", {}).get("email"),
            "country": raw.get("registrant", {}).get("country"),
        },
        "admin": {
            "organization": raw.get("admin", {}).get("organization"),
            "name": raw.get("admin", {}).get("name"),
            "email": raw.get("admin", {}).get("email"),
            "country": raw.get("admin", {}).get("country"),
        },
        "technical": {
            "organization": raw.get("technical", {}).get("organization"),
            "name": raw.get("technical", {}).get("name"),
            "email": raw.get("technical", {}).get("email"),
            "country": raw.get("technical", {}).get("country"),
        },
        "raw_rdap": raw.get("raw"),
        "_meta": {
            "source": "who-dat",
            "queried_at": raw.get("_queried_at"),
        },
    }
    return normalized


def run_for_level(domain: str, test_level: int) -> dict[str, Any]:
    """
    Ejecuta who-dat según nivel de prueba.
    - Nivel 1 (pasivo): consulta simple del dominio apex
    - Nivel 2 (semi-activo): + subdominios www, mail, api
    - Nivel 3 (activo): + bulk con subdominios descubiertos (hasta 10)
    - Nivel 4 (invasivo): igual que nivel 3 (who-dat es pasivo por naturaleza)
    """
    result: dict[str, Any] = {"domain": domain, "level": test_level}

    if test_level < 1:
        return {"error": "invalid_level", "level": test_level}

    apex_result = run_who_dat_single(domain)
    result["apex"] = normalize_who_dat_result(apex_result)

    if test_level >= 2:
        subdomains = [f"www.{domain}", f"mail.{domain}", f"api.{domain}", f"admin.{domain}"]
        bulk_result = run_who_dat_bulk(subdomains)
        result["subdomains"] = {}
        if "results" in bulk_result:
            for item in bulk_result["results"]:
                sub = item.get("domain")
                if sub:
                    result["subdomains"][sub] = normalize_who_dat_result(item)

    if test_level >= 3:
        pass

    return result