from __future__ import annotations

import csv
import io
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import requests

VULNDB_DIR = Path(__file__).resolve().parent / "vulndb"
CVE_URL = "https://raw.githubusercontent.com/scipag/vulscan/master/cve.csv"
EXPLOITDB_URL = "https://raw.githubusercontent.com/scipag/vulscan/master/exploitdb.csv"
SCIPVULDB_URL = "https://raw.githubusercontent.com/scipag/vulscan/master/scipvuldb.csv"

REFRESH_DAYS = 7
DOWNLOAD_TIMEOUT = 30

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

PRODUCT_ALIASES: dict[str, list[str]] = {
    "Apache": ["apache", "httpd", "apache httpd"],
    "nginx": ["nginx", "nginx/"],
    "IIS": ["iis", "internet information services", "microsoft-iis", "microsoft iis"],
    "OpenSSH": ["openssh", "ssh"],
    "OpenSSL": ["openssl"],
    "Node.js": ["node.js", "nodejs", "node"],
    "Express": ["express"],
    "Python": ["python"],
    "PHP": ["php"],
    "MySQL": ["mysql", "mariadb"],
    "PostgreSQL": ["postgresql", "postgres"],
    "Redis": ["redis"],
    "MongoDB": ["mongodb", "mongo"],
    "Tomcat": ["tomcat", "apache tomcat"],
    "Jetty": ["jetty", "eclipse jetty"],
    "nginx/": ["nginx"],
}


def _download_csv(url: str, dest: Path) -> bool:
    try:
        resp = requests.get(url, timeout=DOWNLOAD_TIMEOUT)
        resp.raise_for_status()
        dest.write_text(resp.text, encoding="utf-8")
        return True
    except Exception:
        return False


def _load_csv(path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        reader = csv.reader(io.StringIO(text), delimiter=";")
        for row in reader:
            if len(row) >= 2:
                vid = row[0].strip()
                title = row[1].strip()
                if vid and title:
                    entries.append((vid, title))
    except Exception:
        pass
    return entries


def _needs_refresh(path: Path) -> bool:
    if not path.exists():
        return True
    age = time.time() - path.stat().st_mtime
    return age > REFRESH_DAYS * 86400


def _normalize_product(name: str) -> str:
    name = name.lower().strip()
    for canonical, aliases in PRODUCT_ALIASES.items():
        for a in aliases:
            if a in name:
                return canonical
    return name


def _product_matches(title_lower: str, product: str) -> bool:
    for alias in PRODUCT_ALIASES.get(product, [product.lower()]):
        if alias in title_lower:
            return True
    return bool(re.search(r"\b" + re.escape(product.lower()) + r"\b", title_lower))


class VulnDB:
    def __init__(self) -> None:
        self.cve_entries: list[tuple[str, str]] = []
        self.exploitdb_entries: list[tuple[str, str]] = []
        self.scipvuldb_entries: list[tuple[str, str]] = []
        self._loaded = False
        self._load_error: str | None = None

    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        VULNDB_DIR.mkdir(parents=True, exist_ok=True)

        cve_csv = VULNDB_DIR / "cve.csv"
        exploitdb_csv = VULNDB_DIR / "exploitdb.csv"
        scipvuldb_csv = VULNDB_DIR / "scipvuldb.csv" if (VULNDB_DIR / "scipvuldb.csv").exists() else None

        if _needs_refresh(cve_csv):
            if _download_csv(CVE_URL, cve_csv):
                pass
        if _needs_refresh(exploitdb_csv):
            _download_csv(EXPLOITDB_URL, exploitdb_csv)

        if cve_csv.exists():
            self.cve_entries = _load_csv(cve_csv)
        if exploitdb_csv.exists():
            self.exploitdb_entries = _load_csv(exploitdb_csv)
        if scipvuldb_csv and scipvuldb_csv.exists():
            self.scipvuldb_entries = _load_csv(scipvuldb_csv)

        self._loaded = True
        total = len(self.cve_entries) + len(self.exploitdb_entries) + len(self.scipvuldb_entries)
        if total == 0:
            self._load_error = "No vulnerability databases loaded"

    def lookup(self, product: str, version: str | None = None) -> list[dict[str, Any]]:
        self.ensure_loaded()
        results: list[dict[str, Any]] = []
        prod_lower = product.lower()

        for vid, title in self.cve_entries:
            title_lower = title.lower()
            if prod_lower in title_lower or _product_matches(title_lower, product):
                if version and version not in title and version.lower() not in title_lower:
                    continue
                results.append({
                    "id": vid,
                    "title": title[:300],
                    "type": "CVE",
                    "source": "cve.csv",
                    "db_url": f"https://nvd.nist.gov/vuln/detail/{vid}",
                })

        for vid, title in self.exploitdb_entries:
            title_lower = title.lower()
            if prod_lower in title_lower or _product_matches(title_lower, product):
                results.append({
                    "id": f"EDB-{vid}",
                    "title": title[:300],
                    "type": "Exploit",
                    "source": "exploitdb.csv",
                    "db_url": f"https://www.exploit-db.com/exploits/{vid}",
                })

        for vid, title in self.scipvuldb_entries:
            title_lower = title.lower()
            if prod_lower in title_lower or _product_matches(title_lower, product):
                results.append({
                    "id": f"VulDB-{vid}",
                    "title": title[:300],
                    "type": "VulDB",
                    "source": "scipvuldb.csv",
                    "db_url": f"https://vuldb.com/?id.{vid}",
                })

        return results

    def lookup_banners(self, banners: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for b in banners:
            product = b.get("product", "") or b.get("protocol", "")
            version = b.get("version")
            port = b.get("port", 0)
            if not product or product == "unknown":
                continue
            matches = self.lookup(product, version)
            for m in matches:
                dedup_key = f"{m['id']}:{port}"
                if dedup_key not in seen_ids:
                    seen_ids.add(dedup_key)
                    m["port"] = port
                    m["product"] = product
                    results.append(m)
        results.sort(key=lambda x: x.get("id", ""))
        return results

    # ------------------------------------------------------------------ #
    #  EPSS (Exploit Prediction Scoring System) — online API             #
    # ------------------------------------------------------------------ #
    _epss_cache: dict[str, dict[str, float | None]] = {}

    def _fetch_epss_scores(self, cve_ids: list[str]) -> dict[str, dict[str, float | None]]:
        """Batch query the EPSS API for a list of CVE IDs.
        Returns {cve_id: {"epss": float|None, "percentile": float|None}}.
        """
        needed = [c for c in cve_ids if c not in self._epss_cache]
        if needed:
            try:
                params = {"cve": ",".join(needed)}
                resp = requests.get(EPSS_API_URL, params=params, timeout=DOWNLOAD_TIMEOUT)
                if resp.status_code == 200:
                    data = resp.json().get("data", [])
                    for entry in data:
                        cid = entry.get("cve", "")
                        try:
                            epss = float(entry.get("epss", 0)) if entry.get("epss") else None
                        except (ValueError, TypeError):
                            epss = None
                        try:
                            pct = float(entry.get("percentile", 0)) if entry.get("percentile") else None
                        except (ValueError, TypeError):
                            pct = None
                        self._epss_cache[cid] = {"epss": epss, "percentile": pct}
                for c in needed:
                    self._epss_cache.setdefault(c, {"epss": None, "percentile": None})
            except Exception:
                for c in needed:
                    self._epss_cache.setdefault(c, {"epss": None, "percentile": None})
        return {c: self._epss_cache.get(c, {"epss": None, "percentile": None}) for c in cve_ids}

    # ------------------------------------------------------------------ #
    #  CISA KEV (Known Exploited Vulnerabilities) — online feed          #
    # ------------------------------------------------------------------ #
    _kev_set: set[str] | None = None

    def _load_kev_catalog(self) -> set[str]:
        """Download & cache the CISA KEV catalog locally. Returns set of CVE IDs."""
        if self._kev_set is not None:
            return self._kev_set
        kev_path = VULNDB_DIR / "known_exploited_vulnerabilities.json"
        if _needs_refresh(kev_path):
            try:
                resp = requests.get(KEV_URL, timeout=DOWNLOAD_TIMEOUT)
                if resp.status_code == 200:
                    kev_path.write_text(resp.text, encoding="utf-8")
            except Exception:
                pass
        cves: set[str] = set()
        if kev_path.exists():
            try:
                data = json.loads(kev_path.read_text(encoding="utf-8", errors="replace"))
                for vuln in data.get("vulnerabilities", []):
                    cid = vuln.get("cveID", "")
                    if cid.startswith("CVE-"):
                        cves.add(cid)
            except Exception:
                pass
        self._kev_set = cves
        return cves

    # ------------------------------------------------------------------ #
    #  Composite risk score + enrichment                                 #
    # ------------------------------------------------------------------ #
    _TYPE_SEVERITY = {"CVE": 1.0, "Exploit": 0.7, "VulDB": 0.4}

    def enrich_cve_findings(self, findings: list[dict[str, Any]]) -> None:
        """Enrich CVE findings with EPSS, KEV status, and composite risk score. Modifies in-place."""
        cve_ids = [f["id"] for f in findings if f.get("type") == "CVE" and f["id"].startswith("CVE-")]
        epss_data: dict[str, dict[str, float | None]] = {}
        kev_set: set[str] = set()
        if cve_ids:
            try:
                epss_data = self._fetch_epss_scores(cve_ids)
            except Exception:
                pass
            try:
                kev_set = self._load_kev_catalog()
            except Exception:
                pass

        for f in findings:
            cve_id = f.get("id", "")
            epss_info = epss_data.get(cve_id, {})
            f["epss_score"] = epss_info.get("epss")
            f["epss_percentile"] = epss_info.get("percentile")
            f["in_kev"] = cve_id in kev_set

            epss_val = f["epss_score"] or 0.0
            kev_val = 1.0 if f["in_kev"] else 0.0
            type_sev = self._TYPE_SEVERITY.get(f.get("type", ""), 0.1)
            risk = (epss_val * 3.5) + (kev_val * 3.0) + (type_sev * 3.5)
            f["risk_score"] = round(min(risk, 10.0), 2)


_db_instance: VulnDB | None = None


def get_db() -> VulnDB:
    global _db_instance
    if _db_instance is None:
        _db_instance = VulnDB()
    return _db_instance


def lookup_vulnerabilities(banners: list[dict[str, Any]]) -> list[dict[str, Any]]:
    db = get_db()
    db.ensure_loaded()
    findings = db.lookup_banners(banners)
    try:
        db.enrich_cve_findings(findings)
    except Exception:
        pass
    return findings


def refresh_databases() -> dict[str, Any]:
    VULNDB_DIR.mkdir(parents=True, exist_ok=True)
    results: dict[str, bool] = {}
    for name, url in [("cve.csv", CVE_URL), ("exploitdb.csv", EXPLOITDB_URL)]:
        dest = VULNDB_DIR / name
        ok = _download_csv(url, dest)
        results[name] = ok
    return results
