from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

_CONFIG_PATH = Path(__file__).resolve().parent / "integrations_config.json"


def _get_key(key_id: str) -> str:
    env_val = os.environ.get(key_id, "")
    if env_val:
        return env_val
    try:
        cfg = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
        for integ in cfg.get("integrations", []):
            if integ.get("key_id") == key_id:
                return integ.get("_key", "")
            if integ.get("key_id2") == key_id:
                return integ.get("_key2", "")
    except Exception:
        pass
    return ""


def _log(msg: str) -> None:
    print(f"[external_sources] {msg}")


def run_whois(domain: str) -> dict:
    try:
        import whois
        w = whois.whois(domain)
        result = {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": _fmt_date(w.creation_date),
            "expiration_date": _fmt_date(w.expiration_date),
            "updated_date": _fmt_date(w.updated_date),
            "name_servers": _listify(w.name_servers)[:10],
            "status": _listify(w.status)[:10],
            "registrant_organization": w.org,
            "registrant_country": w.country,
            "registrant_name": w.name,
            "emails": _listify(w.emails)[:10],
            "dnssec": w.dnssec,
        }
        return result
    except ImportError:
        return {"error": "python-whois not installed"}
    except Exception as e:
        return {"error": str(e)}


def _fmt_date(val: Any) -> str | None:
    if not val:
        return None
    if isinstance(val, list):
        val = val[0]
    if hasattr(val, "strftime"):
        return val.strftime("%Y-%m-%d %H:%M:%S")
    return str(val)[:19]


def _listify(val: Any) -> list[str]:
    if not val:
        return []
    if isinstance(val, list):
        return [str(v) for v in val if v]
    return [str(val)]


def run_dnsdumpster(domain: str) -> dict:
    try:
        sess = requests.Session()
        sess.headers.update({"User-Agent": USER_AGENT})
        r1 = sess.get("https://dnsdumpster.com/", timeout=30)
        soup = BeautifulSoup(r1.text, "html.parser")
        csrf = soup.find("input", {"name": "csrfmiddlewaretoken"})
        if not csrf or not csrf.get("value"):
            return {"error": "No se pudo extraer CSRF token de dnsdumpster"}
        token = csrf["value"]
        cookies = {c.name: c.value for c in sess.cookies}
        data = {"csrfmiddlewaretoken": token, "targetip": domain, "user": "free"}
        r2 = sess.post(
            "https://dnsdumpster.com/",
            data=data,
            cookies=cookies,
            headers={"Referer": "https://dnsdumpster.com/"},
            timeout=60,
        )
        soup2 = BeautifulSoup(r2.text, "html.parser")
        result: dict[str, Any] = {"domain": domain}
        tables = soup2.find_all("table")
        for table in tables:
            header = table.find("th")
            if not header:
                continue
            hdr_text = header.get_text(strip=True).lower()
            rows = []
            for tr in table.find_all("tr")[1:]:
                cols = [td.get_text(strip=True) for td in tr.find_all("td")]
                if cols:
                    rows.append(cols)
            if "dns" in hdr_text:
                result["dns_servers"] = rows[:10]
            elif "mx" in hdr_text:
                result["mx_records"] = rows[:10]
            elif "txt" in hdr_text:
                result["txt_records"] = rows[:10]
            elif "host" in hdr_text:
                result["host_records"] = rows[:20]
        if not any(k in result for k in ("dns_servers", "mx_records", "txt_records", "host_records")):
            return {"error": "No se encontraron tablas en la respuesta", "raw_preview": r2.text[:500]}
        return result
    except ImportError:
        return {"error": "requests o beautifulsoup4 no instalados"}
    except Exception as e:
        return {"error": str(e)}


def run_shodan(domain: str) -> dict:
    api_key = _get_key("SHODAN_API_KEY")
    if not api_key:
        return {"error": "SHODAN_API_KEY no configurada", "skipped": True}
    try:
        import shodan
        api = shodan.Shodan(api_key)
        result: dict[str, Any] = {"domain": domain}
        try:
            dns_info = api.dns.resolve(domain)
            result["ip"] = dns_info.get("ip")
        except Exception as e:
            result["dns_error"] = str(e)
        ips = []
        if result.get("ip"):
            ips = [result["ip"]]
        try:
            for sub in ["www", "mail", "ftp", "admin", "api"]:
                try:
                    sd = api.dns.resolve(f"{sub}.{domain}")
                    if sd.get("ip") and sd["ip"] not in ips:
                        ips.append(sd["ip"])
                except Exception:
                    pass
        except Exception:
            pass
        hosts = []
        for ip in ips[:5]:
            try:
                host = api.host(ip)
                hosts.append({
                    "ip": ip,
                    "ports": host.get("ports", []),
                    "hostnames": host.get("hostnames", []),
                    "org": host.get("org"),
                    "isp": host.get("isp"),
                    "os": host.get("os"),
                    "country": host.get("country_name"),
                    "city": host.get("city"),
                    "vulns": list(host.get("vulns", {}).keys())[:10],
                })
            except Exception:
                pass
        result["hosts"] = hosts
        return result
    except ImportError:
        return {"error": "shodan library not installed"}
    except Exception as e:
        return {"error": str(e)}


def run_censys(domain: str) -> dict:
    api_id = _get_key("CENSYS_API_ID")
    api_secret = _get_key("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        return {"error": "CENSYS_API_ID/CENSYS_API_SECRET no configurados", "skipped": True}
    try:
        from censys.search import Certificates, Hosts
        result: dict[str, Any] = {"domain": domain}
        try:
            certs = Certificates(api_id=api_id, api_secret=api_secret)
            query = f"names: {domain}"
            cert_results = list(certs.search(query, per_page=5, pages=1))
            parsed_certs = []
            for c in cert_results[:5]:
                parsed = {
                    "fingerprint_sha256": c.get("fingerprint_sha256", "")[:24] + "...",
                    "issuer": c.get("parsed", {}).get("issuer", {}),
                    "validity": c.get("parsed", {}).get("validity", {}),
                    "names": c.get("parsed", {}).get("names", [])[:5],
                }
                parsed_certs.append(parsed)
            result["certificates"] = parsed_certs
        except Exception as e:
            result["certificates_error"] = str(e)
        try:
            hosts_api = Hosts(api_id=api_id, api_secret=api_secret)
            host_results = list(hosts_api.search(query, per_page=5, pages=1))
            parsed_hosts = []
            for h in host_results[:5]:
                parsed_hosts.append({
                    "ip": h.get("ip"),
                    "location": h.get("location", {}),
                    "services": [
                        {"port": s.get("port"), "service_name": s.get("service_name"), "transport_protocol": s.get("transport_protocol")}
                        for s in (h.get("services") or [])[:5]
                    ],
                })
            result["hosts"] = parsed_hosts
        except Exception as e:
            result["hosts_error"] = str(e)
        if not result.get("certificates") and not result.get("hosts"):
            return {"error": "Sin resultados de Censys"}
        return result
    except ImportError:
        return {"error": "censys library not installed"}
    except Exception as e:
        return {"error": str(e)}


def run_theharvester(domain: str) -> dict:
    result: dict[str, Any] = {"domain": domain}
    harvester_cmd = None
    for cmd in ["theHarvester", "theharvester", "theHarvester.exe"]:
        try:
            subprocess.run([cmd, "--help"], capture_output=True, timeout=10)
            harvester_cmd = cmd
            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    if not harvester_cmd:
        return {"error": "theHarvester no encontrado en PATH", "skipped": True}
    sources = ["baidu", "bing", "crtsh", "google", "yahoo", "dnsdumpster"]
    combined: dict[str, list[str]] = {"emails": [], "subdomains": [], "hosts": [], "ips": []}
    for src in sources:
        try:
            proc = subprocess.run(
                [harvester_cmd, "-d", domain, "-b", src, "-l", "50"],
                capture_output=True, text=True, timeout=60,
            )
            out = proc.stdout + proc.stderr
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", out)
            for e in emails:
                if e not in combined["emails"]:
                    combined["emails"].append(e)
            hosts = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", out)
            for h in hosts:
                if h not in combined["ips"]:
                    combined["ips"].append(h)
            lines = out.splitlines()
            for line in lines:
                if line.startswith("[+]") and domain in line.lower():
                    parts = line.split()
                    for p in parts:
                        if p.endswith(f".{domain}") and p not in combined["subdomains"]:
                            combined["subdomains"].append(p)
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", p) and p not in combined["ips"]:
                            combined["ips"].append(p)
        except Exception as e:
            _log(f"theHarvester source {src} error: {e}")
    result["emails"] = combined["emails"][:50]
    result["subdomains"] = combined["subdomains"][:50]
    result["ips"] = combined["ips"][:20]
    result["sources_used"] = sources
    return result


def run_all(domain: str) -> dict:
    return {
        "whois": run_whois(domain),
        "dnsdumpster": run_dnsdumpster(domain),
        "shodan": run_shodan(domain),
        "censys": run_censys(domain),
        "theharvester": run_theharvester(domain),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
