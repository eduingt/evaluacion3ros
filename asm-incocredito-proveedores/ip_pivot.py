from __future__ import annotations

import json
import socket
import time
from typing import Any

import dns.resolver
import requests

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"


def _ptr_lookup(ip: str) -> list[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return [name] if name else []
    except (socket.herror, socket.gaierror):
        return []


def _crt_sh_by_ip(ip: str) -> list[dict[str, Any]]:
    try:
        r = requests.get(
            f"https://crt.sh/?q={ip}&output=json",
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            seen: set[str] = set()
            results: list[dict[str, Any]] = []
            for entry in data[:100]:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n and n not in seen and "*" not in n:
                        seen.add(n)
                        results.append({
                            "fqdn": n,
                            "issuer": entry.get("issuer_name", ""),
                            "not_after": entry.get("not_after", ""),
                        })
            return results
    except Exception:
        pass
    return []


def _rdap_lookup(ip: str) -> dict[str, Any]:
    try:
        r = requests.get(
            f"https://rdap-bootstrap.arin.net/bootstrap/ip/{ip}",
            headers={"User-Agent": USER_AGENT},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            entities = []
            for e in data.get("entities", [])[:5]:
                name = ""
                for vcard in e.get("vcardArray", []):
                    if isinstance(vcard, list):
                        for item in vcard:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                name = item[3]
                entities.append({
                    "handle": e.get("handle", ""),
                    "name": name,
                    "roles": e.get("roles", []),
                })
            return {
                "handle": data.get("handle", ""),
                "name": data.get("name", ""),
                "country": data.get("country", ""),
                "entities": entities,
            }
    except Exception:
        pass
    return {}


def _reverse_dns_brute(ip_prefix: str) -> list[str]:
    found: list[str] = []
    ip_parts = ip_prefix.strip().split(".")
    if len(ip_parts) < 3:
        return found
    base = ".".join(ip_parts[:3])
    import concurrent.futures

    def _check(last: int) -> str | None:
        target = f"{base}.{last}"
        try:
            name, _, _ = socket.gethostbyaddr(target)
            return name
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(_check, i): i for i in range(1, 255)}
        for future in concurrent.futures.as_completed(futures, timeout=30):
            result = future.result()
            if result:
                found.append(result)
    return found


def pivot_ip(ip: str) -> dict[str, Any]:
    ptr = _ptr_lookup(ip)
    time.sleep(0.5)
    crt_entries = _crt_sh_by_ip(ip)
    rdap = _rdap_lookup(ip)
    fqdns_from_crt = list({e["fqdn"] for e in crt_entries})
    return {
        "ip": ip,
        "ptr": ptr,
        "fqdns_from_crt": fqdns_from_crt,
        "crt_entries": crt_entries[:30],
        "rdap": rdap,
    }


def pivot_ips(ips: list[str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for ip in ips:
        try:
            result = pivot_ip(ip)
            results.append(result)
        except Exception:
            continue
    return results
