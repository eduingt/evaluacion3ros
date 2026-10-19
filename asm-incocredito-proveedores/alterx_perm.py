"""alterx-lite: descubrimiento de subdominios por permutacion de nombres conocidos.

Inspirado en el patron `alterx` + `dnsx` de EasyEASM (pkg/active). No duplica el
brute de wordlist (`subdomain_brute.py`): genera variantes de los nombres ya
descubiertos (dev/prod, swap de separadores, sufijos numericos) y las resuelve
por DNS, filtrando wildcard DNS. Solo quimica pasiva/semi-activa (consultas a
resolvers publicos), acorde al nivel >= 2 del escaner.
"""
from __future__ import annotations

import concurrent.futures
import random
import time
from typing import Any

import dns.resolver

from subdomain_brute import RESOLVERS

_ENV = [
    "dev", "test", "staging", "stage", "uat", "qa", "prod", "preprod",
    "new", "old", "alpha", "beta", "demo", "internal", "admin", "api",
    "app", "web", "www", "portal", "secure", "vpn", "git", "ci",
    "cdn", "static", "data", "db",
]

_MAX_CANDIDATES = 600
_MAX_PER_SEED = 120
_SUFFIXES = ["1", "2", "3", "01"]


def _host_of(s: Any) -> str:
    if isinstance(s, dict):
        return (s.get("fqdn") or s.get("host") or s.get("name")
                or s.get("subdomain") or s.get("domain") or "")
    return s or ""


def _labels(seeds: list[dict[str, Any]] | list[str], apex: str) -> set[str]:
    out: set[str] = set()
    for s in seeds:
        fqdn = _host_of(s)
        fqdn = fqdn.strip().lower().rstrip(".")
        if not fqdn.endswith("." + apex) or fqdn == apex:
            continue
        label = fqdn[: -(len(apex) + 1)]
        if label and "." not in label and len(label) <= 50:
            out.add(label)
    return out


def _variants(label: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def add(x: str) -> None:
        if x and x != label and x not in seen and len(x) <= 63 and ".." not in x:
            seen.add(x)
            out.append(x)

    parts = label.split("-")
    for n in _SUFFIXES:
        add(f"{label}{n}")
        add(f"{label}-{n}")
    if len(parts) > 1:
        add("-".join(reversed(parts)))
        for i, p in enumerate(parts):
            if p in _ENV:
                for e in _ENV:
                    if e != p:
                        add("-".join(parts[:i] + [e] + parts[i + 1:]))
    for e in _ENV:
        if e == label:
            continue
        add(f"{e}-{label}")
        add(f"{label}-{e}")
    return out[:_MAX_PER_SEED]


def _wildcard(domain: str, resolver_ips: list[str]) -> set[str]:
    probe = f"dns-verify-{random.randint(100000, 999999)}.{domain}"
    r = _resolve(probe, resolver_ips)
    return set(r["ips"]) if r else set()


def _resolve(fqdn: str, resolver_ips: list[str]) -> dict[str, Any] | None:
    for resolver_ip in random.sample(resolver_ips, min(3, len(resolver_ips))):
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [resolver_ip]
            r.timeout = 3
            r.lifetime = 4
            answers = r.resolve(fqdn, "A", lifetime=4)
            ips = [str(a) for a in answers]
            cname = ""
            try:
                cname = str(r.resolve(fqdn, "CNAME", lifetime=3)[0].target)
            except Exception:
                pass
            return {"fqdn": fqdn, "ips": ips, "cname": cname}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            continue
        except Exception:
            continue
    return None


def permute_subdomains(domain: str, seeds: list[dict[str, Any]] | list[str],
                       existing: set[str] | None = None,
                       max_workers: int = 50, timeout: int = 45) -> dict[str, Any]:
    """Genera y resuelve permutaciones de los labels conocidos bajo `domain`.

    Devuelve {"results": [...], "wildcard": bool, "generated": int, "tested": int}.
    Cada result: {"subdomain", "fqdn", "ips", "cname", "source"}.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {"results": [], "wildcard": False, "generated": 0, "tested": 0}

    existing = {x.lower().rstrip(".") for x in (existing or set())}
    labels = _labels(seeds, domain)
    if not labels:
        return {"results": [], "wildcard": False, "generated": 0, "tested": 0}

    candidates: dict[str, set[str]] = {}
    for label in labels:
        for var in _variants(label):
            fqdn = f"{var}.{domain}"
            if fqdn in existing:
                continue
            candidates.setdefault(fqdn, set()).add(label)
            if len(candidates) >= _MAX_CANDIDATES:
                break
        if len(candidates) >= _MAX_CANDIDATES:
            break

    resolver_ips = RESOLVERS[:]
    random.shuffle(resolver_ips)
    wc_ips = _wildcard(domain, resolver_ips)

    results: list[dict[str, Any]] = []
    tested = 0
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_resolve, fqdn, resolver_ips): fqdn for fqdn in candidates}
        for future in concurrent.futures.as_completed(futures, timeout=timeout + 10):
            if time.time() - start > timeout:
                break
            fqdn = futures[future]
            tested += 1
            try:
                res = future.result()
            except Exception:
                res = None
            if not res:
                continue
            if wc_ips and set(res["ips"]).issubset(wc_ips):
                continue
            src = sorted(candidates[fqdn])[0]
            results.append({
                "subdomain": fqdn[: -(len(domain) + 1)],
                "fqdn": fqdn,
                "ips": res["ips"],
                "cname": res["cname"],
                "source": f"permutation:{src}",
            })

    results.sort(key=lambda x: x["fqdn"])
    return {
        "results": results,
        "wildcard": bool(wc_ips),
        "generated": len(candidates),
        "tested": tested,
    }
