#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent

LOGO_B64 = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjE3IiBoZWlnaHQ9IjYxIiB2aWV3Qm94PSIwIDAgMjE3IDYxIiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTI1Ljg3NTYgMjYuODM4NEMyNi4wMDEzIDI3LjMyNTcgMjYuNDkxNiAyNy41NzcgMjYuOTg5NyAyNy40MTE4QzMxLjA3MzUgMjYuMTU3NSAzNS4xNjc0IDI1LjI5OTEgMzkuMzkxNCAyNC42NzQ3QzM5Ljg3NTUgMjQuNjEgNDAuMTQwNCAyNC4xMTAzIDM5Ljk2MjQgMjMuNjA5MUMzOS41ODc0IDIyLjU1MjkgMzkuMzk3OCAyMi4wMjYyIDM5LjAxNDUgMjAuOTc2MkMzOC44NTE4IDIwLjUzMDMgMzguNDExNiAyMC4yMzc5IDM3Ljk2MTEgMjAuMjg2N0MzMy44MzMgMjAuNzk0NyAyOS44NDQ3IDIxLjU0NSAyNS44NDc3IDIyLjcwMDdDMjUuMzI3MiAyMi44NjM4IDI1LjAwNzYgMjMuNDQ1NiAyNS4xMzg4IDIzLjk2MTdDMjUuNDMwOSAyNS4xMTA3IDI1LjU3ODMgMjUuNjg1OSAyNS44NzU2IDI2LjgzODRaIiBmaWxsPSIjRkQwRDFCIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNDIuNDMwNSAyNy40MTU3QzQyLjI3MiAyNi45NDM3IDQxLjg0MTggMjYuNjI4MiA0MS40MTY0IDI2LjY4MzhDMzQuOTUzOCAyNy41MDYxIDI4LjY2MDkgMjkuMTAwOCAyMi42OTM2IDMxLjczNjRDMjIuMjU4MyAzMS45NDE5IDIxLjk5NzIgMzIuNDg4NCAyMi4wODg0IDMyLjk3QzIyLjMyMjQgMzQuMjAxOCAyMi40NDA0IDM0LjgxODMgMjIuNjc5MiAzNi4wNTI0QzIyLjc4MTIgMzYuNTgwMSAyMy4yNzUgMzYuODIzMSAyMy43NjIgMzYuNTg2MUMyOS44MjM0IDMzLjgxNTEgMzYuMjI4OCAzMi4wNTA4IDQyLjc5OTkgMzAuOTk4OEM0My4yMTc1IDMwLjkzMDUgNDMuNDMwNSAzMC40NTI4IDQzLjI3MDcgMjkuOTYwNkM0Mi45Mzk3IDI4Ljk0MDEgNDIuNzcxNSAyOC40MzEyIDQyLjQzMDUgMjcuNDE1N1oiIGZpbGw9IiNGRDBEMUIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik00Mi40MDk1IDM0LjI5NDVDNDIuMjQ5MyAzMy43OTA3IDQxLjc4MTIgMzMuNDYyIDQxLjMzNjQgMzMuNTUzM0MzNy4zMDEyIDM0LjQyNzIgMzMuMzU3IDM1LjQ4MDQgMjkuNDQ5NyAzNi44MjA1QzI4Ljk1NDIgMzcuMDAyMSAyOC42NzUxIDM3LjUyMzkgMjguODA1MyAzOC4wMDM5QzI5LjExNTkgMzkuMTQ3NSAyOS4yNzIzIDM5LjcyMDIgMjkuNTg2NyA0MC44Njc0QzI5LjczNDQgNDEuNDA2MyAzMC4zNDA0IDQxLjY4MiAzMC44OTg2IDQxLjQ2OTdDMzQuODA0NCA0MC4wNzM1IDM4Ljc0OTUgMzguODU0NCA0Mi43ODA5IDM3Ljg3N0M0My4xNjc1IDM3Ljc4MzIgNDMuMzU3OCAzNy4zMzA2IDQzLjIxNDEgMzYuODYzN0M0Mi44OTY3IDM1LjgzMzggNDIuNzM1OSAzNS4zMTk5IDQyLjQwOTUgMzQuMjk0NVoiIGZpbGw9IiNGRDBEMUIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNzIuODUzIDQxLjI3MDhDMTc1LjE4MiA0MS4yNzA4IDE3Ny4wMjYgMzkuNDI2NiAxNzcuMDI2IDM3LjA5NzRDMTc3LjAyNiAzNC43NjgyIDE3NS4xODIgMzIuOTI0MSAxNzIuODUzIDMyLjkyNDFDMTcwLjUyNCAzMi45MjQxIDE2OC42OCAzNC43NjgyIDE2OC42OCAzNy4wOTc0QzE2OC42OCAzOS40MjY2IDE3MC41MjQgNDEuMjcwOCAxNzIuODUzIDQxLjI3MDhaTTE3Mi44NTMgMzMuODQzNkMxNzQuNjM3IDMzLjg0MzYgMTc2LjEwNiAzNS4zMTI5IDE3Ni4xMDYgMzcuMDk3NEMxNzYuMTA2IDM4Ljg4MiAxNzQuNjM3IDQwLjM1MTMgMTcyLjg1MyA0MC4zNTEzQzE3MS4wNjkgNDAuMzUxMyAxNjkuNiAzOC44ODIgMTY5LjYgMzcuMDk3NEMxNjkuNiAzNS4zMTI5IDE3MS4wNjkgMzMuODQzNiAxNzIuODUzIDMzLjg0MzZaIiBmaWxsPSIjRkQwRDFCIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTcyLjg1MyA0MS4yNzA4QzE3NS4xODIgNDEuMjcwOCAxNzcuMDI2IDM5LjQyNjYgMTc3LjAyNiAzNy4wOTc0QzE3Ny4wMjYgMzQuNzY4MiAxNzUuMTgyIDMyLjkyNDEgMTcyLjg1MyAzMi45MjQxQzE3MC41MjQgMzIuOTI0MSAxNjguNjggMzQuNzY4MiAxNjguNjggMzcuMDk3NEMxNjguNjggMzkuNDI2NiAxNzAuNTI0IDQxLjI3MDggMTcyLjg1MyA0MS4yNzA4Wk0xNzIuODUzIDMzLjg0MzZDMTc0LjYzNyAzMy44NDM2IDE3Ni4xMDYgMzUuMzEyOSAxNzYuMTA2IDM3LjA5NzRDMTc2LjEwNiAzOC44ODIgMTc0LjYzNyA0MC4zNTEzIDE3Mi44NTMgNDAuMzUxM0MxNzEuMDY5IDQwLjM1MTMgMTY5LjYgMzguODgyIDE2OS42IDM3LjA5NzRDMTY5LjYgMzUuMzEyOSAxNzEuMDY5IDMzLjg0MzYgMTcyLjg1MyAzMy44NDM2WiIgZmlsbD0iI0ZEMEQxQiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTE4Mi43MDIgMjguMzI2NUwxODIuNzAyIDQwLjg0MUwxODEuNzgyIDQwLjg0MUwxODEuNzgyIDI4LjMyNjV6IiBmaWxsPSIjRkQwRDFCIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTg3LjI3MiAzMy4yNjQ3QzE4Ni41MDIgMzIuNDk0NyAxODUuNTcyIDMyLjEwOTcgMTg0LjQ4MiAzMi4xMDk3QzE4My4zOTIgMzIuMTA5NyAxODIuNDYyIDMyLjQ5NDcgMTgxLjY5MiAzMy4yNjQ3QzE4MC45MjIgMzQuMDM0NyAxODAuNTM3IDM0Ljk2NDcgMTgwLjUzNyAzNi4wNTQ3QzE4MC41MzcgMzcuMTQ0NyAxODAuOTIyIDM4LjA3NDcgMTgxLjY5MiAzOC44NDQ3QzE4Mi40NjIgMzkuNjE0NyAxODMuMzkyIDM5Ljk5OTcgMTg0LjQ4MiAzOS45OTk3QzE4NS41NzIgMzkuOTk5NyAxODYuNTAyIDM5LjYxNDcgMTg3LjI3MiAzOC44NDQ3QzE4OC4wNDIgMzguMDc0NyAxODguNDI3IDM3LjE0NDcgMTg4LjQyNyAzNi4wNTQ3QzE4OC40MjcgMzQuOTY0NyAxODguMDQyIDM0LjAzNDcgMTg3LjI3MiAzMy4yNjQ3Wk0xODYuNTAyIDM4LjA3NDdDMTg2LjAyMiAzOC41NTQ3IDE4NS4zOTIgMzguNzk0NyAxODQuNDgyIDM4Ljc5NDdDMTgzLjU3MiAzOC43OTQ3IDE4Mi45NDIgMzguNTU0NyAxODIuNDYyIDM4LjA3NDdDMTgxLjk4MiAzNy41OTQ3IDE4MS43NDIgMzYuOTY0NyAxODEuNzQyIDM2LjA1NDdDMTgxLjc0MiAzNS4xNDQ3IDE4MS45ODIgMzQuNTE0NyAxODIuNDYyIDM0LjAzNDdDMTgyLjk0MiAzMy41NTQ3IDE4My41NzIgMzMuMzE0NyAxODQuNDgyIDMzLjMxNDdDMTg1LjM5MiAzMy4zMTQ3IDE4Ni4wMjIgMzMuNTU0NyAxODYuNTAyIDM0LjAzNDdDMTg2Ljk4MiAzNC41MTQ3IDE4Ny4yMjIgMzUuMTQ0NyAxODcuMjIyIDM2LjA1NDdDMTg3LjIyMiAzNi45NjQ3IDE4Ni45ODIgMzcuNTk0NyAxODYuNTAyIDM4LjA3NDdaIiBmaWxsPSIjRkQwRDFCIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTkzLjc1MyAzMi4xMDk3QzE5Mi4yMjMgMzIuMTA5NyAxOTAuOTkzIDMyLjYyOTcgMTkwLjA2MyAzMy42Njk3QzE4OS4xMzMgMzQuNzA5NyAxODguNjY4IDM2LjAyOTcgMTg4LjY2OCAzNy42Mjk3QzE4OC42NjggMzkuMTc5NyAxODkuMTEzIDQwLjQ1OTcgMTkwLjAwMyA0MS40Njk3QzE5MC44OTMgNDIuNDc5NyAxOTIuMDMzIDQyLjk4NDcgMTkzLjQyMyA0Mi45ODQ3QzE5NC40NzMgNDIuOTg0NyAxOTUuMzQzIDQyLjczOTcgMTk2LjAzMyA0Mi4yNDk3QzE5Ni43MjMgNDEuNzU5NyAxOTcuMTUzIDQxLjE0OTcgMTk3LjMyMyA0MC40MTk3TDE5Ni40MTMgNDAuMTQ5N0MxOTYuMjczIDQwLjY2OTcgMTk1Ljk3MyA0MS4wOTk3IDE5NS41MTMgNDEuNDM5N0MxOTUuMDUzIDQxLjc3OTcgMTk0LjQ2MyA0MS45NDk3IDE5My43NDMgNDEuOTQ5N0MxOTIuNzUzIDQxLjk0OTcgMTkxLjkzMyA0MS42MDk3IDE5MS4yODMgNDAuOTI5N0MxOTAuNjMzIDQwLjI0OTcgMTkwLjMwOCAzOS4zNTk3IDE5MC4zMDggMzguMjU5N0wxOTcuMjczIDM4LjI1OTdMMTk3LjI3MyAzNy41NDk3QzE5Ny4yNzMgMzUuOTE5NyAxOTYuODEzIDM0LjU4OTcgMTk1Ljg5MyAzMy41NTk3QzE5NC45NzMgMzIuNTI5NyAxOTMuODMzIDMyLjEwOTcgMTkyLjQ4MyAzMi4xMDk3SDE5My43NTNaTTE5MC4zMzggMzcuMzk5N0MxOTAuNDQ4IDM2LjU3OTcgMTkwLjc4OCAzNS45MTk3IDE5MS4zNTggMzUuNDE5N0MxOTEuOTI4IDM0LjkxOTcgMTkyLjYyOCAzNC42Njk3IDE5My40NTggMzQuNjY5N0MxOTQuMjU4IDM0LjY2OTcgMTk0LjkzOCAzNC45MTk3IDE5NS40OTggMzUuNDE5N0MxOTYuMDU4IDM1LjkxOTcgMTk2LjM4OCAzNi41Nzk3IDE5Ni40ODggMzcuMzk5N0wxOTAuMzM4IDM3LjM5OTdaIiBmaWxsPSIjRkQwRDFCIi8+Cjwvc3ZnPg=="

def esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)

def parse_matrix_row(m: dict[str, Any]) -> dict[str, Any]:
    spf_dmarc = str(m.get("spf_dmarc", ""))
    spf_ok = "SPF:ok" in spf_dmarc
    spf_missing = "SPF:missing" in spf_dmarc
    spf_partial = "SPF:partial" in spf_dmarc
    dm = re.search(r"DMARC:(\S+)", spf_dmarc)
    dmarc = dm.group(1) if dm else "-"
    https = m.get("https")
    https_ok = isinstance(https, int) and 200 <= https < 400
    dns = m.get("dns") or {}
    starttls_results = dns.get("starttls_results") or []
    takeover_risks = m.get("takeover_risks") or []
    return {
        **m,
        "https_ok": https_ok,
        "spf_ok": spf_ok,
        "spf_missing": spf_missing,
        "spf_partial": spf_partial,
        "dmarc_label": dmarc,
        "dnssec_ok": bool(dns.get("dnssec_ok")),
        "ip_reputation_clean": len(dns.get("ip_reputation") or []) == 0,
        "starttls_ok": all(s.get("starttls") for s in starttls_results) if starttls_results else False,
        "starttls_count": len(starttls_results),
        "takeover_risks": takeover_risks,
        "takeover_count": len(takeover_risks),
        "takeover_vulnerable": any(r.get("vulnerable") for r in takeover_risks),
        "csp_findings": m.get("csp_findings") or [],
        "csp_finding_count": len(m.get("csp_findings") or []),
        "cookie_findings": m.get("cookie_findings") or [],
        "cookie_insecure": any(f.get("severity") in ("high",) for f in (m.get("cookie_findings") or [])),
        "supply_reputation_dnsbl_count": (m.get("supply_chain_reputation") or {}).get("dnsbl_count", 0),
        "supply_reputation_urlhaus_count": (m.get("supply_chain_reputation") or {}).get("urlhaus_count", 0),
        "supply_reputation_clean": (m.get("supply_chain_reputation") or {}).get("clean", True),
    }

def domain_score(p: dict[str, Any]) -> float:
    pts = 0.0
    h = p.get("https", {}) or {}
    headers = h.get("headers") or {}
    tls = p.get("tls") or {}
    dns = p.get("dns") or {}
    if p.get("port_443", {}).get("open"): pts += 8
    if p.get("port_80", {}).get("open"): pts += 2
    if isinstance(h.get("status_code"), int) and 200 <= h["status_code"] < 400: pts += 18
    if headers.get("strict-transport-security"): pts += 12
    if headers.get("content-security-policy") or headers.get("content-security-policy-report-only"): pts += 10
    if headers.get("x-frame-options"): pts += 6
    if headers.get("x-content-type-options"): pts += 4
    if tls.get("negotiated_version") and not tls.get("error"): pts += 14
    if tls.get("tls13_only_ok"): pts += 6
    spf = str(dns.get("spf_record", ""))
    if "-all" in spf.replace(" ", "").lower(): pts += 10
    elif spf: pts += 5
    if dns.get("dmarc_policy") in ("reject", "quarantine"): pts += 10
    elif dns.get("dmarc_policy"): pts += 5
    starttls = dns.get("starttls_results") or []
    if starttls and all(s.get("starttls") for s in starttls): pts += 5
    elif starttls: pts += 1
    if not dns.get("ip_reputation"): pts += 8
    elif len(dns["ip_reputation"]) <= 2: pts += 4
    urlhaus = p.get("urlhaus") or {}
    if not urlhaus.get("malicious"): pts += 5
    elif urlhaus.get("error"): pts += 1
    if not p.get("vulnerabilities"): pts += 5
    leaks = p.get("credential_leaks") or []
    if not leaks or all("error" in l for l in leaks): pts += 5
    if not p.get("typosquatting"): pts += 5
    patching = p.get("patching") or []
    eol_count = sum(1 for x in patching if x.get("status") in ("eol",))
    if eol_count == 0: pts += 8
    elif eol_count <= 2: pts += 4
    supply = p.get("supply_chain") or []
    if len(supply) == 0: pts += 5
    elif len(supply) <= 3: pts += 2
    takeover = p.get("takeover_risks") or []
    vulnerable = any(r.get("vulnerable") for r in takeover)
    if not takeover: pts += 6
    elif not vulnerable: pts += 3
    csp_f = p.get("csp_findings") or []
    if not csp_f: pts += 5
    elif all(f.get("severity") in ("low", "medium") for f in csp_f): pts += 2
    cookie_f = p.get("cookie_findings") or []
    cookie_insecure = any(f.get("severity") in ("high",) for f in cookie_f)
    if not cookie_f: pts += 5
    elif not cookie_insecure: pts += 2
    scr = p.get("supply_chain_reputation") or {}
    scr_dnsbl = scr.get("dnsbl_count", 0)
    scr_urlhaus = scr.get("urlhaus_count", 0)
    if scr_dnsbl == 0 and scr_urlhaus == 0: pts += 5
    elif scr_dnsbl <= 2 and scr_urlhaus == 0: pts += 2
    return round(min(pts, 100), 1)

def grade_letter(s: float) -> str:
    return "F" if s < 30 else "E" if s < 45 else "D" if s < 60 else "C" if s < 75 else "B" if s < 90 else "A"

FACTOR_DEFS = [
    ("SEGURIDAD DE APLICACION WEB", "web_security", "El modulo de Seguridad de aplicacion web utiliza inteligencia sobre amenazas entrantes por vulnerabilidades conocidas. La puntuacion determina la probabilidad de una proxima filtracion en la aplicacion web y comprueba cabeceras de seguridad, cookies y configuracion de recursos."),
    ("CUBIT SCORE", "cubit", "Este modulo patentado mide distintos problemas de seguridad que una empresa podria tener. Comprueba fuentes de inteligencia de amenazas en busca de IP/senalizaciones."),
    ("ESTADO DE DNS", "dns_health", "Este modulo mide el estado y la configuracion de los ajustes DNS de una empresa, incluyendo SPF, DMARC, DNSSEC, DKIM, DANE y STARTTLS en MX."),
    ("SEGURIDAD DE PUNTOS DE CONEXION", "endpoint", "Este modulo realiza un seguimiento de los puntos de identificacion extraidos de metadatos del sistema operativo, navegador web y complementos."),
    ("HACKER CHATTER", "hacker", "Este modulo es un sistema automatizado de recopilacion y agregacion para el analisis de multiples flujos de charla de piratas informaticos en sitios clandestinos."),
    ("REPUTACION DE IP", "ip_reputation", "Este modulo utiliza infraestructura de sistemas sinkhole y fuentes OSINT para detectar IPs listadas en DNSBL y malware."),
    ("FILTRACION DE INFORMACION", "leak", "Este modulo usa capacidades de monitorizacion de la Deep Web para identificar credenciales comprometidas y filtraciones de datos."),
    ("SEGURIDAD DE RED", "network", "Este modulo comprueba conjuntos de datos publicos en busca de puertos abiertos de alto riesgo, protocolos debiles y configuraciones TLS inseguras."),
    ("CADENCIA DE APLICACION DE REVISIONES", "patching", "Este modulo analiza la rapidez con la que una empresa reacciona a las vulnerabilidades para medir las practicas de aplicacion de revisiones."),
    ("INGENIERIA SOCIAL", "social", "Este modulo analiza la exposicion a campanas de phishing, presencia de dominios sospechosos, configuraciones de seguridad email y riesgos de subdomain takeover."),
]

def build_report(asm: dict[str, Any], title: str, subtitle: str, version: str) -> str:
    providers = asm.get("providers") or []
    matrix = [parse_matrix_row(p) for p in providers]
    scores = [domain_score(p) for p in matrix]
    avg = round(sum(scores) / len(scores), 1) if scores else 0
    grade = grade_letter(avg)
    trust = int(avg)
    n = len(matrix)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    gen = asm.get("generated_at", now)

    # Compute factor scores and issues per provider
    factor_data: dict[str, dict] = {}
    for fname, fkey, fdesc in FACTOR_DEFS:
        factor_data[fname] = {"fkey": fkey, "desc": fdesc, "providers": {}}

    for p in matrix:
        dom = str(p.get("dominio", "?"))
        dns = p.get("dns") or {}
        h = p.get("https", {}) or {}
        headers = h.get("headers") or {}
        tls = p.get("tls") or {}
        issues_found = False

        # Web Application Security
        ws_issues = []
        if not headers.get("strict-transport-security"):
            ws_issues.append(("ALTA", "Falta la cabecera HSTS", "HTTP Strict Transport Security (HSTS) es un mecanismo de seguridad web que ayuda a proteger los sitios web contra ataques de tipo man-in-the-middle. Sin HSTS, los atacantes podrian aprovechar vulnerabilidades tales como degradacion de protocolos o secuestro de cookies.", "Configure su servidor web para incluir el encabezado Strict-Transport-Security con un max-age adecuado (ej: max-age=31536000; includeSubDomains).", -12))
        if not (headers.get("content-security-policy") or headers.get("content-security-policy-report-only")):
            ws_issues.append(("ALTA", "Falta la politica de seguridad de contenido (CSP)", "No implementar una CSP expone las aplicaciones web a ataques de scripts de sitios (XSS). Sin CSP, agentes malintencionados pueden inyectar y ejecutar scripts daninos.", "Implemente una politica de seguridad de contenido mediante la configuracion de encabezados HTTP, definiendo fuentes de confianza para scripts, estilos e imagenes.", -9))
        if not headers.get("x-frame-options"):
            ws_issues.append(("MEDIA", "Falta X-Frame-Options", "Sin X-Frame-Options, el sitio es vulnerable a ataques de clickjacking, donde un atacante puede incrustar el sitio en un iframe y enganar a los usuarios.", "Configure el encabezado X-Frame-Options con valor DENY o SAMEORIGIN para evitar la inclusion en iframes.", -6))
        if not headers.get("x-content-type-options"):
            ws_issues.append(("BAJA", "Falta X-Content-Type-Options", "No usar el encabezado X-Content-Type-Options permite a los navegadores interpretar contenido basandose en heuristicas, lo que puede generar vulnerabilidades MIME.", "Configure el encabezado X-Content-Type-Options con el valor nosniff.", -0.2))
        csp_findings = p.get("csp_findings") or []
        high_csp = [f for f in csp_findings if f.get("severity") == "high"]
        for f in high_csp[:3]:
            ws_issues.append(("ALTA", f"CSP debil: {f.get('directive','?')}", f.get("description", "Directiva CSP insegura o ausente."), "Revise y endurezca la politica CSP eliminando unsafe-inline/unsafe-eval, comodines y fuentes que permitan bypass.", -9))
        cookie_findings = p.get("cookie_findings") or []
        high_cookies = [f for f in cookie_findings if f.get("severity") == "high"]
        if high_cookies:
            ws_issues.append(("ALTA", "Cookies sin flags de seguridad", "Algunas cookies HTTP carecen de Secure, HttpOnly o SameSite, exponiendo a session hijacking y XSS.", "Establezca los flags Secure, HttpOnly y SameSite=Lax/Strict en todas las cookies.", -8))
        if ws_issues:
            factor_data["SEGURIDAD DE APLICACION WEB"]["providers"][dom] = ws_issues
            issues_found = True

        # DNS Health
        dns_issues = []
        spf = dns.get("spf_record")
        if not spf:
            dns_issues.append(("ALTA", "Falta registro SPF", "Sin SPF, los atacantes pueden falsificar la identidad del remitente de correo electronico (spoofing), facilitando ataques de phishing.", "Anada un registro SPF en su zona DNS que especifique los servidores autorizados para enviar correo en su dominio.", -15))
        elif "-all" not in str(spf).replace(" ", "").lower():
            dns_issues.append(("MEDIA", "SPF sin mecanismo -all", "SPF configurado pero sin el mecanismo -all, lo que permite falsificacion parcial de correo.", "Actualice su registro SPF para incluir -all al final, lo cual rechaza correos de servidores no autorizados.", -8))
        dmarc = dns.get("dmarc_policy")
        if not dmarc:
            dns_issues.append(("ALTA", "Falta DMARC", "Sin DMARC, no hay proteccion contra spoofing de dominio en correos, aumentando el riesgo de phishing.", "Configure un registro DMARC con politica reject o quarantine en su zona DNS.", -12))
        elif dmarc not in ("reject", "quarantine"):
            dns_issues.append(("MEDIA", f"DMARC en modo {dmarc} (debe ser reject/quarantine)", "DMARC configurado en modo None solo informa pero no protege contra spoofing.", "Cambie la politica DMARC a reject o quarantine para bloquear correos no autorizados.", -5))
        if not dns.get("dnssec_ok"):
            dns_issues.append(("MEDIA", "DNSSEC no configurado", "Sin DNSSEC, las respuestas DNS pueden ser manipuladas por atacantes (DNS spoofing/cache poisoning).", "Configure las firmas DNSSEC en su zona DNS para garantizar la integridad de las respuestas.", -5))
        starttls_ok = p.get("starttls_ok", False)
        starttls_count = p.get("starttls_count", 0)
        if starttls_count > 0 and not starttls_ok:
            dns_issues.append(("MEDIA", "STARTTLS no soportado en servidores MX", "Sin STARTTLS, las comunicaciones de correo entrante viajan en texto plano, exponiendo credenciales y contenido.", "Configure STARTTLS en todos los servidores de correo para cifrar las comunicaciones SMTP entrantes.", -5))
        if dns_issues:
            factor_data["ESTADO DE DNS"]["providers"][dom] = dns_issues
            issues_found = True

        # Network Security
        net_issues = []
        if not p.get("port_443", {}).get("open"):
            net_issues.append(("ALTA", "Puerto 443 cerrado o sin respuesta", "Sin servicio HTTPS detectable, el sitio no esta disponible de forma segura.", "Configure un servidor web con certificado SSL/TLS valido en el puerto 443.", -20))
        elif tls.get("error") or not tls.get("negotiated_version"):
            net_issues.append(("ALTA", f"Error TLS: {esc(tls.get('error','sin respuesta'))}", "El servicio SSL/TLS presenta errores de configuracion que imponen una comunicacion segura.", "Actualice la configuracion TLS del servidor, asegurando versiones modernas y cifrados fuertes.", -15))
        elif not tls.get("tls13_only_ok"):
            net_issues.append(("ALTA", "El servicio SSL/TLS admite un protocolo debil", "Usar versiones antiguas de TLS (1.0/1.1) expone a ataques como BEAST, POODLE y man-in-the-middle.", "Desactive TLS 1.0 y 1.1, mantenga solo TLS 1.2 y 1.3 con cifrados fuertes.", -6.5))
        if net_issues:
            factor_data["SEGURIDAD DE RED"]["providers"][dom] = net_issues
            issues_found = True

        # Subdomain Takeover (in Social Engineering factor)
        takeover_issues = []
        takeover_risks = p.get("takeover_risks") or []
        for r in takeover_risks:
            host = r.get("host", "?")
            cname = r.get("cname", "?")
            if r.get("vulnerable"):
                takeover_issues.append(("ALTA", f"Subdominio vulnerable a takeover: {host} -> {cname}", r.get("description", "CNAME colgante detectado."), "Investigue y elimine el registro CNAME del subdominio o configure el servicio externo correspondiente.", -15))
            else:
                takeover_issues.append(("MEDIA", f"Subdominio potencialmente vulnerable: {host} -> {cname}", r.get("description", "CNAME apunta a servicio externo."), "Verifique que el servicio externo este correctamente configurado y bajo su control.", -6))
        if takeover_issues:
            factor_data["INGENIERIA SOCIAL"]["providers"][dom] = takeover_issues
            issues_found = True

        # IP Reputation
        ip_issues = []
        ip_rep = dns.get("ip_reputation") or []
        if ip_rep:
            labels = [r.get("list","?") if isinstance(r,dict) else str(r) for r in ip_rep[:3]]
            ip_issues.append(("ALTA", f"IP listada en {len(ip_rep)} lista(s) negra(s): {', '.join(labels)}", "Las IPs del dominio aparecen en listas de reputacion negativa (DNSBL), lo que indica posible actividad maliciosa o compromiso previo.", "Revise las IPs afectadas, investigue la causa de la listacion y solicite la deslistacion tras mitigar el problema.", -15))
        urlhaus = p.get("urlhaus") or {}
        if urlhaus.get("malicious"):
            ip_issues.append(("ALTA", "Dominio reportado en URLhaus (distribucion de malware)", "El dominio ha sido reportado como distribuidor de malware segun la base de datos de Abuse.ch.", "Elimine el contenido malicioso, escanee el servidor en busca de compromisos y solicite la revision en URLhaus.", -20))
        scr = p.get("supply_chain_reputation") or {}
        scr_dnsbl = scr.get("dnsbl_count", 0)
        scr_urlhaus = scr.get("urlhaus_count", 0)
        if scr_dnsbl or scr_urlhaus:
            ip_issues.append(("ALTA", "Terceros (Supply Chain) con reputacion negativa", f"{scr_dnsbl} listing(s) DNSBL y {scr_urlhaus} dominio(s) en URLhaus detectados entre los terceros. Indica que IPs o dominios de la cadena de suministro estan comprometidos o listados como maliciosos.", "Revise las IPs y dominios de terceros detectados, investigue los listings y reemplace o aisle los recursos comprometidos.", -15))
        if ip_issues:
            factor_data["REPUTACION DE IP"]["providers"][dom] = ip_issues
            issues_found = True

        # Information Leak
        leak_issues = []
        leaks = p.get("credential_leaks") or []
        clean_leaks = [l for l in leaks if "error" not in l]
        if clean_leaks:
            leak_issues.append(("ALTA", "Filtracion de informacion detectada", f"{len(clean_leaks)} breach(es) encontrados. El dominio aparece en filtraciones de datos conocidas, exponiendo posibles credenciales o informacion sensible.", "Revise las credenciales filtradas, fuerce cambios de contrasenas e implemente autenticacion multifactor.", -20))
        if leak_issues:
            factor_data["FILTRACION DE INFORMACION"]["providers"][dom] = leak_issues
            issues_found = True

        # Patching Cadence
        patch_issues = []
        osv = p.get("vulnerabilities") or []
        if osv:
            patch_issues.append(("ALTA", f"Vulnerabilidad(es) detectada(s): {len(osv)} CVE(s)", "Se han detectado vulnerabilidades conocidas (CVEs) asociadas a las tecnologias y versiones identificadas en el servidor.", "Actualice las bibliotecas y software a las versiones mas recientes que corrijan las vulnerabilidades identificadas.", -10))
        patching = p.get("patching") or []
        eol = sum(1 for x in patching if x.get("status") in ("eol",))
        if eol > 0:
            patch_issues.append(("ALTA", f"{eol} tecnologia(s) en estado End-of-Life (EOL)", "Tecnologias sin soporte del fabricante no reciben parches de seguridad, exponiendo a vulnerabilidades conocidas.", "Actualice o reemplace las tecnologias EOL por versiones con soporte activo.", -8))
        if patch_issues:
            factor_data["CADENCIA DE APLICACION DE REVISIONES"]["providers"][dom] = patch_issues
            issues_found = True

        # Factors without data get empty issues (score 100)
        for fname, fkey, fdesc in FACTOR_DEFS:
            if fname not in ("SEGURIDAD DE APLICACION WEB", "ESTADO DE DNS", "SEGURIDAD DE RED", "REPUTACION DE IP", "FILTRACION DE INFORMACION", "CADENCIA DE APLICACION DE REVISIONES"):
                if dom not in factor_data[fname]["providers"]:
                    factor_data[fname]["providers"][dom] = []

    # Compute factor scores
    factor_score_map = {}
    for fname, fkey, fdesc in FACTOR_DEFS:
        provs = factor_data[fname]["providers"]
        total_impact = 0
        total_issues = 0
        for dom_issues in provs.values():
            for sev, tit, desc, rec, impact in dom_issues:
                total_impact += abs(impact)
                total_issues += 1
        score = max(0, 100 - total_impact)
        factor_score_map[fname] = (score, total_issues)

    # Action items table
    action_rows = ""
    for fname, fkey, fdesc in FACTOR_DEFS:
        for dom in sorted(factor_data[fname]["providers"]):
            for sev, tit, desc, rec, impact in factor_data[fname]["providers"][dom]:
                sev_cls = sev.lower()
                action_rows += f"""<tr>
  <td><span class="sev {sev_cls}">{esc(sev)}</span></td>
  <td>{esc(fname)}</td>
  <td class="num">{impact}</td>
  <td>{esc(tit)}<div class="muted small">{esc(desc[:200])}</div></td>
  <td class="num">1</td>
</tr>"""
    if not action_rows:
        action_rows = "<tr><td colspan='5' class='muted c'>No se encontraron problemas.</td></tr>"

    # Factor overview cards
    factor_cards = ""
    for fname, fkey, fdesc in FACTOR_DEFS:
        fscore, fcnt = factor_score_map[fname]
        sev_label = f"{fcnt} INCIDENCIA(S)" if fcnt else "NINGUNA INCIDENCIA"
        color = "#1a7d4f" if fscore >= 80 else "#b8860b" if fscore >= 60 else "#c0392b"
        bar_w = max(fscore, 5)
        factor_cards += f"""<div class="factor">
  <div class="factor-head">
    <span class="factor-score-num" style="color:{color}">{fscore}</span>
    <span class="factor-name">{esc(fname)}</span>
  </div>
  <div class="factor-bar"><div class="factor-fill" style="width:{bar_w}%;background:{color}"></div></div>
  <div class="factor-label">{sev_label}</div>
</div>"""

    # Per-factor deep-dive sections
    factor_details = ""
    for fname, fkey, fdesc in FACTOR_DEFS:
        fscore, fcnt = factor_score_map[fname]
        doms = factor_data[fname]["providers"]
        color = "#1a7d4f" if fscore >= 80 else "#b8860b" if fscore >= 60 else "#c0392b"

        # Group findings by severity
        alta = []
        media = []
        baja = []
        for dom in sorted(doms):
            for sev, tit, desc, rec, impact in doms[dom]:
                entry = (dom, tit, desc, rec, impact)
                if sev == "ALTA": alta.append(entry)
                elif sev == "MEDIA": media.append(entry)
                else: baja.append(entry)

        def render_findings_list(items: list) -> str:
            if not items:
                return '<p class="muted small" style="padding:8px 0">No hay problemas de esta gravedad.</p>'
            out = ""
            for dom, tit, desc, rec, impact in items:
                out += f"""<div class="finding">
  <div class="finding-title">{esc(tit)} <span class="finding-impact">{impact} IMPACTO EN EL SCORE</span></div>
  <div class="finding-domain">{esc(dom)}</div>
  <div class="finding-desc"><strong>Descripcion:</strong> {esc(desc)}</div>
  <div class="finding-rec"><strong>Recomendacion:</strong> {esc(rec)}</div>
</div>"""
            return out

        alta_html = render_findings_list(alta)
        media_html = render_findings_list(media)
        baja_html = render_findings_list(baja)

        no_issues = ""
        if not alta and not media and not baja:
            no_issues = '<p class="no-issues">No se encontro ningun problema</p>'

        factor_details += f"""<div class="factor-detail">
  <div class="fd-header">
    <span class="fd-score" style="background:{color}">{fscore}</span>
    <div><h3>{esc(fname)}</h3></div>
  </div>
  <div class="fd-desc">El modulo {esc(fname.lower())} utiliza inteligencia sobre amenazas para evaluar riesgos. {esc(fdesc)}</div>
  {no_issues}
  <div class="severity-block">
    <h4 class="sev-title alta">GRAVEDAD ALTA</h4>
    {alta_html}
    <h4 class="sev-title media">GRAVEDAD MEDIA</h4>
    {media_html}
    <h4 class="sev-title baja">GRAVEDAD BAJA</h4>
    {baja_html}
  </div>
</div>"""

    # Provider scores / domain details
    prov_sections = ""
    for p in matrix:
        dom = esc(p.get("dominio", "?"))
        score = domain_score(p)
        grade_p = grade_letter(score)
        gcol = {"A":"#1a7d4f","B":"#2d8a5e","C":"#b8860b","D":"#cc7a00","E":"#c0392b","F":"#b22222"}.get(grade_p, "#666")
        h = p.get("https", {}) or {}
        headers = h.get("headers") or {}
        tls = p.get("tls") or {}
        dns = p.get("dns") or {}

        prov_sections += f"""<div class="card">
  <div class="card-header">
    <div><h3>{esc(dom)}</h3><div class="meta">Score: {score} - Grado: {grade_p}</div></div>
    <div class="score-badge" style="background:{gcol}">{grade_p}</div>
  </div>
  <div class="kpi-row">
    <span><strong>HSTS:</strong> {"Si" if headers.get("strict-transport-security") else "No"}</span>
    <span><strong>Social:</strong> {esc(", ".join(p.get("social",{}).keys()) or "-")}</span>
    <span><strong>CSP:</strong> {"Si" if (headers.get("content-security-policy") or headers.get("content-security-policy-report-only")) else "No"}</span>
    <span><strong>CSP-W:</strong> {p.get("csp_finding_count", 0)}</span>
    <span><strong>COOK:</strong> {"Insecure" if p.get("cookie_insecure") else "OK"}</span>
    <span><strong>SPF/DMARC:</strong> {esc(p.get("spf_dmarc","-"))}</span>
    <span><strong>DNSSEC:</strong> {"Si" if dns.get("dnssec_ok") else "No"}</span>
    <span><strong>STARTTLS:</strong> {"Si" if p.get("starttls_ok") else ("No" if p.get("starttls_count", 0) > 0 else "N/A")}</span>
    <span><strong>TLS:</strong> {esc(tls.get("negotiated_version","-"))}</span>
    <span><strong>CVE:</strong> {len(p.get("vulnerabilities") or [])}</span>
    <span><strong>DNSBL:</strong> {len(dns.get("ip_reputation") or [])}</span>
    <span><strong>TAKEOVER:</strong> {esc(len(p.get("takeover_risks") or []))}</span>
    <span><strong>SC-REP:</strong> {"Clean" if p.get("supply_reputation_clean") else "Issues"}</span>
    <span><strong>Social:</strong> {esc(", ".join(p.get("social",{}).keys()) or "-")}</span>
  </div>
</div>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{esc(title)} v{esc(version)}</title>
<style>
:root {{
  --red:#FD0D1B; --red-dark:#C4000A; --red-light:#FF4D55;
  --dark:#2C2A29; --bg:#f5f5f5; --text:#1a1d21; --muted:#6c757d;
  --border:#ddd; --card:#ffffff;
  --blue:#005A9E; --teal:#008080;
  --good:#1a7d4f; --warn:#b8860b; --bad:#c0392b;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; font-size:13px; }}
.wrap {{ max-width:1000px; margin:0 auto; padding:0 0 40px; }}
.header {{
  background:linear-gradient(135deg, var(--red-dark) 0%, var(--red) 60%, var(--red-light) 100%);
  color:#fff; padding:20px 28px 16px;
  display:flex; align-items:center; gap:20px;
}}
.header .logo {{ height:42px; }}
.header .tech-by {{ font-size:11px; opacity:.75; text-transform:uppercase; letter-spacing:.1em; }}
.header h1 {{ margin:4px 0 2px; font-size:1.3rem; font-weight:700; letter-spacing:-0.01em; }}
.header .meta {{ margin:0; font-size:12px; opacity:.8; }}
.header .version {{ margin-left:auto; font-size:11px; opacity:.65; text-transform:uppercase; letter-spacing:.08em; }}
.content {{ padding:20px 28px; }}

h2.sec {{
  font-size:1rem; color:var(--blue); font-weight:600;
  border-bottom:2px solid var(--blue); padding-bottom:5px; margin:28px 0 14px;
  display:flex; align-items:center; gap:8px;
}}
h2.sec::before {{ content:""; display:inline-block; width:4px; height:18px; background:var(--blue); border-radius:2px; }}

.grade-hero {{
  display:flex; align-items:center; gap:16px;
  background:linear-gradient(135deg, var(--blue), var(--teal));
  color:#fff; padding:16px 20px; border-radius:8px; margin-bottom:14px;
}}
.grade-hero .letter {{ font-size:48px; font-weight:700; line-height:1; opacity:.95; }}
.grade-hero .details {{ font-size:12px; opacity:.85; }}
.grade-hero .trust-score {{ font-size:22px; font-weight:600; }}

.factors-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:8px; margin-bottom:14px; }}
.factor {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:10px 12px; }}
.factor-head {{ display:flex; align-items:baseline; gap:6px; margin-bottom:4px; }}
.factor-score-num {{ font-size:22px; font-weight:700; }}
.factor-name {{ font-size:11px; font-weight:600; flex:1; line-height:1.2; }}
.factor-bar {{ height:4px; background:#e9ecef; border-radius:2px; margin-bottom:3px; }}
.factor-fill {{ height:4px; border-radius:2px; }}
.factor-label {{ font-size:10px; color:var(--muted); letter-spacing:.02em; }}

.card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:16px 18px; margin-bottom:14px; }}
.card-header {{ display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px; }}
.card-header h3 {{ margin:0; font-size:1rem; }}
.meta {{ font-size:12px; color:var(--muted); margin:2px 0 0; }}
.kpi-row {{ display:flex; flex-wrap:wrap; gap:6px 14px; margin:8px 0; font-size:12px; color:var(--muted); }}
.kpi-row strong {{ color:var(--text); }}
.score-badge {{ width:40px; height:40px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:18px; color:#fff; flex-shrink:0; }}

table.data {{ width:100%; border-collapse:collapse; font-size:11.5px; margin-top:6px; }}
table.data th, table.data td {{ border:1px solid var(--border); padding:5px 6px; text-align:left; vertical-align:top; }}
table.data th {{ background:#e9ecef; font-weight:600; font-size:9px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em; }}
table.data .num {{ text-align:right; white-space:nowrap; }}

.small {{ font-size:11px; }}
.muted {{ color:var(--muted); }}
.sev {{ display:inline-block; padding:1px 7px; border-radius:4px; font-size:10px; font-weight:600; text-transform:uppercase; }}
.sev.alta {{ background:#fce4e4; color:var(--bad); }}
.sev.media {{ background:#fff3cd; color:#856404; }}
.sev.baja {{ background:#e8f5e9; color:var(--good); }}

pre.small {{ background:#f8fafc; padding:8px; border-radius:6px; overflow:auto; max-height:180px; font-size:11px; border:1px solid var(--border); }}
ul.compact {{ margin:4px 0; padding-left:1.1rem; font-size:12.5px; }}
ul.compact li {{ margin:2px 0; }}

.factor-detail {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:14px 16px; margin-bottom:16px; }}
.fd-header {{ display:flex; align-items:center; gap:12px; margin-bottom:8px; }}
.fd-score {{ display:inline-flex; align-items:center; justify-content:center; width:36px; height:36px; border-radius:50%; color:#fff; font-weight:700; font-size:16px; flex-shrink:0; }}
.fd-header h3 {{ margin:0; font-size:1rem; }}
.fd-desc {{ font-size:12px; color:var(--muted); margin-bottom:12px; line-height:1.5; }}
.severity-block {{ margin-top:8px; }}
.sev-title {{ font-size:11px; font-weight:700; text-transform:uppercase; margin:12px 0 6px; padding:4px 8px; border-radius:4px; }}
.sev-title.alta {{ background:#fce4e4; color:var(--bad); }}
.sev-title.media {{ background:#fff3cd; color:#856404; }}
.sev-title.baja {{ background:#e8f5e9; color:var(--good); }}
.finding {{ padding:8px 0; border-bottom:1px solid var(--border); }}
.finding:last-child {{ border-bottom:none; }}
.finding-title {{ font-weight:600; font-size:12.5px; display:flex; gap:8px; align-items:baseline; }}
.finding-impact {{ font-weight:700; font-size:11px; color:var(--bad); white-space:nowrap; }}
.finding-domain {{ font-size:11px; color:var(--muted); margin:1px 0; }}
.finding-desc, .finding-rec {{ font-size:11.5px; margin:3px 0; line-height:1.5; }}
.finding-rec {{ color:var(--blue); }}
.no-issues {{ text-align:center; padding:20px; color:var(--muted); font-size:13px; }}

.footnote {{ font-size:11px; color:var(--muted); margin-top:32px; padding-top:12px; border-top:1px solid var(--border); }}
details summary {{ cursor:pointer; }}
details summary:focus {{ outline:none; }}
@media print {{
  body {{ background:#fff; }}
  .header, .grade-hero, .score-badge, .factor-fill, .fd-score {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <img class="logo" src="{esc(LOGO_B64)}" alt="Bancolombia"/>
    <div>
      <div class="tech-by">con la tecnologia de</div>
      <h1>{esc(title)}</h1>
      <p class="meta">{esc(subtitle)}</p>
    </div>
    <div class="version">v{esc(version)}</div>
  </div>
  <div class="content">

    <div class="grade-hero">
      <div class="letter">{esc(grade)}</div>
      <div>
        <div class="trust-score">{trust}/100</div>
        <div class="details">Puntuacion de seguridad &middot; Grado orientativo (A-F) basado en controles ASM verificables &middot; Escaneo: {esc(gen)}</div>
      </div>
    </div>

    <h2 class="sec">Factores de Riesgo</h2>
    <div class="factors-grid">{factor_cards}</div>

    <h2 class="sec">Resumen de evaluacion</h2>
    <div class="card">
      <p>Postura observada por <strong>Attack Surface Management (ASM)</strong> sobre <strong>{n} dominio(s)</strong> de proveedores.</p>
      <div class="kpi-row">
        <span><strong>Activos:</strong> {n}</span>
        <span><strong>443 abierto:</strong> {sum(1 for p in matrix if p.get("port_443",{}).get("open"))}/{n}</span>
        <span><strong>80 abierto:</strong> {sum(1 for p in matrix if p.get("port_80",{}).get("open"))}/{n}</span>
        <span><strong>HSTS:</strong> {sum(1 for p in matrix if (p.get("https") or {}).get("headers",{}).get("strict-transport-security"))}/{n}</span>
        <span><strong>DNSSEC:</strong> {sum(1 for p in matrix if (p.get("dns") or {}).get("dnssec_ok"))}/{n}</span>
        <span><strong>CVE:</strong> {sum(len(p.get("vulnerabilities") or []) for p in matrix)}</span>
        <span><strong>DNSBL:</strong> {sum(len((p.get("dns") or {}).get("ip_reputation") or []) for p in matrix)}</span>
        <span><strong>Typos:</strong> {sum(len(p.get("typosquatting") or []) for p in matrix)}</span>
        <span><strong>Supply Chain:</strong> {sum(len(p.get("supply_chain") or []) for p in matrix)}</span>
        <span><strong>CSP Weak:</strong> {sum(p.get("csp_finding_count",0) for p in matrix)}</span>
        <span><strong>Cookie Insecure:</strong> {sum(1 for p in matrix if p.get("cookie_insecure"))}/{n}</span>
        <span><strong>SC-REP Issues:</strong> {sum(1 for p in matrix if not ((p.get("supply_chain_reputation") or {}).get("clean", True)))}/{n}</span>
      </div>
    </div>

    <h2 class="sec">Elementos de accion</h2>
    <div class="card">
      <table class="data">
        <thead><tr><th>Severidad</th><th>Factor</th><th>Impacto</th><th>Problema detectado</th><th>#</th></tr></thead>
        <tbody>{action_rows}</tbody>
      </table>
    </div>

    <h2 class="sec">Analisis detallado por factor</h2>
    {factor_details}

    <h2 class="sec">Superficie de ataque por proveedor</h2>
    {prov_sections}

    <div class="footnote">
      <p><strong>SCOR3BANK</strong> &middot; powered by @eduingt &middot; Informe generado el {esc(now)} &middot; Version {esc(version)} &middot; Los datos presentados reflejan el estado en el momento del escaneo y pueden variar.</p>
    </div>
  </div>
</div>
</body>
</html>"""

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--asm", type=Path, default=ROOT / "asm_report.json")
    ap.add_argument("--out", type=Path, default=ROOT / "informe_scor3bank.html")
    ap.add_argument("--title", default="INFORME SCOR3BANK")
    ap.add_argument("--subtitle", default="Evaluacion ASM del sitio publico")
    ap.add_argument("--version", default="1.0")
    args = ap.parse_args()
    asm = json.loads(args.asm.read_text(encoding="utf-8"))
    html_out = build_report(asm, args.title, args.subtitle, args.version)
    args.out.write_text(html_out, encoding="utf-8")
    print(f"[OK] {args.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
