#!/usr/bin/env python3
"""
Genera informe PDF ver.grupocibest con identidad gráfica de Grupo Cibest.
Basado en generate_socradar_style_report.py pero con branding propio.
"""

from __future__ import annotations

import argparse
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pasivo_canon import collect_pasive_items
from precia_scorecard import render_precialike_block
from toc_helper import render_toc
from score_legend import render_score_legend

FORMULA_VERSION = "B3-v2.0"
FORMULA_DATE = "2026-09-22"
from resumen_ejecutivo import render_resumen_ejecutivo
from semi_canon import collect_semi_active_items

ROOT = Path(__file__).resolve().parent

LOGO_B64 = "data:image/png;base64,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"


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
    mx_records = m.get("mx_records", [])
    ns_records = m.get("ns_records", [])
    dns = m.get("dns") or {}
    dkim_records = dns.get("dkim_records", [])
    dane_records = dns.get("dane_records", [])
    ip_reputation = dns.get("ip_reputation", [])
    starttls_results = dns.get("starttls_results") or []
    return {
        **m,
        "https_ok": https_ok,
        "spf_ok": spf_ok,
        "spf_missing": spf_missing,
        "spf_partial": spf_partial,
        "dmarc_label": dmarc,
        "mx_count": len(mx_records),
        "ns_count": len(ns_records),
        "dnssec_ok": bool(dns.get("dnssec_ok")),
        "dkim_count": len(dkim_records),
        "dane_count": len(dane_records),
        "ip_reputation_count": len(ip_reputation),
        "ip_reputation_clean": len(ip_reputation) == 0,
        "supply_chain_count": m.get("supply_chain_count", 0),
        "starttls_ok": all(s.get("starttls") for s in starttls_results) if starttls_results else False,
        "starttls_count": len(starttls_results),
        "csp_findings": m.get("csp_findings") or [],
        "csp_finding_count": len(m.get("csp_findings") or []),
        "cookie_findings": m.get("cookie_findings") or [],
        "cookie_insecure": any(f.get("severity") in ("high",) for f in (m.get("cookie_findings") or [])),
        "supply_reputation_dnsbl_count": m.get("supply_reputation_dnsbl_count", 0),
        "supply_reputation_urlhaus_count": m.get("supply_reputation_urlhaus_count", 0),
        "supply_reputation_clean": m.get("supply_reputation_clean", True),
    }


def domain_score(p: dict[str, Any]) -> float:
    """Benevolo: parte de 100 y resta suave — 100 con higiene básica, baja gradual."""
    pts = 100.0
    h = p.get("https", {}) or {}
    headers = h.get("headers") or {}
    tls = p.get("tls") or {}
    dns = p.get("dns") or {}
    if not p.get("port_443", {}).get("open"): pts -= 6
    if not (isinstance(h.get("status_code"), int) and 200 <= h["status_code"] < 400): pts -= 4
    if not headers.get("strict-transport-security"): pts -= 4
    if not (headers.get("content-security-policy") or headers.get("content-security-policy-report-only")): pts -= 4
    elif p.get("csp_findings"):
        csp_f = p.get("csp_findings") or []
        if any(f.get("severity")=="high" for f in csp_f): pts -= 3
        elif csp_f: pts -= 2
    if not headers.get("x-frame-options"): pts -= 2
    if not headers.get("x-content-type-options"): pts -= 2
    if tls.get("error") or not tls.get("negotiated_version"): pts -= 6
    elif not tls.get("tls13_only_ok"): pts -= 2
    spf = dns.get("spf_record") or ""
    if not spf: pts -= 4
    elif "-all" not in spf.replace(" ","").lower(): pts -= 2
    dmarc_pol = dns.get("dmarc_policy") or ""
    if not dns.get("dmarc_record"): pts -= 4
    elif dmarc_pol not in ("reject","quarantine"): pts -= 2
    starttls = dns.get("starttls_results") or []
    if starttls and not all(s.get("starttls") for s in starttls): pts -= 2
    ip_rep = dns.get("ip_reputation") or []
    if len(ip_rep) >= 1: pts -= 4 if len(ip_rep)>=3 else 2
    urlhaus = p.get("urlhaus") or {}
    if urlhaus.get("malicious"): pts -= 3
    vulns = p.get("vulnerabilities") or []
    if len(vulns) >= 1: pts -= 4 if len(vulns)>=3 else 2
    leaks = [l for l in (p.get("credential_leaks") or []) if "error" not in l]
    if len(leaks) >= 1: pts -= 4 if len(leaks)>=3 else 2
    typos = p.get("typosquatting") or []
    if len(typos) >= 1: pts -= 3 if len(typos)>=3 else 1
    patch = p.get("patching") or []
    eol = sum(1 for x in patch if x.get("status")=="eol")
    if eol >= 1: pts -= 3 if eol>=2 else 1
    supply = p.get("supply_chain") or []
    if len(supply) > 5: pts -= 1
    takeover = p.get("takeover_risks") or []
    if any(r.get("vulnerable") for r in takeover): pts -= 5
    elif len(takeover) >= 1: pts -= 2
    cookie_f = p.get("cookie_findings") or []
    if any(f.get("severity")=="high" for f in cookie_f): pts -= 3
    elif cookie_f: pts -= 1
    scr_dnsbl = p.get("supply_reputation_dnsbl_count", 0)
    scr_urlhaus = p.get("supply_reputation_urlhaus_count", 0)
    if scr_dnsbl >= 1 or scr_urlhaus >= 1: pts -= 3 if scr_dnsbl>=2 or scr_urlhaus>=1 else 1
    return max(0.0, min(100.0, round(pts, 2)))


def build_report(asm: dict[str, Any], title: str, subtitle: str, version: str) -> str:
    providers = asm.get("providers") or []
    matrix = [parse_matrix_row(m) for m in (asm.get("matrix") or [])]
    gen = str(asm.get("generated_utc", ""))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    n = len(providers)
    scores = [domain_score(p) for p in providers]
    trust = round(sum(scores) / max(1, n), 2)

    missing_hsts = sum(1 for m in matrix if not m.get("hsts"))
    missing_csp = sum(1 for m in matrix if not m.get("csp"))
    missing_headers = sum(1 for m in matrix if not m.get("hsts") or not m.get("csp"))
    spf_missing = sum(1 for m in matrix if m.get("spf_missing"))
    spf_partial = sum(1 for m in matrix if m.get("spf_partial"))
    https_fail = sum(1 for m in matrix if not m.get("https_ok"))
    tls_issues = sum(1 for m in matrix if not m.get("tls_version") and m.get("puertos", "").find("443:open") >= 0)

    total_subs = sum(len(p.get("subdomains") or []) for p in providers)
    total_crt = sum(len(p.get("crt_subdomains") or []) for p in providers)
    total_san = sum(len(p.get("san_list") or []) for p in providers)
    has_caa = sum(1 for p in providers if p.get("caa_records"))
    has_mta_sts = sum(1 for p in providers if p.get("mta_sts"))
    has_tls_rpt = sum(1 for p in providers if p.get("tls_rpt"))
    has_bimi = sum(1 for p in providers if p.get("bimi"))
    open443 = sum(1 for p in providers if (p.get("port_443") or {}).get("open"))
    open80 = sum(1 for p in providers if (p.get("port_80") or {}).get("open"))
    total_vulns = sum(len(p.get("vulnerabilities") or []) for p in providers)

    starttls_missing = sum(1 for m in matrix if not m.get("starttls_ok") and m.get("mx_count", 0) > 0)

    risk_rows = [
        ("Application Security", "HTTP Missing Security Headers (HSTS o CSP)", missing_headers, "Medium"),
        ("Email Security", "SPF ausente o dominio sin resolucion", spf_missing, "Medium"),
        ("Email Security", "SPF parcial / endurecimiento pendiente", spf_partial, "Low"),
        ("Email Security", "STARTTLS no soportado en MX", starttls_missing, "Medium"),
        ("SSL-TLS", "HTTPS no verificable o error TLS en apex", https_fail, "High"),
        ("SSL-TLS", "TLS negociado no constatado con 443 abierto", tls_issues, "Medium"),
    ]
    if total_vulns:
        risk_rows.insert(0, ("Vulnerability Management", f"CVEs detectados en tecnologias del servidor", total_vulns, "High"))
    total_leaks = sum(len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) for p in providers)
    if total_leaks:
        risk_rows.insert(0, ("Credential Security", "Dominios en breaches de credenciales conocidos", total_leaks, "High"))
    total_typos = sum(len(p.get("typosquatting") or []) for p in providers)
    if total_typos:
        risk_rows.insert(0, ("Phishing", "Posibles dominios typosquatting resolviendo", total_typos, "High"))
    total_patch_eol = sum(sum(1 for x in (p.get("patching") or []) if x.get("status") == "eol") for p in providers)
    if total_patch_eol:
        risk_rows.insert(0, ("Software Maintenance", "Tecnologias EOL detectadas", total_patch_eol, "High"))
    total_takeover = sum(len(p.get("takeover_risks") or []) for p in providers)
    if total_takeover:
        risk_rows.insert(0, ("Subdomain Takeover", "Posibles subdominios vulnerables a takeover", total_takeover, "High"))
    total_csp_weak = sum(len(p.get("csp_findings") or []) for p in providers)
    if total_csp_weak:
        risk_rows.insert(0, ("Application Security", "Debilidades en CSP detectadas", total_csp_weak, "Medium"))
    total_cookie_insecure = sum(1 for p in providers if any(f.get("severity") in ("high",) for f in (p.get("cookie_findings") or [])))
    if total_cookie_insecure:
        risk_rows.insert(0, ("Application Security", "Cookies sin flags de seguridad (Secure/HttpOnly)", total_cookie_insecure, "Medium"))
    total_scr_dnsbl = sum(m.get("supply_reputation_dnsbl_count", 0) for m in matrix)
    total_scr_urlhaus = sum(m.get("supply_reputation_urlhaus_count", 0) for m in matrix)
    if total_scr_dnsbl or total_scr_urlhaus:
        risk_rows.insert(0, ("Supply Chain Reputation", "IPs o dominios de terceros con reputación negativa (DNSBL/URLhaus)", total_scr_dnsbl + total_scr_urlhaus, "High"))
    total_supply = sum(len(p.get("supply_chain") or []) for p in providers)
    if total_supply:
        risk_rows.insert(0, ("Supply Chain", "Dependencias de terceros detectadas (CSP/scripts)", total_supply, "Low"))
    total_fr_js = sum(len((p.get("finalrecon") or {}).get("javascripts") or []) + len(((p.get("finalrecon") or {}).get("wayback") or {}).get("js_files") or []) for p in providers)
    if total_fr_js:
        risk_rows.insert(0, ("Application Security", f"Archivos JavaScript expuestos ({total_fr_js})", total_fr_js, "Medium"))
    total_fr_api = sum(len(((p.get("finalrecon") or {}).get("wayback") or {}).get("api_endpoints") or []) for p in providers)
    if total_fr_api:
        risk_rows.insert(0, ("Information Leak", f"Endpoints API en Wayback Machine ({total_fr_api})", total_fr_api, "High"))
    total_fr_params = sum(len(((p.get("finalrecon") or {}).get("wayback") or {}).get("juicy_params") or []) for p in providers)
    if total_fr_params:
        risk_rows.insert(0, ("Information Leak", f"Parametros sensibles en Wayback Machine ({total_fr_params})", total_fr_params, "Medium"))
    total_fr_sitemap = sum(len((p.get("finalrecon") or {}).get("sitemap") or []) for p in providers)
    if total_fr_sitemap:
        risk_rows.insert(0, ("Information Leak", f"Sitemap expuesto ({total_fr_sitemap} URLs)", total_fr_sitemap, "Low"))

    def risk_table_rows() -> str:
        out = []
        for cat, name, cnt, severity in risk_rows:
            if cnt <= 0:
                continue
            badge = {"High": "high", "Medium": "med", "Low": "low"}.get(severity, "low")
            out.append(
                f'<tr><td>{esc(cat)}</td><td>{esc(name)}</td>'
                f'<td class="num">{cnt}</td><td><span class="sev {badge}">{severity}</span></td></tr>'
            )
        if not out:
            out.append("<tr><td colspan='4' class='muted'>Sin hallazgos en las categorias mostradas.</td></tr>")
        return "\n".join(out)

    def grade_from_trust(t: float) -> str:
        if t >= 90: return "A"
        if t >= 75: return "B"
        if t >= 60: return "C"
        if t >= 45: return "D"
        if t >= 30: return "E"
        return "F"

    grade = grade_from_trust(trust)

    # Resumen Ejecutivo canónico (estilo Beta1) — usa mismo trust que el informe
    resumen_block = render_resumen_ejecutivo(providers, asm, score_general=int(trust), fecha_str=gen, org="Incocredito", analista="@eduingt")

    
    score_legend_block = render_score_legend()    # Precia-like scorecard (estilo SecurityScorecard)
    precia_blocks = "\n".join(render_precialike_block(pr, analista="@eduingt", org=pr.get("name") or pr.get("domain",""), generated=gen) for pr in providers)

    def vuln_block(esc_f, vulns):
        if not vulns:
            return ""
        items = "".join(
            f'<li><span class="cve-badge">{esc_f(v.get("cve_id", v.get("id", "?")))}</span>'
            f' {esc_f(v.get("summary", "")[:120])}'
            f' <span class="muted">({esc_f(v.get("package", ""))})</span></li>'
            for v in vulns
        )
        if len(vulns) > 10:
            items += f'<li class="muted">... y {len(vulns) - 10} mas</li>'
        return f"<h4>Vulnerabilidades (OSV.dev)</h4><ul class='compact'>{items}</ul>"

    def typo_block(esc_f, typos):
        if not typos:
            return ""
        items = "".join(
            f"<li><code>{esc_f(t.get('domain', ''))}</code> {esc_f(', '.join(t.get('ips', [])))}</li>"
            for t in typos
        )
        return f"<h4>Typosquatting detectados</h4><ul class='compact'>{items}</ul>"

    def patch_block(esc_f, patching):
        if not patching:
            return ""
        ok_mark = chr(10003)
        warn_mark = chr(9888)
        err_mark = chr(10007)
        items = ""
        for pch in patching:
            status = pch.get("status", "")
            if status == "current":
                icon = f'<span class="ok">{ok_mark}</span>'
            elif status == "ending":
                icon = f'<span class="warn">{warn_mark}</span>'
            else:
                icon = f'<span class="err">{err_mark}</span>'
            items += f"<li>{icon} <strong>{esc_f(pch.get('technology', ''))}</strong> {esc_f(pch.get('version', '') or '?')} {esc_f(pch.get('detail', ''))}</li>"
        return f"<h4>Patching cadence (endoflife.date)</h4><ul class='compact'>{items}</ul>"

    def supply_block(esc_f, supply):
        if not supply:
            return ""
        items = "".join(
            f"<li><code>{esc_f(s.get('domain', ''))}</code> ({s.get('source', '?')}) — {'✓ resuelve' if s.get('resolves') else '✗ no resuelve'} {esc_f(', '.join(s.get('ips', [])[:3]) or '')}</li>"
            for s in supply
        )
        if len(supply) > 10:
            items += f"<li class='muted'>… y {len(supply) - 10} más</li>"
        return f"<h4>Dependencias de terceros (Supply Chain)</h4><ul class='compact'>{items}</ul>"

    def cve_block(esc_f, cve_findings):
        if not cve_findings:
            return ""
        items = "".join(
            f"<li><strong>{esc_f(c.get('id', '?'))}</strong> — {esc_f(c.get('title', '')[:150])} "
            f"<span class='muted'>[{esc_f(c.get('type', ''))}] Puerto {c.get('port', '?')} / {esc_f(c.get('product', ''))}</span></li>"
            for c in cve_findings
        )
        if len(cve_findings) > 20:
            items += f"<li class='muted'>… y {len(cve_findings) - 20} más</li>"
        return f"<h4>CVEs por Banner Grab (vulscan)</h4><ul class='compact'>{items}</ul>"

    def banner_block(esc_f, banners):
        if not banners:
            return ""
        items = "".join(
            f"<li><strong>Puerto {b.get('port', '?')}</strong> ({b.get('protocol', '?')}): "
            f"<code>{esc_f(b.get('product', 'desconocido'))}</code>"
            + (f" v{esc_f(b.get('version', ''))}" if b.get('version') else "")
            + (f" <span class='muted'>{esc_f(b.get('banner', '')[:120])}</span>" if b.get('banner') else "")
            + (f" <span class='error'>{esc_f(b.get('error', ''))}</span>" if b.get('error') else "")
            + "</li>"
            for b in banners
        )
        return f"<h4>Banners de Servicio</h4><ul class='compact'>{items}</ul>"

    def api_block(esc_f, api_eps):
        if not api_eps:
            return ""
        total = len(api_eps)
        non404 = [e for e in api_eps if e.get("status_code") and e["status_code"] != 404]
        shadow = [e for e in api_eps if e.get("is_shadow")]
        rows = "".join(
            f"<tr><td>{e.get('method','?')}</td><td><code>{esc_f(e.get('path','?'))}</code></td>"
            f"<td>{e.get('status_code','?')}</td><td>{esc_f(e.get('category','?'))}</td>"
            f"<td>{'⚠ Shadow' if e.get('is_shadow') else ''}</td></tr>"
            for e in non404[:25]
        )
        extra = ""
        if len(non404) > 25:
            extra = f"<p class='muted small'>… y {len(non404)-25} más de {total} endpoints probados</p>"
        return (
            f"<h4>API Endpoints Discovery</h4>"
            f"<p class='meta'>{total} rutas probadas · {len(non404)} responden · {len(shadow)} shadow API</p>"
            f"<table class='data'><thead><tr><th>Método</th><th>Ruta</th><th>Status</th><th>Categoría</th><th>Shadow</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>{extra}"
        )

    def paths_block(esc_f, paths):
        if not paths:
            return ""
        interesting = [x for x in paths if x.get("status_code") not in (None, 404)]
        to_show = interesting if interesting else paths[:8]
        items = "".join(
            f"<tr><td><code>{esc_f(x.get('path',''))}</code></td>"
            f"<td>{esc_f(str(x.get('status_code') if x.get('status_code') is not None else x.get('error') or '—'))}</td>"
            f"<td>{esc_f(x.get('method','HEAD'))}</td></tr>"
            for x in to_show
        )
        return f"<h4>Rutas Públicas (HEAD)</h4><table class='data'><thead><tr><th>Ruta</th><th>Status</th><th>Método</th></tr></thead><tbody>{items}</tbody></table>"

    def _cert_block(esc_f, tls):
        items = []
        if tls.get("cert_subject"): items.append(f"<li><strong>Subject:</strong> {esc_f(tls['cert_subject'])}</li>")
        if tls.get("cert_issuer"): items.append(f"<li><strong>Issuer:</strong> {esc_f(tls['cert_issuer'])}</li>")
        if tls.get("cert_expiry"): items.append(f"<li><strong>Expira:</strong> {esc_f(tls['cert_expiry'])}</li>")
        if tls.get("cert_serial"): items.append(f"<li><strong>Serial:</strong> {esc_f(tls['cert_serial'])}</li>")
        if tls.get("cert_version"): items.append(f"<li><strong>Version:</strong> {esc_f(tls['cert_version'])}</li>")
        return f"<h4>Detalles del Certificado TLS</h4><ul class='compact'>{''.join(items)}</ul>" if items else ""

    def _redirect_block(esc_f, h):
        chain = h.get("redirect_chain") or []
        if not chain:
            return ""
        items = "".join(f"<li><code>{esc_f(url)}</code></li>" for url in chain[:10])
        return f"<h4>Cadena de Redireccion</h4><ul class='compact'>{items}</ul>"

    def _fingerprint_block(esc_f, h):
        items = []
        if h.get("server_fingerprint"): items.append(f"<li><strong>Server:</strong> {esc_f(h['server_fingerprint'])}</li>")
        if h.get("x_powered_by"): items.append(f"<li><strong>X-Powered-By:</strong> {esc_f(h['x_powered_by'])}</li>")
        if h.get("via"): items.append(f"<li><strong>Via:</strong> {esc_f(h['via'])}</li>")
        if h.get("cf_ray"): items.append(f"<li><strong>CF-Ray:</strong> {esc_f(h['cf_ray'])}</li>")
        return f"<h4>Huella de Servidor</h4><ul class='compact'>{''.join(items)}</ul>" if items else ""

    def _sec_headers_block(esc_f, hdr):
        checks = {"x-frame-options": "X-Frame-Options", "x-content-type-options": "X-Content-Type-Options", "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy", "cross-origin-opener-policy": "COOP"}
        items = []
        for key, label in checks.items():
            val = hdr.get(key)
            if val is not None:
                items.append(f"<li><strong>{label}:</strong> <code>{esc_f(val)}</code></li>")
        if not items:
            return ""
        return f"<h4>Cabeceras de Seguridad</h4><ul class='compact'>{''.join(items)}</ul>"

    def _open_ports_block(esc_f, open_ports):
        if not open_ports:
            return ""
        open_only = [o for o in open_ports if o.get("state") == "open"]
        items = "".join(
            f"<li>Puerto {o.get('port','?')}: {o.get('service', '?')}</li>"
            for o in open_only
        )
        return f"<h4>Puertos Abiertos</h4><ul class='compact'>{items}</ul>"

    def _brute_block(esc_f, brute_subs):
        if not brute_subs:
            return ""
        items = "".join(
            f"<li><code>{esc_f(b.get('fqdn','?'))}</code> — {esc_f(', '.join(b.get('ips') or []))}</li>"
            for b in brute_subs
        )
        return f"<h4>Subdominios (Brute Force DNS)</h4><ul class='compact'>{items}</ul>"

    def _pivot_block(esc_f, pivot_results):
        if not pivot_results:
            return ""
        items = "".join(
            f"<li><code>{esc_f(r.get('ip','?'))}</code>: PTR={esc_f(r.get('ptr','-'))}, crt.sh: {', '.join(r.get('fqdns_from_crt', [])[:5])}{'...' if len(r.get('fqdns_from_crt',[]))>5 else ''}</li>"
            for r in pivot_results[:5]
        )
        return f"<h4>IP Pivot (FQDNs descubiertos)</h4><ul class='compact'>{items}</ul>"

    def _external_block(esc_f, p):
        ext = p.get("external") or {}
        parts = []
        whois = ext.get("whois") or {}
        if "error" not in whois:
            items = []
            if whois.get("registrar"): items.append(f"<li>Registrar: {esc_f(whois['registrar'])}</li>")
            if whois.get("registrant_organization"): items.append(f"<li>Organizacion: {esc_f(whois['registrant_organization'])}</li>")
            if whois.get("registrant_country"): items.append(f"<li>Pais: {esc_f(whois['registrant_country'])}</li>")
            if whois.get("creation_date"): items.append(f"<li>Creado: {esc_f(whois['creation_date'])}</li>")
            if whois.get("expiration_date"): items.append(f"<li>Expira: {esc_f(whois['expiration_date'])}</li>")
            if whois.get("emails"): items.append(f"<li>Emails: {esc_f(', '.join(whois['emails'][:5]))}</li>")
            if items:
                parts.append(f"<h4>WHOIS</h4><ul class='compact'>{''.join(items)}</ul>")
        dnsd = ext.get("dnsdumpster") or {}
        if "error" not in dnsd and dnsd.get("host_records"):
            items = "".join(f"<li><code>{esc_f(r[0])}</code> ({esc_f(', '.join(r[1:]))})</li>" for r in dnsd["host_records"][:10])
            parts.append(f"<h4>DNSDumpster</h4><ul class='compact'>{items}</ul>")
        shodan = ext.get("shodan") or {}
        if "error" not in shodan and shodan.get("hosts"):
            ports = list({p2 for h in shodan["hosts"] for p2 in h.get("ports", [])})
            vulns = list({v for h in shodan["hosts"] for v in h.get("vulns", [])})
            items = []
            if ports: items.append(f"<li>Puertos: {esc_f(', '.join(str(p) for p in sorted(ports)[:20]))}</li>")
            if vulns: items.append(f"<li>Vulnerabilidades: {esc_f(', '.join(vulns))}</li>")
            for h in shodan["hosts"][:3]:
                if h.get("org"): items.append(f"<li>Org: {esc_f(h['org'])} ({esc_f(h.get('country','?'))})</li>")
            if items:
                parts.append(f"<h4>Shodan</h4><ul class='compact'>{''.join(items)}</ul>")
        censys = ext.get("censys") or {}
        if "error" not in censys:
            certs = censys.get("certificates") or []
            if certs:
                items = "".join(f"<li><code>{esc_f(c.get('fingerprint_sha256','')[:24])}</code> {esc_f(str(c.get('validity',{}).get('start',''))[:10])}</li>" for c in certs[:3])
                parts.append(f"<h4>Censys ({len(certs)} certificados)</h4><ul class='compact'>{items}</ul>")
            hosts = censys.get("hosts") or []
            if hosts:
                items = "".join(f"<li>{esc_f(h.get('ip','?'))} — {esc_f(', '.join(s.get('service_name','') for s in (h.get('services') or [])[:5]))}</li>" for h in hosts[:3])
                parts.append(f"<h4>Censys Hosts</h4><ul class='compact'>{items}</ul>")
        th = ext.get("theharvester") or {}
        if "error" not in th:
            items = []
            if th.get("emails"): items.append(f"<li>Emails: {esc_f(', '.join(th['emails'][:10]))}</li>")
            if th.get("subdomains"): items.append(f"<li>Subdominios: {esc_f(', '.join(th['subdomains'][:10]))}</li>")
            if th.get("ips"): items.append(f"<li>IPs: {esc_f(', '.join(th['ips'][:5]))}</li>")
            if items:
                parts.append(f"<h4>theHarvester</h4><ul class='compact'>{''.join(items)}</ul>")
        kumo = p.get("kumo") or {}
        if isinstance(kumo, dict):
            k_parts = []
            wb = kumo.get("wayback") or {}
            if wb.get("interesting") and not wb.get("error"):
                k_parts.append(f"<h4>Wayback Machine</h4><ul class='compact'>" + "".join(f"<li><code>{esc_f(u)}</code></li>" for u in wb["interesting"][:6]) + "</ul>")
            bi = kumo.get("breachintel") or {}
            if bi and not bi.get("error"):
                s = bi.get("summary") or {}
                bi_seg = []
                if s.get("total_employees_leaked"): bi_seg.append(f"empleados: {s['total_employees_leaked']}")
                if s.get("total_clients_leaked"): bi_seg.append(f"clientes: {s['total_clients_leaked']}")
                if s.get("total_infostealer_hits"): bi_seg.append(f"<b>infostealer: {s['total_infostealer_hits']}</b>")
                if bi_seg:
                    k_parts.append(f"<h4>Breach Intel</h4><ul class='compact'><li>{' · '.join(bi_seg)}</li></ul>")
            js = kumo.get("js_secrets") or {}
            if js.get("secrets") and not js.get("error"):
                js_items = "".join(f"<li><b>{esc_f(x.get('type',''))}</b> en <code>{esc_f(x.get('file',''))}</code> — {esc_f(str(x.get('value',''))[:50])}</li>" for x in js["secrets"][:8])
                k_parts.append(f"<h4>JS Secrets</h4><ul class='compact'>{js_items}</ul>")
            nu = kumo.get("nuclei") or {}
            if nu.get("findings") and not nu.get("error"):
                sc = nu.get("severity_counts") or {}
                sc_seg = ' · '.join(f"{sc.get(sv,0)} {sv}" for sv in ("critical","high","medium","low","info") if sc.get(sv))
                nu_items = "".join(f"<li>{esc_f(f.get('name','?'))}</li>" for f in nu["findings"][:10])
                k_parts.append(f"<h4>Vuln Scanner KUMO</h4><p class='meta'>{esc_f(sc_seg)}</p><ul class='compact'>{nu_items}</ul>")
            if k_parts:
                parts.append("".join(k_parts))
        prism = p.get("prism") or {}
        if isinstance(prism, dict):
            pr_parts = []
            ll = prism.get("leak_lookup") or {}
            if ll and not ll.get("error") and ll.get("breaches"):
                ll_items = "".join(f"<li><span class='err'>{esc_f(b.get('name','?'))}</span></li>" for b in ll["breaches"][:12])
                pr_parts.append(f"<h4>Prism Breach Lookup ({len(ll.get('breaches', []))})</h4><ul class='compact'>{ll_items}</ul>")
            oc = prism.get("onion_checker") or {}
            if oc and not oc.get("error") and oc.get("results"):
                oc_items = "".join(f"<li><code>{esc_f(r.get('url','?'))}</code> ({esc_f(r.get('source','?'))})</li>" for r in oc["results"][:8])
                pr_parts.append(f"<h4>Prism Onion / Dark Web</h4><ul class='compact'>{oc_items}</ul>")
            gh = prism.get("github_recon") or {}
            if gh and not gh.get("error") and gh.get("profile"):
                prof = gh.get("profile") or {}
                gh_seg = []
                if prof.get("name"): gh_seg.append(f"@{gh.get('username','?')} ({esc_f(prof['name'])})")
                if gh.get("repo_count"): gh_seg.append(f"{gh.get('repo_count')} repos · {gh.get('total_stars',0)} stars")
                if gh.get("emails"): gh_seg.append("emails: " + esc_f(", ".join(gh["emails"][:4])))
                pr_parts.append(f"<h4>Prism GitHub Recon</h4><ul class='compact'><li>{' · '.join(gh_seg)}</li></ul>")
            gr = prism.get("gravatar") or {}
            if gr and not gr.get("error") and gr.get("hits"):
                gr_items = "".join(f"<li><b>{esc_f(h.get('display_name','?'))}</b> ({esc_f(h.get('email','?'))})</li>" for h in gr["hits"][:6])
                pr_parts.append(f"<h4>Prism Gravatar</h4><ul class='compact'>{gr_items}</ul>")
            wa = prism.get("website_analyzer") or {}
            if wa and not wa.get("error"):
                wa_items = []
                if wa.get("technologies"): wa_items.append("<li><b>Tech:</b> " + esc_f(", ".join(wa["technologies"])) + "</li>")
                if wa.get("social_links"): wa_items.append("<li><b>Redes:</b> " + " · ".join(f"{esc_f(s.get('platform','?'))}: @{esc_f(s.get('username','?'))}" for s in wa["social_links"][:6]) + "</li>")
                if wa.get("emails"): wa_items.append("<li><b>Emails:</b> " + esc_f(", ".join(wa["emails"][:6])) + "</li>")
                if wa.get("phones"): wa_items.append("<li><b>Tel:</b> " + esc_f(", ".join(wa["phones"][:4])) + "</li>")
                if wa_items:
                    pr_parts.append(f"<h4>Prism Website Analyzer</h4><ul class='compact'>{''.join(wa_items)}</ul>")
            sv = prism.get("smtp_verify") or {}
            if sv and not sv.get("error") and sv.get("per_email"):
                sv_items = []
                for r in sv["per_email"]:
                    if not isinstance(r, dict): continue
                    st = "existe" if r.get("exists") is True else ("no existe" if r.get("exists") is False else "indefinido")
                    sv_items.append(f"<li><code>{esc_f(r.get('email','?'))}</code>: <b>{st}</b>" + (" · catch-all" if r.get("catch_all") else "") + "</li>")
                pr_parts.append(f"<h4>Prism SMTP Verify</h4><ul class='compact'>{''.join(sv_items)}</ul>")
            vt = prism.get("virustotal") or {}
            if vt and not vt.get("error") and vt.get("status") == "ok":
                verdict = "malicioso" if vt.get("malicious") else ("sospechoso" if vt.get("suspicious") else "limpio")
                vt_seg = f"{esc_f(vt.get('query','?'))}: <b>{verdict}</b>"
                if vt.get("malicious"): vt_seg += f" · {vt.get('malicious')} malicioso"
                if vt.get("suspicious"): vt_seg += f" · {vt.get('suspicious')} sospechoso"
                pr_parts.append(f"<h4>Prism VirusTotal</h4><ul class='compact'><li>{vt_seg}</li></ul>")
            ab = prism.get("abuseipdb") or {}
            if ab and not ab.get("error") and ab.get("status") == "ok":
                ab_seg = f"score {ab.get('abuse_score')}/100 · {ab.get('total_reports',0)} reportes"
                if ab.get("is_tor"): ab_seg += " · TOR"
                pr_parts.append(f"<h4>Prism AbuseIPDB</h4><ul class='compact'><li>{esc_f(ab_seg)}</li></ul>")
            if pr_parts:
                parts.append("".join(pr_parts))
        co = p.get("claude_osint") or {}
        if isinstance(co, dict):
            co_parts = []
            m365 = co.get("m365_fingerprint") or {}
            if m365 and not m365.get("error"):
                m365_items = []
                if m365.get("tenant_space"): m365_items.append(f"Namespace: <b>{esc_f(m365['tenant_space'])}</b>")
                if m365.get("tenant_guid"): m365_items.append(f"Tenant GUID: <code>{esc_f(m365['tenant_guid'])}</code>")
                if m365.get("oidc", {}).get("issuer"): m365_items.append(f"Issuer: <code>{esc_f(m365['oidc']['issuer'][:80])}</code>")
                if m365.get("m365_detected"): m365_items.append("Microsoft 365 detectado")
                if m365_items:
                    co_parts.append(f"<h4>Claude-OSINT M365 Fingerprint</h4><ul class='compact'>" + "".join(f"<li>{x}</li>" for x in m365_items) + "</ul>")
            spf = co.get("spf_supply_chain") or {}
            if spf and not spf.get("error"):
                v = spf.get("verdict") or {}
                spf_items = [f"Verdict: <b>{esc_f(v.get('spoofable','?'))}</b> — {esc_f(v.get('vector',''))}"]
                sc = spf.get("supply_chain") or {}
                if sc:
                    spf_items.append(f"Lookups: {sc.get('lookup_cost_mechanisms')} · voids: {sc.get('void_lookups')}")
                    if sc.get("dead_includes"): spf_items.append(f"Dead: <code>{esc_f(', '.join(sc['dead_includes'][:5]))}</code>")
                    if sc.get("perm_error"): spf_items.append("<span class='err'>PermError SPF fail-open</span>")
                co_parts.append(f"<h4>Claude-OSINT SPF/DMARC Supply-chain</h4><ul class='compact'>" + "".join(f"<li>{x}</li>" for x in spf_items) + "</ul>")
            org = co.get("org_attribution") or {}
            if org and not org.get("error") and (org.get("lei") or org.get("crt_sh_org", {}).get("candidate_domains")):
                org_items = []
                if org.get("lei"): org_items.append(f"LEI: <code>{esc_f(org['lei'])}</code> — {esc_f(org.get('legal_name') or '')}")
                if org.get("direct_children"): org_items.append(f"Hijos GLEIF: {esc_f(', '.join(c.get('name') or '?' for c in org['direct_children'][:5]))}")
                if org.get("crt_sh_org", {}).get("candidate_domains"): org_items.append(f"crt.sh O=: <code>{esc_f(', '.join(org['crt_sh_org']['candidate_domains'][:6]))}</code>")
                co_parts.append(f"<h4>Claude-OSINT Org Attribution</h4><ul class='compact'>" + "".join(f"<li>{x}</li>" for x in org_items) + "</ul>")
            cti = co.get("cti_chatter") or {}
            if cti and not cti.get("error"):
                cti_items = []
                rw = cti.get("ransomwatch") or {}
                if rw.get("hits"): cti_items.append(f"Ransomwatch: <b>{rw.get('total',0)}</b> (" + esc_f("; ".join(h.get('title','?')[:60] for h in rw['hits'][:3])) + ")")
                rl = cti.get("ransomware_live") or {}
                if rl.get("hits"): cti_items.append(f"Ransomware.live: <b>{rl.get('total',0)}</b>")
                if cti_items:
                    co_parts.append(f"<h4>Claude-OSINT CTI Chatter</h4><ul class='compact'>" + "".join(f"<li>{x}</li>" for x in cti_items) + "</ul>")
            pdn = co.get("passive_dns_extra") or {}
            if pdn and not pdn.get("error") and pdn.get("subdomains"):
                pdn_items = "".join(f"<li><code>{esc_f(s)}</code></li>" for s in pdn["subdomains"][:10])
                co_parts.append(f"<h4>Claude-OSINT Passive DNS ({len(pdn.get('subdomains', []))})</h4><ul class='compact'>{pdn_items}</ul>")
            cn = co.get("cloud_native_fp") or {}
            if cn and not cn.get("error") and cn.get("fingerprints"):
                cn_items = "".join(f"<li><b>{esc_f(f.get('service','?'))}</b> — <code>{esc_f(f.get('cname','?'))}</code></li>" for f in cn["fingerprints"][:6])
                co_parts.append(f"<h4>Claude-OSINT Cloud-native fingerprint</h4><ul class='compact'>{cn_items}</ul>")
            sop = co.get("saml_oidc_probe") or {}
            if sop and not sop.get("error"):
                sop_items = []
                for key, label in (("openid_config", "OIDC"), ("saml_metadata", "SAML"), ("adfs_mex", "ADFS")):
                    ch = sop.get(key) or {}
                    if ch.get("reachable"):
                        sop_items.append(f"<li>{label}: {ch.get('status','?')}" + (" metadata" if ch.get("is_metadata") else "") + "</li>")
                if sop_items:
                    co_parts.append(f"<h4>Claude-OSINT SSO/OIDC probe</h4><ul class='compact'>{''.join(sop_items)}</ul>")
            ss = co.get("secret_scan") or {}
            if ss and not ss.get("error") and ss.get("critical"):
                ss_items = "".join(f"<li><span class='err'>{esc_f(g.get('pattern','?'))}</span> x{g.get('count')} — <code>{esc_f(str(g.get('first',''))[:60])}</code></li>" for g in ss["critical"][:4])
                co_parts.append(f"<h4>Claude-OSINT Secret Scan</h4><ul class='compact'>{ss_items}</ul>")
            if co_parts:
                parts.append("".join(co_parts))
        canon = [it for it in collect_pasive_items(p) if it.get("status") == "ok"]
        if canon:
            by_group: dict[str, list] = {}
            for it in canon:
                by_group.setdefault(it.get("grupo") or "Otros", []).append(it)
            for grupo in sorted(by_group):
                listed = "".join(f"<li><strong>{esc_f(it['label'])}:</strong> {esc_f(it['valor'])}</li>" for it in by_group[grupo])
                parts.append(f"<h4>Pasivo · {esc_f(grupo)}</h4><ul class='compact'>{listed}</ul>")
        semi = [it for it in collect_semi_active_items(p) if it.get("status") == "ok"]
        if semi:
            by_group = {}
            for it in semi:
                by_group.setdefault(it.get("grupo") or "Otros", []).append(it)
            for grupo in sorted(by_group):
                listed = "".join(f"<li><strong>{esc_f(it['label'])}:</strong> {esc_f(it['valor'])}</li>" for it in by_group[grupo])
                parts.append(f"<h4>Semi-activo · {esc_f(grupo)}</h4><ul class='compact'>{listed}</ul>")
        strix = p.get("strix") or {}
        if strix and strix.get("status") == "ok":
            findings = strix.get("findings") or []
            meta = f"Modo {esc_f(strix.get('mode','?'))} · {len(findings)} hallazgo(s)"
            parts.append(f"<h4>Strix AI Pentest</h4><p class='meta'>{meta}</p>")
            if findings:
                items = "".join(
                    f"<li><span class='risk-{esc_f(f.get('severity','low'))}'>[{esc_f(f.get('severity','?'))}]</span> "
                    f"<strong>{esc_f(f.get('title','?'))}</strong> · {esc_f(f.get('cve','-'))} · CVSS {esc_f(f.get('cvss','-'))}<br/>"
                    f"<span class='muted'>{esc_f(str(f.get('remediation_steps',''))[:160])}</span></li>"
                    for f in sorted(findings, key=lambda x: str(x.get('severity','low')).lower() in ("critical","high"), reverse=True)[:8]
                )
                parts.append(f"<ul class='compact'>{items}</ul>")
        return "\n".join(parts)

    def takeover_block(esc_f, risks):
        if not risks:
            return ""
        items = ""
        for r in risks:
            vulnerable = r.get("vulnerable", False)
            badge = '<span class="err">' + chr(10007) + ' VULNERABLE</span>' if vulnerable else '<span class="warn">&#9888; POTENCIAL</span>'
            items += f'<li><code>{esc_f(r.get("host", ""))}</code> &rarr; <code>{esc_f(r.get("cname", ""))}</code> {badge}: {esc_f(r.get("description", ""))}</li>'
        if len(risks) > 10:
            items += f'<li class="muted">... y {len(risks) - 10} mas</li>'
        return f"<h4>Riesgos de Subdomain Takeover</h4><ul class='compact'>{items}</ul>"

    def csp_block(esc_f, findings):
        if not findings:
            return ""
        ok_mark = chr(10003)
        err_mark = chr(10007)
        items = ""
        for f in findings:
            icon = err_mark if f.get("severity") == "high" else ("&#9888;" if f.get("severity") == "medium" else "&#9679;")
            items += f"<li>{icon} [{f.get('severity','').upper()}] <strong>{esc_f(f.get('directive',''))}</strong>: {esc_f(f.get('description',''))}</li>"
        if len(findings) > 10:
            items += f'<li class="muted">... y {len(findings) - 10} mas</li>'
        return f"<h4>Análisis de CSP</h4><ul class='compact'>{items}</ul>"

    def cookie_block(esc_f, findings):
        if not findings:
            return ""
        ok_mark = chr(10003)
        err_mark = chr(10007)
        items = ""
        for f in findings:
            icon = err_mark if f.get("severity") == "high" else ("&#9888;" if f.get("severity") == "medium" else "&#9679;")
            items += f"<li>{icon} [{f.get('severity','').upper()}] {esc_f(f.get('description',''))}</li>"
        if len(findings) > 10:
            items += f'<li class="muted">... y {len(findings) - 10} mas</li>'
        return f"<h4>Seguridad de Cookies</h4><ul class='compact'>{items}</ul>"

    def scr_block(esc_f, p):
        scr = p.get("supply_chain_reputation") or {}
        dnsbl = scr.get("dnsbl") or []
        urlhaus = scr.get("urlhaus") or []
        items = ""
        for d in dnsbl:
            items += f"<li><span class='err'>{chr(10007)} DNSBL: IP {esc_f(d.get('ip',''))} listada en {esc_f(d.get('dnsbl',''))}</span></li>"
        for u in urlhaus:
            items += f"<li><span class='err'>{chr(10007)} URLhaus: {esc_f(u.get('domain',''))} ({u.get('url_count',0)} urls maliciosas)</span></li>"
        if items:
            return f"<h4>Reputación de terceros (Supply Chain)</h4><ul class='compact'>{items}</ul>"
        return ""

    def finalrecon_block(esc_f, p):
        fr = p.get("finalrecon") or {}
        if not fr:
            return ""
        items = ""
        fr_js = fr.get("javascripts") or []
        fr_wb = fr.get("wayback") or {}
        fr_wb_js = fr_wb.get("js_files") or []
        fr_wb_api = fr_wb.get("api_endpoints") or []
        fr_wb_params = fr_wb.get("juicy_params") or []
        fr_sitemap = fr.get("sitemap") or []
        fr_ext = fr.get("external_urls") or []
        all_js = list(dict.fromkeys(fr_js + fr_wb_js))
        if all_js:
            items += f"<li>Archivos JS expuestos: {len(all_js)}</li>"
        if fr_ext:
            items += f"<li>Enlaces externos: {len(fr_ext)}</li>"
        if fr_sitemap:
            items += f"<li>Sitemap: {len(fr_sitemap)} URLs</li>"
        if fr_wb_js:
            items += f"<li>JS históricos Wayback: {len(fr_wb_js)}</li>"
        if fr_wb_api:
            items += f"<li>Endpoints API Wayback: {len(fr_wb_api)}</li>"
        if fr_wb_params:
            items += f"<li>Parametros sensibles Wayback: {len(fr_wb_params)}</li>"
        if not items:
            return ""
        return f"<h4>Web Recon - FinalRecon</h4><ul class='compact'>{items}</ul>"

    def owasp_block(esc_f, m):
        ow = m.get("owasp") or {}
        if not ow:
            return '<h4>OWASP Agentic Top 10</h4><ul class="compact"><li class="muted">Sin evaluación disponible.</li></ul>'
        grade = ow.get("overall_grade", "—")
        pct = ow.get("overall_compliance", 0)
        items = ""
        ok_mark = chr(10003)
        err_mark = chr(10007)
        for r_id, r_data in sorted((ow.get("risks") or {}).items()):
            if r_data.get("finding_count", 0) > 0:
                icon = err_mark if r_data["compliance_pct"] < 60 else ok_mark
                items += f"<li>{icon} <strong>{r_id}</strong>: Grado {r_data['grade']} ({r_data['compliance_pct']}%) — {r_data['finding_count']} hallazgo(s)</li>"
        if not items:
            items = '<li class="muted">Sin hallazgos que afecten compliance.</li>'
        return f'<h4>OWASP Agentic Top 10 — Grado: {grade} ({pct}%)</h4><ul class="compact">{items}</ul>'

    def social_block(esc_f, p):
        social = p.get("social") or {}
        if not social:
            return '<h4>Redes Sociales (OSINT)</h4><ul class="compact"><li class="muted">Sin datos de redes sociales configurados. Agregue social_* al providers.json.</li></ul>'
        labels = {"instagram": "Instagram", "tiktok": "TikTok", "twitter": "Twitter", "twitch": "Twitch", "telegram": "Telegram", "github": "GitHub"}
        urls = {"instagram": "https://www.instagram.com/", "tiktok": "https://www.tiktok.com/@", "twitter": "https://nitter.net/", "twitch": "https://www.twitch.tv/", "telegram": "https://t.me/", "github": "https://github.com/"}
        items = ""
        for net, data in social.items():
            uname = data.get("username", "")
            err = data.get("error")
            label = labels.get(net, net)
            if err:
                items += f"<li>{label}: @{esc_f(uname)} — error</li>"
            else:
                url = urls.get(net, "") + uname
                followers = str(data.get("followers") or data.get("seguidores") or "")
                desc = str(data.get("description", "") or "")[:120]
                items += f"<li><strong>{label}</strong>: <a href='{esc_f(url)}' target='_blank'>@{esc_f(uname)}</a> · {esc_f(str(data.get('name','') or data.get('full_name','')))} · seguidores: {esc_f(followers)} · {esc_f(desc)}</li>"
        return f"<h4>Redes Sociales (OSINT)</h4><ul class='compact'>{items}</ul>"

    prov_sections = []
    matrix_by_domain = {m.get("dominio", ""): m for m in matrix}
    for p in providers:
        dom = p.get("domain", "")
        ips = ", ".join((p.get("dns") or {}).get("ipv4") or []) or "-"
        h = p.get("https") or {}
        tls = p.get("tls") or {}
        hdr = h.get("headers") or {}
        subs = p.get("subdomains") or []
        crt_subs = p.get("crt_subdomains") or []
        san_list = p.get("san_list") or []
        sub_li = "".join(f"<li><code>{esc(s.get('host'))}</code> {esc(', '.join(s.get('ipv4') or []))}</li>" for s in subs)
        crt_li = "".join(f"<li><code>{esc(s)}</code></li>" for s in crt_subs)
        san_li = "".join(f"<li><code>{esc(s)}</code></li>" for s in san_list)
        dns_items = []
        dns_data = p.get("dns") or {}
        mx = dns_data.get("mx_records") or []
        for m in mx:
            dns_items.append(f"MX: {esc(m.get('preference', '?'))} {esc(m.get('exchange', ''))}")
        ns = dns_data.get("ns_records") or []
        for n in ns:
            dns_items.append(f"NS: {esc(n.get('nameserver', '') or n.get('target', ''))}")
        spf = dns_data.get("spf_record")
        if spf:
            dns_items.append(f"SPF: {esc(spf[:180])}")
        dmarc_rec = dns_data.get("dmarc_record")
        if dmarc_rec:
            dns_items.append(f"DMARC: {esc(dmarc_rec[:180])}")
        dkim = dns_data.get("dkim_records") or []
        for dk in dkim:
            dns_items.append(f"DKIM/{esc(dk.get('selector', '?'))}: {esc(dk.get('record', '')[:100])}")
        dane = dns_data.get("dane_records") or []
        for dn in dane:
            dns_items.append(f"DANE: _{esc(dn.get('port','?'))}._{esc(dn.get('protocol','?'))} usage={esc(dn.get('usage','?'))}")
        if dns_data.get("dnssec_ok"):
            dns_items.append("DNSSEC: activo")
        ipv6 = dns_data.get("ipv6") or []
        if ipv6:
            dns_items.append(f"AAAA IPv6: {', '.join(esc(x) for x in ipv6)}")
        caa = p.get("caa_records") or []
        for rec in caa:
            dns_items.append(f"CAA: {esc(rec.get('tag', '?'))} {esc(rec.get('value', '?'))}")
        if p.get("mta_sts"):
            dns_items.append(f"MTA-STS: {esc(p['mta_sts'][:120])}")
        if p.get("tls_rpt"):
            dns_items.append(f"TLS-RPT: {esc(p['tls_rpt'][:120])}")
        if p.get("bimi"):
            dns_items.append(f"BIMI: {esc(p['bimi'][:120])}")
        ip_rep = dns_data.get("ip_reputation") or []
        if ip_rep:
            ipr = ", ".join(f"{r.get('ip','?')} en {r.get('dnsbl','?')}" for r in ip_rep[:5])
            dns_items.append(f"DNSBL: {esc(ipr)}")

        score = domain_score(p)
        cl_443 = "abierto" if (p.get("port_443") or {}).get("open") else "cerrado"
        cl_80 = "abierto" if (p.get("port_80") or {}).get("open") else "cerrado"
        crt_hdr = '<h4>Subdominios (crt.sh)</h4><ul class="compact">'
        san_hdr = '<h4>SAN</h4><ul class="compact">'
        dns_hdr = '<h4>Registros DNS</h4><ul class="compact"><li>'
        if score >= 90:
            score_cls = "score-a"
        elif score >= 75:
            score_cls = "score-b"
        elif score >= 60:
            score_cls = "score-c"
        elif score >= 45:
            score_cls = "score-d"
        elif score >= 30:
            score_cls = "score-e"
        else:
            score_cls = "score-f"

        prov_sections.append(
            (lambda sc, cl, sl, di, sub_li, crt_li, san_li, dns_items: f"""
<section class="card">
  <div class="card-header">
    <div>
      <h3>{esc(p.get("name"))}</h3>
      <p class="meta"><code>{esc(dom)}</code> &middot; {esc(ips)}</p>
    </div>
    <div class="{sc} score-badge">{esc(grade_from_trust(score))}</div>
  </div>
  <div class="kpi-row">
    <span><strong>{score}</strong>/100</span>
    <span>443: {cl_443}</span>
    <span>80: {cl_80}</span>
    <span>Subdominios: {len(subs)}</span>
    <span>crt.sh: {len(crt_subs)}</span>
    <span>SAN: {len(san_list)}</span>
  </div>
  <p><strong>HTTPS:</strong> {esc(h.get("status_code") if isinstance(h.get("status_code"), int) else h.get("error") or "-")} &middot; <strong>TLS:</strong> {esc(tls.get("negotiated_version") or tls.get("error") or "-")} &middot; <strong>Cert. hasta:</strong> {esc(tls.get("cert_expiry") or "-")}</p>
  <h4>Subdominios</h4>
  <ul class="compact">{sub_li or '<li class="muted">Ninguno con el diccionario actual</li>'}</ul>
  {crt_hdr + crt_li + "</ul>" if crt_subs else ""}
  {san_hdr + san_li + "</ul>" if san_list else ""}
  {dns_hdr + "</li><li>".join(dns_items) + "</li></ul>" if dns_items else ""}
  {_cert_block(esc, tls)}
  {_redirect_block(esc, h)}
  {_fingerprint_block(esc, h)}
  {_sec_headers_block(esc, hdr)}
  {_open_ports_block(esc, p.get("open_ports") or [])}
  {_brute_block(esc, p.get("brute_subs") or [])}
  {_pivot_block(esc, p.get("pivot_results") or [])}
  {vuln_block(esc, p.get("vulnerabilities") or [])}
  {takeover_block(esc, p.get("takeover_risks") or [])}
  {csp_block(esc, p.get("csp_findings") or [])}
  {cookie_block(esc, p.get("cookie_findings") or [])}
        {scr_block(esc, p)}
        {finalrecon_block(esc, p)}
        {social_block(esc, p)}
  {owasp_block(esc, matrix_by_domain.get(dom, {}))}
  {typo_block(esc, p.get("typosquatting") or [])}
  {patch_block(esc, p.get("patching") or [])}
  {supply_block(esc, p.get("supply_chain") or [])}
  {cve_block(esc, p.get("cve_findings") or [])}
  {banner_block(esc, p.get("banner_grabs") or [])}
  {api_block(esc, p.get("api_endpoints") or [])}
  {paths_block(esc, p.get("public_paths") or [])}
  {_external_block(esc, p)}
  <details>
    <summary class="muted small">Ver cabeceras HTTP</summary>
    <pre class="small">{esc(json.dumps(hdr, indent=2, ensure_ascii=False) if hdr else "{}")}</pre>
  </details>
</section>
""")(score_cls,
    "abierto" if (p.get("port_443") or {}).get("open") else "cerrado",
    "abierto" if (p.get("port_80") or {}).get("open") else "cerrado",
    dom,
    sub_li, crt_li, san_li, dns_items)
        )

    matrix_html = ""
    ok_mark = chr(10003)
    err_mark = chr(10007)
    for m in matrix:
        matrix_html += f"""<tr>
 <td>{esc(m.get("proveedor"))}<div class="muted small">{esc(m.get("dominio"))}</div></td>
 <td class="num">{esc(m.get("subdominios"))}</td>
 <td class="num">{m.get("crt_subdominios", 0)}</td>
 <td class="small">{esc(m.get("https"))}</td>
 <td class="c">{ok_mark if m.get("hsts") else err_mark}</td>
 <td class="c">{ok_mark if m.get("csp") else err_mark}</td>
 <td class="num">{m.get("csp_finding_count", 0)}</td>
 <td class="c">{ok_mark if not m.get("cookie_insecure") else err_mark}</td>
 <td class="small">{esc(m.get("spf_dmarc"))}</td>
 <td class="c">{ok_mark if m.get("tls13_negociado") else err_mark}</td>
 <td class="small">{esc(m.get("tls_version"))}</td>
 <td class="c">{ok_mark if m.get("caa") else err_mark}</td>
 <td class="c">{ok_mark if m.get("mta_sts") else err_mark}</td>
 <td class="c">{ok_mark if m.get("tls_rpt") else err_mark}</td>
 <td class="c">{ok_mark if m.get("starttls_ok") else (err_mark if m.get("mx_count", 0) > 0 else "—")}</td>
 <td class="num">{m.get("mx_count", 0)}</td>
 <td class="num">{m.get("ns_count", 0)}</td>
 <td class="c">{ok_mark if m.get("dnssec_ok") else err_mark}</td>
 <td class="num">{m.get("dkim_count", 0)}</td>
 <td class="num">{m.get("dane_count", 0)}</td>
 <td class="c">{ok_mark if m.get("ip_reputation_clean") else esc(str(m.get("ip_reputation_count", 0)))}</td>
 <td class="c">{ok_mark if not m.get("urlhaus_malicious") else err_mark}</td>
 <td class="num">{m.get("vulnerability_count", 0)}</td>
 <td class="num">{m.get("credential_leak_count", 0)}</td>
 <td class="num">{esc(m.get("typosquatting_count", 0))}</td>
  <td class="num">{esc(m.get("patching_eol", 0) + m.get("patching_ending", 0))}</td>
  <td class="c">{ok_mark if m.get("takeover_vulnerable") else (err_mark if m.get("takeover_count", 0) > 0 else "—")}</td>
  <td class="num">{m.get("supply_chain_count", 0)}</td>
  <td class="c">{ok_mark if m.get("supply_reputation_clean") else err_mark}</td>
  </tr>"""

    toc_block = render_toc(report_type="b3")
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{esc(title)} v{esc(version)}</title>
<style>
:root {{
  --navy:#0d1b2a; --navy2:#1b2a41; --navy3:#243b53;
  --gold:#c9a84c; --gold-light:#e8d48b;
  --card:#ffffff; --bg:#f0f2f5; --text:#1a1d21; --muted:#6c757d;
  --border:#dde1e6; --accent:#1b2a41;
  --good:#1a7d4f; --warn:#b8860b; --bad:#b22222;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; font-size:13.5px; }}
.wrap {{ max-width:1000px; margin:0 auto; padding:0 0 40px; }}
.header {{
  background:linear-gradient(135deg, var(--navy) 0%, var(--navy2) 60%, var(--navy3) 100%);
  color:#fff; padding:24px 28px 20px;
  display:flex; align-items:center; gap:20px;
}}
.header .logo {{ height:50px; }}
.header h1 {{ margin:0; font-size:1.2rem; font-weight:600; letter-spacing:-0.01em; }}
.header .meta {{ margin:4px 0 0; font-size:12px; opacity:.8; }}
.header .version {{ margin-left:auto; font-size:11px; opacity:.65; text-transform:uppercase; letter-spacing:.08em; }}
.content {{ padding:20px 28px; }}

h2.sec {{
  font-size:1rem; color:var(--navy); font-weight:600;
  border-bottom:2px solid var(--gold); padding-bottom:5px; margin:28px 0 14px;
  display:flex; align-items:center; gap:8px;
}}
h2.sec::before {{ content:""; display:inline-block; width:4px; height:18px; background:var(--gold); border-radius:2px; }}

.card {{
  background:var(--card); border:1px solid var(--border); border-radius:8px;
  padding:16px 18px; margin-bottom:14px;
  box-shadow:0 1px 3px rgba(0,0,0,.04);
}}
.card-header {{
  display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;
}}
.card-header h3 {{ margin:0; font-size:1rem; }}
.meta {{ font-size:12px; color:var(--muted); margin:2px 0 0; }}
.kpi-row {{ display:flex; flex-wrap:wrap; gap:6px 14px; margin:8px 0; font-size:12px; color:var(--muted); }}
.kpi-row strong {{ color:var(--text); }}

.score-badge {{
  width:40px; height:40px; border-radius:50%;
  display:flex; align-items:center; justify-content:center;
  font-weight:700; font-size:18px; color:#fff; flex-shrink:0;
}}
.score-a {{ background:var(--good); }}
.score-b {{ background:#2d8a5e; }}
.score-c {{ background:var(--warn); }}
.score-d {{ background:#cc7a00; }}
.score-e {{ background:#c0392b; }}
.score-f {{ background:var(--bad); }}

.grade-hero {{
  display:flex; align-items:center; gap:16px;
  background:linear-gradient(135deg, var(--navy), var(--navy2));
  color:#fff; padding:16px 20px; border-radius:8px; margin-bottom:14px;
}}
.grade-hero .letter {{ font-size:48px; font-weight:700; line-height:1; opacity:.95; }}
.grade-hero .details {{ font-size:12px; opacity:.85; }}
.grade-hero .trust-score {{ font-size:22px; font-weight:600; }}

table.data {{ width:100%; border-collapse:collapse; font-size:12px; margin-top:6px; }}
table.data th, table.data td {{ border:1px solid var(--border); padding:5px 7px; text-align:left; vertical-align:top; }}
table.data th {{ background:#e9ecef; font-weight:600; font-size:10px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em; }}
table.data .num {{ text-align:right; }}
table.data .c {{ text-align:center; }}

.small {{ font-size:11px; }}
.muted {{ color:var(--muted); }}
.ok {{ color:var(--good); font-weight:600; }}
.warn {{ color:var(--warn); }}
.err {{ color:var(--bad); }}
.sev {{ display:inline-block; padding:1px 7px; border-radius:4px; font-size:10px; font-weight:600; text-transform:uppercase; }}
.sev.high {{ background:#fce4e4; color:var(--bad); }}
.sev.med {{ background:#fff3cd; color:#856404; }}
.sev.low {{ background:#e8f5e9; color:var(--good); }}

pre.small {{ background:#f8fafc; padding:8px; border-radius:6px; overflow:auto; max-height:180px; font-size:11px; border:1px solid var(--border); }}
ul.compact {{ margin:4px 0; padding-left:1.1rem; font-size:12.5px; }}
ul.compact li {{ margin:2px 0; }}
.footnote {{ font-size:11px; color:var(--muted); margin-top:32px; padding-top:12px; border-top:1px solid var(--border); }}
.risk-critical {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#5c1010; color:#fff; }}
.risk-high {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#9b1c1c; color:#fff; }}
.risk-med {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#cc8800; color:#fff; }}
.risk-low {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#2d7a4a; color:#fff; }}
.epss-badge {{ display:inline-block; font-size:10px; padding:1px 5px; border-radius:4px; background:#e8eef5; color:#3a5478; }}
.kev-badge {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#fce4e4; color:#a00; }}
details summary {{ cursor:pointer; }}
details summary:focus {{ outline:none; }}
.cve-badge {{ display:inline-block; background:#e9ecef; padding:0 6px; border-radius:3px; font-family:monospace; font-size:11px; }}
@media print {{
  body {{ background:#fff; }}
  .header {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .grade-hero {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .score-badge {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <img class="logo" src="{esc(LOGO_B64)}" alt="Grupo Cibest"/>
    <div>
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
        <div class="details">Grado orientativo (A-F) basado en controles ASM verificables &middot; Escaneo: {esc(gen)}</div>
      </div>
    </div>

    {toc_block}

  <h2 class="sec">Resumen de evaluación</h2>
    <div class="card">
      <p>Postura observada por <strong>Attack Surface Management (ASM)</strong> sobre <strong>{n} dominio(s)</strong> de proveedores. Las puntuaciones son indicativas, calculadas a partir de cabeceras HTTP, TLS, DNS (SPF/DMARC), reputación, vulnerabilidades, typosquatting, patching cadence y dependencias de terceros.</p>
      <div class="kpi-row">
        <span><strong>Activos:</strong> {n}</span>
        <span><strong>Subdominios (DNS):</strong> {total_subs}</span>
        <span><strong>Subdominios (crt.sh):</strong> {total_crt}</span>
        <span><strong>443 abierto:</strong> {open443}/{n}</span>
        <span><strong>80 abierto:</strong> {open80}/{n}</span>
        <span><strong>CAA:</strong> {has_caa}/{n}</span>
        <span><strong>MTA-STS:</strong> {has_mta_sts}/{n}</span>
        <span><strong>CVE detectados:</strong> {total_vulns}</span>
      </div>
    </div>

    {resumen_block}

  {score_legend_block}

    <h2 class="sec">Hallazgos</h2>
    <div class="card">
      <table class="data">
        <thead><tr><th>Categoria</th><th>Descripcion</th><th>Proveedores</th><th>Severidad</th></tr></thead>
        <tbody>{precia_blocks}

  {risk_table_rows()}</tbody>
      </table>
    </div>

    <h2 class="sec">Factores evaluados</h2>
    <div class="card">
      <p>Este informe evalua los siguientes factores de seguridad:</p>
      <table class="data">
        <thead><tr><th>Factor</th><th>Fuente</th><th>Detalle</th></tr></thead>
        <tbody>
          <tr><td>Configuraciones DNS</td><td>SPF/DMARC, DKIM, DNSSEC, DANE, MX, NS, CAA, MTA-STS, TLS-RPT, BIMI, STARTTLS</td><td>Verifica presencia y correcta configuración de registros DNS de seguridad y STARTTLS en MX</td></tr>
          <tr><td>SSL/TLS</td><td>Version negociada, vigencia, SAN</td><td>Evalua la fortaleza de la configuración TLS del servidor web</td></tr>
          <tr><td>Cabeceras HTTP de seguridad</td><td>HSTS, CSP, X-Frame-Options, X-Content-Type-Options</td><td>Detecta cabeceras de seguridad faltantes o mal configuradas</td></tr>
          <tr><td>Análisis de CSP</td><td>Directivas CSP (base-uri, object-src, frame-ancestors, form-action, unsafe-inline/unsafe-eval, comodines, bypass JSONP, report-uri)</td><td>Detección de debilidades en la política de seguridad de contenido</td></tr>
          <tr><td>Seguridad de Cookies</td><td>Flags Secure, HttpOnly, SameSite</td><td>Verificacion de flags de seguridad en cookies HTTP</td></tr>
          <tr><td>Superficie de subdominios</td><td>DNS prefijos + crt.sh + BufferOver + ThreatCrowd</td><td>Descubrimiento pasivo de subdominios y activos expuestos</td></tr>
          <tr><td>Reputación de IPs</td><td>DNSBL (Spamhaus, Barracuda, SpamCop, SORBS, CBL)</td><td>Verifica si las IPs del dominio estan listadas como maliciosas</td></tr>
          <tr><td>Malware</td><td>URLhaus (Abuse.ch)</td><td>Consulta si el dominio ha sido reportado como distribuidor de malware</td></tr>
          <tr><td>Vulnerabilidades</td><td>OSV.dev</td><td>Detección de CVEs asociados a tecnologias y versiones detectadas</td></tr>
          <tr><td>Fugas de credenciales</td><td>leak-lookup.com</td><td>Identifica si el dominio aparece en breaches conocidos (requiere LEAK_API_KEY)</td></tr>
          <tr><td>Typosquatting</td><td>Variantes DNS (TLD, caracteres, omisiones)</td><td>Genera variantes del dominio y verifica si estan activas</td></tr>
          <tr><td>Patching cadence</td><td>endoflife.date</td><td>Determina si las tecnologias detectadas estan EOL o proximas a EOL</td></tr>
          <tr><td>Subdomain Takeover</td><td>CNAME + fingerprints (S3, CloudFront, Heroku, Azure, GitHub Pages, etc.)</td><td>Detecta CNAMEs a servicios externos no configurados o colgantes</td></tr>
          <tr><td>Supply Chain</td><td>CSP headers + HTML scripts</td><td>Extrae dominios de terceros desde CSP y scripts, verifica resolucion DNS</td></tr>
          <tr><td>Reputación de terceros (Supply Chain)</td><td>DNSBL + URLhaus sobre IPs y dominios de terceros</td><td>Verifica si las IPs y dominios de la cadena de suministro tienen reputación negativa</td></tr>
        </tbody>
      </table>
    </div>

    <h2 class="sec">Matriz de controles ASM</h2>
    <div class="card" style="overflow:auto">
      <table class="data" style="font-size:10px">
        <thead><tr><th>Proveedor</th><th>Sub</th><th>crt.sh</th><th>HTTPS</th><th>HSTS</th><th>CSP</th><th>CSP-W</th><th>COOK</th><th>SPF/DMARC</th><th>TLS1.3</th><th>TLS</th><th>CAA</th><th>MTA-STS</th><th>TLS-RPT</th><th>STLS</th><th>MX</th><th>NS</th><th>DNSSEC</th><th>DKIM</th><th>DANE</th><th>DNSBL</th><th>URLH</th><th>CVE</th><th>LEAK</th><th>TYPO</th><th>PATCH</th><th>TKO</th><th>SC</th><th>SC-REP</th></tr></thead>
        <tbody>{matrix_html}</tbody>
      </table>
    </div>

    <h2 class="sec">Superficie de ataque por proveedor</h2>
    {"".join(prov_sections)}

    <h2 class="sec">CVEs frecuentes en ransomware (referencia)</h2>
    <div class="card">
      <p class="muted">En el informe PDF de referencia se listan CVEs con chequeo "Passed". Aquí no hay escaneo activo de CVE por host; use herramientas autorizadas (p. ej. nuclei con plantillas oficiales) si necesita esta capa.</p>
      <table class="data">
        <thead><tr><th>CVE</th><th>CVSSv3 (ref.)</th><th>Estado en este informe</th></tr></thead>
        <tbody>
          <tr><td>CVE-2021-44228</td><td>10.0</td><td class="muted">No evaluado (sin escaneo)</td></tr>
          <tr><td>CVE-2018-13379</td><td>9.8</td><td class="muted">No evaluado (sin escaneo)</td></tr>
          <tr><td>CVE-2020-5902</td><td>9.8</td><td class="muted">No evaluado (sin escaneo)</td></tr>
        </tbody>
      </table>
    </div>

    <div class="footnote">
      <p><strong>Grupo Cibest</strong> &middot; Informe generado el {esc(now)} &middot; Version {esc(version)} &middot; Los datos presentados reflejan el estado en el momento del escaneo y pueden variar.</p>
    </div>
  </div>
</div>
</body>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--asm", type=Path, default=ROOT / "asm_report.json")
    ap.add_argument("--out", type=Path, default=ROOT / "informe_grupocibest.html")
    ap.add_argument("--title", default="Third-Party Risk Assessment Report")
    ap.add_argument("--subtitle", default="Evaluacion ASM del sitio publico Informe (host www)")
    ap.add_argument("--version", default="1.0")
    args = ap.parse_args()
    asm = json.loads(args.asm.read_text(encoding="utf-8"))
    html_out = build_report(asm, args.title, args.subtitle, args.version)
    args.out.write_text(html_out, encoding="utf-8")
    print(f"[OK] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
