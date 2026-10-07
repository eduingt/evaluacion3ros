#!/usr/bin/env python3
"""
Genera informe HTML estilo Third-Party Risk Assessment (SOCRadar-like)
a partir de asm_report.json (salida de asm_scan.py).
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
from semi_canon import collect_semi_active_items
from precia_scorecard import render_precialike_block
from score_legend import render_score_legend
from toc_helper import render_toc
from resumen_ejecutivo import render_resumen_ejecutivo

FORMULA_VERSION = "B3-v2.0"
FORMULA_DATE = "2026-09-22"

ROOT = Path(__file__).resolve().parent


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


def build_report(asm: dict[str, Any], title: str, subtitle: str) -> str:
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
    providers_with_vulns = sum(1 for p in providers if p.get("vulnerabilities"))

    asm_score = min(1.0, round((missing_headers + https_fail + tls_issues) / max(1, n * 3), 4))
    drp_score = 0.0
    cti_score = 0.0

    starttls_missing = sum(1 for m in matrix if not m.get("starttls_ok") and m.get("mx_count", 0) > 0)

    risk_rows = [
        ("ASM / Application Security", "HTTP Missing Security Headers (HSTS o CSP)", missing_headers, 0.5),
        ("ASM / Email Security", "SPF ausente o dominio sin resolución", spf_missing, 0.3),
        ("ASM / Email Security", "SPF parcial / endurecimiento pendiente", spf_partial, 0.15),
        ("ASM / Email Security", "STARTTLS no soportado en MX", starttls_missing, 0.25),
        ("ASM / SSL-TLS", "HTTPS no verificable o error TLS en apex", https_fail, 0.45),
        ("ASM / SSL-TLS", "TLS negociado no constatado con 443 abierto", tls_issues, 0.2),
    ]
    if total_vulns:
        risk_rows.insert(0, ("ASM / Vulnerability Management", f"CVEs detectados en tecnologías del servidor", total_vulns, 0.6))
    total_leaks = sum(len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) for p in providers)
    if total_leaks:
        risk_rows.insert(0, ("ASM / Credential Security", "Dominios en breaches de credenciales conocidos", total_leaks, 0.55))
    total_typos = sum(len(p.get("typosquatting") or []) for p in providers)
    if total_typos:
        risk_rows.insert(0, ("ASM / Phishing", "Posibles dominios typosquatting resolviendo", total_typos, 0.5))
    total_patch_eol = sum(sum(1 for x in (p.get("patching") or []) if x.get("status") == "eol") for p in providers)
    if total_patch_eol:
        risk_rows.insert(0, ("ASM / Software Maintenance", "Tecnologías EOL detectadas", total_patch_eol, 0.5))
    total_takeover = sum(len(p.get("takeover_risks") or []) for p in providers)
    if total_takeover:
        risk_rows.insert(0, ("ASM / Subdomain Takeover", "Posibles subdominios vulnerables a takeover", total_takeover, 0.55))
    total_csp_weak = sum(len(p.get("csp_findings") or []) for p in providers)
    if total_csp_weak:
        risk_rows.insert(0, ("ASM / Application Security", "Debilidades en CSP detectadas", total_csp_weak, 0.4))
    total_cookie_insecure = sum(1 for p in providers if any(f.get("severity") in ("high",) for f in (p.get("cookie_findings") or [])))
    if total_cookie_insecure:
        risk_rows.insert(0, ("ASM / Application Security", "Cookies sin flags de seguridad (Secure/HttpOnly)", total_cookie_insecure, 0.4))
    total_scr_dnsbl = sum(m.get("supply_reputation_dnsbl_count", 0) for m in matrix)
    total_scr_urlhaus = sum(m.get("supply_reputation_urlhaus_count", 0) for m in matrix)
    if total_scr_dnsbl or total_scr_urlhaus:
        risk_rows.insert(0, ("ASM / Supply Chain Reputation", "IPs o dominios de terceros con reputación negativa (DNSBL/URLhaus)", total_scr_dnsbl + total_scr_urlhaus, 0.55))
    total_supply = sum(len(p.get("supply_chain") or []) for p in providers)
    if total_supply:
        risk_rows.insert(0, ("ASM / Supply Chain", "Dependencias de terceros detectadas (CSP/scripts)", total_supply, 0.35))
    total_fr_js = sum(len((p.get("finalrecon") or {}).get("javascripts") or []) + len(((p.get("finalrecon") or {}).get("wayback") or {}).get("js_files") or []) for p in providers)
    if total_fr_js:
        risk_rows.insert(0, ("ASM / Application Security", f"Archivos JavaScript expuestos ({total_fr_js})", total_fr_js, 0.35))
    total_fr_api = sum(len(((p.get("finalrecon") or {}).get("wayback") or {}).get("api_endpoints") or []) for p in providers)
    if total_fr_api:
        risk_rows.insert(0, ("ASM / Information Leak", f"Endpoints API en Wayback Machine ({total_fr_api})", total_fr_api, 0.5))
    total_fr_params = sum(len(((p.get("finalrecon") or {}).get("wayback") or {}).get("juicy_params") or []) for p in providers)
    if total_fr_params:
        risk_rows.insert(0, ("ASM / Information Leak", f"Parametros sensibles en Wayback Machine ({total_fr_params})", total_fr_params, 0.4))
    total_fr_sitemap = sum(len((p.get("finalrecon") or {}).get("sitemap") or []) for p in providers)
    if total_fr_sitemap:
        risk_rows.insert(0, ("ASM / Information Leak", f"Sitemap expuesto ({total_fr_sitemap} URLs)", total_fr_sitemap, 0.25))

    def risk_table_rows() -> str:
        out = []
        for typ, name, cnt, imp in risk_rows:
            if cnt <= 0:
                continue
            out.append(
                f"<tr><td>{esc(typ)}</td><td>{esc(name)}</td>"
                f"<td class='num'>{cnt}</td><td class='num'>{imp}</td></tr>"
            )
        if not out:
            out.append("<tr><td colspan='4' class='muted'>Sin hallazgos agregados en las categorías mostradas.</td></tr>")
        return "\n".join(out)

    def grade_from_trust(t: float) -> str:
        if t >= 90:
            return "A"
        if t >= 75:
            return "B"
        if t >= 60:
            return "C"
        if t >= 45:
            return "D"
        if t >= 30:
            return "E"
        return "F"

    grade = grade_from_trust(trust)

    # Precia-like scorecard blocks (one per provider, estilo SecurityScorecard)
    precia_blocks = "\n".join(render_precialike_block(p, analista="@eduingt", org=p.get("name") or p.get("domain",""), generated=gen) for p in providers)
    # Resumen Ejecutivo canónico (estilo Beta1)
    resumen_block = render_resumen_ejecutivo(providers, asm, score_general=int(trust), fecha_str=now, org="Incocredito", analista="@eduingt")

    
    score_legend_block = render_score_legend()
    def vuln_block(esc_f, vulns):
        if not vulns:
            return ""
        items = "".join(f"<li><strong>{esc_f(v.get('cve_id', v.get('id', '?')))}</strong> — {esc_f(v.get('summary', '')[:120])} <span class='muted'>({esc_f(v.get('package', ''))})</span></li>" for v in vulns)
        if len(vulns) > 30:
            items += f"<li class='muted'>… y {len(vulns) - 30} más</li>"
        return f"<h4>Vulnerabilidades (OSV.dev)</h4><ul class='compact'>{items}</ul>"

    def typo_block(esc_f, typos):
        if not typos:
            return ""
        items = "".join(f"<li><code>{esc_f(t.get('domain', ''))}</code> — {esc_f(', '.join(t.get('ips', [])))}</li>" for t in typos)
        if len(typos) > 10:
            items += f"<li class='muted'>… y {len(typos) - 10} más</li>"
        return f"<h4>Typosquatting detectados</h4><ul class='compact'>{items}</ul>"

    def patch_block(esc_f, patching):
        if not patching:
            return ""
        items = ""
        for pch in patching:
            status = pch.get("status", "")
            icon = "✓" if status == "current" else ("⚠" if status == "ending" else "✗")
            items += f"<li>{icon} <strong>{esc_f(pch.get('technology', ''))}</strong> {esc_f(pch.get('version', '') or '?')} — {esc_f(pch.get('detail', ''))}</li>"
        if len(patching) > 10:
            items += f"<li class='muted'>… y {len(patching) - 10} más</li>"
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
        def _badge(c):
            parts = []
            rs = c.get("risk_score")
            if rs is not None:
                if rs >= 7:
                    cls = "risk-critical"
                elif rs >= 4:
                    cls = "risk-high"
                elif rs >= 2:
                    cls = "risk-med"
                else:
                    cls = "risk-low"
                parts.append(f"<span class='{cls}'>Risk {rs:.1f}</span>")
            epss = c.get("epss_score")
            if epss is not None:
                parts.append(f"<span class='epss-badge'>EPSS {epss*100:.1f}%</span>")
            if c.get("in_kev"):
                parts.append("<span class='kev-badge'>KEV</span>")
            return " " + " ".join(parts) if parts else ""
        items = "".join(
            f"<li><strong>{esc_f(c.get('id', '?'))}</strong> — {esc_f(c.get('title', '')[:110])} "
            f"<span class='muted'>[{esc_f(c.get('type', ''))}] :{c.get('port', '?')} / {esc_f(c.get('product', ''))}</span>{_badge(c)}</li>"
            for c in cve_findings
        )
        if len(cve_findings) > 30:
            items += f"<li class='muted'>… y {len(cve_findings) - 30} más</li>"
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
        return f"<h4>Rutas Públicas (HEAD)</h4><table class='data'><thead><tr><th>Ruta</th><th>Status</th><th>Metodo</th></tr></thead><tbody>{items}</tbody></table>"

    def waf_block(esc_f, waf):
        if not waf or not waf.get("detected"):
            return ""
        names = " ".join(f"<span class='waf-badge'>{esc_f(w)}</span>" for w in waf.get("waf") or [])
        ev = "".join(f"<li class='muted'>{esc_f(e)}</li>" for e in waf.get("evidence") or [])
        return f"<h4>WAF / CDN detectado</h4><div>{names}</div><ul class='compact'>{ev}</ul>"

    def cloud_block(esc_f, cloud):
        if not cloud or not cloud.get("buckets"):
            return ""
        lines = []
        for b in cloud.get("buckets") or []:
            st = b.get("status_code")
            srv = b.get("server") or "?"
            status = "PUBLICO" if b.get("public") else ("privado" if b.get("error") is None else "error")
            sens = b.get("sensitive_files") or []
            extra = f" · sensibles: {len(sens)}" if sens else ""
            lines.append(
                f"<li><code>{esc_f(b.get('url',''))}</code> — {esc_f(srv)} "
                f"[<span class='{'risk-critical' if b.get('public') else 'muted'}'>{esc_f(status)}{extra}</span>]</li>"
            )
        return f"<h4>Cloud Storage / Buckets</h4><ul class='compact'>" + "".join(lines) + "</ul>"

    def kumo_block(esc_f, kumo):
        if not kumo or not isinstance(kumo, dict):
            return ""
        parts = []

        def sev_class(s):
            return {"critical": "risk-critical", "high": "risk-high",
                    "medium": "risk-med", "low": "risk-low"}.get(s or "", "muted")

        # wayback
        wb = (kumo.get("wayback") or {})
        if wb and not wb.get("error") and (wb.get("interesting") or wb.get("urls")):
            items = []
            if wb.get("range"):
                items.append(f"<li>Rango: {esc_f(wb['range'])} · {esc_f(str(wb.get('total', 0)))} URLs archivadas</li>")
            for u in (wb.get("interesting") or [])[:8]:
                items.append(f"<li><code>{esc_f(u)}</code></li>")
            parts.append(f"<h4>Wayback Machine</h4><ul class='compact'>{''.join(items)}</ul>")

        # breachintel
        bi = (kumo.get("breachintel") or {})
        if bi and not bi.get("error"):
            s = bi.get("summary") or {}
            bi_items = []
            if s.get("total_employees_leaked"): bi_items.append(f"Empleados filtrados: {s['total_employees_leaked']}")
            if s.get("total_clients_leaked"): bi_items.append(f"Clientes filtrados: {s['total_clients_leaked']}")
            if s.get("total_emails_found"): bi_items.append(f"Emails en leaks: {s['total_emails_found']}")
            if s.get("total_infostealer_hits"): bi_items.append(f"<b>Máquinas con infostealer: {s['total_infostealer_hits']}</b>")
            if s.get("breach_names"): bi_items.append(f"Breaches: {esc_f(', '.join(s['breach_names'][:6]))}")
            for cf in (s.get("critical_findings") or [])[:5]:
                bi_items.append(f"<li class='risk-critical'>{esc_f(str(cf))}</li>")
            if bi_items:
                parts.append(f"<h4>Breach Intelligence</h4><ul class='compact'><li>{' · '.join(bi_items)}</li></ul>")

        # robots / security.txt
        rb = (kumo.get("robots") or {})
        if rb and not rb.get("error") and (rb.get("robots") or rb.get("security_txt") or rb.get("sitemaps")):
            rp_items = []
            robots = rb.get("robots") or {}
            sens = [d for d in (robots.get("disallowed") or []) if d.get("sensitive")]
            if sens:
                rp_items.append(f"<li>Rutas sensibles en robots.txt: {' · '.join(esc_f(x['path']) for x in sens[:8])}</li>")
            if rb.get("security_txt"):
                rp_items.append(f"<li>security.txt: <code>{esc_f(rb['security_txt'].get('path',''))}</code> encontrado</li>")
            if rb.get("sitemaps"):
                rp_items.append(f"<li>Sitemaps: {esc_f(', '.join(rb['sitemaps'][:3]))}</li>")
            if rp_items:
                parts.append(f"<h4>Robots / Security</h4><ul class='compact'>{''.join(rp_items)}</ul>")

        # favicon
        fav = (kumo.get("favicon") or {})
        if fav and not fav.get("error") and fav.get("favicon_found"):
            tech = fav.get("technology")
            parts.append(
                f"<h4>Favicon Hash</h4><ul class='compact'>"
                f"<li>Shodan hash: <code>{fav.get('hash_shodan')}</code>"
                + (f" · Match: <span class='waf-badge'>{esc_f(tech)}</span>" if tech else "")
                + "</li></ul>"
            )

        # js_secrets
        js = (kumo.get("js_secrets") or {})
        if js and not js.get("error") and js.get("secrets"):
            sev = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
            items = "".join(
                f"<li><span class='{sev_class(x.get('severity'))}'>{sev.get(x.get('severity'), x.get('severity','?'))}</span> "
                f"<b>{esc_f(x.get('type',''))}</b> en <code>{esc_f(x.get('file',''))}</code> — {esc_f(str(x.get('value',''))[:60])}</li>"
                for x in (js.get("secrets") or [])[:12]
            )
            parts.append(f"<h4>JS Secrets ({js.get('total', len(js.get('secrets', [])))})</h4><ul class='compact'>{items}</ul>")

        # content_intel
        ci = (kumo.get("content_intel") or {})
        if ci and not ci.get("error"):
            cats = ci.get("categories") or {}
            ci_items = []
            sens = cats.get("sensitive") or []
            if sens:
                for x in sens[:6]:
                    ci_items.append(f"<li><span class='{sev_class(x.get('severity','low'))}'>{esc_f(x.get('kind','Sensible'))}</span>: <code>{esc_f(str(x.get('value',''))[:70])}</code></li>")
            for k in ("api_endpoints", "databases", "cloud_storage", "internal_hosts"):
                for x in (cats.get(k) or [])[:6]:
                    ci_items.append(f"<li><b>{k.replace('_',' ').upper()}</b>: <code>{esc_f(str(x.get('value',''))[:70])}</code></li>")
            if ci_items:
                parts.append(f"<h4>Content Intelligence ({ci.get('total')})</h4><ul class='compact'>{''.join(ci_items)}</ul>")

        # api_fuzzer
        af = (kumo.get("api_fuzzer") or {})
        if af and not af.get("error") and (af.get("endpoints") or af.get("graphql")):
            items = []
            for e in (af.get("endpoints") or [])[:12]:
                items.append(f"<li><code>{esc_f(str(e.get('path','')))}</code> — {e.get('status','?')} "
                             f"[<span class='{sev_class(e.get('severity'))}'>{esc_f(e.get('severity','?'))}</span>] {esc_f(e.get('name',''))}</li>")
            if af.get("graphql"):
                g = af["graphql"]
                items.append(f"<li><span class='{sev_class(g.get('severity'))}'>{esc_f(g.get('severity','?'))}</span> "
                             f"<code>{esc_f(str(g.get('path','')))}</code> — {esc_f(g.get('detail',''))}</li>")
            if items:
                parts.append(f"<h4>API Fuzzer</h4><ul class='compact'>{''.join(items)}</ul>")

        # nuclei
        nu = (kumo.get("nuclei") or {})
        if nu and not nu.get("error"):
            sc = nu.get("severity_counts") or {}
            sev_items = []
            for sev_n in ("critical", "high", "medium", "low", "info"):
                if sc.get(sev_n):
                    sev_items.append(f"{sc[sev_n]} {sev_n}")
            items = "".join(
                f"<li><span class='{sev_class(f.get('severity'))}'>{esc_f(f.get('severity','?'))}</span> "
                f"{esc_f(f.get('name','?'))}{' — ' + esc_f(f.get('description',''))[:90] if f.get('description') else ''}</li>"
                for f in (nu.get("findings") or [])[:15]
            )
            head = f"<p class='meta'>{' · '.join(sev_items)}</p>" if sev_items else ""
            if items:
                parts.append(f"<h4>Vuln Scanner KUMO (nuclei)</h4>{head}<ul class='compact'>{items}</ul>")

        if not parts:
            return ""
        return "\n".join(parts)

    def prism_block(esc_f, prism):
        if not prism or not isinstance(prism, dict):
            return ""
        parts = []

        # leak_lookup — breaches aggregadas (XON / LeakCheck / HIBP / Leak-Lookup)
        ll = (prism.get("leak_lookup") or {})
        if ll and not ll.get("error"):
            if ll.get("breaches"):
                items = "".join(
                    f"<li><span class='risk-high'>{esc_f(b.get('name','?'))}</span></li>"
                    for b in ll["breaches"][:20]
                )
                parts.append(f"<h4>Prism Breach Lookup ({len(ll.get('breaches', []))} filtración(es))</h4><ul class='compact'>{items}</ul>")
            else:
                parts.append("<h4>Prism Breach Lookup</h4><p class='muted'>Sin filtraciones en las fuentes consultadas (XposedOrNot, LeakCheck, HIBP, Leak-Lookup)</p>")

        # onion_checker — mirrors .onion
        oc = (prism.get("onion_checker") or {})
        if oc and not oc.get("error") and oc.get("results"):
            items = "".join(
                f"<li><code>{esc_f(r.get('url','?'))}</code> (<span class='waf-badge'>{esc_f(r.get('source','?'))}</span>)</li>"
                for r in oc["results"][:10]
            )
            parts.append(f"<h4>Prism Onion / Dark Web ({oc.get('total_found', 0)})</h4><ul class='compact'>{items}</ul>")

        # github_recon — org profile
        gh = (prism.get("github_recon") or {})
        if gh and not gh.get("error") and gh.get("profile"):
            prof = gh.get("profile") or {}
            gh_items = []
            if prof.get("name"): gh_items.append(f"Nombre: {esc_f(prof['name'])}")
            if prof.get("company"): gh_items.append(f"Compañía: {esc_f(prof['company'])}")
            if gh.get("repo_count"): gh_items.append(f"Repos: {gh.get('repo_count')} · Stars: {gh.get('total_stars', 0)}")
            if gh.get("emails"): gh_items.append(f"Emails: {esc_f(', '.join(gh['emails']))}")
            if gh_items:
                parts.append(f"<h4>Prism GitHub Recon @{esc_f(gh.get('username','?'))}</h4><ul class='compact'>" + "".join(f"<li>{x}</li>" for x in gh_items) + "</ul>")

        # gravatar — perfiles de persona desde emails
        gr = (prism.get("gravatar") or {})
        if gr and not gr.get("error") and gr.get("hits"):
            items = "".join(
                f"<li><b>{esc_f(h.get('display_name','?'))}</b> ({esc_f(h.get('email','?'))})"
                + (f" — {esc_f('; '.join(a.get('display') or a.get('name') or '?' for a in h.get('accounts') or [])[:120])}" if h.get("accounts") else "")
                + "</li>"
                for h in gr["hits"][:8]
            )
            parts.append(f"<h4>Prism Gravatar ({gr.get('total_hits', 0)} perfil(es))</h4><ul class='compact'>{items}</ul>")

        # website_analyzer — tech stack + social + emails/phones del HTML
        wa = (prism.get("website_analyzer") or {})
        if wa and not wa.get("error"):
            wa_items = []
            if wa.get("technologies"):
                wa_items.append("<li><b>Tecnologías:</b> " + esc_f(", ".join(wa["technologies"])) + "</li>")
            if wa.get("social_links"):
                wa_items.append("<li><b>Redes:</b> " + " · ".join(f"{esc_f(s.get('platform','?'))}: @{esc_f(s.get('username','?'))}" for s in wa["social_links"][:8]) + "</li>")
            if wa.get("emails"):
                wa_items.append("<li><b>Emails web:</b> " + esc_f(", ".join(wa["emails"][:8])) + "</li>")
            if wa.get("phones"):
                wa_items.append("<li><b>Teléfonos:</b> " + esc_f(", ".join(wa["phones"][:5])) + "</li>")
            if wa_items:
                parts.append(f"<h4>Prism Website Analyzer</h4><ul class='compact'>{''.join(wa_items)}</ul>")

        # smtp_verify — emails verificados
        sv = (prism.get("smtp_verify") or {})
        if sv and not sv.get("error") and sv.get("per_email"):
            sv_items = []
            for r in sv["per_email"]:
                if not isinstance(r, dict):
                    continue
                st = "existe" if r.get("exists") is True else ("no existe" if r.get("exists") is False else "indefinido")
                note = " · catch-all" if r.get("catch_all") else ""
                sv_items.append(f"<li><code>{esc_f(r.get('email','?'))}</code>: <b>{st}</b>{note}</li>")
            head = "<p class='meta'>Catch-all: %s</p>" % ("Sí" if sv.get("catch_all") else "No")
            if sv_items:
                parts.append(f"<h4>Prism SMTP Verify</h4>{head}<ul class='compact'>{''.join(sv_items)}</ul>")

        # virustotal — reputación dominio
        vt = (prism.get("virustotal") or {})
        if vt and not vt.get("error") and vt.get("status") == "ok":
            verdict = "malicioso" if vt.get("malicious") else ("sospechoso" if vt.get("suspicious") else "limpio")
            vt_items = [f"<code>{esc_f(vt.get('query','?'))}</code>: <b>{verdict}</b>"]
            if vt.get("malicious"): vt_items.append(f"{vt.get('malicious')} malicioso")
            if vt.get("suspicious"): vt_items.append(f"{vt.get('suspicious')} sospechoso")
            if vt.get("reputation") is not None: vt_items.append(f"reputación {vt.get('reputation')}")
            if vt.get("categories"):
                cats = list(set(str(c) for c in vt["categories"].values()))
                vt_items.append("categorías: " + esc_f(", ".join(cats[:5])))
            parts.append("<h4>Prism VirusTotal</h4><ul class='compact'><li>" + " · ".join(vt_items) + "</li></ul>")

        # abuseipdb — reputación IP
        ab = (prism.get("abuseipdb") or {})
        if ab and not ab.get("error") and ab.get("status") == "ok":
            ab_items = []
            if ab.get("abuse_score") is not None:
                ab_items.append(f"Abuse score: <b>{ab.get('abuse_score')}/100</b>")
            if ab.get("total_reports"): ab_items.append(f"{ab.get('total_reports')} reporte(s)")
            if ab.get("is_tor"): ab_items.append("TOR exit node")
            if ab.get("isp"): ab_items.append(esc_f(ab["isp"]))
            if ab.get("domain"): ab_items.append(esc_f(ab["domain"]))
            parts.append("<h4>Prism AbuseIPDB</h4><ul class='compact'><li>" + " · ".join(ab_items) + "</li></ul>")

        if not parts:
            return ""
        return "\n".join(parts)

    def claude_osint_block(esc_f, co):
        if not co or not isinstance(co, dict):
            return ""
        parts = []

        def _skip(obj):
            return obj and not obj.get("error") and not obj.get("skipped")

        # m365_fingerprint — tenant Azure/Entra Fingerprint
        m365 = co.get("m365_fingerprint") or {}
        if _skip(m365):
            m_items = []
            if m365.get("tenant_space"):
                m_items.append(f"Espacio namespace: <b>{esc_f(m365['tenant_space'])}</b>")
            if m365.get("tenant_guid"):
                m_items.append(f"Tenant GUID: <code>{esc_f(m365['tenant_guid'])}</code>")
            if m365.get("auth_url"):
                m_items.append(f"Auth URL: <code>{esc_f(m365['auth_url'][:90])}</code>")
            if m365.get("oidc"):
                m_items.append(f"OIDC issuer: <code>{esc_f(m365['oidc'].get('issuer',''))}</code>")
            if m365.get("m365_detected"):
                m_items.append("Microsoft 365 detectado (Autodiscover)")
            if m365.get("federation_endpoint"):
                m_items.append(f"Federation endpoint: {esc_f(m365['federation_endpoint'])}")
            if m_items:
                parts.append(f"<h4>Claude-OSINT M365 Fingerprint</h4><ul class='compact'>"
                             + "".join(f"<li>{x}</li>" for x in m_items) + "</ul>")

        # spf_supply_chain — verdict spoof + supply chain SPF
        spf = co.get("spf_supply_chain") or {}
        if _skip(spf):
            v = spf.get("verdict") or {}
            sev = {"ALTO": "risk-high", "MEDIO": "risk-med", "INFO": "muted"}.get((v.get("severity") or "").upper(), "muted")
            sp_items = [f"Verdict: <b><span class='{sev}'>{esc_f(v.get('spoofable','?'))}</span></b> — {esc_f(v.get('vector',''))}"]
            sc = spf.get("supply_chain") or {}
            if sc:
                sp_items.append(f"Coste lookups SPF: {sc.get('lookup_cost_mechanisms')} · voids: {sc.get('void_lookups')}")
                if sc.get("dead_includes"):
                    sp_items.append(f"Dead includes: <code>{esc_f(', '.join(sc['dead_includes'][:6]))}</code>")
                if sc.get("perm_error"):
                    sp_items.append("<span class='risk-high'>PermError SPF → fail-open</span>")
            parts.append(f"<h4>Claude-OSINT SPF/DMARC Supply-chain</h4><ul class='compact'>"
                         + "".join(f"<li>{x}</li>" for x in sp_items) + "</ul>")

        # org_attribution — GLEIF + crt.sh O=
        org = co.get("org_attribution") or {}
        if _skip(org):
            o_items = []
            if org.get("lei"):
                o_items.append(f"LEI: <code>{esc_f(org['lei'])}</code> — {esc_f(org.get('legal_name') or '')} ({esc_f(org.get('jurisdiction') or '')})")
            if org.get("direct_children"):
                names = [c.get("name") or "?" for c in org["direct_children"][:8]]
                o_items.append(f"Hijos directos GLEIF: {esc_f(', '.join(names))}")
            if org.get("crt_sh_org", {}).get("candidate_domains"):
                cands = org["crt_sh_org"]["candidate_domains"][:10]
                o_items.append(f"crt.sh O= ({org['crt_sh_org'].get('certificates',0)} cert): <code>{esc_f(', '.join(cands))}</code>")
            if o_items:
                parts.append(f"<h4>Claude-OSINT Org Attribution (GLEIF + crt.sh O=)</h4><ul class='compact'>"
                             + "".join(f"<li>{x}</li>" for x in o_items) + "</ul>")

        # cti_chatter — ransomware + HN
        cti = co.get("cti_chatter") or {}
        if _skip(cti):
            c_items = []
            rw = cti.get("ransomwatch") or {}
            if rw.get("hits"):
                c_items.append(f"Ransomwatch: <b>{rw.get('total',0)}</b> — " + esc_f("; ".join(h.get('title','?')[:80] for h in rw["hits"][:4])))
            rl = cti.get("ransomware_live") or {}
            if rl.get("hits"):
                c_items.append(f"Ransomware.live: <b>{rl.get('total',0)}</b> — " + esc_f("; ".join(h.get('victim','?')[:80] for h in rl["hits"][:4])))
            hn = cti.get("hackernews") or {}
            if hn.get("hits"):
                c_items.append("HackerNews: " + esc_f("; ".join(h.get('title','?')[:80] for h in hn["hits"][:3])))
            if c_items:
                parts.append(f"<h4>Claude-OSINT CTI Chatter</h4><ul class='compact'>"
                             + "".join(f"<li>{x}</li>" for x in c_items) + "</ul>")

        # passive_dns_extra
        pdn = co.get("passive_dns_extra") or {}
        if _skip(pdn) and pdn.get("subdomains"):
            subs = pdn["subdomains"][:12]
            srcs = pdn.get("sources") or {}
            src_txt = ", ".join(f"{k}: {v}" for k, v in list(srcs.items())[:5])
            parts.append(f"<h4>Claude-OSINT Passive DNS extra ({len(pdn.get('subdomains', []))})</h4>"
                         f"<p class='meta'>{esc_f(src_txt)}</p><ul class='compact'>"
                         + "".join(f"<li><code>{esc_f(s)}</code></li>" for s in subs) + "</ul>")

        # cloud_native_fp
        cn = co.get("cloud_native_fp") or {}
        if _skip(cn) and cn.get("fingerprints"):
            fp_items = "".join(
                f"<li><b>{esc_f(f.get('service','?'))}</b> — <code>{esc_f(f.get('cname','?'))}</code></li>"
                for f in cn["fingerprints"][:8]
            )
            parts.append(f"<h4>Claude-OSINT Cloud-native fingerprint</h4><ul class='compact'>{fp_items}</ul>")

        # saml_oidc_probe
        sop = co.get("saml_oidc_probe") or {}
        if _skip(sop):
            so_items = []
            for key, label in (("openid_config", "OIDC"), ("saml_metadata", "SAML"), ("adfs_mex", "ADFS")):
                ch = sop.get(key) or {}
                if ch.get("reachable"):
                    extra = " (metadata)" if ch.get("is_metadata") else ""
                    hint = f" — {esc_f(ch['issuer_hint'])}" if ch.get("issuer_hint") else ""
                    so_items.append(f"{label}: {ch.get('status','?')}{extra}{hint}")
            if so_items:
                parts.append(f"<h4>Claude-OSINT SSO/OIDC probe</h4><ul class='compact'>"
                             + "".join(f"<li>{x}</li>" for x in so_items) + "</ul>")

        # secret_scan
        ss = co.get("secret_scan") or {}
        if _skip(ss) and ss.get("critical"):
            s_items = "".join(
                f"<li><span class='risk-critical'>{esc_f(g.get('pattern','?'))}</span> x{g.get('count')} — <code>{esc_f(str(g.get('first',''))[:80])}</code></li>"
                for g in ss["critical"][:5]
            )
            parts.append(f"<h4>Claude-OSINT Secret Scan ({ss.get('total_matches',0)} match(es))</h4><ul class='compact'>{s_items}</ul>")

        # h1_reference
        h1 = co.get("h1_reference") or {}
        if _skip(h1) and h1.get("references"):
            def _sev_badge(s):
                return (f" <span class='risk-high'>sev {esc_f(s)}</span>") if s else ""
            h_items = "".join(
                f"<li><b>{esc_f(r.get('program') or '?')}</b> — {esc_f(r.get('title','?'))}"
                + _sev_badge(str(r.get('severity')))
                + (f" · {r.get('votes')} votes" if r.get('votes') else "")
                + "</li>"
                for r in h1["references"][:6]
            )
            parts.append(f"<h4>Claude-OSINT HackerOne references</h4><ul class='compact'>{h_items}</ul>")

        if not parts:
            return ""
        return "\n".join(parts)

    def strix_block(esc_f, strix):
        if not strix or not isinstance(strix, dict) or strix.get("status") != "ok":
            return ""
        findings = strix.get("findings") or []
        parts = []
        run_rec = strix.get("run_record") or {}
        meta = [
            f"Modo: <b>{esc_f(strix.get('mode','?'))}</b>",
            f"Hallazgos: <b>{len(findings)}</b>",
        ]
        usage = (run_rec.get("llm_usage") or {})
        if usage.get("total_cost_usd"):
            meta.append(f"Costo LLM: ${float(usage['total_cost_usd']):.2f}")
        if strix.get("exit_code") == 2:
            meta.append("<span class='risk-high'>vulnerabilidades encontradas</span>")
        elif strix.get("exit_code") == 0:
            meta.append("<span class='ok'>sin hallazgos validados</span>")
        parts.append(f"<h4>Strix AI Pentest</h4><p class='meta'>{' · '.join(meta)}</p>")

        if findings:
            rows = "".join(
                f"<tr><td><span class='risk-{esc_f(r.get('severity','low'))}'>{esc_f(r.get('severity','?'))}</span></td>"
                f"<td>{esc_f(r.get('title','?'))}</td>"
                f"<td>{esc_f(r.get('cve','-'))}</td><td>{esc_f(r.get('cwe','-'))}</td>"
                f"<td>{esc_f(r.get('cvss',''))}</td></tr>"
                for r in sorted(findings, key=lambda x: (str(x.get('severity','low')).lower() not in ("critical","high"), x.get('cvss') or 0), reverse=True)[:20]
            )
            parts.append(
                f"<table class='data'><thead><tr><th>Severidad</th><th>Titulo</th><th>CVE</th><th>CWE</th><th>CVSS</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
            top = sorted(findings, key=lambda x: (str(x.get('severity','low')).lower() not in ("critical","high"), x.get('cvss') or 0), reverse=True)[0]
            parts.append(f"<p class='muted small'>Top: <code>{esc_f(top.get('endpoint',''))}</code> · {esc_f(top.get('remediation_steps',''))[:200]}</p>")

        rec = (strix.get("scan_results") or {})
        if rec.get("executive_summary"):
            parts.append(f"<p><strong>Resumen ejecutivo:</strong> {esc_f(rec['executive_summary'][:400])}</p>")
        return "\n".join(parts)

    def who_dat_block(esc_f, wd):
        if not wd or not isinstance(wd, dict):
            return ""
        apex = wd.get("apex") or {}
        if not apex or apex.get("error"):
            return ""
        parts = []

        apex_norm = apex
        registered = apex_norm.get("is_registered")
        parts.append(f"<p class='meta'>Dominio: <b>{esc_f(apex_norm.get('domain','?'))}</b> · Registrado: <b>{'Sí' if registered else 'No'}</b> · Fuente: who-dat (RDAP+WHOIS normalizado)</p>")

        items = []
        if apex_norm.get("registrar"):
            items.append(f"<li><strong>Registrar:</strong> {esc_f(apex_norm['registrar'])}</li>")
        if apex_norm.get("creation_date"):
            items.append(f"<li><strong>Creación:</strong> {esc_f(apex_norm['creation_date'])}</li>")
        if apex_norm.get("expiration_date"):
            items.append(f"<li><strong>Expiración:</strong> {esc_f(apex_norm['expiration_date'])}</li>")
        if apex_norm.get("updated_date"):
            items.append(f"<li><strong>Última actualización:</strong> {esc_f(apex_norm['updated_date'])}</li>")
        if apex_norm.get("name_servers"):
            ns = ", ".join(apex_norm["name_servers"][:5])
            items.append(f"<li><strong>Nameservers:</strong> {esc_f(ns)}</li>")
        if apex_norm.get("dnssec") is not None:
            items.append(f"<li><strong>DNSSEC:</strong> {'✓ Habilitado' if apex_norm['dnssec'] else '✗ Deshabilitado'}</li>")
        if apex_norm.get("status"):
            items.append(f"<li><strong>Estado:</strong> {esc_f(', '.join(apex_norm['status'][:5]))}</li>")

        registrant = apex_norm.get("registrant") or {}
        if any(registrant.values()):
            reg_items = []
            if registrant.get("organization"): reg_items.append(f"Org: {esc_f(registrant['organization'])}")
            if registrant.get("name"): reg_items.append(f"Nombre: {esc_f(registrant['name'])}")
            if registrant.get("email"): reg_items.append(f"Email: {esc_f(registrant['email'])}")
            if registrant.get("country"): reg_items.append(f"País: {esc_f(registrant['country'])}")
            if reg_items:
                items.append(f"<li><strong>Registrante:</strong> {' · '.join(reg_items)}</li>")

        admin = apex_norm.get("admin") or {}
        if any(admin.values()):
            adm_items = []
            if admin.get("organization"): adm_items.append(f"Org: {esc_f(admin['organization'])}")
            if admin.get("email"): adm_items.append(f"Email: {esc_f(admin['email'])}")
            if adm_items:
                items.append(f"<li><strong>Admin:</strong> {' · '.join(adm_items)}</li>")

        technical = apex_norm.get("technical") or {}
        if any(technical.values()):
            tech_items = []
            if technical.get("organization"): tech_items.append(f"Org: {esc_f(technical['organization'])}")
            if technical.get("email"): tech_items.append(f"Email: {esc_f(technical['email'])}")
            if tech_items:
                items.append(f"<li><strong>Técnico:</strong> {' · '.join(tech_items)}</li>")

        if items:
            parts.append(f"<h4>WHOIS/RDAP (apex)</h4><ul class='compact'>{''.join(items)}</ul>")

        subs = wd.get("subdomains") or {}
        if subs:
            sub_items = []
            for sub_domain, sub_data in list(subs.items())[:5]:
                if sub_data.get("error"):
                    sub_items.append(f"<li><code>{esc_f(sub_domain)}</code>: error - {esc_f(sub_data['error'])}</li>")
                elif sub_data.get("is_registered"):
                    sub_items.append(f"<li><code>{esc_f(sub_domain)}</code>: registrado ({esc_f(sub_data.get('registrar','?'))})</li>")
                else:
                    sub_items.append(f"<li><code>{esc_f(sub_domain)}</code>: no registrado</li>")
            if sub_items:
                parts.append(f"<h4>Subdominios consultados</h4><ul class='compact'>{''.join(sub_items)}</ul>")

        if not parts:
            return ""
        return "\n".join(parts)

    def nuclei_block(esc_f, nuclei):
        if not nuclei or not isinstance(nuclei, dict):
            return ""
        status = nuclei.get("status", "unknown")
        if status not in ("ok", "partial", "error", "skipped", "timeout"):
            return ""
        findings = nuclei.get("findings") or []
        sev_counts = nuclei.get("severity_counts") or {}
        parts = []

        meta = [
            f"Total: <b>{len(findings)}</b> hallazgo(s)",
            f"Severidad: {' · '.join(f'{k}: {v}' for k, v in sorted(sev_counts.items(), key=lambda x: ['critical','high','medium','low','info'].index(x[0]) if x[0] in ['critical','high','medium','low','info'] else 99))}",
            f"Tiempo: {nuclei.get('elapsed_seconds', 0)}s",
        ]
        parts.append(f"<h4>Nuclei Vulnerability Scanner</h4><p class='meta'>{' · '.join(meta)}</p>")

        if findings:
            # Agrupar por severidad
            sev_order = ["critical", "high", "medium", "low", "info"]
            for sev in sev_order:
                sev_findings = [f for f in findings if f.get("severity") == sev]
                if not sev_findings:
                    continue
                sev_class = {"critical": "risk-critical", "high": "risk-high", "medium": "risk-med", "low": "risk-low", "info": "muted"}.get(sev, "muted")
                rows = "".join(
                    f"<tr><td><span class='{sev_class}'>{sev.upper()}</span></td>"
                    f"<td>{esc_f(f.get('template_name', f.get('template_id', '?')))}</td>"
                    f"<td><code>{esc_f(f.get('template_id', '?'))}</code></td>"
                    f"<td>{esc_f(f.get('matched_at', '')[:80])}</td>"
                    f"<td>{esc_f(f.get('description', '')[:120])}</td>"
                    f"<td>{esc_f(', '.join(f.get('tags', [])[:3]))}</td></tr>"
                    for f in sev_findings[:15]
                )
                parts.append(
                    f"<table class='data'><thead><tr><th>Severidad</th><th>Plantilla</th><th>ID</th><th>Match</th><th>Descripción</th><th>Tags</th></tr></thead>"
                    f"<tbody>{rows}</tbody></table>"
                )

        if nuclei.get("status") == "partial":
            parts.append("<p class='muted small'>Escaneo parcial (algunos módulos fallaron o timeout)</p>")
        elif nuclei.get("status") in ("error", "skipped", "timeout"):
            reason = nuclei.get("error") or nuclei.get("reason") or "sin detalles"
            parts.append(f"<p class='muted small'>No ejecutado: {esc_f(reason)}</p>")
        return "\n".join(parts)

    def gobuster_block(esc_f, gobuster):
        if not gobuster or not isinstance(gobuster, dict):
            return ""
        status = gobuster.get("status", "unknown")
        if status not in ("ok", "partial", "error", "skipped", "timeout"):
            return ""
        modes = gobuster.get("modes") or {}
        parts = []

        meta = [f"Estado: <b>{gobuster.get('status', '?')}</b>"]
        if gobuster.get("level"):
            meta.append(f"Nivel: {gobuster['level']}")
        parts.append(f"<h4>Gobuster Content Discovery</h4><p class='meta'>{' · '.join(meta)}</p>")

        # Modo dir (directorios/archivos)
        dir_mode = modes.get("dir") or {}
        if dir_mode.get("findings"):
            findings = dir_mode["findings"]
            rows = "".join(
                f"<tr><td><code>{esc_f(f.get('path', '?'))}</code></td>"
                f"<td>{f.get('status_code', '?')}</td>"
                f"<td>{f.get('size', '?')}</td></tr>"
                for f in findings[:50]
            )
            parts.append(
                f"<h5>Directorios/Archivos (dir)</h5>"
                f"<p class='meta'>Wordlist: {esc_f(dir_mode.get('wordlist', '?'))} · {len(findings)} hallazgos · {dir_mode.get('elapsed_seconds', 0)}s</p>"
                f"<table class='data'><thead><tr><th>Ruta</th><th>Status</th><th>Size</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )

        # Modo dns (subdominios)
        dns_mode = modes.get("dns") or {}
        if dns_mode.get("findings"):
            findings = dns_mode["findings"]
            rows = "".join(
                f"<tr><td><code>{esc_f(f.get('subdomain', '?'))}</code></td>"
                f"<td>{esc_f(f.get('ip', '?'))}</td></tr>"
                for f in findings[:50]
            )
            parts.append(
                f"<h5>Subdominios (dns)</h5>"
                f"<p class='meta'>Wordlist: {esc_f(dns_mode.get('wordlist', '?'))} · {len(findings)} hallazgos · {dns_mode.get('elapsed_seconds', 0)}s</p>"
                f"<table class='data'><thead><tr><th>Subdominio</th><th>IP</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )

        # Modo vhost
        vhost_mode = modes.get("vhost") or {}
        if vhost_mode.get("findings"):
            findings = vhost_mode["findings"]
            rows = "".join(
                f"<tr><td><code>{esc_f(f.get('vhost', '?'))}</code></td>"
                f"<td>{f.get('size', '?')}</td></tr>"
                for f in findings[:30]
            )
            parts.append(
                f"<h5>Virtual Hosts (vhost)</h5>"
                f"<p class='meta'>Wordlist: {esc_f(vhost_mode.get('wordlist', '?'))} · {len(findings)} hallazgos · {vhost_mode.get('elapsed_seconds', 0)}s</p>"
                f"<table class='data'><thead><tr><th>VHost</th><th>Size</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )

        if gobuster.get("status") == "partial":
            parts.append("<p class='muted small'>Escaneo parcial (algunos modos fallaron o timeout)</p>")
        elif gobuster.get("status") in ("error", "skipped", "timeout"):
            reason = gobuster.get("error") or gobuster.get("reason") or "sin detalles"
            parts.append(f"<p class='muted small'>No ejecutado: {esc_f(reason)}</p>")
        return "\n".join(parts)

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
        idb = ext.get("internetdb") or {}
        if idb.get("ips"):
            idb_items = []
            for ip, entry in list(idb["ips"].items())[:6]:
                seg = []
                if entry.get("ports"): seg.append(f"puertos: {esc_f(', '.join(str(p) for p in sorted(entry['ports'])[:15]))}")
                if entry.get("vulns"): seg.append(f"<b>CVEs: {esc_f(', '.join(entry['vulns'][:8]))}</b>")
                if entry.get("cpes"): seg.append(f"CPE: {esc_f(', '.join(entry['cpes'][:4]))}")
                if entry.get("hostnames"): seg.append(f"host: {esc_f(', '.join(entry['hostnames'][:4]))}")
                state = ("sin datos" if entry.get("enriched") is False else "--")
                line = " · ".join(seg) if seg else state
                idb_items.append(f"<li><strong>{esc_f(ip)}</strong> — {line}</li>")
            parts.append(f"<h4>Shodan InternetDB</h4><ul class='compact'>{''.join(idb_items)}</ul>")
        expo = ext.get("shodan_exposure") or {}
        if expo:
            em = []
            if expo.get("ip_count"): em.append(f"IPs: {expo['ip_count']}")
            if expo.get("puertos_expuestos"): em.append(f"Puertos expuestos: {esc_f(', '.join(str(p) for p in expo['puertos_expuestos'][:20]))}")
            if expo.get("total_cves"): em.append(f"<b>CVEs: {expo['total_cves']}</b>")
            if expo.get("critico"):
                em.append("<span class='risk-critical'>Exposición confirmada</span>")
            if em:
                parts.append(f"<h4>Shodan Internet Exposure</h4><ul class='compact'><li>{' · '.join(em)}</li></ul>")
        return "\n".join(parts)

    def pasivo_canon_block(esc_f, p):
        items = [it for it in collect_pasive_items(p) if it.get("status") == "ok"]
        if not items:
            return ""
        by_group: dict[str, list] = {}
        for it in items:
            by_group.setdefault(it.get("grupo") or "Otros", []).append(it)
        parts = []
        for grupo, its in by_group.items():
            listed = "".join(f"<li><strong>{esc_f(it['label'])}:</strong> {esc_f(it['valor'])}</li>" for it in its)
            parts.append(f"<h4>Panorama pasivo · {esc_f(grupo)}</h4><ul class='compact'>{listed}</ul>")
        return "<h4>Panorama pasivo (canónico nivel 1)</h4>" + "\n".join(parts)

    def semi_canon_block(esc_f, p):
        items = [it for it in collect_semi_active_items(p) if it.get("status") == "ok"]
        if not items:
            return ""
        by_group: dict[str, list] = {}
        for it in items:
            by_group.setdefault(it.get("grupo") or "Otros", []).append(it)
        parts = []
        for grupo, its in by_group.items():
            listed = "".join(f"<li><strong>{esc_f(it['label'])}:</strong> {esc_f(it['valor'])}</li>" for it in its)
            parts.append(f"<h4>Semi-activo · {esc_f(grupo)}</h4><ul class='compact'>{listed}</ul>")
        return "<h4>Panorama semi-activo (canónico nivel 2)</h4>" + "\n".join(parts)

    def takeover_block(esc_f, risks):
        if not risks:
            return ""
        items = "".join(
            f"<li><code>{esc_f(r.get('host', ''))}</code> → <code>{esc_f(r.get('cname', ''))}</code>"
            f" {'🔴 VULNERABLE' if r.get('vulnerable') else '🟡 POTENCIAL'}: {esc_f(r.get('description', ''))}</li>"
            for r in risks
        )
        if len(risks) > 10:
            items += f"<li class='muted'>… y {len(risks) - 10} más</li>"
        return f"<h4>Riesgos de Subdomain Takeover</h4><ul class='compact'>{items}</ul>"

    def csp_block(esc_f, findings):
        if not findings:
            return ""
        items = "".join(
            f"<li>{'🔴' if f.get('severity') == 'high' else '🟡' if f.get('severity') == 'medium' else '⚪'} "
            f"[{f.get('severity','').upper()}] <strong>{esc_f(f.get('directive',''))}</strong>: "
            f"{esc_f(f.get('description',''))}</li>"
            for f in findings
        )
        if len(findings) > 10:
            items += f"<li class='muted'>… y {len(findings) - 10} más</li>"
        return f"<h4>Análisis de CSP</h4><ul class='compact'>{items}</ul>"

    def cookie_block(esc_f, findings):
        if not findings:
            return ""
        items = "".join(
            f"<li>{'🔴' if f.get('severity') == 'high' else '🟡' if f.get('severity') == 'medium' else '⚪'} "
            f"[{f.get('severity','').upper()}] {esc_f(f.get('description',''))}</li>"
            for f in findings
        )
        if len(findings) > 10:
            items += f"<li class='muted'>… y {len(findings) - 10} más</li>"
        return f"<h4>Seguridad de Cookies</h4><ul class='compact'>{items}</ul>"

    def scr_block(esc_f, p):
        scr = p.get("supply_chain_reputation") or {}
        dnsbl = scr.get("dnsbl") or []
        urlhaus = scr.get("urlhaus") or []
        items = ""
        for d in dnsbl:
            items += f"<li>🔴 DNSBL: IP {esc_f(d.get('ip',''))} listada en {esc_f(d.get('dnsbl',''))}</li>"
        for u in urlhaus:
            items += f"<li>🔴 URLhaus: {esc_f(u.get('domain',''))} ({u.get('url_count',0)} urls maliciosas)</li>"
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
            items += f"<li>🟠 Archivos JS expuestos: {len(all_js)}</li>"
        if fr_ext:
            items += f"<li>🔵 Enlaces externos: {len(fr_ext)}</li>"
        if fr_sitemap:
            items += f"<li>🔵 Sitemap: {len(fr_sitemap)} URLs</li>"
        if fr_wb_js:
            items += f"<li>🟠 JS históricos Wayback: {len(fr_wb_js)}</li>"
        if fr_wb_api:
            items += f"<li>🔴 Endpoints API Wayback: {len(fr_wb_api)}</li>"
        if fr_wb_params:
            items += f"<li>🟠 Parametros sensibles Wayback: {len(fr_wb_params)}</li>"
        if not items:
            return ""
        return f"<h4>Web Recon — FinalRecon</h4><ul class='compact'>{items}</ul>"

    def owasp_block(esc_f, m):
        ow = m.get("owasp") or {}
        if not ow:
            return "<h4>OWASP Agentic Top 10</h4><ul class='compact'><li class='muted'>Sin evaluación disponible.</li></ul>"
        grade = ow.get("overall_grade", "—")
        pct = ow.get("overall_compliance", 0)
        items = ""
        for r_id, r_data in sorted((ow.get("risks") or {}).items()):
            if r_data.get("finding_count", 0) > 0:
                items += f"<li><strong>{r_id}</strong>: Grado {r_data['grade']} ({r_data['compliance_pct']}%) — {r_data['finding_count']} hallazgo(s)</li>"
        if not items:
            items = '<li class="muted">Sin hallazgos que afecten compliance.</li>'
        return f"<h4>OWASP Agentic Top 10 — Grado: {grade} ({pct}%)</h4><ul class='compact'>{items}</ul>"

    def social_block(esc_f, p):
        social = p.get("social") or {}
        if not social:
            return "<h4>Redes Sociales (OSINT)</h4><ul class='compact'><li class='muted'>Sin datos de redes sociales configurados. Agregue social_* al providers.json.</li></ul>"
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
        ips = ", ".join((p.get("dns") or {}).get("ipv4") or []) or "—"
        h = p.get("https") or {}
        tls = p.get("tls") or {}
        hdr = h.get("headers") or {}
        subs = p.get("subdomains") or []
        crt_subs = p.get("crt_subdomains") or []
        san_list = p.get("san_list") or []
        sub_li = "".join(f"<li><code>{esc(s.get('host'))}</code> — {esc(', '.join(s.get('ipv4') or []))}</li>" for s in subs)
        if len(subs) > 25:
            sub_li += f"<li class='muted'>… y {len(subs) - 25} más (ver JSON)</li>"
        crt_li = "".join(f"<li><code>{esc(s)}</code></li>" for s in crt_subs)
        if len(crt_subs) > 30:
            crt_li += f"<li class='muted'>… y {len(crt_subs) - 30} más</li>"
        san_li = "".join(f"<li><code>{esc(s)}</code></li>" for s in san_list)
        if len(san_list) > 20:
            san_li += f"<li class='muted'>… y {len(san_list) - 20} más</li>"
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
        dmarc = dns_data.get("dmarc_record")
        if dmarc:
            dns_items.append(f"DMARC: {esc(dmarc[:180])}")
        dkim = dns_data.get("dkim_records") or []
        for dk in dkim:
            sel = dk.get("selector", "?")
            rec = dk.get("record", "")[:100]
            dns_items.append(f"DKIM/{esc(sel)}: {esc(rec)}")
        dane = dns_data.get("dane_records") or []
        for dn in dane:
            dns_items.append(f"DANE: _{esc(dn.get('port','?'))}._{esc(dn.get('protocol','?'))} usage={esc(dn.get('usage','?'))} sel={esc(dn.get('selector','?'))}")
        if dns_data.get("dnssec_ok"):
            dns_items.append("DNSSEC: activo")
        else:
            dns_items.append("DNSSEC: no detectado")
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
            ip_rep_str = ", ".join(f"{r.get('ip','?')} en {r.get('dnsbl','?')}" for r in ip_rep[:5])
            dns_items.append(f"DNSBL: {esc(ip_rep_str)}")
        prov_sections.append(
            f"""
<section class="card" id="{esc(p.get('id', dom))}">
  <h3>{esc(p.get('name'))}</h3>
  <p class="meta"><strong>Dominio:</strong> <code>{esc(dom)}</code> · <strong>IPv4:</strong> {esc(ips)}</p>
  <div class="kpi-row">
    <span class="pill">Score indicativo: <strong>{domain_score(p)}</strong>/100</span>
    <span class="pill">443: {'abierto' if (p.get('port_443') or {}).get('open') else 'cerrado'}</span>
    <span class="pill">80: {'abierto' if (p.get('port_80') or {}).get('open') else 'cerrado'}</span>
    <span class="pill">Subdominios (prefijos): {len(subs)}</span>
    <span class="pill">crt.sh: {len(crt_subs)}</span>
    <span class="pill">SAN: {len(san_list)}</span>
  </div>
  <p><strong>HTTPS:</strong> {esc(h.get('status_code') if isinstance(h.get('status_code'), int) else h.get('error') or '—')}</p>
  <p><strong>TLS:</strong> {esc(tls.get('negotiated_version') or tls.get('error') or '—')} · <strong>Cert. hasta:</strong> {esc(tls.get('cert_expiry') or '—')}</p>
  <h4>Cabeceras relevantes (apex)</h4>
  <pre class="small">{esc(json.dumps(hdr, indent=2, ensure_ascii=False) if hdr else '{}')}</pre>
  <h4>Subdominios detectados (DNS prefijos)</h4>
  <ul class="compact">{sub_li or '<li class="muted">Ninguno con el diccionario actual</li>'}</ul>
  {"<h4>Subdominios (crt.sh / Certificate Transparency)</h4><ul class='compact'>" + crt_li + "</ul>" if crt_subs else ""}
  {"<h4>Subject Alternative Names (SAN)</h4><ul class='compact'>" + san_li + "</ul>" if san_list else ""}
    {"<h4>Registros DNS pasivos</h4><ul class='compact'><li>" + "</li><li>".join(dns_items) + "</li></ul>" if dns_items else ""}
    {"<h4>Subdominios (Brute Force DNS)</h4><ul class='compact'>" + "".join(f"<li><code>{esc(b.get('fqdn','?'))}</code> — {esc(', '.join(b.get('ips') or []))}</li>" for b in (p.get('brute_subs') or [])[:20]) + ("<li class='muted'>… y " + str(len(p.get('brute_subs') or []) - 20) + " más</li>" if len(p.get('brute_subs') or []) > 20 else "") + "</ul>" if p.get('brute_subs') else ""}
    {"<h4>IP Pivot (FQDNs descubiertos)</h4><ul class='compact'>" + "".join(f"<li><code>{esc(r.get('ip','?'))}</code>: PTR={esc(r.get('ptr','-'))}, crt.sh: {', '.join(r.get('fqdns_from_crt', [])[:5])}{'...' if len(r.get('fqdns_from_crt',[]))>5 else ''}</li>" for r in (p.get('pivot_results') or [])[:5]) + "</ul>" if p.get('pivot_results') else ""}
    {_cert_block(esc, tls)}
    {_redirect_block(esc, h)}
    {_fingerprint_block(esc, h)}
    {_sec_headers_block(esc, hdr)}
    {"<h4>Puertos Abiertos</h4><ul class='compact'>" + "".join(f"<li>Puerto {o.get('port','?')}: {o.get('service','?')}</li>" for o in (p.get('open_ports') or []) if o.get('state') == 'open')[:20] + ("<li class='muted'>… y " + str(len([o for o in (p.get('open_ports') or []) if o.get('state') == 'open']) - 20) + " más</li>" if len([o for o in (p.get('open_ports') or []) if o.get('state') == 'open']) > 20 else "") + "</ul>" if p.get('open_ports') else ""}
    {vuln_block(esc, p.get("vulnerabilities") or [])}
    {takeover_block(esc, p.get("takeover_risks") or [])}
    {csp_block(esc, p.get("csp_findings") or [])}
    {cookie_block(esc, p.get("cookie_findings") or [])}
     {typo_block(esc, p.get("typosquatting") or [])}
     {patch_block(esc, p.get("patching") or [])}
     {supply_block(esc, p.get("supply_chain") or [])}
     {cve_block(esc, p.get("cve_findings") or [])}
     {banner_block(esc, p.get("banner_grabs") or [])}
      {api_block(esc, p.get("api_endpoints") or [])}
{waf_block(esc, p.get("waf_detection") or {})}
{cloud_block(esc, p.get("cloud_storage") or {})}
{kumo_block(esc, p.get("kumo") or {})}
{prism_block(esc, p.get("prism") or {})}
{claude_osint_block(esc, p.get("claude_osint") or {})}
{strix_block(esc, p.get("strix") or {})}
{who_dat_block(esc, p.get("who_dat") or {})}
{nuclei_block(esc, p.get("nuclei") or {})}
{gobuster_block(esc, p.get("gobuster") or {})}
      {paths_block(esc, p.get("public_paths") or [])}
{_external_block(esc, p)}
        {pasivo_canon_block(esc, p)}
        {semi_canon_block(esc, p)}
        {scr_block(esc, p)}
        {finalrecon_block(esc, p)}
        {social_block(esc, p)}
    {owasp_block(esc, matrix_by_domain.get(dom, {}))}
</section>
"""
        )

    matrix_html = ""
    for m in matrix:
     matrix_html += f"""<tr>
 <td>{esc(m.get('proveedor'))}<div class="muted small">{esc(m.get('dominio'))}</div></td>
 <td class="num">{esc(m.get('subdominios'))}</td>
 <td class="num">{m.get('crt_subdominios', 0)}</td>
 <td class="small">{esc(m.get('https'))}</td>
 <td class="c">{ '✓' if m.get('hsts') else '✗'}</td>
 <td class="c">{ '✓' if m.get('csp') else '✗'}</td>
 <td class="num">{m.get('csp_finding_count', 0)}</td>
 <td class="c">{ '✓' if not m.get('cookie_insecure') else '✗'}</td>
 <td class="small">{esc(m.get('spf_dmarc'))}</td>
 <td class="c">{ '✓' if m.get('tls13_negociado') else '✗'}</td>
 <td class="small">{esc(m.get('tls_version'))}</td>
 <td class="c">{ '✓' if m.get('caa') else '✗'}</td>
 <td class="c">{ '✓' if m.get('mta_sts') else '✗'}</td>
 <td class="c">{ '✓' if m.get('tls_rpt') else '✗'}</td>
 <td class="c">{ '✓' if m.get('starttls_ok') else ('✗' if m.get('mx_count', 0) > 0 else '—')}</td>
 <td class="num">{m.get('mx_count', 0)}</td>
 <td class="num">{m.get('ns_count', 0)}</td>
 <td class="c">{ '✓' if m.get('dnssec_ok') else '✗'}</td>
 <td class="num">{m.get('dkim_count', 0)}</td>
 <td class="num">{m.get('dane_count', 0)}</td>
 <td class="c">{ '✓' if m.get('ip_reputation_clean') else esc(str(m.get('ip_reputation_count', 0)))}</td>
 <td class="c">{ '✓' if not m.get('urlhaus_malicious') else '✗'}</td>
    <td class="num">{m.get('vulnerability_count', 0)}</td>
    <td class="num">{m.get('credential_leak_count', 0)}</td>
    <td class="num">{esc(m.get('typosquatting_count', 0))}</td>
    <td class="num">{esc(m.get('patching_eol', 0) + m.get('patching_ending', 0))}</td>
    <td class="c">{ '✓' if m.get('takeover_vulnerable') else ('✗' if m.get('takeover_count', 0) > 0 else '—')}</td>
    <td class="num">{m.get('supply_chain_count', 0)}</td>
    <td class="c">{ '✓' if m.get('supply_reputation_clean') else '✗'}</td>
    <td class="num">{esc(m.get('open_port_count', 0))}</td>
    <td class="num">{esc(m.get('brute_sub_count', 0))}</td>
    <td class="num">{esc(m.get('pivot_count', 0))}</td>
   </tr>"""

    ports_rows = ""
    for p in providers:
        dom = p.get("domain", "")
        p80 = "Sí" if (p.get("port_80") or {}).get("open") else "No"
        p443 = "Sí" if (p.get("port_443") or {}).get("open") else "No"
        ips = (p.get("dns") or {}).get("ipv4") or ["—"]
        for ip in ips[:3]:
            ports_rows += f"<tr><td>{esc(ip)}</td><td>{esc(dom)}</td><td>80</td><td>{p80}</td></tr>"
            ports_rows += f"<tr><td>{esc(ip)}</td><td>{esc(dom)}</td><td>443</td><td>{p443}</td></tr>"

    toc_block = render_toc(report_type="tpra")
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{esc(title)}</title>
<style>
:root {{
  --bg:#f4f6f8; --card:#fff; --text:#1a1d21; --muted:#5c6570; --border:#d9dee5;
  --accent:#8B0000; --good:#0d6e4f; --warn:#8a5b00; --bad:#9b1c1c;
}}
* {{ box-sizing: border-box; }}
body {{ margin:0; font-family: 'Segoe UI', system-ui, sans-serif; background:var(--bg); color:var(--text); line-height:1.45; font-size:14px; }}
.wrap {{ max-width: 920px; margin: 0 auto; padding: 28px 20px 60px; }}
.cover {{
  background: linear-gradient(135deg, #5c1010 0%, #8B0000 45%, #CC0000 100%);
  color: #fff; padding: 32px 28px; border-radius: 12px; margin-bottom: 28px;
  box-shadow: 0 8px 24px rgba(139,0,0,.3);
}}
.cover h1 {{ margin: 0 0 8px; font-size: 1.45rem; font-weight: 600; letter-spacing: -0.02em; }}
.cover .tag {{ display:inline-block; margin-top:12px; padding:4px 10px; background:rgba(255,255,255,.15); border-radius:6px; font-size:11px; text-transform:uppercase; letter-spacing:.06em; }}
.cover p {{ margin: 10px 0 0; opacity: .92; font-size: 13px; max-width: 52em; }}
.toc {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px 22px; margin-bottom: 24px; }}
.toc h2 {{ margin: 0 0 12px; font-size: 1rem; color: var(--accent); }}
.toc ol {{ margin: 0; padding-left: 1.2rem; color: var(--muted); font-size: 13px; }}
.toc a {{ color: var(--accent); text-decoration: none; }}
.toc a:hover {{ text-decoration: underline; }}
h2.sec {{ font-size: 1.05rem; color: var(--accent); border-bottom: 2px solid var(--border); padding-bottom: 6px; margin-top: 32px; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; margin-bottom: 16px; }}
.card h3 {{ margin: 0 0 8px; font-size: 1rem; }}
.card h4 {{ margin: 16px 0 6px; font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }}
.meta {{ font-size: 13px; color: var(--muted); margin: 0 0 10px; }}
.kpi-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; }}
.pill {{ background: #eef2f7; padding: 4px 10px; border-radius: 999px; font-size: 12px; }}
.score-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 16px 0; }}
.score-box {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px; text-align: center; }}
.score-box .lbl {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
.score-box .val {{ font-size: 26px; font-weight: 700; margin-top: 6px; color: var(--accent); }}
.score-box.trust .val {{ color: var(--good); }}
.grade {{ font-size: 42px; font-weight: 700; color: var(--good); float: right; margin: -8px 0 0 16px; line-height: 1; }}
table.data {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }}
table.data th, table.data td {{ border: 1px solid var(--border); padding: 8px 10px; text-align: left; vertical-align: top; }}
table.data th {{ background: #eef2f7; font-weight: 600; font-size: 11px; text-transform: uppercase; color: var(--muted); }}
table.data .num {{ text-align: right; }}
table.data .c {{ text-align: center; }}
.small {{ font-size: 12px; }}
.muted {{ color: var(--muted); }}
pre.small {{ background: #f8fafc; padding: 10px; border-radius: 8px; overflow: auto; max-height: 200px; font-size: 11px; border: 1px solid var(--border); }}
ul.compact {{ margin: 6px 0; padding-left: 1.2rem; }}
.footnote {{ font-size: 11px; color: var(--muted); margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); }}
.risk-critical {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#5c1010; color:#fff; }}
.risk-high {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#9b1c1c; color:#fff; }}
.risk-med {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#cc8800; color:#fff; }}
.risk-low {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#2d7a4a; color:#fff; }}
.epss-badge {{ display:inline-block; font-size:10px; padding:1px 5px; border-radius:4px; background:#e8eef5; color:#3a5478; }}
.kev-badge {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#fce4e4; color:#a00; }}
.waf-badge {{ display:inline-block; font-size:10px; font-weight:700; padding:1px 7px; border-radius:4px; background:#221f2e; color:#ffd86b; border:1px solid #ffd86b; margin-right:4px; }}
@media print {{
  body {{ background: #fff; }}
  .cover {{ box-shadow: none; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <div class="cover">
    <h1>{esc(title)}</h1>
    <p>{esc(subtitle)}</p>
    <p><strong>Periodo de referencia:</strong> datos ASM · <strong>Última ejecución:</strong> {esc(gen)}</p>
    <p><strong>Fecha de informe:</strong> {esc(now)}</p>
    <span class="tag">EVALUACIÓN DE POSTURA DE SEGURIDAD DE TERCEROS</span>
  </div>

  {toc_block}

  {resumen_block}

  {score_legend_block}

  <h2 class="sec" id="resumen">Third-Party Risk Assessment — Resumen</h2>
  <div class="card">
    <p>Este documento resume la postura observada por <strong>Attack Surface Management (ASM)</strong> sobre <strong>{n} dominios de proveedores</strong>.
    Las puntuaciones son <strong>indicativas</strong>, calculadas a partir de cabeceras HTTP, TLS, DNS (SPF/DMARC) y disponibilidad de servicios; no sustituyen un informe de auditoría certificada.</p>
    <p><strong>Activos analizados:</strong> {n} · <strong>Subdominios (DNS prefijos):</strong> {total_subs} · <strong>Subdominios (crt.sh):</strong> {total_crt} · <strong>443 abierto:</strong> {open443}/{n} · <strong>80 abierto:</strong> {open80}/{n} · <strong>CAA presente:</strong> {has_caa}/{n} · <strong>MTA-STS:</strong> {has_mta_sts}/{n}</p>
  </div>

  <h2 class="sec" id="reglas">Hallazgos agregados</h2>
  <div class="card">
    <table class="data">
      <thead><tr><th>Tipo</th><th>Descripción</th><th>Proveedores afectados</th><th>Impacto ref.</th></tr></thead>
      <tbody>{risk_table_rows()}</tbody>
    </table>
  </div>

  <h2 class="sec" id="puntuaciones">Puntuaciones indicativas</h2>
  <div class="card">
    <div class="grade">{esc(grade)}</div>
    <p class="muted" style="margin-top:0">Grado orientativo a partir del score medio.</p>
    <div class="score-grid">
      <div class="score-box"><div class="lbl">ASM (riesgo normalizado)</div><div class="val">{asm_score}</div><div class="muted small">0 = mejor</div></div>
      <div class="score-box"><div class="lbl">DRP (filtraciones)</div><div class="val">{drp_score}</div><div class="muted small">No medido aquí</div></div>
      <div class="score-box"><div class="lbl">CTI</div><div class="val">{cti_score}</div><div class="muted small">No medido aquí</div></div>
      <div class="score-box trust"><div class="lbl">Security trust (indicativo)</div><div class="val">{trust}</div><div class="muted small">/ 100</div></div>
    </div>
  </div>

  {precia_blocks}

  <div class="card">
    <p><strong>Score heurístico 0–100 y grado A–F:</strong> cada dominio recibe un puntaje basado en los factores que el escáner puede verificar de forma pasiva. El promedio de todos los dominios determina el grado general. La escala sigue el modelo de SecurityScorecard:</p>
    <ul class="compact">
      <li><strong>A</strong> (≥90) — postura excelente, controles sólidos en todos los ejes medibles.</li>
      <li><strong>B</strong> (75–89) — buena, con oportunidades menores de mejora.</li>
      <li><strong>C</strong> (60–74) — aceptable, pero con carencias que deben revisarse.</li>
      <li><strong>D</strong> (45–59) — deficiente, múltiples controles ausentes o mal configurados.</li>
      <li><strong>E</strong> (30–44) — pobre, riesgo elevado en varios dominios.</li>
      <li><strong>F</strong> (&lt;30) — crítico, requiere atención inmediata.</li>
    </ul>
    <p><strong>Factores evaluados en este informe:</strong></p>
    <ul class="compact">
      <li><strong>Configuraciones DNS</strong> — SPF (hard-fail), DMARC (reject/quarantine), DKIM, DNSSEC, DANE/TLSA, registros MX y NS, CAA, MTA-STS, TLS-RPT, BIMI, STARTTLS en MX (puerto 25).</li>
      <li><strong>Certificados SSL/TLS</strong> — versión negociada, TLS 1.3 exclusivo, vigencia, emisor, SAN, serial.</li>
      <li><strong>Puertos abiertos</strong> — disponibilidad de servicios en 80 (HTTP) y 443 (HTTPS).</li>
      <li><strong>Cabeceras de seguridad HTTP</strong> — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Feature-Policy/Permissions-Policy, Expect-CT, X-Permitted-Cross-Domain, Server, X-Powered-By, detección de CDN/WAF (Via, CF-Ray, X-CDN).</li>
      <li><strong>Análisis de CSP</strong> — detección de directivas faltantes (base-uri, object-src, frame-ancestors, form-action), uso de unsafe-inline/unsafe-eval, comodines, CDN allowlists que permiten bypass JSONP, y ausencia de report-uri.</li>
      <li><strong>Seguridad de Cookies</strong> — verificación de flags Secure, HttpOnly y SameSite en cookies HTTP.</li>
      <li><strong>Superficie de subdominios</strong> — descubrimiento por fuerza bruta DNS prefijos y fuentes OSINT pasivas (crt.sh, BufferOver, ThreatCrowd).</li>
      <li><strong>Geolocalización de IPs</strong> — país asociado a las direcciones IPv4 del dominio.</li>
      <li><strong>Reputación de IPs</strong> — consulta a DNSBL (Spamhaus ZEN, Barracuda, SpamCop, SORBS, CBL) para detectar IPs listadas como maliciosas o comprometidas.</li>
      <li><strong>Malware detectado</strong> — consulta a URLhaus (Abuse.ch) para verificar si el dominio ha sido reportado como distribuidor de malware.</li>
      <li><strong>Vulnerabilidades expuestas</strong> — detección de tecnologías desde cabeceras HTTP (Server, X-Powered-By) y consulta a la base OSV.dev para identificar CVEs asociados a las versiones detectadas.</li>
      <li><strong>Fugas de credenciales</strong> — consulta a leak-lookup.com para identificar si el dominio aparece en breaches conocidos (requiere variable de entorno <code>LEAK_API_KEY</code>).</li>
      <li><strong>Riesgos de phishing / typosquatting</strong> — generación de variantes del dominio (cambio de TLD, caracteres adyacentes, omisiones, prefijos comunes) y verificación DNS para detectar posibles dominios falsos activos.</li>
      <li><strong>Patching cadence</strong> — consulta a endoflife.date para las tecnologías detectadas en cabeceras (Server, X-Powered-By) y determina si la versión está EOL, próxima a EOL o vigente.</li>
      <li><strong>Riesgo de terceros y supply chain</strong> — extracción de dominios de terceros desde cabeceras CSP y scripts externos en la página principal, con verificación DNS de resolución.</li>
      <li><strong>Reputación de terceros (Supply Chain Reputation)</strong> — consulta DNSBL sobre las IPs de los terceros detectados y consulta URLhaus sobre sus dominios para identificar terceros maliciosos o comprometidos.</li>
      <li><strong>Subdomain Takeover</strong> — verificación de CNAMEs en subdominios contra servicios externos no configurados (S3, CloudFront, GitHub Pages, Heroku, Azure, etc.) y detección de CNAMEs colgantes.</li>
    </ul>
    <p><strong>Factores NO evaluados en esta versión (a desarrollar):</strong></p>
    <ul class="compact">
    </ul>
    <p><strong>Matriz de controles (ASM):</strong> cada fila representa un proveedor; cada columna indica la presencia (✓) o ausencia (✗) de un control verificado. La tabla de hallazgos agregados resume cuántos proveedores carecen de cada control y su peso de impacto referencial (0.0–1.0).</p>
  </div>

  <h2 class="sec" id="matriz">Check item matrix — controles ASM</h2>
  <div class="card">
    <table class="data">
      <thead><tr><th>Proveedor</th><th>Sub</th><th>crt.sh</th><th>HTTPS</th><th>HSTS</th><th>CSP</th><th>CSP-W</th><th>COOK</th><th>SPF/DMARC</th><th>TLS1.3-only</th><th>Versión TLS</th><th>CAA</th><th>MTA-STS</th><th>TLS-RPT</th><th>STLS</th><th>MX</th><th>NS</th><th>DNSSEC</th><th>DKIM</th><th>DANE</th><th>DNSBL</th><th>URLH</th><th>CVE</th><th>LEAK</th><th>TYPO</th><th>PATCH</th><th>TKO</th><th>SC</th><th>SC-REP</th></tr></thead>
      <tbody>{matrix_html}</tbody>
    </table>
  </div>

  <h2 class="sec" id="superficie">External attack surface — por proveedor</h2>
  {''.join(prov_sections)}

  <h2 class="sec" id="puertos">Open ports (80 / 443)</h2>
  <div class="card">
    <p class="muted small">Solo comprobación TCP a puertos estándar (no escaneo 1–65535).</p>
    <table class="data">
      <thead><tr><th>IP</th><th>Dominio</th><th>Puerto</th><th>Abierto</th></tr></thead>
      <tbody>{ports_rows}</tbody>
    </table>
  </div>

  <h2 class="sec" id="osint">OSINT pasivo — Certificate Transparency, SAN, CAA, MTA-STS, TLS-RPT, BIMI</h2>
  <div class="card">
    <p class="muted">Datos recolectados de fuentes OSINT públicas sin tráfico directo a los servidores del target (excepto consultas DNS estándar).</p>
    <table class="data">
      <thead><tr><th>Indicador</th><th>Valor</th><th>Descripción</th></tr></thead>
      <tbody>
        <tr><td>Subdominios vía crt.sh</td><td class="num">{total_crt}</td><td class="small">Descubiertos desde Certificate Transparency logs (fuente pasiva)</td></tr>
        <tr><td>Subject Alternative Names (SAN)</td><td class="num">{total_san}</td><td class="small">Nombres adicionales en el certificado TLS del apex</td></tr>
        <tr><td>CAA record presente</td><td class="num">{has_caa}/{n}</td><td class="small">Autorización de emisión de certificados (DNS)</td></tr>
        <tr><td>MTA-STS presente</td><td class="num">{has_mta_sts}/{n}</td><td class="small">Política de seguridad SMTP MTA-STS (DNS TXT)</td></tr>
        <tr><td>TLS-RPT presente</td><td class="num">{has_tls_rpt}/{n}</td><td class="small">Reporte de fallos TLS por correo (DNS TXT)</td></tr>
        <tr><td>BIMI presente</td><td class="num">{has_bimi}/{n}</td><td class="small">Brand Indicators for Message Identification (DNS TXT)</td></tr>
      </tbody>
    </table>
  </div>

  <h2 class="sec" id="ransomware">Top vulnerabilities exploited by ransomware groups (referencia)</h2>
  <div class="card">
    <p class="muted">En el informe PDF de referencia se listan CVEs con chequeo “Passed”. Aquí no hay escaneo activo de CVE por host; use herramientas autorizadas (p. ej. nuclei con plantillas oficiales) si necesita esta capa.</p>
    <table class="data">
      <thead><tr><th>CVE</th><th>CVSSv3 (ref.)</th><th>Estado en este informe</th></tr></thead>
      <tbody>
        <tr><td>CVE-2021-44228</td><td>10.0</td><td class="muted">No evaluado (sin escaneo)</td></tr>
        <tr><td>CVE-2018-13379</td><td>9.8</td><td class="muted">No evaluado (sin escaneo)</td></tr>
        <tr><td>CVE-2020-5902</td><td>9.8</td><td class="muted">No evaluado (sin escaneo)</td></tr>
      </tbody>
    </table>
  </div>

  <h2 class="sec" id="vulns">Vulnerability findings</h2>
  <div class="card">
    <p><strong>0 hallazgos</strong> de CVE en esta exportación ASM. Mensaje análogo al PDF: no se detectaron vulnerabilidades catalogadas en el alcance actual del escáner.</p>
  </div>

</div>
</body>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--asm", type=Path, default=ROOT / "asm_report.json")
    ap.add_argument("--out", type=Path, default=ROOT / "informe_tpra_estilo_socradar.html")
    ap.add_argument(
        "--title",
        default="Third-Party Risk Assessment Report — www.informe.com.co",
    )
    ap.add_argument(
        "--subtitle",
        default="Evaluación ASM del sitio público Informé (host www)",
    )
    args = ap.parse_args()
    asm = json.loads(args.asm.read_text(encoding="utf-8"))
    html_out = build_report(asm, args.title, args.subtitle)
    args.out.write_text(html_out, encoding="utf-8")
    print(f"[OK] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
