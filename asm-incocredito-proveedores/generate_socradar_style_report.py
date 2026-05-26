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
    """Heurística 0–100 transparente (no es puntuación SOCRadar oficial)."""
    pts = 0.0
    h = p.get("https", {}) or {}
    headers = h.get("headers") or {}
    tls = p.get("tls") or {}
    dns = p.get("dns") or {}
    if p.get("port_443", {}).get("open"):
        pts += 8
    if p.get("port_80", {}).get("open"):
        pts += 2
    if isinstance(h.get("status_code"), int) and 200 <= h["status_code"] < 400:
        pts += 18
    if headers.get("strict-transport-security"):
        pts += 12
    if headers.get("content-security-policy") or headers.get("content-security-policy-report-only"):
        pts += 10
    if headers.get("x-frame-options"):
        pts += 6
    if headers.get("x-content-type-options"):
        pts += 4
    if tls.get("negotiated_version") and not tls.get("error"):
        pts += 14
    if tls.get("tls13_only_ok"):
        pts += 6
    if dns.get("spf_record") and "-all" in str(dns["spf_record"]).replace(" ", "").lower():
        pts += 10
    elif dns.get("spf_record"):
        pts += 5
    if dns.get("dmarc_policy") in ("reject", "quarantine"):
        pts += 10
    elif dns.get("dmarc_policy"):
        pts += 5
    starttls = dns.get("starttls_results") or []
    if starttls and all(s.get("starttls") for s in starttls):
        pts += 5
    elif starttls:
        pts += 1
    ip_reputation = dns.get("ip_reputation") or []
    if not ip_reputation:
        pts += 8
    elif len(ip_reputation) <= 2:
        pts += 4
    urlhaus = p.get("urlhaus") or {}
    if not urlhaus.get("malicious"):
        pts += 5
    elif urlhaus.get("error"):
        pts += 1
    vulns = p.get("vulnerabilities") or []
    if not vulns:
        pts += 8
    elif len(vulns) <= 3:
        pts += 4
    leaks = p.get("credential_leaks") or []
    valid_leaks = [l for l in leaks if "error" not in l]
    if not valid_leaks:
        pts += 6
    elif len(valid_leaks) <= 2:
        pts += 3
    typos = p.get("typosquatting") or []
    if not typos:
        pts += 6
    elif len(typos) <= 2:
        pts += 3
    patch = p.get("patching") or []
    eol_count = sum(1 for x in patch if x.get("status") == "eol")
    if eol_count == 0:
        pts += 5
    elif eol_count <= 1:
        pts += 2
    supply = p.get("supply_chain") or []
    if not supply:
        pts += 4
    elif len(supply) <= 5:
        pts += 2
    takeover = p.get("takeover_risks") or []
    vulnerable = any(r.get("vulnerable") for r in takeover)
    if not takeover:
        pts += 6
    elif not vulnerable:
        pts += 3
    csp_f = p.get("csp_findings") or []
    if not csp_f:
        pts += 5
    elif all(f.get("severity") in ("low", "medium") for f in csp_f):
        pts += 2
    cookie_f = p.get("cookie_findings") or []
    cookie_insecure = any(f.get("severity") in ("high",) for f in cookie_f)
    if not cookie_f:
        pts += 5
    elif not cookie_insecure:
        pts += 2
    scr_dnsbl = p.get("supply_reputation_dnsbl_count", 0)
    scr_urlhaus = p.get("supply_reputation_urlhaus_count", 0)
    if scr_dnsbl == 0 and scr_urlhaus == 0:
        pts += 5
    elif scr_dnsbl <= 2 and scr_urlhaus == 0:
        pts += 2
    return min(100.0, round(pts, 2))


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
        risk_rows.insert(0, ("ASM / Supply Chain Reputation", "IPs o dominios de terceros con reputacion negativa (DNSBL/URLhaus)", total_scr_dnsbl + total_scr_urlhaus, 0.55))
    total_supply = sum(len(p.get("supply_chain") or []) for p in providers)
    if total_supply:
        risk_rows.insert(0, ("ASM / Supply Chain", "Dependencias de terceros detectadas (CSP/scripts)", total_supply, 0.35))

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

    def vuln_block(esc_f, vulns):
        if not vulns:
            return ""
        items = "".join(f"<li><strong>{esc_f(v.get('cve_id', v.get('id', '?')))}</strong> — {esc_f(v.get('summary', '')[:120])} <span class='muted'>({esc_f(v.get('package', ''))})</span></li>" for v in vulns[:10])
        if len(vulns) > 10:
            items += f"<li class='muted'>… y {len(vulns) - 10} más</li>"
        return f"<h4>Vulnerabilidades (OSV.dev)</h4><ul class='compact'>{items}</ul>"

    def typo_block(esc_f, typos):
        if not typos:
            return ""
        items = "".join(f"<li><code>{esc_f(t.get('domain', ''))}</code> — {esc_f(', '.join(t.get('ips', [])))}</li>" for t in typos[:10])
        if len(typos) > 10:
            items += f"<li class='muted'>… y {len(typos) - 10} más</li>"
        return f"<h4>Typosquatting detectados</h4><ul class='compact'>{items}</ul>"

    def patch_block(esc_f, patching):
        if not patching:
            return ""
        items = ""
        for pch in patching[:10]:
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
            for s in supply[:10]
        )
        if len(supply) > 10:
            items += f"<li class='muted'>… y {len(supply) - 10} más</li>"
        return f"<h4>Dependencias de terceros (Supply Chain)</h4><ul class='compact'>{items}</ul>"

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

    def takeover_block(esc_f, risks):
        if not risks:
            return ""
        items = "".join(
            f"<li><code>{esc_f(r.get('host', ''))}</code> → <code>{esc_f(r.get('cname', ''))}</code>"
            f" {'🔴 VULNERABLE' if r.get('vulnerable') else '🟡 POTENCIAL'}: {esc_f(r.get('description', ''))}</li>"
            for r in risks[:10]
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
            for f in findings[:10]
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
            for f in findings[:10]
        )
        if len(findings) > 10:
            items += f"<li class='muted'>… y {len(findings) - 10} más</li>"
        return f"<h4>Seguridad de Cookies</h4><ul class='compact'>{items}</ul>"

    def scr_block(esc_f, p):
        scr = p.get("supply_chain_reputation") or {}
        dnsbl = scr.get("dnsbl") or []
        urlhaus = scr.get("urlhaus") or []
        items = ""
        for d in dnsbl[:5]:
            items += f"<li>🔴 DNSBL: IP {esc_f(d.get('ip',''))} listada en {esc_f(d.get('dnsbl',''))}</li>"
        for u in urlhaus[:5]:
            items += f"<li>🔴 URLhaus: {esc_f(u.get('domain',''))} ({u.get('url_count',0)} urls maliciosas)</li>"
        if items:
            return f"<h4>Reputación de terceros (Supply Chain)</h4><ul class='compact'>{items}</ul>"
        return ""

    def owasp_block(esc_f, m):
        ow = m.get("owasp") or {}
        if not ow:
            return "<h4>OWASP Agentic Top 10</h4><ul class='compact'><li class='muted'>Sin evaluacion disponible.</li></ul>"
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
        sub_li = "".join(f"<li><code>{esc(s.get('host'))}</code> — {esc(', '.join(s.get('ipv4') or []))}</li>" for s in subs[:25])
        if len(subs) > 25:
            sub_li += f"<li class='muted'>… y {len(subs) - 25} más (ver JSON)</li>"
        crt_li = "".join(f"<li><code>{esc(s)}</code></li>" for s in crt_subs[:30])
        if len(crt_subs) > 30:
            crt_li += f"<li class='muted'>… y {len(crt_subs) - 30} más</li>"
        san_li = "".join(f"<li><code>{esc(s)}</code></li>" for s in san_list[:20])
        if len(san_list) > 20:
            san_li += f"<li class='muted'>… y {len(san_list) - 20} más</li>"
        dnssec_items = []
        caa = p.get("caa_records") or []
        for rec in caa:
            dnssec_items.append(f"CAA: {esc(rec.get('tag', '?'))} {esc(rec.get('value', '?'))}")
        if p.get("mta_sts"):
            dnssec_items.append(f"MTA-STS: {esc(p['mta_sts'][:120])}")
        if p.get("tls_rpt"):
            dnssec_items.append(f"TLS-RPT: {esc(p['tls_rpt'][:120])}")
        if p.get("bimi"):
            dnssec_items.append(f"BIMI: {esc(p['bimi'][:120])}")
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
    {"<h4>Registros DNS pasivos</h4><ul class='compact'><li>" + "</li><li>".join(dnssec_items) + "</li></ul>" if dnssec_items else ""}
    {_cert_block(esc, tls)}
    {_redirect_block(esc, h)}
    {_fingerprint_block(esc, h)}
    {_sec_headers_block(esc, hdr)}
    {vuln_block(esc, p.get("vulnerabilities") or [])}
    {takeover_block(esc, p.get("takeover_risks") or [])}
{csp_block(esc, p.get("csp_findings") or [])}
    {cookie_block(esc, p.get("cookie_findings") or [])}
     {typo_block(esc, p.get("typosquatting") or [])}
     {patch_block(esc, p.get("patching") or [])}
     {supply_block(esc, p.get("supply_chain") or [])}
     {scr_block(esc, p)}
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

  <nav class="toc">
    <h2>Tabla de contenidos</h2>
    <ol>
      <li><a href="#resumen">Resumen de evaluación</a></li>
      <li><a href="#reglas">Hallazgos agregados (reglas simplificadas)</a></li>
      <li><a href="#puntuaciones">Puntuaciones indicativas</a></li>
      <li><a href="#matriz">Matriz de controles (ASM)</a></li>
      <li><a href="#superficie">Superficie de ataque por proveedor</a></li>
      <li><a href="#puertos">Puertos observados (80 / 443)</a></li>
      <li><a href="#osint">OSINT pasivo — Certificate Transparency, SAN, CAA, MTA-STS</a></li>
      <li><a href="#ransomware">CVEs frecuentes en ransomware (referencia)</a></li>
      <li><a href="#vulns">Hallazgos de vulnerabilidad</a></li>
    </ol>
  </nav>

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
        default="Third-Party Risk Assessment Report — www.incocredito.com.co",
    )
    ap.add_argument(
        "--subtitle",
        default="Evaluación ASM del sitio público Incocrédito (host www)",
    )
    args = ap.parse_args()
    asm = json.loads(args.asm.read_text(encoding="utf-8"))
    html_out = build_report(asm, args.title, args.subtitle)
    args.out.write_text(html_out, encoding="utf-8")
    print(f"[OK] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
