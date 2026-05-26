#!/usr/bin/env python3
"""
generate_asm_passive_active_report.py
Report con separacion visual entre ANALISIS PASIVO y ANALISIS ACTIVO.
v2 - Tipografia grande, evidencia detallada por hallazgo.
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


def grade_letter(score: float) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 45: return "D"
    if score >= 30: return "E"
    return "F"


def grade_color(g: str) -> str:
    return {"A": "#10b981", "B": "#22c55e", "C": "#eab308", "D": "#f97316", "E": "#ef4444", "F": "#dc2626"}.get(g, "#6b7280")


def _evidence_block(items: list[str], title: str = "Evidencia") -> str:
    if not items:
        return ""
    lines = "".join(f"<span class='ev-line'>{esc(i)}</span>\n" for i in items if i)
    return f"<details class='ev'><summary>{esc(title)} ({len(items)})</summary><div class='ev-body'>{lines}</div></details>"


def _evidence_text(text: str, title: str = "Evidencia") -> str:
    if not text:
        return ""
    return f"<details class='ev'><summary>{esc(title)}</summary><div class='ev-body'><span class='ev-line'>{esc(text)}</span></div></details>"


def _evidence_dict(d: dict[str, Any], title: str = "Evidencia") -> str:
    if not d:
        return ""
    lines = "".join(f"<span class='ev-line'><strong>{esc(k)}:</strong> {esc(v)}</span>\n" for k, v in d.items() if v is not None)
    if not lines:
        return ""
    return f"<details class='ev'><summary>{esc(title)}</summary><div class='ev-body'>{lines}</div></details>"


def classify_issues(m: dict[str, Any], p: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    passive: list[dict] = []
    active: list[dict] = []

    def add(cat: str, label: str, sev: str, detail: str, dom: str = "", evidence: str = "") -> None:
        target = passive if cat == "passive" else active
        target.append({"label": label, "severity": sev, "detail": detail, "domain": dom, "evidence": evidence})

    domain = m.get("dominio", "")
    dns = p.get("dns", {})
    https = p.get("https", {})
    headers = https.get("headers", {})
    tls = p.get("tls", {})

    # --- PASSIVE ---
    if dns.get("ipv4"):
        add("passive", "A IPv4", "info", f"{len(dns['ipv4'])} registro(s)", domain,
            _evidence_block(dns['ipv4'], "Registros A"))
    if dns.get("ipv6"):
        add("passive", "AAAA IPv6", "info", f"{len(dns['ipv6'])} registro(s)", domain,
            _evidence_block(dns['ipv6'], "Registros AAAA"))
    mx = dns.get("mx_records", [])
    if mx:
        lines = [f"{m.get('preference','?')} {m.get('exchange','')}" for m in mx]
        add("passive", "MX", "info", f"{len(mx)} servidor(es)", domain,
            _evidence_block(lines, "Registros MX"))
    else:
        add("passive", "MX", "baja", "Sin servidores MX", domain)

    ns = dns.get("ns_records", [])
    if ns:
        lines = [m.get("nameserver", "") for m in ns]
        add("passive", "NS", "info", f"{len(ns)} servidor(es)", domain,
            _evidence_block(lines, "Nameservers"))

    spf = dns.get("spf_record")
    if spf:
        if "-all" in spf.replace(" ", "").lower():
            add("passive", "SPF", "info", "Hard-fail (-all) configurado", domain,
                _evidence_text(spf[:500], "Registro SPF"))
        elif "~all" in spf.lower():
            add("passive", "SPF", "media", "Soft-fail (~all)", domain,
                _evidence_text(spf[:500], "Registro SPF"))
        else:
            add("passive", "SPF", "baja", "Sin mecanismo de rechazo fuerte", domain,
                _evidence_text(spf[:500], "Registro SPF"))
    else:
        add("passive", "SPF", "alta", "SPF no configurado", domain)

    dmarc_pol = dns.get("dmarc_policy")
    dmarc_rec = dns.get("dmarc_record")
    if dmarc_rec:
        sev = "info" if dmarc_pol == "reject" else ("media" if dmarc_pol == "quarantine" else "alta")
        add("passive", "DMARC", sev, f"Politica: {dmarc_pol or 'desconocida'}", domain,
            _evidence_text(dmarc_rec[:500], "Registro DMARC"))
    else:
        add("passive", "DMARC", "alta", "DMARC no configurado", domain)

    dkim = dns.get("dkim_records", [])
    if dkim:
        lines = [f"{d['selector']}: {d['record'][:100]}" for d in dkim]
        add("passive", "DKIM", "info", f"{len(dkim)} registro(s)", domain,
            _evidence_block(lines, "Registros DKIM"))
    else:
        add("passive", "DKIM", "media", "Sin registros DKIM", domain)

    if dns.get("dnssec_ok"):
        add("passive", "DNSSEC", "info", "DNSSEC activo", domain)
    else:
        add("passive", "DNSSEC", "media", "DNSSEC no detectado", domain)

    dane = dns.get("dane_records", [])
    if dane:
        lines = [f"_{d['port']}._{d['protocol']}: usage={d['usage']} sel={d['selector']} type={d['mtype']}" for d in dane]
        add("passive", "DANE/TLSA", "info", f"{len(dane)} registro(s)", domain,
            _evidence_block(lines, "Registros DANE/TLSA"))
    else:
        add("passive", "DANE/TLSA", "media", "Sin registros DANE/TLSA", domain)

    caa = p.get("caa_records", [])
    if caa:
        lines = [f"{c.get('tag','')} {c.get('value','')}" for c in caa]
        add("passive", "CAA", "info", f"{len(caa)} registro(s)", domain,
            _evidence_block(lines, "Registros CAA"))
    else:
        add("passive", "CAA", "baja", "Sin registros CAA", domain)

    if p.get("mta_sts"):
        add("passive", "MTA-STS", "info", "Configurado", domain,
            _evidence_text(str(p.get("mta_sts","")), "MTA-STS"))
    else:
        add("passive", "MTA-STS", "baja", "No configurado", domain)
    if p.get("tls_rpt"):
        add("passive", "TLS-RPT", "info", "Configurado", domain,
            _evidence_text(str(p.get("tls_rpt","")), "TLS-RPT"))
    if p.get("bimi"):
        add("passive", "BIMI", "info", "Configurado", domain,
            _evidence_text(str(p.get("bimi","")), "BIMI"))

    ip_rep = dns.get("ip_reputation", [])
    if ip_rep:
        lines = [f"IP {r.get('ip','?')} listada en {r.get('dnsbl','?')}" for r in ip_rep]
        add("passive", "DNSBL", "alta", f"{len(ip_rep)} listado(s)", domain,
            _evidence_block(lines, "Listados DNSBL"))
    else:
        add("passive", "DNSBL", "info", "Sin listados en DNSBL", domain)

    uh = p.get("urlhaus", {})
    if uh.get("malicious"):
        lines = [f"URLs reportadas: {uh.get('url_count',0)}", f"Primer avistamiento: {uh.get('first_seen','?')}", f"Ultimo avistamiento: {uh.get('last_seen','?')}"] + [f"URL: {u}" for u in uh.get('urls',[])]
        add("passive", "URLhaus", "alta", f"Dominio reportado ({uh.get('url_count',0)} URLs)", domain,
            _evidence_block(lines, "URLhaus"))
    elif uh.get("error"):
        add("passive", "URLhaus", "info", f"API: {uh['error']}", domain)
    else:
        add("passive", "URLhaus", "info", "No reportado como malicioso", domain,
            _evidence_text("query_status: ok, url_count: 0", "URLhaus"))

    crt = p.get("crt_subdomains", [])
    if crt:
        add("passive", "CT Logs", "info", f"{len(crt)} subdominio(s)", domain,
            _evidence_block(crt[:20], "Subdominios (Certificate Transparency)"))

    typos = p.get("typosquatting", [])
    if typos:
        lines = [f"{t.get('domain','?')} -> {', '.join(t.get('ips',[]) or [])}" for t in typos]
        add("passive", "Typosquatting", "alta", f"{len(typos)} variante(s) registradas", domain,
            _evidence_block(lines, "Typosquatting"))

    vulns = p.get("vulnerabilities", [])
    if vulns:
        lines = [f"{v.get('cve_id','?')} - {v.get('summary','')[:120]}" for v in vulns[:15]]
        add("passive", "CVE OSV", "alta", f"{len(vulns)} vulnerabilidad(es)", domain,
            _evidence_block(lines, "Vulnerabilidades OSV"))

    leaks = p.get("credential_leaks", [])
    clean_leaks = [l for l in leaks if "error" not in l]
    if clean_leaks:
        lines = [f"{l.get('breach','?')}: {l.get('records',0)} registros" for l in clean_leaks]
        add("passive", "Cred. Leaks", "alta", f"{len(clean_leaks)} breach(es)", domain,
            _evidence_block(lines, "Credential Leaks"))
    if any("error" in l for l in leaks):
        err = next((l.get("error","") for l in leaks if "error" in l), "")
        add("passive", "Cred. Leaks", "info", f"API: {err}", domain)

    social = p.get("social", {})
    for net, data in social.items():
        if data.get("error"):
            continue
        uname = data.get("username", "")
        if uname:
            lines = []
            for k in ("name", "description", "followers", "following", "posts", "url"):
                if data.get(k):
                    lines.append(f"{k}: {data[k]}")
            add("passive", f"Social/{net}", "info", f"@{uname}", domain,
                _evidence_block(lines, f"Perfil {net}"))

    # --- ACTIVE ---
    p80 = p.get("port_80", {})
    p443 = p.get("port_443", {})
    if p80.get("open"):
        add("active", "Puerto 80", "media", "HTTP abierto (redireccion HTTPS?)", domain)
    else:
        err80 = p80.get("error","")
        add("active", "Puerto 80", "info", "Cerrado", domain,
            _evidence_text(err80, "Error al conectar") if err80 else "")
    if p443.get("open"):
        add("active", "Puerto 443", "info", "HTTPS abierto", domain)
    else:
        err443 = p443.get("error","")
        add("active", "Puerto 443", "alta", "HTTPS cerrado", domain,
            _evidence_text(err443, "Error al conectar") if err443 else "")

    tls_ver = tls.get("negotiated_version")
    if tls_ver:
        sev = "info" if "1.3" in str(tls_ver) else ("media" if "1.2" in str(tls_ver) else "alta")
        add("active", "TLS version", sev, f"Negociado: {tls_ver}", domain)
    if tls.get("tls13_only_ok"):
        add("active", "TLS 1.3-only", "info", "Acepta solo TLS 1.3", domain)

    cert_subj = tls.get("cert_subject")
    cert_iss = tls.get("cert_issuer")
    cert_exp = tls.get("cert_expiry")
    cert_ser = tls.get("cert_serial")
    cert_ver = tls.get("cert_version")
    if cert_subj or cert_iss or cert_exp:
        lines = [f"Subject: {cert_subj}", f"Issuer: {cert_iss}", f"Expira: {cert_exp}", f"Serial: {cert_ser}", f"Version: {cert_ver}"]
        add("active", "Certificado TLS", "info", f"Expira: {cert_exp or '?'}", domain,
            _evidence_block([l for l in lines if l and not l.endswith(": ") and not l.endswith(": None")], "Certificado TLS"))

    san = tls.get("san_list", [])
    if san:
        add("active", "SAN list", "info", f"{len(san)} nombre(s) alternativo(s)", domain,
            _evidence_block(san, "Subject Alternative Names"))

    sc = https.get("status_code")
    furl = https.get("final_url")
    if sc:
        sev = "info" if 200 <= sc < 400 else "alta"
        add("active", "HTTP status", sev, f"HTTP {sc} -> {furl or ''}", domain)

    redirects = https.get("redirect_chain", [])
    if len(redirects) > 1:
        add("active", "Redirect chain", "info", f"{len(redirects)} salto(s)", domain,
            _evidence_block(redirects, "Cadena de redirecciones"))

    # All security headers as evidence
    sec_headers = {k: v for k, v in headers.items() if k in (
        "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
        "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
        "cross-origin-opener-policy", "server", "x-powered-by", "set-cookie"
    )}

    hsts = headers.get("strict-transport-security")
    if hsts:
        add("active", "HSTS", "info", "Configurado", domain,
            _evidence_text(hsts, "Header HSTS"))
    else:
        add("active", "HSTS", "alta", "No configurado (riesgo SSL stripping)", domain)

    csp = headers.get("content-security-policy") or headers.get("content-security-policy-report-only")
    if csp:
        add("active", "CSP", "info", "Configurado", domain,
            _evidence_text(csp[:500], "Content-Security-Policy"))
    else:
        add("active", "CSP", "alta", "No configurado (riesgo XSS)", domain)

    csp_findings = p.get("csp_findings", [])
    for f in csp_findings:
        sev = f.get("severity", "media")
        rec = f.get("recommendation", "")
        desc = f.get("description", "")
        add("active", f"CSP: {f.get('directive','')}", sev, desc[:200], domain,
            _evidence_text(f"Recomendacion: {rec[:300]}", "Recomendacion CSP"))

    cookie_findings = p.get("cookie_findings", [])
    for f in cookie_findings:
        sev = f.get("severity", "media")
        desc = f.get("description", "")
        add("active", f"Cookie: {f.get('cookie','')}", sev, desc[:200], domain,
            _evidence_text(f"Recomendacion: {f.get('recommendation','')[:300]}", "Recomendacion Cookie"))

    xfo = headers.get("x-frame-options")
    if xfo:
        add("active", "X-Frame-Options", "info", xfo, domain,
            _evidence_text(xfo, "Header X-Frame-Options"))
    else:
        add("active", "X-Frame-Options", "alta", "No configurado (clickjacking)", domain)

    xcto = headers.get("x-content-type-options")
    if xcto and "nosniff" in xcto.lower():
        add("active", "X-Content-Type-Options", "info", "nosniff configurado", domain,
            _evidence_text(xcto, "Header X-Content-Type-Options"))
    else:
        add("active", "X-Content-Type-Options", "media", "No configurado", domain)

    rp = headers.get("referrer-policy")
    if rp:
        add("active", "Referrer-Policy", "info", rp, domain,
            _evidence_text(rp, "Header Referrer-Policy"))
    else:
        add("active", "Referrer-Policy", "baja", "No configurado", domain)

    pp = headers.get("permissions-policy")
    if pp:
        add("active", "Permissions-Policy", "info", "Configurado", domain,
            _evidence_text(pp[:300], "Permissions-Policy"))
    coop = headers.get("cross-origin-opener-policy")
    if coop:
        add("active", "COOP", "info", coop, domain,
            _evidence_text(coop, "Cross-Origin-Opener-Policy"))

    # Show all security headers as block
    if sec_headers:
        add("active", "Security Headers", "info", f"{len(sec_headers)} cabecera(s)", domain,
            _evidence_dict(sec_headers, "Cabeceras de seguridad HTTP"))

    stls = dns.get("starttls_results", [])
    if stls:
        ok = all(s.get("starttls") for s in stls)
        lines = [f"{s.get('exchange','?')}: STARTTLS={'SI' if s.get('starttls') else 'NO'}{' error='+s.get('error','') if s.get('error') else ''}" for s in stls]
        add("active", "STARTTLS", "info" if ok else "alta",
            "Disponible en todos los MX" if ok else f"Falta en {sum(1 for s in stls if not s.get('starttls'))} MX", domain,
            _evidence_block(lines, "Resultados STARTTLS"))

    takeover = p.get("takeover_risks", [])
    for t in takeover:
        sev = "alta" if t.get("vulnerable") else "media"
        lines = [f"Host: {t.get('host','?')}", f"CNAME: {t.get('cname','?')}", f"Servicio: {t.get('service','?')}", f"Descripcion: {t.get('description','?')}"]
        add("active", "Takeover", sev, f"{t.get('host','?')} -> {t.get('cname','?')}", domain,
            _evidence_block(lines, "Subdomain Takeover"))

    patching = p.get("patching", [])
    for pt in patching:
        if pt.get("status") == "eol":
            add("active", "Patch/EOL", "alta", f"{pt['technology']} {pt.get('version','')}", domain,
                _evidence_text(pt.get('detail',''), f"{pt['technology']} EOL"))
        elif pt.get("status") == "ending":
            add("active", "Patch/EOL", "media", f"{pt['technology']} {pt.get('version','')}", domain,
                _evidence_text(pt.get('detail',''), f"{pt['technology']} ending"))

    supply = p.get("supply_chain", [])
    if supply:
        lines = [f"{s.get('domain','?')} [{s.get('source','?')}] - {', '.join(s.get('ips',[]) or [])}" for s in supply[:10]]
        add("active", "Supply Chain", "info", f"{len(supply)} dependencia(s)", domain,
            _evidence_block(lines, "Cadena de suministro"))

    scr = p.get("supply_chain_reputation", {})
    if scr.get("dnsbl_count", 0) > 0:
        lines = [f"{s.get('ip','?')} en {s.get('dnsbl','?')}" for s in scr.get("dnsbl",[])]
        add("active", "SC Rep/DNSBL", "alta", f"{scr['dnsbl_count']} IP tercero(s) listada(s)", domain,
            _evidence_block(lines, "Supply Chain DNSBL"))
    if scr.get("urlhaus_count", 0) > 0:
        lines = [f"{s.get('domain','?')} ({s.get('url_count',0)} URLs)" for s in scr.get("urlhaus",[])]
        add("active", "SC Rep/URLhaus", "alta", f"{scr['urlhaus_count']} dominio(s) tercero(s) en URLhaus", domain,
            _evidence_block(lines, "Supply Chain URLhaus"))

    fp = https.get("server_fingerprint")
    if fp:
        add("active", "Server FP", "info", fp, domain)

    return passive, active


# ---------------------------------------------------------------------------
# CSS - TIPOGRAFIA GRANDE
# ---------------------------------------------------------------------------

CSS = r"""
:root {
  --bg-body: #f4f5f7;
  --bg-card: #ffffff;
  --bg-card-alt: #f8fafc;
  --border: #e2e8f0;
  --text: #1e293b;
  --text-muted: #64748b;
  --passive: #2563eb;
  --passive-bg: #dbeafe;
  --active: #d97706;
  --active-bg: #fef3c7;
  --good: #16a34a;
  --good-bg: #dcfce7;
  --warn: #d97706;
  --bad: #dc2626;
  --bad-bg: #fee2e2;
  --info: #2563eb;
  --accent: #1e40af;
  --font: 'Segoe UI',system-ui,-apple-system,sans-serif;
}
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg-body); color:var(--text); font-family:var(--font); font-size:16px; line-height:1.6; padding:0; }
.wrap { max-width:1100px; margin:0 auto; padding:20px 24px 50px; }

/* Header */
.header { background:linear-gradient(135deg,#0f172a 0%,#1e3a8a 100%); border-radius:12px; padding:28px 32px; margin-bottom:28px; display:flex; align-items:center; gap:20px; color:#fff; }
.header .shield { font-size:42px; line-height:1; }
.header h1 { font-size:1.5rem; font-weight:700; letter-spacing:.02em; }
.header .meta { font-size:13px; opacity:.75; margin-top:4px; }
.header .badge-pa { display:inline-flex; gap:10px; margin-left:auto; }
.header .badge-pa span { padding:6px 16px; border-radius:6px; font-size:13px; font-weight:700; letter-spacing:.06em; }
.badge-passive { background:rgba(37,99,235,.2); color:#93c5fd; border:1px solid #93c5fd; }
.badge-active { background:rgba(217,119,6,.2); color:#fcd34d; border:1px solid #fcd34d; }

/* KPI row */
.kpis { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:24px; }
.kpi { background:var(--bg-card); border:1px solid var(--border); border-radius:10px; padding:18px 20px; text-align:center; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.kpi .num { font-size:32px; font-weight:700; line-height:1.2; }
.kpi .lbl { font-size:12px; color:var(--text-muted); text-transform:uppercase; letter-spacing:.06em; margin-top:4px; }

/* Grade row */
.grade-row { display:flex; align-items:center; gap:18px; background:var(--bg-card); border:1px solid var(--border); border-radius:12px; padding:20px 24px; margin-bottom:24px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.grade-letter { font-size:56px; font-weight:800; line-height:1; width:70px; text-align:center; }
.grade-bar { flex:1; height:12px; background:#e2e8f0; border-radius:6px; overflow:hidden; }
.grade-fill { height:100%; border-radius:6px; }
.grade-desc { font-size:14px; color:var(--text-muted); }

/* Two-column passive/active overview */
.pa-overview { display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-bottom:24px; }
.pa-col { background:var(--bg-card); border:1px solid var(--border); border-radius:12px; padding:20px 24px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.pa-col.passive { border-left:4px solid var(--passive); }
.pa-col.active { border-left:4px solid var(--active); }
.pa-col h3 { font-size:14px; text-transform:uppercase; letter-spacing:.1em; margin-bottom:10px; display:flex; align-items:center; gap:8px; }
.pa-col h3 .icon { font-size:20px; }
.pa-col.passive h3 { color:var(--passive); }
.pa-col.active h3 { color:var(--active); }
.pa-count { font-size:36px; font-weight:700; }
.pa-sub { font-size:13px; color:var(--text-muted); margin-top:4px; }
.pa-desc { font-size:13px; color:var(--text-muted); margin-top:8px; line-height:1.5; }

/* Table */
table.data { width:100%; border-collapse:collapse; font-size:14px; margin-bottom:24px; background:var(--bg-card); border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.04); }
table.data th { background:#f1f5f9; border:1px solid var(--border); padding:10px 12px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted); font-weight:600; }
table.data td { border:1px solid var(--border); padding:8px 10px; vertical-align:top; }
table.data tr:hover td { background:var(--bg-card-alt); }
table.data .num { text-align:right; white-space:nowrap; }

/* Badges */
.tag { display:inline-block; padding:3px 10px; border-radius:4px; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.05em; }
.tag.passive { background:var(--passive-bg); color:var(--passive); border:1px solid var(--passive); }
.tag.active { background:var(--active-bg); color:#92400e; border:1px solid var(--active); }
.sev { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; text-transform:uppercase; }
.sev.alta { background:var(--bad-bg); color:var(--bad); }
.sev.media { background:var(--active-bg); color:#92400e; }
.sev.baja { background:var(--good-bg); color:var(--good); }
.sev.info { background:var(--passive-bg); color:var(--passive); }

/* Finding cards */
.findings-grid { display:grid; grid-template-columns:1fr; gap:8px; margin-bottom:24px; }
.finding { background:var(--bg-card); border:1px solid var(--border); border-radius:8px; padding:14px 16px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.finding .f-header { display:flex; align-items:center; gap:8px; margin-bottom:6px; flex-wrap:wrap; }
.finding .f-label { font-size:15px; font-weight:600; color:var(--text); }
.finding .f-domain { font-size:13px; color:var(--text-muted); margin-bottom:4px; }
.finding .f-detail { font-size:14px; color:var(--text-muted); line-height:1.5; white-space:pre-wrap; }

/* Evidence collapsible */
details.ev { margin-top:8px; font-size:13px; }
details.ev summary { cursor:pointer; color:var(--accent); font-weight:600; padding:4px 0; user-select:none; }
details.ev summary:hover { color:#2563eb; }
.ev-body { background:#f8fafc; border:1px solid var(--border); border-radius:6px; padding:10px 14px; margin-top:4px; max-height:300px; overflow-y:auto; }
.ev-line { display:block; padding:2px 0; font-family:'Cascadia Code','Fira Code','Consolas',monospace; font-size:13px; word-break:break-all; line-height:1.5; color:#334155; }
.ev-line strong { color:var(--accent); }

/* Provider cards */
.prov-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:14px; margin-bottom:24px; }
.prov-card { background:var(--bg-card); border:1px solid var(--border); border-radius:10px; padding:16px 18px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.prov-card h4 { font-size:15px; font-weight:600; margin-bottom:6px; }
.prov-card .pdom { font-size:13px; color:var(--text-muted); }
.prov-bar { display:flex; gap:0; height:6px; border-radius:3px; overflow:hidden; margin:8px 0; }
.prov-bar .seg.passive { background:var(--passive); }
.prov-bar .seg.active { background:var(--active); }
.prov-stats { display:flex; gap:16px; font-size:13px; color:var(--text-muted); }

/* OWASP */
.owasp-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:10px; margin-bottom:24px; }
.owasp-item { background:var(--bg-card); border:1px solid var(--border); border-radius:8px; padding:12px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.owasp-item .oid { font-size:11px; font-weight:700; color:var(--accent); }
.owasp-item .otitle { font-size:14px; margin:4px 0; }
.owasp-bar { height:6px; background:#e2e8f0; border-radius:3px; margin-top:8px; }
.owasp-fill { height:6px; border-radius:3px; }
.owasp-pct { font-size:13px; color:var(--text-muted); margin-top:2px; }

/* Section title */
.sec-title { font-size:18px; font-weight:700; color:var(--accent); border-bottom:2px solid var(--accent); padding-bottom:6px; margin:28px 0 16px; display:flex; align-items:center; gap:10px; }

/* Footer */
.footer { text-align:center; font-size:13px; color:var(--text-muted); border-top:1px solid var(--border); padding-top:16px; margin-top:28px; }

/* Scrollable table wrapper */
.tbl-wrap { overflow-x:auto; margin-bottom:24px; }

/* Print */
@media print { body { background:#fff; } 
  .header,.kpi,.pa-col,.finding,.prov-card,.owasp-item,.grade-row { break-inside:avoid; }
  .header { background:#0f172a!important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .tag,.sev,.badge-passive,.badge-active { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
}
"""


def build_report(asm: dict[str, Any], title: str, subtitle: str, version: str) -> str:
    providers = asm.get("providers", [])
    matrix = asm.get("matrix", [])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    scanned_at = asm.get("generated_utc", now)

    matrix_by_domain: dict[str, dict] = {}
    for m in matrix:
        matrix_by_domain[m.get("dominio", "")] = m

    all_passive: list[dict] = []
    all_active: list[dict] = []
    prov_summaries: list[dict] = []

    for p in providers:
        domain = p.get("domain", "")
        m = matrix_by_domain.get(domain, {})
        pas, act = classify_issues(m, p)
        all_passive.extend(pas)
        all_active.extend(act)
        prov_summaries.append({
            "name": p.get("name", domain),
            "domain": domain,
            "passive_count": len(pas),
            "active_count": len(act),
            "passive_high": sum(1 for x in pas if x["severity"] in ("alta",)),
            "active_high": sum(1 for x in act if x["severity"] in ("alta",)),
            "total": len(pas) + len(act),
        })

    def severity_summary(items: list[dict]) -> dict:
        return {
            "alta": sum(1 for x in items if x["severity"] == "alta"),
            "media": sum(1 for x in items if x["severity"] == "media"),
            "baja": sum(1 for x in items if x["severity"] == "baja"),
            "info": sum(1 for x in items if x["severity"] == "info"),
        }

    pas_summary = severity_summary(all_passive)
    act_summary = severity_summary(all_active)

    total_high = pas_summary["alta"] * 3 + act_summary["alta"] * 4 + pas_summary["media"] * 1 + act_summary["media"] * 2
    score = max(0, min(100, 100 - total_high))
    grade = grade_letter(score)
    gcol = grade_color(grade)

    def render_finding_grid(items: list[dict], cat: str) -> str:
        if not items:
            return '<div style="color:var(--text-muted);font-size:15px;padding:8px 0;">Sin hallazgos</div>'
        rows = ""
        for f in items:
            sev = f["severity"]
            ev = f.get("evidence", "")
            rows += f"""<div class="finding">
              <div class="f-header">
                <span class="tag {cat}">{cat.upper()}</span>
                <span class="sev {sev}">{sev.upper()}</span>
                <span class="f-label">{esc(f['label'])}</span>
              </div>
              <div class="f-domain">{esc(f['domain'])}</div>
              <div class="f-detail">{esc(f['detail'])}</div>
              {ev}
            </div>"""
        return rows

    # OWASP
    owasp_html = ""
    first_m = next(iter(matrix_by_domain.values()), {})
    owasp_data = first_m.get("owasp") if matrix_by_domain else None
    if owasp_data:
        risks = owasp_data.get("risks", {})
        ocomply = owasp_data.get("overall_compliance", 0)
        ograde = owasp_data.get("overall_grade", "?")
        ocolor = grade_color(ograde)
        items = ""
        for rid in ("ASI-01", "ASI-02", "ASI-03", "ASI-04", "ASI-05", "ASI-06", "ASI-07", "ASI-08", "ASI-09", "ASI-10"):
            r = risks.get(rid, {})
            cpct = r.get("compliance_pct", 0)
            rc = grade_color(grade_letter(cpct))
            items += f"""<div class="owasp-item">
              <div class="oid">{rid}</div>
              <div class="otitle">{esc(r.get('title',''))}</div>
              <div class="owasp-bar"><div class="owasp-fill" style="width:{cpct}%;background:{rc}"></div></div>
              <div class="owasp-pct">{cpct:.0f}% compliance</div>
            </div>"""
        owasp_html = f"""<div class="sec-title">OWASP Agentic Top 10</div>
        <div class="grade-row">
          <div class="grade-letter" style="color:{ocolor}">{esc(ograde)}</div>
          <div><div class="grade-bar"><div class="grade-fill" style="width:{ocomply}%;background:{ocolor}"></div></div></div>
          <div class="grade-desc">{ocomply:.1f}% compliance general</div>
        </div>
        <div class="owasp-grid">{items}</div>"""

    # Provider cards
    prov_cards = ""
    for ps in prov_summaries:
        total = ps["total"] or 1
        pw = ps["passive_count"] / total * 100
        aw = ps["active_count"] / total * 100
        prov_cards += f"""<div class="prov-card">
          <h4>{esc(ps['name'])}</h4>
          <div class="pdom">{esc(ps['domain'])}</div>
          <div class="prov-bar">
            <div class="seg passive" style="width:{pw}%" title="{ps['passive_count']} pasivos"></div>
            <div class="seg active" style="width:{aw}%" title="{ps['active_count']} activos"></div>
          </div>
          <div class="prov-stats">
            <span style="color:var(--passive)">PASIVO: {ps['passive_count']}</span>
            <span style="color:var(--active)">ACTIVO: {ps['active_count']}</span>
            <span style="color:var(--bad)">ALTA: {ps['passive_high'] + ps['active_high']}</span>
          </div>
        </div>"""

    # Matrix table
    matrix_rows = ""
    for m in matrix:
        dom = m.get("dominio", "")
        mp = matrix_by_domain.get(dom, m)
        https_val = mp.get("https", "?")
        hsts_v = "S" if mp.get("hsts") else "N"
        csp_v = "S" if mp.get("csp") else "N"
        dnssec_v = "S" if mp.get("dnssec_ok") else "N"
        tls_v = mp.get("tls_version", "?")
        mx_c = mp.get("mx_count", 0)
        p_eol = mp.get("patching_eol", 0)
        p_end = mp.get("patching_ending", 0)
        sc_c = mp.get("supply_chain_count", 0)
        take_c = mp.get("takeover_count", 0)
        typo_c = mp.get("typosquatting_count", 0)
        csp_weak = "S" if mp.get("csp_finding_count", 0) > 0 else "N"
        cookie_ins = "S" if mp.get("cookie_insecure") else "N"
        caa_v = "S" if mp.get("caa") else "N"
        mta_v = "S" if mp.get("mta_sts") else "N"
        starttls_v = "S" if mp.get("starttls_ok") else ("N" if mp.get("starttls_count", 0) > 0 else "-")
        cve_c = mp.get("vulnerability_count", 0)
        dnsbl_c = mp.get("ip_reputation_count", 0)
        matrix_rows += f"""<tr>
          <td><strong>{esc(mp.get('proveedor',''))}</strong></td>
          <td>{esc(mp.get('dominio',''))}</td>
          <td>{https_val}</td>
          <td>{hsts_v}</td>
          <td>{csp_v}</td>
          <td>{csp_weak}</td>
          <td>{cookie_ins}</td>
          <td>{dnssec_v}</td>
          <td>{tls_v}</td>
          <td class="num">{mx_c}</td>
          <td>{caa_v}</td>
          <td>{mta_v}</td>
          <td>{starttls_v}</td>
          <td class="num">{cve_c}</td>
          <td class="num">{dnsbl_c}</td>
          <td class="num">{sc_c}</td>
          <td class="num">{take_c}</td>
          <td class="num">{typo_c}</td>
          <td class="num">{p_eol}/{p_end}</td>
        </tr>"""

    matrix_table = f"""<div class="tbl-wrap">
    <table class="data">
      <thead><tr>
        <th>Proveedor</th><th>Dominio</th><th>HTTPS</th><th>HSTS</th><th>CSP</th>
        <th>CSP-W</th><th>COOK</th><th>DNSSEC</th><th>TLS</th><th>MX</th>
        <th>CAA</th><th>MTA-STS</th><th>STARTTLS</th><th>CVE</th><th>DNSBL</th>
        <th>SC</th><th>TKO</th><th>TYPO</th><th>EOL/END</th>
      </tr></thead>
      <tbody>{matrix_rows}</tbody>
    </table></div>"""

    html_out = f"""<!DOCTYPE html>
<html lang="es">
<head><meta charset="utf-8"><title>{esc(title)}</title>
<style>{CSS}</style></head>
<body>
<div class="wrap">

  <div class="header">
    <div class="shield">&#x1f6e1;</div>
    <div>
      <h1>{esc(title)}</h1>
      <div class="meta">{esc(subtitle)} | {esc(version)} | {esc(scanned_at)}</div>
    </div>
    <div class="badge-pa">
      <span class="badge-passive">PASIVO: {len(all_passive)}</span>
      <span class="badge-active">ACTIVO: {len(all_active)}</span>
    </div>
  </div>

  <div class="grade-row">
    <div class="grade-letter" style="color:{gcol}">{esc(grade)}</div>
    <div><div class="grade-bar"><div class="grade-fill" style="width:{score}%;background:{gcol}"></div></div></div>
    <div class="grade-desc">Score: {score:.1f}/100 | {len(providers)} proveedor(es) | {len(all_passive) + len(all_active)} hallazgos totales</div>
  </div>

  <div class="kpis">
    <div class="kpi"><div class="num" style="color:var(--info)">{len(providers)}</div><div class="lbl">Proveedores</div></div>
    <div class="kpi"><div class="num" style="color:var(--passive)">{len(all_passive)}</div><div class="lbl">Hallazgos Pasivos</div></div>
    <div class="kpi"><div class="num" style="color:var(--active)">{len(all_active)}</div><div class="lbl">Hallazgos Activos</div></div>
    <div class="kpi"><div class="num" style="color:var(--bad)">{pas_summary['alta'] + act_summary['alta']}</div><div class="lbl">Alta Severidad</div></div>
    <div class="kpi"><div class="num" style="color:var(--warn)">{pas_summary['media'] + act_summary['media']}</div><div class="lbl">Media Severidad</div></div>
  </div>

  <div class="pa-overview">
    <div class="pa-col passive">
      <h3><span class="icon">&#x1f50d;</span> Analisis Pasivo</h3>
      <div class="pa-count" style="color:var(--passive)">{len(all_passive)}</div>
      <div class="pa-sub">{pas_summary['alta']} alta · {pas_summary['media']} media · {pas_summary['baja']} baja · {pas_summary['info']} info</div>
      <div class="pa-desc">DNS records, SPF/DMARC/DKIM, DNSSEC, DANE, CAA, CT Logs, Typosquatting, CVE OSV, Credential Leaks, Social OSINT, DNSBL, URLhaus</div>
    </div>
    <div class="pa-col active">
      <h3><span class="icon">&#x26a1;</span> Analisis Activo</h3>
      <div class="pa-count" style="color:var(--active)">{len(all_active)}</div>
      <div class="pa-sub">{act_summary['alta']} alta · {act_summary['media']} media · {act_summary['baja']} baja · {act_summary['info']} info</div>
      <div class="pa-desc">Puertos, TLS, HTTP Headers, CSP, Cookies, STARTTLS, Takeover, Patching, Supply Chain, Server Fingerprint</div>
    </div>
  </div>

  <div class="sec-title">Resumen por Proveedor</div>
  <div class="prov-grid">{prov_cards}</div>

  <div class="sec-title">Matriz de Hallazgos</div>
  {matrix_table}

  <div class="sec-title" style="border-color:var(--passive);color:var(--passive);">&#x1f50d; Hallazgos Pasivos</div>
  {render_finding_grid(all_passive, "passive")}

  <div class="sec-title" style="border-color:var(--active);color:var(--active);">&#x26a1; Hallazgos Activos</div>
  {render_finding_grid(all_active, "active")}

  {owasp_html}

  <div class="footer">
    Generado: {now} | {esc(title)} v{esc(version)}
  </div>

</div>
</body>
</html>"""
    return html_out


def main() -> int:
    ap = argparse.ArgumentParser(description="Reporte ASM Pasivo/Activo")
    ap.add_argument("--asm", type=Path, default=ROOT / "asm_report.json", help="JSON de asm_scan.py")
    ap.add_argument("--out", type=Path, default=ROOT / "informe_pasivo_activo.html", help="HTML de salida")
    ap.add_argument("--title", default="INFORME ASM - PASIVO vs ACTIVO")
    ap.add_argument("--subtitle", default="Clasificacion de analisis de superficie de ataque")
    ap.add_argument("--version", default="1.0")
    args = ap.parse_args()
    asm = json.loads(args.asm.read_text(encoding="utf-8"))
    html_out = build_report(asm, args.title, args.subtitle, args.version)
    args.out.write_text(html_out, encoding="utf-8")
    print(f"[OK] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
