# semi_canon.py — Set canónico de items semi-activos (nivel 2) compartido por todos los generadores.
# Garantiza que en modo "semi-activo" los 8 informes muestren exactamente los MISMOS items
# (adicionales a los pasivos del pasivo_canon), con estado explícito por item.
#
# Uso desde un generador:
#   from semi_canon import collect_semi_active_items
#   for it in collect_semi_active_items(p):
#       # it = {"id","label","grupo","valor":"...","status":"ok|vacio|sinclave|error"}

from __future__ import annotations

from typing import Any


def _err(d: dict) -> str | None:
    if not isinstance(d, dict):
        return None
    e = d.get("error")
    return str(e) if e else None


def _status(d: dict | None) -> str:
    if not d:
        return "vacio"
    e = _err(d)
    if e:
        low = e.lower()
        if "insuficiente" in low or "api" in low or "key" in low or "configura" in low or "timeout" in low:
            return "sinclave" if ("api" in low or "key" in low or "configura" in low) else "error"
        return "error"
    return "ok"


def _join(lst, n=40) -> str:
    lst = [x for x in (lst or []) if x not in ("", None)]
    return ", ".join(str(x) for x in lst[:n])


def collect_semi_active_items(p: dict) -> list[dict]:
    """Devuelve la lista canónica de items semi-activos (adicionales a pasivo) para el provider p."""
    out: list[dict] = []
    dns = (p.get("dns") or {}) if isinstance(p.get("dns"), dict) else {}

    def item(label, grupo, valor, status):
        out.append({"label": label, "grupo": grupo, "valor": valor, "status": status})

    def first_nonempty(dflt, *keys):
        for k in keys:
            v = (dflt.get(k) if isinstance(dflt, dict) else None) or ""
            if v:
                return v
        return ""

    # ---- 1. Servicios / TLS ----
    p80 = p.get("port_80") or {}
    p443 = p.get("port_443") or {}
    if _err(p80):
        item("Puerto 80", "Servicios", _err(p80), _status(p80))
    else:
        item("Puerto 80", "Servicios", "abierto" if p80.get("open") else "cerrado", "ok")
    if _err(p443):
        item("Puerto 443", "Servicios", _err(p443), _status(p443))
    else:
        item("Puerto 443", "Servicios", "abierto" if p443.get("open") else "cerrado", "ok")
    tls = p.get("tls") or {}
    if _err(tls):
        item("TLS", "Servicios", _err(tls), _status(tls))
    else:
        ver = tls.get("negotiated_version") or ""
        extra = "· TLS 1.3-only" if tls.get("tls13_only_ok") else ""
        item("TLS", "Servicios", (ver or "sin version") + extra, "ok" if ver else "vacio")
        item("Certificado", "Servicios",
             (tls.get("cert_subject") or "") + (" · expira " + str(tls.get("cert_expiry"))[:10] if tls.get("cert_expiry") else ""),
             "ok" if (tls.get("cert_subject") or tls.get("cert_expiry")) else "vacio")
        if tls.get("san_list"):
            item("SAN (certificado)", "Servicios", f"{len(tls['san_list'])} nombre(s)", "ok")

    # ---- 2. HTTPS / cabeceras ----
    h = p.get("https") or {}
    if _err(h):
        item("HTTP / HTTPS", "HTTPS", _err(h), _status(h))
    else:
        code = h.get("status_code")
        item("HTTP status", "HTTPS", (str(code) + (" OK" if code and 200 <= code < 400 else "")) if code is not None else "sin respuesta",
             "ok" if code is not None else "vacio")
        fp = h.get("server_fingerprint") or h.get("x_powered_by")
        if fp:
            item("Server fingerprint", "HTTPS", fp, "ok")
        if h.get("redirect_chain"):
            item("Redirección", "HTTPS", f"{len(h['redirect_chain'])} salto(s) -> {h['redirect_chain'][-1]}", "ok")
        hdrs = h.get("headers") or {}
        sec_checks = {
            "HSTS": hdrs.get("strict-transport-security"),
            "CSP": hdrs.get("content-security-policy") or hdrs.get("content-security-policy-report-only"),
            "X-Frame-Options": hdrs.get("x-frame-options"),
            "X-Content-Type-Options": hdrs.get("x-content-type-options"),
            "Referrer-Policy": hdrs.get("referrer-policy"),
            "Permissions-Policy": hdrs.get("permissions-policy"),
        }
        for name, val in sec_checks.items():
            if val:
                item(name, "Cabeceras de seguridad", str(val)[:70], "ok")

    # ---- 3. Superficie web activa ligera ----
    paths = p.get("public_paths") or []
    if paths:
        alive = [x for x in paths if x.get("status_code") not in (None, 404)]
        item("Rutas públicas", "Superficie web",
             f"{len(paths)} sondeada(s) · {len(alive)} responden", "ok")
    waf = p.get("waf_detection") or {}
    if waf.get("detected"):
        item("WAF / CDN", "Superficie web", ", ".join(waf.get("waf") or []), "ok")
    cloud = p.get("cloud_storage") or {}
    buckets = [b for b in (cloud.get("buckets") or []) if b.get("public")]
    if buckets:
        item("Cloud storage público", "Superficie web", f"{len(buckets)} bucket(s) público(s)", "ok")
    elif cloud.get("buckets"):
        item("Cloud storage", "Superficie web", f"{len(cloud['buckets'])} bucket(s) privado(s)", "ok")

    # ---- 4. Vulnerabilidades / mantenimiento ----
    patching = p.get("patching") or []
    if patching:
        eol = [x for x in patching if x.get("status") == "eol"]
        cur = [x for x in patching if x.get("status") == "current"]
        seg = []
        if eol: seg.append(f"{len(eol)} EOL")
        if cur: seg.append(f"{len(cur)} current")
        if seg:
            item("Patching cadence", "Mantenimiento", " · ".join(seg), "ok")
    vulns = p.get("vulnerabilities") or []
    if vulns:
        ids = "; ".join(str(v.get("id") or "?") for v in vulns[:8])
        item("Vulnerabilidades (OSV)", "Mantenimiento", f"{len(vulns)} CVE(s): {ids}", "ok")
    supply = p.get("supply_chain") or []
    if supply:
        item("Supply chain", "Mantenimiento", f"{len(supply)} tercero(s) ({_join([s.get('domain') for s in supply[:6]])})", "ok")
    csp_f = p.get("csp_findings") or []
    if csp_f:
        sevs = sorted({f.get("severity", "?") for f in csp_f})
        item("CSP findings", "Mantenimiento", f"{len(csp_f)} hallazgo(s) ({', '.join(sevs)})", "ok")
    cookie_f = p.get("cookie_findings") or []
    if cookie_f:
        inseg = sum(1 for f in cookie_f if f.get("severity") in ("high", "medium"))
        item("Cookies", "Mantenimiento", f"{len(cookie_f)} hallazgo(s), {inseg} insegura(s)", "ok")

    # ---- 5. KUMO N2 (robots / favicon) ----
    kumo = (p.get("kumo") or {}) if isinstance(p.get("kumo"), dict) else {}
    rb = kumo.get("robots") or {}
    if _err(rb) is None:
        rob = rb.get("robots") or {}
        sens = [d for d in (rob.get("disallowed") or []) if d.get("sensitive")]
        seg = []
        if rb.get("security_txt"): seg.append("security.txt")
        if rb.get("sitemaps"): seg.append(f"{len(rb['sitemaps'])} sitemap(s)")
        if sens: seg.append(f"{len(sens)} ruta(s) sensible(s)")
        if seg:
            item("Robots / Security", "KUMO N2", " · ".join(seg), "ok")
        elif rb.get("robots") is None and not rb.get("security_txt"):
            if str(rb.get("robots")) == "None" or rb.get("robots") is None:
                pass
    fav = kumo.get("favicon") or {}
    if _err(fav) is None and fav.get("favicon_found"):
        item("Favicon hash", "KUMO N2", f"Shodan {fav.get('hash_shodan')}" + (f" · tech {fav.get('technology')}" if fav.get("technology") else ""), "ok")

    # ---- 6. Prism N2 (website_analyzer) ----
    prism = (p.get("prism") or {}) if isinstance(p.get("prism"), dict) else {}
    wa = prism.get("website_analyzer") or {}
    if _err(wa) is None and wa.get("title"):
        seg = []
        if wa.get("title"): seg.append(f"title: {wa['title'][:60]}")
        if wa.get("technologies"): seg.append(f"tech: {len(wa['technologies'])}")
        if wa.get("emails"): seg.append(f"emails: {len(wa['emails'])}")
        if wa.get("phones"): seg.append(f"tel: {len(wa['phones'])}")
        if wa.get("social_links"): seg.append(f"redes: {len(wa['social_links'])}")
        if seg:
            item("Website Analyzer", "Prism N2", " · ".join(seg), "ok")

    # ---- 7. Claude-OSINT N2 (saml_oidc_probe / secret_scan) ----
    co = (p.get("claude_osint") or {}) if isinstance(p.get("claude_osint"), dict) else {}
    sop = co.get("saml_oidc_probe") or {}
    if _err(sop) is None:
        reach = []
        for key, label in (("openid_config", "OIDC"), ("saml_metadata", "SAML"), ("adfs_mex", "ADFS")):
            ch = sop.get(key) or {}
            if ch.get("reachable"):
                txt = f"{label}: {ch.get('status','?')}" + (" metadata" if ch.get("is_metadata") else "")
                reach.append(txt)
        if reach:
            item("SSO/OIDC probe", "Claude-OSINT N2", " · ".join(reach), "ok")
    ss = co.get("secret_scan") or {}
    if _err(ss) is None and (ss.get("total_matches") or ss.get("critical")):
        item("Secret scan", "Claude-OSINT N2", f"{ss.get('total_matches', 0)} match(es)" + (f" · {len(ss['critical'])} crítico(s)" if ss.get("critical") else ""), "ok")

    # ---- 8. Nuclei (vulnerability scanner) ----
    nuclei = (p.get("nuclei") or {}) if isinstance(p.get("nuclei"), dict) else {}
    if _err(nuclei) is None:
        findings = nuclei.get("findings") or []
        sev_counts = nuclei.get("severity_counts") or {}
        if findings:
            sev_str = " | ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items(), key=lambda x: ['critical','high','medium','low','info'].index(x[0]) if x[0] in ['critical','high','medium','low','info'] else 99))
            item("Nuclei Scanner", "Vulnerabilidades", f"{len(findings)} hallazgos ({sev_str})", "ok")
        else:
            item("Nuclei Scanner", "Vulnerabilidades", "sin hallazgos", "vacio")
    elif _err(nuclei):
        item("Nuclei Scanner", "Vulnerabilidades", _err(nuclei), _status(nuclei))
    else:
        item("Nuclei Scanner", "Vulnerabilidades", "no ejecutado (nivel pasivo)", "sinDatos")

    # ---- 9. Gobuster (content discovery) ----
    gobuster = (p.get("gobuster") or {}) if isinstance(p.get("gobuster"), dict) else {}
    if _err(gobuster) is None:
        modes = gobuster.get("modes") or {}
        dir_mode = modes.get("dir") or {}
        dns_mode = modes.get("dns") or {}
        vhost_mode = modes.get("vhost") or {}
        parts = []
        if dir_mode.get("findings"):
            parts.append(f"dir: {len(dir_mode['findings'])} rutas")
        if dns_mode.get("findings"):
            parts.append(f"dns: {len(dns_mode['findings'])} subs")
        if vhost_mode.get("findings"):
            parts.append(f"vhost: {len(vhost_mode['findings'])} vhosts")
        if parts:
            item("Gobuster Discovery", "Superficie web", " · ".join(parts), "ok")
        else:
            item("Gobuster Discovery", "Superficie web", "sin hallazgos", "vacio")
    elif _err(gobuster):
        item("Gobuster Discovery", "Superficie web", _err(gobuster), _status(gobuster))
    else:
        item("Gobuster Discovery", "Superficie web", "no ejecutado (nivel pasivo)", "sinDatos")

    return out