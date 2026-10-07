# pasivo_canon.py — Set canónico de items pasivos (nivel 1) compartido por todos los generadores.
# Garantiza que en modo "pasivo" los 8 informes muestren exactamente los MISMOS items,
# y que cada item tenga estado explícito (dato / vacío / sin configurar / error) para
# homogeneizar la cobertura independientemente de API keys o datos disponibles.
#
# Uso desde un generador:
#   from pasivo_canon import collect_pasive_items
#   for it in collect_pasive_items(p):
#       # it = {"id","label","grupo","valor":"...","status":"ok|vacio|sinclave|error"}
#       # render según el estilo del informe.

from __future__ import annotations

from typing import Any


def _err(d: dict) -> str | None:
    """Texto del error si el dict es un resultado con error; None si ok."""
    if not isinstance(d, dict):
        return None
    e = d.get("error")
    return str(e) if e else None


def _status(d: dict | None) -> str:
    """ok | vacio | sinclave | error | sinDatos (sin item)."""
    if not d:
        return "sinDatos"
    e = _err(d)
    if e:
        low = e.lower()
        if "key" in low or "api" in low or "configura" in low or "no encontrad" in low or "csrf" in low:
            return "sinclave"
        return "error"
    return "ok"


def _join(lst) -> str:
    lst = [x for x in (lst or []) if x not in ("", None)]
    return ", ".join(str(x) for x in lst[:40])


def _d(strval, status="ok", grupo="", extra=None):
    return {"label": strval["label"], "id": strval["id"], "grupo": strval["grupo"],
            "valor": strval["valor"], "status": status, "extra": extra or {}}


def collect_pasive_items(p: dict) -> list[dict]:
    """Devuelve la lista canónica ordenada de items pasivos para el provider p."""
    out: list[dict] = []
    dns = (p.get("dns") or {}) if isinstance(p.get("dns"), dict) else {}
    ext = (p.get("external") or {}) if isinstance(p.get("external"), dict) else {}
    strepr = p.get("supply_chain_reputation") or {}
    if not isinstance(strepr, dict):
        strepr = {}

    def item(label, grupo, valor, status):
        out.append({"label": label, "grupo": grupo, "valor": valor, "status": status})

    # ---- 1. DNS apex ----
    ip4 = _join(dns.get("ipv4"))
    if ip4:
        item("IPv4 / IPv6", "DNS", f"{ip4}" + (f" / {_join(dns.get('ipv6'))}" if dns.get("ipv6") else ""), "ok")
    elif dns.get("ipv6"):
        item("IPv4 / IPv6", "DNS", _join(dns.get("ipv6")), "ok")
    else:
        item("IPv4 / IPv6", "DNS", "sin datos", "vacio")
    mx = _join(f"{m.get('preference','?')} {m.get('exchange','')}".strip() for m in (dns.get("mx_records") or []) if isinstance(m, dict))
    item("MX", "DNS", mx or "sin datos", "ok" if mx else "vacio")
    ns = _join(dns.get("ns_records"))
    item("NS", "DNS", ns or "sin datos", "ok" if ns else "vacio")
    spf = dns.get("spf_record") or ""
    item("SPF", "DNS", str(spf) or "ausente", "ok" if spf else "vacio")
    dmarc = dns.get("dmarc_record") or ""
    pol = dns.get("dmarc_policy")
    item("DMARC", "DNS", (str(dmarc) + (f" (p={pol})" if pol else "")) or "ausente", "ok" if dmarc else "vacio")
    dkim = dns.get("dkim_records") or []
    item("DKIM", "DNS", f"{len(dkim)} registro(s)" if dkim else "no configurado", "ok" if dkim else "vacio")
    item("DNSSEC", "DNS", "firmado" if dns.get("dnssec_ok") else "no firmado", "ok" if dns.get("dnssec_ok") else "vacio")
    caa = p.get("caa_records") or []
    item("CAA", "DNS", f"{len(caa)} registro(s)" if caa else "no configurado", "ok" if caa else "vacio")
    item("MTA-STS", "DNS", "configurado" if p.get("mta_sts") else "no configurado", "ok" if p.get("mta_sts") else "vacio")
    item("TLS-RPT", "DNS", "configurado" if p.get("tls_rpt") else "no configurado", "ok" if p.get("tls_rpt") else "vacio")
    item("BIMI", "DNS", "configurado" if p.get("bimi") else "no configurado", "ok" if p.get("bimi") else "vacio")

    # ---- 2. Subdominios CT y pasivos ----
    crt = p.get("crt_subdomains") or []
    item("Subdominios (CT)", "Subdominios", _join(crt) or "sin datos", "ok" if crt else "vacio")

    # ---- 3. Credenciales leaks ----
    leaks = p.get("credential_leaks") or []
    if leaks and not any(_err(l) and "API_KEY" in str(_err(l)).upper() for l in leaks):
        seg = []
        for l in leaks[:8]:
            if not isinstance(l, dict):
                continue
            src = l.get("source") or l.get("name") or "?"
            cnt = l.get("count") or l.get("entries") or l.get("total") or "?"
            seg.append(f"{src}: {cnt}")
        item("Credenciales (leaks)", "Reputación", "; ".join(seg) or "sin datos", "ok")
    elif leaks and any(_err(l) for l in leaks):
        item("Credenciales (leaks)", "Reputación", _err(leaks[-1]) or "sin configurar", "sinclave")
    else:
        item("Credenciales (leaks)", "Reputación", "sin datos", "vacio")

    # ---- 4. Typosquatting ----
    typos = p.get("typosquatting") or []
    if isinstance(typos, list):
        item("Typosquatting", "Reputación", "; ".join(f"{t.get('domain','?')}" for t in typos[:8]) or "sin datos", "ok" if typos else "vacio")
    else:
        item("Typosquatting", "Reputación", str(typos) if typos else "sin datos", "ok" if typos else "vacio")

    # ---- 5. DNSBL / URLhaus ----
    dnsbl = strepr.get("dnsbl") or []
    urlhs = strepr.get("urlhaus") or []
    if dnsbl or urlhs:
        seg = [f"DNSBL: {len(dnsbl)}" if dnsbl else "", f"URLhaus: {len(urlhs)}" if urlhs else ""]
        item("DNSBL / URLhaus", "Reputación", " · ".join(s for s in seg if s), "ok")
    else:
        item("DNSBL / URLhaus", "Reputación", "limpio", "vacio")

    # ---- 6. OSINT externo ----
    whois = ext.get("whois") or {}
    if _err(whois):
        item("WHOIS", "OSINT", _err(whois), _status(whois))
    else:
        wseg = []
        if whois.get("registrar"): wseg.append(f"Registrar: {whois['registrar']}")
        if whois.get("registrant_organization"): wseg.append(f"Org: {whois['registrant_organization']}")
        if whois.get("creation_date"): wseg.append(f"Creado: {str(whois['creation_date'])[:10]}")
        if whois.get("expiration_date"): wseg.append(f"Expira: {str(whois['expiration_date'])[:10]}")
        if whois.get("emails"): wseg.append(f"Emails: {', '.join(whois['emails'][:4])}")
        item("WHOIS", "OSINT", " | ".join(wseg) or "sin datos", "ok" if wseg else "vacio")
    wd = p.get("who_dat") or {}
    if isinstance(wd, dict):
        apex = wd.get("apex") or {}
        if _err(apex) is None:
            wd_seg = []
            if apex.get("is_registered"):
                if apex.get("registrar") and isinstance(apex["registrar"], dict):
                    wd_seg.append(f"Registrar: {apex['registrar'].get('name','?')}")
                elif apex.get("registrar"):
                    wd_seg.append(f"Registrar: {apex['registrar']}")
                if apex.get("creation_date"): wd_seg.append(f"Creado: {apex['creation_date']}")
                if apex.get("expiration_date"): wd_seg.append(f"Expira: {apex['expiration_date']}")
                ns = apex.get("name_servers") or []
                if ns: wd_seg.append(f"NS: {', '.join(ns[:3])}")
                if apex.get("dnssec") and isinstance(apex["dnssec"], dict) and apex["dnssec"].get("signed"):
                    wd_seg.append("DNSSEC: sí")
                reg = apex.get("registrant") or {}
                if reg.get("organization"): wd_seg.append(f"Org: {reg['organization']}")
                if reg.get("email"): wd_seg.append(f"Email: {reg['email']}")
                item("WHOIS/RDAP (who-dat)", "OSINT", " | ".join(wd_seg) or "sin datos", "ok" if wd_seg else "vacio")
            else:
                item("WHOIS/RDAP (who-dat)", "OSINT", "dominio no registrado", "ok")
        else:
            item("WHOIS/RDAP (who-dat)", "OSINT", _err(apex) or "sin datos", _status(apex))
    else:
        item("WHOIS/RDAP (who-dat)", "OSINT", "sin datos", "vacio")
    dnsd = ext.get("dnsdumpster") or {}
    if _err(dnsd):
        item("DNSDumpster", "OSINT", _err(dnsd), _status(dnsd))
    elif dnsd.get("host_records"):
        item("DNSDumpster", "OSINT", f"{len(dnsd['host_records'])} registro(s)", "ok")
    else:
        item("DNSDumpster", "OSINT", "sin datos", "vacio")
    shodan = ext.get("shodan") or {}
    if _err(shodan):
        item("Shodan", "OSINT", _err(shodan), _status(shodan))
    elif shodan.get("hosts"):
        ports = sorted({p2 for h in shodan["hosts"] for p2 in h.get("ports", [])})
        item("Shodan", "OSINT", f"{len(shodan['hosts'])} host(s)" + (f" · puertos: {', '.join(str(p) for p in ports[:20])}" if ports else ""), "ok")
    else:
        item("Shodan", "OSINT", "sin datos", "vacio")
    censys = ext.get("censys") or {}
    if _err(censys):
        item("Censys", "OSINT", _err(censys), _status(censys))
    else:
        nc = len(censys.get("certificates") or [])
        nh = len(censys.get("hosts") or [])
        item("Censys", "OSINT", f"{nc} cert(s) · {nh} host(s)" if (nc or nh) else "sin datos", "ok" if (nc or nh) else "vacio")
    th = ext.get("theharvester") or {}
    if _err(th):
        item("theHarvester", "OSINT", _err(th), _status(th))
    else:
        tseg = []
        if th.get("emails"): tseg.append(f"emails: {len(th['emails'])}")
        if th.get("subdomains"): tseg.append(f"subs: {len(th['subdomains'])}")
        if th.get("ips"): tseg.append(f"ips: {len(th['ips'])}")
        item("theHarvester", "OSINT", " · ".join(tseg) or "sin datos", "ok" if tseg else "vacio")
    idb = ext.get("internetdb") or {}
    if idb.get("ips"):
        n_cve = 0
        for e in idb["ips"].values():
            if isinstance(e, dict):
                n_cve += len(e.get("vulns") or [])
        item("Shodan InternetDB", "OSINT", f"{len(idb['ips'])} IP(s)" + (f" · {n_cve} CVE(s)" if n_cve else ""), "ok")
    else:
        item("Shodan InternetDB", "OSINT", "sin datos", "vacio")
    expo = ext.get("shodan_exposure") or {}
    if expo.get("ip_count") or expo.get("puertos_expuestos"):
        eseg = []
        if expo.get("ip_count"): eseg.append(f"{expo['ip_count']} IP(s)")
        if expo.get("total_cves"): eseg.append(f"{expo['total_cves']} CVE(s)")
        if expo.get("critico"): eseg.append("exposición confirmada")
        item("Shodan Exposure", "OSINT", " · ".join(eseg) or "sin datos", "ok")
    else:
        item("Shodan Exposure", "OSINT", "sin datos", "vacio")

    # ---- 7. KUMO N1 ----
    kumo = (p.get("kumo") or {}) if isinstance(p.get("kumo"), dict) else {}
    wb = kumo.get("wayback") or {}
    if _err(wb) is None and (wb.get("interesting") or wb.get("urls")):
        item("Wayback (KUMO)", "KUMO", f"{len(wb.get('interesting') or wb.get('urls'))} URL(s)", "ok")
    else:
        item("Wayback (KUMO)", "KUMO", _err(wb) or "sin datos", _status(wb) if _err(wb) else "vacio")
    bi = kumo.get("breachintel") or {}
    if _err(bi) is None:
        s = bi.get("summary") or {}
        if s.get("total_employees_leaked") or s.get("total_clients_leaked") or s.get("total_infostealer_hits") or s.get("total_emails_found"):
            bseg = []
            if s.get("total_employees_leaked"): bseg.append(f"emp: {s['total_employees_leaked']}")
            if s.get("total_clients_leaked"): bseg.append(f"cl: {s['total_clients_leaked']}")
            if s.get("total_emails_found"): bseg.append(f"emails: {s['total_emails_found']}")
            if s.get("total_infostealer_hits"): bseg.append(f"infostealer: {s['total_infostealer_hits']}")
            item("Breach Intel (KUMO)", "KUMO", " · ".join(bseg), "ok")
        else:
            item("Breach Intel (KUMO)", "KUMO", "sin filtraciones", "vacio")
    else:
        item("Breach Intel (KUMO)", "KUMO", _err(bi), _status(bi))
    eh = kumo.get("email_harvest") or {}
    if _err(eh) is None and eh.get("emails"):
        item("Email Harvest (KUMO)", "KUMO", _join(eh.get("emails")), "ok")
    else:
        item("Email Harvest (KUMO)", "KUMO", _err(eh) or "sin datos", _status(eh) if _err(eh) else "vacio")

    # ---- 8. Prism N1 ----
    prism = (p.get("prism") or {}) if isinstance(p.get("prism"), dict) else {}
    ll = prism.get("leak_lookup") or {}
    if _err(ll) is None and ll.get("breaches"):
        item("Prism Breach Lookup", "Prism", f"{len(ll['breaches'])} filtracion(es)", "ok")
    else:
        item("Prism Breach Lookup", "Prism", _err(ll) or (ll.get("note") or "sin filtraciones"), _status(ll) if _err(ll) else "vacio")
    oc = prism.get("onion_checker") or {}
    if _err(oc) is None and oc.get("results"):
        item("Prism Onion / Dark Web", "Prism", f"{oc.get('total_found', 0)} mirror(s)", "ok")
    else:
        item("Prism Onion / Dark Web", "Prism", _err(oc) or "sin datos", _status(oc) if _err(oc) else "vacio")
    gh = prism.get("github_recon") or {}
    if _err(gh) is None and gh.get("profile"):
        prof = gh.get("profile") or {}
        item("Prism GitHub Recon", "Prism", f"@{gh.get('username','?')} ({prof.get('name','')}) — {gh.get('repo_count',0)} repos", "ok")
    else:
        item("Prism GitHub Recon", "Prism", _err(gh) or "sin datos", _status(gh) if _err(gh) else "vacio")
    gr = prism.get("gravatar") or {}
    if _err(gr) is None and gr.get("hits"):
        item("Prism Gravatar", "Prism", f"{gr.get('total_hits', 0)} perfil(es)", "ok")
    else:
        item("Prism Gravatar", "Prism", _err(gr) or "sin datos", _status(gr) if _err(gr) else "vacio")

    # ---- 9. Claude-OSINT N1 ----
    co = (p.get("claude_osint") or {}) if isinstance(p.get("claude_osint"), dict) else {}
    m365 = co.get("m365_fingerprint") or {}
    if _err(m365) is None and (m365.get("tenant_space") or m365.get("tenant_guid") or m365.get("m365_detected")):
        mseg = []
        if m365.get("tenant_space"): mseg.append(f"namespace {m365['tenant_space']}")
        if m365.get("tenant_guid"): mseg.append(f"tenant {m365['tenant_guid'][:8]}")
        if m365.get("m365_detected"): mseg.append("M365")
        item("Claude-OSINT M365", "Claude-OSINT", " · ".join(mseg), "ok")
    else:
        item("Claude-OSINT M365", "Claude-OSINT", _err(m365) or "sin datos", _status(m365) if _err(m365) else "vacio")
    spf = co.get("spf_supply_chain") or {}
    if _err(spf) is None and (spf.get("verdict") or {}).get("spoofable"):
        vd = spf["verdict"]
        item("Claude-OSINT SPF/DMARC", "Claude-OSINT", f"{vd.get('spoofable','?')} ({vd.get('severity','?')})", "ok")
    else:
        item("Claude-OSINT SPF/DMARC", "Claude-OSINT", _err(spf) or "sin datos", _status(spf) if _err(spf) else "vacio")
    org = co.get("org_attribution") or {}
    if _err(org) is None and (org.get("lei") or org.get("crt_sh_org", {}).get("candidate_domains")):
        oseg = []
        if org.get("lei"): oseg.append(f"LEI {org['lei'][:10]}")
        if org.get("crt_sh_org", {}).get("candidate_domains"): oseg.append(f"crt.sh O= {len(org['crt_sh_org']['candidate_domains'])} candidatos")
        item("Claude-OSINT Org Attribution", "Claude-OSINT", " · ".join(oseg), "ok")
    elif _err(org):
        item("Claude-OSINT Org Attribution", "Claude-OSINT", _err(org), _status(org))
    else:
        item("Claude-OSINT Org Attribution", "Claude-OSINT", "sin datos", "vacio")
    cti = co.get("cti_chatter") or {}
    if _err(cti) is None:
        rw = cti.get("ransomwatch") or {}
        rl = cti.get("ransomware_live") or {}
        tot = (rw.get("total") or 0) + (rl.get("total") or 0)
        item("Claude-OSINT CTI Chatter", "Claude-OSINT", f"{tot} mencion(es)" if tot else "sin hits", "ok" if tot else "vacio")
    else:
        item("Claude-OSINT CTI Chatter", "Claude-OSINT", _err(cti), _status(cti))
    pdn = co.get("passive_dns_extra") or {}
    if _err(pdn) is None and pdn.get("subdomains"):
        item("Claude-OSINT Passive DNS", "Claude-OSINT", f"{len(pdn['subdomains'])} subdominio(s)", "ok")
    else:
        item("Claude-OSINT Passive DNS", "Claude-OSINT", _err(pdn) or "sin datos", _status(pdn) if _err(pdn) else "vacio")
    cn = co.get("cloud_native_fp") or {}
    if _err(cn) is None and cn.get("fingerprints"):
        item("Claude-OSINT Cloud-native", "Claude-OSINT", ", ".join(f.get('service','?') for f in cn['fingerprints'][:6]), "ok")
    else:
        item("Claude-OSINT Cloud-native", "Claude-OSINT", _err(cn) or "sin datos", _status(cn) if _err(cn) else "vacio")
    h1 = co.get("h1_reference") or {}
    if _err(h1) is None and h1.get("references"):
        item("Claude-OSINT HackerOne", "Claude-OSINT", f"{len(h1['references'])} referencia(s)", "ok")
    else:
        item("Claude-OSINT HackerOne", "Claude-OSINT", _err(h1) or "sin datos", _status(h1) if _err(h1) else "vacio")

    # ---- 10. Social OSINT (si hay usernames) ----
    social = p.get("social") or {}
    if isinstance(social, dict) and social:
        sseg = []
        for net in ("instagram", "tiktok", "twitter", "twitch", "telegram", "github"):
            s = social.get(net) or {}
            if s and not s.get("error"):
                sseg.append(f"{net}: @{s.get('username') or s.get('handle') or '?'}")
        if sseg:
            item("Redes sociales", "Social", "; ".join(sseg), "ok")
    if not any(it["label"] == "Redes sociales" for it in out):
        item("Redes sociales", "Social", "sin cuentas declaradas", "vacio")

    return out