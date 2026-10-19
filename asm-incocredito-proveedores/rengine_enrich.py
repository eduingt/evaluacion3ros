#!/usr/bin/env python3
"""
Enriquecimiento inspirado en reNgine (https://github.com/yogeshojha/rengine).

Modulo puro stdlib, sin red. Aporta tres bloques pensados para B5/B6/B7:

  - Candidatos de vulnerabilidad por patrones tipo GF (reNgine DEFAULT_GF_PATTERNS):
    clasifica las URLs ya recolectadas (wayback, rutas publicas, endpoints API) en
    buckets xss/sqli/ssrf/lfi/rce/redirect/ssti/idor/debug_logic/interestingEXT/
    interestingparams/interestingsubs.
  - Busqueda de palabras clave "interesantes" (reNgine InterestingLookupModel):
    coteja subdominios y URLs contra un catalogo de terminos (admin, dashboard, api...).
  - Servicios web en puertos no estandar (reNgine UNCOMMON_WEB_PORTS, via reconFTW).

Cada build_* degrada a {} y cada render_* devuelve '' cuando no hay datos.
Los candidatos son heuristicos: nunca se afirma explotabilidad.
"""

from __future__ import annotations

import html
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_SEV_COLOR = {
    "critical": "#B71C1C",
    "high": "#E64A19",
    "medium": "#F29900",
    "low": "#F9A825",
    "info": "#607D8B",
}


def _esc(v: Any) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


# --------------------------------------------------------------------------- #
#  A. GF patterns (reNgine DEFAULT_GF_PATTERNS)                               #
# --------------------------------------------------------------------------- #
_SQLI_RX = re.compile(
    r"(?:\bunion\b[^=]{0,40}\bselect\b|\bselect\b[^=]{0,40}\bfrom\b"
    r"|\bor\b\s+\d+\s*=\s*\d+|'\s*or\s*'|--\s|/\*|%27|sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
    re.I,
)
_SSRF_RX = re.compile(
    r"(?:https?://|//[a-z0-9]|169\.254\.169\.254|\blocalhost\b|\b127\.0\.0\.1\b"
    r"|\b0\.0\.0\.0\b|/latest/meta-data|metadata\.google)",
    re.I,
)
_LFI_RX = re.compile(
    r"(?:\.\./|%2e%2e|/etc/(?:passwd|shadow|hosts|issue)|php://|file://|data://|expect://"
    r"|/proc/self|c:\\windows)",
    re.I,
)
_RCE_RX = re.compile(
    r"(?:;|\|\||&&|\$\(|`|%00|\bnc\s+-e\b|/bin/(?:sh|bash)|cmd\.exe|powershell|\|\s*\w+\s*$)",
    re.I,
)
_REDIRECT_RX = re.compile(r"^(?:https?:)?//", re.I)
_SSTI_RX = re.compile(r"(?:\{\{|\$\{|<%|#\{|\{\||%\})", re.I)
_DEBUG_RX = re.compile(r"(?:debug|test|dev|admin|verbose|trace)\s*[=:]\s*(?:1|true|yes|on)", re.I)
_EXT_RX = re.compile(
    r"\.(?:bak|old|backup|orig|save|swp|sql|db|sqlite|conf|config|cnf|ini|env|git|svn|log"
    r"|ya?ml|json|xml|tar|tgz|gz|zip|rar|7z|txt|~)$",
    re.I,
)
_IDOR_RX = re.compile(
    r"/(?:\d{3,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)",
    re.I,
)

_GF_PATTERNS: dict[str, dict[str, Any]] = {
    "rce": {
        "label": "Ejecucion de comandos (RCE)",
        "severity": "critical",
        "params": {"cmd", "exec", "command", "execute", "ping", "jump", "code", "reg", "do",
                   "func", "arg", "option", "process", "step", "function", "req", "feature",
                   "exe", "module", "payload", "run", "print", "system", "daemon", "upload"},
        "value_rx": _RCE_RX,
    },
    "sqli": {
        "label": "Inyeccion SQL",
        "severity": "high",
        "params": {"id", "select", "report", "role", "update", "query", "user", "search",
                   "keyword", "cat", "file", "dir", "date", "year", "month", "view", "edit",
                   "type", "debug", "tag", "content", "page", "list", "from", "to", "sort",
                   "order", "column", "table"},
        "value_rx": _SQLI_RX,
    },
    "ssrf": {
        "label": "SSRF",
        "severity": "high",
        "params": {"url", "uri", "dest", "destination", "redirect", "redirect_uri", "continue",
                   "window", "next", "data", "reference", "site", "html", "document", "folder",
                   "root", "load", "read", "path", "img", "image", "feed", "host", "port",
                   "callback", "return", "out", "target", "proxy", "domain"},
        "value_rx": _SSRF_RX,
        "path_values": False,
    },
    "lfi": {
        "label": "Inclusion de ficheros (LFI)",
        "severity": "high",
        "params": {"file", "filename", "path", "dir", "folder", "document", "root", "pg",
                   "style", "template", "php_path", "doc", "page", "name", "pdf", "include",
                   "inc", "require", "load", "read", "view", "cat", "item", "conf", "config"},
        "value_rx": _LFI_RX,
    },
    "ssti": {
        "label": "SSTI (plantillas)",
        "severity": "high",
        "params": {"template", "preview", "activity", "content", "lang"},
        "value_rx": _SSTI_RX,
    },
    "interestingEXT": {
        "label": "Extensiones interesantes",
        "severity": "high",
        "params": set(),
        "ext_rx": _EXT_RX,
    },
    "xss": {
        "label": "Cross-site scripting (XSS)",
        "severity": "medium",
        "params": {"q", "s", "search", "query", "keyword", "lang", "redirect", "callback",
                   "error", "cat", "msg", "file", "path", "val", "url", "action", "key", "text"},
    },
    "redirect": {
        "label": "Redireccion abierta",
        "severity": "medium",
        "params": {"url", "redirect", "redirect_uri", "next", "return", "return_url", "returnto",
                   "rurl", "redir", "return_path", "go", "out", "view", "loginurl", "link",
                   "outurl", "continue", "dest", "destination", "target", "to"},
        "value_rx": _REDIRECT_RX,
        "path_values": False,
    },
    "idor": {
        "label": "IDOR (referencia directa a objetos)",
        "severity": "medium",
        "params": {"user", "account", "uid", "pid", "doc", "key", "no", "number", "order_id"},
        "path_rx": _IDOR_RX,
    },
    "debug_logic": {
        "label": "Logica de depuracion / flags",
        "severity": "medium",
        "params": {"debug", "test", "edit", "admin", "root", "dev", "localhost", "mode",
                   "debug_mode", "verbose", "trace"},
        "value_rx": _DEBUG_RX,
    },
    "interestingparams": {
        "label": "Parametros interesantes",
        "severity": "low",
        "params": {"access", "admin", "debug", "test", "role", "username", "user", "pwd",
                   "password", "token", "key", "secret", "api_key", "apikey", "auth", "session",
                   "callback", "redirect", "file", "path", "id"},
    },
}

_INTERESTING_SUB_LABELS = {
    "admin", "dev", "stage", "staging", "test", "qa", "uat", "api", "beta", "jenkins", "grafana",
    "kibana", "gitlab", "jira", "internal", "vpn", "ftp", "portal", "db", "database", "mail",
    "webmail", "ns1", "old", "backup", "demo", "preprod", "prod", "stg", "sbx", "sandbox",
    "sonar", "npm", "registry", "docker", "k8s", "kubernetes", "ldap", "smb", "rdp", "ssh",
    "monitor", "prometheus", "redis", "elastic", "mongo", "mysql", "postgres", "swagger",
    "graphql", "phpmyadmin", "adminer", "actuator", "noc", "soc", "backup", "pre", "int",
}


# --------------------------------------------------------------------------- #
#  C. Puertos web no estandar (reNgine UNCOMMON_WEB_PORTS, fuente reconFTW)    #
# --------------------------------------------------------------------------- #
_UNCOMMON_WEB_PORTS: set[int] = {
    81, 300, 591, 593, 832, 981, 1010, 1311, 1099, 2082, 2095, 2096, 2480, 3000, 3128, 3333,
    4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5601, 5800, 6543, 7000, 7001,
    7396, 7474, 8000, 8001, 8008, 8014, 8042, 8060, 8069, 8080, 8081, 8083, 8088, 8090, 8091,
    8095, 8118, 8123, 8172, 8181, 8222, 8243, 8280, 8281, 8333, 8337, 8443, 8500, 8834, 8880,
    8888, 8983, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9502, 9800, 9981, 10000,
    10250, 11371, 12443, 15672, 16080, 17778, 18091, 18092, 20720, 32000, 55440, 55672,
}

_PORT_LABELS: dict[int, str] = {
    3000: "Node/Grafana", 5000: "UPnP/Flask", 5601: "Kibana", 7001: "WebLogic", 7474: "Neo4j",
    8000: "HTTP-alt", 8080: "HTTP-alt", 8081: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt",
    9000: "HTTP-alt", 9090: "Prometheus", 9200: "Elasticsearch", 9443: "HTTPS-alt",
    10250: "Kubelet", 15672: "RabbitMQ mgmt",
}

# --------------------------------------------------------------------------- #
#  B. Palabras clave "interesantes" (reNgine InterestingLookupModel)           #
# --------------------------------------------------------------------------- #
RENGINE_DEFAULT_KEYWORDS: tuple[str, ...] = ("admin", "ftp", "cpanel", "dashboard")

EXTENDED_KEYWORDS: tuple[str, ...] = (
    "login", "signin", "portal", "api", "graphql", "swagger", "console", "manager", "jenkins",
    "gitlab", "grafana", "kibana", "phpmyadmin", "adminer", "actuator", "backup", "database",
    "internal", "vpn", "webmail", "old", "staging", "preprod", "uat", "qa", "test", "dev",
    "beta", "status", "health", "metrics", "debug", "token", "apikey", "secret", "config",
    "mail", ".env", ".git",
)

_KEYWORD_TOKENS = tuple(
    dict.fromkeys(k.lower().strip(".") for k in RENGINE_DEFAULT_KEYWORDS + EXTENDED_KEYWORDS if k)
)


# --------------------------------------------------------------------------- #
#  Colectores de datos del proveedor                                          #
# --------------------------------------------------------------------------- #
def _collect_urls(p: dict[str, Any]) -> list[str]:
    out: list[str] = []

    fr = p.get("finalrecon") or {}
    wb = fr.get("wayback") or {}
    for key in ("js_files", "api_endpoints", "juicy_params"):
        for v in (wb.get(key) or []):
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, dict):
                out.append(str(v.get("url") or v.get("endpoint") or v.get("param") or ""))

    km = ((p.get("kumo") or {}).get("wayback") or {})
    for v in (km.get("urls") or []):
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            out.append(str(v.get("url") or ""))

    for it in (p.get("public_paths") or []):
        if isinstance(it, dict):
            out.append(str(it.get("url") or it.get("path") or ""))
    for it in (p.get("api_endpoints") or []):
        if isinstance(it, dict):
            out.append(str(it.get("url") or it.get("path") or ""))

    seen: set[str] = set()
    res: list[str] = []
    for u in out:
        u = u.strip()
        if not u or u in seen:
            continue
        seen.add(u)
        res.append(u)
    return res


def _collect_hosts(p: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for s in (p.get("subdomains") or []):
        if isinstance(s, str):
            out.append(s)
        elif isinstance(s, dict):
            out.append(str(s.get("host") or s.get("fqdn") or s.get("subdomain") or ""))
    for s in (p.get("crt_subdomains") or []):
        if isinstance(s, str):
            out.append(s)
    seen: set[str] = set()
    res: list[str] = []
    for h in out:
        h = h.strip().lower()
        if not h or h in seen:
            continue
        seen.add(h)
        res.append(h)
    return res


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if t}


def _url_parts(u: str) -> tuple[str, list[tuple[str, str]]]:
    raw = u if "://" in u else "http://" + u.lstrip("/")
    sp = urlsplit(raw)
    path = unquote(sp.path or "").lower()
    params = [(k.lower(), unquote(v).lower()) for k, v in parse_qsl(sp.query, keep_blank_values=True)]
    return path, params


def _match_url(u: str, spec: dict[str, Any]) -> str | None:
    path, params = _url_parts(u)
    if spec.get("ext_rx") and spec["ext_rx"].search(path):
        return "extension " + path.rsplit("/", 1)[-1][:24]
    if spec.get("path_rx") and spec["path_rx"].search(path):
        return "ruta " + path[:60]
    hits: list[str] = []
    names = {k for k, _ in params}
    for k in sorted(names & spec.get("params", set())):
        hits.append(k)
    valrx = spec.get("value_rx")
    if valrx:
        if spec.get("path_values", True):
            pm = valrx.search(path)
            if pm:
                return "ruta " + pm.group(0)[:40]
        for k, v in params:
            if v and valrx.search(v):
                hits.append(f"{k}=...")
    if hits:
        return "params: " + ",".join(dict.fromkeys(hits))[:80]
    return None


# --------------------------------------------------------------------------- #
#  A. GF patterns - build / render                                            #
# --------------------------------------------------------------------------- #
def build_gf(provider: dict[str, Any]) -> dict[str, Any]:
    urls = _collect_urls(provider)
    hosts = _collect_hosts(provider)
    buckets: list[dict[str, Any]] = []
    by_sev: dict[str, int] = {}
    total = 0

    for name, spec in _GF_PATTERNS.items():
        samples: list[dict[str, str]] = []
        for u in urls:
            reason = _match_url(u, spec)
            if reason:
                samples.append({"url": u[:200], "reason": reason})
        if not samples:
            continue
        sev = spec["severity"]
        buckets.append({
            "pattern": name,
            "label": spec["label"],
            "severity": sev,
            "count": len(samples),
            "samples": samples[:6],
        })
        by_sev[sev] = by_sev.get(sev, 0) + len(samples)
        total += len(samples)

    sub_samples: list[dict[str, str]] = []
    for h in hosts:
        label = h.split(".")[0]
        if label in _INTERESTING_SUB_LABELS:
            sub_samples.append({"url": h, "reason": "subdominio " + label})
    if sub_samples:
        buckets.append({
            "pattern": "interestingsubs",
            "label": "Subdominios interesantes",
            "severity": "medium",
            "count": len(sub_samples),
            "samples": sub_samples[:6],
        })
        by_sev["medium"] = by_sev.get("medium", 0) + len(sub_samples)
        total += len(sub_samples)

    buckets.sort(key=lambda b: (-_SEV_ORDER.get(b["severity"], 0), -b["count"], b["pattern"]))
    return {
        "buckets": buckets,
        "total_candidates": total,
        "total_urls": len(urls),
        "by_severity": by_sev,
        "note": "Candidatos heuristicos por patrones tipo GF (reNgine DEFAULT_GF_PATTERNS); no implican explotabilidad.",
    }


def render_gf_block(domain: str, provider: dict[str, Any]) -> str:
    data = provider.get("gf") or {}
    buckets = data.get("buckets") or []
    if not buckets:
        return ""
    sev_chips = " &middot; ".join(
        f"<b style='color:{_SEV_COLOR.get(s, '#607D8B')};'>{s}={n}</b>"
        for s, n in sorted(data.get("by_severity", {}).items(), key=lambda kv: -_SEV_ORDER.get(kv[0], 0))
    )
    rows = []
    for b in buckets:
        col = _SEV_COLOR.get(b["severity"], "#607D8B")
        samp = b["samples"][0]
        rows.append(
            "<tr>"
            f"<td style='font-family:monospace;font-size:8px;'>{_esc(b['pattern'])}</td>"
            f"<td style='font-size:8px;'>{_esc(b['label'])}</td>"
            f"<td style='color:{col};font-weight:bold;font-size:8px;text-transform:uppercase;'>{_esc(b['severity'])}</td>"
            f"<td style='text-align:right;font-family:monospace;font-size:8px;'>{b['count']}</td>"
            f"<td style='font-family:monospace;font-size:8px;'>{_esc(samp['url'][:90])}<br><span style='color:#607D8B;'>{_esc(samp['reason'])}</span></td>"
            "</tr>"
        )
    return (
        '<h4 style="margin:6px 0 3px;">Candidatos de vulnerabilidad (patrones GF, reNgine)</h4>'
        f'<p style="font-size:8.5px;margin:2px 0;">URLs analizadas: <b>{data.get("total_urls", 0)}</b> '
        f'&middot; candidatos: <b>{data.get("total_candidates", 0)}</b> &middot; {sev_chips}</p>'
        '<table style="width:100%;border-collapse:collapse;" border="1" cellspacing="0" cellpadding="3">'
        '<thead><tr style="background:#EEEEEE;">'
        '<th style="font-size:8px;text-align:left;">Patron</th>'
        '<th style="font-size:8px;text-align:left;">Tipo</th>'
        '<th style="font-size:8px;text-align:left;">Sev</th>'
        '<th style="font-size:8px;text-align:right;">N</th>'
        '<th style="font-size:8px;text-align:left;">Muestra</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
        f'<p style="font-size:8px;margin:2px 0;color:#607D8B;">{_esc(data.get("note", ""))}</p>'
    )


# --------------------------------------------------------------------------- #
#  B. Palabras clave interesantes - build / render                            #
# --------------------------------------------------------------------------- #
def build_interesting(provider: dict[str, Any]) -> dict[str, Any]:
    items: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    matched_kw: dict[str, int] = {}

    def _add(kw: str, field: str, value: str) -> None:
        key = (field, value)
        if key in seen:
            return
        seen.add(key)
        items.append({"keyword": kw, "field": field, "value": value[:200]})
        matched_kw[kw] = matched_kw.get(kw, 0) + 1

    for h in _collect_hosts(provider):
        toks = _tokens(h)
        for kw in _KEYWORD_TOKENS:
            if kw in toks:
                _add(kw, "subdominio", h)
                break

    for u in _collect_urls(provider):
        toks = _tokens(u)
        for kw in _KEYWORD_TOKENS:
            if kw in toks:
                _add(kw, "url", u)
                break

    return {
        "items": items[:40],
        "count": len(items),
        "keywords_matched": matched_kw,
        "total_keywords": len(_KEYWORD_TOKENS),
        "note": "Coincidencia por termino (reNgine InterestingLookupModel); terminos genericos pueden dar ruido.",
    }


def render_interesting_block(domain: str, provider: dict[str, Any]) -> str:
    data = provider.get("interesting") or {}
    items = data.get("items") or []
    if not items:
        return ""
    kws = ", ".join(
        f"{_esc(k)}={n}" for k, n in
        sorted(data.get("keywords_matched", {}).items(), key=lambda kv: -kv[1])[:10]
    )
    rows = []
    for it in items:
        rows.append(
            "<tr>"
            f"<td style='font-size:8px;'>{_esc(it['keyword'])}</td>"
            f"<td style='font-size:8px;'>{_esc(it['field'])}</td>"
            f"<td style='font-family:monospace;font-size:8px;'>{_esc(it['value'][:110])}</td>"
            "</tr>"
        )
    return (
        '<h4 style="margin:6px 0 3px;">Activos de interes (palabras clave, reNgine)</h4>'
        f'<p style="font-size:8.5px;margin:2px 0;">Coincidencias: <b>{data.get("count", 0)}</b> '
        f'&middot; terminos: {kws}</p>'
        '<table style="width:100%;border-collapse:collapse;" border="1" cellspacing="0" cellpadding="3">'
        '<thead><tr style="background:#EEEEEE;">'
        '<th style="font-size:8px;text-align:left;">Termino</th>'
        '<th style="font-size:8px;text-align:left;">Campo</th>'
        '<th style="font-size:8px;text-align:left;">Valor</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
        f'<p style="font-size:8px;margin:2px 0;color:#607D8B;">{_esc(data.get("note", ""))}</p>'
    )


# --------------------------------------------------------------------------- #
#  C. Puertos web no estandar - build / render                                #
# --------------------------------------------------------------------------- #
def build_webports(provider: dict[str, Any]) -> dict[str, Any]:
    ports: set[int] = set()
    for it in (provider.get("open_ports") or []):
        if isinstance(it, dict):
            if it.get("open") is False:
                continue
            try:
                ports.add(int(it.get("port")))
            except (TypeError, ValueError):
                pass
        elif isinstance(it, (int, str)):
            try:
                ports.add(int(it))
            except (TypeError, ValueError):
                pass

    found = [
        {"port": port, "label": _PORT_LABELS.get(port, "servicio web no estandar")}
        for port in sorted(ports)
        if port in _UNCOMMON_WEB_PORTS
    ]
    return {
        "ports": found,
        "count": len(found),
        "note": "Puertos de servicio web no estandar expuestos (reNgine UNCOMMON_WEB_PORTS, fuente reconFTW).",
    }


def render_webports_block(domain: str, provider: dict[str, Any]) -> str:
    data = provider.get("webports") or {}
    ports = data.get("ports") or []
    if not ports:
        return ""
    chips = " ".join(
        f"<b style='font-family:monospace;'>{p['port']}</b> <span style='color:#607D8B;'>({_esc(p['label'])})</span>"
        for p in ports
    )
    return (
        '<h4 style="margin:6px 0 3px;">Servicios web en puertos no estandar (reNgine)</h4>'
        f'<p style="font-size:8.5px;margin:2px 0;">Expuestos: <b>{data.get("count", 0)}</b> &middot; {chips}</p>'
        f'<p style="font-size:8px;margin:2px 0;color:#607D8B;">{_esc(data.get("note", ""))}</p>'
    )


# --------------------------------------------------------------------------- #
#  Agregador                                                                  #
# --------------------------------------------------------------------------- #
def build_rengine(provider: dict[str, Any]) -> dict[str, Any]:
    return {
        "gf": build_gf(provider),
        "interesting": build_interesting(provider),
        "webports": build_webports(provider),
    }
