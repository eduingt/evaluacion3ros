from __future__ import annotations

import json
import re
from typing import Any

import requests

TIMEOUT = 10
USER_AGENT = "ASM-Incocredito-Proveedores/1.0 (+research)"

API_PATHS: tuple[dict[str, Any], ...] = (
    # === RESTful common ===
    {"path": "/api", "methods": ["GET"], "desc": "REST API root"},
    {"path": "/api/v1", "methods": ["GET"], "desc": "API v1 root"},
    {"path": "/api/v2", "methods": ["GET"], "desc": "API v2 root"},
    {"path": "/api/v3", "methods": ["GET"], "desc": "API v3 root"},
    {"path": "/api/users", "methods": ["GET"], "desc": "API users endpoint"},
    {"path": "/api/login", "methods": ["POST"], "desc": "API login"},
    {"path": "/api/auth", "methods": ["GET", "POST"], "desc": "API auth"},
    {"path": "/api/token", "methods": ["POST"], "desc": "API token"},
    {"path": "/api/refresh", "methods": ["POST"], "desc": "API refresh token"},
    {"path": "/api/logout", "methods": ["POST"], "desc": "API logout"},
    {"path": "/api/register", "methods": ["POST"], "desc": "API register"},
    {"path": "/api/status", "methods": ["GET"], "desc": "API status"},
    {"path": "/api/ping", "methods": ["GET"], "desc": "API ping"},
    {"path": "/api/version", "methods": ["GET"], "desc": "API version"},
    {"path": "/api/config", "methods": ["GET"], "desc": "API config"},
    {"path": "/api/health", "methods": ["GET"], "desc": "API health"},
    {"path": "/api/metrics", "methods": ["GET"], "desc": "API metrics"},
    {"path": "/api/export", "methods": ["GET"], "desc": "API export"},
    {"path": "/api/upload", "methods": ["POST"], "desc": "API upload"},
    {"path": "/api/download", "methods": ["GET"], "desc": "API download"},
    {"path": "/api/search", "methods": ["GET", "POST"], "desc": "API search"},
    {"path": "/api/query", "methods": ["POST"], "desc": "API query"},
    {"path": "/api/graphql", "methods": ["POST"], "desc": "API GraphQL"},
    # === GraphQL ===
    {"path": "/graphql", "methods": ["POST", "GET"], "desc": "GraphQL endpoint"},
    {"path": "/graphiql", "methods": ["GET"], "desc": "GraphQL IDE"},
    {"path": "/v1/graphql", "methods": ["POST", "GET"], "desc": "GraphQL v1"},
    {"path": "/graph", "methods": ["POST", "GET"], "desc": "GraphQL alternative"},
    # === Auth / OAuth ===
    {"path": "/auth", "methods": ["GET"], "desc": "Auth root"},
    {"path": "/auth/login", "methods": ["POST"], "desc": "Auth login"},
    {"path": "/auth/logout", "methods": ["POST"], "desc": "Auth logout"},
    {"path": "/auth/register", "methods": ["POST"], "desc": "Auth register"},
    {"path": "/auth/validate", "methods": ["POST"], "desc": "Auth validate"},
    {"path": "/oauth", "methods": ["GET"], "desc": "OAuth root"},
    {"path": "/oauth/authorize", "methods": ["GET"], "desc": "OAuth authorize"},
    {"path": "/oauth/token", "methods": ["POST"], "desc": "OAuth token"},
    {"path": "/oauth/revoke", "methods": ["POST"], "desc": "OAuth revoke"},
    {"path": "/.well-known/openid-configuration", "methods": ["GET"], "desc": "OIDC discovery"},
    {"path": "/.well-known/oauth-authorization-server", "methods": ["GET"], "desc": "OAuth server metadata"},
    {"path": "/sso", "methods": ["GET"], "desc": "SSO root"},
    {"path": "/saml", "methods": ["GET", "POST"], "desc": "SAML endpoint"},
    # === Admin / Management ===
    {"path": "/admin", "methods": ["GET"], "desc": "Admin panel"},
    {"path": "/admin/api", "methods": ["GET"], "desc": "Admin API"},
    {"path": "/admin/login", "methods": ["POST"], "desc": "Admin login"},
    {"path": "/admin/config", "methods": ["GET"], "desc": "Admin config"},
    {"path": "/admin/users", "methods": ["GET"], "desc": "Admin users"},
    {"path": "/admin/logs", "methods": ["GET"], "desc": "Admin logs"},
    {"path": "/admin/panel", "methods": ["GET"], "desc": "Admin panel"},
    {"path": "/admin/dashboard", "methods": ["GET"], "desc": "Admin dashboard"},
    {"path": "/admin/health", "methods": ["GET"], "desc": "Admin health"},
    {"path": "/management", "methods": ["GET"], "desc": "Management interface"},
    {"path": "/manage", "methods": ["GET"], "desc": "Manage interface"},
    {"path": "/console", "methods": ["GET"], "desc": "Console"},
    # === API Documentation ===
    {"path": "/docs", "methods": ["GET"], "desc": "API docs"},
    {"path": "/docs/api", "methods": ["GET"], "desc": "API docs"},
    {"path": "/swagger", "methods": ["GET"], "desc": "Swagger UI"},
    {"path": "/swagger.json", "methods": ["GET"], "desc": "Swagger spec"},
    {"path": "/swagger/v1/swagger.json", "methods": ["GET"], "desc": "Swagger v1 spec"},
    {"path": "/api-docs", "methods": ["GET"], "desc": "API docs"},
    {"path": "/v1/api-docs", "methods": ["GET"], "desc": "API docs v1"},
    {"path": "/v2/api-docs", "methods": ["GET"], "desc": "API docs v2"},
    {"path": "/v3/api-docs", "methods": ["GET"], "desc": "API docs v3"},
    {"path": "/openapi.json", "methods": ["GET"], "desc": "OpenAPI spec"},
    {"path": "/api/openapi.json", "methods": ["GET"], "desc": "API OpenAPI spec"},
    {"path": "/api/swagger.json", "methods": ["GET"], "desc": "API Swagger spec"},
    {"path": "/redoc", "methods": ["GET"], "desc": "ReDoc UI"},
    # === Health / Status ===
    {"path": "/health", "methods": ["GET"], "desc": "Health check"},
    {"path": "/healthz", "methods": ["GET"], "desc": "Health check"},
    {"path": "/readyz", "methods": ["GET"], "desc": "Readiness check"},
    {"path": "/livez", "methods": ["GET"], "desc": "Liveness check"},
    {"path": "/status", "methods": ["GET"], "desc": "Status page"},
    {"path": "/version", "methods": ["GET"], "desc": "Version info"},
    {"path": "/info", "methods": ["GET"], "desc": "Info endpoint"},
    {"path": "/ping", "methods": ["GET"], "desc": "Ping"},
    # === Actuator (Spring Boot) ===
    {"path": "/actuator", "methods": ["GET"], "desc": "Spring Actuator"},
    {"path": "/actuator/health", "methods": ["GET"], "desc": "Actuator health"},
    {"path": "/actuator/info", "methods": ["GET"], "desc": "Actuator info"},
    {"path": "/actuator/env", "methods": ["GET"], "desc": "Actuator env"},
    {"path": "/actuator/metrics", "methods": ["GET"], "desc": "Actuator metrics"},
    {"path": "/actuator/beans", "methods": ["GET"], "desc": "Actuator beans"},
    {"path": "/actuator/mappings", "methods": ["GET"], "desc": "Actuator mappings"},
    {"path": "/actuator/loggers", "methods": ["GET"], "desc": "Actuator loggers"},
    {"path": "/actuator/threaddump", "methods": ["GET"], "desc": "Actuator thread dump"},
    {"path": "/actuator/heapdump", "methods": ["GET"], "desc": "Actuator heap dump"},
    {"path": "/actuator/httptrace", "methods": ["GET"], "desc": "Actuator HTTP trace"},
    # === WebDAV / File access ===
    {"path": "/webdav", "methods": ["GET", "PROPFIND"], "desc": "WebDAV"},
    {"path": "/files", "methods": ["GET"], "desc": "File listing"},
    {"path": "/uploads", "methods": ["GET"], "desc": "Uploads"},
    {"path": "/backup", "methods": ["GET"], "desc": "Backup"},
    # === Common services ===
    {"path": "/ws", "methods": ["GET"], "desc": "WebSocket endpoint"},
    {"path": "/ws/v1", "methods": ["GET"], "desc": "WebSocket v1"},
    {"path": "/socket.io", "methods": ["GET"], "desc": "Socket.io"},
    {"path": "/cable", "methods": ["GET"], "desc": "ActionCable"},
    {"path": "/webhook", "methods": ["POST"], "desc": "Webhook receiver"},
    {"path": "/hooks", "methods": ["POST"], "desc": "Hooks receiver"},
    {"path": "/callback", "methods": ["POST"], "desc": "Callback"},
    {"path": "/notifications", "methods": ["GET", "POST"], "desc": "Notifications"},
    {"path": "/events", "methods": ["GET"], "desc": "Events"},
    {"path": "/integration", "methods": ["GET"], "desc": "Integration"},
    {"path": "/webhooks", "methods": ["POST"], "desc": "Webhooks"},
    {"path": "/cron", "methods": ["GET"], "desc": "Cron jobs"},
    {"path": "/scheduler", "methods": ["GET"], "desc": "Scheduler"},
    {"path": "/jobs", "methods": ["GET"], "desc": "Jobs"},
    {"path": "/queue", "methods": ["GET"], "desc": "Queue"},
    # === Debug / Dev ===
    {"path": "/debug", "methods": ["GET"], "desc": "Debug interface"},
    {"path": "/dev", "methods": ["GET"], "desc": "Dev interface"},
    {"path": "/test", "methods": ["GET"], "desc": "Test endpoint"},
    {"path": "/phpinfo.php", "methods": ["GET"], "desc": "PHP info"},
    {"path": "/info.php", "methods": ["GET"], "desc": "PHP info"},
    # === Common API patterns ===
    {"path": "/api/user", "methods": ["GET"], "desc": "API user profile"},
    {"path": "/api/profile", "methods": ["GET"], "desc": "API profile"},
    {"path": "/api/account", "methods": ["GET"], "desc": "API account"},
    {"path": "/api/settings", "methods": ["GET"], "desc": "API settings"},
    {"path": "/api/preferences", "methods": ["GET"], "desc": "API preferences"},
    {"path": "/api/notifications", "methods": ["GET"], "desc": "API notifications"},
    {"path": "/api/messages", "methods": ["GET"], "desc": "API messages"},
    {"path": "/api/products", "methods": ["GET"], "desc": "API products"},
    {"path": "/api/orders", "methods": ["GET"], "desc": "API orders"},
    {"path": "/api/invoices", "methods": ["GET"], "desc": "API invoices"},
    {"path": "/api/payments", "methods": ["GET"], "desc": "API payments"},
    {"path": "/api/reports", "methods": ["GET"], "desc": "API reports"},
)

_JSON_CONTENT_TYPES = re.compile(r"application/(json|.*\+json)")
_XML_CONTENT_TYPES = re.compile(r"application/(xml|.*\+xml)|text/xml")


def _is_json_response(resp: requests.Response) -> bool:
    ct = (resp.headers.get("Content-Type") or "").lower()
    return bool(_JSON_CONTENT_TYPES.search(ct))


def _is_xml_response(resp: requests.Response) -> bool:
    ct = (resp.headers.get("Content-Type") or "").lower()
    return bool(_XML_CONTENT_TYPES.search(ct))


def _is_html_response(resp: requests.Response) -> bool:
    ct = (resp.headers.get("Content-Type") or "").lower()
    return "text/html" in ct


def _classify_response(resp: requests.Response) -> str:
    sc = resp.status_code
    if sc == 200:
        return "open"
    if sc == 201:
        return "created"
    if sc in (204, 205):
        return "empty"
    if sc in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location", "")
        if "login" in location.lower() or "auth" in location.lower() or "signin" in location.lower():
            return "redirect_login"
        return "redirect"
    if sc == 304:
        return "not_modified"
    if sc == 400:
        return "bad_request"
    if sc == 401:
        return "auth_required"
    if sc == 403:
        return "forbidden"
    if sc == 404:
        return "not_found"
    if sc == 405:
        return "method_not_allowed"
    if sc == 406:
        return "not_acceptable"
    if sc == 409:
        return "conflict"
    if sc == 410:
        return "gone"
    if sc == 415:
        return "unsupported_media"
    if sc == 422:
        return "unprocessable"
    if sc == 429:
        return "rate_limited"
    if sc >= 500:
        return "server_error"
    return f"unknown_{sc}"


SHADOW_CLASSIFICATIONS = {
    "open": True,
    "created": True,
    "auth_required": True,
    "forbidden": True,
    "redirect_login": True,
    "empty": True,
    "bad_request": True,
    "unprocessable": True,
    "conflict": True,
}


def _is_shadow_endpoint(category: str) -> bool:
    return SHADOW_CLASSIFICATIONS.get(category, False)


def discover_api_endpoints(
    domain: str,
    https_ok: bool = True,
    timeout: int = TIMEOUT,
) -> list[dict[str, Any]]:
    scheme = "https" if https_ok else "http"
    base = f"{scheme}://{domain}"
    sess = requests.Session()
    sess.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json, */*"})

    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    for entry in API_PATHS:
        path = entry["path"]
        methods = entry["methods"]
        desc = entry.get("desc", "")

        for method in methods:
            key = f"{method}:{path}"
            if key in seen:
                continue
            seen.add(key)

            url = f"{base}{path}"
            result: dict[str, Any] = {
                "path": path,
                "method": method,
                "url": url,
                "description": desc,
                "status_code": None,
                "content_type": None,
                "category": None,
                "is_shadow": False,
                "body_preview": None,
                "error": None,
            }

            try:
                if method == "PROPFIND":
                    resp = sess.request("PROPFIND", url, timeout=timeout, allow_redirects=False)
                else:
                    resp = sess.request(method, url, timeout=timeout, allow_redirects=False)

                result["status_code"] = resp.status_code
                result["content_type"] = (resp.headers.get("Content-Type") or "").split(";")[0].strip()
                result["category"] = _classify_response(resp)
                result["is_shadow"] = _is_shadow_endpoint(result["category"])

                # Body preview for non-404 responses
                if resp.status_code != 404:
                    try:
                        body = resp.text[:500]
                        if _is_json_response(resp):
                            try:
                                parsed = json.loads(body)
                                result["body_preview"] = json.dumps(parsed, ensure_ascii=False)[:300]
                            except json.JSONDecodeError:
                                result["body_preview"] = body[:200]
                        else:
                            result["body_preview"] = re.sub(r"\s+", " ", body)[:200]
                    except Exception:
                        result["body_preview"] = None

                # Detect API framework from response headers
                server = resp.headers.get("Server", "")
                if server:
                    result["server"] = server

            except requests.exceptions.SSLError as e:
                result["error"] = f"SSL: {e}"[:200]
            except requests.exceptions.ConnectionError as e:
                result["error"] = f"Connection: {e}"[:200]
            except requests.exceptions.Timeout:
                result["error"] = "timeout"
            except requests.exceptions.RequestException as e:
                result["error"] = str(e)[:200]

            results.append(result)

    sess.close()
    return results
