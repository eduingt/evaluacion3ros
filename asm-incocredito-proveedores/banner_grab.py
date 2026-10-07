from __future__ import annotations

import socket
import ssl
import time
from typing import Any

BANNER_TIMEOUT = 4.0
HTTP_REQUEST = b"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: ASM-Incocredito-Proveedores/1.0\r\nAccept: */*\r\n\r\n"

PROTO_SIGNATURES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    465: "SMTPS", 587: "SMTP-submit", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP",
    8443: "HTTPS", 27017: "MongoDB",
}

HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8888, 9090, 9443, 4443, 6443, 7443}


def _recv_banner(sock: socket.socket, max_bytes: int = 4096) -> str:
    sock.settimeout(BANNER_TIMEOUT)
    data = b""
    try:
        while len(data) < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 4096:
                break
    except socket.timeout:
        pass
    except Exception:
        pass
    text = data.decode("utf-8", errors="replace").strip()
    return text[:2000]


def _parse_http_banner(banner: str) -> dict[str, Any]:
    result: dict[str, Any] = {"protocol": "HTTP", "banner": banner[:500]}
    for line in banner.split("\r\n"):
        lower = line.lower()
        if lower.startswith("server:"):
            result["product"] = line.split(":", 1)[1].strip()
        elif lower.startswith("x-powered-by:"):
            result["x_powered_by"] = line.split(":", 1)[1].strip()
        elif lower.startswith("x-aspnet-version:"):
            result["aspnet_version"] = line.split(":", 1)[1].strip()
    if banner.startswith("HTTP/"):
        status_line = banner.split("\r\n")[0]
        result["status_line"] = status_line
    if not result.get("product"):
        result["product"] = "unknown"
    return result


def _parse_ssh_banner(banner: str) -> dict[str, Any]:
    result: dict[str, Any] = {"protocol": "SSH", "banner": banner[:500]}
    if banner.startswith("SSH-"):
        parts = banner.split("-", 2)
        if len(parts) >= 3:
            result["product"] = parts[1]
            result["version"] = parts[2].split()[0] if parts[2] else ""
        else:
            result["product"] = banner
    else:
        result["product"] = banner
    return result


def _parse_ftp_banner(banner: str) -> dict[str, Any]:
    result: dict[str, Any] = {"protocol": "FTP", "banner": banner[:500]}
    lines = banner.split("\r\n")
    for line in lines:
        if "220" in line and "FTP" in line.upper():
            result["product"] = line[line.index("FTP"):].strip() if "FTP" in line.upper() else line.strip()
            break
    if not result.get("product"):
        result["product"] = lines[0][:200] if lines else "unknown"
    return result


def _parse_smtp_banner(banner: str) -> dict[str, Any]:
    result: dict[str, Any] = {"protocol": "SMTP", "banner": banner[:500]}
    lines = banner.split("\r\n")
    for line in lines:
        if "220" in line:
            result["product"] = line[3:].strip() if len(line) > 3 else line
            break
    if not result.get("product"):
        result["product"] = lines[0][:200] if lines else "unknown"
    return result


def _parse_generic_banner(banner: str, proto: str) -> dict[str, Any]:
    return {"protocol": proto, "banner": banner[:500], "product": banner[:200] if banner else "unknown"}


PARSERS: dict[str, Any] = {
    "HTTP": _parse_http_banner,
    "HTTPS": _parse_http_banner,
    "SSH": _parse_ssh_banner,
    "FTP": _parse_ftp_banner,
    "SMTP": _parse_smtp_banner,
    "SMTP-submit": _parse_smtp_banner,
    "SMTPS": _parse_smtp_banner,
}


def _grab_port(host: str, port: int, proto: str | None = None) -> dict[str, Any] | None:
    if proto is None:
        proto = PROTO_SIGNATURES.get(port, "unknown")
    is_ssl = proto in ("HTTPS", "SMTPS", "IMAPS", "POP3S", 443, 8443, 9443, 4443, 6443, 7443)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(BANNER_TIMEOUT)
        sock.connect((host, port))

        if is_ssl:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except Exception as exc:
                sock.close()
                return {"port": port, "protocol": proto, "error": f"SSL: {exc}"}

        if proto in ("HTTP", "HTTPS") or port in HTTP_PORTS:
            req = HTTP_REQUEST.replace(b"{host}", host.encode())
            sock.sendall(req)
            banner = _recv_banner(sock)
            result = _parse_http_banner(banner)
        elif proto == "SSH":
            banner = _recv_banner(sock)
            result = _parse_ssh_banner(banner)
        elif proto == "FTP":
            banner = _recv_banner(sock)
            result = _parse_ftp_banner(banner)
        elif proto in ("SMTP", "SMTP-submit"):
            banner = _recv_banner(sock)
            result = _parse_smtp_banner(banner)
        else:
            banner = _recv_banner(sock)
            if "SSH-" in banner[:10]:
                result = _parse_ssh_banner(banner)
            elif banner.startswith("220"):
                result = _parse_smtp_banner(banner)
            else:
                result = _parse_generic_banner(banner, proto)

        result["port"] = port
        sock.close()
        return result

    except socket.timeout:
        return {"port": port, "protocol": proto, "error": "timeout"}
    except ConnectionRefusedError:
        return {"port": port, "protocol": proto, "error": "refused"}
    except Exception as exc:
        return {"port": port, "protocol": proto, "error": str(exc)[:200]}


def grab_banners(host: str, open_ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for entry in open_ports:
        port = entry.get("port", 0)
        proto = entry.get("service", PROTO_SIGNATURES.get(port))
        banner = _grab_port(host, port, proto)
        if banner:
            results.append(banner)
        time.sleep(0.1)
    return results
