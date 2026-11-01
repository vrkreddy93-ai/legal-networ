"""Low-impact network and web posture checks. No payloads or load generation."""

from __future__ import annotations

import http.client
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import Event
from typing import Any, Callable

from .models import Target


SERVICE_NAMES = {
    22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 3389: "rdp", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}
ProgressCallback = Callable[[str], None]


def resolve_host(host: str) -> list[str]:
    """Resolve a hostname once, returning unique IPv4/IPv6 addresses."""
    addresses = {info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    return sorted(addresses)


def _port_is_open(connect_host: str, port: int, timeout: float, cancel_event: Event | None = None) -> dict[str, Any] | None:
    if cancel_event is not None and cancel_event.is_set():
        return None
    try:
        with socket.create_connection((connect_host, port), timeout=timeout):
            return {"port": port, "service": SERVICE_NAMES.get(port, "unknown"), "state": "open"}
    except (OSError, TimeoutError):
        return None


def scan_tcp_ports(
    host: str,
    ports: list[int],
    timeout: float,
    *,
    cancel_event: Event | None = None,
    progress: ProgressCallback | None = None,
) -> list[dict[str, Any]]:
    """Attempt one TCP connection per selected port without sending data."""
    open_ports: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(8, len(ports))) as executor:
        futures = [executor.submit(_port_is_open, host, port, timeout, cancel_event) for port in ports]
        completed = 0
        for future in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                for pending in futures:
                    pending.cancel()
                break
            result = future.result()
            if result is not None:
                open_ports.append(result)
            completed += 1
            if progress:
                progress(f"Checking selected TCP ports ({completed}/{len(ports)})")
    return sorted(open_ports, key=lambda item: item["port"])


def inspect_tls(host: str, port: int, timeout: float, *, connect_host: str | None = None) -> dict[str, Any]:
    """Verify TLS against the target hostname while connecting to its pinned IP."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((connect_host or host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
                expires_at: str | None = None
                days_until_expiry: int | None = None
                if certificate.get("notAfter"):
                    expiry = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(certificate["notAfter"]), tz=timezone.utc
                    )
                    expires_at = expiry.isoformat()
                    days_until_expiry = max(0, int((expiry - datetime.now(timezone.utc)).total_seconds() // 86400))
                return {
                    "port": port,
                    "verified": True,
                    "protocol": tls_socket.version(),
                    "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                    "expires_at": expires_at,
                    "days_until_expiry": days_until_expiry,
                }
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return {"port": port, "verified": False, "error": str(exc)[:160]}


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, connect_host: str, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._connect_host = connect_host

    def connect(self) -> None:
        self.sock = socket.create_connection((self._connect_host, self.port), self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, connect_host: str, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._connect_host = connect_host

    def connect(self) -> None:
        raw_socket = socket.create_connection((self._connect_host, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _head_request(host: str, port: int, scheme: str, timeout: float, connect_host: str | None = None) -> dict[str, Any]:
    if connect_host:
        connection_class = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
        connection = connection_class(host, port, connect_host, timeout)
    else:
        connection_class = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        kwargs: dict[str, Any] = {"timeout": timeout}
        if scheme == "https":
            kwargs["context"] = ssl.create_default_context()
        connection = connection_class(host, port=port, **kwargs)
    try:
        connection.request("HEAD", "/", headers={"User-Agent": "Aegis-Guard/0.3 (authorized posture check)"})
        response = connection.getresponse()
        headers: dict[str, Any] = {}
        for key, value in response.getheaders():
            normalized_key = key.lower()
            if normalized_key == "set-cookie":
                headers.setdefault(normalized_key, []).append(value)
            elif normalized_key in headers:
                headers[normalized_key] = f"{headers[normalized_key]}, {value}"
            else:
                headers[normalized_key] = value
        # Do not read a response body. HEAD is the only request type sent.
        return {"scheme": scheme, "port": port, "reachable": True, "status": response.status, "headers": headers}
    except (OSError, http.client.HTTPException, ssl.SSLError, TimeoutError) as exc:
        return {"scheme": scheme, "port": port, "reachable": False, "error": str(exc)[:160], "headers": {}}
    finally:
        connection.close()


def inspect_http(
    target: Target,
    open_ports: list[dict[str, Any]],
    timeout: float,
    *,
    connect_host: str | None = None,
) -> list[dict[str, Any]]:
    """Make at most one HEAD request to an observed or explicitly selected web port."""
    open_port_numbers = {item["port"] for item in open_ports}
    candidates: list[tuple[str, int]] = []
    if target.scheme and target.port:
        candidates.append((target.scheme, target.port))
    elif target.scheme:
        candidates.append((target.scheme, 443 if target.scheme == "https" else 80))
    else:
        for scheme, port in (("https", 443), ("http", 80), ("https", 8443), ("http", 8080)):
            if port in open_port_numbers:
                candidates.append((scheme, port))
                break
    return [_head_request(target.host, port, scheme, timeout, connect_host) for scheme, port in candidates]
