"""Input validation that intentionally keeps every scan to one host."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .models import Target


class TargetValidationError(ValueError):
    """Raised when scan input could broaden or obscure the selected scope."""


_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)$")


def parse_target(value: str) -> Target:
    """Return a normalized single-host target, rejecting broad target syntaxes."""
    raw = value.strip()
    if not raw:
        raise TargetValidationError("A target hostname or IP address is required.")
    if any(marker in raw for marker in ("*", ",", "..", "\\", "@")):
        raise TargetValidationError("Only one hostname or IP address is allowed; ranges, CIDRs, paths, and credentials are not accepted.")

    scheme: str | None = None
    host: str
    port: int | None = None
    if "://" in raw:
        try:
            parsed = urlsplit(raw)
            parsed_port = parsed.port
            parsed_hostname = parsed.hostname
        except ValueError as exc:
            raise TargetValidationError("The URL has an invalid port or host format.") from exc
        if parsed.scheme not in {"http", "https"}:
            raise TargetValidationError("Only http and https URLs are accepted.")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise TargetValidationError("Provide only a host (optionally with scheme and port), without a path, query, or credentials.")
        if not parsed_hostname:
            raise TargetValidationError("The URL does not contain a hostname.")
        scheme, host, port = parsed.scheme, parsed_hostname, parsed_port
    else:
        if "/" in raw:
            raise TargetValidationError("Provide only one hostname or IP address, without a path.")
        host = raw.strip("[]")

    try:
        address = ipaddress.ip_address(host)
        if address.is_unspecified or address.is_multicast or address.is_link_local:
            raise TargetValidationError("Unspecified, multicast, and link-local addresses are not valid scan targets.")
    except ValueError:
        if not _HOSTNAME.fullmatch(host):
            raise TargetValidationError("Target must be a valid hostname, IPv4 address, or IPv6 address.")

    return Target(host=host.lower(), port=port, scheme=scheme)


def parse_ports(value: str) -> list[int]:
    """Validate a small, explicit list of TCP ports for low-impact checking."""
    try:
        ports = sorted({int(item.strip()) for item in value.split(",") if item.strip()})
    except ValueError as exc:
        raise TargetValidationError("Ports must be a comma-separated list of numbers.") from exc
    if not ports:
        raise TargetValidationError("Specify at least one TCP port.")
    if len(ports) > 64:
        raise TargetValidationError("At most 64 ports can be checked in one run.")
    if any(port < 1 or port > 65535 for port in ports):
        raise TargetValidationError("Ports must be between 1 and 65535.")
    return ports


