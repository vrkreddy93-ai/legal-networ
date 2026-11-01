"""Data types shared by the scanner, analysis, and report writer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Target:
    host: str
    port: int | None = None
    scheme: str | None = None

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}" if self.port is not None else self.host


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    evidence: str
    recommendation: str
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: Target
    resolved_addresses: list[str] = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    tls: list[dict[str, Any]] = field(default_factory=list)
    http: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": asdict(self.target),
            "resolved_addresses": self.resolved_addresses,
            "open_ports": self.open_ports,
            "tls": self.tls,
            "http": self.http,
            "findings": [finding.to_dict() for finding in self.findings],
            "notes": self.notes,
        }
