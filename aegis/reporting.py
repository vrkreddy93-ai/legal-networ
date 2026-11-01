"""Stable JSON and Markdown reports suitable for review and evidence storage."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analysis import risk_score
from .models import ScanResult


def build_report(result: ScanResult, authorization_reference: str | None) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "authorization": {"declared": True, "reference": authorization_reference or "not provided"},
        "scope": {"single_target": result.target.label, "non_intrusive": True},
        "risk_score": risk_score(result.findings),
        "scan": result.to_dict(),
        "findings": [finding.to_dict() for finding in result.findings],
        "limitations": [
            "This report records low-impact observations, not proof that a system is secure or vulnerable.",
            "No exploit, credential, load, or vulnerability-database checks were performed.",
            "DDoS posture is not verified by traffic generation.",
            "Only the first resolved address was checked; other addresses for the hostname may have different exposure.",
            "Service names are inferred from port numbers; service identity and access controls were not verified.",
            "HTTP findings reflect at most one HEAD request to the root path and may differ on other routes or methods.",
            "The 0–100 priority score is a local heuristic, not CVSS, exploitability, likelihood, or a security grade.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    scan = report["scan"]
    lines = [
        "# Aegis Guard security posture report", "",
        f"- **Target:** `{report['scope']['single_target']}`",
        f"- **Generated (UTC):** {report['generated_at']}",
        f"- **Authorization reference:** {report['authorization']['reference']}",
        f"- **Heuristic priority score:** {report['risk_score']}/100", "",
        "The score is a local prioritization aid, not CVSS, likelihood, or proof of security.", "",
        "## Scope and observations", "",
    ]
    if scan.get("resolved_addresses"):
        lines.append(f"- **Resolved addresses:** {', '.join(f'`{address}`' for address in scan['resolved_addresses'])}")
        lines.append(f"- **Address checked:** `{scan['resolved_addresses'][0]}`")
    if scan.get("notes"):
        lines.extend(["", *(f"- {note}" for note in scan["notes"])])
    lines.extend(["", "## TCP exposure", ""])
    if scan["open_ports"]:
        lines.extend(["| Port | Service | State |", "| --- | --- | --- |"])
        lines.extend(f"| {item['port']} | {item['service']} | {item['state']} |" for item in scan["open_ports"])
    else:
        lines.append("No selected TCP port accepted a connection.")
    lines.extend(["", "## TLS observations", ""])
    if scan.get("tls"):
        for item in scan["tls"]:
            status = "verified" if item.get("verified") else "not verified"
            details = f"; protocol {item['protocol']}" if item.get("protocol") else ""
            if item.get("days_until_expiry") is not None:
                details += f"; certificate expires in {item['days_until_expiry']} day(s)"
            if item.get("error"):
                details += f"; {item['error']}"
            lines.append(f"- Port {item['port']}: {status}{details}.")
    else:
        lines.append("No TLS handshake was attempted on the selected target and observed ports.")
    lines.extend(["", "## HTTP observations", ""])
    if scan.get("http"):
        for item in scan["http"]:
            status = f"HTTP {item['status']}" if item.get("status") is not None else "unreachable"
            lines.append(f"- {item.get('scheme', 'HTTP').upper()} port {item['port']}: {status}.")
    else:
        lines.append("No HTTP HEAD request was made.")
    lines.extend(["", "## Findings", ""])
    if report["findings"]:
        for finding in report["findings"]:
            lines.extend([
                f"### {finding['severity'].upper()} — {finding['title']}", "",
                f"**Category / confidence:** {finding['category']} / {finding.get('confidence', 'unspecified')}", "",
                f"**Evidence:** {finding['evidence']}", "",
                f"**Recommendation:** {finding['recommendation']}", "",
            ])
    else:
        lines.append("No findings were generated from the selected low-impact checks.")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def write_reports(report: dict[str, Any], destination: Path, output_format: str) -> list[Path]:
    """Write selected formats for normal command-line use."""
    destination.mkdir(parents=True, exist_ok=True)
    safe_name = report["scope"]["single_target"].replace(":", "_").replace("/", "_")
    paths: list[Path] = []
    if output_format in {"json", "both"}:
        json_path = destination / f"{safe_name}-aegis-report.json"
        json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        paths.append(json_path)
    if output_format in {"markdown", "both"}:
        markdown_path = destination / f"{safe_name}-aegis-report.md"
        markdown_path.write_text(render_markdown(report), encoding="utf-8")
        paths.append(markdown_path)
    return paths
