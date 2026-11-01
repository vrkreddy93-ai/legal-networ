"""Command line entry point for Aegis Guard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from threading import Event
from typing import Callable

from .analysis import analyze, risk_score
from .models import ScanResult
from .reporting import build_report, write_reports
from .scanners import inspect_http, inspect_tls, resolve_host, scan_tcp_ports
from .target import TargetValidationError, parse_ports, parse_target


DEFAULT_PORTS = "22,80,443,445,3389,3306,5432,6379,8080,8443,27017"
ProgressCallback = Callable[[str], None]
ReportCallback = Callable[[dict], None]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Authorized, low-impact security posture scanner for one host.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan = subcommands.add_parser("scan", help="Perform safe posture checks for one authorized target.")
    scan.add_argument("--target", required=True, help="One hostname, IP address, or http(s) host URL. No paths, CIDRs, or ranges.")
    scan.add_argument("--authorized", action="store_true", help="Required declaration that you are authorized to assess this exact target.")
    scan.add_argument("--authorization-reference", help="Change ticket, asset ID, or written authorization reference recorded in the report.")
    scan.add_argument("--ports", default=DEFAULT_PORTS, help=f"Comma-separated TCP ports (default: {DEFAULT_PORTS}; maximum 64).")
    scan.add_argument("--timeout", type=float, default=1.5, help="Connect timeout in seconds (0.2–10; default: 1.5).")
    scan.add_argument("--output", type=Path, default=Path("reports"), help="Directory for reports (default: reports).")
    scan.add_argument("--format", choices=("json", "markdown", "both"), default="both", help="Report format (default: both).")
    scan.add_argument("--dry-run", action="store_true", help="Validate scope and show planned checks without network traffic.")
    serve = subcommands.add_parser("serve", help="Start the local Aegis Guard web dashboard.")
    serve.add_argument("--port", type=int, default=8765, help="Local dashboard port (1024–65535; default: 8765).")
    serve.add_argument("--no-browser", action="store_true", help="Start the dashboard without opening a browser window.")
    subcommands.add_parser("desktop", help="Open the native Aegis Guard desktop application.")
    return parser


def _write_failure_report(result: ScanResult, args: argparse.Namespace, on_report: ReportCallback | None = None) -> list[Path]:
    result.findings = analyze(result)
    report = build_report(result, args.authorization_reference)
    paths = write_reports(report, args.output, args.format)
    if on_report:
        on_report(report)
    return paths


def _run_scan(
    args: argparse.Namespace,
    *,
    progress: ProgressCallback | None = None,
    cancel_event: Event | None = None,
    on_report: ReportCallback | None = None,
) -> int:
    def stage(message: str) -> None:
        if progress:
            progress(message)

    def cancelled() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    stage("Validating authorization, target, ports, and timeout")
    if not args.authorized:
        print("Refusing to scan: pass --authorized only when you have permission for this exact target.", file=sys.stderr)
        return 2
    try:
        target = parse_target(args.target)
        ports = parse_ports(args.ports)
    except TargetValidationError as exc:
        print(f"Invalid target scope: {exc}", file=sys.stderr)
        return 2
    if target.port and target.port not in ports:
        if len(ports) >= 64:
            print("Invalid port scope: include the URL port in --ports when selecting 64 ports.", file=sys.stderr)
            return 2
        ports = sorted([*ports, target.port])
    if not 0.2 <= args.timeout <= 10:
        print("Invalid timeout: choose a value from 0.2 to 10 seconds.", file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"Authorization declared for: {target.label}")
        print(f"Planned non-intrusive checks: DNS resolution; one TCP connect per selected port ({', '.join(map(str, ports))}); TLS verification on observed HTTPS ports; at most one HTTP HEAD request.")
        print("No network traffic was sent because preview mode was selected.")
        return 0

    if cancelled():
        print("Scan cancelled before network checks began.")
        return 130
    print(f"Assessing authorized target: {target.label}")
    result = ScanResult(target=target)
    try:
        stage("Resolving target once and pinning the destination address")
        result.resolved_addresses = resolve_host(target.host)
    except OSError as exc:
        result.notes.append(f"DNS resolution failed: {str(exc)[:160]}")
        written = _write_failure_report(result, args, on_report)
        print("DNS resolution failed; report written to: " + ", ".join(str(path) for path in written))
        return 1
    if not result.resolved_addresses:
        result.notes.append("DNS resolution returned no addresses.")
        written = _write_failure_report(result, args, on_report)
        print("DNS resolution returned no addresses; report written to: " + ", ".join(str(path) for path in written))
        return 1

    pinned_address = result.resolved_addresses[0]
    result.notes.append(f"Network checks were pinned to the first resolved address: {pinned_address}.")
    print(f"Resolved addresses: {', '.join(result.resolved_addresses)}")
    print(f"Pinned network destination: {pinned_address}")
    stage(f"Checking selected TCP ports on pinned address {pinned_address}")
    result.open_ports = scan_tcp_ports(pinned_address, ports, args.timeout, cancel_event=cancel_event, progress=progress)
    if cancelled():
        print("Scan cancelled during TCP checks. No completion report was written.")
        return 130

    tls_ports = [item["port"] for item in result.open_ports if item["port"] in {443, 8443}]
    if target.scheme == "https" and target.port and target.port not in tls_ports:
        tls_ports.append(target.port)
    for index, port in enumerate(sorted(set(tls_ports)), start=1):
        if cancelled():
            print("Scan cancelled during TLS checks. No completion report was written.")
            return 130
        stage(f"Verifying TLS on port {port} ({index}/{len(set(tls_ports))})")
        result.tls.append(inspect_tls(target.host, port, args.timeout, connect_host=pinned_address))

    if cancelled():
        print("Scan cancelled before HTTP review. No completion report was written.")
        return 130
    stage("Reviewing HTTP security headers (at most one HEAD request)")
    result.http = inspect_http(target, result.open_ports, args.timeout, connect_host=pinned_address)
    if cancelled():
        print("Scan cancelled before report generation. No completion report was written.")
        return 130
    stage("Correlating observations and writing report")
    result.findings = analyze(result)
    report = build_report(result, args.authorization_reference)
    written = write_reports(report, args.output, args.format)
    if on_report:
        on_report(report)
    print(f"Completed low-impact posture checks. Heuristic priority score: {risk_score(result.findings)}/100 (not a probability or vulnerability count).")
    print("Report written to: " + ", ".join(str(path) for path in written))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "serve":
        if not 1024 <= args.port <= 65535:
            parser.error("Dashboard port must be between 1024 and 65535.")
        from .web import serve

        serve(port=args.port, open_browser=not args.no_browser)
        return 0
    if args.command == "desktop":
        from .desktop import run_desktop

        run_desktop()
        return 0
    parser.error("Unknown command")
    return 2
