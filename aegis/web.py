"""Local-only web dashboard for Aegis Guard."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import threading
import uuid
import webbrowser
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .cli import DEFAULT_PORTS, _run_scan
from .target import TargetValidationError, parse_ports, parse_target


ASSET_DIRECTORY = Path(__file__).with_name("web_assets")
MAX_REQUEST_BYTES = 16_384
JOB_ID_PATTERN = re.compile(r"^[a-f0-9]{24}$")


def _allowed_targets_from_environment() -> set[str]:
    raw = os.environ.get("AEGIS_ALLOWED_TARGETS", "").strip()
    allowed: set[str] = set()
    if not raw:
        return allowed
    for value in raw.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            allowed.add(parse_target(value).host)
        except TargetValidationError as exc:
            raise ValueError(f"Invalid host in AEGIS_ALLOWED_TARGETS: {value!r}: {exc}") from exc
    return allowed


def build_scan_args(payload: dict[str, Any], *, dry_run: bool, allowed_targets: set[str] | None = None) -> argparse.Namespace:
    """Validate all scope fields server-side before planning or scanning."""
    target_text = str(payload.get("target", "")).strip()
    ports_text = str(payload.get("ports", DEFAULT_PORTS)).strip()
    reference = str(payload.get("authorization_reference", "")).strip()
    try:
        timeout = float(payload.get("timeout", 1.5))
    except (TypeError, ValueError) as exc:
        raise ValueError("Timeout must be a number from 0.2 to 10 seconds.") from exc
    if not payload.get("authorized") is True:
        raise ValueError("Confirm that you own this host or have permission to assess it.")
    if len(target_text) > 512 or len(ports_text) > 512 or len(reference) > 512:
        raise ValueError("One or more values exceed the dashboard limits.")
    if not 0.2 <= timeout <= 10:
        raise ValueError("Timeout must be a number from 0.2 to 10 seconds.")
    output_format = str(payload.get("format", "both"))
    if output_format not in {"json", "markdown", "both"}:
        raise ValueError("Select JSON, Markdown, or both report formats.")
    try:
        target = parse_target(target_text)
        ports = parse_ports(ports_text)
    except TargetValidationError as exc:
        raise ValueError(str(exc)) from exc
    if target.port and target.port not in ports:
        if len(ports) >= 64:
            raise ValueError("Include the URL port in the list; the 64-port limit has been reached.")
        ports = sorted([*ports, target.port])
    if allowed_targets and target.host not in allowed_targets:
        raise ValueError("This host is not in the Aegis Guard asset allowlist configured for this installation.")
    return argparse.Namespace(
        target=target_text,
        authorized=True,
        authorization_reference=reference or None,
        ports=",".join(map(str, ports)),
        timeout=timeout,
        output=Path.cwd() / "reports",
        format=output_format,
        dry_run=dry_run,
    )


def build_scan_plan(payload: dict[str, Any], *, allowed_targets: set[str] | None = None) -> dict[str, Any]:
    """Return a validated plan without invoking network code or global stdout redirection."""
    args = build_scan_args(payload, dry_run=True, allowed_targets=allowed_targets)
    target = parse_target(args.target)
    ports = parse_ports(args.ports)
    timeout_text = f"{args.timeout:g}"
    authorization = f"Authorization declared for: {target.label}"
    plan = (
        f"{authorization}\n"
        f"Planned non-intrusive checks: DNS resolution; one TCP connect per selected port ({', '.join(map(str, ports))}); "
        "TLS verification on observed HTTPS ports; at most one HTTP HEAD request.\n"
        f"Connection timeout: {timeout_text} seconds.\n"
        "Network destination will be pinned to the first address resolved for this host.\n"
        "No network traffic was sent because preview mode was selected."
    )
    return {"ok": True, "mode": "preview", "transcript": plan, "ports": ports, "target": target.label}

def run_dashboard_scan(payload: dict[str, Any], *, dry_run: bool, allowed_targets: set[str] | None = None) -> dict[str, Any]:
    """Run a validated preview synchronously; previews perform no network checks."""
    args = build_scan_args(payload, dry_run=dry_run, allowed_targets=allowed_targets)
    transcript = StringIO()
    with redirect_stdout(transcript), redirect_stderr(transcript):
        exit_code = _run_scan(args)
    return {
        "ok": exit_code == 0,
        "exit_code": exit_code,
        "mode": "preview" if dry_run else "scan",
        "transcript": transcript.getvalue().strip(),
    }


class AegisDashboard(ThreadingHTTPServer):
    """Loopback-only dashboard with token-protected APIs and process-local jobs."""

    def __init__(self, port: int) -> None:
        allowed_targets = _allowed_targets_from_environment()
        super().__init__(("127.0.0.1", port), DashboardHandler)
        self.request_token = secrets.token_urlsafe(24)
        self.allowed_targets = allowed_targets
        self.jobs: dict[str, dict[str, Any]] = {}
        self.cancel_events: dict[str, threading.Event] = {}
        self.job_lock = threading.RLock()
        self.audit_lock = threading.Lock()

    def audit(self, action: str, **fields: Any) -> None:
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": action, **fields}
        audit_path = Path.cwd() / "reports" / "audit.jsonl"
        try:
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_lock:
                with audit_path.open("a", encoding="utf-8") as audit_file:
                    audit_file.write(json.dumps(record, ensure_ascii=True) + "\n")
        except OSError as exc:
            print(f"Aegis audit record could not be saved ({type(exc).__name__}).")

    def update_job(self, job_id: str, **changes: Any) -> None:
        with self.job_lock:
            if job_id in self.jobs:
                self.jobs[job_id].update(changes)

    def public_job(self, job_id: str) -> dict[str, Any] | None:
        with self.job_lock:
            job = self.jobs.get(job_id)
            if job is None:
                return None
            return {key: value for key, value in job.items() if key != "_report"}


class DashboardHandler(BaseHTTPRequestHandler):
    server: AegisDashboard

    def log_message(self, _format: str, *_args: object) -> None:
        """Keep routine browser requests out of the console."""

    def do_GET(self) -> None:  # noqa: N802
        if not self._has_local_host():
            self._send_json(HTTPStatus.MISDIRECTED_REQUEST, {"ok": False, "error": "Dashboard requests must use a loopback host."})
            return
        parsed = urlparse(self.path)
        path = parsed.path
        assets = {
            "/app.css": ("app.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "application/javascript; charset=utf-8"),
            "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json; charset=utf-8"),
            "/icon.svg": ("icon.svg", "image/svg+xml; charset=utf-8"),
            "/icon-192.png": ("icon-192.png", "image/png"),
            "/icon-512.png": ("icon-512.png", "image/png"),
        }
        if path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/":
            index = (ASSET_DIRECTORY / "index.html").read_text(encoding="utf-8")
            self._send(HTTPStatus.OK, "text/html; charset=utf-8", index.replace("__AEGIS_TOKEN__", self.server.request_token).encode("utf-8"))
            return
        if path in assets:
            filename, content_type = assets[path]
            self._send(HTTPStatus.OK, content_type, (ASSET_DIRECTORY / filename).read_bytes())
            return
        if path.startswith("/api/") and not self._has_valid_token():
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Invalid dashboard token."})
            return
        if path == "/api/jobs/active":
            with self.server.job_lock:
                active = next((item for item in reversed(list(self.server.jobs.values())) if item["status"] in {"queued", "running", "cancelling"}), None)
                active_job = {key: value for key, value in active.items() if key != "_report"} if active else None
            self._send_json(HTTPStatus.OK, {"job": active_job})
            return
        if path == "/api/settings":
            self._send_json(HTTPStatus.OK, {
                "allowlist_enabled": bool(self.server.allowed_targets),
                "allowed_target_count": len(self.server.allowed_targets),
                "local_only": True,
            })
            return
        if path == "/api/reports":
            self._list_reports()
            return
        if path.startswith("/api/reports/"):
            self._read_report(path.rsplit("/", 1)[-1])
            return
        if path.startswith("/api/jobs/"):
            job_id = path.rsplit("/", 1)[-1]
            job = self.server.public_job(job_id) if JOB_ID_PATTERN.fullmatch(job_id) else None
            if job is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Scan job not found."})
            else:
                self._send_json(HTTPStatus.OK, job)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        if not self._has_local_host():
            self._send_json(HTTPStatus.MISDIRECTED_REQUEST, {"ok": False, "error": "Dashboard requests must use a loopback host."})
            return
        path = urlparse(self.path).path
        if path not in {"/api/plan", "/api/scan", "/api/reports/clear", "/api/shutdown"} and not re.fullmatch(r"/api/jobs/[a-f0-9]{24}/cancel", path):
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found."})
            return
        if not self._has_valid_token():
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Invalid dashboard token."})
            return
        try:
            payload = self._read_json_body() if path in {"/api/plan", "/api/scan"} else {}
            if path == "/api/plan":
                result = build_scan_plan(payload, allowed_targets=self.server.allowed_targets)
                self._send_json(HTTPStatus.OK if result["ok"] else HTTPStatus.BAD_REQUEST, result)
                return
            if path == "/api/scan":
                self._start_scan(payload)
                return
            if path == "/api/shutdown":
                with self.server.job_lock:
                    active_job = any(job["status"] in {"queued", "running", "cancelling"} for job in self.server.jobs.values())
                if active_job:
                    self._send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "Wait for the active scan to finish or cancel it before stopping the dashboard."})
                    return
                self._send_json(HTTPStatus.OK, {"ok": True, "status": "stopping"})
                threading.Timer(0.25, self.server.shutdown).start()
                return
            if path == "/api/reports/clear":
                self._clear_history()
                return
            job_id = path.split("/")[3]
            event = self.server.cancel_events.get(job_id)
            job = self.server.public_job(job_id)
            if event is None or job is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Scan job not found."})
                return
            if job["status"] not in {"queued", "running"}:
                self._send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "This scan can no longer be cancelled."})
                return
            event.set()
            self.server.audit("scan_cancel_requested", job_id=job_id)
            self.server.update_job(job_id, status="cancelling", progress="Cancellation requested; waiting for the current bounded check to finish.")
            self._send_json(HTTPStatus.OK, {"ok": True, "job_id": job_id, "status": "cancelling"})
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "The dashboard could not process this request."})

    def _start_scan(self, payload: dict[str, Any]) -> None:
        args = build_scan_args(payload, dry_run=False, allowed_targets=self.server.allowed_targets)
        with self.server.job_lock:
            active = next((job for job in self.server.jobs.values() if job["status"] in {"queued", "running", "cancelling"}), None)
            if active:
                self._send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "Aegis Guard is already processing a scan."})
                return
            job_id = uuid.uuid4().hex[:24]
            event = threading.Event()
            job = {
                "job_id": job_id,
                "status": "queued",
                "progress": "Waiting to start",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None,
                "transcript": "",
                "report_id": None,
                "findings": [],
                "risk_score": None,
                "_report": None,
            }
            self.server.jobs[job_id] = job
            self.server.cancel_events[job_id] = event
        self.server.audit("scan_started", job_id=job_id, target=args.target, authorization_reference=args.authorization_reference or "not provided")
        worker = threading.Thread(target=self._scan_worker, args=(job_id, event, args), daemon=True, name=f"aegis-scan-{job_id}")
        worker.start()
        self._send_json(HTTPStatus.ACCEPTED, {"ok": True, "job_id": job_id, "status": "queued"})

    def _scan_worker(self, job_id: str, event: threading.Event, args: argparse.Namespace) -> None:
        transcript = StringIO()
        report_holder: dict[str, Any] = {}

        def progress(value: str) -> None:
            self.server.update_job(job_id, status="cancelling" if event.is_set() else "running", progress=value)

        def save_report(report: dict[str, Any]) -> None:
            report_holder["report"] = report
            history_dir = args.output / "history"
            history_dir.mkdir(parents=True, exist_ok=True)
            (history_dir / f"{job_id}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            findings = report.get("findings", [])
            self.server.update_job(
                job_id,
                report_id=job_id,
                risk_score=report.get("risk_score"),
                findings=findings,
                _report=report,
            )

        self.server.update_job(job_id, status="running", progress="Starting authorized scan")
        try:
            with redirect_stdout(transcript), redirect_stderr(transcript):
                exit_code = _run_scan(args, progress=progress, cancel_event=event, on_report=save_report)
            status = "cancelled" if exit_code == 130 else "complete" if exit_code == 0 else "failed"
            self.server.audit("scan_finished", job_id=job_id, status=status, risk_score=report_holder.get("report", {}).get("risk_score"))
            self.server.update_job(
                job_id,
                status=status,
                progress="Scan cancelled" if status == "cancelled" else "Scan complete" if status == "complete" else "Scan failed; review the output",
                transcript=transcript.getvalue().strip(),
                finished_at=datetime.now(timezone.utc).isoformat(),
                _report=report_holder.get("report"),
            )
        except Exception as exc:
            # Details remain in the local console; the UI receives a safe summary.
            print(f"Aegis scan job {job_id} failed: {type(exc).__name__}: {exc}")
            self.server.audit("scan_failed", job_id=job_id, error_type=type(exc).__name__)
            self.server.update_job(
                job_id,
                status="failed",
                progress="Scan failed",
                transcript="The scan failed unexpectedly. Check the local Aegis Guard console for details.",
                finished_at=datetime.now(timezone.utc).isoformat(),
            )

    def _list_reports(self) -> None:
        history_dir = Path.cwd() / "reports" / "history"
        reports: list[dict[str, Any]] = []
        if history_dir.is_dir():
            for report_path in history_dir.glob("[a-f0-9]" * 24 + ".json"):
                try:
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    findings = report.get("findings", [])
                    counts: dict[str, int] = {}
                    for finding in findings:
                        severity = str(finding.get("severity", "info")).lower()
                        counts[severity] = counts.get(severity, 0) + 1
                    reports.append({
                        "report_id": report_path.stem,
                        "target": report.get("scope", {}).get("single_target", "unknown"),
                        "generated_at": report.get("generated_at"),
                        "risk_score": report.get("risk_score"),
                        "finding_count": len(findings),
                        "severity_counts": counts,
                    })
                except (OSError, json.JSONDecodeError, AttributeError):
                    continue
        reports.sort(key=lambda item: item.get("generated_at") or "", reverse=True)
        self._send_json(HTTPStatus.OK, {"reports": reports[:100]})

    def _clear_history(self) -> None:
        with self.server.job_lock:
            active_job = any(job["status"] in {"queued", "running", "cancelling"} for job in self.server.jobs.values())
        if active_job:
            self._send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "Wait for the active scan to finish before clearing history."})
            return
        history_dir = Path.cwd() / "reports" / "history"
        deleted = 0
        if history_dir.is_dir():
            for report_path in history_dir.glob("[a-f0-9]" * 24 + ".json"):
                if JOB_ID_PATTERN.fullmatch(report_path.stem):
                    try:
                        report_path.unlink()
                        deleted += 1
                    except OSError:
                        continue
        self._send_json(HTTPStatus.OK, {"ok": True, "deleted": deleted})
    def _read_report(self, report_id: str) -> None:
        if not JOB_ID_PATTERN.fullmatch(report_id):
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid report identifier."})
            return
        report_path = Path.cwd() / "reports" / "history" / f"{report_id}.json"
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Report not found."})
            return
        except (OSError, json.JSONDecodeError):
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "Report could not be read."})
            return
        self._send_json(HTTPStatus.OK, report)

    def _has_local_host(self) -> bool:
        host = self.headers.get("Host", "").lower()
        port = self.server.server_port
        return host in {f"127.0.0.1:{port}", f"localhost:{port}"}
    def _has_valid_token(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-Aegis-Token", ""), self.server.request_token)

    def _read_json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request length.") from exc
        if length < 1 or length > MAX_REQUEST_BYTES:
            raise ValueError("Request body must be between 1 and 16 KB.")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Dashboard request must contain valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ValueError("Dashboard request must be a JSON object.")
        return payload

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        self._send(status, "application/json; charset=utf-8", json.dumps(payload).encode("utf-8"))

    def _send(self, status: HTTPStatus, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)


def serve(*, port: int = 8765, open_browser: bool = True) -> None:
    """Serve the dashboard on loopback until the user stops it with Ctrl+C."""
    server = AegisDashboard(port)
    address = f"http://127.0.0.1:{port}"
    print(f"Aegis Guard dashboard is running at {address}")
    print("The dashboard accepts connections only from this computer. Press Ctrl+C to stop it.")
    if server.allowed_targets:
        print(f"Asset allowlist is active for {len(server.allowed_targets)} configured target(s).")
    else:
        print("No asset allowlist is configured; each scan still requires the explicit authorization declaration.")
    if open_browser:
        threading.Timer(0.4, webbrowser.open, args=(address,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAegis Guard dashboard stopped.")
    finally:
        server.server_close()
