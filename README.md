# Aegis Guard

Aegis Guard is a small, defensive command-line security posture scanner for a **single host you are authorized to assess**. It performs low-impact checks only: DNS resolution, bounded TCP connection checks, TLS verification, HTTP response-header review, and an explainable risk correlation pass.

It does not exploit vulnerabilities, authenticate as a user, brute-force credentials, flood services, evade controls, or launch DDoS/other attacks.

## Quick start

Requires Python 3.10 or later. No third-party packages are needed.

```powershell
cd "C:\Users\manoj reddy\Documents\Codex\2026-10-25\o\outputs\Aegis Guard Version 2"
python -m aegis scan --target https://your-authorized-host.example --authorized --authorization-reference CHG-1234
```

The scanner writes JSON and Markdown reports to `reports/` by default. Use `--dry-run` to see the proposed checks without sending network traffic.

```powershell
python -m aegis scan --target 192.0.2.10 --authorized --dry-run
python -m aegis scan --target app.example --authorized --ports 80,443,8443 --format markdown
```

## Local web dashboard

Start the local dashboard with:

```powershell
python -m aegis serve
```

It opens at `http://127.0.0.1:8765`. The dashboard validates scope on the server, previews checks without network traffic, runs scans in the background with stage and port progress, and supports cancellation. It presents findings with severity, confidence, evidence, limitations, and remediation; exports JSON or Markdown; stores local report snapshots for history and comparison; and writes a local activity log to `reports/audit.jsonl`. Use **Clear history** in the dashboard to delete only saved history snapshots; generated reports and the activity log remain in `reports/`.

The dashboard binds to loopback only, validates the Host header, and protects its API with a per-process request token. It is intended for a single local operator, not shared or hosted use. Use the dashboard Stop button to close the local server. For an exact-host allowlist, set this before starting the dashboard:

```powershell
$env:AEGIS_ALLOWED_TARGETS = "app.example,203.0.113.7"
python -m aegis serve
```

Allowlist entries are exact hostnames or IP addresses; wildcards and CIDRs are not accepted. Network checks use the first address returned by DNS for the duration of a scan to reduce DNS rebinding risk. Press `Ctrl+C` in the terminal to stop the dashboard.

## Native desktop application

The Windows launcher `Aegis Guard.pyw` opens the local dashboard in your default browser. To use the separate native desktop interface, run:

```powershell
python -m aegis desktop
```

The desktop window offers scoped target entry, authorization declaration, preview, safe scan, and report options using Python's built-in UI toolkit.

## Guardrails

- One hostname or IP address per run; CIDRs, ranges, wildcards, URLs with paths, and credentials are rejected.
- `--authorized` is mandatory and is recorded in every report.
- TCP checks are limited to 64 ports, use a short timeout, and send no application payload. The selected destination is pinned to the first resolved IP for the scan.
- HTTP checks make at most one `HEAD /` request; they do not follow redirects or submit data.
- DDoS output is **posture assessment and mitigation guidance only**. The tool never creates traffic load.

## What it checks

| Area | Safe checks |
| --- | --- |
| Network exposure | Resolves the selected host and attempts bounded TCP connections to selected ports. |
| TLS | Verifies a TLS handshake on discovered HTTPS ports and records certificate-expiry timing. |
| Web posture | Reviews security headers, clickjacking controls, cookie flags, server-banner disclosure, and observable CDN/WAF/rate-limit signals. |
| DDoS resilience | Notes observable edge protection and rate-limit signals; never treats a single request as proof that controls are absent. |
| Risk analysis | Correlates findings using local, explainable rules and produces prioritized remediation guidance. |

## Dashboard and scan lifecycle

- If you specify a URL with a custom port, Aegis Guard adds that port to the bounded TCP check so the scan plan matches the requested URL.
- TLS results include certificate-expiry timing and flag certificates entering the 30-day renewal window.
- HTTP response handling evaluates every `Set-Cookie` header rather than only one cookie.
- Web posture checks now report observable clickjacking controls and a missing `Permissions-Policy` header.
- Dashboard previews use server-side hostname, port, timeout, authorization, and allowlist validation.
- Dashboard scans run as cancellable background jobs and expose bounded stage progress.
- Completed report snapshots remain in `reports/history/` until cleared; comparison is based on finding IDs and warns when targets differ.
- Dashboard API responses include local-only browser security headers and require the per-process request token.

## Development and tests

```powershell
python -m unittest discover -s tests -v
python -m aegis --help
```

## Practical next steps

For production use, run it from a controlled CI runner, store reports in a protected evidence bucket, add your approved asset inventory and vulnerability-feed integrations, and have a security team review every high- or critical-severity result. Keep scan scope and written authorization with the report.





