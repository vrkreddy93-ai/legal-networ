# Aegis Guard 0.5.0

Aegis Guard is a local-first, low-impact security posture scanner for a single host you own or are explicitly authorized to assess. It includes a command-line interface and a local web dashboard.

This is a bounded exposure and configuration check, not a penetration test, vulnerability scanner, compliance certification, or proof that a system is secure. It does not exploit vulnerabilities, authenticate to targets, brute-force credentials, submit application payloads, or generate traffic load.

## Requirements

- Python 3.10 or later

## Install and start the dashboard

```sh
git clone https://github.com/vrkreddy93-ai/legal-networ.git
cd legal-networ
python -m pip install -e .
python -m aegis serve
```

The dashboard opens at [http://127.0.0.1:8765](http://127.0.0.1:8765). It binds to loopback for one local operator and is not designed to be exposed to the public internet. GitHub Pages cannot run this Python backend.

In a supported browser, choose **Install app** in the dashboard or use the browser's install menu. The installed window still requires the local Aegis Guard server to be running; start it with `python -m aegis serve` or the Windows launcher before opening the installed app. There is no offline scan mode.

On Windows, you can launch the desktop interface with:

```powershell
python "Aegis Guard.pyw"
```

## Run a scan

The tool requires an explicit authorization declaration. Only scan a target that you own or have written permission to assess.

```sh
python -m aegis scan --target https://your-authorized-host.example --authorized
```

Preview the selected scope without sending network traffic:

```sh
python -m aegis scan --target app.example --authorized --dry-run
```

Reports are written to the local `reports/` directory by default. Use `python -m aegis --help` to see all options.

For stricter dashboard scope, set an exact hostname or IP allowlist before starting the server:

```powershell
$env:AEGIS_ALLOWED_TARGETS = "app.example,203.0.113.7"
python -m aegis serve
```

Allowlist entries are exact hostnames or IP addresses; wildcards and CIDR ranges are not accepted.

## What it checks

- DNS resolution for the selected host
- One bounded TCP connection attempt per selected port
- TLS verification on observed HTTPS ports (and an explicitly supplied HTTPS port)
- At most one HTTP `HEAD /` request for header review
- Local rule based summaries and JSON or Markdown reports

The scanner pins checks to the first address returned by DNS and records the resolved addresses in the report. Other addresses for the same hostname are not checked in that run. Service names are inferred from port numbers; the tool does not verify service identity or authentication controls. HTTP findings reflect one root-path `HEAD` response and may differ across paths, methods, or user sessions.

The 0–100 score is a local heuristic used to prioritize observations. It is not CVSS, probability, exploitability, or a security grade. Review the evidence and confidence for each finding, then confirm important results with an appropriate assessment method.

## Tests

Run the included unit tests with:

```sh
python -m unittest discover -s tests -v
```

The [Aegis Guard intro presentation](Aegis%20Guard%20Intro.pptx) is included in the repository.
