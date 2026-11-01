# Aegis Guard

A local-first security posture scanner for a **single host you own or are authorized to assess**. It provides a command-line scanner and a local web dashboard.

The dashboard is served on your computer at `127.0.0.1`. This repository is not a hosted scanner, and GitHub Pages cannot run the Python backend.

## Requirements

- Python 3.10 or later

## Install and start the dashboard

Clone the repository, install the package, and start the local server:

```sh
git clone https://github.com/vrkreddy93-ai/legal-networ.git
cd legal-networ
python -m pip install -e .
python -m aegis serve
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765) if the dashboard does not open automatically. The server is intended for one local operator and binds to loopback; it is not designed to be exposed to the public internet.

To run the Windows desktop launcher instead, use:

```powershell
python "Aegis Guard.pyw"
```

## Command-line scan

Only scan hosts you own or have explicit permission to assess. The authorization flag is required:

```sh
python -m aegis scan --target https://your-authorized-host.example --authorized
```

Use `--dry-run` to preview the bounded checks without sending network traffic:

```sh
python -m aegis scan --target app.example --authorized --dry-run
```

Reports are written to the local `reports/` folder by default. Use `python -m aegis --help` for available commands and options.

## Checks and limits

Aegis Guard performs bounded DNS resolution, TCP connection checks, TLS verification, and HTTP response-header review, then summarizes observations using local rules. It does not exploit vulnerabilities, authenticate to a target, brute-force credentials, send application payloads, or generate traffic load.

Targets must be a single hostname or IP address. Ranges, wildcards, and CIDRs are not accepted. TCP checks are bounded, and the HTTP check makes at most one `HEAD /` request without following redirects. The dashboard previews the plan before a scan is started. Use the tool only within an explicitly authorized scope.

## Development

Run the included unit tests with:

```sh
python -m unittest discover -s tests -v
```

The [Aegis Guard introduction presentation](Aegis%20Guard%20Intro.pptx) is also included.
