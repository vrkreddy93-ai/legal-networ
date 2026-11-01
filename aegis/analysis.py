"""Explainable local risk correlation for safe scan observations."""

from __future__ import annotations

from .models import Finding, ScanResult, SEVERITY_ORDER


def _finding(identifier: str, title: str, severity: str, category: str, evidence: str, recommendation: str, confidence: str = "high") -> Finding:
    return Finding(identifier, title, severity, category, evidence, recommendation, confidence)


def analyze(result: ScanResult) -> list[Finding]:
    """Create prioritized observations without claiming unobserved vulnerabilities."""
    findings: list[Finding] = []
    open_ports = {item["port"] for item in result.open_ports}
    exposed_services = {
        445: ("SMB is reachable", "high", "Restrict SMB to private, managed networks and require current patching and signing."),
        3389: ("Remote Desktop is reachable", "high", "Place RDP behind a VPN or zero-trust gateway, enforce MFA, and limit source IPs."),
        3306: ("MySQL is reachable", "high", "Do not expose database listeners publicly; restrict them to application subnets and require TLS."),
        5432: ("PostgreSQL is reachable", "high", "Do not expose database listeners publicly; restrict them to application subnets and require TLS."),
        6379: ("Redis is reachable", "critical", "Restrict Redis to private networks immediately and require authentication and TLS."),
        27017: ("MongoDB is reachable", "critical", "Restrict MongoDB to private networks immediately and require authentication and TLS."),
    }
    for port, (title, severity, recommendation) in exposed_services.items():
        if port in open_ports:
            findings.append(_finding(f"network-{port}-exposure", title, severity, "network-exposure", f"A TCP connection to port {port} succeeded.", recommendation))

    for tls in result.tls:
        if not tls["verified"]:
            findings.append(_finding(f"tls-{tls['port']}-verification", "TLS certificate or handshake could not be verified", "medium", "transport-security", f"TLS verification on port {tls['port']} failed: {tls.get('error', 'unknown error')}", "Install a trusted, unexpired certificate with the correct hostname and supported TLS configuration."))
            continue
        days_until_expiry = tls.get("days_until_expiry")
        if days_until_expiry is not None and days_until_expiry <= 14:
            findings.append(_finding(f"tls-{tls['port']}-expiry", "TLS certificate expires soon", "medium", "transport-security", f"TLS certificate on port {tls['port']} expires in {days_until_expiry} day(s).", "Renew and deploy the certificate before expiry, then confirm the renewal with a follow-up scan."))
        elif days_until_expiry is not None and days_until_expiry <= 30:
            findings.append(_finding(f"tls-{tls['port']}-expiry", "TLS certificate renewal window is approaching", "low", "transport-security", f"TLS certificate on port {tls['port']} expires in {days_until_expiry} day(s).", "Schedule certificate renewal and confirm the renewal before the certificate enters its final two weeks."))

    for response in result.http:
        if not response.get("reachable"):
            continue
        headers = response["headers"]
        port = response["port"]
        if response["scheme"] == "https" and "strict-transport-security" not in headers:
            findings.append(_finding(f"http-{port}-hsts", "HSTS header is not present", "low", "web-security", "HTTPS response did not include Strict-Transport-Security.", "Enable HSTS after confirming every subdomain safely supports HTTPS."))
        missing = [label for header, label in (("content-security-policy", "Content-Security-Policy"), ("x-content-type-options", "X-Content-Type-Options"), ("referrer-policy", "Referrer-Policy")) if header not in headers]
        if missing:
            findings.append(_finding(f"http-{port}-headers", "Recommended HTTP security headers are missing", "low", "web-security", f"Missing: {', '.join(missing)}.", "Set the missing headers using values appropriate for the application, and test them before enforcement."))
        content_security_policy = headers.get("content-security-policy", "").lower()
        if "x-frame-options" not in headers and "frame-ancestors" not in content_security_policy:
            findings.append(_finding(f"http-{port}-framing", "Clickjacking protection is not observable", "low", "web-security", "The response did not include X-Frame-Options or a Content-Security-Policy frame-ancestors directive.", "Set X-Frame-Options or a Content-Security-Policy frame-ancestors directive that matches the application's embedding requirements."))
        if "permissions-policy" not in headers:
            findings.append(_finding(f"http-{port}-permissions-policy", "Permissions-Policy header is not present", "info", "web-security", "The response did not include Permissions-Policy.", "Consider a Permissions-Policy that disables browser features the application does not use."))
        if "server" in headers:
            findings.append(_finding(f"http-{port}-banner", "Web server banner is disclosed", "info", "information-disclosure", f"Server header: {headers['server'][:120]}", "Consider minimizing version and product disclosure in response headers."))
        cookie_headers = headers.get("set-cookie", [])
        if isinstance(cookie_headers, str):
            cookie_headers = [cookie_headers]
        incomplete_cookies = [
            value for value in cookie_headers
            if "secure" not in value.lower() or "httponly" not in value.lower()
        ]
        if incomplete_cookies:
            findings.append(_finding(f"http-{port}-cookie-flags", "Cookie protection flags may be incomplete", "medium", "web-security", f"{len(incomplete_cookies)} Set-Cookie header(s) did not include both Secure and HttpOnly tokens.", "For session cookies, set Secure, HttpOnly, and an appropriate SameSite attribute. Review application-specific exceptions."))

        waf_markers = ("cf-ray", "x-sucuri-id", "x-amzn-waf", "x-akamai", "x-cdn")
        has_edge_signal = any(marker in headers for marker in waf_markers) or "cloudflare" in headers.get("server", "").lower()
        rate_limit_signal = any(name in headers for name in ("ratelimit-limit", "x-ratelimit-limit", "retry-after"))
        if has_edge_signal or rate_limit_signal:
            signals = (["edge/WAF header"] if has_edge_signal else []) + (["rate-limit header"] if rate_limit_signal else [])
            findings.append(_finding(f"ddos-{port}-signal", "Observable DDoS-resilience control signal", "info", "ddos-posture", f"Observed {' and '.join(signals)} in a single HEAD response.", "Validate CDN/WAF coverage, origin shielding, rate-limit rules, alert routing, and a documented incident runbook.", "medium"))
        else:
            findings.append(_finding(f"ddos-{port}-visibility", "DDoS resilience cannot be confirmed by this low-impact check", "info", "ddos-posture", "No edge-protection or rate-limit signal was observable in one HEAD response; this does not prove controls are absent.", "Review CDN/WAF coverage, rate limiting, origin access controls, autoscaling limits, and DDoS incident procedures. Do not use load generation without a separately approved test plan.", "low"))

    findings.sort(key=lambda finding: (-SEVERITY_ORDER[finding.severity], finding.id))
    return findings


def risk_score(findings: list[Finding]) -> int:
    """Return a bounded, transparent posture score; it is not a vulnerability count."""
    weights = {"critical": 35, "high": 20, "medium": 10, "low": 4, "info": 0}
    return min(100, sum(weights[finding.severity] for finding in findings))
