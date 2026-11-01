"""Explainable local risk correlation for safe scan observations."""

from __future__ import annotations

from .models import Finding, ScanResult, SEVERITY_ORDER


def _finding(identifier: str, title: str, severity: str, category: str, evidence: str, recommendation: str, confidence: str = "high") -> Finding:
    return Finding(identifier, title, severity, category, evidence, recommendation, confidence)


def _cookie_attributes(set_cookie: str) -> set[str]:
    """Return exact Set-Cookie attribute names, ignoring the cookie value."""
    return {
        segment.partition("=")[0].strip().lower()
        for segment in set_cookie.split(";")[1:]
        if segment.partition("=")[0].strip()
    }


def analyze(result: ScanResult) -> list[Finding]:
    """Create prioritized observations without claiming unobserved vulnerabilities."""
    findings: list[Finding] = []
    open_ports = {item["port"] for item in result.open_ports}
    exposed_services = {
        445: ("Possible SMB service reachable on port 445", "high", "Confirm the exposure is intended; restrict SMB to managed networks and verify patching and signing."),
        3389: ("Possible Remote Desktop service reachable on port 3389", "high", "Confirm the exposure is intended; place remote access behind a VPN or zero-trust gateway, enforce MFA, and limit source IPs."),
        3306: ("Possible MySQL service reachable on port 3306", "high", "Confirm the exposure is intended; restrict database access to approved application networks and verify authentication and TLS."),
        5432: ("Possible PostgreSQL service reachable on port 5432", "high", "Confirm the exposure is intended; restrict database access to approved application networks and verify authentication and TLS."),
        6379: ("Possible Redis service reachable on port 6379", "high", "Confirm the exposure is intended; restrict access to approved private networks and verify authentication and TLS."),
        27017: ("Possible MongoDB service reachable on port 27017", "high", "Confirm the exposure is intended; restrict access to approved private networks and verify authentication and TLS."),
    }
    for port, (title, severity, recommendation) in exposed_services.items():
        if port in open_ports:
            findings.append(_finding(
                f"network-{port}-exposure",
                title,
                severity,
                "network-exposure",
                f"A TCP connection to port {port} succeeded. The service identity and its access controls were not verified.",
                recommendation,
                "medium",
            ))

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
        cookie_attributes = [_cookie_attributes(value) for value in cookie_headers]
        missing_secure = sum("secure" not in attributes for attributes in cookie_attributes)
        missing_httponly = sum("httponly" not in attributes for attributes in cookie_attributes)
        missing_samesite = sum("samesite" not in attributes for attributes in cookie_attributes)
        if missing_secure or missing_httponly or missing_samesite:
            missing_flags = []
            if missing_secure:
                missing_flags.append(f"{missing_secure} Set-Cookie header(s) missing Secure")
            if missing_httponly:
                missing_flags.append(f"{missing_httponly} Set-Cookie header(s) missing HttpOnly")
            if missing_samesite:
                missing_flags.append(f"{missing_samesite} Set-Cookie header(s) missing SameSite")
            severity = "medium" if missing_secure or missing_httponly else "low"
            findings.append(_finding(
                f"http-{port}-cookie-flags",
                "Cookie protection attributes may be incomplete",
                severity,
                "web-security",
                f"{'; '.join(missing_flags)}. Cookie purpose was not determined.",
                "Review each cookie's purpose. Session cookies generally need Secure, HttpOnly, and an appropriate SameSite value; assess exceptions in application context.",
                "medium",
            ))

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
