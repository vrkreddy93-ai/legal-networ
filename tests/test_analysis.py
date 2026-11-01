import unittest

from aegis.analysis import analyze, risk_score
from aegis.models import ScanResult, Target


class AnalysisTests(unittest.TestCase):
    def test_exposed_redis_is_critical(self):
        result = ScanResult(target=Target("example.com"), open_ports=[{"port": 6379, "service": "redis", "state": "open"}])
        findings = analyze(result)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].confidence, "medium")
        self.assertGreaterEqual(risk_score(findings), 20)

    def test_single_http_response_yields_ddos_posture_guidance(self):
        result = ScanResult(target=Target("example.com"), http=[{"scheme": "https", "port": 443, "reachable": True, "status": 200, "headers": {}}])
        findings = analyze(result)
        self.assertTrue(any(item.category == "ddos-posture" for item in findings))

    def test_cookie_check_evaluates_each_set_cookie_header(self):
        result = ScanResult(
            target=Target("example.com"),
            http=[{
                "scheme": "https",
                "port": 443,
                "reachable": True,
                "status": 200,
                "headers": {"set-cookie": ["session=abc; Secure; HttpOnly", "theme=dark"]},
            }],
        )
        findings = analyze(result)
        cookie_finding = next(item for item in findings if item.id == "http-443-cookie-flags")
        self.assertIn("1 Set-Cookie", cookie_finding.evidence)

    def test_tls_expiry_enters_renewal_window(self):
        result = ScanResult(
            target=Target("example.com"),
            tls=[{"port": 443, "verified": True, "days_until_expiry": 20}],
        )
        findings = analyze(result)
        self.assertTrue(any(item.id == "tls-443-expiry" and item.severity == "low" for item in findings))


if __name__ == "__main__":
    unittest.main()
