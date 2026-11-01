import unittest

from aegis.web import build_scan_args, run_dashboard_scan


class DashboardTests(unittest.TestCase):
    def test_preview_uses_the_same_bounded_cli_plan(self):
        payload = {
            "target": "https://example.com:9443",
            "authorized": True,
            "ports": "443",
            "timeout": "1.5",
            "format": "both",
        }
        result = run_dashboard_scan(payload, dry_run=True)
        self.assertTrue(result["ok"])
        self.assertIn("443, 9443", result["transcript"])
        self.assertIn("No network traffic", result["transcript"])

    def test_dashboard_requires_a_target(self):
        with self.assertRaises(ValueError):
            build_scan_args({"authorized": True}, dry_run=True)

    def test_dashboard_rejects_an_unknown_report_format(self):
        with self.assertRaises(ValueError):
            build_scan_args({"target": "example.com", "authorized": True, "format": "xml"}, dry_run=True)


if __name__ == "__main__":
    unittest.main()
