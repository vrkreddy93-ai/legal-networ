import unittest

from aegis.target import TargetValidationError, parse_ports, parse_target


class TargetParsingTests(unittest.TestCase):
    def test_accepts_hostname_and_https_url(self):
        self.assertEqual(parse_target("App.Example.com").host, "app.example.com")
        target = parse_target("https://app.example.com:8443")
        self.assertEqual((target.host, target.scheme, target.port), ("app.example.com", "https", 8443))

    def test_rejects_broad_or_obscured_scope(self):
        for target in ("10.0.0.0/24", "*.example.com", "https://user:pass@example.com", "https://example.com/admin"):
            with self.subTest(target=target):
                with self.assertRaises(TargetValidationError):
                    parse_target(target)

    def test_limits_port_list(self):
        self.assertEqual(parse_ports("443,80,443"), [80, 443])
        with self.assertRaises(TargetValidationError):
            parse_ports("0,80")
        with self.assertRaises(TargetValidationError):
            parse_ports(",".join(str(port) for port in range(1, 66)))

    def test_rejects_non_web_url_scheme(self):
        with self.assertRaises(TargetValidationError):
            parse_target("ftp://example.com")


if __name__ == "__main__":
    unittest.main()
