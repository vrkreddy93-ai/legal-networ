# Changelog

## 0.4.0

- Fixed validation so unspecified, multicast, and link-local IP addresses are rejected instead of falling through hostname validation.
- Parse cookie attributes by exact attribute name, and include missing SameSite in cookie review.
- Label port-based service findings as possible services, record medium confidence, and state that service identity and access controls were not verified.
- Expand reports with address coverage, TLS and HTTP observations, finding confidence, and explicit limits on interpreting the heuristic score.
- Document the tool as a local, low-impact posture assessment rather than a full penetration test or security certification.
