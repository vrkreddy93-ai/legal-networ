# Changelog

## 0.5.0

- Added an installable standalone app presentation with a branded icon and manifest.
- Added an in-dashboard install action when the browser offers installation.
- Refined dashboard spacing, focus states, sticky header, and reduced-motion handling.
- Kept app data and scan APIs on the local server; no offline cache or public service was added.

## 0.4.0

- Fixed validation so unspecified, multicast, and link-local IP addresses are rejected instead of falling through hostname validation.
- Parse cookie attributes by exact attribute name, and include missing SameSite in cookie review.
- Label port-based service findings as possible services, record medium confidence, and state that service identity and access controls were not verified.
- Expand reports with address coverage, TLS and HTTP observations, finding confidence, and explicit limits on interpreting the heuristic score.
- Document the tool as a local, low-impact posture assessment rather than a full penetration test or security certification.
