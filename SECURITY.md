# Security and privacy scope

This release candidate is a local synthetic academic prototype, not production-ready monitoring software. Bind only to loopback. Never use real employee activity, personal credentials or production databases for its demo.

Preserved safeguards include removal of the destructive development router, same-origin operation without wildcard CORS, externally supplied signing/Fernet keys, active-company checks, scoped admin/device routes and recommendation-only response status. New release safeguards disable implicit database migrations, automatic CNN training, screenshot presentation overrides, and default background/external-service execution. Admin usernames have a database uniqueness constraint; oversized passwords fail safely.

Remaining limits:

- The known dependency verification blocker is resolved for the tested configuration (INSTALLATION.md). Exact versions and official wheel bytes were verified; requirements.txt is not a portable hash lock. No zero-vulnerability claim is made.
- Company enrollment codes confer tenant-wide onboarding/status trust; there is no independent per-device enrollment challenge. Device tokens and database contents need local protection. JWTs in browser localStorage are XSS-readable.
- Public company registration, no comprehensive rate limiting/request-size controls, single-process state, limited concurrency coverage, and no deployment TLS configuration. Selected tenant checks passed; every endpoint has not been exhaustively audited.
- Endpoint telemetry can include usernames, paths, processes, network/device identifiers and authentication events. Collection requires informed authorization and an appropriate retention/privacy design. The release process did not run the collector.
- SMTP and LLM functions may transmit sensitive data when explicitly enabled. They are disabled by default. PDF handling, notifications and report workflows were not validated here.
- Heuristic scores and experimental model outputs are not calibrated threat probabilities. Recommendations do not enforce containment.

Do not submit real logs, secrets, databases or employee records in public issues. No public vulnerability-reporting contact or external account has been provisioned by this release preparation.

## Retained advisory findings (2026-11-01 verification)

- PyJWT 2.14.0: [GHSA-42vr-xj54-vc7v](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-42vr-xj54-vc7v) / PYSEC-2026-4141 concerns unverified payload/PyJWKClient parsing. LITDS uses verified HS256 decoding, no PyJWKClient and no verify_signature=False path.
- PyJWT 2.14.0: [GHSA-x33g-cr3x-6449](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-x33g-cr3x-6449) / PYSEC-2026-4183 concerns OKP JWKs; LITDS does not use JWKs.
- python-dotenv 1.0.1: [GHSA-mf9w-mj56-hr94](https://github.com/advisories/GHSA-mf9w-mj56-hr94) / PYSEC-2026-2270 affects set_key/unset_key; LITDS only reads dotenv files and does not call those write APIs.

These version-level matches were retained and assessed as unused functionality, not suppressed. No remaining relevant security blocker was identified in the reviewed enabled paths. Deployment behavior and optional integrations remain unverified. The targeted PyPI advisory check found no matches for the added requests 2.34.2, psutil 7.2.2 or urllib3 2.8.0 versions. This records the completed verification, not a new security audit or a promise about future advisories.
