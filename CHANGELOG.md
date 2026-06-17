# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with a `v` prefix (e.g. `v1.2.0`).

## [Unreleased]

## [v1.0.0] - 2026-06-17

Initial release of **CRL Monitor** — a single-container monitor for
HTTP(S)-published RFC 5280 CRLs, with a dashboard, selectable conformance
checks, uptime reporting, and CRL-metadata history.

### Added
- Core CRL checking: resolve CRL distribution points (or an explicit URL),
  download and parse the CRL (DER/PEM), verify its signature against the issuer,
  validate `thisUpdate`/`nextUpdate` freshness, and look up the certificate's
  revocation status (with revocation date and CRLReason code).
- SSRF-safe outbound fetching: URL validation plus DNS-rebinding-safe IP
  pinning, and a runtime-configurable maximum CRL download size.
- Selectable verification tests (foundational + evaluation), configurable
  globally and per monitor: CRL Number extension (rollback detection),
  weak signature-algorithm detection, Issuing Distribution Point scope,
  delta CRL / Freshest CRL support, and a response-time threshold.
- Scheduling: fixed-frequency or CRL `nextUpdate`-based scheduling with a
  safety window, plus a configurable retry/backoff policy after failed checks.
- CRL data history: per-check snapshots capturing the issuing CA, CRL number,
  number of revoked certificates, time remaining, `nextUpdate`, status, and
  response time, retained for a configurable period.
- Uptime reports and maintenance windows: time-weighted uptime, a downtime list
  with editable comments, maintenance windows, and per-outage exclusion from the
  uptime calculation (persisted across reports).
- Dashboard with per-check result pills (globally show/hide), status history,
  Uptime Kuma push integration, and a settings UI.
- Security hardening: CSRF protection and per-IP rate limiting on
  state-changing API requests; XSS-safe rendering.
- Packaging: Docker image published to GHCR and a `docker-compose.yml` for a
  single-container deployment.

[Unreleased]: https://github.com/jgoodloe/crl-monitor/compare/v1.0.0...HEAD
[v1.0.0]: https://github.com/jgoodloe/crl-monitor/releases/tag/v1.0.0
