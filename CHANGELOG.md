# Changelog

## [0.1.2] - 2026-11-03

### Changed

- Add explicit `manage_namespace: false` support for a shared, operator-owned
  Kubernetes namespace; the default continues to create and own a dedicated
  namespace.
- Standardize maintainer guidance in repository-root `AGENTS.md`.
- Align release documentation with the Tuxbull-Open-Source repository namespace.

### Verified

- Authorized shared-namespace QA in `qa`: non-secret rendering, server-side
  validation, generated LDAPS and SMTP STARTTLS fixtures, installer apply,
  rollout, `doctor.sh`, repeated unchanged install, and exact labelled-resource
  cleanup.
- Confirmed fail-closed behavior before fixture completion: unavailable LDAP or
  non-STARTTLS SMTP prevents a Ready application. The final generated fixtures
  used CA-verified service-DNS TLS and produced one Ready Authelia replica with
  a Bound PVC.

## [0.1.0]

- Standalone Authelia in a dedicated namespace, k3s local-path PVC/SQLite.
- Interactive/replay configuration, declarative install, status/restart and diagnostics.
- Verified LDAP/SMTP TLS, stable generated keys and non-root read-only runtime.
- Real disposable-k3s and Chromium LDAP/TOTP, notification, session and idempotency QA.
- Public TLS stays operator-owned; future Hermes integration documented only.
- No product backup/restore: removed at operator request; recovery is operator-owned via Velero.
