# Changelog

## [0.1.2] - 2026-11-04

### Changed

- Enforce one exclusive installer-owned namespace for new setup, reconfigure,
  upgrade, doctor, and restart; remove the shared-namespace configuration path.
- Reject non-Authelia application/configuration resources in the configured
  namespace, allowing only Kubernetes baseline `serviceaccount/default` and
  `configmap/kube-root-ca.crt` without the installer ownership label.
- Label the Authelia Deployment pod template with
  `app.kubernetes.io/managed-by=kube.authelia_setup` so exclusivity checks do
  not reject its own Pods.
- Standardize maintainer guidance in repository-root `AGENTS.md`.
- Align release documentation with the Tuxbull-Open-Source repository namespace.

### Validated

- Shell syntax, Python unit tests, Python compile, release-artifact checks, and
  `git diff --check` passed for the exclusive-namespace implementation.
- Unit coverage verifies that an installer-owned namespace with Kubernetes
  baseline objects is accepted and that a foreign workload is rejected.
- The prior shared-namespace QA resources and the subsequent dedicated QA/
  fixture namespaces were removed after testing; no QA namespace remains.

### Remaining live-QA gate

- A final end-to-end lifecycle test in a newly created exclusive Authelia
  namespace remains required before release. Its LDAP/SMTP/browser fixtures
  must run in a distinct disposable namespace; the last fixture run was stopped
  and cleaned up after the LDAP fixture failed before readiness.

## [0.1.0]

- Standalone Authelia in a dedicated namespace, k3s local-path PVC/SQLite.
- Interactive/replay configuration, declarative install, status/restart and diagnostics.
- Verified LDAP/SMTP TLS, stable generated keys and non-root read-only runtime.
- Real disposable-k3s and Chromium LDAP/TOTP, notification, session and idempotency QA.
- Public TLS stays operator-owned; future Hermes integration documented only.
- No product backup/restore: removed at operator request; recovery is operator-owned via Velero.
