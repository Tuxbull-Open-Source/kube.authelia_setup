# Changelog

## [0.2.0] - Unreleased

### Maintenance candidate

- Add repository-owned, checkout-bound maintenance with explicit version planning,
  supervised patch upgrades and persisted image pins.
- Use existing Velero/Kopia infrastructure for a cold backup of the single
  `authelia-data` PVC before any image upgrade.
- Preserve matching database encryption/session/OIDC keys and namespace metadata;
  do not treat an image downgrade as a database rollback.
- Keep reviewed host provisioning, recovery and operation coordination in this
  repository, separate from other applications' installed control paths.
- Enrolled maintenance replaces the old unbound status/restart dispatcher; the
  legacy direct restart path is intentionally unavailable. Configure/install/doctor
  retain their explicit configuration interface, while maintenance uses one bound
  `current_config/config.json` per checkout.
- Keep private configuration, credentials, rendered data and recovery artifacts
  outside Git; add local/hosted regression checks under multiple umasks.

This is an unreleased development candidate. Live qualification and current-head
CI must pass before handoff; no production deployment is implied by this entry.

## [0.1.3] - 2026-11-04

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
