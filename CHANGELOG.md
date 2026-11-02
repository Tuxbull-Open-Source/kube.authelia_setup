# Changelog

## 0.1.1 (unreleased)

- Focus the README on web application SSO through reverse-proxy forward authentication, existing LDAP identities/groups, MFA and SMTP notifications.
- Clarify the single protected hostname/group scope, separate application-local login and absence of native OpenID Connect client configuration.
- Remove unrelated project comparisons from the introduction and unmanaged-component list; retain provenance and optional integration documentation.
- Documentation-only patch; no installer, runtime configuration or dependency changes.

## 0.1.0

- Standalone Authelia in a dedicated namespace, k3s local-path PVC/SQLite.
- Interactive/replay configuration, declarative install, status/restart and diagnostics.
- Verified LDAP/SMTP TLS, stable generated keys and non-root read-only runtime.
- Real disposable-k3s and Chromium LDAP/TOTP, notification, session and idempotency QA.
- Public TLS stays operator-owned; future Hermes integration documented only.
- No product backup/restore: removed at operator request; recovery is operator-owned via Velero.
