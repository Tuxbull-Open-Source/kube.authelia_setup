# Authelia installer 0.2.0 release preparation

This is an installer release candidate, not an Authelia upstream release and not
an automatically published tag. The current published installer line is 0.1.3;
0.2.0 adds the repository-owned maintenance interface. The lab-only warning remains.

## Changes

- Checkout-bound `maintain.sh` status, plan/latest-stable, supervised upgrade and logs.
- Existing Velero/Kopia infrastructure supplies mandatory cold one-PVC checkpoints,
  namespace-scoped listing and exact-name recovery.
- Reviewed host provisioning installs only Authelia-specific fixed control paths;
  neither Hermes nor other legacy controllers are replaced.
- Configuration, namespace/PVC identities, matching encryption/session/OIDC keys
  and CA trust are protected against drift. No implicit key rotation.
- Backup-time image provenance supports recovery of earlier tag-only installs
  without guessing their historical image digest after an upgrade.
- Exact image pins are persisted in the authoritative private configuration.
- CI and private-artifact checks distinguish local contracts from live qualification.

## Compatibility and prerequisites

The fixed privileged interpreter is `/usr/bin/python3.12`; it must be installed
and protected independently. Existing sudo rights, systemd, Git, kubectl, Velero,
OpenSSL and normal Linux tools are prerequisites. No user-owned Python environment
runs as root, and the installer does not silently change sudo policy.

The old unbound maintenance dispatcher is replaced by explicit reviewed enrollment.
Maintenance owns exactly `current_config/config.json` in its checkout; there is no
second target selector. Configure/install/doctor retain their normal configuration
interface. The old direct `maintain.sh restart` route is not part of this interface.

Only same-major/minor stable patch upgrades are qualified by this path; cross-family
schema migrations require a separate procedure. The backup algorithm handles the
single `authelia-data` claim, not Hermes's two-PVC layout. LDAP, SMTP, DNS, external
HTTPS and relying-party application deployments remain operator-owned.

## Operator flow after reviewed bootstrap

Follow [host maintenance](host-maintenance.md) for the administrator trust decision,
private settings, protected source staging and capability handshake. Then:

```bash
./provision-host.sh --revision FULL_REVIEWED_COMMIT
./maintain.sh status
./maintain.sh plan --latest-stable
./maintain.sh upgrade EXACT_PREPARED_PLAN
./maintain.sh logs EXACT_OPERATION
```

A launcher returning `started` is not a completed operation. A successful rollout
still needs application acceptance: schema/encryption, intended public health,
real directory login and OIDC consumers. Preserve directory-owned MFA rather than
introducing another enrollment during an unrelated maintenance change.

## Release gates

Before marking the PR ready, qualify a real old-to-new patch transition and recovery
of encrypted synthetic data and matching keys through the final native CLI. Include
a failed-workload recovery case; empty-database startup is insufficient. Keep private
logs/credentials outside Git, report scope/limitations, verify cleanup, and read back
all hosted CI results for the exact PR head. Published release/tag creation requires
its own approval; merging the feature is not evidence that a running instance was
upgraded.
