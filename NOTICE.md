# Provenance

This project is MIT licensed; see LICENSE.

The operator-facing configure.sh / install.sh / maintain.sh / doctor.sh workflow,
private generated configuration, declarative rendering, Secret reuse, single-replica
Recreate deployment, rollout verification and fail-closed credential principles are
adapted from [Tuxbull-Open-Source/kube.hermes_setup](https://github.com/Tuxbull-Open-Source/kube.hermes_setup).

Reference upstream main: `cd557e1998dc4eea6b69143ff39067c9916fe161`.
Local read-only reference: `63adf2a95c07de055dc1d5b011292e57d3b7885f`.
Original MIT copyright: Copyright (c) 2026 hermes-speedboat, retained in LICENSE.

This is a separate implementation, not a fork that bundles Hermes code/runtime.
The reference repository was not modified. The original's shell env format is
intentionally replaced by data-only private JSON, while retaining the lifecycle
entrypoints and safety model. Backup/restore functionality is intentionally absent
at the operator's request; Velero remains externally operated.

Authelia is an independent upstream project. Its container and license remain
upstream-owned; this repository is not an official Authelia distribution or Helm chart.
