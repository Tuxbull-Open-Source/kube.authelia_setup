# kube.authelia_setup

Standalone Authelia on an **existing k3s cluster**, in its own namespace, with a `local-path` filesystem PVC and SQLite. No dependency on Hermes. No changes to `kube.hermes_setup`.

The operator workflow follows `kube.hermes_setup`: **configure → install → maintain → doctor**. The implementation is deliberately smaller: Bash entrypoints and a dependency-free Python renderer/controller; no Helm chart dependency. See [provenance](NOTICE.md).

## Boundaries and defaults

| Component | This repository owns |
|---|---|
| Namespace | `authelia` by default; rejects system namespaces and unmanaged existing resources |
| Authelia | `authelia/authelia:4.39.28`, one non-root replica, `Recreate`, ClusterIP port 9091 |
| Storage | `authelia-data`, 1Gi, RWO, `rancher.io/local-path`; SQLite at `/data/db.sqlite3` |
| Secrets | LDAP/SMTP passwords, generated session and storage keys; mounted files, never printed |
| Sessions | 2h inactivity, 12h absolute, remember-me disabled; single-process memory sessions |
| Authentication | External LDAP live bind with LDAPS/StartTLS and CA verification |
| Authorization | Default deny; one explicit protected domain + LDAP group; **two_factor** by default |
| Notifications | External SMTP, TLS required, CA verification; no filesystem notifier |
| Backup/recovery | Operator-owned through Velero; no installer feature |

**Not installed or managed:** k3s, ingress controllers, public DNS, TLS certificates/keys/issuers, cert-manager, ACME, LDAP, SMTP, Redis, OIDC clients or Hermes. No system packages, system services, cron jobs or reboot are performed by product scripts. Images are downloaded by Kubernetes on first use. Only the isolated [QA harness](tests/lab/README.md) provisions its own test TLS, LDAP and SMTP fixtures.

**Not HA:** local-path volumes are tied to a node. Node loss can lose all data. PVC capacity is not a disk quota; expansion is not supported by the standard local-path class. Protect and recover state through your operator-owned Velero procedure. Sessions are lost on pod restart; users must authenticate again.

## Prerequisites

- Linux operator host: Bash, Python **3.10+**, `kubectl`.
- Existing k3s, a Ready node, healthy DNS and `local-path` provisioner; writable node disk. Application request: 100m CPU / 128Mi RAM; limit: 1 CPU / 512Mi. Allow additional headroom for k3s .
- Kubeconfig with permission to create the dedicated namespace and manage its Deployments, Pods/exec, ConfigMaps, Secrets, Services and PVCs; read StorageClasses. Runtime pods receive **no Kubernetes API token**.
- Working external LDAP service account, user/group/mail attributes, and SMTP relay. The LDAP account should be read-only; self-service LDAP password reset is disabled.
- Operator-owned HTTPS reverse proxy for `https://sso.example.com`, forwarding to `authelia.authelia.svc.cluster.local:9091` over a trusted network. Preserve Host and set forwarded scheme to HTTPS; strip untrusted forwarded headers. **Do not expose port 9091 publicly.**

## Configure and install

```bash
git clone https://github.com/Tuxbull-Open-Source/kube.authelia_setup.git
cd kube.authelia_setup
./configure.sh --no-install
./install.sh --render-only
# Inspect current_config/artifacts/resources.json (no password values).
./install.sh
./doctor.sh
./maintain.sh status
```

`configure.sh` prompts for all fields, hides password input, saves `current_config/config.json` with mode 0600, then installs unless `--no-install` is supplied. Blank answers preserve existing values; edit the private JSON directly to explicitly clear an optional value. CA input accepts an operator-owned PEM CA bundle file; it does **not** create certificates or manage public TLS.

For automation, copy `examples/config.json` to a private path, set all actual values without putting them in shell arguments, `chmod 600` the file, and use:

```bash
./configure.sh --from-answers /secure/authelia.json --no-install
./install.sh --config /secure/authelia.json
./doctor.sh --config /secure/authelia.json
```

Every script accepts `--config`; precedence is explicit `--config`, then `CONFIG_FILE`, then repository `current_config/config.json`. JSON is parsed as data, **never sourced as shell code**. Unknown fields/options fail. No `.env` file is sourced.

The [example config](examples/config.json) is the complete schema. Key groups:
- `url`, `cookie_domain`: HTTPS portal origin and cookie parent domain, e.g. `https://sso.example.com` and `example.com`.
- `session_idle`, `session_max`: positive integer plus `s`, `m` or `h`; idle cannot exceed maximum.
- `ldap_*`: address, StartTLS boolean, implementation (`custom`, `freeipa`, etc.), base/bind DNs, users/groups filters, username/display/mail attribute names and bind password. Defaults suit an RFC2307-style directory; adapt filters to exclude disabled accounts for your directory.
- `smtp_*`: address (`submission://smtp.example.com:587` or `submissions://smtp.example.com:465`), sender, optional authentication username/password. Empty username supports an IP-authorized TLS relay.
- `ca_pem`: optional CA PEM string augmenting system trust for LDAP/SMTP. No skip-verification knob exists.
- `protected_domain`, `allowed_group`, `policy`: exact protected hostname in the cookie domain and LDAP group. `one_factor` is an explicit opt-down; it is not MFA. Unlisted domains/groups are denied.
- `namespace`, `image`, `storage_size`: dedicated namespace, pinned image tag/digest, initial PVC size. Do not edit namespace or PVC size as an in-place migration.

A repeated install preserves keys and PVC identity; config/secret changes update pod-template hashes and trigger rollout, while an unchanged install does not force a restart. A missing encryption Secret beside an existing PVC **fails closed** rather than generating unusable replacement keys. Server-side dry-run precedes applying application resources. Namespace creation can occur during preflight; application updates are not transactional. Reapply the previous config after configuration failure; data recovery belongs to the operator.

## Operate

```bash
./maintain.sh status
./maintain.sh restart
./doctor.sh
```

There is no automatic upgrade, key rotation, uninstall, backup/restore or PVC deletion command. **Backup/recovery is operator-owned through Velero.** This repository does not install, configure or validate Velero. Preserve the PVC and its matching encryption Secret together under that process.

For upgrades, review upstream release notes, follow your operator-owned protection procedure, edit the pinned `image`, run install/doctor and repeat browser acceptance. Changing an image tag does not reverse a SQLite schema migration.

See [operations](docs/operations.md), [security and TLS boundary](docs/security.md), [future Hermes integration](docs/hermes-integration.md), and [actual QA evidence](docs/qa.md).

## Tests

```bash
bash -n configure.sh install.sh maintain.sh doctor.sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts tests
# Optional development dependency: ruff
ruff check scripts tests
ruff format --check scripts tests
```

Live and Chromium acceptance are separate mandatory release gates, not simulated by the unit suite. Public CI is not configured in this initial repository. See the reproducible [disposable lab procedure](tests/lab/README.md).
