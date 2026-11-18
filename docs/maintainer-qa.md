# Maintaining the installer: start here

Use the same four entry points operators use. The test driver supplies private answers; it must not copy a running Deployment, patch rendered config to make a test pass, or provision helpers during a normal install. Hermes WebUI and Dashboard are relying parties, not startup dependencies.

## Fast gate: no cluster or accounts

From the repository root on Linux with Python and OpenSSL:

```sh
python3 -m unittest discover -s tests -p 'test_qa_render.py' -v
python3 -m unittest discover -s tests -v
for f in configure.sh install.sh maintain.sh doctor.sh; do bash -n "$f" || exit 1; done
python3 -m compileall -q scripts tests
ruff check scripts tests
ruff format --check scripts tests
git diff --check
```

The first test starts with `examples/config.json`, generates temporary printable credentials, invokes configure and render-only, then checks the actual rendered SMTP notifier, Secret volume/file reference, namespace and absence of Ingress. It does **not** start Authelia, authenticate to SMTP or deliver a message.

## Where to make changes

| Change | Update together |
|---|---|
| Installer inputs/defaults | `scripts/setup.py`, config loading/wizard in `scripts/cli.py`, `examples/config.json`, README and replay/legacy-config tests |
| Kubernetes resource or Secret wiring | `render()` in `scripts/setup.py`, `secret_doc()` and install/doctor in `scripts/cli.py`, render and lifecycle tests |
| Authelia runtime version | Check upstream stable release, registry digest and migration notes; update default image, example and docs. Exercise old-to-new on synthetic state; do not equate a clean install with an upgrade. `VERSION` is the installer release, not the Authelia image version. Do not overwrite a saved operator image pin. |

## Live installer and notifier qualification

Run [the K3s driver](../tests/k3s/run.py) from a trusted Linux machine with Python 3, OpenSSL, `kubectl`, a dedicated non-changing kubeconfig/current context, and permission to create and delete disposable namespaces. It invokes the checkout's actual `configure.sh`, `install.sh`, `doctor.sh` and `maintain.sh`. Do not use Python's optimization flag. Do not run on a cluster that lacks approval for a temporary public QA login portal.

```sh
python3 tests/k3s/run.py --context "$APPROVED_CONTEXT" --domain "$QA_WILDCARD_ZONE" \
  --evidence "$PRIVATE_PARENT/run-$(date -u +%Y%m%dT%H%M%SZ)"
```

The evidence directory must not exist. Prerequisites: amd64 node (the Authelia manifest pin is architecture-specific), `local-path` storage with deletion on reclaim, Traefik, cluster DNS under `cluster.local`, enforced NetworkPolicy, and existing wildcard DNS, routing and trusted HTTPS for the QA zone. The fixture pulls a digest-pinned Alpine image and installs packages from signed Alpine repositories at startup; this requires network access and does not pin each package revision. No DNS records, public certificates or ingress-controller settings are changed.

Each run generates a new installer-owned app namespace, separate fixture namespace, short-lived CA, server certificate and printable credentials. Only the portal gets an Ingress. The provider Pod has no service-account token; OpenLDAP and the authenticated STARTTLS sink use ephemeral storage and a ClusterIP. The sink discards mail bodies. The driver tests bind/search and authenticated submission, renders and installs with private answers, checks doctor and the running digest, verifies the public wildcard certificate, signs in with the synthetic LDAP identity and triggers session elevation. A matching recipient and envelope ID in the sink are required. Repeat install must preserve Pod, PVC and Secret checksum; maintenance restart must replace the Pod and permit a new login against unchanged storage and keys.

`evidence.jsonl` records source hashes, UIDs, TLS fingerprint, envelope, verification stages and cleanup. A pass requires both `cleanup: pass` and `result: pass`. On ordinary failure the driver attempts cleanup before exiting; private diagnostic logs may be retained and are not publication artifacts. On interruption, inspect the journal: compare recorded namespace UIDs and contents before manually deleting either namespace, verify the recorded PV is absent, and remove private answers/keys. Never delete by name alone or rerun against an interrupted namespace.

This qualifies a fresh installation and same-version maintenance, **not** an image upgrade, MFA enrollment, or OIDC relying-party flow. Use [the separate disposable VM lab](../tests/lab/README.md) and [QA notes](qa.md) for that coverage. Do not run VM provisioning on a shared node. `tests/live.py --yes-disposable` deliberately deletes/restores the encryption Secret and is not part of this K3s runner.
