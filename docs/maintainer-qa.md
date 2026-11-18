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

## Cluster qualification: what exists and what remains

[Lab instructions](../tests/lab/README.md) and [QA evidence](qa.md) cover the disposable-VM harness. Do not run its host provisioning on a shared k3s node. `tests/live.py --yes-disposable` is a **post-install** test that deletes and restores a QA encryption Secret, not an environment provisioner. There is not yet a Kubernetes-native one-command fixture runner. Implement it under `tests/k3s/`, outside the product scripts, with this acceptance contract:

1. Require an explicit approved context. Reserve two absent, unique names. Let the installer create the dedicated application namespace; create LDAP, SMTP sink and client in the fixture namespace. Use only synthetic accounts, service-DNS SAN certificates, ephemeral storage for helpers, ClusterIP and no external mail relay. Record cluster identity and resource UIDs for cleanup. Do not depend on a pre-created/shared namespace switch.
2. Prove LDAPS bind/search and authenticated STARTTLS against the fixtures. Generate a private answers file with the bind DN/password, member/group filters, sender/login/password, trusted public CA and test portal origin. No password on argv. Keep startup checks enabled. Do not pass raw random bytes to a text config template: generate printable secret values. Do not fetch production Secrets.
3. Run configure with `--from-answers`, `--config`, `--no-install`; then install `--render-only`, install, and doctor with that same explicit config path. Require Ready, correct digest, Bound PVC and internal health. Classify fresh current/previous logs privately; don't publish message bodies or session tokens. Fixture failure, render failure and process startup failure are different results.
4. For notifier changes, trigger a real Authelia notification and match the envelope in the authenticated TLS sink. For OIDC changes, use the fixture client to check callback, PKCE and group allow/deny. Verify repeat install preserves Pod/PVC identity and keys, then restart via maintain and verify login still works. On upgrade, preserve the matching data/key rollback checkpoint; an older image alone is not rollback.
5. On success **or failure**, remove only resources from the recorded run. Check namespace identity before deletion; refuse replacements or unexpected resources. Verify recorded QA PVs and both namespaces are absent and erase private run files. Make interrupted cleanup resumable. Record revision, digest, pass/fail/skipped for each gate, and cleanup result. A required skip or cleanup failure is not a pass.

Until that runner has passed on an authorized cluster, report local render results and live evidence separately. Historical QA is not evidence for a new revision.
