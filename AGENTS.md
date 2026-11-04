# Repository instructions

This repository deploys a standalone Authelia identity service to Kubernetes or
k3s. It is a Kubernetes installer project, not an Ansible Galaxy role.

## Safety and ownership

- Treat the configured namespace as a managed cluster target. Do not test in a
  namespace containing a production Authelia deployment.
- Preserve the separation of responsibility: this project owns only its labelled
  Authelia Namespace, PVC, Deployment, Service, ConfigMaps, Secrets, and optional
  Ingress. DNS, public TLS, ingress-controller installation, LDAP, SMTP, and
  Velero remain operator-owned.
- Never commit configuration JSON containing real LDAP bind passwords, SMTP
  credentials, OIDC secrets, CA bundles, kubeconfigs, or private addresses.
- Never read, copy, or reuse existing Kubernetes Secret values to construct a QA
  deployment. Generate QA-only credentials and delete only the exact labelled
  QA resources after verification.
- Do not run `tests/live.py` outside an explicitly disposable installation: it
  intentionally deletes/recreates the encryption secret as a fail-closed test.

## Verification

Run before a PR:

```bash
bash -n configure.sh install.sh maintain.sh doctor.sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts tests
ruff check scripts tests
ruff format --check scripts tests
git diff --check
```

For an authorized cluster QA deployment, first inventory the namespace and
prove intended resource names are absent. Use a private mode-0600 config,
perform `--render-only`, install, run `doctor.sh`, verify a second unchanged
install, and delete only the exact installer-labelled resources created for the
QA run. Report LDAP/SMTP/MFA/OIDC acceptance separately unless a dedicated,
trusted QA fixture actually exercised it.
