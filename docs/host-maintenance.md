# Repository-owned Authelia maintenance

This is an unreleased lab-oriented maintenance candidate. Read the README warning.
All project-specific provisioning, coordination and recovery code lives in this
repository. Root-installed copies are derived from a reviewed commit, not separate
locally patched implementations. No Hermes controller or recovery module is used
at runtime.

## Scope and prerequisites

- One canonical checkout owns one configured Authelia namespace through its
  private `current_config/config.json`. No maintenance `--config`, namespace
  override, ambient context or second selector is accepted.
- Existing systemd, sudo rights, Git, kubectl, Velero, OpenSSL and ordinary Linux
  utilities are required. The fixed privileged interpreter is the protected,
  root-owned `/usr/bin/python3.12`; a user-writable virtualenv is not acceptable.
  Python 3.10+ still suffices for ordinary configure/install/doctor commands.
- Existing Velero **1.18+**, Kopia node-agent, Available storage location, and a
  supported dynamic Filesystem `authelia-data` claim are required. The product
  does not install Velero, create a bucket, distribute storage credentials or
  schedule backups.
- The configured namespace must contain only installer-owned application objects
  and Kubernetes baseline objects. Unmanaged writers/controllers are refused.
- Maintain external LDAP/SMTP, DNS, HTTPS and client integrations independently.
  Pause other installers/GitOps/manual changes to this instance during an operation.
- Backups and upgrades cause a service interruption. Cold backups stop writers;
  no request sessions are preserved by a stopped process. The recovery point does
  not include the external directory, SMTP service or other application namespaces.

Set these non-secret fields in the existing private configuration before enrollment:

```json
{
  "kubeconfig": "/etc/authelia-maintenance/kubeconfig",
  "velero_namespace": "velero",
  "velero_storage_location": "YOUR_EXISTING_LOCATION",
  "velero_backup_ttl": "720h"
}
```

This is a configuration **fragment**, not a replacement for the existing file.
Preserve all LDAP/SMTP settings, clients, issuer/cookie settings and CA inputs.
The kubeconfig must already exist as a protected root-owned regular file; the
provisioner checks its location and does not read, print or copy credential bytes.
CA inputs must be canonical regular files owned by the configuration owner,
without group/other write access. CA hashes are bound and drift is rejected.

## Administrator-reviewed bootstrap

Never run `sudo python scripts/provision_host.py` from an operator-writable checkout.
A checkout hash alone is not an administrator code review.

1. Review a clean committed source revision and its complete diff/tests.
2. Export public source as the ordinary operator:

   ```bash
   git --no-replace-objects archive --format=tar \
     --output=current_config/reviewed-source.tar FULL_REVIEWED_COMMIT
   ```

3. The administrator copies the archive into a root-only staging directory,
   independently verifies its provenance/digest and reviews the provisioner code.
   Preserve any existing installed Authelia control files under `/srv/backup`
   after checking free space and record the change in `/CHANGES.md`.
4. Install the reviewed module from protected administrator staging, not directly
   from the operator checkout. `/usr/local/libexec` must remain root-owned,
   protected from writes by other users and traversable (normally 0755). Do not
   make a shared executable directory 0700 or silently alter unrelated permissions.

   ```bash
   install -o root -g root -m 0755 \
     /root/authelia-reviewed/provision_host.py \
     /usr/local/libexec/authelia-provision-host.py

   /usr/local/libexec/authelia-provision-host.py \
     --stage-archive /root/authelia-reviewed/source.tar \
     --archive-sha256 ADMINISTRATOR_VERIFIED_SHA256 \
     --revision FULL_REVIEWED_COMMIT
   ```

   The digest is a review attestation, not a signature. Staging checks archive
   paths/types, commit metadata and content, rejects links/devices/duplicates and
   creates an immutable protected snapshot. Use the platform's normal SELinux
   labeling where applicable; never disable enforcement to execute these tools.
5. As the ordinary operator, from the instance's checkout:

   ```bash
   ./provision-host.sh --revision FULL_REVIEWED_COMMIT
   ./maintain.sh status
   ```

The launcher probes the installed provisioner's capability before enrollment.
Unsupported installed code fails before enrollment; an administrator must bootstrap
the reviewed replacement first. It does not rely on an old helper updating itself
through an incompatible first transaction.

Installed paths are Authelia-specific:

- `/usr/local/libexec/authelia-provision-host.py`
- `/usr/local/libexec/authelia-maintenance-v1.py`
- `/usr/local/lib/authelia-maintenance/<commit>/`
- `/etc/authelia-maintenance/`
- `/srv/backup/authelia-maintenance/`

No other application's helper is replaced. Enrollment preserves unrelated bindings,
checks active workers and uses an exclusive provisioning lock. Workers hold its
shared counterpart. Repeated unchanged enrollment is a no-change operation.

## Upgrade transaction

```bash
./maintain.sh plan --latest-stable
./maintain.sh upgrade EXACT_PREPARED_PLAN
./maintain.sh logs EXACT_OPERATION
```

`plan` queries the intended cluster, checks exact identity/ownership, snapshots the
private configuration and current resource contract, verifies the official stable
release and registry digest, and renders from reviewed code. It writes protected
host planning artifacts but changes no application resources. Without
`--latest-stable`, it resolves the configured image rather than selecting a new
release. Only same-major/minor, non-downgrade patch transitions are supported;
other migrations require separate qualification.

`upgrade` executes exactly that prepared plan, not a moving release tag. It refuses
source/configuration/CA/identity drift and consumed plans. A supervised host worker:

1. Takes a cold Velero checkpoint of the matching namespace resources and data PVC.
2. Requires exact one-volume completion, unchanged cold samples, resumed replicas
   and the successful-resume seal before continuing.
3. Rechecks the live contract and applies the existing installer without rotating
   encryption/session/OIDC keys or replacing the data claim.
4. Checks rollout, configuration/health, storage schema and encryption.
5. Persists the verified image pin in the authoritative private configuration.

The worker survives SSH disconnection and application restarts. A launcher response
`started` is not completion; inspect the durable phase with `logs`. Failed gates
retain private evidence and never automatically downgrade the image or database.
If rollout completed but configuration publication failed, inspect the recorded
phase and reconcile configuration instead of blindly replaying the installer.

## Backup and recovery

```bash
./maintain.sh backup
./maintain.sh logs EXACT_OPERATION
./maintain.sh list-backups
./maintain.sh restore EXACT_ELIGIBLE_BACKUP --accept-data-loss
./maintain.sh logs EXACT_OPERATION
```

Use the exact verified backup name, never a position such as "second newest".
Listing separates namespace selection, completion and eligibility; legacy or
otherwise unqualified Velero backups may be listed without being accepted by this
specialized recovery protocol. Completed alone is insufficient.

The independent pinned helper mounts only `authelia-data`, read-only. Sample output
contains hashes and modes/ownership, not private filenames or contents. Normal
restore-eligible checkpoints also require registry connectivity and a ready running
workload: the immutable image provenance must match its observed Pod image IDs.
This evidence is recorded at backup time, including for older tag-only installs.
Restore checks it offline and pins the restored Deployment to those recorded bytes;
it never invents a historical digest from the currently configured release.
Backup
includes the original Namespace metadata; other cluster-scoped resources are
explicitly excluded and the native metadata archive is inspected privately for
scope. The database and its matching Kubernetes encryption/signing keys belong to
one checkpoint.

Restore first creates a safety backup, then replaces only the bound namespace and
claim with the selected point. Subsequent writes are lost. Old claim bindings are
removed so storage is dynamically recreated. The PV resource type remains permitted
in Restore because Velero requires it to create filesystem PVRs, even though source
PV manifests are deliberately absent from the backup. Applications remain stopped
until volume completion, new identities, namespace metadata and samples match.
Unknown warning results or uncertain helpers keep the gate closed.

After successful recovery, explicitly re-enroll the new namespace/PVC identities:

```bash
./provision-host.sh --revision FULL_REVIEWED_COMMIT
./maintain.sh status
./doctor.sh
```

Inspect failure evidence before any retry. No automatic second namespace deletion
or blind schema downgrade is supported. An isolated fixture restore is not proof
that every production recovery point or external identity dependency is recoverable.

## Application acceptance and audit

Readiness is only one gate. Verify public health through the intended routing,
actual LDAP authentication, expected MFA ownership, OIDC discovery/JWKS and client
login separately. Preserve the existing user-factor arrangement; do not introduce
new TOTP enrollment into a deployment where the directory owns MFA.

`authelia storage schema-info` and `authelia storage encryption check` must run with
the existing container configuration/Secret-file environment. Do not print keys or
put credentials in arguments. Correct schema and successful encryption checks do
not by themselves prove browser login or mail delivery.

Control backups, job plans, stdout/stderr and failure artifacts are root-only.
They may contain private configuration and must not be copied into Git or public
issues. Native operations record `/CHANGES.md`; supplement them with actual
application acceptance and any operator-approved recovery limitations.
