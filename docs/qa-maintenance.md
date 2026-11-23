# Native maintenance qualification — installer 0.2.0

This records a disposable synthetic test, not production certification. Runtime
qualification used executable revision
`c13133aac09cb8d248edc3f24d05f131ab0ebbfc`. Later release-documentation changes do
not imply a second deployment or different executable qualification.

## Environment and interface

- Disposable Ubuntu 24.04, K3s 1.36.4+k3s1, Velero 1.18.0 and Kopia.
- Existing Available fixture object-storage location; no production credentials.
- One exclusive installer-owned Authelia namespace and `authelia-data` claim.
- Synthetic LDAP and TLS SMTP dependencies outside the application namespace.
- Actual original Authelia **4.39.27**, installed from the prior installer revision;
  its Deployment initially used a tag-only image reference.
- One generated encrypted TOTP fixture record, a separate data marker and a
  synthetic public PKCE OIDC client. This does not change directory-owned MFA.
- Reviewed protected source staging, fixed system Python 3.12 and a non-root
  operator checkout. Application actions used the normal `maintain.sh` entrypoint.

## Executed transaction

1. Established healthy original application, successful real LDAP first-factor
   authentication, matching encrypted data/key state and the pre-checkpoint marker.
2. Enrolled the reviewed controller, ran `status`, and prepared
   `plan --latest-stable`. The target was Authelia 4.39.28 with a verified immutable
   registry reference.
3. Executed `upgrade EXACT_PLAN`: the native cold checkpoint completed with exactly
   one successful Kopia PVB and its successful-resume seal before installation.
   The worker reached `rollout-complete; application acceptance required`.
4. Verified the actual container binary was **4.39.28**, the original decrypted
   fixture factor and marker remained, and Secret data matched the baseline.
5. Changed only the synthetic factor and marker after the checkpoint. Injected an
   unavailable image into the disposable Deployment to represent a failed upgrade.
6. Executed `restore EXACT_GOOD_BACKUP --accept-data-loss` without repairing the
   failing application first. Its safety-only checkpoint completed, remained
   unsealed for normal eligibility, and did not require the failed image to start.
7. Native restore completed with a successful filesystem PVR, new namespace/PVC
   identities and the recorded original immutable image. The actual binary was
   again **4.39.27**; the earlier tag-only deployment did not require guessing a
   digest from the newer configuration.
8. Confirmed the original encrypted factor, matching Secret data and original
   marker were restored. Checked schema version, no schema upgrade pending,
   valid encryption key and the native encryption check's explicit SUCCESS marker.
9. Verified OIDC discovery/JWKS and a real LDAP first-factor login after restore
   (HTTP 200, status OK). Re-enrolled the replacement identities and ran `plan`
   without latest-stable: it retained the restored 4.39.27 pin.
10. `list-backups` accepted the good selected checkpoint and rejected both the
    earlier failed/unsealed checkpoint and the safety-only checkpoint.

No direct backup or data-copy workaround replaced the native transaction. Direct
fixture operations were limited to setup, synthetic test-data changes and explicit
fault injection. Manual availability recovery from an earlier failed test is
separately identified below; that failed operation was not counted as success.

## Failures caught before qualification

- The fixture LDAP daemon could not open its configuration under a root-home
  directory. Only fixture runtime paths were moved to normal LDAP service paths;
  AppArmor was not disabled or weakened.
- Kubernetes omits the false `volumeMount.readOnly` default. Planning now normalizes
  only that equivalent default; true/read-write changes, mount paths and subpaths
  still fail the protected contract.
- Native Velero metadata contains both preferred and version-qualified copies of
  the same Deployment. Archive inspection now accepts identical aliases and rejects
  conflicting objects; it does not weaken namespace or image-provenance checks.
- A failed archive check had been masked by a generic resume error. The original
  failure is now retained while writers remain stopped after safe helper cleanup.

The initial archive-validation attempt produced a completed but **unsealed** backup,
which remained ineligible. After verifying no helper/writer Pods and completed
volume upload, the existing baseline installer restored fixture availability.
A fresh reviewed candidate and fresh native plan then performed the complete
successful transaction above. The failed plan was not replayed or relabeled.

## Limits and operator review

- The safety-only checkpoint is forensic data protection, not a normal eligible
  application recovery point. Its failed workload was deliberately not resumed.
- This tests an intact owned namespace/PVC/key set with an unready application,
  not adoption of a foreign/missing namespace, missing keys or arbitrary node loss.
- Normal eligible checkpoints need ready workload image provenance and registry
  connectivity. Restore validates stored provenance offline; image pulls may still
  need an available registry or cache.
- This same-family patch test does not certify cross-family schema migrations,
  production directory policies, real mail delivery, browser MFA or every OIDC
  relying party. Discovery/JWKS is not a full authorization-code application test.
- Fixture logical data and matched keys are verified. Sample hashes/modes/ownership
  are not a complete filesystem audit of all possible operator data.
- Infrastructure and private evidence are retained outside Git for operator review;
  retention is not a claim of teardown. Production installations were not changed
  by this release preparation.
- Hosted CI verifies local contracts for its exact PR head, not this cluster run.
  Its status must be read separately before publication.

## Vendor references

- [Authelia storage schema information](https://www.authelia.com/reference/cli/authelia/authelia_storage_schema-info/)
- [Authelia storage encryption checks](https://www.authelia.com/reference/cli/authelia/authelia_storage_encryption_check/)
- [Authelia synthetic TOTP generation](https://www.authelia.com/reference/cli/authelia/authelia_storage_user_totp_generate/)
- [Velero filesystem backup](https://velero.io/docs/v1.18/file-system-backup/)
- [Velero restore resource modifiers](https://velero.io/docs/v1.18/restore-resource-modifiers/)
