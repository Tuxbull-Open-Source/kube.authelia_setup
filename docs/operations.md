# Operations and diagnostics

## Lifecycle and ownership

- `./maintain.sh status`: list workload, Service and PVC status.
- `./maintain.sh restart`: restart the one application deployment and wait for readiness.
- `./install.sh`: converge the configured image, configuration and credentials.
- `./doctor.sh`: verify ownership, rollout, one Ready pod, Bound PVC, upstream config validation and real internal HTTP health.

Use one trusted admin host and one config path per installation. Scripts use a nonblocking local lock on `<config>.lock`; **this is not a distributed lock**. Do not operate concurrently from multiple hosts or race a GitOps controller. Server-side apply uses field manager `kube-authelia` and never forces ownership conflicts.

Owned names are the configured namespace, `deployment/authelia`, `service/authelia`, `pvc/authelia-data`, `configmap/authelia-config`, optional `configmap/authelia-ca`, `secret/authelia-secrets`, and enabled `ingress/authelia`. Every non-baseline namespaced resource must carry the installer ownership label; foreign resources are rejected before application writes. Do not relabel another application's resources to bypass that protection.

### Ingress upgrades and disabling

New configs enable `ingress_enabled` with class `traefik`. Saved configs missing that field load as false, including noninteractive answer files; upgrade alone never enables exposure. Configure offers an explicit true/false prompt (blank preserves). After preparing operator-owned HTTPS and an existing controller, choose true and `ingress_class`, render/review, then install. The host is derived from `url`; no independent host override is needed. No TLS spec, certificates, issuers or controller are provisioned.

The installer creates and owns exactly one dedicated namespace. It refuses install, reconfigure, upgrade, doctor, or restart if the namespace contains any non-Authelia application/configuration resource. Kubernetes baseline `serviceaccount/default` and `configmap/kube-root-ca.crt` are the only unlabelled objects permitted. Do not place fixtures, databases, proxies, or any other workload in the Authelia namespace.

With `ingress_enabled: false`, install deliberately deletes only `ingress/authelia` in the configured namespace **if its `app.kubernetes.io/managed-by` label equals `kube.authelia_setup`**. It re-reads ownership immediately before deletion and sends UID and resourceVersion preconditions; concurrent replacement/modification fails rather than deleting a different object. No broad label prune is used. Other names/namespaces and an unlabelled same-name external route are untouched. Render-only merely omits the Ingress; run install to reconcile removal. Repeated disabled installs are safe. Service, keys and PVC remain available for externally managed routing.

Prepare an alternative route before disabling if continuity is required. Do not run two routes for the same hostname simultaneously. Enabling with an external same-name route fails before resource writes: deliberately migrate/rename that operator-owned route yourself, or keep routing disabled. Changing `url` or class updates the owned route; validate DNS, controller selection, HTTPS termination and a real login independently. Doctor checks internal health, not end-to-end external HTTPS. Namespace changes are not a migration and do not clean up the old namespace's route.

The installer does not install a scheduler, automatic upgrade job, backup tool, TLS component or Velero. **Backup and recovery are entirely operator-owned through Velero; this product has no backup/restore commands.** The operator is responsible for consistent PVC contents, the matching encryption Secret, private configuration, retention and recovery verification. No Velero installation, configuration or validation is performed here.

## Changes

To change LDAP/SMTP passwords, update the external service account under its normal rotation procedure, update the private config and rerun install. Verify actual authentication and notification delivery. Config and Secret hashes trigger a rollout only when necessary.

Session/storage keys are generated on first install and reused thereafter. OIDC HMAC and RSA signing keys are generated when OIDC is first enabled, then preserved (including across temporary disabling). An established OIDC Secret missing its key material fails closed. No private key appears in the non-secret render artifact. The installer refuses to generate replacements when a PVC exists but its encryption Secret is missing. Recover matching state through your operator-owned recovery process. Do not overwrite the storage key to "fix" a failed startup: that loses access to encrypted factors.

For an upgrade: review upstream release/migration notes, ensure your operator-owned protection/recovery procedure is ready, confirm the namespace remains exclusive, change `image` to an explicit tag/digest, then run install, doctor and real browser acceptance. Changing an image tag alone does not reverse a database migration.

Do not edit namespace or PVC size as an in-place migration. `local-path` is node-local, not HA, and its standard StorageClass does not support expansion. Monitor node disk space, pod restarts/readiness and external certificate expiry. In-memory sessions are lost on pod restart.

## Troubleshooting

Install prints flushed stage/readiness progress. Requests use a 20s Kubernetes timeout, a 45s process timeout and an approximately 300s readiness deadline. CrashLoop/image failures stop early with classified hints. Command failures omit raw stderr deliberately because Kubernetes validation errors can echo Secret payloads. Ctrl-C exits 130 without a traceback; changes already applied are preserved. Inspect privately:

```bash
kubectl -n authelia get pods,pvc
kubectl -n authelia get events --sort-by=.lastTimestamp
kubectl -n authelia logs deployment/authelia --tail=100
kubectl -n authelia logs deployment/authelia --previous --tail=100
```

Never publish raw credentials, LDAP DNs, email addresses or user details. Doctor does not prove external routing/TLS, authorization or mail receipt; perform those checks separately.

| Symptom | Check |
|---|---|
| PVC Pending | local-path provisioner, node disk/readiness, pod scheduling; WaitForFirstConsumer is normal before scheduling |
| x509 unknown authority / hostname | Select manual or fingerprint-verified endpoint CA trust for LDAP/SMTP; install validates files before cluster changes. Obtain missing roots independently; never bypass verification. |
| Missing manual CA file | Place the verified PEM CA bundle at the exact printed path (default current_config/ldap-ca.pem or smtp-ca.pem), then rerun with the same --config. |
| LDAP bind error 49 | Bind DN/password, account policy; production service account must be least privilege |
| User/group absent | Base DN, filters, attribute mapping and disabled-account filtering |
| SMTP startup fails | Relay authentication, CA, hostname/SAN, STARTTLS; never disable TLS checks |
| SMTP startup succeeds but no mail | Trigger real device enrollment and verify delivery; startup does not send a message |
| Legacy port conflicts with server.address | Keep `enableServiceLinks: false`; Kubernetes Service environment variables collide with Authelia names |
| Generic startup failure on read-only filesystem | Keep `server.disable_healthcheck: true`; this disables the Docker helper's `/app/.healthcheck.env` write, **not** the Kubernetes `/api/health` probes |
| Enrollment rate limited | Wait the reported delay; don't weaken production rate limits for repeated QA |
| Missing encryption Secret | Recover matching keys using the operator's process; no silent key regeneration |

## Stop or remove

To stop without deleting data:

```bash
kubectl -n authelia scale deployment/authelia --replicas=0
```

Permanent removal is a deliberate operator action outside the scripts. **Deleting the namespace/PVC with local-path's Delete reclaim policy destroys node-local data.** No installer or maintenance command deletes a PVC or namespace.
