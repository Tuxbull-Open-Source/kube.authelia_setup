# kube.authelia_setup

Set up **native single sign-on for web applications** with Authelia on Kubernetes/k3s. Applications supporting OpenID Connect redirect users to a central login portal, authenticate against your LDAP directory, and receive an authorization code at their registered callback. LDAP groups control which clients users may access; two-factor authentication is the recommended default.

For applications without OIDC, optional reverse-proxy forward authentication protects an explicit hostname/group. Gateway authentication alone does not replace application-local login.

## Configure → install → maintain → doctor

```bash
git clone https://github.com/Tuxbull-Open-Source/kube.authelia_setup.git
cd kube.authelia_setup
./configure.sh --no-install
./install.sh --render-only
# Inspect current_config/artifacts/resources.json (no passwords or signing keys).
./install.sh
./doctor.sh
./maintain.sh status
```

The interactive configurator saves private JSON (0600), then installs unless `--no-install` is used. Passwords are hidden. Blank answers preserve existing settings; `-` disables the optional forward-auth hostname. OIDC clients/policies are loaded from JSON files when prompted: start with [clients](examples/oidc-clients.json) and [policies](examples/oidc-policies.json), changing IDs and exact callback URLs for your applications. No application client secret is needed: this version supports **public authorization-code clients**, not confidential clients.

The [complete example](examples/config.json) contains sanitized FreeIPA settings: `idm01.sun.example.com`, `dc=example,dc=com`, bind DN `uid=authelia-bind,cn=users,cn=compat,dc=example,dc=com`, disabled-account filtering, and `uid`/`cn`/`mail` attributes. SMTP uses `submission://mail01.sun.example.com:587`, with example username/sender `send@example.com`. These are editable examples, not discovered settings or working credentials. AD and other directories need their own implementation, filters, DNs and attributes; the FreeIPA `nsAccountLock` filter is not portable to directories without that schema.

For automation, copy the example to a private path, set actual values, and run:

```bash
chmod 600 /secure/authelia.json
./configure.sh --from-answers /secure/authelia.json --no-install
./install.sh --config /secure/authelia.json
./doctor.sh --config /secure/authelia.json
```

Every script accepts `--config`; precedence is explicit `--config`, then `CONFIG_FILE`, then `current_config/config.json`. JSON is data, never sourced as shell code. Unknown fields/options fail. Existing values, inline CA bundles, and forward-auth rules are preserved. New fields acquire defaults **except `ingress_enabled`: a saved config without this field remains disabled**, avoiding silent exposure on upgrade.

## Portal Ingress routing (TLS remains operator-owned)

New interactive configs and the example enable **`ingress_enabled: true`**, with **`ingress_class: "traefik"`**. Install creates `networking.k8s.io/v1` Ingress `authelia` in the configured namespace: the host comes from the validated HTTPS `url`, path `/` with Prefix matching routes to Service `authelia:9091`. Choose the class of your existing controller; the installer does not install one.

**Provide working HTTPS termination before enabling routing.** The Ingress intentionally has no `spec.tls`, certificate Secret, issuer, ACME configuration or TLS annotations. Configure certificates/HTTPS at your external proxy or controller independently, including HTTP-to-HTTPS policy and trusted forwarding headers. A plain default k3s Traefik deployment does not by itself satisfy this HTTPS prerequisite. LDAP/SMTP CA trust is unrelated to public HTTPS.

For external routing, set `ingress_enabled: false`. Install omits the Ingress and removes only a previously installer-labelled `ingress/authelia` in the selected namespace; it never deletes unrelated or unlabelled routes, Services, Secrets or PVCs. `--render-only` performs no deletion. An unmanaged same-name Ingress is preserved when disabled and rejected before resource mutation when enabled; it is never adopted automatically.

**Upgrading:** old configs (including `--from-answers` files) without `ingress_enabled` load as false. Run `./configure.sh --no-install`, explicitly answer `true` at the routing prompt after preparing external HTTPS, select your class, inspect `./install.sh --render-only`, then install. Blank keeps the previous choice. Alternatively retain false and your existing external route. Do not create duplicate routes for the same hostname; see [operations](docs/operations.md).

## Native OIDC

Configure each application with:

- Issuer: your exact HTTPS portal origin, e.g. `https://sso.app.example.com`.
- Discovery: `https://sso.app.example.com/.well-known/openid-configuration`.
- Client ID: its configured `oidc_clients[].client_id`.
- Client authentication: `none`; authorization-code flow with **PKCE S256**.
- Callback: the exact registered HTTPS URI; wildcards, fragments and embedded credentials are rejected.
- Scopes: `openid profile email groups`; use the userinfo endpoint for identity/group claims.

`oidc_policies` maps arbitrary names to an explicit LDAP `group` and `policy` (`two_factor`, or explicitly `one_factor`). The renderer creates a default-deny OIDC policy with a group-restricted rule. Each client must reference one of these policies. These are independent of forward-auth access-control rules. Leave `protected_domain` empty for OIDC-only operation; the gateway then denies all requests.

Omitting `require_pkce` means **true**, with S256 enforced per client. Only for an application proven not to support PKCE, explicitly set `require_pkce: false` on that client. This disables its challenge requirement and is a security downgrade; it does not enable plain PKCE or weaken other clients. Prefer fixing the application's PKCE support. `one_factor` is likewise an explicit MFA opt-down.

Session/storage keys and OIDC HMAC/RSA signing keys are generated once into a Kubernetes Secret and preserved on reruns. Signing keys are mounted in a separate Secret-backed config, never placed in rendered artifacts or ConfigMaps. There is no automatic key rotation. Preserve the Secret with its matching PVC.

`cookie_domain` defaults to `app.example.com`, with 2h idle / 12h absolute lifetime and remember-me disabled. Use a distinct `cookie_name` for independent instances sharing a domain. The portal must be inside that cookie domain. OIDC callbacks can belong to other domains; application sessions have their own expiry and logout behavior.

## LDAP and SMTP CA trust

**This manages client trust, not public HTTPS certificates.** The operator still supplies public HTTPS termination. TLS verification is never disabled in Authelia.

Configure LDAP and SMTP independently:

| Mode | Behavior |
|---|---|
| `system` | Use the container's public CA trust. Appropriate for publicly trusted endpoints; no private CA file required. Legacy `ca_pem`, if populated, remains additive. |
| `manual` | Supply a verified PEM CA bundle at the exact path printed by configure. Saving a config with a missing file is allowed; install stops **before any Kubernetes calls or changes** until the file exists and validates. |
| `fetch` | Retrieve the chain presented by the configured LDAP/mail TLS endpoint, then require a CA certificate SHA256 fingerprint obtained independently from your administrator before accepting it. Existing files are reused and checked, never overwritten or silently refreshed. |

LDAP fields: `ca_mode`, `ca_file`, `ca_fingerprint`. SMTP fields: `smtp_ca_mode`, `smtp_ca_file`, `smtp_ca_fingerprint`. Relative file paths resolve beside the config file, by default **`current_config/ldap-ca.pem`** and **`current_config/smtp-ca.pem`**. Configure prints absolute paths. `--from-answers` preserves source-relative paths by resolving them before copying the config.

Fetch uses the configured hostname/port with SNI: `ldaps://` for implicit TLS, `ldap://` with `ldap_starttls: true` for LDAP StartTLS, `submissions://` for SMTP implicit TLS, and `submission://` (or `smtp://`) for SMTP STARTTLS. There is no plaintext fallback and no HTTP CA download/FreeIPA-specific distribution URL. A chain fetched from an untrusted connection is **discovery only**, not proof of authenticity. Interactive configure distinguishes fetched chains from reused local files, reports retrieval progress and the save destination, and lists numbered candidates with Subject, Issuer, expiry and SHA256. These identities are display aids, not proof of authenticity: enter the SHA256 value obtained through an independent trusted channel, never blindly copy a displayed candidate. It reports whether the matched CA was saved or the existing file was reused unchanged. Noninteractive fetch requires that value in the respective `*_fingerprint` field. A mismatch fails without saving the fetched CA.

Servers often omit their root CA, particularly AD servers. If the returned chain contains no valid CA, fetch fails with manual-mode guidance; it never substitutes an ordinary leaf certificate. Get the CA bundle through your directory/mail administrator's trusted channel. A SHA256 fingerprint is over the certificate's DER encoding (`openssl x509 -in trusted-ca.pem -noout -fingerprint -sha256`), not over the PEM file bytes.

Bundles must contain only parseable, nonexpired PEM certificates with `CA:TRUE`; private keys and leaf certificates are rejected. Fetch has a bounded subprocess timeout and a 1 MiB accepted-chain limit. Authelia verifies the endpoint hostname and chain at startup. Its single certificates directory means **the union of approved LDAP and SMTP CAs is trusted for both services**; separate input files are not isolated trust stores.

## Prerequisites and ownership

- Linux operator host: Bash, Python **3.10+**, `kubectl`, **OpenSSL** (CA inspection/fetch and RSA generation). Scripts install no packages.
- Existing k3s with a Ready node, healthy DNS and `rancher.io/local-path` storage. One non-root Authelia replica (`authelia/authelia:4.39.28`), Recreate strategy, 100m CPU / 128Mi memory request, 1 CPU / 512Mi limit.
- A dedicated namespace and kubeconfig permissions for Namespace, Deployment, Pod read/logs/exec, ConfigMap, Secret, Service, PVC and Ingress operations (including Ingress get/delete for disabled-route reconciliation), and StorageClass reads. Runtime pods have no Kubernetes API token. Existing unmanaged resources are refused before enabled-resource writes.
- External LDAP service account, real user/group/mail attributes and a working TLS SMTP relay. LDAP password reset is disabled; use a read-only service account.
- Operator-owned public DNS and HTTPS termination for the portal, reaching the installer-owned Ingress through your existing controller, or an external route to `authelia.authelia.svc.cluster.local:9091` when Ingress is disabled. Preserve Host/HTTPS forwarding and strip untrusted identity/forwarding headers. **Never expose 9091 directly to the Internet.**

Not installed or managed: k3s, ingress controllers, DNS, public TLS certificates/issuers, cert-manager, ACME, LDAP, SMTP, Redis, applications or Velero. No system services, cron jobs or reboot are performed. Kubernetes downloads the pinned image on first use. QA-only certificates and services live in the isolated [lab harness](tests/lab/README.md).

SQLite and encrypted factor data live on the 1Gi `authelia-data` PVC. **Not HA:** local-path is node-local; node loss can lose data. Its standard class does not support expansion. Sessions are in memory and are lost on pod restart. Backup/recovery is operator-owned through Velero; the product has no backup/restore commands and does not install/configure Velero.

## Operation and failure handling

Install prints flushed stages (trust, ownership/storage, dry-run, apply, rollout) and readiness progress. Kubernetes requests have a 20s request timeout and commands a 45s subprocess timeout; rollout checks are bounded to approximately five minutes plus any in-flight check. CrashLoop/image/config failures stop early. Classified hints cover CA/hostname, LDAP bind, SMTP, RBAC and connectivity failures without dumping potentially credential-bearing stderr/logs. Ctrl-C exits cleanly (130); a partial apply is not rolled back.

Reruns preserve keys and PVC identity; unchanged configuration does not restart the pod. Missing encryption Secret beside a PVC fails closed. Server-side dry-run precedes application writes; namespace creation can occur before that validation. See [operations](docs/operations.md), [security](docs/security.md), [OIDC integration](docs/oidc.md), [QA evidence](docs/qa.md), and [attribution](NOTICE.md).

```bash
./maintain.sh status
./maintain.sh restart
./doctor.sh
```

No automatic upgrade, key rotation, uninstall or PVC deletion. Review upstream migrations before changing the pinned image; changing it back does not undo a database migration.

## Tests

```bash
bash -n configure.sh install.sh maintain.sh doctor.sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts tests
ruff check scripts tests
ruff format --check scripts tests
```

Live/browser acceptance is separate from the local suite. Public CI is not configured. The disposable lab exercises real LDAP/SMTP, native OIDC callbacks, token validation, PKCE, group denial, MFA and reruns; it is not a claim of production FreeIPA/AD or application-specific cutover validation.
