# Validation evidence

## Installer-owned Ingress follow-up — 2026-11-02

A new disposable Hetzner fsn1/cx23 Ubuntu **24.04.4 LTS** VM ran **k3s v1.34.1+k3s1**, standard Traefik/local-path, and Authelia **4.39.28** with isolated real LDAPS and SMTP STARTTLS fixtures. The final application container was Ready with restartCount=0 and image digest `sha256:bd97cff4fcbf715b5ff1f9ae286afbe6033afce385302520b0368122d43a6f54`.

**Local and VM unit suite:** 30 tests passed, including six Ingress tests covering enabled/disabled render, class/host/namespace/backend and exact no-TLS manifest, validation, legacy configuration, wizard opt-in guidance, pre-mutation ownership refusal, Deployment secret-hash targeting, and scoped deletion preconditions. Bash syntax, Python compileall, Ruff lint/format and diff whitespace checks passed locally.

**Actual disposable k3s acceptance** (`tests/lab/ingress.py --yes-disposable`):

- Installed a legacy config without the new routing fields: no Ingress was created.
- Explicitly enabled routing on that running installation: installer-owned `ingress/authelia` used Traefik, the configured portal Host and Service `authelia:9091`; no TLS spec. A real HTTP request with the portal Host through Traefik returned Authelia `/api/health` HTTP 200 and status OK.
- Enabling and repeating install preserved existing Secret data/UID, PVC UID and pod template; the repeated enabled install retained Ingress UID.
- Disabling removed the owned route through Kubernetes UID/resourceVersion-preconditioned deletion; the old Host then returned HTTP 404. Application state and an unrelated operator Ingress remained unchanged.
- Disabled installation preserved an unmanaged same-name Ingress. Enabling refused that ownership conflict and left the route and application state unchanged. Removing the disposable fixture conflict and re-enabling restored HTTP health.
- `tests/live.py` passed repeated-install stability, missing-encryption-Secret fail-closed behavior with an existing PVC, invalid-config no-mutation checks and doctor. Maintenance restart and final doctor passed.

The tested VM source hashes matched the local source exactly:

```text
d13dc1246c77dfc680f5730732c162407912898409a6f5790502880171a99627  scripts/cli.py
b056cc41bb9f259f2be79dba73f3835543158b4afc720412c79c7642d320343c  scripts/setup.py
ca62a1430bbd1cd7192de540e3d0923e16734aa3faa44accf6e1fd8151a18c1d  tests/lab/ingress.py
```

**Limits:** This follow-up verifies application routing via loopback HTTP with a Host header, not public HTTPS termination. Certificates, controller installation and HTTPS policy remain operator responsibilities. Browser MFA/OIDC flows were not rerun in this routing-only follow-up; their earlier evidence is retained below. Class customization is renderer-tested; live controller coverage is Traefik only. Source self-review was performed; no independent review agent or public CI was available. No user cluster, consumer repository, backup/restore or release was changed.

**Cleanup verified before publication:** exact temporary server, SSH key and both primary IPs returned API 404. Run-labelled enumeration returned zero servers, SSH keys, primary IPs, volumes and firewalls. No paid resource from this run remains.

The historical initial-publication statement below that the product creates no Ingress is superseded by this follow-up. TLS provisioning remains excluded.

---

## Native OIDC and trust-workflow follow-up — 2026-11-02

A new disposable Hetzner fsn1/cx23 Ubuntu 24.04.4 LTS x86_64 VM ran k3s v1.34.1+k3s1, Authelia 4.39.28 and Chromium 156.0.8078.4. Final pod: Ready, restartCount=0, image digest `sha256:bd97cff4fcbf715b5ff1f9ae286afbe6033afce385302520b0368122d43a6f54`.

**Local and lab unit suite:** 18 tests passed. Bash syntax, compileall, Ruff lint/format and git diff whitespace checks passed. Unit tests include private config replay/migration, unsafe OIDC registry rejection, stable keys, missing manual LDAP/SMTP CA paths before cluster calls, fingerprint mismatch and leaf rejection (including a spoofed `CA:TRUE` subject), output limits, safe diagnostics and Ctrl-C exit 130 without traceback.

**Actual live acceptance:**

- Browser LDAP login, both `/auth/callback` and `/api/auth/oidc/callback` with S256, authorization-code exchange, RS256 signature/issuer/audience/nonce validation, userinfo groups, and code replay rejection.
- Public discovery/JWKS without private key material; exact callback restriction; authenticated non-member denial; missing PKCE rejection; explicit per-client no-PKCE compatibility path. No browser JavaScript exceptions.
- Real endpoint chain fetch from LDAPS, LDAP StartTLS, SMTP STARTTLS and implicit SMTP TLS, including custom ports. Wrong fingerprints rejected. A real leaf-only TLS endpoint gives manual-CA guidance; a real SMTP server without STARTTLS fails without plaintext fallback.
- Persisted pinned LDAP/SMTP files install successfully and are reused without overwriting on rerun. Real missing-CA CrashLoop in a separate disposable namespace yields actionable LDAP CA guidance well before the five-minute deadline; supplying the correct CA recovers it.
- Authelia SMTP STARTTLS delivery through real browser enrollment and emailed-code/TOTP verification. Authelia implicit SMTP TLS startup and independent CA/hostname-verified SMTP message receipt.
- Reinstall preserves session/storage/OIDC HMAC/signing key data, PVC UID and unchanged pod template. Missing matching encryption Secret fails closed. Restart and doctor passed; portal HTTPS health passed with CA and hostname verification.
- The existing forward-auth/MFA harness also passed: invalid LDAP password rejection, LDAP+TOTP login, first-factor-only denial, allowed/default-denied gateway access, logout, 30s idle and 2m absolute expiry under activity.

The tested controller/renderer matched local source bytes exactly before cleanup:

```text
6224f2734cf9eeb88f1bbdc2d2b35291eff50c1c782b665fee2dd152bdebbd46  scripts/cli.py
626c7ca7a8ecc521e293e080834c839a7307fe0ebe3c018cb185d4773401d95e  scripts/setup.py
```

**Findings:** Authelia 4.39.28 rejects default-deny gateway configuration without any rules, so OIDC-only mode renders an explicit deny-all gateway rule. Some OIDC failures return to the authenticated portal; tests corroborate no code issuance with the provider's exact PKCE/group-denial log classification. A FreeIPA disabled-account filter cannot be applied unchanged to OpenLDAP without that attribute schema; the fixture now explicitly uses its own custom filter. CA validation inspects Basic Constraints itself rather than arbitrary certificate subject text.

**Limits:** These are generic test relying-party callbacks, not a deployed consumer application. No production FreeIPA/AD deployment, AD account policy, FreeIPA OTP reuse, real SMTP credentials/provider delivery or application-specific session/WebSocket cutover was exercised. The implicit-SMTP message probe uses an independent SMTP client; actual Authelia enrollment notification delivery was tested over STARTTLS. Wrong-verifier PKCE and twelve-hour endurance are not claimed. There is no public CI or independent security-review agent in this environment; checks include source self-review, not an independent audit. No product TLS provisioning or backup/restore was added.

**Cleanup:** Exact temporary server, SSH key and both primary IPs returned API 404; run-labelled enumeration returned zero servers, SSH keys, primary IPs, volumes and firewalls. No paid lab resources remain. Production namespaces and consumer repositories were not touched.

---

## Initial publication evidence

Final checks completed **2026-11-02**, before initial publication. Tests used real Kubernetes resources and Chromium; no simulated cluster or fabricated API responses.

## Environment

- Disposable Hetzner cx23, fsn1, x86_64, 2 vCPU / 4GB.
- Ubuntu **24.04.4 LTS**, k3s **v1.34.1+k3s1**, local-path provisioner and Traefik.
- Authelia **4.39.28**; observed image digest:
  `sha256:bd97cff4fcbf715b5ff1f9ae286afbe6033afce385302520b0368122d43a6f54`.
- Real Chromium **156.0.8078.4** via Playwright.
- Separate disposable OpenLDAP LDAPS fixture, STARTTLS SMTP sink and self-signed HTTPS harness. These are not product dependencies/deployments.

## Final local/static results

```text
bash -n configure.sh install.sh maintain.sh doctor.sh: PASS
python3 -m compileall -q scripts tests: PASS
python3 -m unittest discover -s tests -v: 5 tests, OK
ruff check scripts tests: All checks passed
ruff format --check scripts tests: 10 files already formatted
```

The unit suite checks CLI help/unknown options, private configuration replay/rendering, non-secret manifests, one replica/Recreate/ClusterIP/no TLS resources, TLS/namespace/session validation and key preservation/fail-closed behavior. It does not pretend to replace live tests.

## Final live results (after backup/restore removal)

```text
PASS ownership, rollout, PVC, configuration, internal HTTP health
PASS install and rollout
PASS reinstall preserves secrets, PVC UID and pod template
PASS missing encryption key fails closed with existing PVC
PASS invalid configuration changes no application resources
PASS restart
PASS browser LDAP+TOTP, first-factor-only denial, forward-auth allow
PASS forward-auth default deny
PASS browser logout invalidates access
PASS idle timeout after 30s
PASS absolute timeout at 2m despite activity
PASS zero browser JavaScript exceptions
PASS HTTPS health with CA and hostname verification
PASS final fresh-namespace install and repeated install
PASS product installs no Ingress/TLS harness
PASS temporary clean namespace deleted
PASS final maintenance help only status/restart
```

The final application container was **Ready with restartCount=0**. A separate fresh namespace was installed and reinstalled from the final product scripts, then deleted. The established instance retained its enrolled factor across reinstall/restart, verified by real MFA login afterward.

Browser enrollment also produced real evidence:

```text
PASS browser invalid LDAP password rejected
PASS real SMTP notification received
PASS browser enrollment completed without JS errors
```

SMTP verification included actual receipt, emailed-code verification and TOTP registration—not only a TCP connection or startup check. A real authenticated screenshot was captured and visually checked: Authelia's One-Time Password panel displayed a green check and “Authenticated”. Screenshots and raw private browser/API data are intentionally not published.

Session tests used 30s inactivity / 2m maximum for a bounded test. The production defaults are separately renderer-tested at 2h/12h, not an actual twelve-hour endurance run. The idle test leaves the portal inactive because portal polling itself can refresh activity.

## Issues found and corrected

- Disabled Kubernetes Service links to prevent `AUTHELIA_PORT` collisions with legacy Authelia configuration.
- Rendered remember-me disablement as integer `-1`, not an invalid duration string.
- Disabled only the upstream Docker healthcheck-file writer for the read-only filesystem; Kubernetes HTTP probes remain active.
- Accounted for real enrollment rate limiting and the current multi-step enrollment UI.
- Tested forward-auth directly on the trusted internal endpoint; externally supplied forwarded headers are correctly stripped by the QA ingress and cannot be used as an authorization test.

## Scope and limitations

- Backup/restore code, CLI options, dependencies and associated tests were **removed at the user's request**. Velero is entirely operator-owned; no Velero setup or recovery claim is made.
- No consumer application deployment was modified or tested. Native OIDC was absent at initial publication; the follow-up evidence above supersedes that original limitation.
- OpenLDAP + Authelia TOTP was tested; FreeIPA OTP-control reuse, production directory-specific filtering and existing hardware keys were not.
- Internal forward-auth allow/default-deny was tested, not a complete downstream Hermes proxy/header/WebSocket integration or a production network-policy bypass audit.
- Static checks and source self-review were performed. An independent reviewer CLI/subagent was unavailable; this is not an independent security audit. Public CI is not configured in the initial repository.

## Cleanup evidence

The provider API returned **404** for the exact temporary server, temporary SSH key, and both automatically created primary IP resources. A second label-scoped enumeration returned **0 servers, 0 SSH keys, 0 primary IPs, 0 volumes and 0 firewalls** for the run. Cleanup completed before publication; no paid QA resource was left running.

The read-only `kube.hermes_setup` reference remained clean at
`63adf2a95c07de055dc1d5b011292e57d3b7885f`.
