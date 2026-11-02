# Validation evidence

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
- No Hermes deployment was modified or tested. Native OIDC provider/client support is a future extension, not a hidden implementation claim.
- OpenLDAP + Authelia TOTP was tested; FreeIPA OTP-control reuse, production directory-specific filtering and existing hardware keys were not.
- Internal forward-auth allow/default-deny was tested, not a complete downstream Hermes proxy/header/WebSocket integration or a production network-policy bypass audit.
- Static checks and source self-review were performed. An independent reviewer CLI/subagent was unavailable; this is not an independent security audit. Public CI is not configured in the initial repository.

## Cleanup evidence

The provider API returned **404** for the exact temporary server, temporary SSH key, and both automatically created primary IP resources. A second label-scoped enumeration returned **0 servers, 0 SSH keys, 0 primary IPs, 0 volumes and 0 firewalls** for the run. Cleanup completed before publication; no paid QA resource was left running.

The read-only `kube.hermes_setup` reference remained clean at
`63adf2a95c07de055dc1d5b011292e57d3b7885f`.
