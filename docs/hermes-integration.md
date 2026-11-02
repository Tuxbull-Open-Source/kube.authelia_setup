# Future Hermes integration (no Hermes changes here)

`kube.authelia_setup` owns Authelia only. `kube.hermes_setup` continues to own Hermes workloads, application auth and its PVCs/Secrets. Public DNS, HTTPS/TLS and the reverse proxy remain operator-owned. Backup/recovery remains operator-owned via Velero.

Reference reviewed: [`kube.hermes_setup` main at cd557e1998dc4eea6b69143ff39067c9916fe161](https://github.com/Tuxbull-Open-Source/kube.hermes_setup/tree/cd557e1998dc4eea6b69143ff39067c9916fe161). Its native `external-oidc` wiring is implemented; `external-proxy` is documentation-only/fails closed. This repository does **not** change that implementation or enable either mode.

## Native OIDC: a future provider extension

```text
Browser -> Hermes -> Authelia OIDC redirect -> LDAP + MFA
        <- exact application callback <- authorization code + PKCE
```

The current standalone installer intentionally does **not** configure an OIDC provider, signing key or clients. Do not point Hermes at this portal and expect OIDC discovery to work. A future scoped extension must:

1. Add persistent Secret-backed OIDC HMAC and signing keys without silent rotation.
2. Add separate public authorization-code/PKCE clients, if compatible with the exact Hermes versions:
   - Dashboard client: `https://hermes-admin.example.com/auth/callback`
   - WebUI client: `https://hermes.example.com/api/auth/oidc/callback`
3. Restrict exact redirect URIs, require S256 PKCE, enforce an explicit LDAP group and MFA, and include required identity/group claims in ID tokens.
4. Align Authelia session lifetimes (default idle 2h / max 12h) with the independently operated Hermes application-session policy. Authelia logout/expiry does not automatically invalidate a separate application's already-issued session.
5. Configure Hermes through its own supported `configure.sh`/source-of-truth configuration in a separately authorized change. Remove weaker alternative local login only after verified cutover/rollback planning.
6. Test discovery, signature/issuer/audience/nonce, both callbacks, group denial, WebSockets/chat, direct-Service bypass, logout and expiry in real browsers.

Do not claim FreeIPA OTP reuse: Authelia's LDAP client must support the actual FreeIPA OTP control/enforcement mechanism, and password-only rejection plus replay/expired-code tests are required. This lab proves OpenLDAP live bind and Authelia-managed TOTP, not FreeIPA OTP.

## Forward-auth: available Authelia endpoint, not proven Hermes mode

```text
Browser -> trusted HTTPS proxy -> Authelia /api/authz/forward-auth
                              -> protected application only on allow
```

The [Traefik middleware example](../examples/forward-auth.yaml) targets `http://authelia.authelia.svc.cluster.local:9091/api/authz/forward-auth`. Apply it yourself to a separate application route only after adapting namespace, routing, trust and NetworkPolicy. Never put it on the Authelia portal itself.

The QA verifies Authelia's internal forward-auth endpoint: first-factor-only denied under two-factor policy, authenticated LDAP+TOTP allowed for the configured domain/group, unlisted domain denied. It does not prove a production proxy-to-Hermes cutover. Current Hermes `external-proxy` remains unsupported; do not disable its local auth or trust arbitrary `Remote-User` headers as a workaround.

## Upstream references

- [Authelia LDAP](https://www.authelia.com/configuration/first-factor/ldap/)
- [SMTP](https://www.authelia.com/configuration/notifications/smtp/)
- [OIDC provider configuration](https://www.authelia.com/configuration/identity-providers/openid-connect/provider/)
- [Traefik integration](https://www.authelia.com/integration/proxies/traefik/)
- [Existing Hermes SSO design](https://github.com/Tuxbull-Open-Source/kube.hermes_setup/blob/cd557e1998dc4eea6b69143ff39067c9916fe161/docs/authelia-freeipa-sso-overview.md)
