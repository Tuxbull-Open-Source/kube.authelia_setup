# Application-native OpenID Connect

Register each application's exact client ID and HTTPS callback in `oidc_clients`; configure its issuer as the public Authelia origin. The [complete config](../examples/config.json) demonstrates two independent public clients and a group-restricted policy. Do not attach forward-auth middleware to the OIDC portal or its callbacks as a substitute for native OIDC.

```json
{
  "oidc_policies": {"staff": {"group": "sysadmins", "policy": "two_factor"}},
  "oidc_clients": [
    {"client_id": "dashboard", "redirect_uris": ["https://dashboard.app.example.com/auth/callback"], "authorization_policy": "staff", "require_pkce": true},
    {"client_id": "webui", "redirect_uris": ["https://webui.app.example.com/api/auth/oidc/callback"], "authorization_policy": "staff", "require_pkce": true}
  ]
}
```

Supported registry fields are `client_id`, optional `client_name`, `redirect_uris`, `authorization_policy`, and optional boolean `require_pkce` (default true). Unknown fields are rejected, including `client_secret`. Public clients use token endpoint authentication `none`, grant `authorization_code`, response `code`, and scopes `openid profile email groups`. The userinfo endpoint supplies profile/email/group claims. Clients must validate state, nonce, issuer, audience, expiry and ID-token signature themselves.

Policies map names to exactly `group` and `policy`; the renderer creates default-deny policies with one `subject: [[group:...]]` allow rule. Per-client policies can use `one_factor` explicitly, but this is not MFA. A client's OIDC policy does not inherit gateway rules or `allowed_group`.

For a legacy client without PKCE support, set `require_pkce: false` on that client only. The generated provider delegates enforcement to individual clients (`enforce_pkce: never`); every client without an explicit false override still has `require_pkce: true` and `pkce_challenge_method: S256`. Plain challenges remain disabled globally. This exception weakens authorization-code protection; document the exception and migrate the application to S256.

The operator owns application-side setup. Provider login does not prove the application consumes identity correctly, disables unwanted alternative login, protects its direct service endpoints, or handles its own session/logout/expiry correctly. Authelia logout does not invalidate an independent application's already-issued session.

## Acceptance

Test discovery/public JWKS; invalid and valid LDAP credentials; browser authorization and consent; exact callbacks; signed token issuer/audience/nonce; userinfo groups; code replay; missing/wrong PKCE; wrong callback; non-member denial; MFA when configured; session expiry/logout; and application-specific functionality. See the actual coverage and limits in [QA](qa.md).

Upstream references: [provider](https://www.authelia.com/configuration/identity-providers/openid-connect/provider/), [clients](https://www.authelia.com/configuration/identity-providers/openid-connect/clients/).
