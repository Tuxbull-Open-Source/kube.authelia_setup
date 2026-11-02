# Optional Hermes consumer example

Native public-client OIDC is now supported by this provider; see [generic integration](oidc.md). This repository does not configure a consumer application.

For an independently managed Dashboard and Web UI, register separate client IDs and their exact callbacks:

- Dashboard: `https://dashboard.app.example.com/auth/callback`
- Web UI: `https://webui.app.example.com/api/auth/oidc/callback`

Use the configured public portal origin as issuer, no client secret, and PKCE S256 where supported. Only if the exact application version cannot send a challenge, explicitly set its `require_pkce` to false; this is a compatibility/security exception, not the default. Group-restricted policies can use `one_factor` explicitly or the recommended `two_factor`.

Configure the consumer through its own supported configuration workflow. Validate both callbacks, signatures, issuer/audience/nonce, group decisions, application sessions, logout and actual chat/WebSocket behavior before cutover. The lab exercises generic browser callbacks with these path shapes, **not a deployed Hermes consumer**. No changes to that application's repository or an existing installation are made here.

Authelia-managed TOTP is not FreeIPA OTP reuse. Directory-specific OTP controls, disabled-account policy and production SMTP delivery remain operator acceptance tasks. Forward-auth remains a separate optional integration and does not replace native application login automatically.
