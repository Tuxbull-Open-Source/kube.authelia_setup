"""Disposable lab only: native OIDC browser callback and cryptographic validation."""

import base64
import hashlib
import json
import pathlib
import secrets
import subprocess
import sys
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, "/root/authelia/scripts")
import cli

P = pathlib.Path("/root/qa")
config_path = pathlib.Path("/root/authelia/current_config/config.json")
c = cli.load(config_path)
callbacks = {
    "dashboard": c["url"] + "/auth/callback",
    "webui": c["url"] + "/api/auth/oidc/callback",
    "legacy": c["url"] + "/auth/callback",
    "denied": c["url"] + "/auth/callback",
}
c.update(
    protected_domain="",
    session_idle="2h",
    session_max="12h",
    cookie_name="qa_native_session",
    oidc_policies={
        "staff": {"group": "authelia-users", "policy": "one_factor"},
        "restricted": {"group": "not-a-member", "policy": "one_factor"},
    },
    oidc_clients=[
        {
            "client_id": name,
            "redirect_uris": [callbacks[name]],
            "authorization_policy": policy,
            "require_pkce": pkce,
        }
        for name, policy, pkce in [
            ("dashboard", "staff", True),
            ("webui", "staff", True),
            ("legacy", "staff", False),
            ("denied", "restricted", True),
        ]
    ],
)
cli.save(config_path, json.dumps(c).encode())
cli.install(c)
cli.doctor(c)
creds = json.loads((P / "credentials.json").read_text())

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(ignore_https_errors=True)
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    discovery = page.request.get(c["url"] + "/.well-known/openid-configuration").json()
    assert discovery["issuer"] == c["url"]
    jwks = page.request.get(discovery["jwks_uri"]).json()
    assert jwks["keys"] and all("d" not in key for key in jwks["keys"])
    print("PASS OIDC discovery and public-only JWKS", flush=True)
    page.route(
        "**/auth/**callback?**",
        lambda route: route.fulfill(
            status=200, content_type="text/html", body="<h1>QA callback</h1>"
        ),
    )

    def request(client, pkce=True):
        verifier = secrets.token_urlsafe(48)
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        args = dict(
            client_id=client,
            redirect_uri=callbacks[client],
            response_type="code",
            scope="openid profile email groups",
            state=state,
            nonce=nonce,
        )
        if pkce:
            args.update(
                code_challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .decode()
                .rstrip("="),
                code_challenge_method="S256",
            )
        return args, verifier

    def finish(client, pkce=True, login=False):
        args, verifier = request(client, pkce)
        page.goto(discovery["authorization_endpoint"] + "?" + urlencode(args))
        if login:
            page.locator("#username-textfield").fill("qa")
            page.locator("#password-textfield").fill(creds["user"])
            page.locator('button[type="submit"]').click()
        # Consent is a real browser interaction, never bypassed in the provider.
        expect(
            page.get_by_role("heading", name="QA callback").or_(
                page.get_by_role("button", name="Accept", exact=True)
            )
        ).to_be_visible(timeout=15000)
        if urlparse(page.url).path != urlparse(callbacks[client]).path:
            page.get_by_role("button", name="Accept", exact=True).click()
        page.wait_for_url(callbacks[client] + "?**")
        result = parse_qs(urlparse(page.url).query)
        assert result["state"][0] == args["state"] and "code" in result
        data = dict(
            grant_type="authorization_code",
            client_id=client,
            redirect_uri=callbacks[client],
            code=result["code"][0],
        )
        if pkce:
            data["code_verifier"] = verifier
        token_response = page.request.post(discovery["token_endpoint"], form=data)
        assert token_response.status == 200, "token endpoint rejected valid code"
        token = token_response.json()
        key = jwt.PyJWK.from_dict(
            next(
                x
                for x in jwks["keys"]
                if x["kid"] == jwt.get_unverified_header(token["id_token"])["kid"]
            )
        ).key
        claims = jwt.decode(
            token["id_token"], key, algorithms=["RS256"], audience=client, issuer=c["url"]
        )
        assert claims["nonce"] == args["nonce"] and claims["sub"]
        userinfo = page.request.get(
            discovery["userinfo_endpoint"],
            headers={"Authorization": "Bearer " + token["access_token"]},
        )
        assert userinfo.status == 200 and "authelia-users" in userinfo.json()["groups"]
        assert page.request.post(discovery["token_endpoint"], form=data).status == 400
        return args, verifier

    finish("dashboard", login=True)
    print(
        "PASS browser LDAP login -> S256 callback -> token exchange; RS256 signature/issuer/audience/nonce, userinfo groups and code replay rejection",
        flush=True,
    )
    finish("webui")
    print("PASS second native application callback /api/auth/oidc/callback with S256", flush=True)
    finish("legacy", pkce=False)
    print("PASS explicit public-client compatibility override without PKCE", flush=True)
    args, _ = request("dashboard", False)
    page.goto(discovery["authorization_endpoint"] + "?" + urlencode(args))
    page.wait_for_timeout(1000)
    if page.get_by_role("button", name="Accept", exact=True).is_visible():
        page.get_by_role("button", name="Accept", exact=True).click()
        page.wait_for_timeout(1000)
    (P / "pkce-result.txt").write_text(page.url + "\n" + page.locator("body").inner_text())
    assert "code=" not in page.url
    logs = cli.kube("-n", c["namespace"], "logs", "deployment/authelia", "--since=20s").decode()
    assert "Clients must include a 'code_challenge'" in logs and "enforces PKCE" in logs
    print("PASS secure client rejects missing PKCE", flush=True)
    args, _ = request("denied")
    page.goto(discovery["authorization_endpoint"] + "?" + urlencode(args))
    page.wait_for_timeout(1500)
    assert "code=" not in page.url
    logs = cli.kube("-n", c["namespace"], "logs", "deployment/authelia", "--since=20s").decode()
    assert (
        "client with id 'denied' using policy 'restricted'" in logs
        and "is not authorized to use this client" in logs
    )
    print("PASS authenticated non-member denied by OIDC group policy", flush=True)
    args, _ = request("dashboard")
    args["redirect_uri"] = "https://not-registered.example.com/callback"
    response = page.request.get(
        discovery["authorization_endpoint"] + "?" + urlencode(args), max_redirects=0
    )
    assert "not-registered.example.com" not in response.headers.get("location", "")
    assert response.status in (400, 302, 303)
    assert not errors
    print("PASS unregistered callback rejected; zero browser JS exceptions", flush=True)
    browser.close()

subprocess.run(
    ["python3", "tests/live.py", "--config", str(config_path), "--yes-disposable"],
    check=True,
    cwd="/root/authelia",
)
print("PASS native OIDC reinstall preserves signing/HMAC/session/storage keys and PVC", flush=True)
