import os

os.umask(0o077)
import json
import pathlib
import time

from playwright.sync_api import expect, sync_playwright

P = pathlib.Path("/root/qa")
c = json.loads(pathlib.Path("/root/authelia/current_config/config.json").read_text())
creds = json.loads((P / "credentials.json").read_text())
with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    page = b.new_page(ignore_https_errors=True)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on(
        "response",
        lambda r: (
            (P / ("response-" + r.url.split("/")[-1] + ".json")).write_text(json.dumps(r.json()))
            if "/api/" in r.url and r.status == 200 and "json" in r.headers.get("content-type", "")
            else None
        ),
    )
    page.goto(c["url"])
    page.locator("#username-textfield").fill("qa")
    page.locator("#password-textfield").fill("deliberately-invalid-test-password")
    page.locator('button[type="submit"]').click()
    expect(page.get_by_role("heading", name="Incorrect username or password")).to_be_visible()
    print("PASS browser invalid LDAP password rejected")
    page.locator("#password-textfield").fill(creds["user"])
    page.locator('button[type="submit"]').click()
    page.wait_for_timeout(1800)
    page.screenshot(path=str(P / "authenticated.png"))
    assert not errors
    before = set(P.glob("mail-*.eml"))
    page.get_by_role("button", name="Register device", exact=True).click()
    page.get_by_role("button", name="Add", exact=True).first.click()
    page.wait_for_timeout(1500)
    after = set(P.glob("mail-*.eml"))
    assert len(after - before) == 1
    print("PASS real SMTP notification received")
    import email
    import email.policy
    import re

    msg = email.message_from_bytes(
        next(iter(after - before)).read_bytes(), policy=email.policy.default
    )
    text = msg.get_body(preferencelist=("plain",)).get_content()
    code = re.search(r"-{10,}\s+([A-Za-z0-9]{8})\s+-", text)[1]
    page.get_by_label("One-Time Code", exact=True).fill(code)
    page.get_by_role("button", name="Verify", exact=True).click()
    page.wait_for_timeout(1000)
    page.wait_for_timeout(2500)
    page.get_by_role("button", name="Next", exact=True).click()
    page.wait_for_timeout(800)
    page.get_by_role("button", name="Next", exact=True).click()
    page.wait_for_timeout(500)
    import base64
    import hashlib
    import hmac
    import struct
    import urllib.parse

    data = json.loads((P / "response-register.json").read_text())["data"]
    secret = data["base32_secret"]
    (P / "totp.secret").write_text(secret)
    params = urllib.parse.parse_qs(urllib.parse.urlparse(data["otpauth_url"]).query)
    period = int(params.get("period", ["30"])[0])
    digits = int(params.get("digits", ["6"])[0])
    algorithm = params.get("algorithm", ["SHA1"])[0].lower()
    digest = hmac.new(
        base64.b32decode(secret + "=" * ((-len(secret)) % 8)),
        struct.pack(">Q", int(time.time()) // period),
        getattr(hashlib, algorithm),
    ).digest()
    offset = digest[-1] & 15
    otp = str(
        (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 10**digits
    ).zfill(digits)
    page.get_by_role("dialog").locator("input").first.press_sequentially(otp)
    page.get_by_role("button", name="Next", exact=True).click()
    page.wait_for_timeout(1500)
    assert page.request.get(c["url"] + "/api/user/info").json()["data"]["has_totp"] is True
    assert not errors
    print("PASS browser enrollment completed without JS errors")
    b.close()
