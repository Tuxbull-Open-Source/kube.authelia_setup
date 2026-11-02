import os

os.umask(0o077)
import base64
import hashlib
import hmac
import json
import pathlib
import struct
import time

from playwright.sync_api import expect, sync_playwright

P = pathlib.Path("/root/qa")
c = json.loads(pathlib.Path("/root/authelia/current_config/config.json").read_text())
creds = json.loads((P / "credentials.json").read_text())
secret = (P / "totp.secret").read_text()
period = 30
digits = 6
algorithm = "sha1"


def otp():
    d = hmac.new(
        base64.b32decode(secret + "=" * ((-len(secret)) % 8)),
        struct.pack(">Q", int(time.time()) // period),
        getattr(hashlib, algorithm),
    ).digest()
    off = d[-1] & 15
    return str((struct.unpack(">I", d[off : off + 4])[0] & 0x7FFFFFFF) % 10**digits).zfill(digits)


import subprocess

service_ip = subprocess.check_output(
    ["kubectl", "-n", "authelia", "get", "svc", "authelia", "-o", "jsonpath={.spec.clusterIP}"]
).decode()


def authz(page, target):
    cookies = "; ".join(x["name"] + "=" + x["value"] for x in page.context.cookies())
    response = page.request.get(
        "http://" + service_ip + ":9091/api/authz/forward-auth",
        headers={
            "Cookie": cookies,
            "X-Forwarded-Method": "GET",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": target,
            "X-Forwarded-Uri": "/",
        },
        max_redirects=0,
    )
    return response.status


with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    page = b.new_page(ignore_https_errors=True)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    def login():
        page.goto(c["url"])
        page.locator("#username-textfield").fill("qa")
        page.locator("#password-textfield").fill(creds["user"])
        page.locator('button[type="submit"]').click()
        expect(page.get_by_text("One-Time Password", exact=True)).to_be_visible()
        assert authz(page, c["protected_domain"]) != 200
        page.locator("input").first.press_sequentially(otp())
        expect(page.get_by_text("Authenticated", exact=True)).to_be_visible()
        assert authz(page, c["protected_domain"]) == 200

    login()
    print("PASS browser LDAP+TOTP, first-factor-only denial, forward-auth allow")
    assert authz(page, "denied." + c["cookie_domain"]) != 200
    print("PASS forward-auth default deny")
    page.screenshot(path=str(P / "authenticated-mfa.png"))
    page.get_by_role("button", name="Logout", exact=True).click()
    expect(page.locator("#username-textfield")).to_be_visible()
    assert authz(page, c["protected_domain"]) != 200
    print("PASS browser logout invalidates access")
    # Avoid TOTP replay protection; a fresh interval is required after logout.
    time.sleep(period - (time.time() % period) + 1)
    login()
    page.goto("about:blank")
    page.wait_for_timeout(33000)
    assert authz(page, c["protected_domain"]) != 200
    page.goto(c["url"])
    expect(page.locator("#username-textfield")).to_be_visible()
    print("PASS idle timeout after 30s")
    time.sleep(period - (time.time() % period) + 1)
    login()
    started = time.monotonic()
    while time.monotonic() - started < 125:
        page.wait_for_timeout(10000)
        if authz(page, c["protected_domain"]) != 200:
            break
    assert time.monotonic() - started >= 105
    assert authz(page, c["protected_domain"]) != 200
    page.reload()
    expect(page.locator("#username-textfield")).to_be_visible()
    print("PASS absolute timeout at 2m despite activity")
    assert not errors
    print("PASS zero browser JavaScript exceptions")
    b.close()
