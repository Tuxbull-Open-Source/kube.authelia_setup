"""Disposable lab only: actual endpoint trust fetch + startup failure recovery."""

import hashlib
import pathlib
import socket
import ssl
import subprocess
import sys
import time

from aiosmtpd.controller import Controller

sys.path.insert(0, "/root/authelia/scripts")
import cli

P = pathlib.Path("/root/qa")
c = cli.load("/root/authelia/current_config/config.json")
pem = (P / "tls.crt").read_text()
pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(P / "tls.crt", P / "tls.key")


class Handler:
    async def handle_DATA(self, server, session, envelope):
        (P / "implicit-mail.eml").write_bytes(envelope.content)
        return "250 accepted"


implicit = Controller(Handler(), hostname="10.42.0.1", port=1465, ssl_context=context)
plain = Controller(Handler(), hostname="127.0.0.1", port=1588)
implicit.start()
plain.start()
try:
    for label, endpoint, starttls in [
        ("LDAPS", "ldaps://10.42.0.1:636", False),
        ("LDAP STARTTLS", "ldap://127.0.0.1:389", True),
        ("SMTP STARTTLS", "submission://10.42.0.1:587", False),
        ("SMTP implicit TLS", "submissions://10.42.0.1:1465", False),
    ]:
        chain = cli.download_ca(endpoint, starttls)
        assert cli.select_ca(chain, pin).strip() == pem.strip()
        try:
            cli.select_ca(chain, "0" * 64)
        except ValueError:
            pass
        else:
            raise AssertionError("wrong CA fingerprint accepted")
        print(
            "PASS actual " + label + " endpoint chain fetch and wrong fingerprint rejection",
            flush=True,
        )
    try:
        cli.download_ca("submission://127.0.0.1:1588")
    except ValueError:
        pass
    else:
        raise AssertionError("plaintext SMTP accepted")
    print("PASS SMTP without STARTTLS fails; no plaintext fallback", flush=True)

    # A real TLS endpoint presenting only a non-CA leaf must never become a trust anchor.
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(P / "leaf.key"),
            "-out",
            str(P / "leaf.crt"),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ],
        check=True,
        capture_output=True,
    )
    server = subprocess.Popen(
        [
            "openssl",
            "s_server",
            "-accept",
            "127.0.0.1:1636",
            "-cert",
            str(P / "leaf.crt"),
            "-key",
            str(P / "leaf.key"),
            "-quiet",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", 1636), timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        try:
            cli.select_ca(cli.download_ca("ldaps://127.0.0.1:1636"), pin)
        except ValueError as e:
            assert "manual" in str(e)
        else:
            raise AssertionError("leaf accepted as CA")
        print("PASS actual leaf-only TLS chain fails with manual-root guidance", flush=True)
    finally:
        server.terminate()
        server.wait(timeout=5)

    # Exercise the persisted endpoint fetch workflow against both real services.
    fetched = dict(
        c,
        ca_pem="",
        ca_mode="fetch",
        ca_file=str(P / "fetched-ldap.pem"),
        ca_fingerprint=pin,
        smtp_ca_mode="fetch",
        smtp_ca_file=str(P / "fetched-smtp.pem"),
        smtp_ca_fingerprint=pin,
    )
    cli.install(fetched)
    cli.install(fetched)
    print("PASS pinned LDAP/SMTP fetch installation and non-overwriting rerun", flush=True)

    # Unknown-CA reproducer: isolated second namespace, never the user's cluster.
    broken = dict(c, namespace="qa-ca-failure", ca_pem="", ca_mode="system", smtp_ca_mode="system")
    started = time.monotonic()
    try:
        cli.install(broken)
    except RuntimeError as e:
        assert "CA" in str(e) and "LDAP" in str(e), str(e)
        assert time.monotonic() - started < 180
        print("PASS real missing LDAP CA CrashLoop gets fast actionable diagnosis", flush=True)
    else:
        raise AssertionError("missing CA unexpectedly trusted")
    cli.install(dict(broken, ca_pem=pem))
    print("PASS supplying trusted CA recovers failed namespace", flush=True)

    # Verify Authelia SMTP implicit TLS startup and real delivery, not just chain discovery.
    implicit_config = dict(c, smtp_address="submissions://10.42.0.1:1465")
    cli.install(implicit_config)
    import smtplib

    trust = ssl.create_default_context(cafile=str(P / "tls.crt"))
    with smtplib.SMTP_SSL("10.42.0.1", 1465, context=trust, timeout=10) as smtp:
        smtp.sendmail(
            "send@example.com",
            ["qa@example.com"],
            "Subject: QA implicit TLS\r\n\r\nFixture notification",
        )
    assert (P / "implicit-mail.eml").is_file()
    print(
        "PASS Authelia SMTP implicit TLS startup and independent verified-TLS message delivery",
        flush=True,
    )
finally:
    cli.install(c)
    implicit.stop()
    plain.stop()
