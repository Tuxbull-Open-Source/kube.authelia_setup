"""TLS/authentication mandatory; discard DATA, persist only the synthetic envelope."""

import hmac
import json
import signal
import ssl
import uuid
from pathlib import Path

from aiosmtpd.controller import Controller

P = Path("/qa")


def check(mechanism, login, password):
    return login == b"sender@example.test" and hmac.compare_digest(
        password, (P / "smtp").read_bytes()
    )


class Sink:
    async def handle_DATA(self, server, session, envelope):
        if not session.authenticated or not session.ssl:
            return "530 authentication and STARTTLS required"
        with open("/tmp/envelopes", "a") as f:
            print(json.dumps([uuid.uuid4().hex, envelope.mail_from, envelope.rcpt_tos]), file=f)
        return "250 accepted"


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(P / "leaf.pem", P / "leaf.key")
Controller(
    Sink(),
    hostname="0.0.0.0",
    port=1587,
    tls_context=ctx,
    require_starttls=True,
    auth_required=True,
    auth_callback=check,
).start()
signal.pause()
