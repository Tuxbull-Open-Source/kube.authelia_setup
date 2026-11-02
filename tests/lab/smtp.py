import os

os.umask(0o077)
import asyncio
import pathlib
import ssl
import time

from aiosmtpd.controller import Controller

P = pathlib.Path("/root/qa")


class Handler:
    async def handle_DATA(self, server, session, envelope):
        (P / ("mail-" + str(time.time_ns()) + ".eml")).write_bytes(envelope.content)
        return "250 accepted"


ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ctx.load_cert_chain(P / "tls.crt", P / "tls.key")
c = Controller(Handler(), hostname="10.42.0.1", port=587, tls_context=ctx, require_starttls=True)
c.start()
asyncio.get_event_loop().run_forever()
