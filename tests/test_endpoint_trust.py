import hashlib
import pathlib
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import cli


class EndpointTrustTests(unittest.TestCase):
    def test_protocol_selection(self):
        for endpoint, starttls, protocol, port in [
            ("ldaps://ldap.example.com:1636", False, None, "1636"),
            ("ldap://ldap.example.com:1389", True, "ldap", "1389"),
            ("submissions://mail.example.com:1465", False, None, "1465"),
            ("submission://mail.example.com:1587", False, "smtp", "1587"),
        ]:
            with patch.object(cli, "run", return_value=b"chain") as run:
                self.assertEqual(cli.download_ca(endpoint, starttls), "chain")
                args = run.call_args.args[0]
                self.assertIn(endpoint.split("://")[1].split(":")[0] + ":" + port, args)
                self.assertIn("-servername", args)
                self.assertEqual("-starttls" in args, protocol is not None)
                if protocol:
                    self.assertIn(protocol, args)
        with self.assertRaises(ValueError):
            cli.download_ca("ldap://ldap.example.com", False)

    def test_fingerprint_pin_and_leaf_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            for name, ca in [("ca", "TRUE"), ("leaf", "FALSE")]:
                subprocess.run(
                    [
                        "openssl",
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-keyout",
                        str(p / (name + ".key")),
                        "-out",
                        str(p / name),
                        "-days",
                        "1",
                        "-subj",
                        "/CN=CA:TRUE",
                        "-addext",
                        "basicConstraints=critical,CA:" + ca,
                    ],
                    check=True,
                    capture_output=True,
                )
            with self.assertRaisesRegex(ValueError, "not a CA"):
                cli.validate_ca((p / "leaf").read_text())
            pem = (p / "ca").read_text()
            fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
            self.assertEqual(cli.select_ca(pem, fingerprint), pem.strip() + "\n")
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                cli.select_ca(pem, "0" * 64)
            with self.assertRaisesRegex(ValueError, "manual"):
                cli.select_ca((p / "leaf").read_text(), fingerprint)
            c = cli.defaults()
            c.update(
                ldap_password="fixture", smtp_ca_mode="manual", smtp_ca_file=str(p / "missing")
            )
            with patch.object(cli, "kube") as kube:
                with self.assertRaisesRegex(ValueError, "Place.*missing"):
                    cli.install(c)
                kube.assert_not_called()
