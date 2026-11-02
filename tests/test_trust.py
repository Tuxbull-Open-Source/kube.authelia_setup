import hashlib
import json
import pathlib
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import cli


class TrustTests(unittest.TestCase):
    def test_manual_missing_stops_before_cluster(self):
        c = cli.defaults()
        c.update(ldap_password="fixture", ca_mode="manual", ca_file="/missing/ldap-ca.pem")
        with patch.object(cli, "kube") as kube:
            with self.assertRaisesRegex(ValueError, "Place.*ldap-ca.pem"):
                cli.install(c)
            kube.assert_not_called()

    def test_ca_validation_and_fetch(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(p / "key"),
                    "-out",
                    str(p / "ca"),
                    "-subj",
                    "/CN=Fixture",
                    "-days",
                    "1",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                ],
                check=True,
                capture_output=True,
            )
            pem = (p / "ca").read_text()
            cli.validate_ca(pem)
            for bad in ("", "not pem", pem + (p / "key").read_text()):
                with self.assertRaises(ValueError):
                    cli.validate_ca(bad)
            c = cli.defaults()
            c.update(
                ca_mode="fetch",
                ca_file=str(p / "download"),
                ca_fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest(),
            )
            with patch.object(cli, "download_ca", return_value=pem):
                self.assertEqual(cli.resolve_ca(c)["ca_pem"], pem.strip())
                self.assertEqual((p / "download").stat().st_mode & 0o777, 0o600)
            with patch.object(
                cli, "download_ca", side_effect=AssertionError("rerun must not fetch")
            ):
                self.assertEqual(cli.resolve_ca(c)["ca_pem"], pem.strip())
            c["ca_file"] = str(p / "new")
            with patch.object(cli, "download_ca", return_value="bad"):
                with self.assertRaises(ValueError):
                    cli.resolve_ca(c)
            self.assertFalse((p / "new").exists())

    def test_legacy_config_migration(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "config.json"
            c = cli.defaults()
            c["ldap_password"] = "fixture"
            for k in ("ca_mode", "ca_file", "ca_fingerprint"):
                c.pop(k, None)
            p.write_text(json.dumps(c))
            p.chmod(0o600)
            self.assertEqual(cli.load(p)["ca_mode"], "system")
