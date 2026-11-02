import contextlib
import hashlib
import io
import pathlib
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import cli


class TrustWizardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as td:
            cls.certs = []
            for name in ("Root", "Intermediate"):
                result = subprocess.run(
                    [
                        "openssl",
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-keyout",
                        str(pathlib.Path(td) / "key"),
                        "-days",
                        "1",
                        "-subj",
                        "/CN=Wizard Test " + name,
                        "-addext",
                        "basicConstraints=critical,CA:TRUE",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                cls.certs.append(result.stdout)
        cls.pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cls.certs[0])).hexdigest()

    def test_existing_file_candidates_have_identity_and_local_provenance(self):
        for prefix, answers in [
            ("", ["fetch", "", self.pin, "system"]),
            ("smtp_", ["system", "fetch", "", self.pin]),
        ]:
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as td:
                c = cli.defaults()
                ca = pathlib.Path(td) / c[prefix + "ca_file"]
                chain = "".join(self.certs)
                ca.write_text(chain)
                output = io.StringIO()
                with (
                    patch("builtins.input", side_effect=answers),
                    patch.object(cli, "download_ca") as download,
                    contextlib.redirect_stdout(output),
                ):
                    cli.configure_trust(c, pathlib.Path(td) / "config.json")
                text = output.getvalue()
                self.assertIn("existing local CA file", text)
                self.assertIn("no endpoint connection", text)
                self.assertIn("Reused", text)
                self.assertNotIn("presented", text)
                self.assertNotIn("Retrieved", text)
                self.assertIn("Candidate 1", text)
                self.assertIn("Candidate 2", text)
                self.assertIn("Subject: CN=Wizard Test Root", text)
                self.assertIn("Issuer: CN=Wizard Test Intermediate", text)
                self.assertIn("Expires:", text)
                self.assertIn("SHA256: " + self.pin, text)
                self.assertIn("not proof of authenticity", text)
                self.assertEqual(ca.read_text(), chain)
                download.assert_not_called()

    def test_fetch_guidance_is_not_manual_placement(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "config.json"
            c = cli.defaults()
            output = io.StringIO()
            with (
                patch("builtins.input", side_effect=["system", "fetch", "", self.pin]),
                patch.object(cli, "download_ca", return_value="".join(self.certs)) as download,
                contextlib.redirect_stdout(output),
            ):
                cli.configure_trust(c, path)
            text = output.getvalue()
            self.assertNotIn("Place the independently verified", text)
            self.assertIn("Connecting", text)
            self.assertIn("Retrieved", text)
            self.assertIn("Saved", text)
            self.assertIn(c["smtp_ca_file"], text)
            self.assertEqual(pathlib.Path(c["smtp_ca_file"]).read_text(), self.certs[0])
            download.assert_called_once_with(c["smtp_address"], False)

    def test_fetch_mismatch_does_not_save(self):
        with tempfile.TemporaryDirectory() as td:
            c = cli.defaults()
            output = io.StringIO()
            with (
                patch("builtins.input", side_effect=["system", "fetch", "", "0" * 64]),
                patch.object(cli, "download_ca", return_value="".join(self.certs)),
                contextlib.redirect_stdout(output),
                self.assertRaisesRegex(ValueError, "fingerprint missing/mismatch"),
            ):
                cli.configure_trust(c, pathlib.Path(td) / "config.json")
            self.assertFalse(pathlib.Path(c["smtp_ca_file"]).exists())
            self.assertNotIn("Saved", output.getvalue())

    def test_fetch_progress_is_flushed_before_network_call(self):
        with tempfile.TemporaryDirectory() as td:
            output = io.StringIO()

            def fetch(*args):
                self.assertIn("Connecting", output.getvalue())
                return "".join(self.certs)

            with (
                patch("builtins.input", side_effect=["fetch", "", self.pin, "system"]),
                patch.object(cli, "download_ca", side_effect=fetch),
                contextlib.redirect_stdout(output),
                patch("builtins.print", wraps=print) as printer,
            ):
                cli.configure_trust(cli.defaults(), pathlib.Path(td) / "config.json")
            for call in printer.call_args_list:
                self.assertTrue(call.kwargs.get("flush"))

    def test_identity_inspection_errors_do_not_leak_subprocess_output(self):
        with patch.object(cli, "run", side_effect=RuntimeError("sensitive stderr")):
            with self.assertRaisesRegex(ValueError, "Unable to inspect") as error:
                cli.ca_details(self.certs[0])
        self.assertNotIn("sensitive", str(error.exception))

    def test_manual_does_not_fetch(self):
        with tempfile.TemporaryDirectory() as td:
            output = io.StringIO()
            c = cli.defaults()
            with (
                patch("builtins.input", side_effect=["manual", "", "system"]),
                patch.object(cli, "download_ca") as download,
                contextlib.redirect_stdout(output),
            ):
                cli.configure_trust(c, pathlib.Path(td) / "config.json")
            self.assertIn("Place the independently verified LDAP PEM CA bundle", output.getvalue())
            self.assertNotIn("Connecting", output.getvalue())
            self.assertNotIn("Retrieved", output.getvalue())
            download.assert_not_called()
            self.assertFalse(pathlib.Path(c["ca_file"]).exists())
