import json
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import cli

ROOT = pathlib.Path(__file__).resolve().parents[1]


class OperatorTests(unittest.TestCase):
    def test_manual_save_then_missing_install_hint(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            c = cli.defaults()
            c.update(ldap_password="fixture-only", ca_mode="manual")
            cli.save(p / "source.json", json.dumps(c).encode())
            saved = subprocess.run(
                [
                    str(ROOT / "configure.sh"),
                    "--from-answers",
                    str(p / "source.json"),
                    "--config",
                    str(p / "config.json"),
                    "--no-install",
                ],
                capture_output=True,
            )
            self.assertEqual(saved.returncode, 0)
            installed = subprocess.run(
                [str(ROOT / "install.sh"), "--config", str(p / "config.json")], capture_output=True
            )
            self.assertEqual(installed.returncode, 1)
            self.assertIn(str(p / "ldap-ca.pem"), installed.stderr.decode())
            self.assertIn("Place", installed.stderr.decode())
            self.assertNotIn("[2/5]", installed.stdout.decode())

    def test_ctrl_c_without_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.Popen(
                [
                    str(ROOT / "configure.sh"),
                    "--config",
                    str(pathlib.Path(td) / "config.json"),
                    "--no-install",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                time.sleep(0.3)
                proc.send_signal(signal.SIGINT)
                stdout, stderr = proc.communicate(timeout=5)
                self.assertEqual(proc.returncode, 130)
                self.assertIn(b"Cancelled", stderr)
                self.assertNotIn(b"Traceback", stdout + stderr)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()

    def test_exclusive_namespace_rejects_foreign_resources(self):
        c = cli.defaults()
        owned = {"kind": "Deployment", "metadata": {"name": "authelia", "labels": cli.LABEL}}
        owned_pod = {"kind": "Pod", "metadata": {"name": "authelia-abc", "labels": cli.LABEL}}
        baseline = [
            {"kind": "ConfigMap", "metadata": {"name": "kube-root-ca.crt", "labels": {}}},
            {"kind": "ServiceAccount", "metadata": {"name": "default", "labels": {}}},
            owned,
            owned_pod,
        ]
        with patch.object(cli, "kube", return_value=json.dumps({"items": baseline}).encode()):
            cli.exclusive_namespace(c)
        foreign = {"kind": "Deployment", "metadata": {"name": "other-app", "labels": {}}}
        with patch.object(cli, "kube", return_value=json.dumps({"items": [foreign]}).encode()):
            with self.assertRaisesRegex(ValueError, "namespace is not exclusive"):
                cli.exclusive_namespace(c)

    def test_oidc_rejects_unsafe_registry(self):
        c = cli.defaults()
        c.update(
            ldap_password="fixture",
            oidc_policies={"staff": {"group": "sysadmins", "policy": "two_factor"}},
            oidc_clients=[
                {
                    "client_id": "app",
                    "redirect_uris": ["https://app.example.com/callback"],
                    "authorization_policy": "staff",
                }
            ],
        )
        cli.validate(c)
        for field, value in [
            ("redirect_uris", ["http://app.example.com/callback"]),
            ("redirect_uris", ["https://*.example.com/callback"]),
            ("authorization_policy", "one_factor"),
            ("require_pkce", "false"),
            ("client_secret", "do-not-accept"),
        ]:
            with self.subTest(field=field):
                bad = json.loads(json.dumps(c))
                bad["oidc_clients"][0][field] = value
                with self.assertRaises(ValueError):
                    cli.validate(bad)
