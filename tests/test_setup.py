import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class SetupTests(unittest.TestCase):
    def test_render_contract(self):
        self.assertTrue(
            (ROOT / "scripts/setup.py").exists(),
            "configuration renderer not implemented",
        )
        spec = importlib.util.spec_from_file_location("setup", ROOT / "scripts/setup.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        c = m.defaults()
        c.update(ldap_password="test-only", smtp_password="test-only")
        docs = m.render(c)
        kinds = [d["kind"] for d in docs]
        self.assertIn("PersistentVolumeClaim", kinds)
        self.assertNotIn("Ingress", kinds)
        self.assertNotIn("Certificate", kinds)
        deploy = next(d for d in docs if d["kind"] == "Deployment")
        self.assertFalse(deploy["spec"]["template"]["spec"].get("enableServiceLinks", True))
        config = json.loads(
            next(d for d in docs if d["kind"] == "ConfigMap")["data"]["configuration.yml"]
        )
        self.assertEqual(config["session"]["remember_me"], -1)
        self.assertTrue(config["server"].get("disable_healthcheck", False))
        self.assertEqual(deploy["spec"]["replicas"], 1)
        self.assertEqual(deploy["spec"]["strategy"]["type"], "Recreate")
        self.assertEqual(
            next(d for d in docs if d["kind"] == "Service")["spec"]["type"], "ClusterIP"
        )

    def test_validation_fails_closed(self):
        spec = importlib.util.spec_from_file_location("setup", ROOT / "scripts/setup.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        self.assertTrue(hasattr(m, "validate"), "validation not implemented")
        c = m.defaults()
        c["ldap_password"] = "test-only"
        m.validate(c)
        for field, value in [
            ("url", "http://sso.example.com"),
            ("namespace", "default"),
            ("ldap_address", "ldap://ldap.example.com"),
            ("session_idle", "99h"),
            ("policy", "bypass"),
            ("unknown", True),
        ]:
            with self.subTest(field=field):
                bad = dict(c)
                bad[field] = value
                with self.assertRaises(ValueError):
                    m.validate(bad)

    def test_cli_contract(self):
        import subprocess

        for script in ["configure.sh", "install.sh", "maintain.sh", "doctor.sh"]:
            self.assertTrue((ROOT / script).exists(), script + " missing")
            self.assertEqual(
                subprocess.run([str(ROOT / script), "--help"], capture_output=True).returncode,
                0,
            )
            self.assertNotEqual(
                subprocess.run([str(ROOT / script), "--bogus"], capture_output=True).returncode,
                0,
            )

    def test_secret_safety(self):
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        import cli

        c = cli.defaults()
        c["ldap_password"] = "qa-only"
        with self.assertRaises(ValueError):
            cli.secret_doc(c, None, data_exists=True)
        first = cli.secret_doc(c)
        self.assertEqual(first, cli.secret_doc(c, first))
        broken = json.loads(json.dumps(first))
        broken["data"].pop("storage")
        with self.assertRaises(ValueError):
            cli.secret_doc(c, broken)

    def test_configure_replay_and_private_render(self):
        import subprocess
        import sys
        import tempfile

        sys.path.insert(0, str(ROOT / "scripts"))
        import cli

        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = pathlib.Path(td)
            source = root / "answers.json"
            target = root / "output/config.json"
            config = cli.defaults()
            config["ldap_password"] = "literal-$()-quote-'value"
            source.write_text(json.dumps(config))
            source.chmod(0o600)
            subprocess.run(
                [
                    str(ROOT / "configure.sh"),
                    "--config",
                    str(target),
                    "--from-answers",
                    str(source),
                    "--no-install",
                ],
                check=True,
                capture_output=True,
            )
            self.assertEqual(json.loads(target.read_text()), config)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            subprocess.run(
                [str(ROOT / "install.sh"), "--config", str(target), "--render-only"],
                check=True,
                capture_output=True,
            )
            rendered = (target.parent / "artifacts/resources.json").read_text()
            self.assertNotIn(config["ldap_password"], rendered)
            self.assertNotIn('"kind": "Secret"', rendered)


if __name__ == "__main__":
    unittest.main()
