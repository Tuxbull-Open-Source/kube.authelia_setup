"""Exercise the public installer entry points without a kubeconfig or real credentials."""

import json
import os
import secrets
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class QARenderTests(unittest.TestCase):
    def test_authenticated_submission_from_private_answers(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            answers = json.loads((ROOT / "examples/config.json").read_text())
            answers.update(
                namespace="authelia-qa-render",
                ingress_enabled=False,
                smtp_address="submission://smtp.fixture.example:587",
                smtp_sender="qa@example.test",
                smtp_username="qa@example.test",
                smtp_password=secrets.token_urlsafe(32),
                ldap_password=secrets.token_urlsafe(32),
                ca_mode="system",
                smtp_ca_mode="system",
            )
            src, cfg = run / "answers.json", run / "instance.json"
            src.touch(mode=0o600)
            src.write_text(json.dumps(answers))
            env = dict(os.environ, KUBECONFIG=str(run / "absent"))
            for args in (
                ["configure.sh", "--from-answers", str(src), "--no-install"],
                ["install.sh", "--render-only"],
            ):
                p = subprocess.run(
                    [str(ROOT / args[0]), *args[1:], "--config", str(cfg)],
                    env=env,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(p.returncode, 0, args[0])
                for key in ("smtp_password", "ldap_password"):
                    self.assertFalse(answers[key].encode() in p.stdout + p.stderr)
            self.assertEqual(cfg.stat().st_mode & 0o777, 0o600)
            raw = (run / "artifacts/resources.json").read_text()
            for key in ("smtp_password", "ldap_password"):
                self.assertFalse(answers[key] in raw)
            docs = json.loads(raw)["items"]
            self.assertFalse(any(d["kind"] in ("Ingress", "Secret") for d in docs))
            self.assertEqual(
                [d["metadata"]["name"] for d in docs if d["kind"] == "Namespace"],
                [answers["namespace"]],
            )
            for d in docs:
                if d["kind"] != "Namespace":
                    self.assertEqual(d["metadata"]["namespace"], answers["namespace"])
            cm = next(d for d in docs if d["metadata"]["name"] == "authelia-config")
            notifier = json.loads(cm["data"]["configuration.yml"])["notifier"]
            self.assertIn("smtp", notifier)
            self.assertNotIn("filesystem", notifier)
            smtp = notifier["smtp"]
            for key in ("address", "username", "sender"):
                self.assertEqual(smtp[key], answers["smtp_" + key])
            self.assertFalse(smtp["tls"]["skip_verify"])
            pod = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]
            container = next(c for c in pod["containers"] if c["name"] == "authelia")
            refs = {e["name"]: e.get("value") for e in container["env"]}
            self.assertEqual(refs["AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE"], "/secrets/smtp")
            mount = next(m for m in container["volumeMounts"] if m["mountPath"] == "/secrets")
            self.assertTrue(mount["readOnly"])
            volume = next(v for v in pod["volumes"] if v["name"] == mount["name"])
            self.assertEqual(volume["secret"]["secretName"], "authelia-secrets")
