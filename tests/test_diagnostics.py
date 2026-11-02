import contextlib
import io
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import cli


class DiagnosticsTests(unittest.TestCase):
    def test_output_limit(self):
        with self.assertRaisesRegex(RuntimeError, "output limit"):
            cli.run(
                [sys.executable, "-c", "import os; os.write(1, b'x' * 20000)"], output_limit=1024
            )

    def test_classification_never_repeats_raw_log(self):
        message = cli.diagnostic_hint(
            "password=TOPSECRET x509: certificate signed by unknown authority provider=user"
        )
        self.assertIn("CA", message)
        self.assertIn("LDAP", message)
        self.assertNotIn("TOPSECRET", message)

    def test_bounded_command_and_safe_failure(self):
        with patch.object(
            cli.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, b"", b"password=TOPSECRET Forbidden"),
        ) as run:
            with self.assertRaisesRegex(RuntimeError, "RBAC") as error:
                cli.kube("-n", "authelia", "get", "pods")
            self.assertNotIn("TOPSECRET", str(error.exception))
            self.assertEqual(run.call_args.kwargs["timeout"], 45)
            self.assertIn("--request-timeout=20s", run.call_args.args[0])

    def test_rollout_fails_fast_with_ca_hint(self):
        c = cli.defaults()
        pods = {
            "items": [
                {
                    "metadata": {"name": "authelia-test"},
                    "status": {
                        "containerStatuses": [
                            {"ready": False, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}
                        ]
                    },
                }
            ]
        }
        import json

        with (
            patch.object(
                cli,
                "kube",
                side_effect=[
                    json.dumps(pods).encode(),
                    b"x509: certificate signed by unknown authority provider=user",
                ],
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            with self.assertRaisesRegex(RuntimeError, "LDAP.*CA"):
                cli.rollout(c)
        self.assertIn("Waiting", output.getvalue())
