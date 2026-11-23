"""Keep private installation and recovery artifacts out of the Git index."""

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = (
    "current_config/config.json",
    ".private/answers.json",
    "configuration_answers",
    "backups/metadata.json",
    "nested/plans/operation.json",
    "nested/logs/worker.log",
    ".maintenance-state/binding.json",
    "kubeconfig",
    "nested/kubeconfig.fixture",
    "nested/kubeconfigs/cluster.yaml",
    ".kube/config",
    ".ssh/id_ed25519",
    ".env",
    ".env.private",
    "auth.json",
    "credentials.json",
    "config.json",
    "ldap-ca.pem",
    "private.key",
    "database.sqlite3",
    "database.sqlite3-wal",
    "state.db-shm",
    "metadata.tar.gz",
    "binding.json",
    "plan.json",
    "source-config-before.json",
    "protected-config-before.json",
    "backup-metadata.json",
    "replicas.json",
    "resume.json",
    "restore-result.json",
    "restore-state.json",
    "pvb.json",
    "pvr.json",
)


def ignored(paths):
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "-z", "--stdin"],
        input="\0".join(paths) + "\0",
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("Unable to verify Git ignore contract")
    return set(result.stdout.rstrip("\0").split("\0")) - {""}


class PrivateArtifacts(unittest.TestCase):
    def test_generated_private_paths_are_ignored(self):
        self.assertEqual(ignored(PRIVATE), set(PRIVATE))

    def test_sanitized_public_examples_remain_trackable(self):
        examples = ["examples/config.json", "examples/oidc-clients.json"]
        self.assertFalse(ignored(examples))

    def test_index_contains_no_ignored_private_artifacts(self):
        paths = (
            subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT, text=True)
            .rstrip("\0")
            .split("\0")
        )
        bad = ignored(paths)
        # A credential or session identifier can itself appear in a filename.
        self.assertFalse(
            bool(bad), f"{len(bad)} private artifact paths tracked; inspect the index privately"
        )


if __name__ == "__main__":
    unittest.main()
