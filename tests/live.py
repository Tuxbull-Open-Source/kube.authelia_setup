#!/usr/bin/env python3
"""Destructive integration checks: ONLY on an explicitly disposable namespace."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import cli


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", required=True)
    p.add_argument("--yes-disposable", action="store_true", required=True)
    args = p.parse_args()
    c = cli.load(args.config)
    cli.doctor(c)

    def snapshot():
        secret = cli.get(c, "secret", "authelia-secrets")
        pvc = cli.get(c, "pvc", "authelia-data")
        deployment = cli.get(c, "deployment", "authelia")
        return (
            hashlib.sha256(json.dumps(secret["data"], sort_keys=True).encode()).hexdigest(),
            pvc["metadata"]["uid"],
            deployment["spec"]["template"],
        )

    before = snapshot()
    cli.install(c)
    assert before == snapshot()
    print("PASS reinstall preserves secrets, PVC UID and pod template")
    original_secret = cli.get(c, "secret", "authelia-secrets")
    cli.kube("-n", c["namespace"], "delete", "secret", "authelia-secrets")
    try:
        try:
            cli.install(c)
        except ValueError:
            pass
        else:
            raise AssertionError("missing storage encryption key was regenerated")
    finally:
        cli.apply(
            cli.obj("Secret", "authelia-secrets", c, type="Opaque", data=original_secret["data"])
        )
    assert before == snapshot()
    print("PASS missing encryption key fails closed with existing PVC")
    with tempfile.TemporaryDirectory(dir=Path(args.config).parent, prefix="qa-") as td:
        d = Path(td)
        bad = dict(c)
        bad["url"] = "http://sso.example.com"
        cli.save(d / "invalid.json", json.dumps(bad).encode())
        result = subprocess.run(
            [str(cli.ROOT / "install.sh"), "--config", str(d / "invalid.json")],
            capture_output=True,
            check=False,
        )
        assert result.returncode != 0 and snapshot() == before
        print("PASS invalid configuration changes no application resources")
    cli.doctor(c)


if __name__ == "__main__":
    main()
