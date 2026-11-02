#!/usr/bin/env python3
"""Ingress acceptance on a fresh disposable VM with fixtures.py and smtp.py only."""

import argparse
import copy
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import cli


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yes-disposable", action="store_true", required=True)
    parser.parse_args()
    os.umask(0o077)
    fixture = Path("/root/qa")
    c = cli.defaults() | {
        "ldap_address": "ldaps://10.42.0.1:636",
        "ldap_implementation": "custom",
        "ldap_users_filter": "(&({username_attribute}={input})(objectClass=person))",
        "ldap_user": "cn=admin,dc=example,dc=com",
        "ldap_password": json.loads((fixture / "credentials.json").read_text())["bind"],
        "smtp_address": "submission://10.42.0.1:587",
        "ca_pem": (fixture / "tls.crt").read_text(),
    }
    path = cli.ROOT / "current_config/config.json"
    assert cli.get(c, "namespace", c["namespace"]) is None, "fresh disposable namespace required"
    legacy = dict(c)
    legacy.pop("ingress_enabled")
    legacy.pop("ingress_class")
    cli.save(path, json.dumps(legacy).encode())
    legacy = cli.load(path)
    assert legacy["ingress_enabled"] is False
    cli.install(legacy)
    assert cli.get(c, "ingress", "authelia") is None
    print("PASS legacy configuration does not expose an ingress")

    def snapshot():
        secret = cli.get(c, "secret", "authelia-secrets")
        pvc = cli.get(c, "pvc", "authelia-data")
        deployment = cli.get(c, "deployment", "authelia")
        return (
            secret["metadata"]["uid"],
            hashlib.sha256(json.dumps(secret["data"], sort_keys=True).encode()).hexdigest(),
            pvc["metadata"]["uid"],
            deployment["spec"]["template"],
        )

    def route_status(expected):
        request = urllib.request.Request(
            "http://127.0.0.1/api/health", headers={"Host": "sso.app.example.com"}
        )
        for _ in range(30):
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    status = response.status
                    if status == expected:
                        assert json.load(response)["status"] == "OK"
                        return
            except urllib.error.HTTPError as error:
                if error.code == expected:
                    return
            time.sleep(1)
        raise AssertionError("Ingress route did not reach expected HTTP status")

    before = snapshot()
    cli.save(path, json.dumps(c).encode())
    cli.install(c)
    assert snapshot() == before
    route = cli.get(c, "ingress", "authelia")
    assert route["spec"]["ingressClassName"] == "traefik"
    assert "tls" not in route["spec"]
    assert route["spec"]["rules"][0]["host"] == "sso.app.example.com"
    route_status(200)
    print("PASS installer-owned Host route returns real Authelia health; no TLS spec")
    cli.install(c)
    assert snapshot() == before
    assert cli.get(c, "ingress", "authelia")["metadata"]["uid"] == route["metadata"]["uid"]
    print("PASS enable and repeat install preserve Secret data/UID, PVC UID and pod template")

    external = copy.deepcopy(next(d for d in cli.render(c) if d["kind"] == "Ingress"))
    external["metadata"] = {"name": "operator-route", "namespace": c["namespace"]}
    external["spec"]["rules"][0]["host"] = "other.app.example.com"
    cli.apply(external)
    other = cli.get(c, "ingress", "operator-route")
    disabled = c | {"ingress_enabled": False}
    cli.install(disabled)
    assert cli.get(c, "ingress", "authelia") is None
    assert cli.get(c, "ingress", "operator-route") == other
    assert snapshot() == before
    route_status(404)
    print("PASS disabled removes owned route only, preserves application and unrelated ingress")

    external["metadata"]["name"] = "authelia"
    cli.apply(external)
    foreign = cli.get(c, "ingress", "authelia")
    cli.install(disabled)
    assert cli.get(c, "ingress", "authelia") == foreign
    try:
        cli.install(c)
    except ValueError as error:
        assert "unmanaged resource: ingress/authelia" in str(error)
    else:
        raise AssertionError("unmanaged ingress was adopted")
    assert cli.get(c, "ingress", "authelia") == foreign
    assert snapshot() == before
    print("PASS disabled preserves same-name external route; enabled refuses ownership conflict")
    # Only the explicitly created disposable fixture is removed here.
    cli.kube("-n", c["namespace"], "delete", "ingress", "authelia")
    cli.install(c)
    route_status(200)
    cli.doctor(c)
    print("PASS ingress acceptance complete")


if __name__ == "__main__":
    main()
