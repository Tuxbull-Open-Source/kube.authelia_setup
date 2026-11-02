#!/usr/bin/env python3
"""Operator CLI; never print credentials or subprocess inputs."""

import argparse
import base64
import fcntl
import getpass
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from setup import LABEL, ROOT, defaults, obj, render, validate


def run(args, data=None):
    r = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode:
        raise RuntimeError(
            "command failed: "
            + args[0]
            + " "
            + (args[1] if len(args) > 1 else "")
            + " (inspect cluster events/logs privately)"
        )
    return r.stdout


def kube(*args, data=None):
    return run(["kubectl", *args], data)


def get(c, kind, name):
    raw = kube("-n", c["namespace"], "get", kind, name, "--ignore-not-found", "-o", "json")
    return json.loads(raw) if raw.strip() else None


def apply(doc, dry=False):
    kube(
        "apply",
        "--server-side",
        "--field-manager=kube-authelia",
        *(["--dry-run=server"] if dry else []),
        "-f",
        "-",
        data=json.dumps(doc).encode(),
    )


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("refusing symlink output")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".authelia-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_mode & 0o077:
        raise ValueError("configuration must be a regular private file (chmod 600)")
    c = json.loads(p.read_text())
    validate(c)
    return c


def ownership(c):
    for kind, name in [
        ("namespace", c["namespace"]),
        ("pvc", "authelia-data"),
        ("secret", "authelia-secrets"),
        ("configmap", "authelia-config"),
        ("configmap", "authelia-ca"),
        ("deployment", "authelia"),
        ("service", "authelia"),
    ]:
        d = get(c, kind, name)
        if (
            d
            and d["metadata"].get("labels", {}).get("app.kubernetes.io/managed-by")
            != LABEL["app.kubernetes.io/managed-by"]
        ):
            raise ValueError("refusing unmanaged resource: " + kind + "/" + name)


def secret_doc(c, old=None, data_exists=False):
    if data_exists and old is None:
        raise ValueError(
            "PVC exists but encryption Secret is missing; recover matching keys through the operator-owned process"
        )
    data = old["data"].copy() if old else {}
    for key in ("session", "storage"):
        if old and (key not in data or len(base64.b64decode(data[key])) < 32):
            raise ValueError(
                "existing encryption key missing/weak; recover matching keys, do not rotate"
            )
        if key not in data:
            data[key] = base64.b64encode(secrets.token_hex(32).encode()).decode()
    for key, val in [("ldap", c["ldap_password"]), ("smtp", c["smtp_password"])]:
        data[key] = base64.b64encode(val.encode()).decode()
    return obj("Secret", "authelia-secrets", c, type="Opaque", data=data)


def rollout(c):
    kube(
        "-n",
        c["namespace"],
        "rollout",
        "status",
        "deployment/authelia",
        "--timeout=300s",
    )


def install(c):
    validate(c)
    sc = json.loads(kube("get", "storageclass", "local-path", "-o", "json"))
    if sc["provisioner"] != "rancher.io/local-path":
        raise ValueError("local-path must use rancher.io/local-path")
    ownership(c)
    docs = render(c)
    apply(docs[0])
    s = secret_doc(
        c,
        get(c, "secret", "authelia-secrets"),
        data_exists=get(c, "pvc", "authelia-data") is not None,
    )
    docs[-1]["spec"]["template"]["metadata"]["annotations"]["secrets-sha256"] = hashlib.sha256(
        json.dumps(s["data"], sort_keys=True).encode()
    ).hexdigest()
    for d in [s, *docs[1:]]:
        apply(d, dry=True)
    for d in [s, *docs[1:]]:
        apply(d)
    rollout(c)
    print("PASS install and rollout")


def doctor(c):
    ownership(c)
    rollout(c)
    p = get(c, "pvc", "authelia-data")
    if not p or p["status"]["phase"] != "Bound":
        raise ValueError("PVC not Bound")
    pods = json.loads(
        kube("-n", c["namespace"], "get", "pods", "-l", "app=authelia", "-o", "json")
    )["items"]
    if len(pods) != 1:
        raise ValueError("expected one application pod")
    statuses = pods[0]["status"].get("containerStatuses", [])
    if not statuses or not all(s["ready"] for s in statuses):
        raise ValueError("container not ready")
    kube(
        "-n",
        c["namespace"],
        "exec",
        "deployment/authelia",
        "--",
        "authelia",
        "validate-config",
        "--config",
        "/config/configuration.yml",
    )
    kube(
        "-n",
        c["namespace"],
        "exec",
        "deployment/authelia",
        "--",
        "wget",
        "-qO-",
        "http://127.0.0.1:9091/api/health",
    )
    print("PASS ownership, rollout, PVC, configuration, internal HTTP health")
    print(
        "NOTE TLS, external routing, LDAP account policy and real notification delivery require operator acceptance"
    )


def configure(args):
    path = Path(args.config)
    if args.from_answers:
        c = load(args.from_answers)
    else:
        c = load(path) if path.exists() else defaults()
        for k in defaults():
            if k in ("ldap_password", "smtp_password"):
                value = getpass.getpass(k + " (blank keeps existing): ")
                if value:
                    c[k] = value
            elif k == "ca_pem":
                value = input("CA certificate file (blank keeps system/existing trust): ")
                if value:
                    c[k] = Path(value).read_text()
            else:
                value = input(k + " [" + str(c[k]) + "]: ")
                if value:
                    if isinstance(c[k], bool):
                        if value not in ("true", "false"):
                            raise ValueError("boolean must be true/false")
                        c[k] = value == "true"
                    else:
                        c[k] = value
    validate(c)
    save(path, json.dumps(c, indent=2).encode())
    print("PASS private configuration saved")
    if not args.no_install:
        install(c)


def main():
    os.umask(0o077)
    mode = sys.argv[1]
    p = argparse.ArgumentParser(
        prog=mode + ".sh",
        description="Standalone Authelia; TLS and LDAP/SMTP services remain operator-owned.",
    )
    p.add_argument(
        "--config",
        default=os.getenv("CONFIG_FILE", str(ROOT / "current_config/config.json")),
    )
    if mode == "configure":
        p.add_argument("--from-answers", metavar="PRIVATE_JSON")
        p.add_argument("--no-install", action="store_true")
    elif mode == "install":
        p.add_argument("--render-only", action="store_true")
    elif mode == "maintain":
        p.add_argument("action", choices=["status", "restart"])
    args = p.parse_args(sys.argv[2:])
    Path(args.config).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_fd = os.open(str(args.config) + ".lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if mode == "configure":
            configure(args)
            return
        c = load(args.config)
        if mode == "install":
            if args.render_only:
                out = Path(args.config).parent / "artifacts/resources.json"
                save(
                    out,
                    json.dumps(
                        dict(apiVersion="v1", kind="List", items=render(c)), indent=2
                    ).encode(),
                )
                print("PASS rendered non-secret resources")
            else:
                install(c)
        elif mode == "doctor":
            doctor(c)
        elif args.action == "status":
            print(
                kube("-n", c["namespace"], "get", "deploy,pods,svc,pvc").decode(),
                end="",
            )
        elif args.action == "restart":
            ownership(c)
            kube("-n", c["namespace"], "rollout", "restart", "deployment/authelia")
            rollout(c)
            print("PASS restart")


if __name__ == "__main__":
    try:
        main()
    except (
        ValueError,
        RuntimeError,
        OSError,
        KeyError,
        json.JSONDecodeError,
    ) as e:
        print("ERROR: " + str(e), file=sys.stderr)
        sys.exit(1)
