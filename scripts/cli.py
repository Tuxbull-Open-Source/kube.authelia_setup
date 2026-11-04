#!/usr/bin/env python3
"""Operator CLI; never print credentials or subprocess inputs."""

import argparse
import base64
import fcntl
import getpass
import hashlib
import json
import os
import re
import resource
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

from setup import LABEL, ROOT, defaults, obj, render, validate


def run(args, data=None, timeout=45, output_limit=None):
    try:
        if output_limit is None:
            r = subprocess.run(
                args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
            )
        else:
            # Bound discovery output on disk AND in memory, including hostile peers.
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                r = subprocess.run(
                    args,
                    input=data,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=timeout,
                    preexec_fn=lambda: resource.setrlimit(
                        resource.RLIMIT_FSIZE, (output_limit, output_limit)
                    ),
                )
                if stdout.tell() >= output_limit or stderr.tell() >= output_limit:
                    raise RuntimeError("command output limit exceeded")
                stdout.seek(0)
                stderr.seek(0)
                r.stdout, r.stderr = stdout.read(), stderr.read()
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "command timed out (bounded wait); check connectivity and service health"
        ) from None
    if r.returncode:
        operation = next(
            (x for x in args[1:] if x in ("get", "apply", "exec", "rollout", "logs")), "operation"
        )
        raise RuntimeError(
            Path(args[0]).name
            + " "
            + operation
            + " failed: "
            + diagnostic_hint(r.stderr.decode(errors="replace"))
        )
    return r.stdout


def kube(*args, data=None):
    return run(["kubectl", "--request-timeout=20s", *args], data)


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


def validate_ca(pem):
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    if (
        not blocks
        or len(pem.encode()) > 1024 * 1024
        or re.sub(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", "", pem, flags=re.S
        ).strip()
    ):
        raise ValueError("CA bundle must contain only PEM CA certificates (maximum 1 MiB)")
    for block in blocks:
        try:
            text = run(
                ["openssl", "x509", "-noout", "-ext", "basicConstraints"], block.encode()
            ).decode()
            run(["openssl", "x509", "-noout", "-checkend", "0"], block.encode())
        except RuntimeError:
            raise ValueError("Invalid or expired PEM CA certificate") from None
        if "CA:TRUE" not in text:
            raise ValueError("Certificate is not a CA (Basic Constraints CA:TRUE required)")


def download_ca(endpoint, starttls=False):
    u = urlparse(endpoint)
    ports = {"ldaps": 636, "ldap": 389, "submissions": 465, "submission": 587, "smtp": 25}
    if (
        u.scheme not in ports
        or not u.hostname
        or u.username
        or u.password
        or (u.scheme == "ldap" and not starttls)
    ):
        raise ValueError("CA fetch requires LDAPS/LDAP StartTLS or SMTP TLS/STARTTLS")
    host = "[" + u.hostname + "]" if ":" in u.hostname else u.hostname
    args = [
        "openssl",
        "s_client",
        "-connect",
        host + ":" + str(u.port or ports[u.scheme]),
        "-servername",
        u.hostname,
        "-showcerts",
    ]
    if u.scheme in ("ldap", "smtp", "submission"):
        args += ["-starttls", "ldap" if u.scheme == "ldap" else "smtp"]
    try:
        # Discovery only: this untrusted chain is NEVER accepted without an out-of-band pin.
        output = run(args, b"", timeout=20, output_limit=1024 * 1024)
    except RuntimeError:
        raise ValueError(
            "TLS/STARTTLS chain fetch failed; check endpoint/protocol or use manual CA mode. No plaintext fallback."
        ) from None
    if len(output) > 1024 * 1024:
        raise ValueError("Certificate chain exceeds 1 MiB")
    return output.decode("ascii", errors="replace")


def ca_candidates(chain):
    candidates = []
    for block in re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", chain, re.S
    ):
        try:
            validate_ca(block)
        except ValueError:
            continue
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(block)).hexdigest()
        candidates.append((fingerprint, block + "\n"))
    if not candidates:
        raise ValueError(
            "Endpoint chain contains no usable CA (servers often omit the root). Use manual CA mode with your directory/mail administrator's verified CA bundle; a leaf certificate is not a CA."
        )
    return candidates


def select_ca(chain, fingerprint):
    fingerprint = fingerprint.replace(":", "").lower()
    for digest, pem in ca_candidates(chain):
        if digest == fingerprint:
            return pem
    raise ValueError(
        "CA fingerprint missing/mismatch. Independently verify the SHA256 fingerprint with the administrator, or use manual CA mode."
    )


def resolve_one_ca(c, prefix, endpoint, starttls=False):
    c = dict(c)
    if c[prefix + "ca_mode"] == "system":
        return ""
    path = Path(c[prefix + "ca_file"])
    hint = (
        "Place the independently verified PEM CA bundle at "
        + str(path)
        + "; then rerun install.sh with the same --config."
    )
    if path.is_symlink():
        raise ValueError("Refusing CA symlink. " + hint)
    if not path.exists() and c[prefix + "ca_mode"] == "fetch":
        pem = select_ca(download_ca(endpoint, starttls), c[prefix + "ca_fingerprint"])
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Exclusive creation: never overwrite a concurrently supplied trust anchor.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pem)
    if not path.is_file():
        raise ValueError(hint)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("CA bundle exceeds 1 MiB. " + hint)
    try:
        pem = path.read_text(encoding="ascii")
        validate_ca(pem)
    except (ValueError, OSError):
        raise ValueError("Invalid/unreadable CA bundle. " + hint) from None
    if c[prefix + "ca_mode"] == "fetch":
        pem = select_ca(pem, c[prefix + "ca_fingerprint"])
    return pem


def resolve_ca(c):
    c = dict(c)
    bundles = [c["ca_pem"]]
    if c["ca_pem"]:
        validate_ca(c["ca_pem"])
    bundles.append(resolve_one_ca(c, "", c["ldap_address"], c["ldap_starttls"]))
    bundles.append(resolve_one_ca(c, "smtp_", c["smtp_address"]))
    # Authelia has one shared certificates directory for LDAP and SMTP.
    c["ca_pem"] = "\n".join(x.strip() for x in bundles if x)
    return c


def load(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_mode & 0o077:
        raise ValueError("configuration must be a regular private file (chmod 600)")
    saved = json.loads(p.read_text())
    # Missing routing consent in older configs must never expose a deployment.
    c = defaults() | {"ingress_enabled": False} | saved
    validate(c)
    for field in ("ca_file", "smtp_ca_file"):
        if not Path(c[field]).is_absolute():
            c[field] = str((p.parent / c[field]).absolute())
    return c


def exclusive_namespace(c):
    """Reject any workload/configuration not owned by this installer.

    Kubernetes automatically creates the default ServiceAccount and
    kube-root-ca.crt ConfigMap. They are the only allowed unlabelled objects.
    """
    raw = kube(
        "-n",
        c["namespace"],
        "get",
        "deploy,statefulset,daemonset,job,cronjob,pod,service,ingress,pvc,configmap,secret,networkpolicy,role,rolebinding,serviceaccount",
        "-o",
        "json",
    )
    allowed = {("ConfigMap", "kube-root-ca.crt"), ("ServiceAccount", "default")}
    for item in json.loads(raw).get("items", []):
        identity = (item["kind"], item["metadata"]["name"])
        if identity in allowed:
            continue
        labels = item["metadata"].get("labels", {})
        if labels.get("app.kubernetes.io/managed-by") != LABEL["app.kubernetes.io/managed-by"]:
            raise ValueError(
                "namespace is not exclusive; refusing non-Authelia resource: "
                + item["kind"].lower()
                + "/"
                + item["metadata"]["name"]
            )


def ownership(c):
    resources = [
        ("namespace", c["namespace"]),
        ("pvc", "authelia-data"),
        ("secret", "authelia-secrets"),
        ("configmap", "authelia-config"),
        ("configmap", "authelia-ca"),
        ("deployment", "authelia"),
        ("service", "authelia"),
    ]
    resources += [("ingress", "authelia")] if c["ingress_enabled"] else []
    for kind, name in resources:
        d = get(c, kind, name)
        if (
            d
            and d["metadata"].get("labels", {}).get("app.kubernetes.io/managed-by")
            != LABEL["app.kubernetes.io/managed-by"]
        ):
            raise ValueError("refusing unmanaged resource: " + kind + "/" + name)


def reconcile_ingress(c):
    """Disable only our exact route; preconditions protect against replacement races."""
    if c["ingress_enabled"]:
        return
    route = get(c, "ingress", "authelia")
    if (
        not route
        or route["metadata"].get("labels", {}).get("app.kubernetes.io/managed-by")
        != LABEL["app.kubernetes.io/managed-by"]
    ):
        return
    metadata = route["metadata"]
    options = dict(
        apiVersion="v1",
        kind="DeleteOptions",
        preconditions={
            "uid": metadata["uid"],
            "resourceVersion": metadata["resourceVersion"],
        },
    )
    print("Removing installer-owned ingress/authelia (routing disabled)", flush=True)
    kube(
        "delete",
        "--raw",
        "/apis/networking.k8s.io/v1/namespaces/" + c["namespace"] + "/ingresses/authelia",
        "-f",
        "-",
        data=json.dumps(options).encode(),
    )


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
    established = bool(
        old and old.get("metadata", {}).get("annotations", {}).get("oidc-established") == "true"
    )
    if established and not {"oidc-hmac", "oidc.yml"} <= set(data):
        raise ValueError("Established OIDC keys missing; recover matching Secret, do not rotate")
    if c["oidc_clients"]:
        if "oidc-hmac" in data and "oidc.yml" not in data:
            raise ValueError("OIDC signing key missing; recover matching Secret, do not rotate")
        if "oidc.yml" not in data:
            key = run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
            )
            oidc = dict(
                jwks=[dict(key_id="authelia", algorithm="RS256", use="sig", key=key.decode())]
            )
            data["oidc.yml"] = base64.b64encode(
                json.dumps(dict(identity_providers=dict(oidc=oidc))).encode()
            ).decode()
            data["oidc-hmac"] = base64.b64encode(secrets.token_hex(32).encode()).decode()
        if "oidc-hmac" not in data:
            raise ValueError("OIDC HMAC key missing; recover matching Secret")
    secret = obj("Secret", "authelia-secrets", c, type="Opaque", data=data)
    if c["oidc_clients"] or established:
        secret["metadata"]["annotations"] = {"oidc-established": "true"}
    return secret


def diagnostic_hint(text):
    text = text.lower()
    if "x509" in text or "certificate" in text and "verify" in text:
        provider = "LDAP" if "ldap" in text or "provider=user" in text else "LDAP/SMTP"
        return (
            provider
            + " TLS CA/hostname verification failed. Configure manual or fingerprint-verified endpoint CA trust; verify server name and chain. Never disable TLS verification."
        )
    if "forbidden" in text or "unauthorized" in text:
        return "Kubernetes RBAC/authentication denied; check kubeconfig/context and required permissions."
    if "connection refused" in text or "timeout" in text or "no such host" in text:
        return "Connection/DNS failed; check endpoint, service, routing and firewall."
    if "invalid credentials" in text or "error code 49" in text or "result code 49" in text:
        return "LDAP bind rejected; verify service-account DN/password and account state privately."
    if "smtp" in text or "notifier" in text:
        return (
            "SMTP startup failed; verify TLS mode, CA, sender and relay authentication privately."
        )
    if "configuration" in text:
        return "Authelia configuration rejected; run validate-config and inspect logs privately."
    return "Inspect namespace events and application logs privately; raw output is withheld to protect credentials."


def rollout(c):
    deadline = time.monotonic() + 300
    print("Waiting for Authelia readiness (maximum 300s; checks every 5s)...", flush=True)
    while time.monotonic() < deadline:
        pods = json.loads(
            kube("-n", c["namespace"], "get", "pods", "-l", "app=authelia", "-o", "json")
        )["items"]
        for pod in pods:
            statuses = pod.get("status", {}).get("containerStatuses", [])
            for status in statuses:
                reason = status.get("state", {}).get("waiting", {}).get("reason", "")
                if reason in (
                    "CrashLoopBackOff",
                    "ImagePullBackOff",
                    "ErrImagePull",
                    "CreateContainerConfigError",
                ):
                    hint = (
                        "Check image availability, pull credentials, volumes and Secret references."
                    )
                    if reason == "CrashLoopBackOff":
                        try:
                            logs = kube(
                                "-n",
                                c["namespace"],
                                "logs",
                                pod["metadata"]["name"],
                                "--tail=60",
                                "--limit-bytes=16384",
                            )
                            hint = diagnostic_hint(logs.decode(errors="replace"))
                        except RuntimeError:
                            hint = "Inspect previous container logs privately."
                    raise RuntimeError(reason + ": " + hint)
        deployment = get(c, "deployment", "authelia")
        if deployment:
            state = deployment.get("status", {})
            if (
                state.get("observedGeneration", 0) >= deployment["metadata"].get("generation", 1)
                and state.get("updatedReplicas", 0) == 1
                and state.get("availableReplicas", 0) == 1
                and state.get("replicas", 0) == 1
            ):
                print("PASS Authelia ready", flush=True)
                return
        print("Waiting: deployment not ready; checking pod state...", flush=True)
        time.sleep(5)
    raise RuntimeError(
        "Readiness deadline exceeded. Check scheduling, PVC binding, events and private container logs in namespace "
        + c["namespace"]
    )


def install(c):
    validate(c)
    print("[1/5] Validating LDAP/SMTP CA trust before cluster changes", flush=True)
    c = resolve_ca(c)
    print("[2/5] Checking cluster storage and resource ownership", flush=True)
    sc = json.loads(kube("get", "storageclass", "local-path", "-o", "json"))
    if sc["provisioner"] != "rancher.io/local-path":
        raise ValueError("local-path must use rancher.io/local-path")
    ownership(c)
    docs = render(c)
    apply(docs[0])
    exclusive_namespace(c)
    s = secret_doc(
        c,
        get(c, "secret", "authelia-secrets"),
        data_exists=get(c, "pvc", "authelia-data") is not None,
    )
    deployment = next(d for d in docs if d["kind"] == "Deployment")
    deployment["spec"]["template"]["metadata"]["annotations"]["secrets-sha256"] = hashlib.sha256(
        json.dumps(s["data"], sort_keys=True).encode()
    ).hexdigest()
    print("[3/5] Server-side validation of application resources", flush=True)
    for d in [s, *docs[1:]]:
        apply(d, dry=True)
    print("[4/5] Applying resources (preserving existing keys and PVC)", flush=True)
    for d in [s, *docs[1:]]:
        apply(d)
    reconcile_ingress(c)
    print("[5/5] Checking rollout", flush=True)
    rollout(c)
    print("PASS install and rollout")


def doctor(c):
    ownership(c)
    exclusive_namespace(c)
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
        *(["--config", "/secrets/oidc.yml"] if c["oidc_clients"] else []),
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


def ca_details(pem):
    """Display-only identities; never evidence that a candidate is authentic."""
    try:
        details = run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate", "-nameopt", "RFC2253"],
            pem.encode(),
        ).decode("ascii", errors="backslashreplace")
    except RuntimeError:
        raise ValueError("Unable to inspect CA certificate identity; no CA saved.") from None
    labels = {"subject": "Subject", "issuer": "Issuer", "notAfter": "Expires"}
    lines = []
    for line in details.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in labels:
            # Keep untrusted certificate names from emitting terminal control characters.
            value = "".join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in value)
            lines.append("  " + labels[key] + ": " + value)
    return "\n".join(lines)


def configure_trust(c, path):
    print(
        "Trust is for LDAP/SMTP, not public HTTPS certificate provisioning. Endpoint chains may omit the root CA (common with AD).",
        flush=True,
    )
    for prefix, label, endpoint, starttls in (
        ("", "LDAP", c["ldap_address"], c["ldap_starttls"]),
        ("smtp_", "SMTP", c["smtp_address"], False),
    ):
        mode = (
            input(label + " CA trust: system / manual / fetch [" + c[prefix + "ca_mode"] + "]: ")
            or c[prefix + "ca_mode"]
        )
        if mode not in ("system", "manual", "fetch"):
            raise ValueError("choose system, manual or fetch")
        c[prefix + "ca_mode"] = mode
        if mode == "system":
            print(
                label
                + ": system trust (legacy ca_pem, if present, remains additive). Private CAs normally require manual/fetch.",
                flush=True,
            )
            continue
        field = prefix + "ca_file"
        value = input(label + " CA PEM file [" + c[field] + "]: ") or c[field]
        ca_path = Path(value)
        if not ca_path.is_absolute():
            ca_path = path.absolute().parent / ca_path
        c[field] = str(ca_path)
        if mode == "manual":
            print(
                "Place the independently verified "
                + label
                + " PEM CA bundle at "
                + str(ca_path)
                + ". Install stops before cluster changes if missing/invalid. Existing files are never overwritten.",
                flush=True,
            )
        if mode == "fetch":
            print(label + " CA save destination: " + str(ca_path), flush=True)
            if ca_path.is_file():
                print(
                    label
                    + ": Reading existing local CA file (no endpoint connection; never overwritten).",
                    flush=True,
                )
                chain = ca_path.read_text()
                source = "existing local CA file"
            else:
                print(
                    label
                    + ": Connecting to configured TLS endpoint to retrieve its certificate chain...",
                    flush=True,
                )
                chain = download_ca(endpoint, starttls)
                print(
                    label + ": Retrieved certificate chain (discovery only, not trusted).",
                    flush=True,
                )
                source = "retrieved endpoint chain"
            print(
                "CA candidates from "
                + source
                + ". Names and fingerprints shown here are not proof of authenticity. "
                "Compare with a SHA256 fingerprint from your administrator through an independent trusted channel; do not blindly copy a value below.",
                flush=True,
            )
            for number, (fingerprint, candidate) in enumerate(ca_candidates(chain), 1):
                print(
                    label
                    + " Candidate "
                    + str(number)
                    + " (UNTRUSTED until independently verified)\n"
                    + ca_details(candidate)
                    + "\n  SHA256: "
                    + fingerprint,
                    flush=True,
                )
            fingerprint = input(
                "Enter the SHA256 fingerprint obtained independently from your administrator (not merely copied above): "
            )
            pem = select_ca(chain, fingerprint)
            c[prefix + "ca_fingerprint"] = fingerprint
            if not ca_path.exists():
                ca_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                fd = os.open(ca_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(pem)
                print(label + ": Saved fingerprint-matched CA to " + str(ca_path), flush=True)
            else:
                print(
                    label
                    + ": Reused fingerprint-matched CA from "
                    + str(ca_path)
                    + " (file unchanged).",
                    flush=True,
                )


def configure(args):
    path = Path(args.config)
    if args.from_answers:
        c = load(args.from_answers)
    else:
        c = load(path) if path.exists() else defaults()
        if not path.exists():
            c["ca_mode"] = "manual"
        print(
            "FreeIPA example values are presets, not discovered settings. Edit for AD/custom LDAP. Native OIDC is configured independently of optional forward-auth.",
            flush=True,
        )
        for k in defaults():
            if k == "ingress_enabled":
                print(
                    "Ingress routing: new configs default true; legacy configs without this field remain false. "
                    "Requires an existing ingress controller and operator-provided HTTPS termination. "
                    "false removes only installer-owned ingress/authelia in this namespace on install; unrelated routes remain. "
                    "No certificates, TLS spec or controller are provisioned. Enter true/false; blank keeps.",
                    flush=True,
                )
            if k in (
                "ca_pem",
                "ca_mode",
                "ca_file",
                "ca_fingerprint",
                "smtp_ca_mode",
                "smtp_ca_file",
                "smtp_ca_fingerprint",
            ):
                continue
            if k == "protected_domain":
                value = input(
                    "Optional forward-auth hostname (blank keeps; '-' disables) [" + c[k] + "]: "
                )
                if value:
                    c[k] = "" if value == "-" else value
            elif k in ("oidc_clients", "oidc_policies"):
                value = input(
                    k
                    + " JSON file (blank keeps current; see examples/oidc-clients.json and oidc-policies.json): "
                )
                if value:
                    c[k] = json.loads(Path(value).read_text())
            elif k in ("ldap_password", "smtp_password"):
                value = getpass.getpass(k + " (blank keeps existing): ")
                if value:
                    c[k] = value
            else:
                value = input(k + " [" + str(c[k]) + "]: ")
                if value:
                    if isinstance(c[k], bool):
                        if value not in ("true", "false"):
                            raise ValueError("boolean must be true/false")
                        c[k] = value == "true"
                    else:
                        c[k] = value
        configure_trust(c, path)
    validate(c)
    save(path, json.dumps(c, indent=2).encode())
    print("PASS private configuration saved")
    if not args.no_install:
        install(load(path))


def main():
    os.umask(0o077)
    mode = sys.argv[1]
    p = argparse.ArgumentParser(
        prog=mode + ".sh",
        description="Standalone Authelia with configurable Ingress routing (new configs enabled; legacy configs opt in). TLS, ingress controller and LDAP/SMTP services remain operator-owned.",
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
                        dict(apiVersion="v1", kind="List", items=render(resolve_ca(c))), indent=2
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
            exclusive_namespace(c)
            kube("-n", c["namespace"], "rollout", "restart", "deployment/authelia")
            rollout(c)
            print("PASS restart")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(
            "\nCancelled. Existing cluster resources are preserved; installation may be partial. Rerun install/doctor with the same config.",
            file=sys.stderr,
        )
        sys.exit(130)
    except (
        ValueError,
        RuntimeError,
        OSError,
        KeyError,
        json.JSONDecodeError,
    ) as e:
        print("ERROR: " + str(e), file=sys.stderr)
        sys.exit(1)
