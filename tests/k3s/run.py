#!/usr/bin/env python3
"""Live, disposable K3s installer qualification. Never supply production credentials."""

import argparse
import hashlib
import http.cookiejar
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURE = "alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f"
IMAGE = "authelia/authelia:4.39.28@sha256:a9931f4443882fcc43bc368bffd40b51ff1867045d46c8dc2e87fb2b03a32178"
p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--context", required=True)
p.add_argument("--domain", required=True, help="Approved wildcard HTTPS zone")
p.add_argument("--evidence", type=Path, required=True, help="New private directory")
a = p.parse_args()
if not __debug__:
    p.error("Python optimization disables QA assertions")
signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
os.umask(0o077)
e = a.evidence.resolve()
e.mkdir(mode=0o700)
t = e / "private"
t.mkdir()
os.chdir(t)
uid = secrets.token_hex(6)
app = "authelia-qa-" + uid
fix = "fixture-qa-" + uid
host = app + "." + a.domain
url = "https://" + host
service = "providers." + fix + ".svc.cluster.local"
ids = {}
phase = "preflight"


def log(**fields):
    with (e / "evidence.jsonl").open("a") as f:
        print(json.dumps(dict(at=time.strftime("%FT%TZ", time.gmtime()), **fields)), file=f)


def run(*args, data=None, timeout=180):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        # Private diagnostic, never Echo command arguments or Secret manifests.
        (t / "failure.log").write_bytes(result.stdout + result.stderr)
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}) in {phase}")
    return result.stdout.decode().strip()


def k(*args):
    return run("kubectl", "--context", a.context, *args)


def get(kind, name, ns=None, field="{.metadata.uid}"):
    return k(
        *(["-n", ns] if ns else []),
        "get",
        kind,
        name,
        "--ignore-not-found",
        "-o",
        "jsonpath=" + field,
    )


def create(kind, name, **fields):
    ns = {} if kind == "Namespace" else {"namespace": fix}
    doc = dict(
        apiVersion="networking.k8s.io/v1" if kind == "NetworkPolicy" else "v1",
        kind=kind,
        metadata=dict(name=name, labels={"qa-run": uid}, **ns),
        **fields,
    )
    return run(
        "kubectl",
        "--context",
        a.context,
        "create",
        "-f",
        "-",
        "-o",
        "jsonpath={.metadata.uid}",
        data=json.dumps(doc).encode(),
    )


def fixture_exec(*args):
    return k("-n", fix, "exec", "providers", "--", *args)


def product(name, *args):
    return run(str(ROOT / (name + ".sh")), "--config", str(t / "instance.json"), *args, timeout=260)


def https(path, body=None):
    req = urllib.request.Request(
        url + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Origin": url},
    )
    with client.open(req, timeout=12) as resp:
        if resp.url != url + path or resp.status != 200 or json.load(resp).get("status") != "OK":
            raise ValueError("Unexpected HTTPS result: " + path)


def identity():
    pod = json.loads(k("-n", app, "get", "pod", "-l", "app=authelia", "-o", "json"))["items"]
    assert len(pod) == 1
    obj = pod[0]
    return dict(
        pod=obj["metadata"]["uid"],
        image=obj["status"]["containerStatuses"][0]["imageID"],
        pvc=get("pvc", "authelia-data", app),
        pv=get("pvc", "authelia-data", app, "{.spec.volumeName}"),
        keyset=get(
            "deploy", "authelia", app, "{.spec.template.metadata.annotations.secrets-sha256}"
        ),
    )


def cert(*args):
    run("openssl", *args)


def scenario():
    global phase, client
    assert run("kubectl", "config", "current-context") == a.context
    assert not get("ns", app) and not get("ns", fix)
    hashes = {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [
            *ROOT.glob("*.sh"),
            ROOT / "scripts/setup.py",
            ROOT / "scripts/cli.py",
            ROOT / "examples/config.json",
            HERE / "fixture.sh",
            HERE / "run.py",
            HERE / "sink.py",
        ]
    }
    log(source_sha256=hashes)
    log(
        run=uid,
        app=app,
        fixture=fix,
        both_absent=True,
        cluster=k("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"),
        host=host,
    )
    phase = "fixtures"
    ids[fix] = create("Namespace", fix)
    log(namespace=fix, uid=ids[fix])
    create(
        "NetworkPolicy",
        "providers",
        spec={
            "podSelector": {},
            "policyTypes": ["Ingress"],
            "ingress": [
                {
                    "from": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {"kubernetes.io/metadata.name": app}
                            }
                        },
                        {"podSelector": {}},
                    ]
                }
            ],
        },
    )
    cert(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "2",
        "-subj",
        "/CN=QA CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    )
    cert(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "leaf.key",
        "-out",
        "leaf.csr",
        "-subj",
        "/CN=" + service,
    )
    Path("extensions").write_text(
        "subjectAltName=DNS:" + service + "\nextendedKeyUsage=serverAuth\n"
    )
    cert(
        "x509",
        "-req",
        "-in",
        "leaf.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        "extensions",
        "-out",
        "leaf.pem",
    )
    bind, smtp, user = (secrets.token_urlsafe(30) for _ in range(3))
    recipient = uid + "@example.test"
    dn = "cn=admin,dc=example,dc=com"
    ldif = f"""dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=qa,dc=example,dc=com
objectClass: inetOrgPerson
uid: qa
cn: QA
sn: User
mail: {recipient}
userPassword: {user}

dn: cn=staff,dc=example,dc=com
objectClass: groupOfNames
cn: staff
member: uid=qa,dc=example,dc=com
"""
    data = {n: Path(n).read_text() for n in ("ca.pem", "leaf.pem", "leaf.key")}
    data.update({n: (HERE / n).read_text() for n in ("fixture.sh", "sink.py")})
    data.update(bind=bind, smtp=smtp, **{"entries.ldif": ldif})
    create("Secret", "providers", stringData=data)
    create(
        "Service",
        "providers",
        spec={
            "selector": {"qa-run": uid},
            "ports": [dict(name="ldaps", port=1636), dict(name="smtp", port=1587)],
        },
    )
    create(
        "Pod",
        "providers",
        spec=dict(
            automountServiceAccountToken=False,
            restartPolicy="Never",
            containers=[
                dict(
                    name="providers",
                    image=FIXTURE,
                    command=["sh", "/qa/fixture.sh"],
                    securityContext={"allowPrivilegeEscalation": False},
                    resources={
                        "requests": {"cpu": "20m", "memory": "48Mi"},
                        "limits": {"cpu": "1", "memory": "256Mi", "ephemeral-storage": "256Mi"},
                    },
                    volumeMounts=[dict(name="qa", mountPath="/qa", readOnly=True)],
                    readinessProbe={"tcpSocket": {"port": 1587}, "periodSeconds": 2},
                )
            ],
            volumes=[dict(name="qa", secret={"secretName": "providers", "defaultMode": 256})],
        ),
    )
    k("wait", "-n", fix, "--for=condition=Ready", "pod/providers", "--timeout=85s")
    assert recipient in fixture_exec(
        "env",
        "LDAPTLS_CACERT=/qa/ca.pem",
        "ldapsearch",
        "-LLL",
        "-x",
        "-H",
        "ldaps://" + service + ":1636",
        "-D",
        dn,
        "-y",
        "/qa/bind",
        "-b",
        "dc=example,dc=com",
        "(uid=qa)",
        "mail",
    )
    fixture_exec(
        "python3",
        "-c",
        f"import smtplib,ssl,pathlib; s=smtplib.SMTP('{service}',1587,timeout=8); s.starttls(context=ssl.create_default_context(cafile='/qa/ca.pem')); s.login('sender@example.test',pathlib.Path('/qa/smtp').read_text()); s.quit()",
    )
    log(gate="fixtures", passed=True)
    phase = "configure-render"
    cfg = json.loads((ROOT / "examples/config.json").read_text())
    cfg.update(
        namespace=app,
        url=url,
        cookie_domain=host,
        image=IMAGE,
        oidc_clients=[],
        oidc_policies={},
        ldap_implementation="custom",
        ldap_users_filter="(&({username_attribute}={input})(objectClass=inetOrgPerson))",
        ldap_user=dn,
        ldap_password=bind,
        ldap_address="ldaps://" + service + ":1636",
        smtp_address="submission://" + service + ":1587",
        smtp_username="sender@example.test",
        smtp_sender="sender@example.test",
        smtp_password=smtp,
        ca_file=str(t / "ca.pem"),
        smtp_ca_mode="manual",
        smtp_ca_file=str(t / "ca.pem"),
    )
    Path("answers").write_text(json.dumps(cfg))
    product("configure", "--from-answers", str(t / "answers"), "--no-install")
    product("install", "--render-only")
    docs = json.loads(Path("artifacts/resources.json").read_text())["items"]
    assert all(
        d["metadata"].get("namespace") == app
        if d["kind"] != "Namespace"
        else d["metadata"]["name"] == app
        for d in docs
    )
    assert [
        rule["host"] for d in docs if d["kind"] == "Ingress" for rule in d["spec"]["rules"]
    ] == [host]
    log(gate=phase, passed=True)
    phase = "install"
    assert not get("ns", app)
    try:
        product("install")
    finally:
        ident = get("ns", app)
        if (
            ident
            and get("ns", app, field=r"{.metadata.labels.app\.kubernetes\.io/managed-by}")
            == "kube.authelia_setup"
        ):
            ids[app] = ident
            log(namespace=app, uid=ident)
    product("doctor")
    logs = k("-n", app, "logs", "deployment/authelia")
    counts = {
        level: logs.count("level=" + level) for level in ("warning", "error", "fatal", "panic")
    }
    log(gate="startup-log-review", counts=counts)
    assert not any(counts[key] for key in ("error", "fatal", "panic"))
    before = identity()
    log(gate="install-doctor", **before)
    assert (
        before["pvc"]
        and before["keyset"]
        and before["pv"]
        and IMAGE.split("@")[1] in before["image"]
    )
    phase = "https-notification"
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    for i in range(12):
        try:
            https("/api/health")
            break
        except Exception:
            if i == 11:
                raise
            time.sleep(2)
    with socket.create_connection((host, 443), timeout=10) as sock:
        with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
            assert ("DNS", "*." + a.domain) in tls.getpeercert()["subjectAltName"]
            log(
                gate="wildcard-https",
                protocol=tls.version(),
                leaf_sha256=hashlib.sha256(tls.getpeercert(True)).hexdigest(),
            )
    login = dict(username="qa", password=user, keepMeLoggedIn=False)
    https("/api/firstfactor", login)
    https("/api/user/session/elevation", {})
    for _ in range(10):
        rows = fixture_exec("sh", "-c", "test ! -e /tmp/envelopes || cat /tmp/envelopes")
        match = [
            v
            for v in map(json.loads, rows.splitlines())
            if v[1:] == ["sender@example.test", [recipient]]
        ]
        if match:
            break
        time.sleep(1)
    assert len(match) == 1
    log(gate=phase, envelope=match[0])
    phase = "repeat-install"
    product("install")
    assert before == identity()
    log(gate=phase, passed=True)
    phase = "maintenance"
    product("maintain", "status")
    product("maintain", "restart")
    product("doctor")
    after = identity()
    assert after["pod"] != before["pod"] and all(
        after[n] == before[n] for n in ("pv", "pvc", "image", "keyset")
    )
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    https("/api/firstfactor", login)
    log(gate=phase, **after)


def cleanup():
    pv = get("pvc", "authelia-data", app, "{.spec.volumeName}") if app in ids else ""
    for ns in (app, fix):
        if ns not in ids:
            continue
        assert ids[ns] == get("ns", ns)
        # Check names without fetching Secret values. Controllers inherit template labels.
        selector = (
            "qa-run!=" + uid if ns == fix else "app.kubernetes.io/managed-by!=kube.authelia_setup"
        )
        objects = k(
            "-n",
            ns,
            "get",
            "all,ingress,networkpolicy,pvc,secret,configmap,role,rolebinding,serviceaccount",
            "-l",
            selector,
            "-o",
            "name",
        ).splitlines()
        assert set(objects) <= {"serviceaccount/default", "configmap/kube-root-ca.crt"}, (
            "unowned resources: refusing deletion"
        )
        k("delete", "namespace", ns, "--timeout=100s")
        assert not get("ns", ns)
    if pv:
        for _ in range(40):
            if not get("pv", pv):
                break
            time.sleep(1)
        assert not get("pv", pv)
    log(cleanup="pass", namespaces=list(ids), pv=pv)


try:
    scenario()
except Exception as exc:
    log(failure=phase, error=type(exc).__name__)
    # Emit only bounded, redaction-reviewed classifications to the evidence journal.
    for ns, pod in ((fix, "providers"), (app, "deployment/authelia")):
        if ns in ids:
            try:
                (t / (ns + ".log")).write_text(k("logs", "-n", ns, pod, "--tail=60"))
            except Exception:
                pass
    raise
finally:
    cleanup()
    # On failure allow diagnostics to be reviewed on this private host only.
    for path in t.iterdir():
        if path.suffix == ".log":
            path.rename(e / path.name)
    shutil.rmtree(t)
log(result="pass")
