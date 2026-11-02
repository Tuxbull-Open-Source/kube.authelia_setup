import os

os.umask(0o077)
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, "/root/authelia/scripts")
from setup import defaults

p = pathlib.Path("/root/qa")
host = sys.argv[1]
c = defaults()
c.update(
    ingress_enabled=False,  # The browser harness supplies its own QA-only HTTPS route.
    url="https://" + host,
    cookie_domain=host.removeprefix("sso."),
    protected_domain="app." + host.removeprefix("sso."),
    ldap_address="ldaps://10.42.0.1:636",
    ldap_implementation="custom",
    ldap_users_filter="(&({username_attribute}={input})(objectClass=person))",
    allowed_group="authelia-users",
    ldap_user="cn=admin,dc=example,dc=com",
    ldap_password=json.loads((p / "credentials.json").read_text())["bind"],
    smtp_address="submission://10.42.0.1:587",
    ca_pem=(p / "tls.crt").read_text(),
    policy="two_factor",
    session_idle="30s",
    session_max="2m",
)
q = pathlib.Path("/root/authelia/current_config")
q.mkdir(mode=0o700, exist_ok=True)
f = q / "config.json"
f.write_text(json.dumps(c, indent=2))
f.chmod(0o600)
subprocess.run(
    ["/root/authelia/configure.sh", "--from-answers", str(f), "--no-install"], check=True
)
subprocess.run(["/root/authelia/install.sh"], check=True)
subprocess.run(
    [
        "kubectl",
        "-n",
        "authelia",
        "create",
        "secret",
        "tls",
        "qa-tls",
        "--cert=" + str(p / "tls.crt"),
        "--key=" + str(p / "tls.key"),
    ],
    check=True,
)
ing = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "Ingress",
    "metadata": {
        "name": "qa-portal",
        "namespace": "authelia",
        "annotations": {"traefik.ingress.kubernetes.io/router.entrypoints": "websecure"},
    },
    "spec": {
        "ingressClassName": "traefik",
        "tls": [{"hosts": [host], "secretName": "qa-tls"}],
        "rules": [
            {
                "host": host,
                "http": {
                    "paths": [
                        {
                            "path": "/",
                            "pathType": "Prefix",
                            "backend": {"service": {"name": "authelia", "port": {"number": 9091}}},
                        }
                    ]
                },
            }
        ],
    },
}
subprocess.run(["kubectl", "apply", "-f", "-"], input=json.dumps(ing).encode(), check=True)
