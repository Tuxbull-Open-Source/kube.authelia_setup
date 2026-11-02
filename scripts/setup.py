#!/usr/bin/env python3
"""Standalone Authelia lifecycle. JSON is a YAML subset; no YAML dependency."""

import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
LABEL = {"app.kubernetes.io/managed-by": "kube.authelia_setup"}


def defaults():
    return dict(
        namespace="authelia",
        url="https://sso.example.com",
        cookie_domain="example.com",
        session_idle="2h",
        session_max="12h",
        image="authelia/authelia:4.39.28",
        storage_size="1Gi",
        ldap_address="ldaps://ldap.example.com:636",
        ldap_starttls=False,
        ldap_implementation="custom",
        ldap_base_dn="dc=example,dc=com",
        ldap_user="uid=authelia,ou=people,dc=example,dc=com",
        ldap_users_filter="(&({username_attribute}={input})(objectClass=person))",
        ldap_groups_filter="(&(member={dn})(objectClass=groupOfNames))",
        ldap_username_attribute="uid",
        ldap_display_attribute="cn",
        ldap_mail_attribute="mail",
        ldap_password="",
        smtp_address="submission://smtp.example.com:587",
        smtp_username="",
        smtp_password="",
        smtp_sender="authelia@example.com",
        ca_pem="",
        protected_domain="app.example.com",
        allowed_group="authelia-users",
        policy="two_factor",
    )


def obj(kind, name, c, spec=None, **extra):
    api = {"Deployment": "apps/v1", "NetworkPolicy": "networking.k8s.io/v1"}.get(kind, "v1")
    d = dict(
        apiVersion=api,
        kind=kind,
        metadata=dict(name=name, namespace=c["namespace"], labels=LABEL.copy()),
    )
    if kind == "Namespace":
        d["metadata"].pop("namespace")
    if spec is not None:
        d["spec"] = spec
    d.update(extra)
    return d


def render(c):
    ldap = dict(
        address=c["ldap_address"],
        start_tls=c["ldap_starttls"],
        implementation=c["ldap_implementation"],
        base_dn=c["ldap_base_dn"],
        user=c["ldap_user"],
        users_filter=c["ldap_users_filter"],
        groups_filter=c["ldap_groups_filter"],
        attributes=dict(
            username=c["ldap_username_attribute"],
            display_name=c["ldap_display_attribute"],
            mail=c["ldap_mail_attribute"],
        ),
        tls=dict(skip_verify=False, minimum_version="TLS1.2"),
    )
    conf = dict(
        server=dict(address="tcp://:9091/", disable_healthcheck=True),
        log=dict(level="info"),
        authentication_backend=dict(password_reset=dict(disable=True), ldap=ldap),
        access_control=dict(
            default_policy="deny",
            rules=[
                dict(
                    domain=c["protected_domain"],
                    policy=c["policy"],
                    subject=["group:" + c["allowed_group"]],
                )
            ],
        ),
        session=dict(
            name="authelia_session",
            same_site="lax",
            inactivity=c["session_idle"],
            expiration=c["session_max"],
            remember_me=-1,
            cookies=[dict(domain=c["cookie_domain"], authelia_url=c["url"])],
        ),
        storage=dict(local=dict(path="/data/db.sqlite3")),
        notifier=dict(
            smtp=dict(
                address=c["smtp_address"],
                username=c["smtp_username"],
                sender=c["smtp_sender"],
                identifier=urlparse(c["url"]).hostname,
                tls=dict(skip_verify=False, minimum_version="TLS1.2"),
            )
        ),
    )
    if c["ca_pem"]:
        conf["certificates_directory"] = "/certificates"
    config = json.dumps(conf, sort_keys=True)
    env = [
        dict(name="AUTHELIA_" + name + "_FILE", value="/secrets/" + key)
        for name, key in [
            ("SESSION_SECRET", "session"),
            ("STORAGE_ENCRYPTION_KEY", "storage"),
            ("AUTHENTICATION_BACKEND_LDAP_PASSWORD", "ldap"),
            ("NOTIFIER_SMTP_PASSWORD", "smtp"),
        ]
    ]
    volumes = [
        dict(name="data", persistentVolumeClaim=dict(claimName="authelia-data")),
        dict(name="config", configMap=dict(name="authelia-config")),
        dict(
            name="secrets",
            secret=dict(secretName="authelia-secrets", defaultMode=0o440),
        ),
        dict(name="tmp", emptyDir={}),
    ]
    mounts = [
        dict(name=n, mountPath=p, readOnly=ro)
        for n, p, ro in [
            ("data", "/data", False),
            ("config", "/config", True),
            ("secrets", "/secrets", True),
            ("tmp", "/tmp", False),
        ]
    ]
    docs = [
        obj("Namespace", c["namespace"], c),
        obj(
            "PersistentVolumeClaim",
            "authelia-data",
            c,
            dict(
                accessModes=["ReadWriteOnce"],
                storageClassName="local-path",
                resources=dict(requests=dict(storage=c["storage_size"])),
            ),
        ),
        obj("ConfigMap", "authelia-config", c, data={"configuration.yml": config}),
    ]
    if c["ca_pem"]:
        docs.append(obj("ConfigMap", "authelia-ca", c, data={"ca.crt": c["ca_pem"]}))
        volumes.append(dict(name="ca", configMap=dict(name="authelia-ca")))
        mounts.append(dict(name="ca", mountPath="/certificates", readOnly=True))
    container = dict(
        name="authelia",
        image=c["image"],
        imagePullPolicy="IfNotPresent",
        env=env,
        ports=[dict(containerPort=9091, name="http")],
        volumeMounts=mounts,
        securityContext=dict(
            allowPrivilegeEscalation=False,
            readOnlyRootFilesystem=True,
            capabilities=dict(drop=["ALL"]),
        ),
        resources=dict(
            requests=dict(cpu="100m", memory="128Mi"),
            limits=dict(cpu="1000m", memory="512Mi"),
        ),
        readinessProbe=dict(httpGet=dict(path="/api/health", port="http"), periodSeconds=5),
        livenessProbe=dict(httpGet=dict(path="/api/health", port="http"), initialDelaySeconds=30),
        startupProbe=dict(
            httpGet=dict(path="/api/health", port="http"),
            failureThreshold=60,
            periodSeconds=5,
        ),
    )
    docs += [
        obj(
            "Service",
            "authelia",
            c,
            dict(
                type="ClusterIP",
                selector={"app": "authelia"},
                ports=[dict(port=9091, targetPort="http")],
            ),
        ),
        obj(
            "Deployment",
            "authelia",
            c,
            dict(
                replicas=1,
                strategy=dict(type="Recreate"),
                selector=dict(matchLabels={"app": "authelia"}),
                template=dict(
                    metadata=dict(
                        labels={"app": "authelia"},
                        annotations={
                            "config-sha256": hashlib.sha256(
                                config.encode() + c["ca_pem"].encode()
                            ).hexdigest()
                        },
                    ),
                    spec=dict(
                        enableServiceLinks=False,
                        automountServiceAccountToken=False,
                        securityContext=dict(
                            runAsNonRoot=True,
                            runAsUser=1000,
                            runAsGroup=1000,
                            fsGroup=1000,
                            seccompProfile=dict(type="RuntimeDefault"),
                        ),
                        containers=[container],
                        volumes=volumes,
                    ),
                ),
            ),
        ),
    ]
    return docs


def duration(value):
    m = re.fullmatch(r"([1-9][0-9]*)(s|m|h)", str(value))
    if not m:
        raise ValueError("durations require a positive integer and s/m/h")
    return int(m[1]) * {"s": 1, "m": 60, "h": 3600}[m[2]]


def validate(c):
    if set(c) - set(defaults()):
        raise ValueError("unknown configuration keys")
    for k, v in defaults().items():
        if k not in c or type(c[k]) is not type(v):
            raise ValueError("missing or invalid type: " + k)
    ns = c["namespace"]
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,61}[a-z0-9]", ns) or ns in (
        "default",
        "kube-system",
        "kube-public",
        "kube-node-lease",
    ):
        raise ValueError("use a dedicated namespace")
    u = urlparse(c["url"])
    if (
        u.scheme != "https"
        or not u.hostname
        or u.username
        or u.password
        or u.path not in ("", "/")
        or u.query
        or u.fragment
    ):
        raise ValueError("url must be an HTTPS origin")
    domain = c["cookie_domain"]
    if (
        "." not in domain
        or not re.fullmatch(r"[a-z0-9.-]+", domain)
        or not (u.hostname == domain or u.hostname.endswith("." + domain))
    ):
        raise ValueError("cookie domain must contain portal host")
    if duration(c["session_idle"]) > duration(c["session_max"]):
        raise ValueError("idle timeout exceeds absolute maximum")
    if c["policy"] not in ("one_factor", "two_factor"):
        raise ValueError("policy must be one_factor or two_factor")
    ldap_url = urlparse(c["ldap_address"])
    if (
        ldap_url.username
        or ldap_url.password
        or not ldap_url.hostname
        or not (ldap_url.scheme == "ldaps" or (ldap_url.scheme == "ldap" and c["ldap_starttls"]))
    ):
        raise ValueError("LDAP requires LDAPS or StartTLS")
    if not c["ldap_password"] or c["ldap_password"] == "CHANGE_ME":
        raise ValueError("LDAP password required")
    if not c["ldap_user"] or not c["ldap_base_dn"]:
        raise ValueError("LDAP DN required")
    s = urlparse(c["smtp_address"])
    if (
        s.scheme not in ("smtp", "submission", "submissions")
        or not s.hostname
        or s.username
        or s.password
    ):
        raise ValueError("invalid SMTP address")
    if c["smtp_username"] and not c["smtp_password"]:
        raise ValueError("SMTP password required for authenticated relay")
    if "@" not in c["smtp_sender"]:
        raise ValueError("SMTP sender required")
    if not c["allowed_group"] or not c["protected_domain"]:
        raise ValueError("explicit protected domain and group required")
    if not re.fullmatch(r"[1-9][0-9]*(Mi|Gi)", c["storage_size"]):
        raise ValueError("invalid storage size")
    if ":latest" in c["image"] or not (":" in c["image"] or "@sha256:" in c["image"]):
        raise ValueError("pin the image version")


if __name__ == "__main__":
    print("Use lifecycle scripts", file=sys.stderr)
    sys.exit(2)
