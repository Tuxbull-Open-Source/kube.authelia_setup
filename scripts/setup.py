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
        url="https://sso.app.example.com",
        ingress_enabled=True,
        ingress_class="traefik",
        cookie_domain="app.example.com",
        cookie_name="authelia_session",
        oidc_clients=[],
        oidc_policies={},
        session_idle="2h",
        session_max="12h",
        image="authelia/authelia:4.39.28",
        storage_size="1Gi",
        ldap_address="ldaps://idm01.sun.example.com:636",
        ldap_starttls=False,
        ldap_implementation="freeipa",
        ldap_base_dn="dc=example,dc=com",
        ldap_user="uid=authelia-bind,cn=users,cn=compat,dc=example,dc=com",
        ldap_users_filter="(&({username_attribute}={input})(objectClass=person)(!(nsAccountLock=TRUE)))",
        ldap_groups_filter="(&(member={dn})(objectClass=groupOfNames))",
        ldap_username_attribute="uid",
        ldap_display_attribute="cn",
        ldap_mail_attribute="mail",
        ldap_password="",
        smtp_address="submission://mail01.sun.example.com:587",
        smtp_username="",
        smtp_password="",
        smtp_sender="send@example.com",
        ca_pem="",  # Legacy inline bundle remains supported.
        ca_mode="system",
        ca_file="ldap-ca.pem",
        ca_fingerprint="",
        smtp_ca_mode="system",
        smtp_ca_file="smtp-ca.pem",
        smtp_ca_fingerprint="",
        protected_domain="",
        allowed_group="sysadmins",
        policy="two_factor",
    )


def obj(kind, name, c, spec=None, **extra):
    api = {
        "Deployment": "apps/v1",
        "NetworkPolicy": "networking.k8s.io/v1",
        "Ingress": "networking.k8s.io/v1",
    }.get(kind, "v1")
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
            ]
            if c["protected_domain"]
            else [dict(domain_regex=".*", policy="deny")],
        ),
        session=dict(
            name=c["cookie_name"],
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
    if c["oidc_clients"]:
        conf["identity_providers"] = dict(
            oidc=dict(
                enforce_pkce="never",  # Enforcement is explicit on each registered client.
                enable_pkce_plain_challenge=False,
                clients=[
                    dict(
                        client_id=x["client_id"],
                        client_name=x.get("client_name", x["client_id"]),
                        public=True,
                        token_endpoint_auth_method="none",
                        redirect_uris=x["redirect_uris"],
                        authorization_policy=x["authorization_policy"],
                        scopes=["openid", "profile", "email", "groups"],
                        grant_types=["authorization_code"],
                        response_types=["code"],
                        require_pkce=x.get("require_pkce", True),
                        pkce_challenge_method="S256" if x.get("require_pkce", True) else "",
                    )
                    for x in c["oidc_clients"]
                ],
                authorization_policies={
                    name: dict(
                        default_policy="deny",
                        rules=[
                            dict(
                                policy=policy["policy"],
                                subject=[["group:" + policy["group"]]],
                            )
                        ],
                    )
                    for name, policy in c["oidc_policies"].items()
                },
            )
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
    if c["oidc_clients"]:
        env.append(
            dict(
                name="AUTHELIA_IDENTITY_PROVIDERS_OIDC_HMAC_SECRET_FILE", value="/secrets/oidc-hmac"
            )
        )
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
    docs = [obj("Namespace", c["namespace"], c)]
    docs.extend(
        [
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
    )
    if c["ca_pem"]:
        docs.append(obj("ConfigMap", "authelia-ca", c, data={"ca.crt": c["ca_pem"]}))
        volumes.append(dict(name="ca", configMap=dict(name="authelia-ca")))
        mounts.append(dict(name="ca", mountPath="/certificates", readOnly=True))
    container = dict(
        name="authelia",
        args=["--config", "/config/configuration.yml"]
        + (["--config", "/secrets/oidc.yml"] if c["oidc_clients"] else []),
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
                        labels={"app": "authelia", **LABEL},
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
    if c["ingress_enabled"]:
        docs.append(
            obj(
                "Ingress",
                "authelia",
                c,
                dict(
                    ingressClassName=c["ingress_class"],
                    rules=[
                        dict(
                            host=urlparse(c["url"]).hostname,
                            http=dict(
                                paths=[
                                    dict(
                                        path="/",
                                        pathType="Prefix",
                                        backend=dict(
                                            service=dict(name="authelia", port=dict(number=9091))
                                        ),
                                    )
                                ]
                            ),
                        )
                    ],
                ),
            )
        )
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
    if c["ca_mode"] not in ("system", "manual", "fetch"):
        raise ValueError("ca_mode must be system, manual or fetch")
    if c["ca_mode"] != "system" and not c["ca_file"]:
        raise ValueError("ca_file required")
    if c["smtp_ca_mode"] not in ("system", "manual", "fetch"):
        raise ValueError("smtp_ca_mode must be system, manual or fetch")
    if c["smtp_ca_mode"] != "system" and not c["smtp_ca_file"]:
        raise ValueError("smtp_ca_file required")
    ns = c["namespace"]
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,61}[a-z0-9]", ns) or ns in (
        "default",
        "kube-system",
        "kube-public",
        "kube-node-lease",
    ):
        raise ValueError("use a dedicated namespace")
    u = urlparse(c["url"])
    for field, value in (
        ("ingress_class", c["ingress_class"]),
        ("portal hostname", u.hostname or ""),
    ):
        if len(value) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")
        ):
            raise ValueError(field + " must be a DNS subdomain")
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
    if c["protected_domain"] and not c["allowed_group"]:
        raise ValueError("forward-auth requires an explicit group")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", c["cookie_name"]):
        raise ValueError("invalid cookie_name")
    validate_oidc(c)
    if not re.fullmatch(r"[1-9][0-9]*(Mi|Gi)", c["storage_size"]):
        raise ValueError("invalid storage size")
    if ":latest" in c["image"] or not (":" in c["image"] or "@sha256:" in c["image"]):
        raise ValueError("pin the image version")


def validate_oidc(c):
    for name, policy in c["oidc_policies"].items():
        if name in ("one_factor", "two_factor", "deny") or not re.fullmatch(
            r"[a-zA-Z0-9_-]+", name
        ):
            raise ValueError("invalid OIDC policy name")
        if not isinstance(policy, dict) or set(policy) != {"group", "policy"}:
            raise ValueError("OIDC policy requires group and policy")
        if (
            not isinstance(policy["group"], str)
            or not policy["group"]
            or policy["policy"] not in ("one_factor", "two_factor")
        ):
            raise ValueError("invalid OIDC group or policy")
    seen = set()
    for client in c["oidc_clients"]:
        if not isinstance(client, dict) or set(client) - {
            "client_id",
            "client_name",
            "redirect_uris",
            "authorization_policy",
            "require_pkce",
        }:
            raise ValueError(
                "unknown OIDC client field; only public authorization-code clients supported"
            )
        if not {"client_id", "redirect_uris", "authorization_policy"} <= set(client):
            raise ValueError("OIDC client requires id, redirect URIs and authorization policy")
        cid = client["client_id"]
        if not isinstance(cid, str) or not re.fullmatch(r"[a-zA-Z0-9._-]+", cid) or cid in seen:
            raise ValueError("invalid or duplicate OIDC client id")
        seen.add(cid)
        if (
            not isinstance(client["authorization_policy"], str)
            or client["authorization_policy"] not in c["oidc_policies"]
        ):
            raise ValueError("OIDC client must reference a group-restricted policy")
        if type(client.get("require_pkce", True)) is not bool:
            raise ValueError("require_pkce must be boolean")
        uris = client["redirect_uris"]
        if not isinstance(uris, list) or not uris:
            raise ValueError("OIDC redirect URIs required")
        for uri in uris:
            if not isinstance(uri, str):
                raise ValueError("OIDC redirect URI must be a string")
            u = urlparse(uri)
            if (
                u.scheme != "https"
                or not u.hostname
                or u.username
                or u.password
                or u.fragment
                or "*" in uri
            ):
                raise ValueError(
                    "OIDC redirect URI must be exact HTTPS without fragment or credentials"
                )


if __name__ == "__main__":
    print("Use lifecycle scripts", file=sys.stderr)
    sys.exit(2)
