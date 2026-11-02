#!/usr/bin/env python3
"""Disposable VM only; NOT part of product. Run as root on fresh Ubuntu 24.04."""

import json
import os
import pathlib
import secrets
import subprocess
import sys

P = pathlib.Path("/root/qa")
P.mkdir(exist_ok=True, mode=0o700)
os.umask(0o077)


def run(a, data=None):
    return subprocess.run(
        a, input=data, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout


pw = secrets.token_urlsafe(30)
userpw = secrets.token_urlsafe(30)
(P / "credentials.json").write_text(json.dumps({"bind": pw, "user": userpw}))
host = sys.argv[1]
run(
    [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(P / "tls.key"),
        "-out",
        str(P / "tls.crt"),
        "-days",
        "2",
        "-subj",
        "/CN=" + host,
        "-addext",
        "subjectAltName=DNS:" + host + ",IP:10.42.0.1",
    ]
)
# Test-only LDAP CA/key, readable by slapd.
run(
    [
        "install",
        "-o",
        "openldap",
        "-g",
        "openldap",
        "-m",
        "600",
        str(P / "tls.key"),
        "/etc/ldap/qa.key",
    ]
)
run(
    [
        "install",
        "-o",
        "openldap",
        "-g",
        "openldap",
        "-m",
        "644",
        str(P / "tls.crt"),
        "/etc/ldap/qa.crt",
    ]
)
conf = """dn: cn=config
changetype: modify
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/qa.crt
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/qa.key
"""
run(["ldapmodify", "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///"], conf.encode())
# Dedicated QA suffix; stock Ubuntu creates mdb database index 1.
hashpw = run(["slappasswd", "-T", "/dev/stdin"], pw.encode()).decode().strip()
conf = f"""dn: olcDatabase={{1}}mdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: dc=example,dc=com
-
replace: olcRootDN
olcRootDN: cn=admin,dc=example,dc=com
-
replace: olcRootPW
olcRootPW: {hashpw}
"""
run(["ldapmodify", "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///"], conf.encode())
p = pathlib.Path("/etc/default/slapd")
s = p.read_text()
s = s.replace("ldap:/// ldapi:///", "ldap://127.0.0.1/ ldaps://10.42.0.1/ ldapi:///")
p.write_text(s)
run(["systemctl", "restart", "slapd"])
userhash = run(["slappasswd", "-T", "/dev/stdin"], userpw.encode()).decode().strip()
ldif = f"""dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: uid=qa,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: qa
cn: QA User
sn: User
mail: qa@example.com
userPassword: {userhash}

dn: cn=authelia-users,dc=example,dc=com
objectClass: groupOfNames
cn: authelia-users
member: uid=qa,ou=people,dc=example,dc=com
"""
(P / "bind").write_text(pw)
run(
    [
        "ldapadd",
        "-x",
        "-H",
        "ldap://127.0.0.1",
        "-D",
        "cn=admin,dc=example,dc=com",
        "-y",
        str(P / "bind"),
    ],
    ldif.encode(),
)
print("PASS isolated LDAP TLS fixture created")
