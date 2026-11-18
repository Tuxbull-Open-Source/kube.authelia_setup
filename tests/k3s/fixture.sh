#!/bin/sh
set -eu
umask 077
ulimit -n 1024
apk add --no-cache openldap openldap-back-mdb openldap-clients py3-aiosmtpd
mkdir /tmp/db
cat > /tmp/slapd.conf <<EOF
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema
modulepath /usr/lib/openldap
moduleload back_mdb
pidfile /tmp/slapd.pid
argsfile /tmp/slapd.args
TLSCertificateFile /qa/leaf.pem
TLSCertificateKeyFile /qa/leaf.key
TLSCACertificateFile /qa/ca.pem
database mdb
maxsize 16777216
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw $(slappasswd -T /qa/bind)
directory /tmp/db
access to attrs=userPassword by anonymous auth by * none
access to * by users read by * none
EOF
slapadd -f /tmp/slapd.conf -l /qa/entries.ldif
slapd -f /tmp/slapd.conf -h ldaps://0.0.0.0:1636/
exec python3 /qa/sink.py
