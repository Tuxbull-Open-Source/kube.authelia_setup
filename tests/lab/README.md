# Disposable live QA (never production)

These root-only fixture scripts are **not called by any product script**. They configure a fresh Ubuntu 24.04 VM with a test OpenLDAP directory, a TLS SMTP sink and a self-signed HTTPS ingress. Credentials are randomly generated and kept under `/root/qa` (0700); no message bodies, seeds or credentials belong in Git. The fixture uses an LDAP administrator only to simplify isolated QA, never as a production recommendation.

Provision a fresh temporary VM through your approved process. The reference run used Hetzner fsn1, cx23, x86_64, 2 vCPU/4GB, Ubuntu 24.04. Cloud spend requires explicit approval; label and record all resources, and delete/verify them afterward. These scripts do not provision cloud resources.

Copy this repository to `/root/authelia` on the VM. Run the following only after verifying the VM identity/OS and that it is disposable:

```bash
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y curl slapd ldap-utils python3-venv python3-aiosmtpd openssl
curl -fsSL https://get.k3s.io -o /root/k3s-install.sh
INSTALL_K3S_VERSION=v1.34.1+k3s1 sh /root/k3s-install.sh
# Wait until the node is registered before using kubectl wait.
kubectl get nodes
kubectl wait node --all --for=condition=Ready --timeout=180s
kubectl -n kube-system rollout status deploy/coredns --timeout=180s
kubectl -n kube-system rollout status deploy/local-path-provisioner --timeout=180s
kubectl -n kube-system rollout status deploy/traefik --timeout=180s
```

Use a DNS name resolving to the disposable VM. The example address below is documentation-only and must be replaced in your private shell:

```bash
HOST=sso.192.0.2.10.sslip.io
cd /root/authelia
python3 tests/lab/fixtures.py "$HOST"
# 10.42.0.1 is the default single-node k3s CNI bridge, not an Internet address.
# Restrict fixture listeners and allow only loopback/pod traffic as appropriate.
iptables -I INPUT -i lo -j ACCEPT
iptables -I INPUT -s 10.42.0.0/16 -p tcp -m multiport --dports 389,636,587 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 389,636,587 -j REJECT
ip6tables -A INPUT -p tcp -m multiport --dports 389,636,587 -j REJECT
systemd-run --unit=qa-smtp /usr/bin/python3 /root/authelia/tests/lab/smtp.py
python3 tests/lab/deploy.py "$HOST"
./doctor.sh
```

Fixtures require the standard single-node k3s pod CIDR/bridge. Adapt intentionally if different. `deploy.py` uses TLS only in the QA harness: it creates a self-signed secret/ingress, sets default two-factor policy and shorter session timeouts (30s idle / 2m absolute) for bounded acceptance. Product scripts still create no ingress/TLS resources.

Install browser tooling **in the lab only** and run enrollment once on the fresh database:

```bash
python3 -m venv /root/qa/venv
/root/qa/venv/bin/pip install playwright
/root/qa/venv/bin/playwright install --with-deps chromium
/root/qa/venv/bin/python tests/lab/enroll.py
/root/qa/venv/bin/python tests/lab/acceptance.py
python3 tests/live.py --config current_config/config.json --yes-disposable
./maintain.sh restart
./doctor.sh
/root/qa/venv/bin/python tests/lab/acceptance.py
```

`enroll.py` verifies invalid LDAP password rejection, valid first-factor authentication, actual STARTTLS SMTP delivery, email verification and TOTP enrollment. It captures private API responses to complete the fixture enrollment; **never publish `/root/qa`**. Repeated enrollment attempts trigger upstream rate limits; wait, don't disable regulation. Use a fresh namespace/database for another enrollment run.

`acceptance.py` verifies real Chromium LDAP+TOTP login, first-factor-only denial, internal forward-auth allow/default deny, logout, idle expiry with the page inactive, absolute expiry despite activity and no JavaScript exceptions. It saves a screenshot of the authenticated UI. The QA browser accepts its self-signed certificate only; separately verify HTTPS with the fixture CA. Public production TLS must use the operator's valid chain.

`tests/live.py` intentionally deletes/reinstates the QA encryption Secret to prove fail-closed behavior, verifies unchanged reinstall (Secret data, PVC UID, pod template), rejects invalid configuration before application mutation, and runs doctor. **Never run this destructive test on a production namespace.**

Velero backup/recovery is out of scope and not exercised or configured by this harness.

After collecting only sanitized PASS/FAIL evidence, delete the temporary VM and its temporary SSH key, IPs and any other task-created cloud resources; poll the provider API to verify absence. Do not leave a paid VM running or publish its actual IP, private key, kubeconfig, database, cookies or credentials.
