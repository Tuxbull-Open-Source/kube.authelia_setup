import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import cli
import setup


def config():
    c = setup.defaults()
    c.update(
        ldap_password="fixture-only",
        protected_domain="",
        cookie_name="isolated_session",
        oidc_clients=[
            dict(
                client_id="dashboard",
                redirect_uris=["https://dashboard.example.com/auth/callback"],
                authorization_policy="staff",
            )
        ],
        oidc_policies={"staff": {"group": "sysadmins", "policy": "one_factor"}},
    )
    return c


class OIDCTests(unittest.TestCase):
    def test_native_oidc_without_forward_auth(self):
        c = config()
        setup.validate(c)
        docs = setup.render(c)
        conf = json.loads(
            next(d for d in docs if d["kind"] == "ConfigMap")["data"]["configuration.yml"]
        )
        self.assertEqual(
            conf["access_control"],
            {"default_policy": "deny", "rules": [{"domain_regex": ".*", "policy": "deny"}]},
        )
        self.assertEqual(conf["session"]["name"], "isolated_session")
        oidc = conf["identity_providers"]["oidc"]
        client = oidc["clients"][0]
        self.assertTrue(client["public"])
        self.assertTrue(client["require_pkce"])
        self.assertEqual(client["pkce_challenge_method"], "S256")
        self.assertEqual(client["token_endpoint_auth_method"], "none")
        self.assertEqual(
            oidc["authorization_policies"]["staff"],
            {
                "default_policy": "deny",
                "rules": [{"policy": "one_factor", "subject": [["group:sysadmins"]]}],
            },
        )
        first = cli.secret_doc(c)
        self.assertEqual(first, cli.secret_doc(c, first))
        keys = json.loads(base64.b64decode(first["data"]["oidc.yml"]))
        self.assertIn("PRIVATE KEY", keys["identity_providers"]["oidc"]["jwks"][0]["key"])
        self.assertNotIn("PRIVATE KEY", json.dumps(docs))
        broken = json.loads(json.dumps(first))
        del broken["data"]["oidc.yml"]
        with self.assertRaises(ValueError):
            cli.secret_doc(c, broken)
        del broken["data"]["oidc-hmac"]
        with self.assertRaises(ValueError):
            cli.secret_doc(c, broken)
