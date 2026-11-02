import argparse
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import cli


class IngressTests(unittest.TestCase):
    def test_wizard_explains_and_enables_legacy_routing(self):
        c = cli.defaults() | {"ldap_password": "qa"}
        c.pop("ingress_enabled")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.json"
            cli.save(p, json.dumps(c).encode())
            prompts = []

            def answer(prompt):
                prompts.append(prompt)
                return "true" if "ingress_enabled" in prompt else ""

            output = io.StringIO()
            with (
                patch("builtins.input", side_effect=answer),
                patch.object(cli.getpass, "getpass", return_value=""),
                redirect_stdout(output),
            ):
                cli.configure(argparse.Namespace(config=str(p), from_answers=None, no_install=True))
            self.assertTrue(cli.load(p)["ingress_enabled"])
            self.assertTrue(any("ingress_enabled [False]" in p for p in prompts))
            self.assertIn("operator-provided HTTPS", output.getvalue())
            self.assertIn("removes only", output.getvalue())

    def test_disable_deletes_only_owned_route_with_preconditions(self):
        c = cli.defaults() | {"ingress_enabled": False}
        owned = {"metadata": {"labels": cli.LABEL, "uid": "original", "resourceVersion": "42"}}
        for route in (None, {"metadata": {"labels": {}}}, owned):
            with patch.object(cli, "get", return_value=route), patch.object(cli, "kube") as kube:
                cli.reconcile_ingress(c)
                if route is owned:
                    self.assertEqual(
                        kube.call_args.args,
                        (
                            "delete",
                            "--raw",
                            "/apis/networking.k8s.io/v1/namespaces/authelia/ingresses/authelia",
                            "-f",
                            "-",
                        ),
                    )
                    self.assertEqual(
                        json.loads(kube.call_args.kwargs["data"])["preconditions"],
                        {"uid": "original", "resourceVersion": "42"},
                    )
                else:
                    kube.assert_not_called()
        with patch.object(cli, "get") as get, patch.object(cli, "kube") as kube:
            cli.reconcile_ingress(c | {"ingress_enabled": True})
            get.assert_not_called()
            kube.assert_not_called()

    def test_install_ownership_and_deployment_hash(self):
        c = cli.defaults() | {"ldap_password": "qa"}
        foreign = {"metadata": {"labels": {}}}
        with (
            patch.object(cli, "resolve_ca", side_effect=lambda c: c),
            patch.object(cli, "kube", return_value=b'{"provisioner":"rancher.io/local-path"}'),
            patch.object(
                cli, "get", side_effect=lambda c, k, n: foreign if k == "ingress" else None
            ),
            patch.object(cli, "apply") as apply,
        ):
            with self.assertRaisesRegex(ValueError, "unmanaged resource: ingress/authelia"):
                cli.install(c)
            apply.assert_not_called()
        with (
            patch.object(cli, "resolve_ca", side_effect=lambda c: c),
            patch.object(cli, "kube", return_value=b'{"provisioner":"rancher.io/local-path"}'),
            patch.object(cli, "get", return_value=None),
            patch.object(cli, "apply") as apply,
            patch.object(cli, "rollout"),
        ):
            cli.install(c)
            deployment = next(
                call.args[0]
                for call in apply.call_args_list
                if call.args[0]["kind"] == "Deployment"
            )
            self.assertIn(
                "secrets-sha256", deployment["spec"]["template"]["metadata"]["annotations"]
            )

    def test_invalid_routing_inputs(self):
        c = cli.defaults() | {"ldap_password": "qa"}
        for key, value in [
            ("ingress_enabled", "true"),
            ("ingress_class", ""),
            ("ingress_class", "bad/class"),
            ("ingress_class", "A"),
            ("url", "https://bad_.app.example.com"),
            ("url", "https://-bad.app.example.com"),
        ]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                cli.validate(c | {key: value})

    def test_legacy_config_remains_private(self):
        c = cli.defaults()
        c["ldap_password"] = "qa"
        c.pop("ingress_enabled", None)
        c.pop("ingress_class", None)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.json"
            cli.save(p, json.dumps(c).encode())
            self.assertFalse(cli.load(p)["ingress_enabled"])
            c["ingress_enabled"] = True
            cli.save(p, json.dumps(c).encode())
            self.assertTrue(cli.load(p)["ingress_enabled"])

    def test_default_route(self):
        c = cli.defaults()
        c.update(namespace="sso-test", url="https://login.app.example.com", ldap_password="qa")
        cli.validate(c)
        routes = [d for d in cli.render(c) if d["kind"] == "Ingress"]
        self.assertEqual(len(routes), 1)
        route = routes[0]
        self.assertEqual(route["apiVersion"], "networking.k8s.io/v1")
        self.assertEqual(
            route["metadata"], dict(name="authelia", namespace="sso-test", labels=cli.LABEL)
        )
        self.assertEqual(
            route["spec"],
            {
                "ingressClassName": "traefik",
                "rules": [
                    {
                        "host": "login.app.example.com",
                        "http": {
                            "paths": [
                                {
                                    "path": "/",
                                    "pathType": "Prefix",
                                    "backend": {
                                        "service": {"name": "authelia", "port": {"number": 9091}}
                                    },
                                }
                            ]
                        },
                    }
                ],
            },
        )
        c["ingress_class"] = "nginx"
        self.assertEqual(cli.render(c)[-1]["spec"]["ingressClassName"], "nginx")
        c["ingress_enabled"] = False
        self.assertNotIn("Ingress", [d["kind"] for d in cli.render(c)])
