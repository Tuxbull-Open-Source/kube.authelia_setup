"""Cluster-free coordinator/security contracts; native systemd/Velero QA is separate."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host = load("host_maintenance")
provision = load("provision_host")
stable = load("stable_images")


class CoordinatorTests(unittest.TestCase):
    def test_missing_keys_fail_without_generation(self):
        import base64

        valid = base64.b64encode(b"x" * 32).decode()
        cli = Mock()
        c = {"namespace": "fixture", "oidc_clients": []}
        for secret in (None, {"data": {}}, {"data": {"session": valid}}):
            cli.get.return_value = secret
            with self.assertRaises(host.Error):
                host.validate_existing_secret(cli, c)
        cli.get.return_value = {"data": {"session": valid, "storage": valid}}
        host.validate_existing_secret(cli, c)
        with self.assertRaises(host.Error):
            host.validate_existing_secret(cli, c | {"oidc_clients": [{"client_id": "fixture"}]})
        cli.get.return_value["metadata"] = {"annotations": {"oidc-established": "true"}}
        with self.assertRaises(host.Error):
            host.validate_existing_secret(cli, c)
        cli.secret_doc.assert_not_called()
        cli.run.assert_not_called()

    def test_ca_content_changes_enrollment_fingerprint(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "config.json"
            config.write_text("{}")
            config.chmod(0o600)
            ca = root / "ca.pem"
            ca.write_text("synthetic-ca-one")
            ca.chmod(0o600)
            binding = {"config_path": str(config)}
            values = {"ca_mode": "manual", "ca_file": "ca.pem"}
            before = host.ca_fingerprints(binding, values)
            ca.write_text("synthetic-ca-two")
            self.assertNotEqual(before, host.ca_fingerprints(binding, values))
            ca.chmod(0o666)
            with self.assertRaises(host.Error):
                host.ca_fingerprints(binding, values)

    def test_worker_success_orders_cold_backup_before_install_and_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            events = []
            backend = Mock(ROOT=folder)
            backend.backup.side_effect = lambda *args: (
                events.append("backup") or "cold-fixture",
                {},
            )
            backend.eligible.side_effect = lambda *args: events.append("eligible")
            cli = Mock()
            for method in ("install", "doctor", "storage_checks"):
                getattr(cli, method).side_effect = lambda *args, method=method: events.append(
                    method
                )
            state = {"secrets": {}, "configmaps": {}, "deployments": []}
            plan = {
                "instance": "fixture",
                "phase": "prepared; no workloads changed",
                "backup": None,
                "before": state,
            }
            (folder / "candidate.json").write_text("{}")
            (folder / "manifest.json").write_text("[]")
            real_open = open

            def private_open(path, *args, **kwargs):
                return real_open(
                    folder / "audit" if str(path) == "/CHANGES.md" else path, *args, **kwargs
                )

            with (
                patch.object(host, "recovery_backend", return_value=backend),
                patch.object(host, "trusted", side_effect=Path),
                patch.object(host, "checkout_lock", return_value=contextlib.nullcontext()),
                patch.object(host, "guard"),
                patch.object(host, "installer", return_value=contextlib.nullcontext(cli)),
                patch.object(host, "snapshot", return_value=state),
                patch.object(host, "protected_contract"),
                patch.object(
                    host, "publish_image_pins", side_effect=lambda *args: events.append("publish")
                ),
                patch("builtins.open", side_effect=private_open),
            ):
                host.worker({"namespace": "fixture"}, folder, plan)
            self.assertEqual(
                events, ["backup", "eligible", "install", "doctor", "storage_checks", "publish"]
            )
            self.assertEqual(plan["backup"], "cold-fixture")
            self.assertTrue(plan["phase"].startswith("rollout-complete"))

    def test_worker_backup_failure_never_installs_or_publishes(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            backend = Mock(ROOT=folder)
            backend.backup.side_effect = host.Error("Cold backup failed")
            plan = {
                "instance": "fixture",
                "phase": "prepared; no workloads changed",
                "backup": None,
            }
            p = {"namespace": "fixture"}
            real_open = open

            def private_open(path, *args, **kwargs):
                return real_open(
                    folder / "audit" if str(path) == "/CHANGES.md" else path, *args, **kwargs
                )

            with (
                patch.object(host, "recovery_backend", return_value=backend),
                patch.object(host, "trusted", side_effect=Path),
                patch.object(host, "checkout_lock", return_value=contextlib.nullcontext()),
                patch.object(host, "guard"),
                patch.object(host, "installer") as installer,
                patch.object(host, "publish_image_pins") as publish,
                patch("builtins.open", side_effect=private_open),
            ):
                with self.assertRaisesRegex(host.Error, "Cold backup failed"):
                    host.worker(p, folder, plan)
                installer.assert_not_called()
                publish.assert_not_called()
                backend.diagnostics.assert_called_once_with("fixture", folder)
            self.assertIn("failed", json.loads((folder / "plan.json").read_text())["phase"])

    def test_checkout_lock_excludes_installer_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "config.json"
            source.write_text("{}")
            source.chmod(0o600)
            p = {"config_path": str(source)}
            with host.checkout_lock(p), self.assertRaises(BlockingIOError), host.checkout_lock(p):
                pass
            lock = Path(str(source) + ".lock")
            self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
            lock.unlink()
            lock.symlink_to(source)
            with self.assertRaises(OSError), host.checkout_lock(p):
                pass

    def test_restore_reconciles_older_backup_pin_not_current_newer_config(self):
        old = "docker.io/authelia/authelia:4.39.27@sha256:" + "a" * 64
        new = "docker.io/authelia/authelia:4.39.28@sha256:" + "b" * 64
        for restored_image in (old, old.split("@")[0], old[:-1] + "f"):
            with tempfile.TemporaryDirectory() as temp, self.subTest(image=restored_image):
                folder = Path(temp)
                source, protected = folder / "config.json", folder / "protected.json"
                original = json.dumps({"image": new, "namespace": "fixture"}).encode()
                for path in (source, protected):
                    path.write_bytes(original)
                    path.chmod(0o600)
                p = {
                    "namespace": "fixture",
                    "config_path": str(source),
                    "config_file": str(protected),
                }
                plan = {
                    "operation": "restore",
                    "target_backup": "cold-old",
                    "config_sha256": hashlib.sha256(original).hexdigest(),
                    "phase": "prepared",
                }
                backend = Mock(ROOT=folder)
                backend.restore.return_value = {"namespace_uid": "restored-uid", "image": old}
                deployment = {
                    "metadata": {"name": "authelia"},
                    "spec": {
                        "template": {
                            "spec": {"containers": [{"name": "authelia", "image": restored_image}]}
                        }
                    },
                }
                real_open = open

                def private_open(path, *args, real_open=real_open, folder=folder, **kwargs):
                    return real_open(
                        folder / "audit" if str(path) == "/CHANGES.md" else path, *args, **kwargs
                    )

                with (
                    patch.object(host, "recovery_backend", return_value=backend),
                    patch.object(host, "trusted", side_effect=Path),
                    patch.object(host, "recovery_guard"),
                    patch.object(
                        host,
                        "kube",
                        side_effect=[
                            {"metadata": {"uid": "restored-uid"}},
                            {"items": [deployment]},
                        ],
                    ),
                    patch("builtins.open", side_effect=private_open),
                ):
                    if restored_image == old:
                        host.recovery_worker(p, folder, plan)
                        self.assertEqual(json.loads(source.read_bytes())["image"], old)
                        self.assertEqual(source.read_bytes(), protected.read_bytes())
                    else:
                        with self.assertRaisesRegex(host.Error, "backup-time pin"):
                            host.recovery_worker(p, folder, plan)
                        self.assertEqual(source.read_bytes(), original)

    def test_unready_launch_and_worker_use_native_safety_checkpoint_contract(self):
        import base64

        from test_velero_recovery import BINDING, PIN, PROVENANCE, UnreadyFake

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backend = UnreadyFake()
            backend.ROOT = root
            with patch.object(backend, "_image_provenance", return_value=PROVENANCE):
                good, _ = backend.backup(BINDING["namespace"], root / "good")
            backend.break_current_app()
            backend.actions.clear()
            source, protected = root / "config.json", root / "protected.json"
            values = {"namespace": BINDING["namespace"], "image": "authelia/authelia:4.39.28"}
            for path in (source, protected):
                path.write_text(json.dumps(values))
                path.chmod(0o600)
            p = dict(
                BINDING,
                source=str(ROOT),
                source_revision="fixture",
                config_path=str(source),
                config_file=str(protected),
            )
            secret = {
                "metadata": {"name": "authelia-secrets", "uid": "secret-original"},
                "data": {k: base64.b64encode(b"x" * 32).decode() for k in ("session", "storage")},
            }
            cli = Mock()
            cli.get.return_value = secret

            def kube(_p, *args):
                kind = args[args.index("get") + 1]
                if kind == "namespace":
                    return backend._get(kind, args[-1])
                if kind == "secrets":
                    return {"items": [copy.deepcopy(secret)]}
                return {"items": backend._items(kind, p["namespace"])}

            real_open = open

            def private_open(path, *args, **kwargs):
                return real_open(
                    root / "audit" if str(path) == "/CHANGES.md" else path, *args, **kwargs
                )

            with (
                patch.object(host, "STATE", root / "state"),
                patch.object(host, "recovery_backend", return_value=backend),
                patch.object(host, "profile", return_value=p),
                patch.object(host, "trusted", side_effect=Path),
                patch.object(host, "installer", side_effect=lambda _: contextlib.nullcontext(cli)),
                patch.object(host, "configuration", return_value={"oidc_clients": []}),
                patch.object(host, "kube", side_effect=kube),
                patch.object(host.os, "statvfs", return_value=Mock(f_bavail=50, f_blocks=100)),
                patch.object(host, "run") as launch,
                patch.object(host, "output"),
                patch("builtins.open", side_effect=private_open),
            ):
                # Real launch preflight + snapshot + plan, real worker guard and
                # backend.restore; only system/cluster transport is simulated.
                host.launch_recovery(p, "fixture", "restore", good)
                self.assertIn("--accept-data-loss", launch.call_args.args[0])
                folder = next((root / "state").iterdir())
                plan = json.loads((folder / "plan.json").read_text())
                self.assertFalse(backend.deleted)
                host.recovery_worker(p, folder, plan)
                result = json.loads((folder / "restore-result.json").read_text())
                self.assertEqual(result["image"], PIN)
                self.assertEqual(json.loads(source.read_text())["image"], PIN)
                self.assertEqual(source.read_bytes(), protected.read_bytes())
                self.assertTrue((folder / "safety/safety-complete.json").is_file())
                self.assertEqual(plan["backup"], good)
                self.assertTrue(backend.deleted)
                deletion = next(
                    i for i, a in enumerate(backend.actions) if "delete" in a and "namespace" in a
                )
                self.assertFalse(any("--replicas=2" in a for a in backend.actions[:deletion]))
                cli.ownership.assert_called()
                cli.exclusive_namespace.assert_called()
                cli.get.assert_called_with({"oidc_clients": []}, "secret", "authelia-secrets")

    def test_current_operator_arguments_parse_without_alternate_workflow(self):
        cases = [
            (["plan", "--latest-stable"], "plan"),
            (["upgrade", "fixture-0123456789ab"], "upgrade"),
            (["restore", "cold-old", "--accept-data-loss"], "restore"),
        ]
        with (
            patch.object(host, "trusted", side_effect=Path),
            patch.object(host.os, "geteuid", return_value=0),
            patch.object(host.os, "umask"),
            patch.object(host, "shared_provision_lock", side_effect=contextlib.nullcontext),
            patch.object(host, "dispatch") as dispatch,
        ):
            for arguments, command in cases:
                host.main(["--checkout", "/fixture", *arguments])
                parsed = dispatch.call_args.args[0]
                self.assertEqual(parsed.command, command)
                if command == "restore":
                    self.assertTrue(parsed.accept_data_loss)
                    self.assertEqual(parsed.backup, "cold-old")
                if command == "plan":
                    self.assertTrue(parsed.latest_stable)

    def test_patch_family(self):
        host.patch_family(
            "authelia/authelia:4.39.27", "docker.io/authelia/authelia:4.39.28@sha256:" + "a" * 64
        )
        for target in ("4.39.26", "4.40.0", "5.0.0", "latest", "4.39.28-rc1"):
            with self.subTest(target=target), self.assertRaises(host.Error):
                host.patch_family("authelia/authelia:4.39.27", "authelia/authelia:" + target)

    def test_binding_id_is_checkout_specific(self):
        self.assertNotEqual(host.binding_id("/one"), host.binding_id("/two"))
        self.assertRegex(host.binding_id("/one"), r"^checkout-[a-f0-9]{24}$")

    def test_private_authoritative_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            checkout = Path(temp)
            (checkout / "current_config").mkdir(mode=0o700)
            config = checkout / "current_config/config.json"
            config.write_text('{"namespace": "fixture"}')
            config.chmod(0o600)
            self.assertEqual(host.source_config(checkout)[1], {"namespace": "fixture"})
            self.assertEqual(provision.source_config(checkout)[2], {"namespace": "fixture"})
            config.chmod(0o644)
            with self.assertRaises(host.Error):
                host.source_config(checkout)
            with self.assertRaises(provision.Error):
                provision.source_config(checkout)
            config.unlink()
            target = checkout / "other.json"
            target.write_text("{}")
            target.chmod(0o600)
            config.symlink_to(target)
            with self.assertRaises(host.Error):
                host.source_config(checkout)

    def test_public_failure_does_not_expose_unclassified_exception(self):
        with tempfile.TemporaryDirectory() as temp:
            host.record_failure(Path(temp), ValueError("synthetic-private-value"))
            failure = json.loads((Path(temp) / "failure.json").read_text())
            self.assertFalse(failure["public_safe"])
            self.assertEqual((Path(temp) / "failure.json").stat().st_mode & 0o777, 0o600)

    def test_replace_configuration_preserves_owner_and_checks_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_bytes(b"old")
            path.chmod(0o600)
            uid = path.stat().st_uid
            with self.assertRaises(host.Error):
                host.replace_configuration(path, b"new", "wrong")
            self.assertEqual(path.read_bytes(), b"old")
            host.replace_configuration(path, b"new", hashlib.sha256(b"old").hexdigest())
            self.assertEqual(path.read_bytes(), b"new")
            self.assertEqual(path.stat().st_uid, uid)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_pin_publication_preserves_every_other_field(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            source, protected = folder / "source.json", folder / "protected.json"
            values = {
                "image": "authelia/authelia:4.39.27",
                "ldap_password": "synthetic",
                "oidc_clients": [{"client_id": "fixture"}],
            }
            for path in (source, protected):
                path.write_text(json.dumps(values))
                path.chmod(0o600)
            plan = {
                "images": {"image": "authelia/authelia:4.39.28@sha256:" + "a" * 64},
                "config_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
            with patch.object(host, "trusted", side_effect=Path):
                host.publish_image_pins(
                    {"config_path": str(source), "config_file": str(protected)}, folder, plan
                )
            self.assertEqual(json.loads(source.read_text()), values | plan["images"])
            self.assertEqual(source.read_bytes(), protected.read_bytes())

    def test_cpu_normalization_does_not_hide_other_resource_changes(self):
        self.assertEqual(
            host.normalized_resources({"limits": {"cpu": "1000m"}}),
            host.normalized_resources({"limits": {"cpu": "1"}}),
        )
        self.assertNotEqual(
            host.normalized_resources({"limits": {"memory": "512Mi"}}),
            host.normalized_resources({"limits": {"memory": "1Gi"}}),
        )

    def test_worker_gate_requires_systemd(self):
        with (
            patch.object(Path, "read_text", return_value="0::/unrelated\n"),
            self.assertRaises(host.Error),
        ):
            host.require_worker_unit("authelia-maintenance-example")

    def test_guard_detects_configmap_drift(self):
        p = {
            "checkout": "/fixture",
            "config_path": "/fixture/current_config/config.json",
            "source": "/reviewed",
        }
        state = {
            "namespace": "uid",
            "secrets": {},
            "configmaps": {"authelia-config": {"data": "old"}},
            "pvcs": [],
            "deployments": [],
        }
        plan = {
            "profile": p,
            "config_sha256": hashlib.sha256(b"same").hexdigest(),
            "source_hashes": {},
            "env_sha256": hashlib.sha256(b"same").hexdigest(),
            "manifest_sha256": hashlib.sha256(b"same").hexdigest(),
            "before": state,
        }
        current = copy.deepcopy(state)
        current["configmaps"]["authelia-config"]["data"] = "changed"
        with (
            patch.object(host, "profile", return_value=p),
            patch.object(Path, "read_bytes", return_value=b"same"),
            patch.object(host, "tree_hash", return_value={}),
            patch.object(host, "snapshot", return_value=current),
            self.assertRaisesRegex(host.Error, "Live state drifted"),
        ):
            host.guard(p, Path("/private"), plan)

    def test_launcher_help_is_nonmutating_and_complete(self):
        for launcher in ("maintain.sh", "provision-host.sh"):
            for args in ([], ["--help"]):
                result = subprocess.run(
                    ["bash", str(ROOT / launcher), *args], capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Usage:", result.stdout)
        text = (ROOT / "maintain.sh").read_text()
        self.assertIn("authelia-maintenance-v1.py", text)
        self.assertNotIn("sudo python", text)

    def test_legacy_cli_cannot_bypass_coordinator(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/cli.py"), "maintain", "restart"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("direct maintenance is disabled", result.stderr)

    def test_isolated_interpreter_contract(self):
        for script in ("host_maintenance.py", "provision_host.py"):
            self.assertEqual(
                (ROOT / "scripts" / script).read_text().splitlines()[0], "#!/usr/bin/python3.12 -I"
            )
        self.assertNotIn("import yaml", (ROOT / "scripts/host_maintenance.py").read_text())


class ProvisionTests(unittest.TestCase):
    def test_capability_probe_has_no_writes(self):
        with (
            patch.object(provision, "stage") as stage,
            patch.object(provision, "enroll") as enroll,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(provision.main(["--protocol-version"]), 0)
            self.assertEqual(out.getvalue().strip(), "authelia-enrollment-v1-isolated-helper")
            stage.assert_not_called()
            enroll.assert_not_called()

    def archive(self, extra=None):
        output = io.BytesIO()
        with tarfile.open(
            fileobj=output, mode="w", format=tarfile.PAX_FORMAT, pax_headers={"comment": "a" * 40}
        ) as archive:
            for name in provision.REQUIRED:
                member = tarfile.TarInfo(name)
                member.size = 1
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(b"x"))
            if extra:
                archive.addfile(extra)
        return output.getvalue()

    def test_archive_exact_revision_and_regular_files(self):
        self.assertEqual(
            set(provision.archive_files(self.archive(), "a" * 40)), set(provision.REQUIRED)
        )
        with self.assertRaises(provision.Error):
            provision.archive_files(self.archive(), "b" * 40)
        for name in ("../escape", "/absolute", "scripts/../escape", "scripts/cli.py"):
            with self.subTest(name=name), self.assertRaises(provision.Error):
                provision.archive_files(self.archive(tarfile.TarInfo(name)), "a" * 40)
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/shadow"
        with self.assertRaises(provision.Error):
            provision.archive_files(self.archive(link), "a" * 40)

    def test_settings_require_explicit_storage(self):
        with self.assertRaises(provision.Error):
            provision.settings({"namespace": "fixture"})
        self.assertEqual(
            provision.settings({"namespace": "fixture", "velero_storage_location": "default"}),
            {"namespace": "velero", "storage_location": "default", "ttl": "720h"},
        )

    def test_no_workers_before_replacement(self):
        with (
            patch.object(
                provision,
                "run",
                return_value="authelia-maintenance-fixture.service loaded active running",
            ),
            self.assertRaises(provision.Error),
        ):
            provision.no_workers()


class ConfigurationTests(unittest.TestCase):
    def test_maintenance_fields_validation(self):
        setup = load("setup")
        values = setup.defaults() | {"ldap_password": "synthetic-fixture-only"}
        setup.validate(values)
        for field, invalid in (
            ("kubeconfig", "relative"),
            ("velero_namespace", values["namespace"]),
            ("velero_storage_location", "../bad"),
            ("velero_backup_ttl", "0h"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                setup.validate(values | {field: invalid})

    def test_native_storage_gates_fail_closed(self):
        with patch.dict(sys.modules, {"setup": load("setup")}):
            cli = load("cli")
        config = {"namespace": "fixture", "oidc_clients": []}
        good = b"Schema Version: 23\nSchema Upgrade Available: no\nSchema Encryption Key: valid\n"
        with patch.object(
            cli, "kube", side_effect=[good, b"Storage Encryption Key Validation: SUCCESS\n"]
        ):
            cli.storage_checks(config)
        for schema in (b"", b"Current Schema Version: 22\nLatest Schema Version: 23\n"):
            with patch.object(cli, "kube", return_value=schema), self.assertRaises(ValueError):
                cli.storage_checks(config)
        with (
            patch.object(cli, "kube", side_effect=[good, b"FAILURE"]),
            self.assertRaises(ValueError),
        ):
            cli.storage_checks(config)


class ResolverTests(unittest.TestCase):
    def test_backup_provenance_binds_index_to_platform_image_id_offline(self):
        child = "sha256:" + "c" * 64
        body = json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": child,
                        "platform": {"os": "linux", "architecture": "amd64"},
                    }
                ],
            }
        ).encode()
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        image = "authelia/authelia:4.39.27"
        with patch.object(stable, "fetch", return_value=(body, {"Docker-Content-Digest": digest})):
            evidence = stable.workload_provenance(image, ["docker.io/authelia/authelia@" + child])
            with self.assertRaisesRegex(ValueError, "imageID"):
                stable.workload_provenance(image, ["sha256:" + "d" * 64])
            with self.assertRaisesRegex(ValueError, "official"):
                stable.workload_provenance("hostile.example/authelia:4.39.27", [child])
        with patch.object(stable, "fetch", side_effect=AssertionError("no historical tag lookup")):
            self.assertEqual(
                stable.validate_provenance(evidence), "docker.io/" + image + "@" + digest
            )
            for key, value in (
                ("image", evidence["image"][:-1] + "f"),
                ("imageIDs", ["evil.example/authelia@" + child]),
                ("manifest", body.decode() + " "),
            ):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    stable.validate_provenance(evidence | {key: value})

    def test_stability_metadata(self):
        self.assertEqual(stable.stable({"tag_name": "v4.39.28"}), "4.39.28")
        for release in (
            {"tag_name": "v4.39.28", "prerelease": True},
            {"tag_name": "v4.39.28", "draft": True},
            {"tag_name": "v4.39.28-rc1"},
        ):
            with self.assertRaises(ValueError):
                stable.stable(release)

    def test_selected_tag_resolves_without_changing_release(self):
        selected = "docker.io/authelia/authelia:4.39.28"
        pinned = selected + "@sha256:" + "a" * 64
        release = {"tag_name": "v4.39.28", "html_url": "https://example.com/release"}
        with (
            patch.object(stable, "fetch", return_value=(json.dumps(release).encode(), {})),
            patch.object(stable, "digest", return_value=pinned),
        ):
            self.assertEqual(stable.verify_selected({"image": selected})["image"]["image"], pinned)
            with self.assertRaises(ValueError):
                stable.verify_selected({"image": selected + "@sha256:" + "b" * 64})

    def test_registry_digest_is_verified_from_actual_bytes(self):
        body = b'{"schemaVersion":2}'
        image = "docker.io/authelia/authelia:4.39.28"
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        with patch.object(stable, "fetch", return_value=(body, {"Docker-Content-Digest": digest})):
            self.assertEqual(stable.digest(image), image + "@" + digest)
        with (
            patch.object(
                stable,
                "fetch",
                return_value=(body, {"Docker-Content-Digest": "sha256:" + "0" * 64}),
            ),
            self.assertRaises(ValueError),
        ):
            stable.digest(image)


if __name__ == "__main__":
    unittest.main()
