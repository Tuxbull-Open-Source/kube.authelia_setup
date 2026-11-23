#!/usr/bin/env python3
"""Mocked unit/sequence tests only: no CLI invocation or live cluster access."""

# Adapted from kube.hermes_setup/scripts/velero_recovery.py and tests/velero-recovery.py.
# Copyright (c) 2026 hermes-speedboat; MIT license, see repository LICENSE.
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "recovery", Path(__file__).resolve().parents[1] / "scripts/velero_recovery.py"
)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
BINDING = {
    "checkout": "/example/checkout",
    "namespace": "example-app",
    "namespace_uid": "ns-original",
    "cluster_uid": "cluster-original",
    "pvc_uids": {"authelia-data": "data-original"},
    "kubeconfig": "/protected/kubeconfig",
    "velero": {"storage_location": "primary"},
}
SOURCE_IMAGE = "authelia/authelia:4.39.27"
MANIFEST = json.dumps({"schemaVersion": 2, "config": {}, "layers": []})
PIN = "docker.io/" + SOURCE_IMAGE + "@sha256:" + hashlib.sha256(MANIFEST.encode()).hexdigest()
PROVENANCE = {
    "sourceImage": SOURCE_IMAGE,
    "image": PIN,
    "manifest": MANIFEST,
    "imageIDs": [PIN.split(":4.39.27")[0] + "@" + PIN.split("@")[1]],
}
PROBES = "a" * 64 + "  /data/sample\n600:0:0\n"


def obj(name, uid=None, spec=None, status=None):
    return {
        "metadata": {"name": name, "uid": uid or name + "-uid"},
        "spec": spec or {},
        "status": status or {},
    }


class Fake(r.RecoveryBackend):
    """In-memory Kubernetes/Velero fixture; command effects are explicitly mocked."""

    def __init__(self):
        super().__init__(BINDING)
        self.nsuid = BINDING["namespace_uid"]
        self.pvcuids = dict(BINDING["pvc_uids"])
        self.deps = [
            obj(
                "authelia",
                spec={
                    "replicas": 2,
                    "template": {
                        "spec": {"containers": [{"name": "authelia", "image": SOURCE_IMAGE}]}
                    },
                },
            )
        ]
        self.pods, self.backups, self.restores, self.records = [], {}, {}, {}
        self.actions, self.objects = [], []
        self.fail_backup = self.fail_resume = self.fail_remove = self.bad_hash = False
        self.deleted = False

    def _get(self, kind, name=None, ns=None):
        if name is None:
            return {"items": self._items(kind, ns)}
        if kind == "namespace":
            value = obj(name, "cluster-original" if name == "kube-system" else self.nsuid)
            value["metadata"]["labels"] = {"app.kubernetes.io/managed-by": "kube.authelia_setup"}
            return value
        if kind == "backupstoragelocations.velero.io":
            return obj(name, status={"phase": "Available"})
        if kind == "daemonset":
            return obj(name, status={"numberReady": 1, "desiredNumberScheduled": 1})
        if kind == "storageclass":
            return {"provisioner": "example.com/dynamic"}
        if kind == "persistentvolume":
            claim = name.removeprefix("pv-")
            return obj(
                name,
                spec={
                    "claimRef": {"uid": self.pvcuids[claim], "namespace": self.binding["namespace"]}
                },
            )
        if kind == "deployment":
            if name == "velero" and ns == self.velero_namespace:
                return obj(
                    name,
                    spec={
                        "template": {
                            "spec": {
                                "containers": [{"name": "velero", "image": "velero/velero:v1.18.4"}]
                            }
                        }
                    },
                )
            return copy.deepcopy(next(d for d in self.deps if d["metadata"]["name"] == name))
        if kind == "pod":
            return copy.deepcopy(next(p for p in self.pods if p["metadata"]["name"] == name))
        if kind == "backups.velero.io":
            return copy.deepcopy(self.backups[name])
        if kind == "restores.velero.io":
            return copy.deepcopy(self.restores[name])
        raise AssertionError(("unexpected get", kind))

    def _items(self, kind, ns=None):
        if kind in ("persistentvolumeclaims", "pvc"):
            return [
                obj(
                    n,
                    u,
                    {
                        "storageClassName": "dynamic",
                        "volumeName": ("new-" if self.deleted else "") + "pv-" + n,
                    },
                    {"phase": "Bound"},
                )
                for n, u in self.pvcuids.items()
            ]
        if kind == "deployments":
            return copy.deepcopy(self.deps)
        if kind == "pods":
            return copy.deepcopy(self.pods)
        if kind == "namespaces":
            return [] if self.nsuid is None else [obj(self.binding["namespace"], self.nsuid)]
        if kind == "backups.velero.io":
            return list(self.backups.values())
        if kind == "restores.velero.io":
            return list(self.restores.values())
        if kind in ("podvolumebackups.velero.io", "podvolumerestores.velero.io"):
            return [p for (k, _), records in self.records.items() if k == kind for p in records]
        return []

    def _run(self, argv, data=None, timeout=90):
        if "api-resources" in argv:
            return "namespaces\npersistentvolumes\ncustomresourcedefinitions.apiextensions.k8s.io\n"
        self.actions.append(list(argv))
        if "scale" in argv:
            name = next(a.split("/", 1)[1] for a in argv if a.startswith("deployment/"))
            replicas = int(next(a.split("=")[1] for a in argv if a.startswith("--replicas=")))
            if self.fail_resume and replicas:
                raise r.RecoveryError("mock resume failure")
            next(d for d in self.deps if d["metadata"]["name"] == name)["spec"]["replicas"] = (
                replicas
            )
        if "exec" in argv:
            return PROBES.replace("a", "c") if self.bad_hash and self.deleted else PROBES
        if "delete" in argv and "pod" in argv:
            if self.fail_remove:
                raise r.RecoveryError("mock helper failure")
            self.pods = []
        if "delete" in argv and "namespace" in argv:
            self.nsuid, self.pods, self.deleted = None, [], True
        if "annotate" in argv:
            name = argv[argv.index("backups.velero.io") + 1]
            self.backups[name]["metadata"]["annotations"][r.SEAL] = "true"
        return ""

    def _image_provenance(self, ns):
        record = copy.deepcopy(PROVENANCE)
        record["sourceImage"] = self._workload_image(self.deps)
        record["image"] = (
            "docker.io/"
            + record["sourceImage"].removeprefix("docker.io/").split("@")[0]
            + "@"
            + PIN.split("@")[1]
        )
        return record

    def _archive_scope(self, name, meta, folder):
        self.actions.append(("archive-scope", name))

    def _create(self, value):
        self.objects.append(copy.deepcopy(value))
        kind, name = value["kind"], value["metadata"]["name"]
        if kind == "Pod":
            value = copy.deepcopy(value)
            value["metadata"]["uid"] = "helper-uid"
            value["status"] = {"phase": "Running"}
            self.pods = [value]
        if kind == "Backup":
            if self.fail_backup:
                raise r.RecoveryError("mock backup failure")
            value = copy.deepcopy(value)
            value["status"] = {"phase": "Completed", "expiration": "2099-01-01T00:00:00Z"}
            self.backups[name] = value
            m = json.loads(value["metadata"]["annotations"][r.KEY])
            self._records(name, m)
        if kind == "Restore":
            self.nsuid = "ns-restored"
            self.pvcuids = {n: u + "-new" for n, u in self.pvcuids.items()}
            for d in self.deps:
                d["metadata"]["uid"] += "-new"
            m = json.loads(
                self.backups[value["spec"]["backupName"]]["metadata"]["annotations"][r.KEY]
            )
            modifier = next(o for o in reversed(self.objects) if o["kind"] == "ConfigMap")
            rules = json.loads(modifier["data"]["rules.yaml"])["resourceModifierRules"]
            for rule in rules:
                self.assert_single_patch_type(rule)
                if rule["conditions"]["groupResource"] == "deployments.apps":
                    for d in self.deps:
                        if "mergePatches" in rule:
                            d["spec"]["replicas"] = json.loads(
                                rule["mergePatches"][0]["patchData"]
                            )["spec"]["replicas"]
                        if "patches" in rule:
                            d["spec"]["template"]["spec"]["containers"][0]["image"] = rule[
                                "patches"
                            ][0]["value"]
            helper = self._helper(m)
            helper["metadata"]["uid"] = "helper-restored"
            helper["status"] = {"phase": "Running"}
            self.pods = [helper]
            self.restores[name] = dict(value, status={"phase": "Completed"})
            self._records(name, dict(m, helperUID="helper-restored"), True)

    @staticmethod
    def assert_single_patch_type(rule):
        assert sum(key in rule for key in ("patches", "mergePatches", "strategicPatches")) == 1

    def _records(self, name, m, restore=False):
        records = []
        for volume in sorted(r.VOLUMES):
            p = obj(
                "record-" + volume,
                spec={
                    "volume": volume,
                    "pod": {
                        "name": m["helper"],
                        "namespace": m["namespace"],
                        "uid": m["helperUID"],
                    },
                    "uploaderType": "kopia",
                    "backupStorageLocation": self.location,
                },
                status={"phase": "Completed", "snapshotID": "snapshot-" + volume},
            )
            p["metadata"]["labels"] = {
                ("velero.io/restore-name" if restore else "velero.io/backup-name"): name,
                "velero.io/pvc-uid": m["pvcs"]["authelia-" + volume],
            }
            p["metadata"]["annotations"] = {"velero.io/pvc-name": "authelia-" + volume}
            records.append(p)
        self.records[
            ("podvolumerestores.velero.io" if restore else "podvolumebackups.velero.io", name)
        ] = records


class UnreadyFake(Fake):
    """CrashLoop fixture using the real provenance and controller ownership gates."""

    def break_current_app(self):
        self.deps[0]["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "authelia/authelia:4.39.28"
        )
        self.deps[0]["status"] = {"availableReplicas": 0}
        self.pods = []
        for i in range(2):
            pod = obj(
                "crashloop-" + str(i),
                spec=copy.deepcopy(self.deps[0]["spec"]["template"]["spec"]),
                status={
                    "phase": "Running",
                    "containerStatuses": [
                        {
                            "name": "authelia",
                            "ready": False,
                            "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                        }
                    ],
                },
            )
            pod["metadata"]["ownerReferences"] = [{"uid": "rs-uid", "controller": True}]
            self.pods.append(pod)

    def _items(self, kind, ns=None):
        if kind == "replicasets":
            rs = obj("rs", "rs-uid")
            rs["metadata"]["ownerReferences"] = [
                {"uid": self.deps[0]["metadata"]["uid"], "controller": True}
            ]
            return [rs]
        return super()._items(kind, ns)

    def _run(self, argv, data=None, timeout=90):
        result = super()._run(argv, data, timeout)
        if "scale" in argv and "--replicas=0" in argv:
            self.pods = []
        return result

    def _image_provenance(self, ns):
        return r.RecoveryBackend._image_provenance(self, ns)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        # Match the coordinator contract: it creates this private operation root
        # before diagnostics creates nested directories. Do not rely on umask.
        (self.folder / "restore").mkdir(mode=0o700)
        self.b = Fake()
        self.ns = BINDING["namespace"]

    def test_insecure_operation_directory_still_rejected(self):
        unsafe = self.folder / "unsafe"
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o755)
        with self.assertRaisesRegex(r.RecoveryError, "Operation directory must be private"):
            r.save(unsafe / "state.json", {"fixture": True})
        self.assertFalse((unsafe / "state.json").exists())
        self.assertEqual(unsafe.stat().st_mode & 0o777, 0o755)

    def backup(self):
        return self.b.backup(self.ns, self.folder / "backup")

    def test_restore_point_survives_verified_identity_reenrollment(self):
        name, original = self.backup()
        result = self.b.restore(name, self.ns, self.folder / "restore")
        self.b.binding.update(namespace_uid=result["namespace_uid"], pvc_uids=result["pvc_uids"])
        self.assertEqual(self.b.eligible(name, self.ns)["pvcs"], original["pvcs"])
        foreign = r.RecoveryBackend({**self.b.binding, "checkout": "/example/unrelated-checkout"})
        with (
            patch.object(foreign, "_get", side_effect=self.b._get),
            patch.object(foreign, "_items", side_effect=self.b._items),
        ):
            with self.assertRaisesRegex(r.RecoveryError, "Backup identity"):
                foreign.eligible(name, self.ns)

    def test_unsupported_velero_blocks_before_mutation(self):
        original = self.b._get

        def get(kind, name=None, ns=None):
            if kind == "deployment" and name == "velero":
                return obj(
                    name,
                    spec={
                        "template": {
                            "spec": {
                                "containers": [{"name": "velero", "image": "velero/velero:v1.17.0"}]
                            }
                        }
                    },
                )
            return original(kind, name, ns)

        with patch.object(self.b, "_get", side_effect=get):
            with self.assertRaisesRegex(r.RecoveryError, "1.18"):
                self.b.preflight(self.ns)
        self.assertFalse(self.b.actions)

    def test_external_replica_change_not_overwritten(self):
        meta = self.b.preflight(self.ns)
        self.b.deps[0]["spec"]["replicas"] = 3
        with self.assertRaises(r.RecoveryError):
            self.b._scale(meta, True)
        self.assertEqual(self.b.deps[0]["spec"]["replicas"], 3)

    def test_probe_shell_sqlite_fallback_private_names_and_empty(self):
        import hashlib

        volumes = self.folder / "volume"
        volumes.mkdir(mode=0o700)
        database = volumes / "db.sqlite3"
        database.write_bytes(b"synthetic sqlite bytes")
        database.chmod(0o600)
        private = volumes / "personal\nname.txt"
        private.write_text("synthetic-private-content")

        def shell(argv, *args, **kwargs):
            script = argv[-1].replace("/data", str(volumes))
            done = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout.replace(str(volumes), "/data")

        with patch.object(self.b, "_run", side_effect=shell):
            text = self.b._probes({"namespace": self.ns, "helper": "helper"})
            self.assertIn(hashlib.sha256(database.read_bytes()).hexdigest(), text)
            self.assertIn("600:", text)
            database.unlink()
            text = self.b._probes({"namespace": self.ns, "helper": "helper"})
            self.assertIn(hashlib.sha256(private.read_bytes()).hexdigest(), text)
            self.assertNotIn("private-content", text)
            self.assertNotIn("personal", text)
            private.unlink()
            empty = self.b._probes({"namespace": self.ns, "helper": "helper"})
            self.assertIn("/data/no-files", empty)

    def test_archive_rejects_foreign_scope_and_missing_namespace(self):
        import io
        import tarfile

        meta = self.b.preflight(self.ns)
        folder = self.folder / "archive"
        folder.mkdir()
        meta["imageProvenance"] = PROVENANCE
        for case in ("good", "missing", "foreign", "cluster", "wrong-image"):
            deployment = copy.deepcopy(self.b.deps[0])
            deployment["kind"] = "Deployment"
            deployment["metadata"]["namespace"] = self.ns
            if case == "wrong-image":
                deployment["spec"]["template"]["spec"]["containers"][0]["image"] = (
                    "authelia/authelia:4.39.28"
                )
            records = [
                ("resources/deployments.apps/namespaces/" + self.ns + "/authelia.json", deployment)
            ]
            if case != "missing":
                records.append(
                    (
                        "resources/namespaces/cluster/" + self.ns + ".json",
                        {
                            "apiVersion": "v1",
                            "kind": "Namespace",
                            "metadata": {
                                "name": self.ns,
                                "uid": meta["namespaceUID"],
                                "labels": {"app.kubernetes.io/managed-by": "kube.authelia_setup"},
                            },
                        },
                    )
                )
            if case == "foreign":
                records.append(
                    (
                        "resources/secrets/namespaces/other/example.json",
                        {"kind": "Secret", "metadata": {"name": "example", "namespace": "other"}},
                    )
                )
            if case == "cluster":
                records.append(
                    (
                        "resources/clusterroles.rbac.authorization.k8s.io/cluster/example.json",
                        {
                            "kind": "ClusterRole",
                            "metadata": {"name": "example", "namespace": self.ns},
                        },
                    )
                )
            with tarfile.open(folder / "velero-metadata.tar.gz", "w:gz") as archive:
                for name, obj in records:
                    data = json.dumps(obj).encode()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            with patch.object(self.b, "_run", return_value=""), self.subTest(case=case):
                if case == "good":
                    r.RecoveryBackend._archive_scope(self.b, "backup", meta, folder)
                else:
                    with self.assertRaises(r.RecoveryError):
                        r.RecoveryBackend._archive_scope(self.b, "backup", meta, folder)

    def test_first_tag_only_backup_then_newer_upgrade_restores_old_pin(self):
        self.assertEqual(self.b._workload_image(self.b.deps), SOURCE_IMAGE)
        name, meta = self.backup()
        newer = "docker.io/authelia/authelia:4.39.28@" + PIN.split("@")[1]
        self.b.deps[0]["spec"]["template"]["spec"]["containers"][0]["image"] = newer
        result = self.b.restore(name, self.ns, self.folder / "restore")
        self.assertEqual(meta["imageProvenance"]["sourceImage"], SOURCE_IMAGE)
        self.assertEqual(result["image"], PIN)
        self.assertEqual(self.b._workload_image(self.b.deps), PIN)
        self.assertEqual(self.b.deps[0]["spec"]["replicas"], 2)

    def test_missing_or_hostile_provenance_blocks_restore_before_safety_backup(self):
        name, _ = self.backup()
        original = copy.deepcopy(self.b.backups[name])
        for field, value in (
            ("image", PIN[:-1] + "0"),
            ("imageIDs", ["docker.io/hostile/authelia@" + PIN.split("@")[1]]),
            ("manifest", MANIFEST + " "),
        ):
            self.b.backups[name] = copy.deepcopy(original)
            meta = json.loads(original["metadata"]["annotations"][r.KEY])
            meta["imageProvenance"][field] = value
            self.b.backups[name]["metadata"]["annotations"][r.KEY] = json.dumps(meta)
            with self.subTest(field=field), self.assertRaises(r.RecoveryError):
                self.b.restore(name, self.ns, self.folder / "restore")
            self.assertFalse(self.b.deleted)
            self.assertEqual(len(self.b.backups), 1)
        meta.pop("imageProvenance")
        self.b.backups[name]["metadata"]["annotations"][r.KEY] = json.dumps(meta)
        with self.assertRaisesRegex(r.RecoveryError, "backup-time image provenance"):
            self.b.eligible(name, self.ns)

    def test_real_provenance_gate_matches_ready_pod_to_registry_before_stopping(self):
        pod = obj(
            "authelia-pod",
            spec={"containers": [{"name": "authelia", "image": SOURCE_IMAGE}]},
            status={
                "phase": "Running",
                "containerStatuses": [
                    {"name": "authelia", "ready": True, "imageID": PROVENANCE["imageIDs"][0]}
                ],
            },
        )
        self.b.pods = [pod, copy.deepcopy(pod)]
        resolver = self.b._resolver()
        with (
            patch.object(self.b, "_resolver", return_value=resolver),
            patch.object(resolver, "registry_manifest", return_value=(PIN, MANIFEST)),
        ):
            record = r.RecoveryBackend._image_provenance(self.b, self.ns)
            self.assertEqual(record["image"], PIN)
            self.assertFalse(self.b.actions)
            self.b.pods[0]["status"]["containerStatuses"][0]["imageID"] = "sha256:" + "f" * 64
            with self.assertRaisesRegex(r.RecoveryError, "registry/Pod"):
                r.RecoveryBackend._image_provenance(self.b, self.ns)
            self.b.pods = []
            with self.assertRaisesRegex(r.RecoveryError, "Running Authelia"):
                r.RecoveryBackend._image_provenance(self.b, self.ns)

    def test_restore_wrong_image_never_resumes(self):
        name, _ = self.backup()
        create = self.b._create

        def wrong_image(value):
            create(value)
            if value["kind"] == "Restore":
                self.b.deps[0]["spec"]["template"]["spec"]["containers"][0]["image"] = SOURCE_IMAGE

        with patch.object(self.b, "_create", side_effect=wrong_image):
            with self.assertRaises(r.RecoveryError):
                self.b.restore(name, self.ns, self.folder / "restore")
        self.assertEqual(self.b.deps[0]["spec"]["replicas"], 0)

    def test_explicit_cli_binding(self):
        for cmd in (self.b.K, self.b.V):
            self.assertEqual(cmd.count("--kubeconfig"), 1)
            self.assertEqual(cmd[cmd.index("--kubeconfig") + 1], BINDING["kubeconfig"])
        self.assertEqual(self.b.ttl, "720h")
        self.assertEqual(self.b.ROOT, Path("/srv/backup/authelia-maintenance/recovery"))

    def test_namespace_selector_rejected(self):
        with self.assertRaises(r.RecoveryError):
            self.b.preflight("another-app")
        self.assertFalse(self.b.actions)

    def test_identity_drift_blocks_mutation(self):
        for field in ("nsuid", "pvcuids"):
            with self.subTest(field=field):
                self.b = Fake()
                setattr(self.b, field, "wrong" if field == "nsuid" else {})
                with self.assertRaises(r.RecoveryError):
                    self.backup()
                self.assertFalse(self.b.actions)

    def test_preflight_is_read_only(self):
        m = self.b.preflight(self.ns)
        self.assertEqual(m["replicas"], {"authelia": 2})
        self.assertFalse(self.b.actions)
        self.assertFalse(self.b.objects)

    def test_backup_sealed_after_cleanup_and_resume(self):
        name, meta = self.backup()
        self.assertEqual(self.b.eligible(name, self.ns), meta)
        self.assertFalse(self.b.pods)
        self.assertEqual(self.b.deps[0]["spec"]["replicas"], 2)
        seal_index = next(i for i, a in enumerate(self.b.actions) if "annotate" in a)
        cleanup_index = next(i for i, a in enumerate(self.b.actions) if "delete" in a)
        rollout_index = next(i for i, a in enumerate(self.b.actions) if "rollout" in a)
        self.assertLess(cleanup_index, rollout_index)
        self.assertLess(rollout_index, seal_index)
        self.assertEqual((self.folder / "backup" / "replicas.json").stat().st_mode & 0o777, 0o600)

    def test_backup_failure_leaves_writers_stopped(self):
        self.b.fail_backup = True
        with self.assertRaises(r.RecoveryError):
            self.backup()
        self.assertEqual([d["spec"]["replicas"] for d in self.b.deps], [0])
        self.assertFalse(self.b.pods)
        self.assertFalse(any("annotate" in a for a in self.b.actions))

    def test_failed_resume_preserves_metadata_and_never_seals(self):
        self.b.fail_resume = True
        with self.assertRaises(r.RecoveryError):
            self.backup()
        state = json.loads((self.folder / "backup" / "resume.json").read_text())
        self.assertTrue(state["manualRecoveryRequired"])
        self.assertFalse(any("annotate" in a for a in self.b.actions))

    def test_helper_cleanup_failure_keeps_writers_stopped(self):
        self.b.fail_remove = True
        with self.assertRaises(r.RecoveryError):
            self.backup()
        self.assertEqual(self.b.deps[0]["spec"]["replicas"], 0)
        self.assertFalse(any("annotate" in a for a in self.b.actions))

    def test_volume_identity_and_count_fail_closed(self):
        name, m = self.backup()
        key = ("podvolumebackups.velero.io", name)
        original = copy.deepcopy(self.b.records[key])
        for change in ("duplicate", "wrong-uid", "restic", "failed"):
            with self.subTest(change=change):
                records = copy.deepcopy(original)
                if change == "duplicate":
                    records.append(copy.deepcopy(records[0]))
                if change == "wrong-uid":
                    records[0]["spec"]["pod"]["uid"] = "wrong"
                if change == "restic":
                    records[0]["spec"]["uploaderType"] = "restic"
                if change == "failed":
                    records[0]["status"]["phase"] = "Failed"
                self.b.records[key] = records
                with self.assertRaises(r.RecoveryError):
                    self.b.eligible(name, self.ns)

    def test_unsealed_expired_wrong_scope_rejected(self):
        name, _ = self.backup()
        original = copy.deepcopy(self.b.backups[name])
        for mode in ("unsealed", "expired", "scope", "warnings"):
            b = copy.deepcopy(original)
            if mode == "unsealed":
                b["metadata"]["annotations"].pop(r.SEAL)
            if mode == "expired":
                b["status"]["expiration"] = "2000-01-01T00:00:00Z"
            if mode == "scope":
                b["spec"]["includedNamespaces"] = ["*"]
            if mode == "warnings":
                b["status"]["warnings"] = 1
            self.b.backups[name] = b
            with self.subTest(mode=mode), self.assertRaises(r.RecoveryError):
                self.b.eligible(name, self.ns)

    def test_native_csi_default_exclusions_are_narrowly_allowed(self):
        name, _ = self.backup()
        spec = self.b.backups[name]["spec"]
        spec["excludedClusterScopedResources"].append(
            "volumesnapshotcontents.snapshot.storage.k8s.io"
        )
        spec["excludedNamespaceScopedResources"].append("volumesnapshots.snapshot.storage.k8s.io")
        self.b.eligible(name, self.ns)
        spec["excludedNamespaceScopedResources"].append("secrets")
        with self.assertRaises(r.RecoveryError):
            self.b.eligible(name, self.ns)

    def test_restore_warning_results_not_endpoint_log_chatter(self):
        meta = self.b.preflight(self.ns)
        self.b.restores["restore"] = obj("restore", status={"phase": "Completed", "warnings": 2})
        lines = [
            'level=warning msg="stat /resources/persistentvolumes/cluster/'
            + p
            + '.json: no such file or directory" logSource="pkg/controller/restore_controller.go:616"'
            for p in meta["sourcePVs"].values()
        ]
        lines.append(
            'level=warning msg="kube-root-ca.crt already exists; in-cluster version is different" logSource="pkg/controller/restore_controller.go:620"'
        )
        lines.append(
            'level=warning msg="No annotations found, using restore spec setting: false" logSource="pkg/restore/restore.go:2630"'
        )
        with patch.object(self.b, "_run", return_value="\n".join(lines)):
            self.b._velero_wait("restores", "restore", meta)
        lines[-1] = (
            'level=warning msg="unexpected warning" logSource="pkg/controller/restore_controller.go:620"'
        )
        with patch.object(self.b, "_run", return_value="\n".join(lines)):
            with self.assertRaises(r.RecoveryError):
                self.b._velero_wait("restores", "restore", meta)

    def test_safe_listing_does_not_export_metadata(self):
        self.backup()
        result = self.b.list_backups(self.ns)
        self.assertTrue(result[0]["eligible"])
        self.assertNotIn("probes", json.dumps(result))
        self.assertNotIn("namespaceUID", json.dumps(result))

    def test_restore_full_mocked_sequence_new_identities(self):
        name, _ = self.backup()
        result = self.b.restore(name, self.ns, self.folder / "restore")
        self.assertEqual(result["namespace_uid"], "ns-restored")
        self.assertTrue(result["reenrollmentRequired"])
        self.assertEqual([d["spec"]["replicas"] for d in self.b.deps], [2])
        self.assertFalse(self.b.pods)
        self.assertEqual(len(self.b.backups), 2)
        restore = next(o for o in self.b.objects if o["kind"] == "Restore")
        self.assertTrue(restore["spec"]["includeClusterResources"])
        self.assertNotIn("persistentvolumes", restore["spec"]["excludedResources"])
        self.assertNotIn("persistentvolumeclaims", restore["spec"]["excludedResources"])
        self.assertEqual(
            self.b.backups[name]["spec"]["includedClusterScopedResources"], ["namespaces"]
        )
        self.assertEqual(
            set(self.b.backups[name]["spec"]["excludedClusterScopedResources"]),
            {"persistentvolumes", "customresourcedefinitions.apiextensions.k8s.io"},
        )
        modifier = next(o for o in self.b.objects if o["kind"] == "ConfigMap")
        rules = json.loads(modifier["data"]["rules.yaml"])["resourceModifierRules"]
        self.assertIsNone(
            json.loads(rules[0]["mergePatches"][0]["patchData"])["spec"]["volumeName"]
        )
        with self.assertRaises(r.RecoveryError):
            self.b.preflight(self.ns)

    def test_hash_mismatch_never_resumes_restored_workloads(self):
        name, _ = self.backup()
        self.b.bad_hash = True
        with self.assertRaises(r.RecoveryError):
            self.b.restore(name, self.ns, self.folder / "restore")
        self.assertEqual([d["spec"]["replicas"] for d in self.b.deps], [0])
        self.assertTrue((self.folder / "restore" / "restore-failure.json").exists())

    def test_unready_normal_backup_rejected_before_mutation(self):
        b = UnreadyFake()
        b.break_current_app()
        with self.assertRaisesRegex(r.RecoveryError, "not a ready"):
            b.backup(self.ns, self.folder / "normal")
        self.assertFalse(b.actions)
        self.assertFalse(b.objects)

    def test_unready_restore_safety_checkpoint_is_never_eligible(self):
        b = UnreadyFake()
        with patch.object(b, "_image_provenance", return_value=PROVENANCE):
            name, _ = b.backup(self.ns, self.folder / "good")
        b.break_current_app()
        b.actions.clear()
        result = b.restore(name, self.ns, self.folder / "restore")
        self.assertEqual(result["image"], PIN)
        safety = b.backups[result["safetyBackup"]]
        metadata = json.loads(safety["metadata"]["annotations"][r.KEY])
        self.assertEqual(metadata["checkpointPurpose"], "safety-only")
        self.assertFalse(metadata["restoreEligible"])
        self.assertNotIn("imageProvenance", metadata)
        self.assertNotIn(r.SEAL, safety["metadata"]["annotations"])
        # Even an accidentally added normal seal must not promote this checkpoint.
        safety["metadata"]["annotations"][r.SEAL] = "true"
        with self.assertRaisesRegex(r.RecoveryError, "Safety-only"):
            b.eligible(result["safetyBackup"], self.ns)
        deletion = next(i for i, a in enumerate(b.actions) if "delete" in a and "namespace" in a)
        self.assertFalse(any("--replicas=2" in a for a in b.actions[:deletion]))
        self.assertTrue(any("--replicas=2" in a for a in b.actions[deletion:]))

    def test_unready_safety_failure_or_unsafe_helper_never_deletes_or_resumes(self):
        for failure in ("fail_backup", "fail_remove"):
            with self.subTest(failure=failure):
                b = UnreadyFake()
                with patch.object(b, "_image_provenance", return_value=PROVENANCE):
                    name, _ = b.backup(self.ns, self.folder / failure / "good")
                b.break_current_app()
                b.actions.clear()
                setattr(b, failure, True)
                with self.assertRaises(r.RecoveryError):
                    b.restore(name, self.ns, self.folder / failure / "restore")
                self.assertFalse(b.deleted)
                self.assertFalse(any("--replicas=2" in a for a in b.actions))
                self.assertFalse(
                    (self.folder / failure / "restore/safety/safety-complete.json").exists()
                )
                self.assertEqual(b.deps[0]["spec"]["replicas"], 0)

    def test_safety_backup_failure_prevents_namespace_deletion(self):
        name, _ = self.backup()
        self.b.fail_backup = True
        with self.assertRaises(r.RecoveryError):
            self.b.restore(name, self.ns, self.folder / "restore")
        self.assertFalse(self.b.deleted)

    def test_subprocess_failures_do_not_leak_output(self):
        b = r.RecoveryBackend(BINDING)
        for failure in (
            subprocess.CompletedProcess([], 1, "SECRET stdout", "SECRET stderr"),
            subprocess.TimeoutExpired("SECRET command", 1, output="SECRET stdout"),
        ):
            kwargs = (
                {"side_effect": failure}
                if isinstance(failure, Exception)
                else {"return_value": failure}
            )
            with (
                patch.object(r.subprocess, "run", **kwargs),
                self.assertRaises(r.RecoveryError) as caught,
            ):
                b._run(b.K)
            self.assertNotIn("SECRET", str(caught.exception))

    def test_active_velero_blocks_backup(self):
        self.b.backups["external"] = obj("external", status={"phase": "InProgress"})
        with self.assertRaises(r.RecoveryError):
            self.backup()
        self.assertFalse(self.b.actions)

    def test_cluster_identity_blocks_mutation(self):
        original = self.b._get

        def get(kind, name=None, ns=None):
            if kind == "namespace" and name == "kube-system":
                return obj(name, "wrong-cluster")
            return original(kind, name, ns)

        with patch.object(self.b, "_get", side_effect=get), self.assertRaises(r.RecoveryError):
            self.backup()
        self.assertFalse(self.b.actions)

    def test_storage_and_node_agent_fail_closed(self):
        original = self.b._get
        for target in ("backupstoragelocations.velero.io", "daemonset"):

            def get(kind, name=None, ns=None, target=target):
                if kind == target:
                    return obj(name, status={})
                return original(kind, name, ns)

            with (
                self.subTest(target=target),
                patch.object(self.b, "_get", side_effect=get),
                self.assertRaises(r.RecoveryError),
            ):
                self.backup()
        self.assertFalse(self.b.actions)

    def test_unsupported_controllers_block_before_scale(self):
        original = self.b._items
        for target in (
            "statefulsets",
            "daemonsets",
            "cronjobs",
            "horizontalpodautoscalers",
            "replicationcontrollers",
        ):

            def items(kind, ns=None, target=target):
                return [obj("unsupported")] if kind == target else original(kind, ns)

            with (
                self.subTest(target=target),
                patch.object(self.b, "_items", side_effect=items),
                self.assertRaises(r.RecoveryError),
            ):
                self.backup()
        self.assertFalse(self.b.actions)

    def test_unmanaged_pod_blocks_before_scale(self):
        self.b.pods = [obj("writer", status={"phase": "Running"})]
        with self.assertRaises(r.RecoveryError):
            self.backup()
        self.assertFalse(self.b.actions)

    def test_restore_volume_uid_mismatch_blocks_resume(self):
        name, _ = self.backup()
        original = self.b._records

        def records(name, m, restore=False):
            original(name, m, restore)
            if restore:
                self.b.records[("podvolumerestores.velero.io", name)][0]["spec"]["pod"]["uid"] = (
                    "wrong-helper"
                )

        with (
            patch.object(self.b, "_records", side_effect=records),
            self.assertRaises(r.RecoveryError),
        ):
            self.b.restore(name, self.ns, self.folder / "restore")
        self.assertEqual([d["spec"]["replicas"] for d in self.b.deps], [0])

    def test_helper_read_only_and_no_application_image_dependency(self):
        h = self.b._helper(self.b.preflight(self.ns))
        self.assertFalse(h["spec"]["automountServiceAccountToken"])
        self.assertTrue(all(v["readOnly"] for v in h["spec"]["containers"][0]["volumeMounts"]))
        self.assertEqual(
            h["spec"]["containers"][0]["securityContext"]["capabilities"]["add"], ["DAC_OVERRIDE"]
        )

    def test_namespace_ownership_required_before_mutation(self):
        original = self.b._get

        def get(kind, name=None, ns=None):
            value = original(kind, name, ns)
            if kind == "namespace" and name == self.ns:
                value["metadata"]["labels"] = {}
            return value

        with patch.object(self.b, "_get", side_effect=get), self.assertRaises(r.RecoveryError):
            self.backup()
        self.assertFalse(self.b.actions)

    def test_binding_requires_exact_single_pvc_and_pinned_helper(self):
        for change in (
            {"pvc_uids": {}},
            {"pvc_uids": {"authelia-data": "uid", "extra": "uid"}},
            {"velero": {"storage_location": "primary", "helper_image": "busybox:latest"}},
        ):
            with self.subTest(change=change), self.assertRaises(r.RecoveryError):
                r.RecoveryBackend({**BINDING, **change})

    def test_single_data_mount_matches_installer(self):
        helper = self.b._helper(self.b.preflight(self.ns))
        self.assertEqual(
            helper["metadata"]["annotations"]["backup.velero.io/backup-volumes"], "data"
        )
        self.assertEqual(
            helper["spec"]["volumes"],
            [{"name": "data", "persistentVolumeClaim": {"claimName": "authelia-data"}}],
        )
        self.assertEqual(
            helper["spec"]["containers"][0]["volumeMounts"],
            [{"name": "data", "mountPath": "/data", "readOnly": True}],
        )

    def test_duplicate_controller_warning_is_not_accepted(self):
        meta = self.b.preflight(self.ns)
        pv = meta["sourcePVs"]["authelia-data"]
        warning = (
            'level=warning msg="stat /resources/persistentvolumes/cluster/'
            + pv
            + '.json: no such file or directory" logSource="pkg/controller/restore_controller.go:616"'
        )
        self.b.restores["restore"] = obj("restore", status={"phase": "Completed", "warnings": 2})
        with (
            patch.object(self.b, "_run", return_value=warning + "\n" + warning),
            self.assertRaises(r.RecoveryError),
        ):
            self.b._velero_wait("restores", "restore", meta)

    def test_namespace_metadata_drift_blocks_restored_resume(self):
        name, _ = self.backup()
        original = self.b._get

        def get(kind, name=None, ns=None):
            value = original(kind, name, ns)
            if self.b.deleted and kind == "namespace" and name == self.ns:
                value["metadata"]["annotations"] = {"changed": "true"}
            return value

        with patch.object(self.b, "_get", side_effect=get), self.assertRaises(r.RecoveryError):
            self.b.restore(name, self.ns, self.folder / "restore")
        self.assertEqual([d["spec"]["replicas"] for d in self.b.deps], [0])

    def test_artifact_symlink_does_not_overwrite_target(self):
        target = self.folder / "target"
        target.write_text("unchanged")
        link = self.folder / "link"
        link.symlink_to(target)
        r.save(link, {"private": True})
        self.assertEqual(target.read_text(), "unchanged")
        self.assertFalse(link.is_symlink())
        self.assertEqual(link.stat().st_mode & 0o777, 0o600)

    def test_pvr_failure_never_resumes(self):
        name, _ = self.backup()
        original = self.b._records

        def records(name, meta, restore=False):
            original(name, meta, restore)
            if restore:
                self.b.records[("podvolumerestores.velero.io", name)][0]["status"]["phase"] = (
                    "Failed"
                )

        with (
            patch.object(self.b, "_records", side_effect=records),
            self.assertRaises(r.RecoveryError),
        ):
            self.b.restore(name, self.ns, self.folder / "restore")
        self.assertEqual([d["spec"]["replicas"] for d in self.b.deps], [0])

    def test_modifier_clears_all_old_binding_fields(self):
        self.b._modifier("modifier", self.ns, {"imageProvenance": PROVENANCE})
        rules = json.loads(self.b.objects[-1]["data"]["rules.yaml"])["resourceModifierRules"]
        patch_data = json.loads(rules[0]["mergePatches"][0]["patchData"])
        self.assertIsNone(patch_data["spec"]["volumeName"])
        self.assertEqual(
            patch_data["metadata"]["annotations"],
            {
                "pv.kubernetes.io/bind-completed": None,
                "pv.kubernetes.io/bound-by-controller": None,
                "volume.kubernetes.io/selected-node": None,
            },
        )
        self.assertEqual(
            json.loads(rules[1]["mergePatches"][0]["patchData"]), {"spec": {"replicas": 0}}
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
