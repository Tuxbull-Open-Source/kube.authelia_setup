#!/usr/bin/python3.12 -I
"""Adapted from kube.hermes_setup (MIT, Copyright (c) 2026 hermes-speedboat).

Reviewed host enrollment. No operator-writable code is executed as root.

Host prerequisite: root-owned regular /usr/bin/python3.12 with protected parents.
Privileged scripts use its fixed isolated (-I) shebang, never PATH or an operator
virtualenv. These modules require only Python's standard library. Install systemd,
sudo, kubectl, Velero and OpenSSL separately; Velero infrastructure must already
exist. Keep /usr/local/libexec traversable (0755) and state directories private (0700).

Bootstrap is deliberately administrator-reviewed, not sudo of this checkout:
1. As the operator, inspect a clean checkout and export the full reviewed commit:
   git --no-replace-objects archive --format=tar --output=source.tar COMMIT
2. An administrator copies source.tar into a root-only staging directory, verifies
   its provenance/commit and reviews its contents independently. Review THIS module
   separately, install it as a regular root-owned 0755 file at
   /usr/local/libexec/authelia-provision-host.py (all parents protected). Before
   replacement, archive the old helper under /srv/backup and audit /CHANGES.md.
   Never sudo python from the checkout or trust an operator-supplied digest alone.
3. From that protected staging directory, the administrator invokes the installed
   helper with --stage-archive PATH --archive-sha256 REVIEWED_SHA256 --revision
   COMMIT. The digest is an administrator attestation, not a signature. Archive
   extraction rejects links, special files, duplicate names and unsafe paths.
4. The operator runs ./provision-host.sh --revision COMMIT [--kubeconfig PATH].
   Thereafter use ./maintain.sh. No sudoers changes are made.

The initial manual trust decision cannot securely be automated using code from an
operator-writable checkout. Staging and enrollment are separate supported steps.
The root helper never invokes Git in an operator-controlled repository.
"""

import argparse
import contextlib
import datetime
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath

PROVISION = Path("/usr/local/libexec/authelia-provision-host.py")
HELPER = Path("/usr/local/libexec/authelia-maintenance-v1.py")
SOURCES = Path("/usr/local/lib/authelia-maintenance")
CONFIG = Path("/etc/authelia-maintenance")
STATE = Path("/srv/backup/authelia-maintenance")
RECOVERY = STATE / "recovery"
AUDIT = Path("/CHANGES.md")
SAFE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
}
REQUIRED = (
    "scripts/provision_host.py",
    "scripts/host_maintenance.py",
    "scripts/velero_recovery.py",
    "scripts/stable_images.py",
    "scripts/cli.py",
    "scripts/setup.py",
    "install.sh",
)
RECEIPT = ".source-review.json"
MAX_ARCHIVE = 128 * 1024 * 1024


class Error(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Error(message)


def revision(value):
    require(
        bool(re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value)),
        "Use a full lowercase commit ID, not a branch or tag",
    )
    return value


def trusted(path, regular=False):
    path = Path(path)
    require(path.is_absolute(), "Protected path must be absolute")
    for item in [path, *path.parents]:
        mode = item.lstat()
        require(
            not stat.S_ISLNK(mode.st_mode) and mode.st_uid == 0 and not mode.st_mode & 0o022,
            "Protected path has unsafe ownership or permissions",
        )
        require(item == path or stat.S_ISDIR(mode.st_mode), "Invalid protected parent")
    if regular:
        require(stat.S_ISREG(path.lstat().st_mode), "Expected a protected regular file")
    return path


def protected_dir(path):
    path = Path(path)
    if not path.exists():
        if not path.parent.exists():
            protected_dir(path.parent)
        trusted(path.parent)
        path.mkdir(mode=0o700)
    trusted(path)
    require(path.is_dir(), "Expected protected directory")
    if path in (CONFIG, STATE, RECOVERY, SOURCES):
        require(
            stat.S_IMODE(path.stat().st_mode) == 0o700,
            "Private state directories require mode 0700",
        )
    return path


def run(argv):
    result = subprocess.run(
        argv, env=SAFE_ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=90
    )
    require(result.returncode == 0, "Host command failed; no raw output disclosed")
    return result.stdout


def reserve(path, needed=0):
    while not Path(path).exists():
        path = Path(path).parent
    fs = os.statvfs(path)
    require(
        fs.f_blocks > 0 and fs.f_bavail * fs.f_frsize - needed >= fs.f_blocks * fs.f_frsize / 10,
        "Insufficient disk reserve (require at least ten percent after writes)",
    )


def atomic(path, data, mode=0o600):
    path = Path(path)
    trusted(path.parent)
    if path.exists() or path.is_symlink():
        trusted(path, regular=True)
    fd, name = tempfile.mkstemp(prefix=".provision-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def audit(event, commit, binding=None):
    if AUDIT.exists() or AUDIT.is_symlink():
        trusted(AUDIT, regular=True)
    else:
        trusted(AUDIT.parent)
    # Do not include configuration, credential locations or arbitrary strings.
    fd = os.open(AUDIT, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(
            datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d;%H%M%S;")
            + "AUTHELIA_MAINTENANCE;host provisioning;00:00;none;"
            + event
            + " revision="
            + revision(commit)
            + (" binding=" + binding if binding else "")
            + "\n"
        )
        stream.flush()
        os.fsync(stream.fileno())


def no_workers():
    units = run(
        [
            "systemctl",
            "list-units",
            "--all",
            "--no-legend",
            "--plain",
            "--state=active,activating,deactivating,reloading",
            "authelia-maintenance-*.service",
        ]
    )
    require(not units.strip(), "Maintenance is running; stop enrollment and wait for completion")


@contextlib.contextmanager
def exclusive():
    protected_dir(CONFIG)
    # Maintenance launch/worker must share this lock (shared mode). The recovery
    # operation lock additionally excludes a running backup/restore transaction.
    paths = [CONFIG / "provision.lock", RECOVERY / "operation.lock"]
    handles = []
    try:
        protected_dir(RECOVERY)
        require(
            stat.S_IMODE(RECOVERY.stat().st_mode) == 0o700, "Recovery directory must have mode 0700"
        )
        for path in paths:
            if path.exists() or path.is_symlink():
                trusted(path, regular=True)
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            handles.append(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error("Maintenance or recovery is running; no replacement allowed") from None
        no_workers()
        yield
    finally:
        for fd in reversed(handles):
            os.close(fd)


def archive_files(data, commit):
    require(len(data) <= MAX_ARCHIVE, "Source archive is too large")
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        require(
            archive.pax_headers.get("comment") == commit,
            "Archive must be git archive of the exact reviewed commit",
        )
        seen = set()
        total = 0
        for member in archive:
            name = member.name.rstrip("/") if member.isdir() else member.name
            parts = PurePosixPath(name).parts
            require(
                name
                and not name.startswith("/")
                and "\\" not in name
                and all(x not in ("", ".", "..") for x in name.split("/"))
                and parts[0] != ".git"
                and name != RECEIPT,
                "Unsafe archive pathname",
            )
            require(name not in seen, "Duplicate archive pathname")
            seen.add(name)
            require(
                member.isdir() or member.isreg(), "Archive links and special files are forbidden"
            )
            require(not member.mode & 0o7000, "Archive special permission bits are forbidden")
            if member.isreg():
                total += member.size
                require(total <= MAX_ARCHIVE, "Expanded source archive is too large")
                result[name] = (
                    archive.extractfile(member).read(),
                    0o755 if member.mode & 0o111 else 0o644,
                )
    require(
        all(name in result for name in REQUIRED),
        "Reviewed archive lacks repository maintenance modules",
    )
    for name in result:
        require(
            not any(str(parent) in result for parent in PurePosixPath(name).parents),
            "Archive file/directory collision",
        )
    return result


def stage(archive, digest, commit):
    revision(commit)
    require(
        bool(re.fullmatch("[0-9a-f]{64}", digest)),
        "Explicit administrator-reviewed archive SHA256 required",
    )
    data = trusted(archive, regular=True).read_bytes()
    require(hashlib.sha256(data).hexdigest() == digest, "Reviewed archive digest mismatch")
    files = archive_files(data, commit)
    reserve(SOURCES, sum(len(x[0]) for x in files.values()) + 1024 * 1024)
    for path in (STATE, CONFIG, AUDIT.parent):
        reserve(path, 1024 * 1024)
    protected_dir(SOURCES)
    with exclusive():
        target = SOURCES / commit
        if target.exists() or target.is_symlink():
            reviewed_source(commit)
            receipt = json.loads(trusted(target / RECEIPT, regular=True).read_text())
            require(
                receipt.get("archive_sha256") == digest,
                "Existing snapshot belongs to a different archive attestation",
            )
            return target
        audit("source-stage-start", commit)
        folder = Path(tempfile.mkdtemp(prefix=".staging-", dir=SOURCES))
        try:
            hashes = {}
            for name, (content, mode) in files.items():
                dest = folder / name
                dest.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                atomic(dest, content, mode)
                hashes[name] = hashlib.sha256(content).hexdigest()
            atomic(
                folder / RECEIPT,
                json.dumps(
                    {"revision": commit, "archive_sha256": digest, "files": hashes}, sort_keys=True
                ).encode(),
            )
            folder.rename(target)
        finally:
            if folder.exists():
                shutil.rmtree(folder)
        audit("source-stage-complete", commit)
    return target


def reviewed_source(commit):
    source = trusted(SOURCES / revision(commit))
    receipt = json.loads(trusted(source / RECEIPT, regular=True).read_text())
    require(receipt["revision"] == commit, "Source review revision mismatch")
    actual = {}
    for path in source.rglob("*"):
        trusted(path)
        require(path.is_dir() or stat.S_ISREG(path.stat().st_mode), "Unsupported source file")
        if path.is_file() and path != source / RECEIPT:
            actual[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
    require(
        actual == receipt["files"] and all(x in actual for x in REQUIRED),
        "Reviewed immutable source content changed",
    )
    return source


def parse_env(data):
    values = json.loads(data)
    require(isinstance(values, dict), "Configuration must be a JSON object")
    return values


def source_config(checkout):
    checkout = Path(checkout)
    require(
        checkout.is_absolute() and checkout.resolve() == checkout and checkout.is_dir(),
        "Canonical checkout directory required",
    )
    path = checkout / "current_config/config.json"
    require(path.resolve() == path and path.is_file(), "Private canonical configuration required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(st.st_mode) and not st.st_mode & 0o077,
            "Configuration must be a private regular file (0600)",
        )
        data = stream.read(1024 * 1024 + 1)
    require(len(data) <= 1024 * 1024, "Configuration is too large")
    return path, data, parse_env(data)


def settings(values):
    require(
        bool(re.fullmatch(r"[a-z][a-z0-9-]{0,61}[a-z0-9]", values.get("namespace", ""))),
        "Explicit configured namespace required",
    )
    ns = values.get("velero_namespace", "velero")
    require(
        bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", ns))
        and ns != values["namespace"],
        "Valid separate Velero namespace required",
    )
    storage = values.get("velero_storage_location", "")
    require(
        bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", storage)),
        "Explicit velero_storage_location required",
    )
    ttl = values.get("velero_backup_ttl", "720h")
    require(bool(re.fullmatch(r"[1-9][0-9]*h", ttl)), "Velero TTL must be positive whole hours")
    return {"namespace": ns, "storage_location": storage, "ttl": ttl}


def kube(kubeconfig, *args):
    return json.loads(
        run(
            [
                "kubectl",
                "--kubeconfig",
                str(kubeconfig),
                "--request-timeout=45s",
                *args,
                "-o",
                "json",
            ]
        )
    )


def make_binding(checkout, commit, kubeconfig=None):
    source = reviewed_source(commit)
    require(
        trusted(source / "scripts/provision_host.py", regular=True).read_bytes()
        == trusted(PROVISION, regular=True).read_bytes(),
        "Bootstrap reviewed provisioner before enrollment",
    )
    config_path, data, values = source_config(checkout)
    velero = settings(values)
    configured = values.get("kubeconfig")
    require(
        not (configured and kubeconfig and configured != kubeconfig),
        "Kubeconfig argument conflicts with authoritative configuration",
    )
    credential = configured or kubeconfig
    require(
        bool(credential),
        "Set kubeconfig in the authoritative config or supply its protected location",
    )
    # Do not open, print, hash, copy or parse kubeconfig contents.
    credential = trusted(credential, regular=True)
    require(not credential.stat().st_mode & 0o077, "Protected kubeconfig must be private (0600)")
    namespace = values["namespace"]
    cluster_uid = kube(credential, "get", "namespace", "kube-system")["metadata"]["uid"]
    namespace_uid = kube(credential, "get", "namespace", namespace)["metadata"]["uid"]
    pvcs = kube(credential, "-n", namespace, "get", "pvc")["items"]
    require(
        {x["metadata"]["name"] for x in pvcs} == {"authelia-data"},
        "Expected exactly the Authelia data PVC",
    )
    require(
        all(x.get("status", {}).get("phase") == "Bound" for x in pvcs), "Authelia PVC must be Bound"
    )
    require(
        cluster_uid and namespace_uid and all(x["metadata"].get("uid") for x in pvcs),
        "Missing cluster identity",
    )
    name = "checkout-" + hashlib.sha256(str(checkout).encode()).hexdigest()[:24]
    binding = {
        "binding_version": 1,
        "checkout": str(checkout),
        "config_path": str(config_path),
        "namespace": namespace,
        "cluster_uid": cluster_uid,
        "namespace_uid": namespace_uid,
        "pvc_uids": {x["metadata"]["name"]: x["metadata"]["uid"] for x in pvcs},
        "source": str(source),
        "source_revision": commit,
        "config_file": str(CONFIG / (name + ".config.json")),
        "kubeconfig": str(credential),
        "protected_namespaces": [],
        "velero": velero,
    }
    import importlib.util

    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "enrollment_coordinator", source / "scripts/host_maintenance.py"
    )
    coordinator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(coordinator)
    binding["ca_files"] = coordinator.ca_fingerprints(binding, values)
    with coordinator.installer(binding) as cli:
        c = coordinator.configuration(binding, values)
        cli.validate(c)
        cli.ownership(c)
        cli.exclusive_namespace(c)
        coordinator.validate_existing_secret(cli, c)
    coordinator.recovery_backend(binding).preflight(namespace)
    return name, binding, data


def enroll(checkout, commit, kubeconfig=None):
    name, binding, data = make_binding(checkout, commit, kubeconfig)
    helper_data = trusted(
        Path(binding["source"]) / "scripts/host_maintenance.py", regular=True
    ).read_bytes()
    provision_data = trusted(
        Path(binding["source"]) / "scripts/provision_host.py", regular=True
    ).read_bytes()
    targets = [HELPER, CONFIG / (name + ".json"), CONFIG / (name + ".config.json"), PROVISION]
    needed = len(helper_data) + len(provision_data) + len(data) + 1024 * 1024
    for path in targets:
        if path.exists() or path.is_symlink():
            needed += trusted(path, regular=True).stat().st_size
    for path in (STATE, CONFIG, HELPER.parent, AUDIT.parent):
        reserve(path, needed)
    protected_dir(HELPER.parent)
    with exclusive():
        # Re-read source data before installing; configuration drift invalidates enrollment.
        require(source_config(checkout)[1] == data, "Configuration changed during enrollment")
        previous = CONFIG / (name + ".json")
        if previous.exists():
            old = json.loads(trusted(previous, regular=True).read_text())
            require(
                old.get("checkout") == binding["checkout"]
                and old.get("namespace") == binding["namespace"]
                and old.get("cluster_uid") == binding["cluster_uid"],
                "Existing checkout cannot be silently retargeted to another namespace or cluster",
            )
            binding["protected_namespaces"] = old.get("protected_namespaces", [])
            expected = [
                (HELPER, helper_data, 0o755),
                (PROVISION, provision_data, 0o755),
                (CONFIG / (name + ".config.json"), data, 0o600),
            ]
            if (
                old == binding
                and stat.S_IMODE(previous.stat().st_mode) == 0o600
                and all(
                    path.exists()
                    and trusted(path, regular=True).read_bytes() == content
                    and stat.S_IMODE(path.stat().st_mode) == mode
                    for path, content, mode in expected
                )
            ):
                return name
        backup = STATE / ("enrollment-" + uuid.uuid4().hex)
        backup.mkdir(mode=0o700)
        for i, path in enumerate(targets):
            if path.exists():
                atomic(
                    backup / (str(i) + "-" + path.name), trusted(path, regular=True).read_bytes()
                )
        atomic(
            backup / "scope.json",
            json.dumps({"targets": [str(p) for p in targets], "revision": commit}).encode(),
        )
        audit("enrollment-start", commit, name)
        # Binding is the final commit point. Failed partial writes retain backups
        # and fail closed through helper/env/version checks; no automatic rollback.
        atomic(HELPER, helper_data, 0o755)
        atomic(PROVISION, provision_data, 0o755)
        atomic(CONFIG / (name + ".config.json"), data)
        atomic(CONFIG / (name + ".json"), json.dumps(binding, indent=2).encode())
        require(
            json.loads((CONFIG / (name + ".json")).read_text()) == binding
            and (CONFIG / (name + ".config.json")).read_bytes() == data
            and HELPER.read_bytes() == helper_data
            and PROVISION.read_bytes() == provision_data,
            "Installed enrollment verification failed",
        )
        audit("enrollment-complete", commit, name)
    return name


def main(argv=None):
    # Read-only capability probe must precede revision parsing and host writes.
    actual = sys.argv[1:] if argv is None else argv
    if actual == ["--protocol-version"]:
        print("authelia-enrollment-v1-isolated-helper")
        return 0
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--revision", required=True)
    parser.add_argument("--checkout")
    parser.add_argument(
        "--kubeconfig", help="Existing protected credential LOCATION only; never copied"
    )
    parser.add_argument(
        "--stage-archive", help="Administrator only: reviewed archive in protected staging"
    )
    parser.add_argument("--archive-sha256", help="Independent administrator review attestation")
    args = parser.parse_args(argv)
    revision(args.revision)
    require(os.geteuid() == 0, "Use the nonroot provision-host.sh launcher")
    trusted(Path(__file__), regular=True)
    trusted("/usr/bin/python3.12", regular=True)
    require(sys.version_info >= (3, 12), "Protected system Python 3.12 required")
    os.umask(0o077)
    if args.stage_archive:
        require(
            not args.checkout and not args.kubeconfig and args.archive_sha256,
            "Archive staging cannot be combined with enrollment",
        )
        stage(args.stage_archive, args.archive_sha256, args.revision)
        print("Reviewed source snapshot staged. No application resources changed.")
    else:
        require(args.checkout and not args.archive_sha256, "Enrollment requires --checkout")
        name = enroll(args.checkout, args.revision, args.kubeconfig)
        print("Enrolled " + name + ". No application resources changed. Use ./maintain.sh.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(
            "ERROR: "
            + (
                str(exc)
                if isinstance(exc, Error)
                else type(exc).__name__ + "; enrollment failed (details suppressed)"
            ),
            file=sys.stderr,
        )
        sys.exit(1)
