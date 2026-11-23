#!/usr/bin/env python3
"""MIT adaptation of kube.hermes_setup (Copyright (c) 2026 hermes-speedboat).
Resolve publisher stable releases to verified registry manifest digests."""

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

COMPONENTS = {"image": ("authelia/authelia", "docker.io/authelia/authelia", "")}


def fetch(url, headers=None):
    request = urllib.request.Request(
        url, headers={"User-Agent": "kube-authelia-maintenance", **(headers or {})}
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        return response.read(), response.headers


def stable(release):
    if (
        release.get("draft")
        or release.get("prerelease")
        or not re.fullmatch(r"v?\d+\.\d+\.\d+", release.get("tag_name", ""))
    ):
        raise ValueError("Publisher release is not a stable semantic version")
    return release["tag_name"].lstrip("v")


def registry_manifest(image):
    registry, name = image.split("/", 1)
    if "@" in name:
        name, tag = name.split("@")
        name = name.split(":")[0]
    else:
        name, tag = name.rsplit(":", 1)
    host = "registry-1.docker.io" if registry == "docker.io" else registry
    url = f"https://{host}/v2/{name}/manifests/{tag}"
    headers = {
        "Accept": ", ".join(
            [
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            ]
        )
    }
    try:
        body, response = fetch(url, headers)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
        challenge = dict(re.findall(r'(\w+)="([^"]+)"', error.headers.get("WWW-Authenticate", "")))
        realm = challenge.pop("realm")
        if urllib.parse.urlparse(realm).scheme != "https":
            raise ValueError("Insecure registry authentication endpoint") from None
        token = json.loads(fetch(realm + "?" + urllib.parse.urlencode(challenge))[0])
        headers["Authorization"] = "Bearer " + (token.get("token") or token["access_token"])
        body, response = fetch(url, headers)
    calculated = "sha256:" + hashlib.sha256(body).hexdigest()
    if response.get("Docker-Content-Digest") != calculated:
        raise ValueError("Registry manifest digest mismatch")
    manifest = json.loads(body)
    if manifest.get("schemaVersion") != 2:
        raise ValueError("Unsupported registry manifest")
    if "@" in image and image.split("@")[1] != calculated:
        raise ValueError("Requested immutable manifest digest mismatch")
    return image.split("@")[0] + "@" + calculated, body.decode("utf-8")


def digest(image):
    return registry_manifest(image)[0]


def validate_provenance(record):
    """Offline validation: never infer an old digest from today's mutable tag."""
    source = record["sourceImage"].removeprefix("docker.io/")
    if not re.fullmatch(r"authelia/authelia:\d+\.\d+\.\d+(?:@sha256:[a-f0-9]{64})?", source):
        raise ValueError("Recovery source is not an official stable Authelia image")
    body = record["manifest"]
    digest_value = "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
    expected = "docker.io/" + source.split("@")[0] + "@" + digest_value
    if record["image"] != expected or ("@" in source and source.split("@")[1] != digest_value):
        raise ValueError("Recovery manifest digest mismatch")
    manifest = json.loads(body)
    if manifest.get("schemaVersion") != 2:
        raise ValueError("Unsupported recovery manifest")
    allowed = {digest_value}
    for child in manifest.get("manifests", []):
        if child.get("mediaType") in (
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ):
            allowed.add(child["digest"])
    observed = record["imageIDs"]
    if not isinstance(observed, list) or not observed:
        raise ValueError("Running Pod imageID evidence required")
    for image_id in observed:
        value = re.sub(r"^(?:docker-pullable|containerd)://", "", image_id)
        match = re.fullmatch(
            r"(?:(?:docker.io/)?authelia/authelia(?::\d+\.\d+\.\d+)?@)?(sha256:[a-f0-9]{64})",
            value,
        )
        if not match or match[1] not in allowed:
            raise ValueError("Running Pod imageID differs from verified registry manifest")
    return record["image"]


def workload_provenance(image, image_ids):
    canonical = image if image.startswith("docker.io/") else "docker.io/" + image
    if not re.fullmatch(
        r"docker.io/authelia/authelia:\d+\.\d+\.\d+(?:@sha256:[a-f0-9]{64})?", canonical
    ):
        raise ValueError("Recovery source is not an official stable Authelia image")
    pinned, body = registry_manifest(canonical)
    record = {"sourceImage": image, "image": pinned, "manifest": body, "imageIDs": image_ids}
    validate_provenance(record)
    return record


def verify_selected(values):
    records = {}
    for key, (repo, image, _prefix) in COMPONENTS.items():
        selected = values.get(key, "")
        if selected.startswith("authelia/authelia:"):
            selected = "docker.io/" + selected
        match = re.fullmatch(
            re.escape(image) + r":(\d+\.\d+\.\d+)(?:@sha256:[a-f0-9]{64})?", selected
        )
        if not match:
            raise ValueError("Selected image is not a pinned stable publisher image")
        tag = "v" + match[1].lstrip("v")
        release = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases/tags/{tag}")[0])
        if stable(release) != match[1]:
            raise ValueError("Publisher release tag mismatch")
        pinned = digest(selected.split("@")[0])
        if "@" in selected and pinned != selected:
            raise ValueError("Selected digest differs from publisher registry tag")
        records[key] = {
            "image": pinned,
            "release": release["html_url"],
            "tag": tag,
            "prerelease": False,
        }
    return records


def resolve():
    result = {}
    for key, (repo, image, prefix) in COMPONENTS.items():
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        release = json.loads(fetch(url)[0])
        version = stable(release)
        result[key] = {
            "image": digest(f"{image}:{prefix}{version}"),
            "release": release["html_url"],
            "tag": release["tag_name"],
            "prerelease": False,
        }
    return result


if __name__ == "__main__":
    print(json.dumps(resolve(), indent=2))
