#!/usr/bin/env python3
"""Narrow content checks for a hosted AAB, its JAR signature, and derived APK."""

import base64
import hashlib
import json
import pathlib
import re
import ssl
import stat
import subprocess
import tempfile
import zipfile

MANIFEST = "META-INF/MANIFEST.MF"
SIGNATURE = re.compile(r"META-INF/([A-Z0-9_-]{1,8})\.(SF|RSA|DSA|EC)")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def digest(path):
    result = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            result.update(block)
    return result.hexdigest()


def safe_name(name):
    path = pathlib.PurePosixPath(name)
    require(name and not path.is_absolute() and ".." not in path.parts
            and "\\" not in name and not any(ord(character) < 32 or ord(character) == 127 for character in name)
            and str(path) == name.rstrip("/"), "noncanonical ZIP member path")
    return name


def zip_identity(path, *, maximum_bytes=1024**3):
    """Stream payload hashes; refuse duplicate, linked, encrypted or oversized inputs."""
    require(path.is_file() and not path.is_symlink(), "ZIP input must be a regular file")
    files = {}
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [safe_name(entry.filename) for entry in entries]
        require(len(entries) <= 100000 and len(names) == len(set(name.casefold() for name in names)),
                "duplicate or case-ambiguous ZIP members")
        require(sum(entry.file_size for entry in entries) <= maximum_bytes, "ZIP expansion exceeds bound")
        for entry in entries:
            mode = entry.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR)
                    and not entry.flag_bits & 1, "linked, special or encrypted ZIP member")
            require(entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    "unsupported ZIP compression")
            if entry.is_dir():
                continue
            sha = hashlib.sha256()
            with archive.open(entry) as stream:
                for block in iter(lambda: stream.read(1024**2), b""):
                    sha.update(block)
            files[entry.filename] = {"sha256": sha.hexdigest(), "bytes": entry.file_size}
    return files


def manifest_sections(data):
    require(len(data) <= 4 * 1024**2 and b"\0" not in data, "invalid or oversized JAR manifest")
    lines = re.split(rb"\r\n|\n|\r", data)
    sections, attributes, previous = [], {}, None
    for line in lines:
        if not line:
            if attributes:
                sections.append({key: value.decode("utf-8") for key, value in attributes.items()})
                attributes = {}
            previous = None
        elif line.startswith(b" "):
            require(previous is not None, "orphan JAR manifest continuation")
            attributes[previous] += line[1:]
        else:
            require(b": " in line, "invalid JAR manifest attribute")
            key, value = line.split(b": ", 1)
            require(re.fullmatch(rb"[A-Za-z0-9_-]{1,70}", key), "invalid JAR manifest attribute name")
            previous = key.decode("ascii").lower()
            require(previous not in attributes, "duplicate JAR manifest attribute")
            attributes[previous] = value
    require(not attributes and bool(sections), "unterminated or empty JAR manifest")
    main, entries = sections[0], {}
    require("name" not in main, "JAR manifest lacks main attributes")
    for attributes in sections[1:]:
        name = attributes.pop("name", None)
        require(isinstance(name, str) and name not in entries, "duplicate or unnamed JAR manifest section")
        safe_name(name)
        entries[name] = attributes
    return main, entries


def aab_content_identity(unsigned, signed):
    """Permit exactly manifest signing digests and a single SF/signature-block pair.

    Oracle's JAR specification defines these changes. Other META-INF content
    remains a product input and is never stripped from the comparison.
    """
    original, current = zip_identity(unsigned), zip_identity(signed)
    require(not any(SIGNATURE.fullmatch(name) for name in original), "producer AAB is already JAR signed")
    added = set(current) - set(original) - {MANIFEST}
    require(len(added) == 2 and all(SIGNATURE.fullmatch(name) for name in added),
            "AAB signing added unexpected entries")
    matches = [SIGNATURE.fullmatch(name) for name in added]
    require(len({match[1] for match in matches}) == 1
            and {match[2] for match in matches} in ({"SF", "RSA"}, {"SF", "DSA"}, {"SF", "EC"}),
            "AAB must contain one matching signature pair")
    payload = {name: value for name, value in original.items() if name != MANIFEST}
    require({name: value for name, value in current.items() if name not in added and name != MANIFEST} == payload,
            "signed AAB changed original payload content")
    require(MANIFEST in current, "signed AAB lacks its manifest")
    require(current[MANIFEST]["bytes"] <= 4 * 1024**2
            and original.get(MANIFEST, {"bytes": 0})["bytes"] <= 4 * 1024**2,
            "oversized JAR manifest")
    with zipfile.ZipFile(unsigned) as archive:
        old_main, old_entries = manifest_sections(archive.read(MANIFEST)) if MANIFEST in original else ({}, {})
    with zipfile.ZipFile(signed) as archive:
        main, entries = manifest_sections(archive.read(MANIFEST))
    require(main.get("manifest-version") == "1.0"
            and all(main.get(key) == value for key, value in old_main.items())
            and set(main) - set(old_main) <= {"manifest-version", "created-by"},
            "AAB signing changed manifest main semantics")
    require(set(entries) == set(payload) and set(old_entries) <= set(payload),
            "signed manifest does not cover exactly every AAB payload entry")
    for name, identity in payload.items():
        attributes = dict(entries[name])
        encoded = attributes.pop("sha-256-digest", None)
        require(encoded == base64.b64encode(bytes.fromhex(identity["sha256"])).decode("ascii"),
                "AAB manifest has an incorrect payload digest")
        previous = dict(old_entries.get(name, {}))
        previous.pop("sha-256-digest", None)
        require(attributes == previous, "AAB signing changed per-entry manifest semantics")
    return {"payload": payload, "payloadManifestSha256": canonical_digest(payload),
            "signatureEntries": sorted(added)}


def apk_runtime_identity(aab, apk):
    """Bind invariant runtime bytes across the canonical bundletool conversion."""
    bundle, package = zip_identity(aab), zip_identity(apk)
    mapped = {}
    for name, identity in bundle.items():
        if name.startswith("base/lib/"):
            target = name.removeprefix("base/")
        elif name.startswith("base/dex/"):
            target = name.removeprefix("base/dex/")
        elif name.startswith(("base/assets/", "base/root/")):
            target = name.removeprefix("base/") if name.startswith("base/assets/") else name.removeprefix("base/root/")
        elif name.startswith("base/res/") and not name.endswith(".xml"):
            target = name.removeprefix("base/")
        else:
            continue
        require(target not in mapped, "ambiguous AAB runtime mapping")
        require(package.get(target) == identity, "APK runtime bytes differ from the exact AAB")
        mapped[target] = identity
    native = {name: value for name, value in mapped.items() if name.startswith("lib/")}
    require("lib/arm64-v8a/libnostr_vpn_app_core.so" in native, "AAB/APK lacks the production JNI library")
    for predicate in (lambda name: name.startswith("lib/"), lambda name: name.startswith("assets/"),
                      lambda name: re.fullmatch(r"classes[0-9]*\.dex", name)):
        require({name for name in package if predicate(name)} == {name for name in mapped if predicate(name)},
                "APK contains unexpected native, DEX or asset payloads")
    return {"nativeLibraries": native, "mappedPayloadManifestSha256": canonical_digest(mapped)}


def verify_aab_signer(aab, signature_entries, expected_sha256):
    """Verify the exact manifest's CMS signature against the pinned leaf certificate.

    Android's upload certificate may be self-signed. The exact certificate pin
    replaces PKI chain trust; CMS content and signature verification stay enabled.
    """
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256), "invalid Android signer pin")
    require(len(signature_entries) == 2, "missing AAB signature pair")
    signature_file = next(name for name in signature_entries if name.endswith(".SF"))
    signature_block = next(name for name in signature_entries if name != signature_file)
    with zipfile.ZipFile(aab) as archive:
        require(all(archive.getinfo(name).file_size <= 4 * 1024**2
                    for name in (MANIFEST, signature_file, signature_block)),
                "AAB signing metadata exceeds its comparison bound")
        manifest = archive.read(MANIFEST)
        signed_file = archive.read(signature_file)
        block = archive.read(signature_block)
    main, _entries = manifest_sections(signed_file)
    require(main.get("signature-version") == "1.0"
            and main.get("sha-256-digest-manifest")
            == base64.b64encode(hashlib.sha256(manifest).digest()).decode("ascii"),
            "AAB signature file does not cover the exact complete manifest")
    with tempfile.TemporaryDirectory(prefix="nvpn-aab-signature-") as temporary:
        root = pathlib.Path(temporary)
        (root / "signature.sf").write_bytes(signed_file)
        (root / "signature.cms").write_bytes(block)
        verified = subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER",
            "-in", str(root / "signature.cms"), "-content", str(root / "signature.sf"),
            "-noverify", "-signer", str(root / "signer.pem")], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(verified.stdout == signed_file, "CMS signature covers different content")
        certificates = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                                  (root / "signer.pem").read_bytes(), flags=re.S)
        require(len(certificates) == 1, "AAB must have exactly one signing certificate")
        actual = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificates[0].decode("ascii"))).hexdigest()
        require(actual == expected_sha256, "AAB is signed by a different certificate")
    return actual
