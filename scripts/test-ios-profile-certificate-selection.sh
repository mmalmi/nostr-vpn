#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT/scripts/ios_profile_certificate.py" "$ROOT/scripts/ios-profiles" <<'PY'
import ast
import base64
import datetime as dt
import hashlib
import importlib.util
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace

module_path = sys.argv[1]
spec = importlib.util.spec_from_file_location("ios_profile_certificate", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def fixture(
    identifier,
    content,
    expiration,
    certificate_type="IOS_DISTRIBUTION",
    pem=False,
):
    if pem:
        encoded = base64.b64encode(content).decode("ascii")
        content = (
            "-----BEGIN CERTIFICATE-----\n"
            + encoded
            + "\n-----END CERTIFICATE-----\n"
        ).encode("ascii")
    return {
        "id": identifier,
        "attributes": {
            "certificateType": certificate_type,
            "certificateContent": base64.b64encode(content).decode("ascii"),
            "expirationDate": expiration,
        },
    }


matching_content = b"generic matching distribution certificate"
matching_pin = hashlib.sha256(matching_content).hexdigest()
matching_identity = hashlib.sha1(matching_content).hexdigest()
certificates = [
    fixture("newer-wrong", b"generic newer certificate", "2028-01-01T00:00:00Z"),
    fixture("pinned-match", matching_content, "2027-01-01T00:00:00Z", pem=True),
    fixture("expired-match", matching_content, "2025-01-01T00:00:00Z"),
]

selected = module.select_certificate_id(
    certificates,
    required_type="DISTRIBUTION",
    now=now,
    expected_sha256=matching_pin,
)
if selected != "pinned-match":
    raise SystemExit("selector did not prefer the certificate content matching the pin")
if module.certificate_code_sign_identity(certificates[1]) != matching_identity:
    raise SystemExit("selector did not derive an unambiguous Xcode signing identity")

selected = module.select_certificate_id(
    certificates,
    required_type="DISTRIBUTION",
    now=now,
    expected_sha256=matching_pin,
    configured_id="newer-wrong",
)
if selected != "pinned-match":
    raise SystemExit("a stale certificate ID overrode the certificate-content pin")

try:
    module.select_certificate_id(
        certificates,
        required_type="DISTRIBUTION",
        now=now,
        expected_sha256="0" * 64,
    )
except ValueError:
    pass
else:
    raise SystemExit("selector fell back after the certificate-content pin missed")

development = [
    fixture(
        "development-older",
        b"generic development certificate one",
        "2027-01-01T00:00:00Z",
        "IOS_DEVELOPMENT",
    ),
    fixture(
        "development-newer",
        b"generic development certificate two",
        "2028-01-01T00:00:00Z",
        "IOS_DEVELOPMENT",
    ),
]
selected = module.select_certificate_id(
    development,
    required_type="DEVELOPMENT",
    now=now,
)
if selected != "development-newer":
    raise SystemExit("development selection no longer uses the newest valid certificate")

# Exercise the production profile writer without contacting Apple. The exact
# selected profile certificate must override an old, ambiguous export name.
embedded = Path(sys.argv[2]).read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
writer = next(node for node in ast.parse(embedded).body if isinstance(node, ast.FunctionDef) and node.name == "ensure_profiles")
with tempfile.TemporaryDirectory(prefix="nvpn-profile-export-") as temporary:
    env_path = Path(temporary) / "provisioning.env"
    namespace = {
        "select_certificate": lambda: ("pinned-match", matching_identity),
        "select_devices": lambda: [],
        "exact_bundle_id": lambda identifier: {"id": identifier},
        "find_profile": lambda *args: {"id": "profile", "attributes": {"name": "Profile"}},
        "install_profile": lambda profile: ("profile-uuid", env_path.parent / "profile"),
        "os": SimpleNamespace(environ={}),
        "shlex": shlex,
        "PROFILES_ENV_PATH": env_path,
        "TARGETS": [
            {"identifier": "example.app", "env_key": "APP_PROFILE"},
            {"identifier": "example.tunnel", "env_key": "TUNNEL_PROFILE"},
        ],
    }
    exec(compile(ast.Module(body=[writer], type_ignores=[]), "ios-profiles", "exec"), namespace)
    namespace["ensure_profiles"]()
    selected_export = subprocess.check_output([
        "bash", "-c",
        'NVPN_IOS_EXPORT_SIGNING_CERTIFICATE="stale display name"; source "$1"; printf "%s" "$NVPN_IOS_EXPORT_SIGNING_CERTIFICATE"',
        "bash", str(env_path),
    ], text=True)
    if selected_export != matching_identity:
        raise SystemExit("profile writer retained an ambiguous export certificate instead of its exact selected identity")

print("iOS profile certificate selection tests passed")
PY

grep -Fq '"fields[certificates]"' "$ROOT/scripts/ios-profiles"
grep -Fq '"certificateType,expirationDate,certificateContent"' \
  "$ROOT/scripts/ios-profiles"
grep -Fq 'certificate_code_sign_identity(selected_certificate)' "$ROOT/scripts/ios-profiles"
