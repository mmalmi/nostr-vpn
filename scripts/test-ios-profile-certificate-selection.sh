#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT/scripts/ios_profile_certificate.py" <<'PY'
import base64
import datetime as dt
import hashlib
import importlib.util
import sys

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

print("iOS profile certificate selection tests passed")
PY

grep -Fq '"fields[certificates]"' "$ROOT/scripts/ios-profiles"
grep -Fq '"certificateType,expirationDate,certificateContent"' \
  "$ROOT/scripts/ios-profiles"
grep -Fq 'certificate_code_sign_identity(selected)' "$ROOT/scripts/ios-profiles"
