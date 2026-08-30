import base64
import datetime as dt
import hashlib
import re


def _parse_time(value):
    if not value:
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _normalize_sha256(value):
    normalized = re.sub(r"[:\s]", "", value).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise ValueError("configured certificate SHA-256 pin is malformed")
    return normalized


def _certificate_der(certificate):
    content = certificate.get("attributes", {}).get("certificateContent", "")
    if not content:
        raise ValueError("App Store Connect certificate content is missing")
    try:
        decoded = base64.b64decode("".join(content.split()), validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("App Store Connect certificate content is malformed") from error
    if decoded.startswith(b"-----BEGIN CERTIFICATE-----"):
        lines = decoded.decode("ascii").splitlines()
        encoded = "".join(line for line in lines if not line.startswith("-----"))
        try:
            der = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise ValueError("App Store Connect certificate content is malformed") from error
    else:
        der = decoded
    return der


def _content_sha256(certificate):
    return hashlib.sha256(_certificate_der(certificate)).hexdigest()


def certificate_code_sign_identity(certificate):
    """Return the certificate's exact SHA-1 identity accepted by Xcode."""
    return hashlib.sha1(_certificate_der(certificate)).hexdigest()


def select_certificate_id(
    certificates,
    *,
    required_type,
    now,
    expected_sha256="",
    configured_id="",
):
    expected = _normalize_sha256(expected_sha256) if expected_sha256 else ""
    content_matches = []
    candidates = []
    for certificate in certificates:
        attrs = certificate.get("attributes", {})
        if expected and _content_sha256(certificate) == expected:
            content_matches.append(certificate)
        if required_type not in attrs.get("certificateType", ""):
            continue
        expiration = _parse_time(attrs.get("expirationDate"))
        if expiration <= now:
            continue
        candidates.append((expiration, certificate))

    if expected_sha256:
        matches = [
            certificate
            for _, certificate in candidates
            if _content_sha256(certificate) == expected
        ]
        if len(matches) != 1:
            if not content_matches:
                raise ValueError(
                    "configured certificate pin is absent from App Store Connect "
                    "certificate content"
                )
            raise ValueError(
                f"expected one valid {required_type.lower()} certificate matching the pin, "
                f"observed {len(matches)}"
            )
        return matches[0]["id"]

    if configured_id:
        matches = [
            certificate
            for _, certificate in candidates
            if certificate.get("id") == configured_id
        ]
        if len(matches) != 1:
            raise ValueError("configured certificate ID is not valid for this profile type")
        return matches[0]["id"]

    if not candidates:
        raise ValueError(
            f"no non-expired {required_type.lower()} certificate found in App Store Connect"
        )
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]["id"]
