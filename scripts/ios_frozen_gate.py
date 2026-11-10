#!/usr/bin/env python3
"""Seal real-device evidence to one frozen iOS archive export."""

from __future__ import annotations

from apple_hosted_admission import validate_ios_admission

import argparse
import json
import os
import pathlib
import re
import tempfile
from typing import Any

from mobile_release_artifact_receipt import load_json, sha256_file


RECEIPT_SCHEMA = 1
REQUIRED_REAL_DEVICE_GATES = [
    "background-foreground-and-rapid-start-stop",
    "bidirectional-mobile-qr-and-manual-join",
    "desktop-mobile-manual-join",
    "wifi-radio-off-on-recovery",
    "wireguard-exit-and-five-dns-policies",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def required_string(
    value: Any,
    label: str,
    pattern: str,
) -> str:
    require(
        isinstance(value, str) and re.fullmatch(pattern, value) is not None,
        f"{label} is missing or malformed",
    )
    return value


def required_hash(value: Any, label: str, length: int) -> str:
    return required_string(value, label, rf"[0-9a-f]{{{length}}}")


def validate_archive_and_adhoc(
    archive: dict[str, Any],
    adhoc: dict[str, Any],
    archive_receipt_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    require(
        archive.get("receiptSchema") in (RECEIPT_SCHEMA, 2)
        and archive.get("artifactType") == "iOS frozen App Store xcarchive",
        "gate seal received the wrong frozen archive receipt",
    )
    require(
        adhoc.get("receiptSchema") == RECEIPT_SCHEMA
        and adhoc.get("artifactType")
        == "iOS export from frozen xcarchive"
        and adhoc.get("distribution") == "release-testing",
        "gate seal requires a release-testing export",
    )
    for receipt, prefix in ((archive, "archive"), (adhoc, "Ad Hoc export")):
        require(
            receipt.get("rustBuildProfile") == "release",
            f"{prefix} did not use the Release Rust profile",
        )
        required_hash(
            receipt.get("archiveTreeSha256"),
            f"{prefix} archive tree hash",
            64,
        )
        required_hash(receipt.get("appGitSha"), f"{prefix} app Git SHA", 40)
        required_hash(receipt.get("appGitTree"), f"{prefix} app Git tree", 40)
        required_hash(receipt.get("fipsGitSha"), f"{prefix} FIPS Git SHA", 40)
        required_hash(
            receipt.get("fipsGitTree"),
            f"{prefix} FIPS Git tree",
            40,
        )
        required_string(
            receipt.get("fipsCoreVersion"),
            f"{prefix} FIPS version",
            r"[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?",
        )
    for name in ("archiveAppBundleTreeSha256", "archivePathSha256"):
        required_hash(archive.get(name), f"archive {name}", 64)
    required_hash(
        adhoc.get("appBundleTreeSha256"),
        "Ad Hoc app bundle tree",
        64,
    )
    required_hash(adhoc.get("ipaPathSha256"), "Ad Hoc IPA path hash", 64)
    required_hash(adhoc.get("ipaSha256"), "Ad Hoc IPA hash", 64)
    required_hash(
        adhoc.get("archiveReceiptSha256"),
        "Ad Hoc frozen-archive receipt hash",
        64,
    )
    identity = archive.get("identity")
    require(isinstance(identity, dict), "frozen archive lacks code identity")
    required_string(
        identity.get("buildNumber"),
        "frozen archive build number",
        r"[1-9][0-9]*",
    )
    required_string(
        identity.get("marketingVersion"),
        "frozen archive marketing version",
        r"[0-9]+\.[0-9]+\.[0-9]+",
    )
    required_string(
        identity.get("appBundleIdentifier"),
        "frozen archive app bundle identifier",
        r"[A-Za-z0-9][A-Za-z0-9.-]+",
    )
    for name in (
        "fipsCargoMetadataReceiptPathSha256",
        "fipsCargoMetadataReceiptSha256",
        "fipsCheckoutPathSha256",
    ):
        required_hash(archive.get(name), f"archive {name}", 64)
    signing = adhoc.get("signing")
    require(
        isinstance(signing, dict),
        "release-testing export lacks signing evidence",
    )
    required_hash(
        signing.get("appCodeDirectoryHash"),
        "Ad Hoc app CodeDirectory hash",
        40,
    )
    required_hash(
        signing.get("packetTunnelCodeDirectoryHash"),
        "Ad Hoc Packet Tunnel CodeDirectory hash",
        40,
    )
    required_hash(
        signing.get("appProvisioningProfileSha256"),
        "Ad Hoc app provisioning profile hash",
        64,
    )
    required_hash(
        signing.get("packetTunnelProvisioningProfileSha256"),
        "Ad Hoc Packet Tunnel provisioning profile hash",
        64,
    )
    required_hash(
        signing.get("signerCertificateSha256"),
        "Ad Hoc signer certificate hash",
        64,
    )
    required_string(
        signing.get("signingTeamIdentifier"),
        "Ad Hoc signing team",
        r"[A-Z0-9]{10}",
    )
    require(
        adhoc.get("archiveTreeSha256") == archive.get("archiveTreeSha256")
        and adhoc.get("archiveReceiptSha256") == archive_receipt_sha256
        and adhoc.get("appGitSha") == archive.get("appGitSha")
        and adhoc.get("appGitTree") == archive.get("appGitTree")
        and adhoc.get("fipsGitSha") == archive.get("fipsGitSha")
        and adhoc.get("fipsGitTree") == archive.get("fipsGitTree")
        and adhoc.get("fipsCoreVersion") == archive.get("fipsCoreVersion")
        and adhoc.get("rustBuildProfile")
        == archive.get("rustBuildProfile")
        and adhoc.get("identity") == identity,
        "release-testing export is not tied to the frozen archive",
    )
    return identity, signing


def validate_mobile_receipt(
    archive: dict[str, Any],
    adhoc: dict[str, Any],
    identity: dict[str, Any],
    adhoc_signing: dict[str, Any],
    mobile: dict[str, Any],
) -> dict[str, Any]:
    require(
        mobile.get("receiptSchema") == 2
        and mobile.get("artifactType") == "iOS company Ad Hoc Release app"
        and mobile.get("companySigningVerified") is True
        and mobile.get("fipsDependenciesForcedRebuilt") is True
        and mobile.get("cashuAndPaidExitCompiled") is False
        and mobile.get("paidExitWalletWorkerCompiled") is False
        and mobile.get("updaterCompiled") is False
        and mobile.get("debuggable") is False,
        "physical mobile receipt is not a strict signed Release receipt",
    )
    selected_device = mobile.get("selectedPhysicalDevice")
    require(
        isinstance(selected_device, dict)
        and selected_device.get("explicitPhysicalDeviceVerified") is True
        and selected_device.get("platform") == "iOS",
        "physical mobile receipt lacks an explicit physical iPhone",
    )
    required_hash(
        selected_device.get("deviceIdentifierSha256"),
        "physical iPhone identifier hash",
        64,
    )
    required_string(
        selected_device.get("model"),
        "physical iPhone model",
        r".+",
    )
    required_string(
        selected_device.get("productType"),
        "physical iPhone product type",
        r".+",
    )
    require(
        mobile.get("selectedPhysicalDeviceIdentifierSha256")
        == selected_device.get("deviceIdentifierSha256"),
        "physical iPhone identifier evidence is inconsistent",
    )
    for name, label in (
        ("appExecutableSha256", "physical app executable hash"),
        (
            "packetTunnelExecutableSha256",
            "physical Packet Tunnel executable hash",
        ),
        ("appPathSha256", "physical app path hash"),
        ("derivedDataPathSha256", "physical DerivedData path hash"),
        ("testProductsPathSha256", "physical test-products path hash"),
        ("testProductsTreeSha256", "physical test-products tree"),
        ("xctestrunPathSha256", "physical xctestrun path hash"),
        ("xctestrunSha256", "physical xctestrun hash"),
        ("fipsCheckoutPathSha256", "physical FIPS checkout path hash"),
        (
            "fipsCargoMetadataReceiptPathSha256",
            "physical FIPS metadata path hash",
        ),
        (
            "fipsCargoMetadataReceiptSha256",
            "physical FIPS metadata receipt hash",
        ),
    ):
        required_hash(mobile.get(name), label, 64)
    required_hash(
        mobile.get("appCodeDirectoryHash"),
        "physical app CodeDirectory hash",
        40,
    )
    required_hash(
        mobile.get("packetTunnelCodeDirectoryHash"),
        "physical Packet Tunnel CodeDirectory hash",
        40,
    )
    required_hash(
        mobile.get("appProvisioningProfileSha256"),
        "physical app provisioning profile hash",
        64,
    )
    required_hash(
        mobile.get("packetTunnelProvisioningProfileSha256"),
        "physical Packet Tunnel provisioning profile hash",
        64,
    )
    required_hash(
        mobile.get("signerCertificateSha256"),
        "physical signer certificate hash",
        64,
    )
    required_hash(
        mobile.get("appBundleTreeSha256"),
        "physical app bundle tree",
        64,
    )
    required_hash(mobile.get("appGitSha"), "physical app Git SHA", 40)
    required_hash(mobile.get("appGitTree"), "physical app Git tree", 40)
    required_hash(mobile.get("fipsGitSha"), "physical FIPS Git SHA", 40)
    required_hash(mobile.get("fipsGitTree"), "physical FIPS Git tree", 40)
    required_string(
        mobile.get("fipsCoreVersion"),
        "physical FIPS version",
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?",
    )
    required_string(
        mobile.get("installedBuildNumber"),
        "physical installed build number",
        r"[1-9][0-9]*",
    )
    required_string(
        mobile.get("installedMarketingVersion"),
        "physical installed marketing version",
        r"[0-9]+\.[0-9]+\.[0-9]+",
    )
    require(
        mobile.get("appCodeDirectoryHash")
        == adhoc_signing.get("appCodeDirectoryHash")
        and mobile.get("packetTunnelCodeDirectoryHash")
        == adhoc_signing.get("packetTunnelCodeDirectoryHash"),
        "physical mobile receipt tested different iOS CodeDirectory hashes",
    )
    require(
        mobile.get("appProvisioningProfileSha256")
        == adhoc_signing.get("appProvisioningProfileSha256")
        and mobile.get("packetTunnelProvisioningProfileSha256")
        == adhoc_signing.get("packetTunnelProvisioningProfileSha256")
        and mobile.get("signerCertificateSha256")
        == adhoc_signing.get("signerCertificateSha256"),
        "physical mobile receipt tested different iOS signing material",
    )
    require(
        mobile.get("appBundleTreeSha256") == adhoc.get("appBundleTreeSha256"),
        "physical mobile receipt tested a different iOS app tree",
    )
    require(
        mobile.get("treeSha256") == mobile.get("appBundleTreeSha256"),
        "physical mobile receipt has inconsistent app tree evidence",
    )
    require(
        mobile.get("fipsCheckoutPathSha256")
        == archive.get("fipsCheckoutPathSha256")
        and mobile.get("fipsCargoMetadataReceiptPathSha256")
        == archive.get("fipsCargoMetadataReceiptPathSha256")
        and mobile.get("fipsCargoMetadataReceiptSha256")
        == archive.get("fipsCargoMetadataReceiptSha256"),
        "physical mobile receipt used different FIPS linkage evidence",
    )
    require(
        mobile.get("appGitSha") == archive.get("appGitSha")
        and mobile.get("appGitTree") == archive.get("appGitTree")
        and mobile.get("fipsGitSha") == archive.get("fipsGitSha")
        and mobile.get("fipsGitTree") == archive.get("fipsGitTree")
        and mobile.get("fipsCoreVersion") == archive.get("fipsCoreVersion")
        and mobile.get("installedBuildNumber") == identity.get("buildNumber")
        and mobile.get("installedMarketingVersion")
        == identity.get("marketingVersion"),
        "physical mobile receipt has the wrong source or version",
    )
    require(
        mobile.get("installedBundleIdentifier")
        == identity.get("appBundleIdentifier"),
        "physical mobile receipt installed the wrong app bundle",
    )
    return {
        "appBundleTreeSha256": mobile.get("appBundleTreeSha256"),
        "appCodeDirectoryHash": mobile.get("appCodeDirectoryHash"),
        "appGitSha": mobile.get("appGitSha"),
        "appGitTree": mobile.get("appGitTree"),
        "appProvisioningProfileSha256": mobile.get(
            "appProvisioningProfileSha256"
        ),
        "fipsCoreVersion": mobile.get("fipsCoreVersion"),
        "fipsGitSha": mobile.get("fipsGitSha"),
        "fipsGitTree": mobile.get("fipsGitTree"),
        "installedBuildNumber": mobile.get("installedBuildNumber"),
        "installedMarketingVersion": mobile.get(
            "installedMarketingVersion"
        ),
        "packetTunnelCodeDirectoryHash": mobile.get(
            "packetTunnelCodeDirectoryHash"
        ),
        "packetTunnelProvisioningProfileSha256": mobile.get(
            "packetTunnelProvisioningProfileSha256"
        ),
        "signerCertificateSha256": mobile.get(
            "signerCertificateSha256"
        ),
    }


def validate_mobile_join_receipt(
    receipt: dict[str, Any],
    join_variant: dict[str, Any],
    join_variant_receipt_sha256: str,
    production_receipt_sha256: str,
) -> None:
    artifact = receipt.get("artifact")
    ios = artifact.get("ios") if isinstance(artifact, dict) else None
    require(
        receipt.get("schema") == 1
        and receipt.get("platform") == "mobile"
        and receipt.get("coverageScope") == "android-ios-mobile-only"
        and receipt.get("publicUiOnly") is True
        and receipt.get("productionImageImportQr") is False
        and receipt.get("iosJoinTestVariant") is True
        and receipt.get("testOnlyImageImportQr") is True
        and receipt.get("productionQrDecoderPath") is True
        and receipt.get("productionJoinApprovalPath") is True
        and receipt.get("productionRosterPath") is True
        and isinstance(receipt.get("actualRenderedQrScreenCapture"), dict)
        and receipt.get("privateAppStateRead") is False
        and receipt.get("appLaunchArgumentsOrEnvironment") is False
        and receipt.get("deliveryDeadlineMilliseconds") == 15_000,
        "iOS gate seal received a non-strict mobile join receipt",
    )
    require(
        isinstance(artifact, dict)
        and isinstance(ios, dict)
        and ios.get("artifactReceiptSha256")
        == join_variant_receipt_sha256
        and ios.get("productionArtifactReceiptSha256")
        == production_receipt_sha256,
        "mobile join receipt is not bound to the iOS join-test variant",
    )
    require(
        ios.get("joinTestingCompilationCondition")
        == "NVPN_RELEASE_JOIN_TESTING"
        and ios.get("joinTestingCompilationConditionEnabled") is True
        and ios.get("productionAppByteIdentical") is False,
        "mobile join receipt does not identify its iOS join-test variant",
    )
    captures = receipt["actualRenderedQrScreenCapture"]
    for field in (
        "androidRenderedScreenSha256",
        "iosRenderedScreenSha256",
    ):
        required_hash(captures.get(field), f"mobile join {field}", 64)
    for field in (
        "appGitSha",
        "appGitTree",
        "fipsGitSha",
        "fipsGitTree",
        "appBundleTreeSha256",
        "appCodeDirectoryHash",
        "packetTunnelCodeDirectoryHash",
        "appExecutableSha256",
        "packetTunnelExecutableSha256",
        "signerCertificateSha256",
        "installedBundleIdentifier",
    ):
        require(
            ios.get(field) == join_variant.get(field)
            and bool(join_variant.get(field)),
            f"mobile join receipt iOS identity differs at {field}",
        )
    expected_timings = {
        "iPhone-admin-to-Pixel-QR",
        "Pixel-admin-to-iPhone-QR",
        "iPhone-admin-to-Pixel-manual",
        "Pixel-admin-to-iPhone-manual",
    }
    timings = receipt.get("deliveryMilliseconds")
    require(
        isinstance(timings, dict)
        and set(timings) == expected_timings
        and all(
            isinstance(value, int) and 0 <= value <= 15_000
            for value in timings.values()
        ),
        "mobile join receipt has incomplete or slow delivery timings",
    )
    qr = receipt.get("qr")
    manual = receipt.get("manual")
    content_width = receipt.get("contentWidth")
    require(
        isinstance(qr, dict)
        and qr.get("iphoneAdminPixelJoiner") is True
        and qr.get("pixelAdminIphoneJoiner") is True
        and qr.get("pendingQrBackgroundForeground") is True
        and qr.get("exactRosterOnBothSides") is True
        and qr.get("joinerRelaunchDurable") is True
        and qr.get("androidJoinerRelaunchDurable") is True
        and qr.get("iphoneJoinerRelaunchDurable") is True
        and isinstance(manual, dict)
        and manual.get("iphoneAdminPixelJoiner") is True
        and manual.get("pixelAdminIphoneJoiner") is True
        and manual.get("exactRosterOnBothSides") is True
        and manual.get("acceptedRosterOnly") is True
        and manual.get("iphoneAdminPixelJoinerRelaunchDurable") is True
        and manual.get("pixelAdminIphoneJoinerRelaunchDurable") is True
        and isinstance(content_width, dict)
        and content_width.get("minimumRequiredBasisPoints") == 9_800
        and content_width.get("maximumAllowedBasisPoints") == 10_000
        and isinstance(
            content_width.get("androidObservedBasisPoints"), int
        )
        and content_width.get("androidObservedBasisPoints") >= 9_800
        and content_width.get("androidObservedBasisPoints") <= 10_000
        and isinstance(content_width.get("iosObservedBasisPoints"), int)
        and content_width.get("iosObservedBasisPoints") >= 9_800
        and content_width.get("iosObservedBasisPoints") <= 10_000,
        "mobile join receipt lacks strict public-UI/relaunch semantics",
    )


def validate_join_variant_receipt(
    variant: dict[str, Any],
    production: dict[str, Any],
    production_receipt_sha256: str,
) -> None:
    require(
        variant.get("receiptSchema") == 2
        and variant.get("artifactType")
        == "iOS Ad Hoc Release join-test variant"
        and variant.get("joinTestingCompilationCondition")
        == "NVPN_RELEASE_JOIN_TESTING"
        and variant.get("joinTestingCompilationConditionEnabled") is True
        and variant.get("fileSharingFixture")
        == {
            "bundleIdentifier": variant.get("installedBundleIdentifier"),
            "displayName": "Nostr VPN Test Files",
            "scope": "join-test-variant-only",
        }
        and variant.get("productionArtifactReceiptSha256")
        == production_receipt_sha256
        and variant.get("productionAppByteIdentical") is False
        and variant.get("appExecutableSha256")
        != production.get("appExecutableSha256")
        and variant.get("companySigningVerified") is True
        and variant.get("debuggable") is False,
        "iOS join-test variant receipt is incomplete",
    )
    for field in (
        "appGitSha",
        "appGitTree",
        "fipsGitSha",
        "fipsGitTree",
        "fipsCoreVersion",
        "signerCertificateSha256",
        "installedBundleIdentifier",
    ):
        require(
            variant.get(field) == production.get(field)
            and bool(production.get(field)),
            f"iOS join-test variant differs from production at {field}",
        )
    for field, length in (
        ("appBundleTreeSha256", 64),
        ("appCodeDirectoryHash", 40),
        ("packetTunnelCodeDirectoryHash", 40),
        ("appExecutableSha256", 64),
        ("packetTunnelExecutableSha256", 64),
    ):
        required_hash(
            variant.get(field),
            f"iOS join-test variant {field}",
            length,
        )


def validate_mobile_network_receipt(
    receipt: dict[str, Any],
    mobile_artifact: dict[str, Any],
    mode: str,
) -> None:
    covered_modes = receipt.get("coveredModes")
    combined = (
        receipt.get("mode") == "wireguard-dns"
        and covered_modes == ["wireguard-dns", "underlay-lifecycle"]
    )
    receipt_mode = "wireguard-dns" if combined else mode
    expected_cases = (
        {
            "automatic-profile",
            "cloudflare-doh",
            "quad9-doh",
            "custom-doh",
            "through-exit",
        }
        if receipt_mode == "wireguard-dns"
        else {"automatic-profile"}
    )
    allowed_covered_modes = [None, [mode]]
    if combined or mode == "wireguard-dns":
        allowed_covered_modes.append(
            ["wireguard-dns", "underlay-lifecycle"]
        )
    identity = receipt.get("artifactIdentity")
    require(
        receipt.get("receiptSchema") == 1
        and receipt.get("artifactType")
        == f"physical ios Release {receipt_mode} gate"
        and receipt.get("platform") == "ios"
        and receipt.get("mode") == receipt_mode
        and covered_modes in allowed_covered_modes
        and receipt.get("appGitSha") == mobile_artifact.get("appGitSha")
        and receipt.get("appGitTree") == mobile_artifact.get("appGitTree")
        and receipt.get("fipsGitSha") == mobile_artifact.get("fipsGitSha")
        and receipt.get("fipsGitTree") == mobile_artifact.get("fipsGitTree")
        and isinstance(identity, dict),
        f"iOS {mode} receipt is not source/artifact bound",
    )
    for field in (
        "appBundleTreeSha256",
        "appCodeDirectoryHash",
        "packetTunnelCodeDirectoryHash",
        "appExecutableSha256",
        "packetTunnelExecutableSha256",
        "signerCertificateSha256",
        "installedBundleIdentifier",
    ):
        require(
            identity.get(field) == mobile_artifact.get(field)
            and bool(mobile_artifact.get(field)),
            f"iOS {mode} artifact identity differs at {field}",
        )
    cases = receipt.get("dnsCases")
    require(
        isinstance(cases, dict)
        and set(cases) == expected_cases
        and isinstance(receipt.get("evidenceFiles"), dict)
        and bool(receipt["evidenceFiles"]),
        f"iOS {mode} receipt has incomplete concrete evidence",
    )
    require(
        list(receipt["evidenceFiles"]).count(
            "mobile-ios-network-counter-ledger.tsv"
        )
        == 1,
        f"iOS {mode} receipt lacks its durable counter ledger",
    )
    for label, case in cases.items():
        require(
            isinstance(case, dict)
            and case.get("wireGuardRxBytesAfter", 0)
            > case.get("wireGuardRxBytesBefore", 0)
            and case.get("wireGuardTxBytesAfter", 0)
            > case.get("wireGuardTxBytesBefore", 0)
            and case.get("forwardedPacketsAfter", 0)
            > case.get("forwardedPacketsBefore", 0)
            and isinstance(case.get("dnsPathCountersBefore"), dict)
            and isinstance(case.get("dnsPathCountersAfter"), dict),
            f"iOS {mode} {label} lacks real traffic/DNS counters",
        )
    support = receipt.get("support")
    require(isinstance(support, dict), f"iOS {mode} support evidence is missing")
    if receipt_mode == "wireguard-dns":
        require(
            support.get("rapidStartStopCycles") == 8,
            "iOS WireGuard/DNS receipt lacks eight rapid start/stop cycles",
        )
    if mode == "underlay-lifecycle" or covered_modes == [
        "wireguard-dns",
        "underlay-lifecycle",
    ]:
        cycles = support.get("underlayCycles")
        cycle = cycles[0] if isinstance(cycles, list) and len(cycles) == 1 else {}
        process_counts = cycle.get("processIdentifierCounts", {})
        evidence_paths = receipt.get("evidenceFiles", {})
        required_suffixes = (
            "continuity.json",
            "host-markers.tsv",
            "processes.json",
            "reverse-payload.log",
            "runner-markers.log",
            "underlay-fresh-dns-fixture.json",
            "mobile-ios-network-counter-ledger.tsv",
        )
        require(
            isinstance(support.get("lifecycleCycles"), int)
            and support["lifecycleCycles"] >= 1
            and isinstance(cycles, list)
            and len(cycles) == 1
            and cycle.get("gate") == "wifi-radio-off-on-recovery"
            and cycle.get("outageReversePayloads") == 0
            and isinstance(
                cycle.get("dnsAndWireGuardRecoveryMilliseconds"), int
            )
            and 0 <= cycle["dnsAndWireGuardRecoveryMilliseconds"] <= 4_000
            and isinstance(
                cycle.get("firstReversePayloadRecoveryMilliseconds"), int
            )
            and 0
            <= cycle["firstReversePayloadRecoveryMilliseconds"]
            <= 4_000
            and isinstance(cycle.get("freshDnsQueryHost"), str)
            and re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{4}-[0-9a-f]{12}\..+",
                cycle["freshDnsQueryHost"],
            )
            and isinstance(cycle.get("freshDnsFixtureExactQueryCount"), int)
            and cycle["freshDnsFixtureExactQueryCount"] > 0
            and cycle.get("noValidatedPhysicalFallbackEvidenceCount") == 1
            and cycle.get("originalWifiRestoredEvidenceCount") == 1
            and process_counts.get("app") == 1
            and process_counts.get("packetTunnel") == 1
            and isinstance(evidence_paths, dict)
            and all(
                any(path.endswith(suffix) for path in evidence_paths)
                for suffix in required_suffixes
            ),
            "iOS radio-bounce receipt lacks lifecycle/recovery counters",
        )


def validate_desktop_mobile_join_receipt(
    receipt: dict[str, Any],
    join_variant: dict[str, Any],
    join_variant_receipt_sha256: str,
    mobile_join: dict[str, Any],
) -> None:
    artifact = receipt.get("artifact")
    ios_artifact = artifact.get("ios") if isinstance(artifact, dict) else None
    android = artifact.get("android") if isinstance(artifact, dict) else None
    mobile_join_artifact = mobile_join.get("artifact")
    mobile_android = (
        mobile_join_artifact.get("android")
        if isinstance(mobile_join_artifact, dict)
        else None
    )
    timings = receipt.get("deliveryMilliseconds")
    require(
        receipt.get("schema") == 1
        and receipt.get("platform") == "macos"
        and receipt.get("publicUiOnly") is True
        and receipt.get("privateStateRead") is False
        and receipt.get("fixtureInvoked") is False
        and receipt.get("appLaunchArgumentsOrEnvironment") is False
        and receipt.get("desktopAdminAndroidJoiner") is True
        and receipt.get("androidAdminDesktopJoiner") is True
        and receipt.get("desktopAdminIphoneJoiner") is True
        and receipt.get("iphoneAdminDesktopJoiner") is True
        and receipt.get("acceptedRosterRetainedAcrossRelaunch") is True
        and receipt.get("desktopRelaunchDurability") is True
        and receipt.get("pixelRelaunchDurability") is True
        and receipt.get("desktopAdminIphoneJoinerRelaunchDurable") is True
        and receipt.get("iphoneAdminDesktopJoinerRelaunchDurable") is True
        and receipt.get("deliveryDeadlineMilliseconds") == 15_000
        and isinstance(artifact, dict)
        and isinstance(ios_artifact, dict)
        and isinstance(android, dict)
        and isinstance(mobile_android, dict)
        and android.get("artifactReceiptSha256")
        == mobile_android.get("artifactReceiptSha256")
        and re.fullmatch(
            r"[0-9a-f]{64}", android.get("installReceiptSha256", "")
        )
        is not None
        and isinstance(android.get("installReceiptSize"), int)
        and android["installReceiptSize"] > 0
        and ios_artifact.get("artifactReceiptSha256")
        == join_variant_receipt_sha256
        and isinstance(timings, dict)
        and set(timings)
        == {
            "macOS-admin-to-Android-manual",
            "Android-admin-to-macOS-manual",
            "macOS-admin-to-iPhone-manual",
            "iPhone-admin-to-macOS-manual",
        }
        and all(
            isinstance(value, int) and 0 <= value <= 15_000
            for value in timings.values()
        ),
        "desktop/mobile join receipt is incomplete or not source-bound",
    )
    for field in (
        "appGitSha",
        "appGitTree",
        "fipsGitSha",
        "fipsGitTree",
        "apkSha256",
        "installedApkSha256",
        "package",
        "signerCertificateSha256",
    ):
        require(
            android.get(field) == mobile_android.get(field)
            and bool(mobile_android.get(field)),
            f"macOS/Android join artifact identity differs at {field}",
        )
    for field in (
        "appGitSha",
        "appGitTree",
        "fipsGitSha",
        "fipsGitTree",
        "appBundleTreeSha256",
        "appCodeDirectoryHash",
        "packetTunnelCodeDirectoryHash",
        "appExecutableSha256",
        "packetTunnelExecutableSha256",
        "signerCertificateSha256",
        "installedBundleIdentifier",
    ):
        require(
            ios_artifact.get(field) == join_variant.get(field)
            and bool(join_variant.get(field)),
            f"macOS/iPhone join artifact identity differs at {field}",
        )


IOS_DEVICE_OBSERVATION_FIELDS = {
    ("selectedPhysicalDevice", "identityReadAt"),
    ("selectedPhysicalDevice", "identityReadbackSha256"),
}
IOS_JOIN_RUNNER_FIELDS = IOS_DEVICE_OBSERVATION_FIELDS | {
    ("productionArtifactReceiptSha256",), ("testProductsPathSha256",),
    ("testProductsTreeSha256",), ("xctestrunPathSha256",), ("xctestrunSha256",),
    ("derivedDataPathSha256",),
}


def require_same_ios_receipt(original, current, allowed, label, path=()):
    """Allow named leaf values to differ, never keys or nested identity."""
    display = ".".join(map(str, path))
    if path in allowed:
        for value in (original, current):
            required_string(value, f"{label} {display}", r".+")
            if path[-1].endswith("Sha256"):
                required_hash(value, f"{label} {display}", 64)
        return
    require(type(original) is type(current), f"{label} differs at {display}")
    if isinstance(original, dict):
        require(original.keys() == current.keys(), f"{label} keys differ at {display}")
        for key in original:
            require_same_ios_receipt(original[key], current[key], allowed, label,
                                     path + (key,))
    elif isinstance(original, list):
        require(len(original) == len(current), f"{label} length differs at {display}")
        for index, (left, right) in enumerate(zip(original, current)):
            require_same_ios_receipt(left, right, allowed, label, path + (index,))
    else:
        require(original == current, f"{label} differs at {display}")


def desktop_join_pair(args, production, variant, variant_sha):
    variant_path = getattr(args, "desktop_join_ios_variant_receipt", None)
    production_path = getattr(args, "desktop_join_ios_production_receipt", None)
    require(bool(variant_path) == bool(production_path),
            "desktop iOS join requires both exact variant and production receipts")
    if not variant_path:
        return variant, variant_sha, {}
    desktop_production = load_json(pathlib.Path(production_path))
    desktop_production_sha = sha256_file(pathlib.Path(production_path))
    desktop_variant = load_json(pathlib.Path(variant_path))
    desktop_variant_sha = sha256_file(pathlib.Path(variant_path))
    validate_join_variant_receipt(desktop_variant, desktop_production,
                                  desktop_production_sha)
    require_same_ios_receipt(production, desktop_production,
                             IOS_DEVICE_OBSERVATION_FIELDS, "iOS production receipts")
    require_same_ios_receipt(variant, desktop_variant,
                             IOS_JOIN_RUNNER_FIELDS, "iOS join variant receipts")
    return desktop_variant, desktop_variant_sha, {
        "desktopJoinIosVariantReceiptSha256": desktop_variant_sha,
        "desktopJoinIosProductionReceiptSha256": desktop_production_sha,
    }


def seal_gate(args: argparse.Namespace) -> None:
    archive_receipt = pathlib.Path(args.archive_receipt)
    archive = load_json(archive_receipt)
    hosted_admission = validate_ios_admission(archive_receipt, archive)
    adhoc = load_json(pathlib.Path(args.adhoc_receipt))
    mobile_receipt = pathlib.Path(args.mobile_receipt)
    mobile = load_json(mobile_receipt)
    if hosted_admission:
        require(mobile.get("fipsDependenciesRebuildLocation") == "hosted"
                and mobile.get("hostedAdmissionReceiptSha256") == sha256_file(
                    archive_receipt.parent / "hosted-admission.json"),
                "physical mobile receipt lacks the hosted build admission")
    join_variant_receipt = pathlib.Path(args.mobile_join_ios_variant_receipt)
    join_variant = load_json(join_variant_receipt)
    mobile_join_receipt = pathlib.Path(args.mobile_join_receipt)
    mobile_join = load_json(mobile_join_receipt)
    mobile_wg_receipt = pathlib.Path(args.mobile_wg_receipt)
    mobile_wg = load_json(mobile_wg_receipt)
    mobile_underlay_receipt = pathlib.Path(args.mobile_underlay_receipt)
    mobile_underlay = load_json(mobile_underlay_receipt)
    desktop_join_receipt = pathlib.Path(args.desktop_mobile_join_receipt)
    desktop_join = load_json(desktop_join_receipt)
    identity, adhoc_signing = validate_archive_and_adhoc(
        archive,
        adhoc,
        sha256_file(archive_receipt),
    )
    mobile_evidence = validate_mobile_receipt(
        archive,
        adhoc,
        identity,
        adhoc_signing,
        mobile,
    )
    production_receipt_sha256 = sha256_file(mobile_receipt)
    join_variant_receipt_sha256 = sha256_file(join_variant_receipt)
    validate_join_variant_receipt(
        join_variant,
        mobile,
        production_receipt_sha256,
    )
    validate_mobile_join_receipt(
        mobile_join,
        join_variant,
        join_variant_receipt_sha256,
        production_receipt_sha256,
    )
    validate_mobile_network_receipt(mobile_wg, mobile, "wireguard-dns")
    validate_mobile_network_receipt(
        mobile_underlay,
        mobile,
        "underlay-lifecycle",
    )
    desktop_variant, desktop_variant_sha, desktop_pair_hashes = desktop_join_pair(
        args, mobile, join_variant, join_variant_receipt_sha256,
    )
    validate_desktop_mobile_join_receipt(
        desktop_join,
        desktop_variant,
        desktop_variant_sha,
        mobile_join,
    )
    required_gates = sorted(set(args.required_gate))
    require(
        required_gates == REQUIRED_REAL_DEVICE_GATES,
        "gate seal requires the exact five real-device gates",
    )
    sealed_mobile_receipt = pathlib.Path(args.sealed_mobile_receipt)
    atomic_json(sealed_mobile_receipt, mobile)
    value = {
        "receiptSchema": RECEIPT_SCHEMA,
        "artifactType": "iOS frozen archive physical-gate seal",
        "adhocExportReceiptSha256": sha256_file(pathlib.Path(args.adhoc_receipt)),
        "archiveReceiptSha256": sha256_file(pathlib.Path(args.archive_receipt)),
        "archiveTreeSha256": archive["archiveTreeSha256"],
        "mobileArtifactReceiptSha256": sha256_file(sealed_mobile_receipt),
        "mobileJoinIosVariantReceiptSha256": join_variant_receipt_sha256,
        "mobileJoinReceiptSha256": sha256_file(mobile_join_receipt),
        "mobileWireGuardDnsReceiptSha256": sha256_file(mobile_wg_receipt),
        "mobileUnderlayLifecycleReceiptSha256": sha256_file(
            mobile_underlay_receipt
        ),
        "desktopMobileJoinReceiptSha256": sha256_file(desktop_join_receipt),
        **desktop_pair_hashes,
        "realDeviceGateReceiptSha256": {
            "background-foreground-and-rapid-start-stop": [
                sha256_file(mobile_wg_receipt),
                sha256_file(mobile_underlay_receipt),
            ],
            "bidirectional-mobile-qr-and-manual-join": [
                sha256_file(mobile_join_receipt),
                join_variant_receipt_sha256,
            ],
            "desktop-mobile-manual-join": [
                sha256_file(desktop_join_receipt),
                desktop_variant_sha,
            ],
            "wifi-radio-off-on-recovery": [
                sha256_file(mobile_underlay_receipt)
            ],
            "wireguard-exit-and-five-dns-policies": [
                sha256_file(mobile_wg_receipt)
            ],
        },
        "mobileArtifactEvidence": mobile_evidence,
        "requiredRealDeviceGates": required_gates,
    }
    if hosted_admission:
        value["hostedAdmissionReceiptSha256"] = sha256_file(
            archive_receipt.parent / "hosted-admission.json")
    atomic_json(pathlib.Path(args.output), value)


def validate_gate_seal(args: argparse.Namespace) -> None:
    seal = load_json(pathlib.Path(args.gate_seal))
    archive_receipt = pathlib.Path(args.archive_receipt)
    archive = load_json(archive_receipt)
    hosted_admission = validate_ios_admission(archive_receipt, archive)
    require(seal.get("hostedAdmissionReceiptSha256") == (
        sha256_file(archive_receipt.parent / "hosted-admission.json") if hosted_admission else None),
        "physical gate does not bind the exact hosted admission")
    adhoc = load_json(pathlib.Path(args.adhoc_receipt))
    sealed_mobile_receipt = pathlib.Path(args.sealed_mobile_receipt)
    mobile = load_json(sealed_mobile_receipt)
    if hosted_admission:
        require(mobile.get("fipsDependenciesRebuildLocation") == "hosted"
                and mobile.get("hostedAdmissionReceiptSha256") == seal.get("hostedAdmissionReceiptSha256"),
                "sealed mobile receipt does not bind hosted build provenance")
    join_variant_receipt = pathlib.Path(args.mobile_join_ios_variant_receipt)
    join_variant = load_json(join_variant_receipt)
    mobile_join_receipt = pathlib.Path(args.mobile_join_receipt)
    mobile_join = load_json(mobile_join_receipt)
    mobile_wg_receipt = pathlib.Path(args.mobile_wg_receipt)
    mobile_wg = load_json(mobile_wg_receipt)
    mobile_underlay_receipt = pathlib.Path(args.mobile_underlay_receipt)
    mobile_underlay = load_json(mobile_underlay_receipt)
    desktop_join_receipt = pathlib.Path(args.desktop_mobile_join_receipt)
    desktop_join = load_json(desktop_join_receipt)
    require(
        seal.get("receiptSchema") == RECEIPT_SCHEMA
        and seal.get("artifactType")
        == "iOS frozen archive physical-gate seal",
        "iOS physical-gate seal has the wrong type",
    )
    identity, signing = validate_archive_and_adhoc(
        archive,
        adhoc,
        sha256_file(archive_receipt),
    )
    expected_evidence = validate_mobile_receipt(
        archive,
        adhoc,
        identity,
        signing,
        mobile,
    )
    production_receipt_sha256 = sha256_file(sealed_mobile_receipt)
    join_variant_receipt_sha256 = sha256_file(join_variant_receipt)
    validate_join_variant_receipt(
        join_variant,
        mobile,
        production_receipt_sha256,
    )
    validate_mobile_join_receipt(
        mobile_join,
        join_variant,
        join_variant_receipt_sha256,
        production_receipt_sha256,
    )
    validate_mobile_network_receipt(mobile_wg, mobile, "wireguard-dns")
    validate_mobile_network_receipt(
        mobile_underlay,
        mobile,
        "underlay-lifecycle",
    )
    desktop_variant, desktop_variant_sha, desktop_pair_hashes = desktop_join_pair(
        args, mobile, join_variant, join_variant_receipt_sha256,
    )
    require({key: seal[key] for key in (
        "desktopJoinIosVariantReceiptSha256", "desktopJoinIosProductionReceiptSha256",
    ) if key in seal} == desktop_pair_hashes,
            "sealed desktop iOS receipt pair differs")
    validate_desktop_mobile_join_receipt(
        desktop_join,
        desktop_variant,
        desktop_variant_sha,
        mobile_join,
    )
    required_hash(
        seal.get("archiveReceiptSha256"),
        "sealed archive receipt hash",
        64,
    )
    required_hash(
        seal.get("adhocExportReceiptSha256"),
        "sealed Ad Hoc receipt hash",
        64,
    )
    required_hash(
        seal.get("mobileArtifactReceiptSha256"),
        "sealed mobile receipt hash",
        64,
    )
    required_hash(
        seal.get("mobileJoinReceiptSha256"),
        "sealed mobile join receipt hash",
        64,
    )
    require(
        seal.get("mobileJoinIosVariantReceiptSha256")
        == join_variant_receipt_sha256,
        "sealed iOS join-test variant receipt hash differs",
    )
    required_hash(
        seal.get("mobileWireGuardDnsReceiptSha256"),
        "sealed mobile WireGuard/DNS receipt hash",
        64,
    )
    required_hash(
        seal.get("mobileUnderlayLifecycleReceiptSha256"),
        "sealed mobile underlay/lifecycle receipt hash",
        64,
    )
    required_hash(
        seal.get("desktopMobileJoinReceiptSha256"),
        "sealed desktop/mobile join receipt hash",
        64,
    )
    required_hash(
        seal.get("archiveTreeSha256"),
        "sealed archive tree hash",
        64,
    )
    require(
        seal.get("archiveReceiptSha256")
        == sha256_file(pathlib.Path(args.archive_receipt))
        and seal.get("adhocExportReceiptSha256")
        == sha256_file(pathlib.Path(args.adhoc_receipt))
        and seal.get("mobileArtifactReceiptSha256")
        == sha256_file(sealed_mobile_receipt)
        and seal.get("mobileJoinReceiptSha256")
        == sha256_file(mobile_join_receipt)
        and seal.get("mobileWireGuardDnsReceiptSha256")
        == sha256_file(mobile_wg_receipt)
        and seal.get("mobileUnderlayLifecycleReceiptSha256")
        == sha256_file(mobile_underlay_receipt)
        and seal.get("desktopMobileJoinReceiptSha256")
        == sha256_file(desktop_join_receipt)
        and seal.get("archiveTreeSha256") == archive.get("archiveTreeSha256"),
        "iOS physical-gate seal is stale",
    )
    require(
        adhoc.get("archiveTreeSha256") == archive.get("archiveTreeSha256"),
        "sealed release-testing export does not match the frozen archive",
    )
    evidence = seal.get("mobileArtifactEvidence")
    require(
        isinstance(evidence, dict),
        "iOS physical-gate seal lacks artifact evidence",
    )
    require(
        evidence == expected_evidence,
        "iOS physical-gate seal tested a different artifact",
    )
    required = set(args.required_gate)
    required_list = sorted(required)
    observed_list = seal.get("requiredRealDeviceGates")
    require(
        required_list == REQUIRED_REAL_DEVICE_GATES
        and isinstance(observed_list, list)
        and all(isinstance(value, str) and value for value in observed_list)
        and observed_list == required_list,
        f"iOS physical-gate seal mismatch: expected {required_list}, "
        f"got {observed_list!r}",
    )
    expected_gate_receipts = {
        "background-foreground-and-rapid-start-stop": [
            sha256_file(mobile_wg_receipt),
            sha256_file(mobile_underlay_receipt),
        ],
        "bidirectional-mobile-qr-and-manual-join": [
            sha256_file(mobile_join_receipt),
            join_variant_receipt_sha256,
        ],
        "desktop-mobile-manual-join": [
            sha256_file(desktop_join_receipt),
            desktop_variant_sha,
        ],
        "wifi-radio-off-on-recovery": [
            sha256_file(mobile_underlay_receipt)
        ],
        "wireguard-exit-and-five-dns-policies": [
            sha256_file(mobile_wg_receipt)
        ],
    }
    require(
        seal.get("realDeviceGateReceiptSha256") == expected_gate_receipts,
        "iOS physical-gate labels are not backed by exact concrete receipts",
    )
