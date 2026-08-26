#!/usr/bin/env python3
"""Bind macOS Exit DNS public-UI observations to an imported Release app."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
from typing import Any

from macos_release_join_artifact import (
    git_snapshot,
    inspect_signature,
    normalized_hex,
    verify_signature,
)
from mobile_release_artifact_receipt import (
    load_json,
    sha256_file,
    tree_sha256,
)


CASES: dict[str, dict[str, Any]] = {
    "automatic": {
        "mode": "automatic",
        "modeLabel": "Automatic (recommended)",
        "provider": None,
        "providerLabel": None,
        "customUrl": None,
        "bootstrapIps": None,
        "throughServers": None,
    },
    "cloudflare": {
        "mode": "encrypted",
        "modeLabel": "Encrypted DNS",
        "provider": "cloudflare",
        "providerLabel": "Cloudflare",
        "customUrl": None,
        "bootstrapIps": None,
        "throughServers": None,
    },
    "quad9": {
        "mode": "encrypted",
        "modeLabel": "Encrypted DNS",
        "provider": "quad9",
        "providerLabel": "Quad9",
        "customUrl": None,
        "bootstrapIps": None,
        "throughServers": None,
    },
    "custom": {
        "mode": "encrypted",
        "modeLabel": "Encrypted DNS",
        "provider": "custom",
        "providerLabel": "Custom DoH",
        "customUrl": "https://dns.google/dns-query",
        "bootstrapIps": "8.8.8.8,8.8.4.4",
        "throughServers": None,
    },
    "through-exit": {
        "mode": "through_exit",
        "modeLabel": "DNS through exit",
        "provider": None,
        "providerLabel": None,
        "customUrl": None,
        "bootstrapIps": None,
        "throughServers": "10.99.79.53",
    },
}


def fail(message: str) -> None:
    raise ValueError(message)


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def require(value: dict[str, Any], name: str, expected: Any) -> None:
    if value.get(name) != expected:
        fail(
            f"{name} mismatch: expected {expected!r}, "
            f"got {value.get(name)!r}"
        )


def tracked_source_sha(root: pathlib.Path, source: pathlib.Path) -> str:
    relative = source.resolve().relative_to(root.resolve()).as_posix()
    subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", relative],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    committed = subprocess.run(
        ["git", "-C", str(root), "show", f"HEAD:{relative}"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    digest = hashlib.sha256(committed).hexdigest()
    if digest != sha256_file(source):
        fail("macOS Exit DNS AX source differs from the committed candidate")
    return digest


def validate_app_receipt(
    receipt: dict[str, Any],
    app: pathlib.Path,
    expected_app_head: str,
    expected_app_tree: str,
) -> None:
    executable = app / "Contents" / "MacOS" / "Nostr VPN"
    if not executable.is_file() or not app.is_dir():
        fail("exact macOS Release app is missing")
    for name, expected in (
        ("receiptSchema", 1),
        ("artifactType", "macOS company Developer ID Release gate package"),
        ("companySigningVerified", True),
        ("configuration", "Release"),
        ("builtOnHost", True),
        ("builtOnTestVm", False),
        ("appGitSha", expected_app_head),
        ("appGitTree", expected_app_tree),
        ("appExecutableSha256", sha256_file(executable)),
        ("appBundleTreeSha256", tree_sha256(app)),
    ):
        require(receipt, name, expected)
    normalized_hex(
        receipt.get("appSourceManifestSha256"),
        64,
        "app source manifest SHA-256",
    )
    signature = inspect_signature(app, deep=True)
    for name, expected in (
        ("team", receipt.get("signingTeam")),
        ("cdhash", receipt.get("appCodeDirectoryHash")),
        ("certificateSha1", receipt.get("signingIdentitySha1")),
        ("certificateSha256", receipt.get("signerCertificateSha256")),
    ):
        if signature.get(name) != expected:
            fail(f"macOS Release app signature {name} changed")


def observed_driver(args: argparse.Namespace) -> dict[str, Any]:
    root = pathlib.Path(args.app_root).resolve()
    source_path = pathlib.Path(args.driver_source).resolve()
    driver = pathlib.Path(args.driver).resolve()
    app = pathlib.Path(args.app).resolve()
    app_receipt_path = pathlib.Path(args.app_receipt).resolve()
    for path in (source_path, driver, app_receipt_path):
        if not path.is_file():
            fail(f"required macOS Exit DNS artifact is missing: {path}")
    source = git_snapshot(root)
    app_receipt = load_json(app_receipt_path)
    validate_app_receipt(
        app_receipt,
        app,
        args.expected_app_head,
        args.expected_app_tree,
    )
    expected_identity = normalized_hex(
        args.expected_identity_sha1, 40, "signing identity SHA-1"
    )
    expected_signer = normalized_hex(
        args.expected_signer_sha256, 64, "signer certificate SHA-256"
    )
    driver_signature = inspect_signature(driver)
    verify_signature(
        driver_signature,
        expected_team=args.expected_team,
        expected_identity=expected_identity,
        expected_signer=expected_signer,
        label="macOS Exit DNS AX driver",
    )
    if (
        app_receipt.get("signingTeam") != args.expected_team
        or app_receipt.get("signingIdentitySha1") != expected_identity
        or app_receipt.get("signerCertificateSha256") != expected_signer
    ):
        fail("app and Exit DNS driver are not signed by the same company identity")
    return {
        "receiptSchema": 1,
        "artifactType": "macOS Exit DNS public-UI Release gate driver",
        "appArtifactReceiptSha256": sha256_file(app_receipt_path),
        "appExecutableSha256": app_receipt["appExecutableSha256"],
        "appBundleTreeSha256": app_receipt["appBundleTreeSha256"],
        "appGitSha": app_receipt["appGitSha"],
        "appGitTree": app_receipt["appGitTree"],
        "appSourceManifestSha256": app_receipt[
            "appSourceManifestSha256"
        ],
        "harnessGitSha": source["head"],
        "harnessGitTree": source["tree"],
        "harnessSourceManifestSha256": source["manifest"],
        "fipsGitSha": app_receipt["fipsGitSha"],
        "fipsGitTree": app_receipt["fipsGitTree"],
        "fipsCoreVersion": app_receipt["fipsCoreVersion"],
        "driverSourcePath": source_path.relative_to(root).as_posix(),
        "driverSourceSha256": tracked_source_sha(root, source_path),
        "driverExecutableSha256": sha256_file(driver),
        "driverCodeDirectoryHash": driver_signature["cdhash"],
        "signingTeam": driver_signature["team"],
        "signingIdentitySha1": driver_signature["certificateSha1"],
        "signerCertificateSha256": driver_signature["certificateSha256"],
        "companySigningVerified": True,
        "builtOnHost": True,
        "builtOnTestVm": False,
        "expectedCases": list(CASES),
    }


def create_driver(args: argparse.Namespace) -> None:
    write_json(pathlib.Path(args.output), observed_driver(args))


def validate_driver(args: argparse.Namespace) -> None:
    receipt_path = pathlib.Path(args.receipt)
    receipt = load_json(receipt_path)
    observed = observed_driver(args)
    if receipt != observed:
        fail("imported macOS Exit DNS driver receipt changed")
    output = {
        "receiptSchema": 1,
        "remoteDriverVerified": True,
        "driverReceiptSha256": sha256_file(receipt_path),
        "appArtifactReceiptSha256": observed["appArtifactReceiptSha256"],
        "appExecutableSha256": observed["appExecutableSha256"],
        "appBundleTreeSha256": observed["appBundleTreeSha256"],
        "appGitSha": observed["appGitSha"],
        "appGitTree": observed["appGitTree"],
        "harnessGitSha": observed["harnessGitSha"],
        "harnessGitTree": observed["harnessGitTree"],
        "driverExecutableSha256": observed["driverExecutableSha256"],
        "driverSourceSha256": observed["driverSourceSha256"],
        "driverCodeDirectoryHash": observed["driverCodeDirectoryHash"],
        "signingTeam": observed["signingTeam"],
        "signingIdentitySha1": observed["signingIdentitySha1"],
        "signerCertificateSha256": observed["signerCertificateSha256"],
        "builtOnHost": True,
        "builtOnTestVm": False,
    }
    write_json(pathlib.Path(args.verification_output), output)


def label_matches(actual: Any, expected: str) -> bool:
    return isinstance(actual, str) and (
        actual == expected
        or actual.startswith(f"{expected},")
        or actual.endswith(f", {expected}")
    )


def expected_controls(spec: dict[str, Any]) -> list[str]:
    controls = ["exit-dns-mode", "exit-dns-save"]
    if spec["provider"] is not None:
        controls.append("exit-dns-provider")
    if spec["customUrl"] is not None:
        controls += ["exit-dns-custom-url", "exit-dns-bootstrap-ips"]
    if spec["throughServers"] is not None:
        controls.append("exit-dns-through-servers")
    return sorted(controls)


def validate_observation(
    value: dict[str, Any],
    case: str,
    phase: str,
) -> None:
    spec = CASES[case]
    for name, expected in (
        ("receiptSchema", 1),
        ("phase", phase),
        ("case", case),
        ("processName", "Nostr VPN"),
        ("publicUiOnly", True),
        ("privateStateRead", False),
        ("savedViaShippedUi", phase == "apply"),
        (
            "networkCreatedViaShippedUi",
            case == "automatic" and phase == "apply",
        ),
        ("visibleControlIdentifiers", expected_controls(spec)),
    ):
        require(value, name, expected)
    if not isinstance(value.get("pid"), int) or value["pid"] <= 0:
        fail(f"{case} {phase} observation has no real app PID")
    if (
        not isinstance(value.get("observedAtUnixMilliseconds"), int)
        or value["observedAtUnixMilliseconds"] <= 0
    ):
        fail(f"{case} {phase} observation has no timestamp")
    values = value.get("values")
    if not isinstance(values, dict):
        fail(f"{case} {phase} has no public control values")
    require(values, "mode", spec["mode"])
    require(values, "modeLabel", spec["modeLabel"])
    if not label_matches(values.get("rawModeValue"), spec["modeLabel"]):
        fail(f"{case} {phase} mode is not publicly readable")
    optional = (
        ("provider", "provider"),
        ("providerLabel", "providerLabel"),
        ("customUrl", "customUrl"),
        ("bootstrapIps", "bootstrapIps"),
        ("throughServers", "throughServers"),
    )
    for field, spec_field in optional:
        expected = spec[spec_field]
        if expected is None:
            if field in values:
                fail(f"{case} {phase} claims hidden public value {field}")
        else:
            require(values, field, expected)
    if spec["providerLabel"] is not None and not label_matches(
        values.get("rawProviderValue"), spec["providerLabel"]
    ):
        fail(f"{case} {phase} provider is not publicly readable")
    if spec["providerLabel"] is None and "rawProviderValue" in values:
        fail(f"{case} {phase} claims a hidden provider read")


def create_case(args: argparse.Namespace) -> None:
    case = args.case
    if case not in CASES:
        fail(f"unsupported Exit DNS receipt case: {case}")
    apply_path = pathlib.Path(args.apply_observation)
    readback_path = pathlib.Path(args.readback_observation)
    apply = load_json(apply_path)
    readback = load_json(readback_path)
    validate_observation(apply, case, "apply")
    validate_observation(readback, case, "readback")
    if apply["pid"] == readback["pid"]:
        fail(f"{case} was not read from a relaunched app process")
    if (
        readback["observedAtUnixMilliseconds"]
        < apply["observedAtUnixMilliseconds"]
    ):
        fail(f"{case} readback predates its save")
    app_receipt_path = pathlib.Path(args.app_receipt)
    driver_receipt_path = pathlib.Path(args.driver_receipt)
    import_path = pathlib.Path(args.import_verification)
    driver_verification_path = pathlib.Path(args.driver_verification)
    app_receipt = load_json(app_receipt_path)
    driver_receipt = load_json(driver_receipt_path)
    imported = load_json(import_path)
    driver_verified = load_json(driver_verification_path)
    app_receipt_sha = sha256_file(app_receipt_path)
    driver_receipt_sha = sha256_file(driver_receipt_path)
    for name, expected in (
        ("receiptSchema", 1),
        ("remoteImportVerified", True),
        ("artifactReceiptSha256", app_receipt_sha),
        ("appGitSha", app_receipt["appGitSha"]),
        ("appGitTree", app_receipt["appGitTree"]),
    ):
        require(imported, name, expected)
    for name, expected in (
        ("receiptSchema", 1),
        ("remoteDriverVerified", True),
        ("driverReceiptSha256", driver_receipt_sha),
        ("appArtifactReceiptSha256", app_receipt_sha),
        ("appGitSha", app_receipt["appGitSha"]),
        ("appGitTree", app_receipt["appGitTree"]),
    ):
        require(driver_verified, name, expected)
    for name in (
        "appExecutableSha256",
        "appBundleTreeSha256",
        "appGitSha",
        "appGitTree",
        "fipsGitSha",
        "fipsGitTree",
        "fipsCoreVersion",
    ):
        require(driver_receipt, name, app_receipt[name])
    spec = CASES[case]
    output = {
        "receiptSchema": 1,
        "platform": "macos",
        "case": case,
        "evidenceSource": "shipped-ui-restart-readback",
        "releaseBlackbox": True,
        "exitDnsMode": spec["mode"],
        "exitDnsDohProvider": spec["provider"] or "",
        "exitDnsCustomDohUrl": spec["customUrl"] or "",
        "exitDnsCustomDohBootstrapIps": spec["bootstrapIps"] or "",
        "exitDnsThroughExitServers": spec["throughServers"] or "",
        "savedViaShippedUi": True,
        "uiRestartReadback": True,
        "publicUiOnly": True,
        "privateStateRead": False,
        "privateAppStateRead": False,
        "appLaunchArgumentsOrEnvironment": False,
        "canonicalProfile": True,
        "appGitSha": app_receipt["appGitSha"],
        "appGitTree": app_receipt["appGitTree"],
        "fipsGitSha": app_receipt["fipsGitSha"],
        "fipsGitTree": app_receipt["fipsGitTree"],
        "fipsCoreVersion": app_receipt["fipsCoreVersion"],
        "appExecutableSha256": app_receipt["appExecutableSha256"],
        "cliExecutableSha256": app_receipt["cliExecutableSha256"],
        "appBundleTreeSha256": app_receipt["appBundleTreeSha256"],
        "appArtifactReceiptSha256": app_receipt_sha,
        "remoteImportVerificationSha256": sha256_file(import_path),
        "driverExecutableSha256": driver_receipt[
            "driverExecutableSha256"
        ],
        "driverSourceSha256": driver_receipt["driverSourceSha256"],
        "driverReceiptSha256": driver_receipt_sha,
        "remoteDriverVerificationSha256": sha256_file(
            driver_verification_path
        ),
        "applyObservationSha256": sha256_file(apply_path),
        "readbackObservationSha256": sha256_file(readback_path),
        "applyPid": apply["pid"],
        "readbackPid": readback["pid"],
        "relaunchPidChanged": True,
        "builtOnHost": True,
        "builtOnTestVm": False,
        "companySigningVerified": True,
    }
    write_json(pathlib.Path(args.output), output)


def create_seller(args: argparse.Namespace) -> None:
    apply_path = pathlib.Path(args.apply_observation)
    readback_path = pathlib.Path(args.readback_observation)
    apply = load_json(apply_path)
    readback = load_json(readback_path)
    expected_controls = sorted(
        [
            "paid-exit-seller-enabled",
            "paid-exit-price-msat-per-gb",
            "paid-exit-country-code",
            "paid-exit-accepted-mints",
            "paid-exit-seller-save",
        ]
    )
    expected_values = {
        "enabled": True,
        "priceMsatPerGb": 1_000_000,
        "countryCode": "FI",
        "acceptedMints": ["http://cashu-mint:3338"],
    }
    for value, phase in ((apply, "apply"), (readback, "readback")):
        for name, expected in (
            ("receiptSchema", 1),
            ("phase", phase),
            ("case", "paid-exit-seller"),
            ("processName", "Nostr VPN"),
            ("publicUiOnly", True),
            ("privateStateRead", False),
            ("savedViaShippedUi", phase == "apply"),
            ("enabledViaShippedUi", phase == "apply"),
            ("networkCreatedViaShippedUi", False),
            ("visibleControlIdentifiers", expected_controls),
            ("values", expected_values),
        ):
            require(value, name, expected)
        if not isinstance(value.get("pid"), int) or value["pid"] <= 0:
            fail(f"paid-exit seller {phase} observation has no real app PID")
    if apply["pid"] == readback["pid"]:
        fail("paid-exit seller was not read from a relaunched app process")
    if readback["observedAtUnixMilliseconds"] < apply["observedAtUnixMilliseconds"]:
        fail("paid-exit seller readback predates its save")

    app_receipt_path = pathlib.Path(args.app_receipt)
    driver_receipt_path = pathlib.Path(args.driver_receipt)
    import_path = pathlib.Path(args.import_verification)
    driver_verification_path = pathlib.Path(args.driver_verification)
    app_receipt = load_json(app_receipt_path)
    driver_receipt = load_json(driver_receipt_path)
    imported = load_json(import_path)
    driver_verified = load_json(driver_verification_path)
    app_receipt_sha = sha256_file(app_receipt_path)
    driver_receipt_sha = sha256_file(driver_receipt_path)
    for name, expected in (
        ("receiptSchema", 1),
        ("remoteImportVerified", True),
        ("artifactReceiptSha256", app_receipt_sha),
        ("appGitSha", app_receipt["appGitSha"]),
        ("appGitTree", app_receipt["appGitTree"]),
    ):
        require(imported, name, expected)
    for name, expected in (
        ("receiptSchema", 1),
        ("remoteDriverVerified", True),
        ("driverReceiptSha256", driver_receipt_sha),
        ("appArtifactReceiptSha256", app_receipt_sha),
        ("appGitSha", app_receipt["appGitSha"]),
        ("appGitTree", app_receipt["appGitTree"]),
    ):
        require(driver_verified, name, expected)
    for name in (
        "appExecutableSha256",
        "appBundleTreeSha256",
        "appGitSha",
        "appGitTree",
        "fipsGitSha",
        "fipsGitTree",
        "fipsCoreVersion",
    ):
        require(driver_receipt, name, app_receipt[name])

    output = {
        "receiptSchema": 1,
        "platform": "macos",
        "case": "paid-exit-seller",
        "evidenceSource": "shipped-ui-restart-readback",
        "releaseBlackbox": True,
        "savedViaShippedUi": True,
        "enabledViaShippedUi": True,
        "uiRestartReadback": True,
        "publicUiOnly": True,
        "privateStateRead": False,
        "privateAppStateRead": False,
        "appLaunchArgumentsOrEnvironment": False,
        "canonicalProfile": True,
        "paidExitEnabled": True,
        "paidExitPriceMsatPerGb": 1_000_000,
        "paidExitCountryCode": "FI",
        "paidExitAcceptedMints": ["http://cashu-mint:3338"],
        "appGitSha": app_receipt["appGitSha"],
        "appGitTree": app_receipt["appGitTree"],
        "fipsGitSha": app_receipt["fipsGitSha"],
        "fipsGitTree": app_receipt["fipsGitTree"],
        "fipsCoreVersion": app_receipt["fipsCoreVersion"],
        "appExecutableSha256": app_receipt["appExecutableSha256"],
        "cliExecutableSha256": app_receipt["cliExecutableSha256"],
        "appBundleTreeSha256": app_receipt["appBundleTreeSha256"],
        "appArtifactReceiptSha256": app_receipt_sha,
        "remoteImportVerificationSha256": sha256_file(import_path),
        "driverExecutableSha256": driver_receipt["driverExecutableSha256"],
        "driverSourceSha256": driver_receipt["driverSourceSha256"],
        "driverReceiptSha256": driver_receipt_sha,
        "remoteDriverVerificationSha256": sha256_file(driver_verification_path),
        "applyObservationSha256": sha256_file(apply_path),
        "readbackObservationSha256": sha256_file(readback_path),
        "applyPid": apply["pid"],
        "readbackPid": readback["pid"],
        "relaunchPidChanged": True,
        "builtOnHost": True,
        "builtOnTestVm": False,
        "companySigningVerified": True,
    }
    write_json(pathlib.Path(args.output), output)


def create_summary(args: argparse.Namespace) -> None:
    case_dir = pathlib.Path(args.case_dir)
    app_receipt_path = pathlib.Path(args.app_receipt)
    driver_receipt_path = pathlib.Path(args.driver_receipt)
    import_path = pathlib.Path(args.import_verification)
    driver_verification_path = pathlib.Path(args.driver_verification)
    restoration_path = pathlib.Path(args.restoration_receipt)
    app_receipt = load_json(app_receipt_path)
    driver_receipt = load_json(driver_receipt_path)
    restoration = load_json(restoration_path)
    for name, expected in (
        ("receiptSchema", 1),
        ("canonicalProfileRestored", True),
        ("preexistingAppStateRestored", True),
        ("gateAppProcessesStopped", True),
    ):
        require(restoration, name, expected)
    case_hashes: dict[str, str] = {}
    for case, spec in CASES.items():
        path = case_dir / f"{case}.json"
        value = load_json(path)
        for name, expected in (
            ("receiptSchema", 1),
            ("platform", "macos"),
            ("case", case),
            ("evidenceSource", "shipped-ui-restart-readback"),
            ("releaseBlackbox", True),
            ("exitDnsMode", spec["mode"]),
            ("exitDnsDohProvider", spec["provider"] or ""),
            ("exitDnsCustomDohUrl", spec["customUrl"] or ""),
            (
                "exitDnsCustomDohBootstrapIps",
                spec["bootstrapIps"] or "",
            ),
            (
                "exitDnsThroughExitServers",
                spec["throughServers"] or "",
            ),
            ("savedViaShippedUi", True),
            ("uiRestartReadback", True),
            ("publicUiOnly", True),
            ("privateStateRead", False),
            ("appLaunchArgumentsOrEnvironment", False),
            ("appGitSha", app_receipt["appGitSha"]),
            ("appGitTree", app_receipt["appGitTree"]),
            ("appExecutableSha256", app_receipt["appExecutableSha256"]),
            ("cliExecutableSha256", app_receipt["cliExecutableSha256"]),
            (
                "appArtifactReceiptSha256",
                sha256_file(app_receipt_path),
            ),
            (
                "driverReceiptSha256",
                sha256_file(driver_receipt_path),
            ),
        ):
            require(value, name, expected)
        case_hashes[case] = sha256_file(path)
    summary = {
        "receiptSchema": 1,
        "platform": "macos",
        "gate": "shipped Release Exit DNS public UI",
        "cases": case_hashes,
        "allDnsOptionsSavedAndRelaunchRead": True,
        "automaticVerified": True,
        "cloudflareVerified": True,
        "quad9Verified": True,
        "customGoogleDohAndBootstrapVerified": True,
        "dnsThroughExitVerified": True,
        "publicUiOnly": True,
        "privateStateRead": False,
        "appLaunchArgumentsOrEnvironment": False,
        "canonicalProfileRestored": True,
        "appGitSha": app_receipt["appGitSha"],
        "appGitTree": app_receipt["appGitTree"],
        "fipsGitSha": app_receipt["fipsGitSha"],
        "fipsGitTree": app_receipt["fipsGitTree"],
        "fipsCoreVersion": app_receipt["fipsCoreVersion"],
        "appExecutableSha256": app_receipt["appExecutableSha256"],
        "appBundleTreeSha256": app_receipt["appBundleTreeSha256"],
        "appArtifactReceiptSha256": sha256_file(app_receipt_path),
        "remoteImportVerificationSha256": sha256_file(import_path),
        "driverExecutableSha256": driver_receipt[
            "driverExecutableSha256"
        ],
        "driverSourceSha256": driver_receipt["driverSourceSha256"],
        "driverReceiptSha256": sha256_file(driver_receipt_path),
        "remoteDriverVerificationSha256": sha256_file(
            driver_verification_path
        ),
        "restorationReceiptSha256": sha256_file(restoration_path),
        "builtOnHost": True,
        "builtOnTestVm": False,
        "remoteImportVerified": True,
        "companySigningVerified": True,
    }
    write_json(pathlib.Path(args.output), summary)


def add_driver_common(command: argparse.ArgumentParser) -> None:
    for name in (
        "driver",
        "driver_source",
        "app",
        "app_receipt",
        "app_root",
        "expected_app_head",
        "expected_app_tree",
        "expected_team",
        "expected_identity_sha1",
        "expected_signer_sha256",
    ):
        command.add_argument(f"--{name.replace('_', '-')}", required=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-driver")
    add_driver_common(create)
    create.add_argument("--output", required=True)
    validate = commands.add_parser("validate-driver")
    add_driver_common(validate)
    validate.add_argument("--receipt", required=True)
    validate.add_argument("--verification-output", required=True)
    case = commands.add_parser("create-case")
    case.add_argument("--case", required=True, choices=list(CASES))
    for name in (
        "apply_observation",
        "readback_observation",
        "app_receipt",
        "driver_receipt",
        "import_verification",
        "driver_verification",
        "output",
    ):
        case.add_argument(f"--{name.replace('_', '-')}", required=True)
    seller = commands.add_parser("create-seller")
    for name in (
        "apply_observation",
        "readback_observation",
        "app_receipt",
        "driver_receipt",
        "import_verification",
        "driver_verification",
        "output",
    ):
        seller.add_argument(f"--{name.replace('_', '-')}", required=True)
    summary = commands.add_parser("create-summary")
    for name in (
        "case_dir",
        "app_receipt",
        "driver_receipt",
        "import_verification",
        "driver_verification",
        "restoration_receipt",
        "output",
    ):
        summary.add_argument(f"--{name.replace('_', '-')}", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "create-driver":
            create_driver(args)
        elif args.command == "validate-driver":
            validate_driver(args)
        elif args.command == "create-case":
            create_case(args)
        elif args.command == "create-seller":
            create_seller(args)
        else:
            create_summary(args)
    except (
        json.JSONDecodeError,
        OSError,
        subprocess.CalledProcessError,
        ValueError,
    ) as error:
        print(f"macOS Exit DNS UI receipt rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
