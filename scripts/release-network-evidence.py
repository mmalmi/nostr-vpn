#!/usr/bin/env python3
"""Build fail-closed, source-bound receipts from real release network gates."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any


DNS_CASES = {
    "automatic-profile": "dns-profile",
    "cloudflare-doh": "doh-cloudflare",
    "quad9-doh": "doh-quad9",
    "custom-doh": "doh-google",
    "through-exit": "dns-through",
}
COUNTERS = (
    "query",
    "profile",
    "cloudflareSni",
    "quad9Sni",
    "googleSni",
    "through",
    "forward",
)
DNS_COUNTERS_INCREASED = {
    "dns-profile": {"query", "profile"},
    "doh-cloudflare": {"cloudflareSni"},
    "doh-quad9": {"quad9Sni"},
    "doh-google": {"googleSni"},
    "dns-through": {"query", "through"},
}
DESKTOP_DNS_COUNTERS = {
    "automatic": "profile_dns",
    "cloudflare": "cloudflare",
    "quad9": "quad9",
    "custom": "google",
    "through-exit": "fixture_dns",
}
DESKTOP_DNS_COUNTER_NAMES = (
    "profile_dns",
    "cloudflare",
    "quad9",
    "google",
    "fixture_dns",
)
UUID_SUBDOMAIN_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\..+"
)
DESKTOP_DNS_UI_SETTINGS = {
    "automatic": ("automatic", "cloudflare", "", "", ""),
    "cloudflare": ("encrypted", "cloudflare", "", "", ""),
    "quad9": ("encrypted", "quad9", "", "", ""),
    "custom": (
        "encrypted",
        "custom",
        "https://dns.google/dns-query",
        "8.8.8.8,8.8.4.4",
        "",
    ),
    "through-exit": ("through_exit", "cloudflare", "", "", None),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: pathlib.Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing regular JSON receipt: {path}")
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    require(isinstance(value, dict), f"JSON receipt is not an object: {path}")
    return value


def atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def require_hash(value: Any, label: str, length: int = 64) -> str:
    require(
        isinstance(value, str)
        and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None,
        f"{label} is not a lowercase {length}-digit hash",
    )
    return value


def artifact_identity(platform: str, artifact: dict[str, Any]) -> dict[str, Any]:
    expected_type = {
        "android": "Android Release APK",
        "ios": "iOS company Ad Hoc Release app",
    }[platform]
    require(
        artifact.get("receiptSchema") == 2
        and artifact.get("artifactType") == expected_type
        and artifact.get("companySigningVerified") is True,
        f"{platform} network gate artifact receipt is not strict Release evidence",
    )
    if platform == "android":
        require(
            artifact.get("apkDerivedFromAab") is True
            and artifact.get("bundletoolVersion") == "1.18.3",
            "Android network gate APK is not derived from the sealed Play AAB",
        )
        require_hash(artifact.get("aabSha256"), "Android artifact AAB SHA-256")
        require_hash(
            artifact.get("bundleReceiptSha256"),
            "Android bundle relationship receipt SHA-256",
        )
        require_hash(
            artifact.get("bundletoolSha256"),
            "Android artifact bundletool SHA-256",
        )
    for field in ("appGitSha", "appGitTree", "fipsGitSha", "fipsGitTree"):
        require_hash(artifact.get(field), f"{platform} artifact {field}", 40)
    fields = {
        "android": (
            "apkSha256",
            "installedApkSha256",
            "package",
            "signerCertificateSha256",
        ),
        "ios": (
            "appBundleTreeSha256",
            "appCodeDirectoryHash",
            "packetTunnelCodeDirectoryHash",
            "appExecutableSha256",
            "packetTunnelExecutableSha256",
            "signerCertificateSha256",
            "installedBundleIdentifier",
        ),
    }[platform]
    identity = {field: artifact.get(field) for field in fields}
    require(all(identity.values()), f"{platform} artifact identity is incomplete")
    return identity


def validate_dns_path_counters(
    label: str,
    evidence: str,
    before_dns: dict[str, int],
    after_dns: dict[str, int],
    platform: str = "",
) -> None:
    expected_evidence = DNS_CASES.get(label)
    require(expected_evidence == evidence, f"{label} has the wrong DNS evidence kind")
    increased = DNS_COUNTERS_INCREASED[evidence]
    unattributed = (
        {"cloudflareSni", "quad9Sni", "googleSni"}
        if platform == "ios"
        else set()
    )
    require(
        set(before_dns) == set(COUNTERS) and set(after_dns) == set(COUNTERS),
        f"{label} DNS counter set is incomplete",
    )
    for counter in COUNTERS:
        if counter in unattributed:
            continue
        if counter in increased:
            require(
                after_dns[counter] > before_dns[counter],
                f"{label} did not increase required {counter} DNS counter",
            )
        else:
            require(
                after_dns[counter] == before_dns[counter],
                f"{label} used forbidden {counter} DNS path",
            )


def split_dns_counters(
    values: list[int], label: str
) -> tuple[dict[str, int], dict[str, int]]:
    require(
        len(values) == 2 * len(COUNTERS),
        f"{label} DNS counter row has the wrong width",
    )
    width = len(COUNTERS)
    return dict(zip(COUNTERS, values[:width])), dict(zip(COUNTERS, values[width:]))


def parse_counter_ledger(
    path: pathlib.Path,
    expected_cases: list[str],
    platform: str,
) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "mobile counter ledger is missing")
    rows: dict[str, Any] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        fields = raw.split("\t")
        require(len(fields) == 24, "mobile counter ledger row has the wrong width")
        label, evidence = fields[:2]
        require(label not in rows, f"duplicate counter row for {label}")
        values = [int(value) for value in fields[2:]]
        (
            before_rx,
            after_rx,
            before_tx,
            after_tx,
            before_forward,
            after_forward,
            *dns_values,
        ) = values
        require(
            after_rx > before_rx
            and after_tx > before_tx
            and after_forward > before_forward,
            f"{label} lacks increasing WireGuard/forward counters",
        )
        before_observed_at, after_observed_at = dns_values[0], dns_values[8]
        require(
            after_observed_at > before_observed_at,
            f"{label} DNS counters are not bounded by increasing timestamps",
        )
        before_dns, after_dns = split_dns_counters(
            dns_values[1:8] + dns_values[9:], label
        )
        validate_dns_path_counters(
            label, evidence, before_dns, after_dns, platform
        )
        rows[label] = {
            "dnsEvidence": evidence,
            "dnsPathCountersBefore": before_dns,
            "dnsPathCountersAfter": after_dns,
            "dnsPathCountersBeforeObservedAtUnix": before_observed_at,
            "dnsPathCountersAfterObservedAtUnix": after_observed_at,
            "wireGuardRxBytesBefore": before_rx,
            "wireGuardRxBytesAfter": after_rx,
            "wireGuardTxBytesBefore": before_tx,
            "wireGuardTxBytesAfter": after_tx,
            "forwardedPacketsBefore": before_forward,
            "forwardedPacketsAfter": after_forward,
        }
    require(set(rows) == set(expected_cases), "mobile counter ledger has the wrong DNS cases")
    return {label: rows[label] for label in expected_cases}


def evidence_hashes(root: pathlib.Path, paths: list[pathlib.Path]) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(set(paths)):
        require(path.is_file() and not path.is_symlink(), f"invalid evidence file: {path}")
        relative = path.relative_to(root).as_posix()
        require(relative not in result, f"duplicate evidence path: {relative}")
        result[relative] = sha256(path)
    require(result, "network gate has no concrete evidence files")
    return result


def exactly_one(root: pathlib.Path, pattern: str, label: str) -> pathlib.Path:
    matches = list(root.glob(pattern))
    require(len(matches) == 1, f"{label} expected one concrete receipt, found {len(matches)}")
    return matches[0]


def validate_underlay_continuity(
    path: pathlib.Path,
    platform: str,
    ping_path: pathlib.Path,
    marker_path: pathlib.Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    receipt = load_json(path)
    with tempfile.NamedTemporaryFile(suffix=".json") as recomputed:
        completed = subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(__file__).with_name(
                    "validate-mobile-underlay-continuity.py"
                )),
                str(ping_path),
                str(marker_path),
                recomputed.name,
                platform,
                "4000",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            completed.returncode == 0,
            f"{platform} raw underlay evidence failed validation",
        )
        require(
            receipt == load_json(pathlib.Path(recomputed.name)),
            f"{platform} underlay summary differs from its raw evidence",
        )
    cycles = receipt.get("cycles")
    require(
        receipt.get("passed") is True
        and receipt.get("platform") == platform
        and receipt.get("maxRecoveryMilliseconds") == 4_000
        and isinstance(receipt.get("successfulPayloads"), int)
        and receipt["successfulPayloads"] > 0
        and isinstance(cycles, list)
        and len(cycles) == 1,
        f"{platform} underlay continuity receipt is incomplete",
    )
    cycle = cycles[0]
    requested = cycle.get("requestedAtMilliseconds")
    outage = cycle.get("outageAtMilliseconds")
    recovery_requested = cycle.get("recoveryRequestedAtMilliseconds")
    underlay_validated = cycle.get("underlayValidatedAtMilliseconds")
    verified = cycle.get("verifiedAtMilliseconds")
    recovery = cycle.get("recoveryMilliseconds")
    association = cycle.get("underlayAssociationMilliseconds")
    require(
        all(
            isinstance(value, int)
            for value in (
                requested,
                outage,
                recovery_requested,
                underlay_validated,
                verified,
                recovery,
                association,
            )
        )
        and requested <= outage < recovery_requested <= underlay_validated <= verified
        and association == underlay_validated - recovery_requested
        and 0 <= association <= 30_000
        and 0 <= recovery <= 4_000
        and cycle.get("dnsAndWireGuardRecoveryMilliseconds") == recovery
        and cycle.get("outageReversePayloads") == 0
        and isinstance(cycle.get("firstReversePayloadRecoveryMilliseconds"), int)
        and 0 <= cycle["firstReversePayloadRecoveryMilliseconds"] <= 4_000
        and cycle.get("payloadBeforeSwitch") is True
        and cycle.get("reversePayloadAfterRecoveryRequest") is True
        and isinstance(cycle.get("reversePayloadRecoveredBeforeValidation"), bool),
        f"{platform} underlay continuity measurements are incomplete",
    )
    return receipt, cycle


def underlay_marker_values(path: pathlib.Path) -> dict[str, str]:
    require(
        path.is_file() and not path.is_symlink(),
        f"missing regular underlay markers: {path}",
    )
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        require(len(fields) == 2, f"invalid underlay marker row in {path.name}")
        require(fields[0] not in values, f"duplicate underlay marker {fields[0]}")
        values[fields[0]] = fields[1]
    return values


def validate_android_underlay_markers(path: pathlib.Path) -> dict[str, Any]:
    markers = underlay_marker_values(path)
    app_ids = {
        markers.get(f"proof_app_{label}")
        for label in (
            "radio-bounce-start",
            "radio-off",
            "radio-on",
            "background",
            "foreground",
        )
    }
    native_counts = {
        markers.get(f"proof_native_{label}")
        for label in ("radio-bounce-start", "radio-off", "radio-on")
    }
    app_id = next(iter(app_ids), None)
    native_count = next(iter(native_counts), None)
    try:
        no_fallback = int(
            markers["proof_no_validated_physical_fallback_inspections"]
        )
    except (KeyError, ValueError) as error:
        raise ValueError("Android underlay no-fallback proof is invalid") from error
    fresh_dns_host = markers.get("proof_fresh_dns_query", "")
    require(
        len(app_ids) == 1
        and isinstance(app_id, str)
        and app_id.isdigit()
        and int(app_id) > 0
        and len(native_counts) == 1
        and isinstance(native_count, str)
        and native_count.isdigit()
        and int(native_count) > 0
        and no_fallback >= 2
        and re.fullmatch(
            r"[0-9a-f]{64}",
            markers.get("proof_original_wifi_fingerprint", ""),
        )
        is not None
        and markers.get("proof_restored_wifi_fingerprint")
        == markers.get("proof_original_wifi_fingerprint")
        and UUID_SUBDOMAIN_RE.fullmatch(fresh_dns_host) is not None
        and markers.get("proof_wireguard_payload_label") == "radio-on",
        "Android underlay marker proof is incomplete",
    )
    return {
        "appIdentifierCount": len(app_ids),
        "freshDnsQueryHost": fresh_dns_host,
        "nativeTunnelIdentifierCount": len(native_counts),
        "noValidatedPhysicalFallbackEvidenceCount": no_fallback,
    }


def validate_fresh_dns_fixture_proof(
    path: pathlib.Path,
    platform: str,
    query_host: str,
) -> dict[str, Any]:
    proof = load_json(path)
    require(
        proof.get("schemaVersion") == 1
        and proof.get("platform") == platform
        and proof.get("gate") == "wifi-radio-off-on-recovery"
        and proof.get("queryHost") == query_host
        and isinstance(proof.get("exactQueryCount"), int)
        and proof["exactQueryCount"] > 0,
        f"{platform} fresh DNS query lacks exact fixture evidence",
    )
    return proof


def validate_ios_support(
    root: pathlib.Path,
    cases: list[str],
    mode: str,
) -> tuple[dict[str, Any], list[pathlib.Path]]:
    summaries: dict[str, Any] = {}
    paths: list[pathlib.Path] = []
    for case in cases:
        process_path = exactly_one(
            root,
            f"mobile-ios-release-network-{case}-*-processes.json",
            f"iOS {case} process",
        )
        marker_path = exactly_one(
            root,
            f"mobile-ios-release-network-{case}-*-runner-markers.log",
            f"iOS {case} UI marker",
        )
        process = load_json(process_path)
        app_pids = process.get("appProcessIdentifiers")
        tunnel_pids = process.get("packetTunnelProcessIdentifiers")
        required = set(process.get("requiredCheckpoints", []))
        observed = set(process.get("observedCheckpoints", []))
        require(
            process.get("passed") is True
            and process.get("activeSessionBeginSeen") is True
            and process.get("activeSessionEndSeen") is True
            and isinstance(app_pids, list)
            and len(app_pids) == 1
            and isinstance(tunnel_pids, list)
            and len(tunnel_pids) == 1
            and required.issubset(observed),
            f"iOS {case} process continuity receipt is incomplete",
        )
        markers = marker_path.read_text(encoding="utf-8").splitlines()
        require(
            f"NVPN_IOS_RELEASE_DNS_UI_PERSISTED={case}" in markers
            and f"NVPN_IOS_RELEASE_EXIT_CONNECTED={case}" in markers
            and "NVPN_IOS_RELEASE_DIRECT_BEFORE_PASSED=1" in markers
            and "NVPN_IOS_RELEASE_DIRECT_AFTER_PASSED=1" in markers
            and f"NVPN_IOS_RELEASE_NETWORK_PASSED={case}" in markers,
            f"iOS {case} lacks exact shipped-UI markers",
        )
        if case == "through-exit":
            direct_processes = process.get("directCheckpointProcesses")
            require(
                "NVPN_IOS_RELEASE_CONNECTED_DIRECT_PASSED=1" in markers
                and "NVPN_IOS_RELEASE_CONNECTED_DIRECT_RELAUNCH_PASSED=1"
                in markers
                and isinstance(direct_processes, dict)
                and all(
                    isinstance(direct_processes.get(checkpoint), dict)
                    and all(
                        isinstance(
                            direct_processes[checkpoint].get(identifier), int
                        )
                        and direct_processes[checkpoint][identifier] > 0
                        for identifier in (
                            "appProcessIdentifier",
                            "packetTunnelProcessIdentifier",
                        )
                    )
                    for checkpoint in (
                        "release_connected_direct_passed",
                        "release_connected_direct_relaunch_passed",
                    )
                ),
                "iOS through-exit case lacks connected Direct restoration",
            )
        summaries[case] = {
            "appProcessIdentifier": app_pids[0],
            "packetTunnelProcessIdentifier": tunnel_pids[0],
            "requiredCheckpointCount": len(required),
            "observedCheckpointCount": len(observed),
            "sampleCount": process.get("sampleCount"),
        }
        if case == "through-exit":
            summaries[case]["directCheckpointProcesses"] = direct_processes
        paths.extend((process_path, marker_path))

    if mode == "wireguard-dns":
        markers = exactly_one(
            root,
            "mobile-ios-release-network-automatic-profile-*-runner-markers.log",
            "iOS rapid start/stop",
        ).read_text(encoding="utf-8").splitlines()
        require(
            markers.count("NVPN_IOS_RELEASE_START_STOP_RECOVERED=1") == 1,
            "iOS rapid start/stop recovery marker is missing",
        )
        for cycle in range(1, 9):
            require(
                sum(
                    line.startswith(
                        f"NVPN_IOS_RELEASE_RAPID_STOP_REQUESTED_{cycle}_MS="
                    )
                    for line in markers
                )
                == 1
                and sum(
                    line.startswith(f"NVPN_IOS_RELEASE_RAPID_STOPPED_{cycle}_MS=")
                    for line in markers
                )
                == 1,
                f"iOS rapid start/stop cycle {cycle} is incomplete",
            )
        summaries["rapidStartStopCycles"] = 8
    else:
        process_path = exactly_one(
            root,
            "mobile-ios-release-network-automatic-profile-*-processes.json",
            "iOS underlay/lifecycle process",
        )
        runner_markers_path = exactly_one(
            root,
            "mobile-ios-release-network-automatic-profile-*-runner-markers.log",
            "iOS underlay/lifecycle runner markers",
        )
        host_markers_path = exactly_one(
            root,
            "mobile-ios-release-network-automatic-profile-*-host-markers.tsv",
            "iOS underlay/lifecycle host markers",
        )
        reverse_ping_path = exactly_one(
            root,
            "mobile-ios-release-network-automatic-profile-*-reverse-payload.log",
            "iOS underlay/lifecycle reverse payload",
        )
        process = load_json(process_path)
        required = set(process["requiredCheckpoints"])
        lifecycle_cycles = 0
        while (
            f"release_background_{lifecycle_cycles + 1}_requested" in required
            and f"release_foreground_{lifecycle_cycles + 1}_verified" in required
        ):
            lifecycle_cycles += 1
        require(lifecycle_cycles >= 1, "iOS lifecycle proof is missing")
        for cycle in range(1, lifecycle_cycles + 1):
            require(
                f"release_background_{cycle}_requested" in required
                and f"release_foreground_{cycle}_verified" in required,
                f"iOS lifecycle cycle {cycle} is missing",
            )
        for phase in (
            "requested",
            "outage",
            "recovery_requested",
            "underlay_validated",
            "payload_recovery",
            "verified",
        ):
            require(
                f"underlay_switch_1_{phase}" in required,
                f"iOS Wi-Fi radio bounce {phase} is missing",
            )
        continuity_path = exactly_one(
            root,
            "mobile-ios-release-network-automatic-profile-*-continuity.json",
            "iOS underlay continuity",
        )
        continuity, cycle = validate_underlay_continuity(
            continuity_path,
            "iOS",
            reverse_ping_path,
            host_markers_path,
        )
        runner_markers = runner_markers_path.read_text(encoding="utf-8").splitlines()
        fresh_dns_rows = [
            line.partition("=")[2]
            for line in runner_markers
            if line.startswith("NVPN_IOS_UNDERLAY_SWITCH_1_FRESH_DNS_QUERY=")
        ]
        require(
            runner_markers.count(
                "NVPN_IOS_UNDERLAY_SWITCH_1_NO_VALIDATED_PHYSICAL_FALLBACK=1"
            )
            == 1
            and runner_markers.count(
                "NVPN_IOS_UNDERLAY_SWITCH_1_ORIGINAL_WIFI_RESTORED=1"
            )
            == 1
            and len(fresh_dns_rows) == 1
            and UUID_SUBDOMAIN_RE.fullmatch(fresh_dns_rows[0]) is not None,
            "iOS underlay platform proof is incomplete",
        )
        fixture_dns_path = exactly_one(
            root,
            "mobile-ios-underlay-fresh-dns-fixture.json",
            "iOS underlay fresh DNS fixture",
        )
        fixture_dns = validate_fresh_dns_fixture_proof(
            fixture_dns_path,
            "iOS",
            fresh_dns_rows[0],
        )
        summaries["lifecycleCycles"] = lifecycle_cycles
        summaries["underlayCycles"] = [{
            **cycle,
            "freshDnsQueryHost": fresh_dns_rows[0],
            "freshDnsFixtureExactQueryCount": fixture_dns["exactQueryCount"],
            "gate": "wifi-radio-off-on-recovery",
            "noValidatedPhysicalFallbackEvidenceCount": 1,
            "originalWifiRestoredEvidenceCount": 1,
            "processIdentifierCounts": {
                "app": len(process["appProcessIdentifiers"]),
                "packetTunnel": len(process["packetTunnelProcessIdentifiers"]),
            },
        }]
        paths.extend(
            (
                continuity_path,
                fixture_dns_path,
                host_markers_path,
                reverse_ping_path,
            )
        )
    return summaries, paths


def validate_android_dns_ui_receipts(
    root: pathlib.Path,
    cases: list[str],
) -> list[pathlib.Path]:
    state_paths = list(root.glob("mobile-android-exit-dns-state-*.json"))
    expected_settings = {
        "automatic-profile": {
            "mode": "automatic",
            "provider": "cloudflare",
            "customUrl": "",
            "bootstrapIps": "",
            "throughServers": "",
        },
        "cloudflare-doh": {
            "mode": "encrypted",
            "provider": "cloudflare",
            "customUrl": "",
            "bootstrapIps": "",
            "throughServers": "",
        },
        "quad9-doh": {
            "mode": "encrypted",
            "provider": "quad9",
            "customUrl": "",
            "bootstrapIps": "",
            "throughServers": "",
        },
        "custom-doh": {
            "mode": "encrypted",
            "provider": "custom",
            "customUrl": "https://dns.google/dns-query",
            "bootstrapIps": "8.8.8.8",
            "throughServers": "",
        },
        "through-exit": {
            "mode": "through_exit",
            "provider": "cloudflare",
            "customUrl": "",
            "bootstrapIps": "",
            "throughServers": None,
        },
    }
    case_by_mode_provider = {
        (settings["mode"], settings["provider"]): case
        for case, settings in expected_settings.items()
    }
    requested = set(cases)
    require(
        len(requested) == len(cases)
        and requested.issubset(expected_settings),
        "Android DNS settings requested an unknown or duplicate case",
    )
    observed: dict[str, pathlib.Path] = {}
    for path in state_paths:
        state = load_json(path)
        require(
            state.get("receiptSchema") == 1
            and state.get("evidenceSource")
            == "shipped-ui-restart-readback"
            and state.get("uiRestartReadback") is True
            and state.get("releaseBlackbox") is True
            and state.get("wireguardExitEnabled") is True
            and state.get("internetSource") == "wireguard"
            and not state.get("error"),
            "Android DNS settings receipt is not shipped Release UI readback",
        )
        key = (
            str(state.get("exitDnsMode")),
            str(state.get("exitDnsDohProvider")),
        )
        case = case_by_mode_provider.get(key)
        require(
            case is not None and case not in observed,
            "Android DNS settings case is wrong or duplicated",
        )
        expected = expected_settings[case]
        require(
            state.get("exitDnsCustomDohUrl") == expected["customUrl"]
            and state.get("exitDnsCustomDohBootstrapIps")
            == expected["bootstrapIps"],
            f"Android {case} UI readback has the wrong custom DoH values",
        )
        through_servers = state.get("exitDnsThroughExitServers")
        if case == "through-exit":
            values = [
                value.strip()
                for value in str(through_servers).split(",")
                if value.strip()
            ]
            require(
                bool(values)
                and all(
                    ipaddress.ip_address(value).version in {4, 6}
                    for value in values
                ),
                "Android through-exit UI readback has no real DNS server",
            )
        else:
            require(
                through_servers == expected["throughServers"],
                f"Android {case} UI readback retained a forbidden through-exit server",
            )
        observed[case] = path
    require(
        requested.issubset(observed),
        "Android DNS settings receipts have the wrong requested policy values",
    )
    return [observed[case] for case in cases]


def validate_android_support(
    root: pathlib.Path,
    cases: list[str],
    mode: str,
) -> tuple[dict[str, Any], list[pathlib.Path]]:
    state_paths = validate_android_dns_ui_receipts(root, cases)
    paths = list(state_paths)
    app_probe_paths = list(root.glob("mobile-android-app-network-*.json"))
    for path in app_probe_paths:
        probe = load_json(path)
        require(
            isinstance(probe.get("resolvedAddresses"), list)
            and bool(probe["resolvedAddresses"])
            and isinstance(probe.get("statusCode"), int)
            and 200 <= probe["statusCode"] < 400
            and not any(
                probe.get(field)
                for field in ("error", "resolveError", "fetchError")
            ),
            f"Android app DNS/HTTPS receipt failed: {path.name}",
        )
    paths.extend(app_probe_paths)
    paths.extend(root.glob("mobile-android-tun-probe-summary-*.json"))
    summary: dict[str, Any] = {
        "dnsSettingsReceiptCount": len(state_paths),
    }
    if mode == "wireguard-dns":
        start_stop_path = exactly_one(
            root,
            "mobile-android-release-start-stop-*.tsv",
            "Android semantic start/stop",
        )
        start_stop_rows = [
            line.split("\t")
            for line in start_stop_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        require(
            len(start_stop_rows) == 1
            and all(
                len(row) == 3
                and row[0] == "semantic"
                and int(row[1]) > 0
                and int(row[2]) >= 0
                for row in start_stop_rows
            ),
            "Android semantic start/stop receipt is incomplete",
        )
        direct_labels = (
            "before-connect",
            "direct-while-connected",
            "after-disconnect",
            "start-stop-stable-direct",
            "start-stop-reconnect-cleanup",
        )
        direct_paths = []
        for label in direct_labels:
            ping_paths = [
                exactly_one(
                    root,
                    f"mobile-android-network-{label}-[0-9]*.txt",
                    f"Android {label} Direct DNS",
                )
            ]
            https_paths = [
                exactly_one(
                    root,
                    f"mobile-android-network-{label}-direct-https-*.txt",
                    f"Android {label} Direct HTTPS",
                )
            ]
            ping_prefix = f"mobile-android-network-{label}-"
            https_prefix = f"{ping_prefix}direct-https-"
            require(
                ping_paths[0].name.removeprefix(ping_prefix).removesuffix(".txt")
                == https_paths[0]
                .name.removeprefix(https_prefix)
                .removesuffix(".txt"),
                f"Android {label} Direct DNS/HTTPS receipt pair does not match",
            )
            require(
                all(
                    f"label={label}" in path.read_text(encoding="utf-8")
                    and "0% packet loss" in path.read_text(encoding="utf-8")
                    for path in ping_paths
                )
                and all(
                    re.search(
                        r"^directHttpsStatus=[23][0-9][0-9]$",
                        path.read_text(encoding="utf-8"),
                        re.MULTILINE,
                    )
                    for path in https_paths
                ),
                f"Android {label} Direct DNS/HTTPS receipt is incomplete",
            )
            direct_paths.extend((*ping_paths, *https_paths))
        reconnect_path = exactly_one(
            root,
            "mobile-android-network-start-stop-full-reconnect-*.txt",
            "Android start/stop reconnect",
        )
        reconnect_text = reconnect_path.read_text(encoding="utf-8")
        require(
            "capturedHttpStatus=200" in reconnect_text
            and re.search(
                r"capturedHttpsStatus=[23][0-9][0-9]",
                reconnect_text,
            )
            and "exitSourceIp=" in reconnect_text,
            "Android start/stop reconnect lacks real exit packet evidence",
        )
        direct_paths.append(reconnect_path)
        summary["startStopCycles"] = 2
        summary["directBeforeConnectedAfter"] = True
        paths.extend((start_stop_path, *direct_paths))
    if mode == "underlay-lifecycle":
        underlay_path = exactly_one(
            root,
            "mobile-android-underlay-*-summary.json",
            "Android underlay continuity",
        )
        markers_path = exactly_one(
            root,
            "mobile-android-underlay-*-markers.tsv",
            "Android underlay markers",
        )
        reverse_ping_path = exactly_one(
            root,
            "mobile-android-underlay-*-continuity.log",
            "Android underlay reverse payload",
        )
        dns_path = exactly_one(
            root,
            "mobile-android-radio-bounce-dns-*.log",
            "Android underlay fresh DNS",
        )
        udp_path = exactly_one(
            root,
            "mobile-android-radio-bounce-udp-*.log",
            "Android underlay WireGuard UDP",
        )
        underlay, measured_cycle = validate_underlay_continuity(
            underlay_path,
            "Android",
            reverse_ping_path,
            markers_path,
        )
        marker_proof = validate_android_underlay_markers(markers_path)
        fresh_dns_host = marker_proof["freshDnsQueryHost"]
        fixture_dns_path = exactly_one(
            root,
            "mobile-android-underlay-fresh-dns-fixture.json",
            "Android underlay fresh DNS fixture",
        )
        fixture_dns = validate_fresh_dns_fixture_proof(
            fixture_dns_path,
            "Android",
            fresh_dns_host,
        )
        dns_text = dns_path.read_text(encoding="utf-8")
        udp_text = udp_path.read_text(encoding="utf-8")
        dns_match = re.search(
            r"expectedAddress=(\S+) answers=(\S+)",
            dns_text,
        )
        require(
            fresh_dns_host in dns_text
            and dns_match is not None
            and dns_match.group(1) in dns_match.group(2).split(",")
            and "udpEchoLabel=radio-on " in udp_text,
            "Android underlay raw DNS/WireGuard proof is incomplete",
        )
        lifecycle_ledger = exactly_one(
            root,
            "mobile-android-release-lifecycle-*.tsv",
            "Android lifecycle process",
        )
        lifecycle_rows = [
            line.split("\t")
            for line in lifecycle_ledger.read_text(encoding="utf-8").splitlines()
            if line
        ]
        lifecycle_cycles = len(lifecycle_rows)
        require(
            lifecycle_cycles >= 1
            and [int(row[0]) for row in lifecycle_rows]
            == list(range(1, lifecycle_cycles + 1))
            and len({row[1] for row in lifecycle_rows}) == 1
            and len({row[2] for row in lifecycle_rows}) == 1,
            "Android lifecycle lacks contiguous same-process/tunnel receipts",
        )
        lifecycle_paths = []
        for lifecycle_cycle in range(1, lifecycle_cycles + 1):
            for phase in ("background", "foreground"):
                path = exactly_one(
                    root,
                    f"mobile-android-network-release-{phase}-cycle-{lifecycle_cycle}-*.txt",
                    f"Android release {phase} cycle {lifecycle_cycle}",
                )
                text = path.read_text(encoding="utf-8")
                require(
                    "capturedHttpStatus=200" in text
                    and re.search(r"capturedHttpsStatus=[23][0-9][0-9]", text)
                    and "exitSourceIp=" in text,
                    f"Android release {phase} cycle {lifecycle_cycle} lacks DNS/HTTP/HTTPS packet evidence",
                )
                lifecycle_paths.append(path)
        summary["lifecycleCycles"] = lifecycle_cycles
        summary["underlayCycles"] = [{
            **measured_cycle,
            "freshDnsQueryHost": fresh_dns_host,
            "freshDnsFixtureExactQueryCount": fixture_dns["exactQueryCount"],
            "gate": "wifi-radio-off-on-recovery",
            "noValidatedPhysicalFallbackEvidenceCount": marker_proof[
                "noValidatedPhysicalFallbackEvidenceCount"
            ],
            "originalWifiRestoredEvidenceCount": 1,
            "processIdentifierCounts": {
                "app": marker_proof["appIdentifierCount"],
                "nativeTunnel": marker_proof["nativeTunnelIdentifierCount"],
            },
        }]
        summary["postForegroundDnsHttpsAndTunnelCycles"] = lifecycle_cycles
        paths.extend(
            (
                underlay_path,
                markers_path,
                reverse_ping_path,
                fixture_dns_path,
                dns_path,
                udp_path,
                lifecycle_ledger,
                *lifecycle_paths,
            )
        )
    return summary, paths


def validate_mobile_support(
    root: pathlib.Path,
    platform: str,
    cases: list[str],
    mode: str,
    include_underlay_lifecycle: bool,
) -> tuple[dict[str, Any], list[pathlib.Path]]:
    validator = (
        validate_ios_support if platform == "ios" else validate_android_support
    )
    support, paths = validator(root, cases, mode)
    if not include_underlay_lifecycle:
        return support, paths
    require(
        mode == "wireguard-dns" and cases == list(DNS_CASES),
        "combined mobile evidence requires the canonical five DNS cases",
    )
    underlay, underlay_paths = validator(
        root,
        ["automatic-profile"],
        "underlay-lifecycle",
    )
    required = ["lifecycleCycles", "underlayCycles"]
    if platform == "android":
        required.append("postForegroundDnsHttpsAndTunnelCycles")
    require(
        all(key in underlay for key in required),
        f"{platform} combined evidence lacks underlay/lifecycle support",
    )
    support.update({key: underlay[key] for key in required})
    return support, paths + underlay_paths


def build_mobile(args: argparse.Namespace) -> None:
    platform = args.platform
    mode = args.mode
    cases = list(DNS_CASES) if mode == "wireguard-dns" else ["automatic-profile"]
    artifact_path = pathlib.Path(args.artifact_receipt).resolve()
    root = pathlib.Path(args.artifact_dir).resolve()
    artifact = load_json(artifact_path)
    identity = artifact_identity(platform, artifact)
    counter_ledger = pathlib.Path(args.counter_ledger).resolve()
    require(
        counter_ledger.parent == root,
        "mobile counter ledger is not preserved with its artifact evidence",
    )
    counter_cases = parse_counter_ledger(counter_ledger, cases, platform)
    support, paths = validate_mobile_support(
        root,
        platform,
        cases,
        mode,
        args.include_underlay_lifecycle,
    )
    paths.append(counter_ledger)
    receipt = {
        "receiptSchema": 1,
        "artifactType": f"physical {platform} Release {mode} gate",
        "platform": platform,
        "mode": mode,
        "appGitSha": artifact["appGitSha"],
        "appGitTree": artifact["appGitTree"],
        "fipsGitSha": artifact["fipsGitSha"],
        "fipsGitTree": artifact["fipsGitTree"],
        "artifactReceiptSha256": sha256(artifact_path),
        "artifactIdentity": identity,
        "dnsCases": counter_cases,
        "support": support,
        "evidenceFiles": evidence_hashes(root, paths),
    }
    if args.include_underlay_lifecycle:
        receipt["coveredModes"] = ["wireguard-dns", "underlay-lifecycle"]
    atomic_json(pathlib.Path(args.output), receipt)


def key_values(path: pathlib.Path) -> dict[str, str]:
    require(path.is_file() and not path.is_symlink(), f"missing receipt: {path}")
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            require(key not in result, f"duplicate {key} in {path.name}")
            result[key] = value
    return result


def validate_desktop_handoff(receipt: dict[str, Any], label: str) -> dict[str, int]:
    recovery = receipt.get("recovery_milliseconds")
    before = receipt.get("payload_successes_before")
    after = receipt.get("payload_successes_after")
    wg_before = receipt.get("wireguard_payload_successes_before")
    wg_after = receipt.get("wireguard_payload_successes_after")
    rebind_before = receipt.get("rebind_receipts_before")
    rebind_after = receipt.get("rebind_receipts_after")
    require(
        isinstance(recovery, int)
        and 0 <= recovery <= 4_000
        and isinstance(before, int)
        and isinstance(after, int)
        and after > before
        and isinstance(wg_before, int)
        and isinstance(wg_after, int)
        and wg_after > wg_before
        and isinstance(rebind_before, int)
        and rebind_after == rebind_before + 1,
        f"{label} handoff receipt is incomplete",
    )
    return {
        "recoveryMilliseconds": recovery,
        "payloadDelta": after - before,
        "wireGuardPayloadDelta": wg_after - wg_before,
        "rebindDelta": rebind_after - rebind_before,
    }


def desktop_dns_matrix(path: pathlib.Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing receipt: {path}")
    cases: dict[str, Any] = {}
    current = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key == "case":
            current = value
            cases[current] = {}
        elif current and key.startswith(("before_", "after_")):
            cases[current][key] = int(value)
    require(set(cases) == set(DESKTOP_DNS_COUNTERS), "desktop DNS matrix lacks the exact five policies")
    for label, counters in cases.items():
        expected_counter = DESKTOP_DNS_COUNTERS[label]
        expected_keys = {
            f"{phase}_{counter}"
            for phase in ("before", "after")
            for counter in DESKTOP_DNS_COUNTER_NAMES
        }
        require(
            set(counters) == expected_keys,
            f"desktop DNS matrix {label} has an incomplete resolver counter set",
        )
        for counter in DESKTOP_DNS_COUNTER_NAMES:
            before = counters[f"before_{counter}"]
            after = counters[f"after_{counter}"]
            require(
                (
                    after > before
                    if counter == expected_counter
                    else after == before
                ),
                f"desktop DNS matrix {label} used the wrong resolver counter",
            )
    return cases


def validate_desktop_dns_ui_receipts(
    root: pathlib.Path,
    platform: str,
    app_sha: str,
    app_tree: str,
) -> tuple[
    dict[str, Any],
    dict[str, str],
    tuple[str, str],
    str | None,
]:
    require(
        root.is_dir() and not root.is_symlink(),
        f"{platform} desktop DNS UI evidence directory is missing",
    )
    all_receipt_paths = list(root.glob("*.json"))
    expected_receipt_names = {
        f"{case}.json" for case in DESKTOP_DNS_UI_SETTINGS
    }
    allowed_sidecar_names = (
        {"paid-exit-seller.json"}
        if platform == "macos"
        else set()
    )
    observed_receipt_names = {path.name for path in all_receipt_paths}
    require(
        expected_receipt_names <= observed_receipt_names
        and observed_receipt_names
        <= expected_receipt_names | allowed_sidecar_names,
        f"{platform} desktop DNS UI receipts do not cover exactly five policies",
    )
    for path in all_receipt_paths:
        if path.name in allowed_sidecar_names:
            load_json(path)
    receipt_paths = [
        root / name for name in sorted(expected_receipt_names)
    ]
    observed: dict[str, Any] = {}
    evidence: dict[str, str] = {}
    artifact_identity: tuple[str, str] | None = None
    receipts = {path: load_json(path) for path in receipt_paths}
    permitted_source = (app_sha, app_tree)
    reused_artifact_receipt_hash: str | None = None
    receipt_sources = {
        (receipt.get("appGitSha"), receipt.get("appGitTree"))
        for receipt in receipts.values()
    }
    if receipt_sources != {permitted_source}:
        require(
            platform == "macos" and len(receipt_sources) == 1,
            f"{platform} desktop DNS UI receipts are not source-bound",
        )
        receipt_source = next(iter(receipt_sources))
        artifact_path = root.parent / "app-artifact.json"
        driver_path = root.parent / "driver-receipt.json"
        require(
            artifact_path.is_file()
            and not artifact_path.is_symlink()
            and driver_path.is_file()
            and not driver_path.is_symlink(),
            "macos reused DNS UI artifact provenance is missing",
        )
        artifact = load_json(artifact_path)
        driver = load_json(driver_path)
        proof = artifact.get("componentInputProof")
        artifact_receipt_hash = sha256(artifact_path)
        expected_proof_keys = {
            "policy",
            "platform",
            "receipt_app_git_sha",
            "receipt_app_git_tree",
            "candidate_app_git_sha",
            "candidate_app_git_tree",
            "changed_paths_sha256",
        }
        require(
            artifact.get("receiptSchema") == 1
            and artifact.get("appGitSha") == receipt_source[0]
            and artifact.get("appGitTree") == receipt_source[1]
            and isinstance(proof, dict)
            and set(proof) == expected_proof_keys
            and proof.get("policy") == "unchanged-platform-product-inputs-v1"
            and proof.get("platform") == "macos"
            and proof.get("receipt_app_git_sha") == receipt_source[0]
            and proof.get("receipt_app_git_tree") == receipt_source[1]
            and proof.get("candidate_app_git_sha") == app_sha
            and proof.get("candidate_app_git_tree") == app_tree
            and re.fullmatch(
                r"[0-9a-f]{64}", str(proof.get("changed_paths_sha256", ""))
            )
            is not None
            and re.fullmatch(
                r"[0-9a-f]{64}",
                str(artifact.get("componentInputProofSha256", "")),
            )
            is not None
            and driver.get("receiptSchema") == 1
            and driver.get("appGitSha") == receipt_source[0]
            and driver.get("appGitTree") == receipt_source[1]
            and driver.get("harnessGitSha") == app_sha
            and driver.get("harnessGitTree") == app_tree
            and driver.get("appArtifactReceiptSha256") == artifact_receipt_hash
            and all(
                receipt.get("appArtifactReceiptSha256") == artifact_receipt_hash
                and receipt.get("appExecutableSha256")
                == artifact.get("appExecutableSha256")
                and receipt.get("cliExecutableSha256")
                == artifact.get("cliExecutableSha256")
                for receipt in receipts.values()
            ),
            "macos reused DNS UI artifact provenance is invalid",
        )
        permitted_source = receipt_source
        reused_artifact_receipt_hash = artifact_receipt_hash
    for path in receipt_paths:
        receipt = receipts[path]
        case = receipt.get("case")
        require(
            receipt.get("receiptSchema") == 1
            and receipt.get("platform") == platform
            and case in DESKTOP_DNS_UI_SETTINGS
            and case not in observed
            and receipt.get("evidenceSource")
            == "shipped-ui-restart-readback"
            and receipt.get("savedViaShippedUi") is True
            and receipt.get("uiRestartReadback") is True
            and receipt.get("releaseBlackbox") is True
            and receipt.get("publicUiOnly") is True
            and receipt.get("privateStateRead") is False
            and receipt.get("appGitSha") == permitted_source[0]
            and receipt.get("appGitTree") == permitted_source[1],
            f"{platform} {case} DNS receipt is not exact shipped-UI readback",
        )
        app_hash = require_hash(
            receipt.get("appExecutableSha256"),
            f"{platform} {case} DNS UI app SHA-256",
        )
        cli_hash = require_hash(
            receipt.get("cliExecutableSha256"),
            f"{platform} {case} DNS UI CLI SHA-256",
        )
        identity = (app_hash, cli_hash)
        if artifact_identity is None:
            artifact_identity = identity
        require(
            artifact_identity == identity,
            f"{platform} DNS UI cases did not use one exact app/CLI pair",
        )
        expected = DESKTOP_DNS_UI_SETTINGS[str(case)]
        actual = (
            receipt.get("exitDnsMode"),
            receipt.get("exitDnsDohProvider"),
            receipt.get("exitDnsCustomDohUrl"),
            receipt.get("exitDnsCustomDohBootstrapIps"),
            receipt.get("exitDnsThroughExitServers"),
        )
        provider_matches = actual[1] == expected[1] or (
            platform == "macos"
            and case in {"automatic", "through-exit"}
            and actual[1] == ""
        )
        if case == "through-exit":
            servers = [
                item.strip()
                for item in str(actual[4]).split(",")
                if item.strip()
            ]
            require(
                actual[0] == expected[0]
                and provider_matches
                and actual[2:4] == expected[2:4]
                and bool(servers)
                and all(ipaddress.ip_address(item).version in {4, 6} for item in servers),
                f"{platform} through-exit DNS UI readback is invalid",
            )
        else:
            require(
                actual[0] == expected[0]
                and provider_matches
                and actual[2:] == expected[2:],
                f"{platform} {case} DNS UI readback has the wrong settings",
            )
        observed[str(case)] = {
            "mode": actual[0],
            "provider": actual[1],
            "appExecutableSha256": app_hash,
            "cliExecutableSha256": cli_hash,
        }
        evidence[path.name] = sha256(path)
    require(
        set(observed) == set(DESKTOP_DNS_UI_SETTINGS),
        f"{platform} desktop DNS UI receipts have the wrong policies",
    )
    return (
        {case: observed[case] for case in DESKTOP_DNS_UI_SETTINGS},
        dict(sorted(evidence.items())),
        permitted_source,
        reused_artifact_receipt_hash,
    )


def build_desktop(args: argparse.Namespace) -> None:
    platform = args.platform
    root = pathlib.Path(args.artifact_dir).resolve()
    require(root.is_dir() and not root.is_symlink(), "desktop evidence directory is missing")
    app_sha = require_hash(args.app_git_sha, "desktop application commit", 40)
    app_tree = require_hash(args.app_git_tree, "desktop application tree", 40)
    dns_ui_root = pathlib.Path(args.dns_ui_dir).resolve()
    (
        dns_ui_cases,
        dns_ui_evidence,
        dns_ui_source,
        dns_ui_artifact_receipt_hash,
    ) = validate_desktop_dns_ui_receipts(
        dns_ui_root,
        platform,
        app_sha,
        app_tree,
    )
    paths: list[pathlib.Path] = []
    summary: dict[str, Any] = {
        "dnsUiCases": dns_ui_cases,
        "dnsUiPolicyCount": len(dns_ui_cases),
    }

    if platform in {"linux", "windows"}:
        source_path = root / "source-provenance.txt"
        source = key_values(source_path)
        require(
            source.get("nvpn_base_commit") == app_sha
            and source.get("nvpn_tree") == app_tree,
            f"{platform} desktop network receipt is not source-bound",
        )
        tested_path = root / "tested-artifact.json"
        tested = load_json(tested_path)
        tested_cli_sha = require_hash(
            tested.get("cliSha256"),
            f"{platform} tested CLI SHA-256",
        )
        tested_cli_size = tested.get("cliSize")
        require(
            isinstance(tested_cli_size, int)
            and not isinstance(tested_cli_size, bool)
            and tested_cli_size > 0,
            f"{platform} tested CLI size is invalid",
        )
        summary["testedCliSha256"] = tested_cli_sha
        summary["testedCliSize"] = tested_cli_size
        require(
            all(
                case["cliExecutableSha256"] == tested_cli_sha
                for case in dns_ui_cases.values()
            ),
            f"{platform} DNS UI did not use the exact network-tested CLI",
        )
        paths.append(tested_path)
        if platform == "linux":
            tested_receipt_path = root / "tested-artifact-receipt.json"
            tested_receipt = load_json(tested_receipt_path)
            cli = tested_receipt.get("artifacts", {}).get("cli", {})
            mode = tested_receipt.get("builderMode")
            builder_valid = (
                mode == "local-docker"
                and tested_receipt.get("builtOnHostMac") is True
                and tested_receipt.get("builtOnRemoteVm") is False
                and tested_receipt.get("builderHostOs") == "Darwin"
                and tested_receipt.get("builderHostArchitecture")
                in {"arm64", "x86_64"}
            ) or (
                mode == "remote-native"
                and tested_receipt.get("builtOnHostMac") is False
                and tested_receipt.get("builtOnRemoteVm") is True
                and tested_receipt.get("builderHostOs") == "Linux"
                and tested_receipt.get("builderHostArchitecture") == "x86_64"
            )
            require(
                tested_receipt.get("schema") == 2
                and builder_valid
                and re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    tested_receipt.get("containerImageId", ""),
                )
                is not None
                and re.fullmatch(
                    r"[0-9a-f]{64}",
                    tested_receipt.get("dockerfileSha256", ""),
                )
                is not None
                and re.fullmatch(
                    r"[0-9a-f]{64}",
                    tested_receipt.get("containerPayloadSha256", ""),
                )
                is not None
                and tested_receipt.get("appGitSha") == app_sha
                and tested_receipt.get("appGitTree") == app_tree
                and cli.get("sha256") == tested_cli_sha
                and cli.get("size") == tested_cli_size
                and tested.get("artifactReceiptSha256")
                == sha256(tested_receipt_path),
                "Linux tested CLI is not bound to its exact artifact receipt",
            )
            summary["artifactReceiptSha256"] = sha256(tested_receipt_path)
            paths.append(tested_receipt_path)
        secondary_path = root / "secondary-receipt.json"
        primary_path = root / "primary-receipt.json"
        summary["handoffs"] = {
            "primaryToSecondary": validate_desktop_handoff(
                load_json(secondary_path),
                f"{platform} primary-to-secondary",
            ),
            "secondaryToPrimary": validate_desktop_handoff(
                load_json(primary_path),
                f"{platform} secondary-to-primary",
            ),
        }
        dns_path = root / "dns-matrix.txt"
        summary["dnsCases"] = desktop_dns_matrix(dns_path)
        summary["dnsPolicyCount"] = 5
        direct_path = root / "direct-receipt.json"
        direct = load_json(direct_path)
        common_direct = (
            direct.get("wireguard_interface_removed") is True
            and direct.get("wireguard_endpoint_route_removed") is True
            and direct.get("verified_https") is True
        )
        if platform == "linux":
            require(
                common_direct
                and direct.get("wireguard_policy_rule_removed") is True
                and direct.get("wireguard_policy_table_empty") is True,
                "Linux Direct restoration receipt is incomplete",
            )
            crash_path = root / "crash-repair-receipt.json"
            crash = load_json(crash_path)
            require(
                crash.get("sigkill_exit_code") == 137
                and crash.get("fresh_wireguard_handshake") is True
                and crash.get("through_exit_dns_before_crash") is True
                and crash.get("verified_https_before_crash") is True
                and crash.get("cleanup_journal_survived_sigkill") is True
                and crash.get("startup_repair_without_explicit_command") is True
                and crash.get("cleanup_journal_removed") is True
                and crash.get("physical_default_restored") is True
                and crash.get("public_dns_restored") is True
                and crash.get("verified_https_after_restart") is True
                and crash.get("restart_daemon_count") == 1
                and 0 <= crash.get("restart_repair_milliseconds", 4_001) <= 4_000,
                "Linux SIGKILL/restart repair receipt is incomplete",
            )
            summary["crashRepairMilliseconds"] = crash[
                "restart_repair_milliseconds"
            ]
            summary["singletonAfterCrashRecovery"] = True
        else:
            require(
                common_direct
                and direct.get("wireguard_service_removed") is True
                and direct.get("wireguard_source_secrets_removed") is True,
                "Windows Direct restoration receipt is incomplete",
            )
            crash_path = root / "crash-recovery-receipt.json"
            crash = load_json(crash_path)
            crash_recovery = crash.get("startup_recovery_milliseconds")
            crash_true_fields = (
                "exact_candidate_binary_restarted",
                "cleanup_journal_present_before_crash",
                "cleanup_journal_survived_forced_termination",
                "paid_exit_cleanup_ownership_removed_after_restart",
                "crash_cleanup_journal_replaced_after_restart",
                "native_wireguard_owner_directory_layout",
                "native_wireguard_owned_files_survived_forced_termination",
                "native_wireguard_owned_files_removed_after_restart",
                "selected_direct_while_daemon_stopped",
                "wireguard_exit_state_remained_installed_after_crash",
                "dns_policy_remained_installed_after_crash",
                "public_dns",
                "verified_https",
            )
            require(
                isinstance(crash.get("crashed_daemon_pid"), int)
                and crash["crashed_daemon_pid"] > 0
                and isinstance(crash.get("replacement_daemon_pid"), int)
                and crash["replacement_daemon_pid"] > 0
                and crash["replacement_daemon_pid"]
                != crash["crashed_daemon_pid"]
                and crash.get("daemon_process_count") == 1
                and isinstance(crash_recovery, int)
                and 0 <= crash_recovery <= 30_000
                and isinstance(
                    crash.get("active_direct_cleanup_journal_present"), bool
                )
                and isinstance(
                    crash.get("active_direct_cleanup_route_count"), int
                )
                and crash["active_direct_cleanup_route_count"] >= 0
                and all(crash.get(field) is True for field in crash_true_fields),
                "Windows crash/owner-file repair receipt is incomplete",
            )
            summary["crashRepairMilliseconds"] = crash_recovery
            summary["nativeWireGuardOwnerFilesRepaired"] = True
            summary["singletonAfterCrashRecovery"] = True
        summary["directRestored"] = True
        paths.extend(
            (
                source_path,
                secondary_path,
                primary_path,
                dns_path,
                direct_path,
                crash_path,
            )
        )
    else:
        artifact_path = pathlib.Path(args.artifact_receipt).resolve()
        artifact = load_json(artifact_path)
        require(
            artifact.get("receiptSchema") == 1
            and artifact.get("appGitSha") == dns_ui_source[0]
            and artifact.get("appGitTree") == dns_ui_source[1]
            and artifact.get("companySigningVerified") is True,
            "macOS desktop network artifact receipt is not exact",
        )
        if dns_ui_artifact_receipt_hash is not None:
            require(
                sha256(artifact_path) == dns_ui_artifact_receipt_hash,
                "macOS desktop network artifact receipt differs from DNS UI provenance",
            )
        require(
            all(
                case["appExecutableSha256"]
                == artifact.get("appExecutableSha256")
                and case["cliExecutableSha256"]
                == artifact.get("cliExecutableSha256")
                for case in dns_ui_cases.values()
            ),
            "macOS DNS UI did not use the exact gated app/CLI package",
        )
        dns_path = root / "fixture-dns-counters.tsv"
        rows = [
            line.split("\t")
            for line in dns_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        require(
            len(rows) == 5
            and {row[0] for row in rows}
            == {
                "automatic-profile",
                "cloudflare-doh",
                "quad9-doh",
                "custom-doh",
                "through-exit",
            },
            "macOS DNS matrix lacks the exact five policies",
        )
        for row in rows:
            dns_values = [int(value) for value in row[5:]]
            before_dns, after_dns = split_dns_counters(dns_values, row[0])
            require(
                len(row) == 19
                and int(row[2]) > int(row[1])
                and int(row[4]) > int(row[3]),
                f"macOS {row[0]} lacks real WireGuard/forward counters",
            )
            validate_dns_path_counters(
                row[0],
                DNS_CASES[row[0]],
                before_dns,
                after_dns,
            )
        underlay_path = root / "underlay.txt"
        underlay = key_values(underlay_path)
        first = int(underlay.get("primary_to_secondary_ms", "4001"))
        second = int(underlay.get("secondary_to_primary_ms", "4001"))
        require(
            0 <= first <= 4_000
            and 0 <= second <= 4_000
            and underlay.get("connected_peer_count") == "0",
            "macOS dual-underlay receipt is incomplete",
        )
        crash_path = root / "crash-restart.txt"
        crash = key_values(crash_path)
        require(
            crash.get("startup_persist_path_completed") == "true"
            and crash.get("sigkill_tunnel_routes_absent") == "true"
            and crash.get("sigkill_secure_dns_ownership_seen") == "true"
            and crash.get("old_pid") != crash.get("new_pid")
            and 0 <= int(crash.get("restart_payload_ms", "4001")) <= 4_000
            and crash.get("connected_peer_count") == "0",
            "macOS SIGKILL/restart receipt is incomplete",
        )
        direct_path = root / "direct.txt"
        direct = key_values(direct_path)
        require(
            direct.get("resolver_state_absent") == "true"
            and bool(direct.get("direct_interface"))
            and bool(direct.get("direct_gateway"))
            and bool(direct.get("direct_source_ip")),
            "macOS Direct restoration receipt is incomplete",
        )
        summary.update(
            {
                "artifactReceiptSha256": sha256(artifact_path),
                "dnsPolicyCount": len(rows),
                "handoffRecoveryMilliseconds": [first, second],
                "crashRestartPayloadMilliseconds": int(
                    crash["restart_payload_ms"]
                ),
                "directRestored": True,
                "singletonAfterCrashRecovery": True,
            }
        )
        paths.extend((dns_path, underlay_path, crash_path, direct_path))

    atomic_json(
        pathlib.Path(args.output),
        {
            "receiptSchema": 1,
            "artifactType": f"{platform} Release desktop network gate",
            "platform": platform,
            "appGitSha": app_sha,
            "appGitTree": app_tree,
            "summary": summary,
            "evidenceFiles": evidence_hashes(root, paths),
            "desktopDnsUiEvidenceFiles": dns_ui_evidence,
        },
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    mobile = commands.add_parser("mobile")
    mobile.add_argument("--platform", choices=("android", "ios"), required=True)
    mobile.add_argument(
        "--mode",
        choices=("wireguard-dns", "underlay-lifecycle"),
        required=True,
    )
    mobile.add_argument("--artifact-receipt", required=True)
    mobile.add_argument("--artifact-dir", required=True)
    mobile.add_argument("--counter-ledger", required=True)
    mobile.add_argument("--output", required=True)
    mobile.add_argument("--include-underlay-lifecycle", action="store_true")
    desktop = commands.add_parser("desktop")
    desktop.add_argument(
        "--platform",
        choices=("linux", "macos", "windows"),
        required=True,
    )
    desktop.add_argument("--artifact-dir", required=True)
    desktop.add_argument("--artifact-receipt")
    desktop.add_argument("--dns-ui-dir", required=True)
    desktop.add_argument("--app-git-sha", required=True)
    desktop.add_argument("--app-git-tree", required=True)
    desktop.add_argument("--output", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "mobile":
            build_mobile(args)
        elif args.command == "desktop":
            build_desktop(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"release network evidence failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
