#!/usr/bin/env python3
"""Rewrite copied iOS UI-test plans onto immutable absolute products."""

from __future__ import annotations

import argparse
import os
import pathlib
import plistlib
import re
import sys
import tempfile
from typing import Any


APP_NAME = "Nostr VPN.app"
APP_EXECUTABLE = "Nostr VPN"
TUNNEL_NAME = "Nostr VPN Tunnel.appex"
TUNNEL_EXECUTABLE = "Nostr VPN Tunnel"
UI_TEST_RUNNER = "NostrVpnIosUITests-Runner.app"
UI_TEST_BUNDLE = "NostrVpnIosUITests.xctest"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_plist(path: pathlib.Path) -> dict[str, Any]:
    require(path.is_file(), f"property list is missing: {path}")
    value = plistlib.load(path.open("rb"))
    require(
        isinstance(value, dict),
        f"property list root is not a dictionary: {path}",
    )
    return value


def atomic_plist(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            plistlib.dump(value, handle, sort_keys=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def parse_assignment(value: str) -> tuple[str, str]:
    name, separator, setting = value.partition("=")
    require(
        bool(separator) and re.fullmatch(r"[A-Z][A-Z0-9_]*", name) is not None,
        f"invalid xctestrun environment assignment: {value!r}",
    )
    return name, setting


def environment_assignments(args: argparse.Namespace) -> list[tuple[str, str]]:
    values = list(args.environment)
    if args.environment_stdin0:
        payload = sys.stdin.buffer.read()
        require(
            not payload or payload.endswith(b"\0"),
            "xctestrun environment stdin is not NUL terminated",
        )
        for value in payload.split(b"\0"):
            if value:
                values.append(value.decode("utf-8"))
    return [parse_assignment(value) for value in values]


def xctestrun_targets(payload: dict[str, Any]) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    legacy = payload.get("NostrVpnIosUITests")
    if isinstance(legacy, dict):
        targets.append(legacy)
    configurations = payload.get("TestConfigurations")
    if isinstance(configurations, list):
        for configuration in configurations:
            if not isinstance(configuration, dict):
                continue
            configured_targets = configuration.get("TestTargets")
            if not isinstance(configured_targets, list):
                continue
            for target in configured_targets:
                if not isinstance(target, dict):
                    continue
                if (
                    target.get("BlueprintName") == "NostrVpnIosUITests"
                    or target.get("ProductModuleName")
                    == "NostrVpnIosUITests"
                ):
                    targets.append(target)
    unique: list[dict[str, Any]] = []
    seen: set[int] = set()
    for target in targets:
        identity = id(target)
        if identity not in seen:
            unique.append(target)
            seen.add(identity)
    require(unique, "xctestrun lacks NostrVpnIosUITests")
    return unique


def rewrite_coverage_products(
    payload: dict[str, Any],
    *,
    app: pathlib.Path,
    tunnel: pathlib.Path,
    test_bundle: pathlib.Path,
) -> None:
    coverage = payload.get("CodeCoverageBuildableInfos")
    if coverage is None:
        return
    require(
        isinstance(coverage, list),
        "xctestrun code-coverage products are malformed",
    )
    replacements = {
        APP_NAME: app / APP_EXECUTABLE,
        TUNNEL_NAME: tunnel / TUNNEL_EXECUTABLE,
        UI_TEST_BUNDLE: test_bundle / "NostrVpnIosUITests",
    }
    for item in coverage:
        require(
            isinstance(item, dict),
            "xctestrun code-coverage product is malformed",
        )
        paths = item.get("ProductPaths")
        if not isinstance(paths, list) or not paths:
            continue
        name = item.get("Name")
        replacement = replacements.get(name)
        if replacement is None:
            require(
                not any(
                    isinstance(path, str)
                    and (
                        "__TESTROOT__" in path
                        or "__TESTHOST__" in path
                    )
                    for path in paths
                ),
                f"unknown relocatable coverage product: {name!r}",
            )
            continue
        require(
            replacement.is_file(),
            f"xctestrun coverage executable is missing: {replacement}",
        )
        item["ProductPaths"] = [str(replacement)]


def reject_relocatable_paths(value: Any, location: str = "root") -> None:
    if isinstance(value, dict):
        for name, child in value.items():
            reject_relocatable_paths(child, f"{location}.{name}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_relocatable_paths(child, f"{location}[{index}]")
    elif isinstance(value, str):
        for placeholder in (
            "__DERIVEDDATA__",
            "__TESTHOST__",
            "__TESTROOT__",
        ):
            require(
                placeholder not in value,
                f"rewritten xctestrun retains {placeholder} at {location}",
            )


def resolve_relocatable_paths(
    value: Any,
    *,
    derived_data: pathlib.Path,
    runner: pathlib.Path,
    products: pathlib.Path,
) -> Any:
    if isinstance(value, dict):
        return {
            name: resolve_relocatable_paths(
                child,
                derived_data=derived_data,
                runner=runner,
                products=products,
            )
            for name, child in value.items()
        }
    if isinstance(value, list):
        return [
            resolve_relocatable_paths(
                child,
                derived_data=derived_data,
                runner=runner,
                products=products,
            )
            for child in value
        ]
    if isinstance(value, str):
        return (
            value.replace("__DERIVEDDATA__", str(derived_data))
            .replace("__TESTHOST__", str(runner))
            .replace("__TESTROOT__", str(products))
        )
    return value


def rewrite_xctestrun(args: argparse.Namespace) -> None:
    source = pathlib.Path(args.source).resolve()
    output = pathlib.Path(args.output)
    products = pathlib.Path(args.products_root).resolve()
    app = pathlib.Path(args.target_app).resolve()
    runner = products / "Release-iphoneos" / UI_TEST_RUNNER
    test_bundle = runner / "PlugIns" / UI_TEST_BUNDLE
    tunnel = app / "PlugIns" / TUNNEL_NAME
    for path in (source, app, tunnel, runner, test_bundle):
        require(path.exists(), f"xctestrun product is missing: {path}")
    payload = read_plist(source)
    targets = xctestrun_targets(payload)
    assignments = environment_assignments(args)
    app_bundle_id = runner_bundle_id = ""
    if args.use_destination_artifacts:
        app_bundle_id = read_plist(app / "Info.plist").get("CFBundleIdentifier")
        runner_bundle_id = read_plist(runner / "Info.plist").get(
            "CFBundleIdentifier"
        )
        require(
            isinstance(app_bundle_id, str) and app_bundle_id,
            "iOS target app lacks a bundle identifier",
        )
        require(
            isinstance(runner_bundle_id, str) and runner_bundle_id,
            "iOS test runner lacks a bundle identifier",
        )
    for target in targets:
        require(
            "UseDestinationArtifacts" not in target
            or target.get("UseDestinationArtifacts") is False,
            "xctestrun relies on destination-side products",
        )
        target["UITargetAppCommandLineArguments"] = []
        target["UITargetAppEnvironmentVariables"] = {}
        if args.use_destination_artifacts:
            target["UseDestinationArtifacts"] = True
            target["TestHostBundleIdentifier"] = runner_bundle_id
            target["TestBundleDestinationRelativePath"] = (
                f"PlugIns/{UI_TEST_BUNDLE}"
            )
            target["UITargetAppBundleIdentifier"] = app_bundle_id
            # This case supplies the target explicitly. A retained runner plan
            # may instead leave target selection to the tests, which gives
            # parameterless XCUIApplication() no configured application.
            target["UseUITargetAppProvidedByTests"] = False
            for key in (
                "TestBundlePath",
                "TestHostPath",
                "UITargetAppPath",
                "DependentProductPaths",
            ):
                target.pop(key, None)
        else:
            target["TestBundlePath"] = str(test_bundle)
            target["TestHostPath"] = str(runner)
            target["UITargetAppPath"] = str(app)
            target["DependentProductPaths"] = [
                str(tunnel),
                str(app),
                str(runner),
                str(test_bundle),
            ]
        environment = target.get("EnvironmentVariables")
        require(
            isinstance(environment, dict),
            "xctestrun lacks its runner environment",
        )
        for name, setting in assignments:
            environment[name] = setting
    rewrite_coverage_products(
        payload,
        app=app,
        tunnel=tunnel,
        test_bundle=test_bundle,
    )
    payload = resolve_relocatable_paths(
        payload,
        derived_data=products.parent.parent,
        runner=runner,
        products=products,
    )
    targets = xctestrun_targets(payload)
    for target in targets:
        if args.use_destination_artifacts:
            require(
                target.get("UseDestinationArtifacts") is True
                and target.get("TestHostBundleIdentifier") == runner_bundle_id
                and target.get("TestBundleDestinationRelativePath")
                == f"PlugIns/{UI_TEST_BUNDLE}"
                and target.get("UITargetAppBundleIdentifier") == app_bundle_id
                and target.get("UseUITargetAppProvidedByTests") is False,
                "rewritten xctestrun lacks destination artifact identity",
            )
            require(
                not any(
                    key in target
                    for key in (
                        "TestBundlePath",
                        "TestHostPath",
                        "UITargetAppPath",
                        "DependentProductPaths",
                    )
                ),
                "destination-artifact xctestrun retains install paths",
            )
            continue
        for key in (
            "TestBundlePath",
            "TestHostPath",
            "UITargetAppPath",
        ):
            value = target.get(key)
            require(
                isinstance(value, str)
                and value.startswith("/")
                and "__TESTROOT__" not in value
                and "__TESTHOST__" not in value,
                f"rewritten xctestrun has a non-absolute {key}",
            )
        dependent = target.get("DependentProductPaths")
        require(
            isinstance(dependent, list)
            and dependent
            and all(
                isinstance(path, str)
                and path.startswith("/")
                and "__TESTROOT__" not in path
                and "__TESTHOST__" not in path
                for path in dependent
            ),
            "rewritten xctestrun has non-absolute dependent products",
        )
    reject_relocatable_paths(payload)
    atomic_plist(output, payload)
