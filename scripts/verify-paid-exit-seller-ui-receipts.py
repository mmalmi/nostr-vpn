#!/usr/bin/env python3
"""Validate shipped-UI paid-exit seller receipts on supported platforms."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re


EXPECTED_PLATFORMS = {"linux", "macos"}


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-git-sha", required=True)
    parser.add_argument("--app-git-tree", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("receipts", nargs="+")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.app_git_sha):
        parser.error("--app-git-sha must be an exact commit")
    if not re.fullmatch(r"[0-9a-f]{40}", args.app_git_tree):
        parser.error("--app-git-tree must be an exact tree")

    paths: dict[str, pathlib.Path] = {}
    for raw in args.receipts:
        platform, separator, name = raw.partition("=")
        if not separator or platform not in EXPECTED_PLATFORMS:
            parser.error(f"invalid platform=receipt: {raw}")
        if platform in paths:
            parser.error(f"duplicate receipt for {platform}")
        paths[platform] = pathlib.Path(name)
    if set(paths) != EXPECTED_PLATFORMS:
        parser.error(
            f"expected receipts for {sorted(EXPECTED_PLATFORMS)}, got {sorted(paths)}"
        )

    hashes: dict[str, str] = {}
    for platform, path in sorted(paths.items()):
        value = json.loads(path.read_text(encoding="utf-8"))
        expected = {
            "receiptSchema": 1,
            "platform": platform,
            "case": "paid-exit-seller",
            "evidenceSource": "shipped-ui-restart-readback",
            "releaseBlackbox": True,
            "savedViaShippedUi": True,
            "enabledViaShippedUi": True,
            "uiRestartReadback": True,
            "privateStateRead": False,
            "paidExitEnabled": True,
            "paidExitPriceMsatPerGb": 1_000_000,
            "paidExitCountryCode": "FI",
            "paidExitAcceptedMints": ["http://cashu-mint:3338"],
            "appGitSha": args.app_git_sha,
            "appGitTree": args.app_git_tree,
        }
        for field, wanted in expected.items():
            if value.get(field) != wanted:
                raise ValueError(
                    f"{platform} receipt {field}: expected {wanted!r}, "
                    f"got {value.get(field)!r}"
                )
        hashes[platform] = digest(path)

    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_text(
        json.dumps(
            {
                "receiptSchema": 1,
                "gate": "supported-platform paid-exit seller shipped UI",
                "platforms": hashes,
                "allSupportedPlatformsSavedEnabledAndRestartRead": True,
                "sellerContract": {
                    "priceMsatPerGb": 1_000_000,
                    "countryCode": "FI",
                    "acceptedMints": ["http://cashu-mint:3338"],
                },
                "appGitSha": args.app_git_sha,
                "appGitTree": args.app_git_tree,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
