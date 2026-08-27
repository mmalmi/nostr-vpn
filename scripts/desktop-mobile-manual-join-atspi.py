#!/usr/bin/env python3
"""Drive the shipped Linux GTK desktop/mobile join flow through AT-SPI."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

import pyatspi


NPUB = re.compile(r"npub1[023456789acdefghjklmnpqrstuvwxyz]{58}")
TARGET_PID = 0
TARGET_WINDOW = 0
DNS_DROPDOWN_LABELS = {
    "nvpn-exit-dns-mode": (
        "Automatic (recommended)",
        "Encrypted DNS",
        "DNS through exit",
    ),
    "nvpn-exit-dns-provider": (
        "Cloudflare",
        "Quad9",
        "Custom DoH",
    ),
}


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def write_json_atomically(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def walk(node: Any):
    yield node
    try:
        children = list(node)
    except Exception:
        return
    for child in children:
        yield from walk(child)


def visible(node: Any) -> bool:
    try:
        state = node.getState()
        return (
            state.contains(pyatspi.STATE_VISIBLE)
            and state.contains(pyatspi.STATE_SHOWING)
            and not state.contains(pyatspi.STATE_DEFUNCT)
        )
    except Exception:
        return False


def matching_nodes(name: str) -> list[Any]:
    matches = []
    desktop = pyatspi.Registry.getDesktop(0)
    for node in walk(desktop):
        try:
            if (
                node.get_process_id() == TARGET_PID
                and node_matches_name(node, name)
                and visible(node)
            ):
                matches.append(node)
        except Exception:
            continue
    return matches


def node_matches_name(node: Any, name: str) -> bool:
    if name.startswith("nvpn-exit-dns-"):
        return node.get_accessible_id() == name
    return node.name == name


def ancestor_with_accessible_id(node: Any, accessible_id: str) -> Any | None:
    current = node
    for _ in range(16):
        try:
            if current.get_accessible_id() == accessible_id:
                return current
            current = current.parent
        except Exception:
            return None
        if current is None:
            return None
    return None


def focused_target(node: Any, name: str) -> Any | None:
    if name.startswith("nvpn-exit-dns-"):
        return ancestor_with_accessible_id(node, name)
    return node if node_matches_name(node, name) else None


def has_action(node: Any) -> bool:
    try:
        return node.queryAction().nActions > 0
    except Exception:
        return False


def focused_actionable_nodes() -> list[Any]:
    focused = []
    for node in walk(pyatspi.Registry.getDesktop(0)):
        try:
            if (
                node.get_process_id() == TARGET_PID
                and visible(node)
                and has_action(node)
                and node.getState().contains(pyatspi.STATE_FOCUSED)
            ):
                focused.append(node)
        except Exception:
            continue
    return focused


def sole_focused_target(name: str) -> Any | None:
    focused = focused_actionable_nodes()
    if len(focused) != 1:
        return None
    return focused_target(focused[0], name)


def accessible_description(node: Any) -> str:
    try:
        return f"{node.getRoleName()}:{node.name}"
    except Exception:
        return "stale"


def find_named(
    name: str,
    timeout: float = 15,
    *,
    actionable: bool = False,
) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for node in matching_nodes(name):
            if not actionable or has_action(node):
                return node
        pyatspi.Registry.pumpQueuedEvents()
        time.sleep(0.1)
    visible_nodes = []
    for node in walk(pyatspi.Registry.getDesktop(0)):
        try:
            accessible_id = node.get_accessible_id()
            if (
                node.get_process_id() == TARGET_PID
                and visible(node)
                and (node.name or accessible_id)
            ):
                suffix = f"#{accessible_id}" if accessible_id else ""
                visible_nodes.append(f"{node.getRoleName()}:{node.name}{suffix}")
        except Exception:
            continue
    print(
        "Visible AT-SPI controls: " + ", ".join(visible_nodes[:300]),
        file=sys.stderr,
    )
    raise RuntimeError(f"visible AT-SPI control did not appear: {name}")


def wait_single_peer_connected_roster(timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if matching_nodes("1 of 1 devices connected") and matching_nodes("Online"):
            return
        pyatspi.Registry.pumpQueuedEvents()
        time.sleep(0.1)
    raise RuntimeError("single-peer connected roster did not appear")


def focus_named_with_keyboard(name: str, max_tabs: int = 100) -> Any:
    subprocess.run(
        ["xdotool", "windowfocus", "--sync", str(TARGET_WINDOW)],
        check=True,
    )
    focused_names = []
    saw_non_target_focus = False
    for _ in range(max_tabs):
        if not target_window_has_focus():
            subprocess.run(
                ["xdotool", "windowfocus", "--sync", str(TARGET_WINDOW)],
                check=True,
            )
            time.sleep(0.1)
        subprocess.run(
            ["xdotool", "key", "--clearmodifiers", "Tab"],
            check=True,
        )
        time.sleep(0.05)
        pyatspi.Registry.pumpQueuedEvents()
        focused = focused_actionable_nodes()
        target = sole_focused_target(name)
        if target is not None and saw_non_target_focus:
            return target
        if focused and not any(focused_target(node, name) for node in focused):
            saw_non_target_focus = True
        focused_names.append(
            ",".join(accessible_description(node) for node in focused) or "none"
        )
    raise RuntimeError(
        f"keyboard focus did not reach {name}; focused sequence: "
        + ", ".join(focused_names)
    )


def target_window_has_focus() -> bool:
    focused = subprocess.run(
        ["xdotool", "getwindowfocus"],
        text=True,
        capture_output=True,
        check=False,
    )
    return focused.returncode == 0 and focused.stdout.strip() == str(TARGET_WINDOW)


def invoke(name: str, *, stable_focus: float = 0) -> None:
    find_named(name, actionable=True)
    focus_named_with_keyboard(name)
    if stable_focus > 0:
        deadline = time.monotonic() + 5
        stable_since: float | None = None
        while time.monotonic() < deadline:
            pyatspi.Registry.pumpQueuedEvents()
            focused = (
                target_window_has_focus() and sole_focused_target(name) is not None
            )
            if focused:
                if stable_since is None:
                    stable_since = time.monotonic()
                elif time.monotonic() - stable_since >= stable_focus:
                    break
            else:
                stable_since = None
                focus_named_with_keyboard(name)
            time.sleep(0.05)
        else:
            raise RuntimeError(f"keyboard focus did not stabilize on {name}")
    subprocess.run(
        ["xdotool", "key", "--clearmodifiers", "space"],
        check=True,
    )
    time.sleep(0.25)


def set_text(name: str, value: str) -> None:
    node = find_named(name)
    try:
        node.queryEditableText().setTextContents(value)
    except Exception:
        focus_named_with_keyboard(name)
        subprocess.run(
            ["xdotool", "key", "--clearmodifiers", "ctrl+a"],
            check=True,
        )
        subprocess.run(
            ["xdotool", "type", "--clearmodifiers", "--delay", "1", "--", value],
            check=True,
        )
    deadline = time.monotonic() + 3
    actual = ""
    while time.monotonic() < deadline:
        for candidate in matching_nodes(name):
            try:
                actual = candidate.queryText().getText(0, -1)
                if actual == value:
                    return
            except Exception:
                continue
        time.sleep(0.05)
    raise RuntimeError(f"AT-SPI failed to set {name}: got {actual!r}")


def read_text(name: str) -> str:
    deadline = time.monotonic() + 3
    last_error: Exception | None = None
    read_succeeded = False
    while time.monotonic() < deadline:
        for candidate in matching_nodes(name):
            try:
                value = candidate.queryText().getText(0, -1).strip()
                read_succeeded = True
                if value:
                    return value
            except Exception as error:
                last_error = error
        pyatspi.Registry.pumpQueuedEvents()
        time.sleep(0.05)
    if not read_succeeded and last_error is not None:
        raise RuntimeError(f"AT-SPI could not read public text from {name}") from last_error
    raise RuntimeError(f"public GTK value is empty: {name}")


def checked(name: str) -> bool:
    node = find_named(name)
    return node.getState().contains(pyatspi.STATE_CHECKED)


def read_npub(name: str) -> str:
    value = read_text(name)
    match = NPUB.search(value)
    if match is None:
        raise RuntimeError(f"public GTK value is not a valid npub: {name}")
    return match.group(0)


def read_network_id(name: str) -> str:
    value = read_text(name)
    if ":" in value:
        value = value.split(":", 1)[1]
    normalized = re.sub(r"[\s-]", "", value)
    if len(normalized) < 8:
        raise RuntimeError("public GTK Network ID is empty or invalid")
    return normalized


def canonical_ip_csv(value: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(ipaddress.ip_address(part.strip()))
                for part in value.split(",")
                if part.strip()
            }
        )
    )


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_dns_index(name: str, index: int) -> None:
    if name not in DNS_DROPDOWN_LABELS:
        raise RuntimeError(f"unsupported DNS dropdown: {name}")
    find_named(name)
    focus_named_with_keyboard(name)
    subprocess.run(
        ["xdotool", "key", "--clearmodifiers", "Escape"],
        check=True,
    )
    wait_dropdown_expanded(name, False)
    focus_named_with_keyboard(name)
    subprocess.run(
        ["xdotool", "key", "--clearmodifiers", "space"],
        check=True,
    )
    wait_dropdown_expanded(name, True)
    wait_dropdown_popup_ready(name)
    subprocess.run(
        ["xdotool", "key", "--clearmodifiers", "Home"],
        check=True,
    )
    time.sleep(0.15)
    for _ in range(index):
        subprocess.run(
            ["xdotool", "key", "--clearmodifiers", "Down"],
            check=True,
        )
        time.sleep(0.15)
    subprocess.run(
        ["xdotool", "key", "--clearmodifiers", "Return"],
        check=True,
    )
    wait_dropdown_expanded(name, False)
    selected_dns_index(name, expected=index)


def selected_dns_index(
    name: str,
    *,
    expected: int | None = None,
    timeout: float = 3,
) -> int:
    try:
        labels = DNS_DROPDOWN_LABELS[name]
    except KeyError as error:
        raise RuntimeError(f"unsupported DNS dropdown: {name}") from error
    deadline = time.monotonic() + timeout
    label = ""
    while time.monotonic() < deadline:
        for node in matching_nodes(name):
            label = node.name.strip()
            if label in labels:
                index = labels.index(label)
                if expected is None or index == expected:
                    return index
        pyatspi.Registry.pumpQueuedEvents()
        time.sleep(0.05)
    target = "" if expected is None else f", expected index {expected}"
    raise RuntimeError(
        f"AT-SPI exposed an unexpected selected label for {name}: "
        f"{label!r}{target}"
    )


def wait_dropdown_expanded(name: str, expected: bool, timeout: float = 3) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pyatspi.Registry.pumpQueuedEvents()
        for node in matching_nodes(name):
            try:
                expanded = node.getState().contains(pyatspi.STATE_EXPANDED)
                if expanded == expected:
                    return
            except Exception:
                continue
        time.sleep(0.05)
    state = "open" if expected else "close"
    raise RuntimeError(f"AT-SPI dropdown did not {state}: {name}")


def wait_dropdown_popup_ready(name: str, timeout: float = 3) -> None:
    expected_items = len(DNS_DROPDOWN_LABELS[name])
    deadline = time.monotonic() + timeout
    observed = 0
    while time.monotonic() < deadline:
        pyatspi.Registry.pumpQueuedEvents()
        matches = 0
        for node in walk(pyatspi.Registry.getDesktop(0)):
            try:
                if (
                    node.get_process_id() != TARGET_PID
                    or node.getRoleName() != "list box"
                    or not visible(node)
                ):
                    continue
                observed = sum(
                    1
                    for child in walk(node)
                    if child is not node and child.getRoleName() == "list item"
                )
                if observed == expected_items:
                    matches += 1
            except Exception:
                continue
        if matches == 1:
            return
        if matches > 1:
            raise RuntimeError(f"AT-SPI exposed ambiguous dropdown popups: {name}")
        time.sleep(0.05)
    raise RuntimeError(
        f"AT-SPI dropdown popup exposed {observed} items, "
        f"expected {expected_items}: {name}"
    )


def screenshot(root: pathlib.Path, label: str) -> None:
    executable = shutil.which("import")
    if executable is None:
        return
    subprocess.run(
        [executable, "-window", str(TARGET_WINDOW), str(root / f"{label}.png")],
        check=True,
    )


def canonical_data_dir() -> pathlib.Path:
    override = os.environ.get("XDG_DATA_HOME", "").strip()
    if override:
        base = pathlib.Path(override).expanduser().resolve()
    else:
        base = pathlib.Path.home().resolve() / ".local" / "share"
    return base / "nostr-vpn"


def exact_app_pids(app: pathlib.Path) -> list[int]:
    expected = app.resolve()
    result = []
    proc = pathlib.Path("/proc")
    if not proc.is_dir():
        return result
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "exe").resolve() == expected:
                result.append(int(entry.name))
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return result


def stop_exact_app_instances(app: pathlib.Path) -> None:
    pids = exact_app_pids(app)
    for pid in pids:
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and exact_app_pids(app):
        time.sleep(0.05)
    for pid in exact_app_pids(app):
        os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and exact_app_pids(app):
        time.sleep(0.05)
    if exact_app_pids(app):
        raise RuntimeError("could not stop the exact imported GTK app")


class Driver:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.app = args.app.resolve()
        self.marker = args.marker.resolve()
        self.stop_path = args.stop_path.resolve() if args.stop_path else None
        self.artifact_root = args.artifact_root.resolve()
        self.process: subprocess.Popen[bytes] | None = None
        self.log_handle: Any | None = None
        self.evidence: dict[str, Any] = {
            "schema": 1,
            "mode": args.mode,
            "publicUiOnly": True,
            "privateStateRead": False,
            "appLaunchArgumentsOrEnvironment": False,
        }

    def write_evidence(self) -> None:
        write_json_atomically(self.marker, self.evidence)

    def reset(self) -> None:
        if os.environ.get("NVPN_APP_DATA_DIR") or os.environ.get("NVPN_CLI_PATH"):
            raise RuntimeError("public-UI gate refuses app data or CLI overrides")
        stop_exact_app_instances(self.app)
        data_dir = canonical_data_dir()
        expected_parent = (
            pathlib.Path(os.environ.get("XDG_DATA_HOME", "")).expanduser().resolve()
            if os.environ.get("XDG_DATA_HOME", "").strip()
            else pathlib.Path.home().resolve() / ".local" / "share"
        )
        if data_dir.parent != expected_parent or data_dir.name != "nostr-vpn":
            raise RuntimeError("refusing unsafe canonical Linux app-data reset")
        if data_dir.is_symlink():
            raise RuntimeError("refusing symlinked canonical Linux app-data reset")
        if data_dir.exists():
            shutil.rmtree(data_dir)
        self.evidence["resetComplete"] = True
        self.evidence["canonicalProfile"] = True
        self.write_evidence()

    def launch(self) -> None:
        global TARGET_PID, TARGET_WINDOW
        if not self.app.is_file() or self.app.is_symlink():
            raise RuntimeError(f"imported GTK app is missing: {self.app}")
        stop_exact_app_instances(self.app)
        child_env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("NVPN_", "FIPS_", "RUST_"))
        }
        self.log_handle = (
            self.artifact_root / f"{self.args.mode.lower()}-app.log"
        ).open("ab")
        self.process = subprocess.Popen(
            [str(self.app)],
            cwd=self.app.parent,
            env=child_env,
            stdout=self.log_handle,
            stderr=subprocess.STDOUT,
        )
        TARGET_PID = self.process.pid
        deadline = time.monotonic() + self.args.ui_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("GTK app exited before showing its public window")
            search = subprocess.run(
                [
                    "xdotool",
                    "search",
                    "--onlyvisible",
                    "--pid",
                    str(TARGET_PID),
                    "--name",
                    "^Nostr VPN$",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            window = search.stdout.strip().splitlines()
            if window:
                TARGET_WINDOW = int(window[0])
                return
            time.sleep(0.1)
        raise RuntimeError("GTK app window did not appear")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process = None
        if self.log_handle is not None:
            self.log_handle.close()
            self.log_handle = None

    def bootstrap(self) -> None:
        self.launch()
        find_named("nvpn-manual-join-create-network-choice")
        invoke("nvpn-manual-join-choose-join")
        invoke("nvpn-manual-join-expander")
        self.evidence["joinerNpub"] = read_npub(
            "nvpn-manual-join-joiner-device-id-value"
        )
        self.evidence["bootstrapComplete"] = True
        screenshot(self.artifact_root, "bootstrap")
        self.write_evidence()

    def create_admin(self) -> None:
        self.launch()
        invoke("nvpn-manual-join-create-network-choice")
        set_text("nvpn-manual-join-create-network-name", self.args.network_name)
        invoke("nvpn-manual-join-create-network-submit")
        invoke("nvpn-manual-join-admin-open")
        admin = read_npub("nvpn-manual-join-admin-device-id-value")
        network = read_network_id("nvpn-manual-join-admin-network-id-value")
        self.evidence.update(
            {
                "adminNpub": admin,
                "networkId": network,
                "adminReady": True,
            }
        )
        screenshot(self.artifact_root, "create-admin")
        self.write_evidence()

    def admin_add(self) -> None:
        if not NPUB.fullmatch(self.args.participant_npub):
            raise RuntimeError("Pixel joiner Device ID is invalid")
        if self.stop_path is None:
            raise RuntimeError("AdminAdd requires a stop path")
        self.launch()
        invoke("nvpn-manual-join-admin-open")
        set_text(
            "nvpn-manual-join-admin-device-id", self.args.participant_npub
        )
        set_text(
            "nvpn-manual-join-admin-device-name", self.args.participant_alias
        )
        self.evidence["participantNpub"] = self.args.participant_npub
        self.evidence["approvalSubmittedMs"] = now_ms()
        self.write_evidence()
        invoke("nvpn-manual-join-admin-submit")
        find_named(
            "1 of 1 devices connected",
            timeout=self.args.coordination_timeout,
        )
        self.evidence["desktopParticipantVisible"] = True
        self.evidence["desktopAccepted"] = True
        self.evidence["acceptedAtMs"] = now_ms()
        screenshot(self.artifact_root, "desktop-admin-participant-visible")
        self.write_evidence()
        deadline = time.monotonic() + self.args.hold_timeout
        while time.monotonic() < deadline:
            if self.stop_path.is_file() and not self.stop_path.is_symlink():
                self.evidence["holdReleased"] = True
                self.write_evidence()
                return
            if self.process is None or self.process.poll() is not None:
                raise RuntimeError("GTK admin app exited while holding delivery")
            time.sleep(0.1)
        raise RuntimeError("GTK admin hold timed out before orchestrator release")

    def manual_join(self) -> None:
        if not NPUB.fullmatch(self.args.admin_npub):
            raise RuntimeError("Pixel admin Device ID is invalid")
        if not self.args.network_id.strip():
            raise RuntimeError("Pixel admin Network ID is empty")
        self.launch()
        invoke("nvpn-manual-join-choose-join")
        invoke("nvpn-manual-join-expander")
        joiner = read_npub("nvpn-manual-join-joiner-device-id-value")
        self.evidence["joinerNpub"] = joiner
        self.evidence["adminNpub"] = self.args.admin_npub
        self.write_evidence()
        set_text("nvpn-manual-join-admin-id", self.args.admin_npub)
        set_text("nvpn-manual-join-network-id", self.args.network_id)
        self.evidence["manualSubmittedMs"] = now_ms()
        self.write_evidence()
        invoke("nvpn-manual-join-submit")
        wait_single_peer_connected_roster(self.args.coordination_timeout)
        self.evidence["acceptedSelector"] = "single-peer connected roster row"
        self.evidence["desktopAccepted"] = True
        self.evidence["acceptedAtMs"] = now_ms()
        screenshot(self.artifact_root, "desktop-joiner-accepted")
        self.write_evidence()

    def verify(self) -> None:
        if not NPUB.fullmatch(self.args.participant_npub):
            raise RuntimeError("expected accepted participant is invalid")
        self.launch()
        wait_single_peer_connected_roster(self.args.ui_timeout)
        self.evidence["participantNpub"] = self.args.participant_npub
        self.evidence["acceptedSelector"] = "single-peer connected roster row"
        self.evidence["relaunchAccepted"] = True
        screenshot(self.artifact_root, "relaunch-accepted")
        self.write_evidence()

    def dns_policy(self) -> None:
        mode_indexes = {
            "automatic": 0,
            "encrypted": 1,
            "through_exit": 2,
        }
        provider_indexes = {
            "cloudflare": 0,
            "quad9": 1,
            "custom": 2,
        }
        if self.args.dns_mode not in mode_indexes:
            raise RuntimeError("unsupported DNS mode")
        if self.args.dns_provider not in provider_indexes:
            raise RuntimeError("unsupported DNS provider")
        if self.args.case not in {
            "automatic",
            "cloudflare",
            "quad9",
            "custom",
            "through-exit",
        }:
            raise RuntimeError("unsupported desktop DNS case")
        if self.args.cli is None:
            raise RuntimeError("DnsPolicy requires the exact release CLI")
        cli = self.args.cli.resolve()
        if not cli.is_file() or cli.is_symlink():
            raise RuntimeError("exact release CLI is missing")

        def open_dns() -> None:
            self.launch()
            invoke("Internet", stable_focus=0.5)
            find_named("nvpn-exit-dns-mode")

        open_dns()
        select_dns_index(
            "nvpn-exit-dns-mode",
            mode_indexes[self.args.dns_mode],
        )
        if self.args.dns_mode == "encrypted":
            select_dns_index(
                "nvpn-exit-dns-provider",
                provider_indexes[self.args.dns_provider],
            )
            if self.args.dns_provider == "custom":
                set_text(
                    "nvpn-exit-dns-custom-url",
                    self.args.dns_custom_url,
                )
                set_text(
                    "nvpn-exit-dns-bootstrap-ips",
                    self.args.dns_bootstrap_ips,
                )
        elif self.args.dns_mode == "through_exit":
            set_text(
                "nvpn-exit-dns-through-servers",
                self.args.dns_through_servers,
            )
        invoke("nvpn-exit-dns-save")
        time.sleep(0.75)
        screenshot(self.artifact_root, f"dns-{self.args.case}-saved")
        self.stop()

        open_dns()
        if (
            selected_dns_index("nvpn-exit-dns-mode")
            != mode_indexes[self.args.dns_mode]
        ):
            raise RuntimeError("relaunch changed the saved DNS mode")
        if self.args.dns_mode == "encrypted":
            if (
                selected_dns_index("nvpn-exit-dns-provider")
                != provider_indexes[self.args.dns_provider]
            ):
                raise RuntimeError("relaunch changed the saved DNS provider")
            if self.args.dns_provider == "custom":
                observed_url = read_text("nvpn-exit-dns-custom-url")
                observed_bootstrap = read_text("nvpn-exit-dns-bootstrap-ips")
                if observed_url != self.args.dns_custom_url or canonical_ip_csv(
                    observed_bootstrap
                ) != canonical_ip_csv(self.args.dns_bootstrap_ips):
                    raise RuntimeError(
                        "relaunch changed the custom DoH UI fields: "
                        f"url={observed_url!r}, "
                        f"bootstrap={observed_bootstrap!r}"
                    )
        elif self.args.dns_mode == "through_exit":
            if (
                read_text("nvpn-exit-dns-through-servers")
                != self.args.dns_through_servers
            ):
                raise RuntimeError(
                    "relaunch changed the through-exit DNS UI field"
                )
        screenshot(self.artifact_root, f"dns-{self.args.case}-readback")
        self.evidence.update(
            {
                "receiptSchema": 1,
                "platform": "linux",
                "case": self.args.case,
                "evidenceSource": "shipped-ui-restart-readback",
                "savedViaShippedUi": True,
                "uiRestartReadback": True,
                "releaseBlackbox": True,
                "exitDnsMode": self.args.dns_mode,
                "exitDnsDohProvider": self.args.dns_provider,
                "exitDnsCustomDohUrl": self.args.dns_custom_url,
                "exitDnsCustomDohBootstrapIps": (
                    self.args.dns_bootstrap_ips
                ),
                "exitDnsThroughExitServers": (
                    self.args.dns_through_servers
                ),
                "appGitSha": self.args.app_git_sha,
                "appGitTree": self.args.app_git_tree,
                "appExecutableSha256": sha256(self.app),
                "cliExecutableSha256": sha256(cli),
            }
        )
        self.write_evidence()

    def paid_exit_seller(self) -> None:
        if self.args.cli is None:
            raise RuntimeError("PaidExitSeller requires the exact release CLI")
        cli = self.args.cli.resolve()
        if not cli.is_file() or cli.is_symlink():
            raise RuntimeError("exact release CLI is missing")
        if not self.args.seller_price.isdigit():
            raise RuntimeError("seller price must be an unsigned integer")
        if not re.fullmatch(r"[A-Z]{2}", self.args.seller_country):
            raise RuntimeError("seller country must be a two-letter uppercase code")
        if not self.args.seller_mint.startswith(("http://", "https://")):
            raise RuntimeError("seller mint must be an HTTP(S) URL")

        def open_seller() -> None:
            self.launch()
            invoke("Internet", stable_focus=0.5)
            invoke("nvpn-paid-exit-seller-open", stable_focus=0.5)
            find_named("nvpn-paid-exit-seller-enabled")

        open_seller()
        set_text("nvpn-paid-exit-price-msat-per-gb", self.args.seller_price)
        set_text("nvpn-paid-exit-country-code", self.args.seller_country)
        set_text("nvpn-paid-exit-accepted-mints", self.args.seller_mint)
        invoke("nvpn-paid-exit-seller-save")
        time.sleep(0.75)
        if not checked("nvpn-paid-exit-seller-enabled"):
            invoke("nvpn-paid-exit-seller-enabled")
            time.sleep(0.75)
        if not checked("nvpn-paid-exit-seller-enabled"):
            raise RuntimeError("seller enable switch did not remain on")
        screenshot(self.artifact_root, "paid-exit-seller-saved")
        self.stop()

        open_seller()
        observed_price = read_text("nvpn-paid-exit-price-msat-per-gb")
        observed_country = read_text("nvpn-paid-exit-country-code")
        observed_mint = read_text("nvpn-paid-exit-accepted-mints")
        observed_enabled = checked("nvpn-paid-exit-seller-enabled")
        if (
            observed_price != self.args.seller_price
            or observed_country != self.args.seller_country
            or observed_mint != self.args.seller_mint
            or not observed_enabled
        ):
            raise RuntimeError(
                "relaunch changed seller UI values: "
                f"enabled={observed_enabled}, price={observed_price!r}, "
                f"country={observed_country!r}, mint={observed_mint!r}"
            )
        screenshot(self.artifact_root, "paid-exit-seller-readback")
        self.evidence.update(
            {
                "receiptSchema": 1,
                "platform": "linux",
                "case": "paid-exit-seller",
                "evidenceSource": "shipped-ui-restart-readback",
                "savedViaShippedUi": True,
                "enabledViaShippedUi": True,
                "uiRestartReadback": True,
                "releaseBlackbox": True,
                "publicUiOnly": True,
                "privateStateRead": False,
                "paidExitEnabled": True,
                "paidExitPriceMsatPerGb": int(self.args.seller_price),
                "paidExitCountryCode": self.args.seller_country,
                "paidExitAcceptedMints": [self.args.seller_mint],
                "appGitSha": self.args.app_git_sha,
                "appGitTree": self.args.app_git_tree,
                "appExecutableSha256": sha256(self.app),
                "cliExecutableSha256": sha256(cli),
            }
        )
        self.write_evidence()

    def run(self) -> None:
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        if self.args.mode == "Reset":
            self.reset()
        elif self.args.mode == "Bootstrap":
            self.bootstrap()
        elif self.args.mode == "CreateAdmin":
            self.create_admin()
        elif self.args.mode == "AdminAdd":
            self.admin_add()
        elif self.args.mode == "ManualJoin":
            self.manual_join()
        elif self.args.mode == "DnsPolicy":
            self.dns_policy()
        elif self.args.mode == "PaidExitSeller":
            self.paid_exit_seller()
        else:
            self.verify()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument(
        "mode",
        choices=(
            "Reset",
            "Bootstrap",
            "CreateAdmin",
            "AdminAdd",
            "ManualJoin",
            "DnsPolicy",
            "PaidExitSeller",
            "Verify",
        ),
    )
    result.add_argument("--app", type=pathlib.Path, required=True)
    result.add_argument("--marker", type=pathlib.Path, required=True)
    result.add_argument("--artifact-root", type=pathlib.Path, required=True)
    result.add_argument("--stop-path", type=pathlib.Path)
    result.add_argument("--network-name", default="Release Linux admin")
    result.add_argument("--admin-npub", default="")
    result.add_argument("--network-id", default="")
    result.add_argument("--participant-npub", default="")
    result.add_argument("--participant-alias", default="Release Pixel")
    result.add_argument("--cli", type=pathlib.Path)
    result.add_argument("--case", default="")
    result.add_argument("--dns-mode", default="")
    result.add_argument("--dns-provider", default="cloudflare")
    result.add_argument("--dns-custom-url", default="")
    result.add_argument("--dns-bootstrap-ips", default="")
    result.add_argument("--dns-through-servers", default="")
    result.add_argument("--seller-price", default="1000000")
    result.add_argument("--seller-country", default="FI")
    result.add_argument("--seller-mint", default="")
    result.add_argument("--app-git-sha", default="")
    result.add_argument("--app-git-tree", default="")
    result.add_argument("--ui-timeout", type=int, default=15)
    result.add_argument("--coordination-timeout", type=int, default=20)
    result.add_argument("--hold-timeout", type=int, default=30)
    return result


def main() -> None:
    args = parser().parse_args()
    driver = Driver(args)
    try:
        driver.run()
    finally:
        driver.stop()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Linux desktop/mobile AT-SPI gate failed: {error}", file=sys.stderr)
        raise
