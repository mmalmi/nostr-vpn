#!/usr/bin/env python3
"""Drive the shipped Linux manual-join controls through AT-SPI."""

import argparse
import subprocess
import sys
import time

import pyatspi

target_pid = 0
target_window = 0


def walk(node):
    yield node
    try:
        children = list(node)
    except Exception:
        return
    for child in children:
        yield from walk(child)


def visible(node):
    try:
        state = node.getState()
        return (
            state.contains(pyatspi.STATE_VISIBLE)
            and state.contains(pyatspi.STATE_SHOWING)
            and not state.contains(pyatspi.STATE_DEFUNCT)
        )
    except Exception:
        return False


def find_named(name, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        desktop = pyatspi.Registry.getDesktop(0)
        for node in walk(desktop):
            try:
                if (
                    node.get_process_id() == target_pid
                    and node.name == name
                    and visible(node)
                ):
                    return node
            except Exception:
                continue
        pyatspi.Registry.pumpQueuedEvents()
        time.sleep(0.1)
    visible_nodes = []
    for node in walk(pyatspi.Registry.getDesktop(0)):
        try:
            if (
                node.get_process_id() == target_pid
                and visible(node)
                and node.name
            ):
                visible_nodes.append(f"{node.getRoleName()}:{node.name}")
        except Exception:
            continue
    print(
        "Visible AT-SPI controls: " + ", ".join(visible_nodes[:300]),
        file=sys.stderr,
    )
    raise RuntimeError(f"visible AT-SPI control did not appear: {name}")


def has_action(node):
    try:
        return node.queryAction().nActions > 0
    except Exception:
        return False


def focused_actionable_nodes():
    focused = []
    for node in walk(pyatspi.Registry.getDesktop(0)):
        try:
            if (
                node.get_process_id() == target_pid
                and visible(node)
                and has_action(node)
                and node.getState().contains(pyatspi.STATE_FOCUSED)
            ):
                focused.append(node)
        except Exception:
            continue
    return focused


def node_is_named(node, name):
    try:
        return node.name == name
    except Exception:
        return False


def sole_focused_target(name):
    focused = focused_actionable_nodes()
    if len(focused) != 1:
        return None
    return focused[0] if node_is_named(focused[0], name) else None


def accessible_description(node):
    try:
        return f"{node.getRoleName()}:{node.name}"
    except Exception:
        return "stale"


def target_window_has_focus():
    focused = subprocess.run(
        ["xdotool", "getwindowfocus"],
        text=True,
        capture_output=True,
        check=False,
    )
    return focused.returncode == 0 and focused.stdout.strip() == str(target_window)


def focus_named_with_keyboard(name, max_tabs=100):
    subprocess.run(
        ["xdotool", "windowfocus", "--sync", str(target_window)],
        check=True,
    )
    focused_names = []
    saw_non_target_focus = False
    for _ in range(max_tabs):
        if not target_window_has_focus():
            subprocess.run(
                ["xdotool", "windowfocus", "--sync", str(target_window)],
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
        if focused and not any(node_is_named(node, name) for node in focused):
            saw_non_target_focus = True
        focused_names.append(
            ",".join(accessible_description(node) for node in focused)
            or "none"
        )
    raise RuntimeError(
        f"keyboard focus did not reach {name}; focused sequence: "
        + ", ".join(focused_names)
    )


def invoke(name):
    geometry = subprocess.run(
        ["xdotool", "getwindowgeometry", "--shell", str(target_window)],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip().replace("\n", " ")
    print(f"activate {name} through AT-SPI; {geometry}", file=sys.stderr)
    subprocess.run(
        ["xdotool", "windowfocus", "--sync", str(target_window)],
        check=True,
    )
    find_named(name)
    focus_named_with_keyboard(name)
    subprocess.run(
        ["xdotool", "key", "--clearmodifiers", "space"],
        check=True,
    )
    time.sleep(0.25)


def wait_named_visible(name, expected, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        is_visible = False
        for node in walk(pyatspi.Registry.getDesktop(0)):
            try:
                if (
                    node.get_process_id() == target_pid
                    and node.name == name
                    and visible(node)
                ):
                    is_visible = True
                    break
            except Exception:
                continue
        if is_visible == expected:
            return True
        pyatspi.Registry.pumpQueuedEvents()
        time.sleep(0.1)
    return False


def invoke_until_visible(name, expected, attempts=4):
    for _ in range(attempts):
        if wait_named_visible(expected, True, timeout=0.1):
            return
        invoke(name)
        if wait_named_visible(expected, True):
            return
    raise RuntimeError(f"invoking {name} did not reveal {expected}")


def invoke_until_hidden(name, attempts=4):
    for _ in range(attempts):
        invoke(name)
        if wait_named_visible(name, False):
            return
    raise RuntimeError(f"invoking {name} did not leave its current page")


def set_text(name, value):
    actual = ""
    for attempt in range(3):
        focus_named_with_keyboard(name)
        subprocess.run(
            ["xdotool", "key", "--clearmodifiers", "ctrl+a"],
            check=True,
        )
        subprocess.run(
            ["xdotool", "type", "--clearmodifiers", "--delay", "1", "--", value],
            check=True,
        )
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            for candidate in walk(pyatspi.Registry.getDesktop(0)):
                try:
                    if (
                        candidate.get_process_id() == target_pid
                        and candidate.name == name
                        and visible(candidate)
                    ):
                        actual = candidate.queryText().getText(0, -1)
                        if actual == value:
                            return
                except Exception:
                    continue
            time.sleep(0.05)
        print(
            f"retry text entry {name}: attempt={attempt + 1} got={actual!r}",
            file=sys.stderr,
        )
    raise RuntimeError(f"AT-SPI failed to set {name}: got {actual!r}")


def run_joiner(args):
    invoke_until_visible(
        "nvpn-manual-join-choose-join", "nvpn-manual-join-expander"
    )
    invoke_until_visible(
        "nvpn-manual-join-expander", "nvpn-manual-join-admin-id"
    )
    set_text("nvpn-manual-join-admin-id", args.admin_npub)
    set_text("nvpn-manual-join-network-id", args.mesh_network_id)
    invoke_until_hidden("nvpn-manual-join-submit")


def run_admin(args):
    invoke_until_visible(
        "nvpn-manual-join-admin-open", "nvpn-manual-join-admin-device-id"
    )
    set_text("nvpn-manual-join-admin-device-id", args.joiner_npub)
    set_text("nvpn-manual-join-admin-device-name", args.joiner_alias)
    invoke_until_hidden("nvpn-manual-join-admin-submit")


def main():
    global target_pid, target_window
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("joiner", "admin"))
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--window-id", required=True, type=int)
    parser.add_argument("--admin-npub", default="")
    parser.add_argument("--mesh-network-id", default="")
    parser.add_argument("--joiner-npub", default="")
    parser.add_argument("--joiner-alias", default="")
    args = parser.parse_args()
    target_pid = args.pid
    target_window = args.window_id
    if args.phase == "joiner":
        if not args.admin_npub or not args.mesh_network_id:
            parser.error("joiner phase requires --admin-npub and --mesh-network-id")
        run_joiner(args)
    else:
        if not args.joiner_npub or not args.joiner_alias:
            parser.error("admin phase requires --joiner-npub and --joiner-alias")
        run_admin(args)
    print(f"LINUX_MANUAL_JOIN_UI_{args.phase.upper()}_OK")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Linux manual-join UI driver failed: {error}", file=sys.stderr)
        raise
