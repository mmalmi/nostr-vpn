#!/usr/bin/env python3
"""Exercise the actual GTK app in an externally isolated X11/DBus session.

Requires --app, --fixture, --output, and --host-netns. The caller supplies a
fresh network namespace and disposable HOME/XDG directories; this never builds,
installs, starts a real daemon, or contacts a mint.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

import pyatspi

parser = argparse.ArgumentParser()
for argument in ("app", "fixture", "output", "host-netns", "keyboard-driver"):
    parser.add_argument("--" + argument, required=True)
args = parser.parse_args()
spec = importlib.util.spec_from_file_location("desktop_keyboard", args.keyboard_driver)
keyboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(keyboard)
output = Path(args.output).resolve()
output.mkdir()
assert os.readlink("/proc/self/ns/net") != args.host_netns
interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line}
assert interfaces == {"lo"}, interfaces
data = output / "data"
subprocess.run([args.fixture, str(data)], check=True, stdout=(output / "fixture.json").open("xb"))
store_path = data / "paid-routes.json"
before_store = json.loads(store_path.read_text())
assert not before_store["wallet"].get("mints")
assert len(before_store["offers"]) == 2
cli = output / "nvpn"
cli.write_text('''#!/usr/bin/env python3
import json, pathlib, sys, time
p = pathlib.Path(__file__).parent
with (p / "cli-calls.jsonl").open("a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
command = sys.argv[1] if len(sys.argv) > 1 else ""
if command == "status":
    if (p / "block-status").exists():
        (p / "status-started").touch()
        deadline = time.monotonic() + 40
        while (p / "block-status").exists():
            if time.monotonic() > deadline:
                (p / "status-timed-out").touch()
                sys.exit(7)
            time.sleep(0.02)
    print('{"daemon":{"running":false,"state":null}}')
elif command == "service":
    print('{"supported":false,"installed":false,"loaded":false,"running":false,"pid":null}')
elif command == "version":
    print('{"version":"desktop-regression"}')
else:
    sys.exit(8)
''')
cli.chmod(0o755)
manifest = output / "release.json"
manifest.write_text(json.dumps({"tag": "v0.0.0", "assets": [{"name": "nostr-vpn-v0.0.0-linux-x64.AppImage", "path": "unused.AppImage"}]}))
env = dict(os.environ, NVPN_APP_DATA_DIR=str(data), NVPN_CLI_PATH=str(cli),
           NVPN_UPDATE_MANIFEST_URL=manifest.as_uri(), GDK_BACKEND="x11", GTK_A11Y="atspi",
           NO_AT_BRIDGE="0", GSK_RENDERER="cairo")
process = None
checks = []


def wait_until(predicate, label, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        assert process is None or process.poll() is None, "App exited: " + label
        result = predicate()
        if result:
            return result
        pyatspi.Registry.pumpQueuedEvents()
        time.sleep(0.05)
    raise AssertionError("Timed out: " + label)


def walk(node):
    yield node
    try:
        children = list(node)
    except Exception:
        return
    for child in children:
        yield from walk(child)


def nodes():
    found = []
    for node in walk(pyatspi.Registry.getDesktop(0)):
        try:
            state = node.getState()
            if node.get_process_id() == process.pid and not state.contains(pyatspi.STATE_DEFUNCT):
                found.append(node)
        except Exception:
            continue
    return found


def named(name):
    return [node for node in nodes() if node.name == name
            and node.getState().contains(pyatspi.STATE_VISIBLE)
            and node.getState().contains(pyatspi.STATE_SHOWING)]


def buttons(name):
    result = []
    for node in named(name):
        for _ in range(5):
            if node.getRoleName() in ("push button", "button"):
                if node not in result:
                    result.append(node)
                break
            node = node.parent
            if node is None:
                break
    return result


def control_id(node):
    return [node.app.bus_name, node.path]


def click(name, row_label=None):
    def matching_buttons():
        return [node for node in buttons(name) if row_label is None
                or any(child.name == row_label for child in walk(node.parent))]

    candidates = wait_until(matching_buttons, "button " + name)
    assert len(candidates) == 1, "Ambiguous control: " + name
    node = candidates[0]
    target_name = node.name
    assert node.getState().contains(pyatspi.STATE_SENSITIVE), "Disabled: " + name
    window = subprocess.check_output(
        ["xdotool", "search", "--onlyvisible", "--pid", str(process.pid), "--name", "^Nostr VPN$"],
        text=True, timeout=5,
    ).splitlines()
    assert len(window) == 1
    keyboard.target_pid = process.pid
    keyboard.target_window = int(window[0])
    focused = keyboard.focus_named_with_keyboard(target_name)
    # A render replaces the sidebar and page widgets. Resolve the same logical
    # control again, then require the focused object's exact current bus/path.
    current = matching_buttons()
    focused_name, focused_role = focused.name, focused.getRoleName()
    with (output / "interactions.jsonl").open("a") as log:
        log.write(json.dumps({"name": name, "row_label": row_label,
                              "target_name": target_name, "focused_name": focused_name,
                              "focused_role": focused_role,
                              "before": control_id(node), "focused": control_id(focused),
                              "current": [control_id(item) for item in current],
                              "current_names": [item.name for item in current],
                              "window": window[0], "phase": "focus-check"}) + "\n")
    assert len(current) == 1, "Current control is ambiguous: " + name
    assert control_id(focused) == control_id(current[0]), "Keyboard focused a different control: " + name
    assert focused.get_process_id() == process.pid
    assert focused_name == target_name, f"Focused name changed: {focused_name!r}, expected {target_name!r}"
    assert focused_role in ("push button", "button"), "Focused role changed: " + focused_role
    assert keyboard.visible(focused)
    assert keyboard.target_window_has_focus()
    assert focused.getState().contains(pyatspi.STATE_FOCUSED)
    assert focused.getState().contains(pyatspi.STATE_SENSITIVE)
    subprocess.run(["xdotool", "key", "--clearmodifiers", "space"], check=True, timeout=5)
    with (output / "interactions.jsonl").open("a") as log:
        log.write(json.dumps({"name": name, "focused_name": focused_name, "input": "space", "window": window[0]}) + "\n")


def snapshot(label):
    subprocess.run(["import", "-window", "root", str(output / (label + ".png"))], check=True, timeout=5)
    inventory = []
    skipped = 0
    for node in nodes():
        try:
            inventory.append({"name": node.name, "role": node.getRoleName(),
                              "sensitive": node.getState().contains(pyatspi.STATE_SENSITIVE)})
        except Exception:
            # A render can retire a node while diagnostic inventory is read.
            skipped += 1
            continue
    (output / (label + ".json")).write_text(json.dumps(
        {"nodes": inventory, "skipped_transient_nodes": skipped}, indent=2) + "\n")


def launch(label):
    global process
    process = subprocess.Popen([args.app], env=env, stdout=(output / (label + ".log")).open("xb"), stderr=subprocess.STDOUT)
    (output / (label + "-pid.json")).write_text(json.dumps({"pid": process.pid}))


def stop_app():
    global process
    if process is not None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        process = None


def browse_sellers():
    wait_until(lambda: buttons("Internet"), "initial backend result")
    window = subprocess.check_output(
        ["xdotool", "search", "--onlyvisible", "--pid", str(process.pid), "--name", "^Nostr VPN$"],
        text=True, timeout=5,
    ).splitlines()
    assert len(window) == 1
    subprocess.run(["xdotool", "windowsize", "--sync", window[0], "1040", "1120"], check=True, timeout=5)
    click("Internet")
    click("Direct")
    assert not named("Working…"), "Selecting the current Direct route queued an unnecessary change"
    click("Paid · Choose manually")
    wait_until(lambda: len(buttons("Connect")) == 2, "both signed offers rendered")


def connect_states():
    return sorted(node.getState().contains(pyatspi.STATE_SENSITIVE) for node in buttons("Connect"))


def block_next_refresh():
    wait_until(lambda: buttons("Internet"), "initial backend result")
    (output / "status-started").unlink()
    (output / "block-status").touch()
    wait_until(lambda: (output / "status-started").exists(), "periodic refresh blocked")


result = {"status": "running", "network_namespace": os.readlink("/proc/self/ns/net"), "checks": checks}
try:
    (output / "block-status").touch()
    launch("first")
    wait_until(lambda: (output / "status-started").exists(), "constructor inside fake CLI")
    wait_until(lambda: named("Starting Nostr VPN…"), "responsive loading window", seconds=5)
    assert (output / "block-status").exists()
    snapshot("startup-blocked")
    checks.append("Real window exposes its loading state while FFI constructor status call remains blocked")
    (output / "block-status").unlink()
    block_next_refresh()
    browse_sellers()
    wait_until(lambda: connect_states() == [False, True], "free offer enabled; paid offer gated")
    for mint in ["https://first-mint.invalid", "http://second-mint.invalid"]:
        wait_until(lambda: named(mint), "accepted mint URL " + mint)
    wait_until(lambda: named("http://second-mint.invalid · unencrypted HTTP"), "unsecured mint warning")
    assert all(len(buttons(f"Trust mint {url}")) == 1 for url in ["https://first-mint.invalid", "http://second-mint.invalid"])
    snapshot("accepted-mints")
    checks.append("Both accepted mint URLs and Trust mint actions displayed; free offer needs no trusted mint")

    click("Trust mint https://first-mint.invalid")
    wait_until(lambda: named("Working…"), "queued action visible while refresh blocked")
    assert not json.loads(store_path.read_text())["wallet"].get("mints")
    snapshot("trust-queued")
    assert not (output / "status-timed-out").exists(), "Blocked refresh exceeded its fixture deadline"
    (output / "block-status").unlink()
    wait_until(lambda: connect_states() == [True, True], "paid offer enabled after trust")
    current = json.loads(store_path.read_text())
    assert [m["url"] for m in current["wallet"]["mints"]] == ["https://first-mint.invalid"]
    assert current["offers"] == before_store["offers"]
    assert not current.get("channels") and not current.get("sessions")
    snapshot("mint-trusted")
    checks.append("Trust action queues behind blocked refresh, persists exactly the selected mint and enables paid offer without buying")
    stop_app()
    launch("restart")
    block_next_refresh()
    browse_sellers()
    wait_until(lambda: connect_states() == [True, True], "trusted mint survives restart")
    assert not buttons("Trust mint https://first-mint.invalid") and not buttons("Trust mint http://second-mint.invalid")
    snapshot("restart")
    calls = [json.loads(line) for line in (output / "cli-calls.jsonl").read_text().splitlines()]
    assert calls and all(call[0] in ("status", "service", "version") for call in calls)
    assert not (output / "status-timed-out").exists(), "Blocked refresh exceeded its fixture deadline"
    checks.append("Trust survives real app restart; fake CLI received only status/service/version calls")
    result["status"] = "passed"
except BaseException as error:
    result.update(status="failed", error=str(error), error_type=type(error).__name__)
    if process is not None and process.poll() is None:
        try:
            snapshot("failure")
        except Exception as snapshot_error:
            result["snapshot_error"] = repr(snapshot_error)
    raise
finally:
    (output / "block-status").unlink(missing_ok=True)
    stop_app()
    result["artifacts"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.is_file()}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
