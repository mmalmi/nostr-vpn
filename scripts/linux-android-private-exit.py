#!/usr/bin/env python3
"""Prove private exit traffic through the temporary Linux/Android join pair."""
import argparse
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import signal
import subprocess
import sys
import time


def command(args):
    return subprocess.check_output(args, text=True, timeout=12).strip()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def serve():
    import tomllib

    opts = json.loads(sys.stdin.readline())
    addr = ipaddress.IPv4Address(opts["address"])
    nonce, port = opts["challenge"], opts["port"]
    require(addr in ipaddress.IPv4Network("198.18.0.0/15") and re.fullmatch("[a-f0-9]{32}", nonce)
            and 1024 <= port < 65536, "Invalid challenge endpoint")
    require(all(re.fullmatch(r"npub1[023456789acdefghjklmnpqrstuvwxyz]{58}", opts[name])
                for name in ("provider", "android")), "Invalid test pair")
    cli = Path("/usr/bin/nvpn")
    require(not cli.is_symlink() and hashlib.sha256(cli.read_bytes()).hexdigest() == opts["cliSha256"],
            "Installed Linux executable differs from the join receipt")
    cfg = Path.home() / ".config/nvpn/config.toml"
    config = tomllib.loads(cfg.read_text())
    network, = config["networks"]
    require(config["nostr"]["public_key"] == opts["provider"] and network["network_id"] == opts["network"]
            and set(network["devices"]) == {opts["provider"], opts["android"]}
            and not config.get("paid_exit", {}).get("enabled", False), "Expected the exclusive free test network")
    originally_advertised = bool(config["node"].get("advertise_exit_node", False))
    addr_arg = str(addr) + "/32"
    routes = json.loads(command(["ip", "-j", "-4", "route", "show", "table", "all"]))
    require(not any(row.get("dst") not in ("default", None) and addr in ipaddress.ip_network(row["dst"], strict=False)
                    for row in routes), "Test address is already routed")
    matched = False

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal matched
            if self.path != "/" + nonce:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(nonce)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(nonce.encode())
            matched = True

        def log_message(self, *args):
            pass

    def advertise(enable):
        command([str(cli), "set", "--config", str(cfg), "--advertise-exit-node", str(enable).lower()])

    command(["sudo", "-n", "ip", "address", "add", addr_arg, "dev", "lo"])
    try:
        with http.server.HTTPServer((str(addr), port), Handler) as server:
            server.timeout = 1
            try:
                if not originally_advertised:
                    advertise(True)
                print("READY", flush=True)
                until = time.monotonic() + 285
                while time.monotonic() < until:
                    readable, _, _ = select.select([sys.stdin, server], [], [], 1)
                    if sys.stdin in readable:
                        break
                    if server in readable:
                        server.handle_request()
            finally:
                if not originally_advertised:
                    advertise(False)
    finally:
        command(["sudo", "-n", "ip", "address", "del", addr_arg, "dev", "lo"])
    restored = tomllib.loads(cfg.read_text())
    require(bool(restored["node"].get("advertise_exit_node", False)) == originally_advertised
            and not any(entry["local"] == str(addr) for link in json.loads(command(["ip", "-j", "-4", "address"]))
                        for entry in link.get("addr_info", [])), "Provider cleanup incomplete")
    print(json.dumps(dict(matched=matched, restored=True)), flush=True)


def test(args):
    cli = json.loads(args.receipt.read_bytes())["artifacts"]["cli"]["sha256"]
    opts = dict(provider=args.provider, android=args.android, network=args.network, cliSha256=cli,
                address="198.18.245.6", port=17853, challenge=secrets.token_hex(16))
    args.output.mkdir(mode=0o700)
    remote_code = Path(__file__).read_text()
    def interrupt(sig, frame):
        raise InterruptedError("Private exit check interrupted")
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupt)
    with (args.output / "provider.log").open("x") as remote_log:
        ssh = subprocess.Popen(["ssh", "-oBatchMode=yes", "-oConnectTimeout=8", "-oServerAliveInterval=10",
                                "-oServerAliveCountMax=2", args.host,
                                shlex.join(["python3", "-u", "-c", remote_code, "--serve"])],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=remote_log, text=True)
        try:
            ssh.stdin.write(json.dumps(opts) + "\n")
            ssh.stdin.flush()
            require(select.select([ssh.stdout], [], [], 32)[0] and ssh.stdout.readline().strip() == "READY",
                    "Paired Linux provider did not become ready")
            with (args.output / "android.log").open("x") as log:
                cmd = ["bash", str(Path(__file__).with_name("test-android-private-exit.sh")),
                       args.provider, opts["challenge"], opts["address"], str(opts["port"]), str(args.output / "phone")]
                phone = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    require(phone.wait(timeout=200) == 0, "Android private exit test failed")
                finally:
                    if phone.poll() is None:
                        os.killpg(phone.pid, signal.SIGTERM)
                        try:
                            phone.wait(timeout=45)
                        except subprocess.TimeoutExpired:
                            os.killpg(phone.pid, signal.SIGKILL)
                            phone.wait(timeout=5)
        finally:
            ssh.stdin.close()
            shutdown = ssh.stdout.read() if select.select([ssh.stdout], [], [], 35)[0] else ""
            ssh.wait(timeout=15)
            (args.output / "provider-result.log").write_text(shutdown)
        require(ssh.returncode == 0 and json.loads(shutdown) == dict(matched=True, restored=True),
                "Provider did not confirm receipt and restore its original state")
    markers = (args.output / "android.log").read_text().splitlines()
    require(all(markers.count("NVPN_ANDROID_PRIVATE_EXIT_" + m + "=1") == 1
                for m in ("VISIBLE", "TRAFFIC_VERIFIED", "DIRECT_RESTORED")), "Incomplete Android picker evidence")
    image = (args.output / "phone/before-selection.png").read_bytes()
    require(image.startswith(b"\x89PNG\r\n\x1a\n"), "Missing preselection screenshot")
    result = dict(passed=True, screenshotSha256=hashlib.sha256(image).hexdigest(),
                  challengeSha256=hashlib.sha256(opts["challenge"].encode()).hexdigest(),
                  providerObservedFreshRequest=True, directRestored=True, providerRestored=True)
    (args.output / "acceptance.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1:] == ["--serve"]:
        serve()
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        for option in ("host", "provider", "android", "network"):
            parser.add_argument("--" + option, required=True)
        for option in ("receipt", "output"):
            parser.add_argument("--" + option, required=True, type=Path)
        test(parser.parse_args())
