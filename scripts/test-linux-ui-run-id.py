#!/usr/bin/env python3
"""Exercise run-id guards and SSH argument parsing without a remote host."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
WRAPPERS = ("ubuntu-vm-manual-join-e2e.sh", "ubuntu-vm-service-toggle-e2e.sh")


class RunId(unittest.TestCase):
    def test_default_and_valid_ids_survive_ssh_remote_shell_parsing(self):
        for name in WRAPPERS:
            source = (ROOT / "scripts" / name).read_text()
            host = source.split("# shellcheck disable=SC1091", 1)[0]
            guest = source.split("<<'GUEST'\n", 1)[1].split('cd "$repo"', 1)[0]
            with tempfile.TemporaryDirectory() as temporary:
                script = Path(temporary) / "host.sh"
                script.write_text(host + '\nprintf "%s" "$RUN_ID"\n')
                for value in ("", "release-421-platform-1", "run.a_2"):
                    with self.subTest(wrapper=name, value=value):
                        env = {**os.environ, "NVPN_UBUNTU_SSH_HOST": "unused",
                               "NVPN_UBUNTU_UI_RUN_ID": value}
                        result = subprocess.run(["bash", str(script)], env=env,
                                                capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, value)
                        # OpenSSH joins command arguments into remote shell text;
                        # an empty last argument disappears during that parse.
                        command = "bash -s -- /repo /app /cli /fixture " + value
                        result = subprocess.run(["bash", "-c", command],
                            input=guest + '\nprintf "%s" "$run_id"\n',
                            capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, value)

    def test_malformed_ids_are_rejected_on_host_before_import_or_ssh(self):
        for name in WRAPPERS:
            source = (ROOT / "scripts" / name).read_text()
            host = source.split("# shellcheck disable=SC1091", 1)[0]
            with tempfile.TemporaryDirectory() as temporary:
                script = Path(temporary) / "host.sh"
                script.write_text(host + '\nprintf REACHED_IMPORT\n')
                for value in ("two words", "a/b", "a;false", "$(false)",
                              "a`false`", "a\nb", "-leading", "a" * 65):
                    with self.subTest(wrapper=name, value=value):
                        result = subprocess.run(["bash", str(script)],
                            env={**os.environ, "NVPN_UBUNTU_SSH_HOST": "unused",
                                 "NVPN_UBUNTU_UI_RUN_ID": value},
                            capture_output=True, text=True)
                        self.assertEqual(result.returncode, 2)
                        self.assertNotIn("REACHED_IMPORT", result.stdout)

    def test_cleanup_matches_literal_directory_and_component_boundary(self):
        source = (ROOT / "linux/scripts/e2e-manual-join-ui.sh").read_text()
        stop = source[source.index("stop_app() {"):source.index("cleanup() {")]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "pattern"
            root = "/tmp/nostr-vpn-linux-manual-join-ui-run.a"
            script = 'app_pid=""\nwindow_id=""\n' + stop + '''
pkill() { printf '%s' "$2" >"$PATTERN_FILE"; }
stop_app
'''
            subprocess.run(["bash", "-c", script], check=True,
                env={**os.environ, "E2E_ROOT": root, "PATTERN_FILE": str(output)})
            pattern = output.read_text()
            self.assertRegex("nvpn daemon --config " + root + "/admin/config.toml", pattern)
            for other in (root + "-other", root.replace("run.a", "runXa")):
                self.assertIsNone(re.search(pattern, "nvpn --config " + other + "/admin/config.toml"))


if __name__ == "__main__":
    unittest.main()
