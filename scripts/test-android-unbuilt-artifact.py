#!/usr/bin/env python3
"""Exercise sealed APK source reuse against real Git product/harness changes."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent

class AndroidArtifactSource(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nvpn-android-source-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Release fixture")
        (self.root/"scripts").mkdir()
        shutil.copyfile(SCRIPTS/"release-component-source.mjs", self.root/"scripts/release-component-source.mjs")
        (self.root/"scripts/lib-mobile-android-release-gate.sh").write_text("# original harness\n")
        (self.root/"Cargo.toml").write_text("# original product\n")
        self.commit()
        self.receipt = {"schema": 1, "relationship": "universal-apk-derived-from-exact-aab",
            "appGitSha": self.git("rev-parse", "HEAD"), "appGitTree": self.git("rev-parse", "HEAD^{tree}"),
            "bundletoolVersion": "1.18.3", "bundletoolSha256": "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"}
        self.bundle = self.root/"android/app/build/outputs/bundle/release"
        self.bundle.mkdir(parents=True)
        self.apk = self.root/"release.apk"
        for name,path in [("aab", self.bundle/"app-release.aab"), ("apk", self.apk)]:
            path.write_bytes(name.encode())
            self.receipt[name+"Sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            self.receipt[name+"PathSha256"] = hashlib.sha256(str(path.resolve()).encode()).hexdigest()
        self.output = self.root/"evidence"
        self.output.mkdir()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def commit(self):
        self.git("add", "scripts", "Cargo.toml")
        self.git("commit", "-qm", "fixture")

    def run_source(self, success):
        (self.bundle/"physical-gate-artifact.json").write_text(json.dumps(self.receipt))
        command = 'source "$1"; ROOT="$2"; APK_PATH="$3"; RUNTIME_STATE_RESULT_DIR="$4"; ANDROID_RELEASE_HARNESS_GIT_HEAD="$5"; ANDROID_RELEASE_HARNESS_GIT_TREE="$6"; android_release_load_unbuilt_source'
        result = subprocess.run(["bash", "-c", command, "fixture", str(SCRIPTS/"lib-mobile-android-release-gate.sh"), str(self.root), str(self.apk), str(self.output), self.git("rev-parse", "HEAD"), self.git("rev-parse", "HEAD^{tree}")], capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        if success:
            proof = json.loads((self.output/"android-component-proof.json").read_text())
            self.assertEqual(proof["receipt_app_git_sha"], self.receipt["appGitSha"])

    def test_same_product(self): self.run_source(True)
    def test_harness_change(self):
        (self.root/"scripts/lib-mobile-android-release-gate.sh").write_text("# changed harness\n")
        self.commit(); self.run_source(True)
    def test_product_change(self):
        (self.root/"Cargo.toml").write_text("# changed product\n")
        self.commit(); self.run_source(False)
    def test_binary_change(self):
        self.apk.write_bytes(b"other"); self.run_source(False)
    def test_wrong_tree(self):
        self.receipt["appGitTree"] = "0"*40; self.run_source(False)
    def test_wrong_tool(self):
        self.receipt["bundletoolSha256"] = "0"*64; self.run_source(False)
    def test_wrong_path(self):
        self.receipt["apkPathSha256"] = "0"*64; self.run_source(False)

if __name__ == "__main__": unittest.main()
