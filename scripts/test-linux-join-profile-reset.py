#!/usr/bin/env python3
"""A release gate must never reset an existing user's Linux identity."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "linux_join_driver", Path(__file__).with_name("desktop-mobile-manual-join-atspi.py"))
driver = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"pyatspi": types.ModuleType("pyatspi")}):
    spec.loader.exec_module(driver)


class ProfileReset(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.artifacts = self.home / "gate"
        self.artifacts.mkdir()
        self.profile = self.home / ".config/nvpn"
        self.owner = self.artifacts / "canonical-profile.json"
        self.env = patch.dict(os.environ, {"HOME": str(self.home)}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.stop = patch.object(driver, "stop_exact_app_instances")
        self.stop.start()
        self.addCleanup(self.stop.stop)
        self.subject = driver.Driver(argparse.Namespace(
            app=self.home / "app", marker=self.artifacts / "action.json",
            stop_path=None, artifact_root=self.artifacts, mode="Reset"))

    def make_profile(self):
        self.profile.mkdir(parents=True, exist_ok=True)
        (self.profile / "config.toml").write_text("existing identity")

    def test_first_reset_claims_empty_path_and_second_removes_only_its_profile(self):
        self.subject.reset()
        self.assertEqual(json.loads(self.owner.read_text())["path"], str(self.profile))
        self.make_profile()
        self.subject.reset()
        self.assertTrue(self.profile.is_dir())
        self.assertFalse((self.profile / "config.toml").exists())
        driver.manage_profile(self.profile, self.owner, cleanup=True)
        self.assertFalse(self.profile.exists())
        driver.manage_profile(self.profile, self.owner, cleanup=True)

    def test_existing_identity_is_preserved_without_ownership(self):
        self.make_profile()
        with self.assertRaisesRegex(RuntimeError, "existing CLI profile"):
            self.subject.reset()
        self.assertEqual((self.profile / "config.toml").read_text(), "existing identity")
        self.assertFalse(self.owner.exists())

    def test_legacy_profile_is_preserved(self):
        legacy = self.home / ".local/share/nostr-vpn"
        legacy.mkdir(parents=True)
        with self.assertRaisesRegex(RuntimeError, "legacy desktop profile"):
            self.subject.reset()
        self.assertTrue(legacy.is_dir())

    def test_wrong_or_symlinked_ownership_cannot_authorize_reset(self):
        self.subject.reset()
        self.make_profile()
        proof = json.loads(self.owner.read_text())
        proof["path"] = str(self.home / "different")
        self.owner.write_text(json.dumps(proof))
        with self.assertRaisesRegex(RuntimeError, "ownership or parent identity changed"):
            self.subject.reset()
        self.owner.unlink()
        target = self.artifacts / "other"
        target.write_text(json.dumps(proof))
        self.owner.symlink_to(target)
        with self.assertRaises(OSError):
            self.subject.reset()
        self.assertTrue((self.profile / "config.toml").is_file())

    def test_symlinked_profile_is_preserved(self):
        target = self.home / "original"
        target.mkdir()
        self.profile.parent.mkdir()
        self.profile.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "symlinked"):
            self.subject.reset()
        self.assertTrue(target.is_dir())

    def test_nondefault_xdg_roots_are_rejected_before_mutation(self):
        for variable in ("XDG_CONFIG_HOME", "XDG_DATA_HOME"):
            for value in ("relative", str(self.home / "custom")):
                with self.subTest(variable=variable, value=value):
                    with patch.dict(os.environ, {variable: value}):
                        with self.assertRaisesRegex(RuntimeError, "default XDG roots"):
                            self.subject.reset()
                    self.assertFalse(self.owner.exists())

    def assert_foreign_profile_preserved(self):
        for cleanup in (False, True):
            with self.subTest(cleanup=cleanup):
                with self.assertRaises((RuntimeError, OSError)):
                    driver.manage_profile(self.profile, self.owner, cleanup=cleanup)
                self.assertEqual((self.profile / "config.toml").read_text(), "existing identity")

    def test_replaced_directory_at_same_path_cannot_be_reset_or_cleaned(self):
        self.subject.reset()
        self.profile.rename(self.home / "original-test-directory")
        self.make_profile()
        self.assert_foreign_profile_preserved()

    def test_replaced_parent_cannot_be_reset_or_cleaned(self):
        self.subject.reset()
        self.profile.parent.rename(self.home / "original-parent")
        self.make_profile()
        self.assert_foreign_profile_preserved()

    def test_symlinked_replacement_parent_cannot_be_reset_or_cleaned(self):
        self.subject.reset()
        parent = self.profile.parent
        parent.rename(self.home / "original-parent")
        target = self.home / "foreign-parent"
        target.mkdir()
        parent.symlink_to(target)
        self.make_profile()
        self.assert_foreign_profile_preserved()


if __name__ == "__main__":
    unittest.main()
