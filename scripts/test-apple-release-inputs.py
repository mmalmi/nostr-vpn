#!/usr/bin/env python3
"""Exercise source admission against a real isolated Git repository."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "apple_inputs", Path(__file__).with_name("build-apple-release-inputs.py"))
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class SourceAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "test@example.invalid")
        (self.root / "source").write_text("exact input\n")
        self.git("add", "source")
        self.git("commit", "-qm", "Fixture")
        self.head = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        context = patch.dict(os.environ, APP_COMMIT=self.head, APP_TREE=self.tree)
        context.start()
        self.addCleanup(context.stop)

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def test_exact_committed_source_is_accepted(self):
        self.assertEqual(producer.exact_source(self.root, "APP"),
                         {"commit": self.head, "tree": self.tree})

    def test_different_identity_is_rejected(self):
        for key in ("APP_COMMIT", "APP_TREE"):
            with self.subTest(key=key), patch.dict(os.environ, {key: "0" * 40}):
                with self.assertRaises(AssertionError):
                    producer.exact_source(self.root, "APP")

    def test_changed_and_untracked_source_are_rejected(self):
        (self.root / "source").write_text("unreviewed input\n")
        with self.assertRaises(AssertionError):
            producer.exact_source(self.root, "APP")
        (self.root / "source").write_text("exact input\n")
        (self.root / "untracked").write_text("extra input\n")
        with self.assertRaises(AssertionError):
            producer.exact_source(self.root, "APP")


if __name__ == "__main__":
    unittest.main()
