#!/usr/bin/env python3
"""Exercise production CPU evidence binding and reject altered measurement inputs."""
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load("cpu_verifier", "verify-ios-release-gate-cpu.py")
trace = load("cpu_trace", "ios-release-gate-cpu-trace.py")


class ProductionCpuEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "qualification").mkdir()
        (self.root / "trace").mkdir()
        app = self.root / "app"
        app.mkdir()
        (app / "fixture").write_text("synthetic test artifact")
        tree = verifier.tree_sha256(app)
        device = hashlib.sha256(b"fixture-device").hexdigest()
        self.args = SimpleNamespace(receipt=self.root / "acceptance.json",
                                    artifact_receipt=self.root / "artifact.json", app=app,
                                    app_git_sha="a" * 40, fips_git_sha="b" * 40)
        artifact = {"receiptSchema": 2, "artifactType": "iOS company Ad Hoc Release app",
                    "appGitSha": self.args.app_git_sha, "fipsGitSha": self.args.fips_git_sha,
                    "companySigningVerified": True, "debuggable": False,
                    "appBundleTreeSha256": tree, "selectedPhysicalDeviceIdentifierSha256": device}
        self.write("artifact.json", artifact)
        self.write("qualification/validated-production-export.json", {"fixture": True})
        self.inputs = {**artifact, "productionArtifactValidated": True,
                       "productionReceiptSha256": verifier.digest(self.args.artifact_receipt),
                       "frozenExportReceiptSha256": verifier.digest(self.root / "qualification/validated-production-export.json"),
                       "traceDeviceSha256": device}
        self.write("qualification/inputs.json", self.inputs)
        self.write("installed-production.json", {"installedAppVerified": True, "productionAppTreeSha256": tree})
        logs = {}
        for name in ["mesh-before.log", "mesh-after.log"]:
            (self.root / name).write_text("NVPN_RELEASE_JOIN_BOOTSTRAP_CONNECTED=3\nNVPN_RELEASE_JOIN_CLIENT_ONLY=0\nNVPN_RELEASE_JOIN_CARRIER_PREFLIGHT_READY=1\n")
            logs[name] = verifier.digest(self.root / name)
        self.mesh = {"publicMeshVerified": True, "sameTunnelPid": True, "pid": 123,
                     "publicPeerCountsBeforeAfter": [3, 3], "routingRoleObserved": True,
                     "clientOnlyBeforeAfter": [False, False], "logSha256": logs}
        self.write("public-mesh.json", self.mesh)
        toc = self.root / "trace/toc.xml"
        toc.write_text('<trace><run><info><target><device uuid="fixture-device" platform="iOS"/></target><summary><template-name>Activity Monitor</template-name><end-reason>Time limit reached</end-reason><start-date>2026-01-01T00:00:00Z</start-date></summary></info></run></trace>')
        columns = ["time", "pid", "process", "recently-died", "cpu-total-system", "cpu-total-user"]
        rows = []
        for n in range(13):
            process = '<process id="p" fmt="Nostr VPN Tunnel (123)"/>' if n == 0 else '<process ref="p"/>'
            rows.append(f'<row><time>{n * 5_000_000_000}</time><pid>123</pid>{process}<bool>0</bool><cpu>0</cpu><cpu>{n * 75_000_000}</cpu></row>')
        xml = self.root / "trace/sysmon.xml"
        xml.write_text('<table><schema name="sysmon-process">' + ''.join('<col><mnemonic>' + c + '</mnemonic></col>' for c in columns) + '</schema>' + ''.join(rows) + '</table>')
        self.measured = {"pid": 123, "deviceSha256": device, "xmlSha256": verifier.digest(xml),
                         "tocSha256": verifier.digest(toc), **trace.analyze(SimpleNamespace(xml=xml, toc=toc, pid=123, process_name="Nostr VPN Tunnel", device_sha256=device))}
        self.write("trace/cpu-measurement.json", self.measured)
        self.recording = {"wrapperComplete": True, "exitCode": 0, "sameTunnelPidBeforeAfter": True,
                          "recordSeconds": 120, "expectedPid": 123, "deviceSha256": device,
                          "cpu": self.measured, "commands": [{"step": s, "exitCode": 0} for s in ["processes-before", "record", "processes-after", "export-toc", "export-cpu", "analyze"]]}
        self.write("trace/recording.json", self.recording)
        self.accepted = {"scope": "signed-production-iphone-idle-cpu", "releaseAcceptanceProven": True,
                         "exitCode": 0, "cleanupExitCode": 0, **artifact,
                         "clientOnlyBeforeAfter": [False, False], "cpuPercent": self.measured["cpuPercent"],
                         "sampleSeconds": self.measured["elapsedSeconds"]}
        self.seal()

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def seal(self):
        self.accepted["evidenceSha256"] = {n: verifier.digest(self.root / n) for n in ["qualification/inputs.json", "installed-production.json", "public-mesh.json", "trace/recording.json", "trace/cpu-measurement.json"]}
        self.write("acceptance.json", self.accepted)

    def test_valid_production_trace(self):
        self.assertEqual(verifier.validate(self.args)["cpuPercent"], 1.5)

    def test_wrong_source(self):
        for key in ["app_git_sha", "fips_git_sha"]:
            args = copy.copy(self.args)
            setattr(args, key, "f" * 40)
            with self.subTest(key=key), self.assertRaises(ValueError):
                verifier.validate(args)

    def test_mesh_log_key_order_does_not_change_chronology(self):
        self.mesh["logSha256"] = dict(reversed(list(self.mesh["logSha256"].items())))
        self.write("public-mesh.json", self.mesh)
        self.seal()
        self.assertTrue(verifier.validate(self.args)["passed"])

    def high_cpu(self):
        xml = self.root / "trace/sysmon.xml"
        xml.write_text(xml.read_text().replace("900000000</cpu>", "1500000000</cpu>"))
        self.measured.update(trace.analyze(SimpleNamespace(xml=xml, toc=self.root / "trace/toc.xml", pid=123,
                                                         process_name="Nostr VPN Tunnel", device_sha256=self.inputs["traceDeviceSha256"])))
        self.measured["xmlSha256"] = verifier.digest(xml)
        self.recording["cpu"] = self.measured
        self.recording["exitCode"] = 1
        self.recording["commands"][-1]["exitCode"] = 1
        self.accepted["cpuPercent"] = self.measured["cpuPercent"]
        self.accepted.update(exitCode=1, releaseAcceptanceProven=False)
        self.write("trace/cpu-measurement.json", self.measured)
        self.write("trace/recording.json", self.recording)
        self.seal()

    def cpu_exception(self):
        self.args.release_commit = "c" * 40
        self.args.release_version = "4.1.19"
        self.args.release_exception = self.root / "exception.json"
        self.exception = {"scope": "ios-idle-cpu-release-exception",
                          "decision": "accept-known-cpu-issue",
                          "releaseCommit": self.args.release_commit,
                          "releaseVersion": self.args.release_version,
                          "measurementReceiptSha256": verifier.digest(self.args.receipt),
                          "artifactReceiptSha256": verifier.digest(self.args.artifact_receipt),
                          "appBundleTreeSha256": self.inputs["appBundleTreeSha256"],
                          "cpuPercent": self.measured["cpuPercent"], "thresholdPercent": 2,
                          "authorization": "Explicit test release-owner decision"}
        self.write("exception.json", self.exception)

    def test_cpu_over_threshold(self):
        self.high_cpu()
        with self.assertRaises(ValueError):
            verifier.validate(self.args)

    def test_explicit_exception_preserves_failed_measurement(self):
        self.high_cpu()
        self.cpu_exception()
        before = self.args.receipt.read_bytes()
        result = verifier.validate(self.args)
        self.assertFalse(result["passed"])
        self.assertTrue(result["releaseAccepted"])
        self.assertEqual(result["cpuPercent"], 2.5)
        self.assertEqual(result["releaseExceptionSha256"], verifier.digest(self.args.release_exception))
        self.assertEqual(self.args.receipt.read_bytes(), before)

    def test_exception_cannot_cover_another_release_or_measurement(self):
        self.high_cpu()
        self.cpu_exception()
        for key in self.exception:
            changed = {**self.exception, key: ""}
            self.write("exception.json", changed)
            with self.subTest(key=key), self.assertRaises(ValueError):
                verifier.validate(self.args)

    def test_exception_cannot_waive_capture_or_cleanup_failure(self):
        self.high_cpu()
        for target in [self.recording["commands"][0], self.recording["commands"][-1], self.accepted]:
            key = "cleanupExitCode" if target is self.accepted else "exitCode"
            old = target[key]
            target[key] = 2
            self.write("trace/recording.json", self.recording)
            self.seal()
            self.cpu_exception()
            with self.subTest(key=key), self.assertRaises(ValueError):
                verifier.validate(self.args)
            target[key] = old

    def test_exception_cannot_waive_changed_artifact_or_forged_cpu(self):
        self.high_cpu()
        self.cpu_exception()
        (self.args.app / "fixture").write_text("different product")
        with self.assertRaises(ValueError):
            verifier.validate(self.args)
        (self.args.app / "fixture").write_text("synthetic test artifact")
        self.measured["cpuPercent"] = 0.01
        self.accepted["cpuPercent"] = 0.01
        self.write("trace/cpu-measurement.json", self.measured)
        self.write("trace/recording.json", self.recording)
        self.seal()
        self.cpu_exception()
        with self.assertRaises(ValueError):
            verifier.validate(self.args)

    def test_changed_evidence_and_artifact(self):
        for name in ["public-mesh.json", "trace/sysmon.xml", "trace/toc.xml", "app/fixture"]:
            path = self.root / name
            old = path.read_bytes()
            path.write_bytes(old + b" ")
            with self.subTest(name=name), self.assertRaises(ValueError):
                verifier.validate(self.args)
            path.write_bytes(old)

    def test_failed_cleanup(self):
        self.accepted["cleanupExitCode"] = 1
        self.seal()
        with self.assertRaises(ValueError):
            verifier.validate(self.args)

    def test_no_public_peers_even_with_resealed_receipt(self):
        self.mesh["publicPeerCountsBeforeAfter"] = [0, 0]
        self.write("public-mesh.json", self.mesh)
        self.seal()
        with self.assertRaises(ValueError):
            verifier.validate(self.args)

    def test_forged_low_cpu_is_recomputed(self):
        self.measured["cpuPercent"] = 0.01
        self.recording["cpu"] = self.measured
        self.accepted["cpuPercent"] = 0.01
        self.write("trace/cpu-measurement.json", self.measured)
        self.write("trace/recording.json", self.recording)
        self.seal()
        with self.assertRaises(ValueError):
            verifier.validate(self.args)


if __name__ == "__main__":
    unittest.main()
