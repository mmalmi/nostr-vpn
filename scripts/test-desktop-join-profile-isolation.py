#!/usr/bin/env python3
"""Profile isolation must not relax join, platform or artifact acceptance."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('join_receipt', Path(__file__).with_name('desktop_mobile_manual_join_receipt.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProfileIsolation(unittest.TestCase):
    def setUp(self):
        self.desktop = {'appSha256': 'a' * 64, 'cliSha256': 'b' * 64}
        self.proof = {
            'schema': 1, 'kind': 'production-data-directory',
            'environmentKeys': ['NVPN_APP_DATA_DIR'], 'appArguments': [],
            'guiDirectorySha256': 'c' * 64, 'serviceDirectorySha256': 'c' * 64,
            'originalDirectorySha256': 'd' * 64,
            'originalBeforeSha256': 'e' * 64, 'originalAfterSha256': 'e' * 64,
            'originalProfileUnchanged': True, **self.desktop,
            'guiModes': ['AdminAdd', 'Bootstrap', 'CreateAdmin', 'ManualJoin', 'Verify', 'Verify'],
            'serviceInstallCount': 2,
        }
        self.proof['serviceCliSha256'] = self.proof.pop('cliSha256')
        self.evidence = {
            'schema': 1, 'platform': 'windows', 'publicUiOnly': True,
            'privateStateRead': False, 'fixtureInvoked': False,
            'appLaunchArgumentsOrEnvironment': True, 'profileIsolation': self.proof,
            'acceptedSelectorSemantics': 'participant-state-not-pending',
            'completionDeadlineSeconds': 15,
        }
        for role in module.ROLES:
            self.evidence[role] = {**dict.fromkeys(module.ROLE_FLAGS, True), 'deliveryMilliseconds': 100}

    def validate(self, evidence):
        return module.validate_phase_evidence(evidence, evidence['platform'], self.desktop)

    def test_accepts_exact_isolation_and_keeps_truthful_evidence(self):
        result = self.validate(self.evidence)
        self.assertIs(result['appLaunchArgumentsOrEnvironment'], True)
        self.assertEqual(result['profileIsolation'], self.proof)

    def test_default_windows_and_linux_remain_valid(self):
        for platform in ('windows', 'linux'):
            evidence = copy.deepcopy(self.evidence)
            evidence.update(platform=platform, appLaunchArgumentsOrEnvironment=False)
            del evidence['profileIsolation']
            self.assertIs(self.validate(evidence)['appLaunchArgumentsOrEnvironment'], False)

    def test_rejects_unbound_overrides_or_modified_original(self):
        for field, value in (
            ('environmentKeys', ['NVPN_APP_DATA_DIR', 'NVPN_CLI_PATH']),
            ('appArguments', ['--peer', 'injected']), ('serviceDirectorySha256', 'f' * 64),
            ('originalDirectorySha256', 'c' * 64), ('originalAfterSha256', 'f' * 64),
            ('originalProfileUnchanged', False), ('appSha256', 'f' * 64),
            ('serviceCliSha256', 'f' * 64), ('serviceInstallCount', 1),
            ('guiModes', ['ManualJoin']), ('originalBeforeSha256', 'invalid'),
            ('schema', True), ('unexpected', True),
        ):
            with self.subTest(field=field):
                evidence = copy.deepcopy(self.evidence)
                evidence['profileIsolation'][field] = value
                with self.assertRaises(ValueError): self.validate(evidence)

    def test_rejects_other_platform_injection_deadline_or_join_regression(self):
        for field, value in (('platform', 'linux'), ('privateStateRead', True),
                ('fixtureInvoked', True), ('appLaunchArgumentsOrEnvironment', False),
                ('completionDeadlineSeconds', 16), ('profileIsolation', None)):
            with self.subTest(field=field):
                evidence = copy.deepcopy(self.evidence)
                evidence[field] = value
                with self.assertRaises(ValueError): self.validate(evidence)
        for role in module.ROLES:
            for field in module.ROLE_FLAGS:
                evidence = copy.deepcopy(self.evidence)
                evidence[role][field] = False
                with self.assertRaises(ValueError): self.validate(evidence)
            evidence = copy.deepcopy(self.evidence)
            evidence[role]['deliveryMilliseconds'] = 15001
            with self.assertRaises(ValueError): self.validate(evidence)


if __name__ == '__main__': unittest.main()
