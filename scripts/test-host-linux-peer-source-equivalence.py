#!/usr/bin/env python3
"""Exercise the real peer verifier and canonical Git component proof."""
import hashlib
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERIFIER = ROOT / 'scripts/verify-host-linux-peer-artifact.py'

def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()

# Existing history: Windows-only enrollment correction versus its accepted base.
old = '4cf000e99c83eaa739e38a900304b60098643635'
new = '0f7232e145f6317c7f1bbd91cde6ca4214ca3934'
fips = 'f98d97e42dfa48d5fed344c43caa9ebd27b01229'
with tempfile.TemporaryDirectory(prefix='peer-source-proof-') as temp:
    folder = pathlib.Path(temp)
    binary = folder / 'peer'
    binary.write_bytes(b'fixture immutable peer payload')
    binary.chmod(0o555)
    receipt = folder / 'receipt.json'
    base = dict(schema=1, appGitSha=old, appGitTree=git('rev-parse', old+'^{tree}'),
                fipsGitSha=fips, fipsGitTree='dcb1c6d80de1e28a0f442e30cba8ddadb15dc581',
                fipsVersion='0.4.107', target='x86_64-unknown-linux-musl',
                binarySize=binary.stat().st_size, binarySha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                builtOnHostMac=False, builtOnRemoteVm=True, builtOnMacosUtm=False,
                buildExecutionHostClass='remote-linux-builder')
    def check(label, data, candidate=new, root=True, passed=False):
        receipt.write_text(json.dumps(data))
        before = receipt.read_bytes()
        command = ['python3', str(VERIFIER), str(receipt), str(binary), candidate,
                   git('rev-parse', candidate+'^{tree}'), fips, base['fipsGitTree'],
                   '0.4.107', base['target']]
        if root:
            command.append(str(ROOT))
        result = subprocess.run(command, capture_output=True, text=True)
        assert (result.returncode == 0) == passed, (label, result.stderr)
        assert receipt.read_bytes() == before, 'Verifier must never relabel receipt'
        print('PASS', label)
    check('exact source', base, candidate=old, root=False, passed=True)
    check('Windows-only changes retain original Linux source', base, passed=True)
    check('missing candidate root', base, root=False)
    check('mismatched source tree', {**base, 'appGitTree':'0'*40})
    check('binary hash tamper', {**base, 'binarySha256':'0'*64})
    check('FIPS revision mismatch', {**base, 'fipsGitSha':'0'*40})
    earlier='5c1b2f0606f18387ace32f5712dde9b63a274620'
    check('real Linux product changes rejected', {**base, 'appGitSha':earlier,
          'appGitTree':git('rev-parse', earlier+'^{tree}')})
