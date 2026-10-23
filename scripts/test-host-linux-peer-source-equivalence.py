#!/usr/bin/env python3
"""Exercise the real peer verifier and canonical Git component proof."""
import hashlib
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERIFIER = ROOT / 'scripts/verify-host-linux-peer-artifact.py'

with tempfile.TemporaryDirectory(prefix='peer-source-proof-') as temp:
    folder = pathlib.Path(temp)
    source = folder / 'source'
    source.mkdir()

    def git(*args):
        return subprocess.check_output(
            ['git', '-C', str(source), *args], text=True,
        ).strip()

    def commit(label):
        git('add', '.')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture.invalid',
            'commit', '-qm', label)
        return git('rev-parse', 'HEAD')

    git('init', '-q')
    (source / 'linux').mkdir()
    (source / 'linux/main.rs').write_text('fn main() {}\n')
    old = commit('Linux baseline')
    (source / 'windows').mkdir()
    (source / 'windows/Main.cs').write_text('// Windows-only change\n')
    new = commit('Windows-only change')
    (source / 'linux/main.rs').write_text('fn main() { println!("changed"); }\n')
    changed_linux = commit('Linux product change')
    fips = 'a' * 40
    binary = folder / 'peer'
    binary.write_bytes(b'fixture immutable peer payload')
    binary.chmod(0o555)
    receipt = folder / 'receipt.json'
    base = dict(schema=1, appGitSha=old, appGitTree=git('rev-parse', old+'^{tree}'),
                fipsGitSha=fips, fipsGitTree='b' * 40,
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
            command.append(str(source))
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
    check('real Linux product changes rejected', base, candidate=changed_linux)
