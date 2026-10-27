#!/usr/bin/env python3
"""Exercise canonical build commands with fake tools; no compiler or container."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
payload = (ROOT / 'scripts/build-host-linux-vm-bundle-in-container.sh').read_text()
# Keep the actual argument parser and build/verification sequence. Source/lock
# admission has its own existing fixture harness; substitute only mount paths.
parser = payload[:payload.index('cd /workspace/app')]
build = payload.split('export CARGO_NET_OFFLINE=true\n', 1)[1].split('# Package the already-built', 1)[0]

with tempfile.TemporaryDirectory(prefix='nvpn-linux-scope-') as directory:
    root = Path(directory)
    tools = root / 'tools'
    tools.mkdir()
    (root / 'app/linux').mkdir(parents=True)
    target = root / 'target'
    for relative in ('release/nvpn', 'release/nostr-vpn',
                     'release/examples/desktop_manual_join_e2e_fixture',
                     'x86_64-unknown-linux-musl/release/nvpn'):
        artifact = target / relative
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text('#!/bin/sh\necho "nvpn 1.2.3 (rev fixture)"\n')
        artifact.chmod(0o755)
    mock = '''#!/usr/bin/env python3
import json,os,pathlib,sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['MOCK_CALLS'],'a') as log:
    log.write(json.dumps([name,*args])+'\\n')
if name=='file':
    for path in args: print(path+': ELF 64-bit LSB executable, x86-64, statically linked')
elif name=='rustc': print('rustc 1.95.0 (fixture)')
elif name=='cargo' and args==['--version']: print('cargo 1.95.0 (fixture)')
elif name not in {'cargo','file','rustc'}: sys.exit(99)
'''
    for name in ('cargo', 'rustc', 'file', 'docker', 'ssh'):
        path = tools / name
        path.write_text(mock)
        path.chmod(0o755)
    commands = {}
    for scope in ('default', 'full', 'daemon'):
        for retained in ('0', '1'):
            output = root / f'output-{scope}-{retained}'
            output.mkdir()
            log = root / f'calls-{scope}-{retained}.jsonl'
            script = parser + "fips_config=(--config 'patch.fixture.path=\"/fixture\"')\n" + build + '\nprintf "PACKAGING_REACHED\\n"\n'
            for before, after in (('/workspace/app', root / 'app'),
                                  ('/target-root', target), ('/output', output)):
                script = script.replace(before, str(after))
            result = subprocess.run(
                ['/bin/bash', '-c', script, 'payload', 'build', *([] if scope == 'default' else [scope])],
                text=True, capture_output=True, env={**os.environ,
                    'PATH': str(tools) + ':' + os.environ['PATH'],
                    'MOCK_CALLS': str(log), 'NVPN_HOST_LINUX_VM_RETAIN_TARGET': retained})
            assert result.returncode == 0, (scope, retained, result.stdout, result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            commands[scope, retained] = calls
            builds = [call for call in calls if call[0] == 'cargo' and 'build' in call]
            assert len(builds) == (2 if scope == 'daemon' else 4), calls
            assert builds[:2] == [
                ['cargo', '--config', 'patch.fixture.path="/fixture"', 'build', '--frozen', '--release', '-p', 'nvpn'],
                ['cargo', '--config', 'patch.fixture.path="/fixture"', 'build', '--frozen', '--release', '--target', 'x86_64-unknown-linux-musl', '-p', 'nvpn']], builds
            assert ('PACKAGING_REACHED' in result.stdout) == (scope != 'daemon')
            assert any('check' in call for call in calls) == (scope != 'daemon')
            assert any('clean' in call for call in calls) == (scope != 'daemon' and retained == '0')
            binaries = {'nvpn', 'nvpn-x86_64-unknown-linux-musl'}
            if scope != 'daemon':
                binaries |= {'nostr-vpn', 'desktop_manual_join_e2e_fixture'}
            assert {path.name for path in output.iterdir() if os.access(path, os.X_OK)} == binaries
            for other_scope in ('default', 'full', 'daemon'):
                previous = commands.get((other_scope, '0'))
                if previous:
                    assert [c for c in previous if c[0] == 'cargo' and 'build' in c][:2] == builds[:2]
    assert [c for c in commands['default', '0'] if c[0] == 'cargo'] == [c for c in commands['full', '0'] if c[0] == 'cargo']
print('PASS canonical full/default/daemon command selection, matching daemon compiler flags, output sets and packaging exclusion (mock tools only)')
