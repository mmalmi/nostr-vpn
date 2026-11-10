#!/usr/bin/env python3
"""Exercise imported-app launch ownership with real local fixture processes."""
import os
import pathlib
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent
REMOTE = (ROOT / "macos-release-mobile-join-remote.sh").read_text()
FUNCTIONS = "\n".join(re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", REMOTE,
    re.M | re.S)[0] for name in ("launch_app", "stop_app"))

with tempfile.TemporaryDirectory(prefix="nvpn-launch-services-") as temporary:
    root = pathlib.Path(temporary).resolve()
    name = "NvLs" + str(os.getpid())
    executable = root / name
    subprocess.run(["xcrun", "clang", "-x", "c", "-", "-o", str(executable)],
        input="#include <unistd.h>\nint main(void) { for (;;) pause(); }\n",
        text=True, check=True, capture_output=True, timeout=15)
    foreign = root / "foreign-bin" / name
    foreign.parent.mkdir()
    foreign.write_bytes(executable.read_bytes())
    foreign.chmod(0o700)
    launcher = root / "launcher.py"
    launcher.write_text('''import os,pathlib,signal,subprocess,sys,time
case,executable,foreign,records=sys.argv[1:5]
assert sys.argv[5]=='-c'
code=sys.argv[6];sys.argv=['-c',*sys.argv[7:]]
def launch(argv,timeout,check):
 assert argv[0:3]==['/usr/bin/open','-n','-F'] and check and 0<timeout<=10
 environment={};index=3
 while argv[index]=='--env':
  key,value=argv[index+1].split('=',1);environment[key]=value;index+=2
 assert set(environment)=={'HOME','USER','LOGNAME','PATH','TMPDIR','LANG','NVPN_APP_DATA_DIR'}
 assert environment['PATH']=='/usr/bin:/bin:/usr/sbin:/sbin' and environment['NVPN_APP_DATA_DIR']
 assert argv[index]=='--stdout' and argv[index+2]=='--stderr' and len(argv)==index+5
 with open(records+'.calls','a') as output:output.write('open\\n')
 if case=='expired':
  time.sleep(timeout-.1)
  return subprocess.CompletedProcess(argv,0)
 for _ in range(2 if case=='multiple' else 1):
  child=subprocess.Popen([foreign if case=='foreign' else executable],
   start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  with open(records+'.pids','a') as output:output.write(str(child.pid)+'\\n')
 time.sleep(.05)
 if case=='open-failure':raise subprocess.CalledProcessError(1,argv)
 if case=='term':os.kill(os.getppid(),signal.SIGTERM)
 return subprocess.CompletedProcess(argv,0)
subprocess.run=launch
exec(code)
''')
    for case in ("success", "foreign", "multiple", "open-failure", "term", "expired", "write-failure"):
        directory = root / case
        directory.mkdir()
        owner = directory / "owner"
        records = directory / "launch"
        script = f'''set -euo pipefail
source {shlex.quote(str(ROOT / "lib-macos-release-app-ownership.sh"))}
{FUNCTIONS}
MACOS_RELEASE_APP_STATE_DIR={shlex.quote(str(owner))}
MACOS_RELEASE_APP_INSTALLED_EXE=unused-baseline
MACOS_RELEASE_APP_GATE_EXE={shlex.quote(str(executable))}
MACOS_RELEASE_APP_PROCESS_NAME={name}
APP_EXE={shlex.quote(str(executable))}
APP_PATH={shlex.quote(str(root / "Fixture.app"))}
APP_LOG={shlex.quote(str(directory / "app.log"))}
TEST_CONFIG_DIR={shlex.quote(str(directory / "data"))}
IMPORT_VERIFIED={shlex.quote(str(directory / "verified"))}
touch "$IMPORT_VERIFIED"
OWNED_PID_FILE="$MACOS_RELEASE_APP_STATE_DIR/imported.pid"
LAUNCH_PENDING_FILE="$MACOS_RELEASE_APP_STATE_DIR/imported-launch-pending"
APP_PID=""
APP_STOP_UNRESOLVED=0
APP_LAUNCH_PENDING=0
python3() {{ command {shlex.quote(sys.executable)} {shlex.quote(str(launcher))} \
 {shlex.quote(case)} {shlex.quote(str(executable))} {shlex.quote(str(foreign))} \
 {shlex.quote(str(records))} "$@"; }}
trap 'status=$?; stop_app || status=125; exit "$status"' EXIT
trap 'exit 143' TERM
'''
        if case == "write-failure":
            script += 'mv() { [[ "$2" != "$OWNED_PID_FILE" ]] || return 1; command mv "$@"; }\n'
        script += 'launch_app\n'
        if case == "success":
            script += '''[[ "$APP_PID" == "$(cat "$OWNED_PID_FILE")" ]]
[[ "$APP_LAUNCH_PENDING" == 0 && ! -e "$LAUNCH_PENDING_FILE" ]]
'''
        started = time.monotonic()
        try:
            result = subprocess.run(["bash", "-c", script], capture_output=True,
                                    text=True, timeout=16)
            assert result.returncode == (0 if case == "success" else 125), (
                case, result.returncode, result.stdout, result.stderr)
            assert records.with_suffix(".calls").read_text() == "open\n"
            if case == "expired":
                assert 8 <= time.monotonic() - started <= 12
            if case == "success":
                assert not (owner / "imported.pid").exists()
            else:
                assert (owner / "imported-launch-pending").exists()
                # A separate restoration and another launch both refuse this
                # retained uncertainty, even after the first shell has exited.
                repeat = script.split("trap 'status=$?", 1)[0] + '''
if launch_app; then exit 90; fi
if macos_release_app_restore; then exit 91; else [[ "$?" == 125 ]]; fi
'''
                repeated = subprocess.run(["bash", "-c", repeat], capture_output=True,
                                          text=True, timeout=3)
                assert repeated.returncode == 0, (case, repeated.stderr)
                assert records.with_suffix(".calls").read_text() == "open\n"
                assert (owner / "acquired").exists()
        finally:
            pids = records.with_suffix(".pids")
            for value in pids.read_text().splitlines() if pids.exists() else []:
                pid = int(value)
                try:
                    os.killpg(pid, signal.SIGTERM)
                except ProcessLookupError:
                    continue
                except PermissionError:
                    pass
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    try:
                        os.killpg(pid, 0)
                    except ProcessLookupError:
                        break
                    except PermissionError:
                        # Retain uncertainty on EPERM; only ESRCH proves absence.
                        pass
                    time.sleep(.02)
                else:
                    raise AssertionError("exact local fixture group did not close")
        print("launch ownership case passed:", case)

print("Imported launch ownership: 7 focused cases passed; real fixture groups closed; LaunchServices command stubbed, no GUI/VM/device use")
