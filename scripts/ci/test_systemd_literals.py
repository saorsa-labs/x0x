#!/usr/bin/env python3
"""Run #729 readback against disposable systemd units; requires root Linux."""
import argparse, hashlib, json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path
from systemd_isolation import validate

TIMEOUT = 12
UNIT_ROOT = Path("/run/systemd/system")

def q(value, *, path=False):
    if any(ord(c) < 32 or ord(c) == 127 for c in value): raise ValueError("control character")
    out='"'
    for c in value:
        if c == '%': out += '%%'
        elif c == '$': out += '$' if path else '$$'
        elif c == '\\': out += '\\\\'
        elif c == '"': out += '\\"'
        else: out += c
    return out+'"'

def run(state, label, argv, *, ok=(0,)):
    started=time.monotonic()
    try:
        cp=subprocess.run(argv, text=True, capture_output=True, timeout=TIMEOUT)
        rc=cp.returncode
    except subprocess.TimeoutExpired as e:
        cp=e; rc=124
    def text(value):
        if isinstance(value, bytes): return value.decode('utf-8', errors='replace')
        return value or ''
    rec={"label":label,"argv":argv,"exit":rc,"seconds":time.monotonic()-started,
         "stdout":text(getattr(cp,'stdout','')),"stderr":text(getattr(cp,'stderr',''))}
    state["commands"].append(rec); save(state)
    if rc not in ok: raise RuntimeError(f"{label} exit {rc}")
    return rec

def save(state):
    path=Path(state["artifact"])/"receipt.json"; tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(state,indent=2)+"\n"); os.replace(tmp,path)

def wait_json(path, bound=30):
    end=time.monotonic()+bound
    while time.monotonic()<end:
        try: return json.loads(path.read_text())
        except (FileNotFoundError,json.JSONDecodeError): time.sleep(.05)
    raise TimeoutError(str(path))

def assert_first(case_name, first, expected, unit, literal, artifact):
    validate(first.get("isolation"))
    if first["verdict"] != expected:
        raise AssertionError((case_name, first))
    if case_name == "positive":
        wanted = [str(literal), "--artifact", str(artifact)]
        if (first.get("unit"), first.get("user_manager"), first.get("restart"),
            first.get("template_version"), first.get("argv")) != (
                unit, False, "always", 1, wanted):
            raise AssertionError(("positive binding", first, wanted))
    else:
        reason = "ExecStart" if case_name == "unresolved-argv0" else "Restart="
        if reason not in (first.get("detail") or ""):
            raise AssertionError((case_name, "wrong refusal", first))

def cleanup_unit(state, unit):
    safe = unit.replace("/", "_")
    allowed = tuple(code for code in range(256) if code != 124)
    run(state, f"cleanup-stop-{safe}", ["systemctl", "stop", unit], ok=allowed)
    (UNIT_ROOT / unit).unlink(missing_ok=True)
    run(state, f"cleanup-reload-{safe}", ["systemctl", "daemon-reload"])
    load = run(state, f"cleanup-absent-{safe}",
               ["systemctl", "show", unit, "-p", "LoadState", "--value"])["stdout"].strip()
    if load != "not-found":
        raise RuntimeError(f"cleanup failed: {unit} LoadState={load}")
    state["cleanup"][unit] = {"load_state": load}
    save(state)

def unit_text(probe, artifact, *, explicit, restart):
    if explicit:
        cmd='@'+q(str(probe),path=True)+' '+q(str(probe))
    else:
        cmd=q(str(probe),path=True)
    cmd += ' '+q('--artifact')+' '+q(str(artifact))
    return f'''[Unit]\nDescription=x0x #729 disposable literal acceptance\nStartLimitIntervalSec=0\n[Service]\nType=simple\nExecStart={cmd}\nEnvironment=X0X_TEMPLATE_VERSION=1\nRestart={restart}\nRestartSec=1\nUser=65534\nGroup=65534\nPrivateNetwork=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nNoNewPrivileges=yes\nEnvironment="X0X_FIXTURE_PARENT_NETNS={os.readlink('/proc/self/ns/net')}"\n'''

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--probe',required=True); ap.add_argument('--artifact-root')
    a=ap.parse_args(); probe=Path(a.probe).resolve()
    if sys.platform != 'linux' or os.geteuid()!=0: raise SystemExit('requires root on disposable Linux systemd host')
    if not probe.is_file() or not os.access(probe,os.X_OK): raise SystemExit('--probe must be an executable absolute file')
    root=Path(a.artifact_root or tempfile.mkdtemp(prefix='x0x-729-')).resolve(); root.mkdir(mode=0o700, parents=True, exist_ok=False) if not root.exists() else os.chmod(root, 0o700)
    os.chown(root, 65534, 65534)
    state={"schema":1,"artifact":str(root),"probe_source":str(probe),"probe_sha256":hashlib.sha256(probe.read_bytes()).hexdigest(),"commands":[],"cases":{},"cleanup":{}}
    save(state); units=[]
    try:
        run(state,'manager',['systemctl','show','--property=Version','--value'])
        token=f"x0x-729-{os.getpid()}-{int(time.time())}"
        literal=root/'probe % $ ${FOO} $$ space'; shutil.copy2(probe,literal); literal.chmod(0o700); os.chown(literal, 65534, 65534)
        state['literal_probe_sha256']=hashlib.sha256(literal.read_bytes()).hexdigest(); save(state)
        cases=[('positive',True,'always','verified'),('unresolved-argv0',False,'always','not_guaranteed'),('bad-policy',True,'on-failure','not_guaranteed')]
        for name,explicit,restart,expected in cases:
            unit=f"{token}-{name}.service"; units.append(unit); case=root/name; case.mkdir(mode=0o700); os.chown(case, 65534, 65534)
            unit_path=UNIT_ROOT/unit; unit_path.write_text(unit_text(literal,case,explicit=explicit,restart=restart)); os.chmod(unit_path, 0o600)
            run(state,f'reload-{name}',['systemctl','daemon-reload']); run(state,f'start-{name}',['systemctl','start',unit])
            first=wait_json(case/'invocation-1.json'); state['cases'][name]={"unit":unit,"first":first,"expected":expected}; save(state)
            assert_first(name, first, expected, unit, literal, case)
            show=run(state,f'show-{name}',['systemctl','show',unit,'-p','MainPID','-p','InvocationID','-p','ExecStart','-p','Restart','-p','NRestarts'])
            (case/'systemctl-show.txt').write_text(show['stdout'])
            if name=='positive':
                (case/'release-first').touch(); second=wait_json(case/'invocation-2.json',35)
                validate(second.get('isolation'))
                if second['verdict']!='verified' or second['pid']==first['pid'] or second['invocation_id']==first['invocation_id']: raise AssertionError('respawn proof')
                state['cases'][name]['second']=second; save(state)
            cleanup_unit(state, unit)
        state['result']='PASS'; save(state); print(root)
    except BaseException as error:
        state["result"] = "FAIL"
        state["error_type"] = type(error).__name__
        save(state)
        raise
    finally:
        failures=[]
        for unit in reversed(units):
            if unit in state["cleanup"]:
                continue
            try:
                cleanup_unit(state, unit)
            except Exception as error:
                failures.append({"unit": unit, "error_type": type(error).__name__})
        state['cleanup']['failures']=failures; save(state)
        if failures:
            state["result"] = "FAIL_CLEANUP"
            save(state)
            raise RuntimeError(f'cleanup failed: {failures}')
def self_test():
    """Exercise main success and failure cleanup using an inert fake manager."""
    global UNIT_ROOT, run, wait_json
    original_run, original_wait, original_platform, original_geteuid = run, wait_json, sys.platform, os.geteuid
    original_chown, original_readlink = os.chown, os.readlink
    with tempfile.TemporaryDirectory(prefix="x0x-729-stub-") as temp:
        base = Path(temp); UNIT_ROOT = base / "units"; UNIT_ROOT.mkdir()
        probe = base / "probe"; probe.write_text("stub"); probe.chmod(0o700)
        for failure in (None, "start", "cleanup-timeout"):
            artifact = base / f"artifact-{failure or 'success'}"
            commands = []
            def fake_run(state, label, argv, *, ok=(0,)):
                commands.append(label)
                if failure == "start" and label == "start-positive": raise RuntimeError("stub start")
                if failure == "cleanup-timeout" and label.startswith("cleanup-stop-"): raise RuntimeError("stub timeout")
                stdout = "not-found\n" if "absent" in label else ""
                return {"stdout": stdout, "stderr": "", "exit": 0}
            def fake_wait(path, bound=30):
                invocation = 2 if "invocation-2" in path.name else 1
                case = path.parent.name; unit = next(p.name for p in UNIT_ROOT.iterdir() if f"-{case}.service" in p.name)
                literal = path.parent.parent / "probe % $ ${FOO} $$ space"
                expected = "verified" if case == "positive" else "not_guaranteed"
                detail = None if expected == "verified" else ("ExecStart unresolved" if case == "unresolved-argv0" else "Restart=on-failure")
                return {"schema":1,"invocation":invocation,"pid":100+invocation,"invocation_id":f"i{invocation}","argv":[str(literal),"--artifact",str(path.parent)],"exit_intent":"clean_exit_after_release" if invocation==1 else "wait_for_manager_stop","verdict":expected,"unit":unit if expected=="verified" else None,"user_manager":False if expected=="verified" else None,"restart":"always" if expected=="verified" else None,"template_version":1 if expected=="verified" else None,"detail":detail,"isolation":{"namespace":"net:[101]","namespace_changed":True,"links":[{"ifname":"lo"}],"routes":{"-4":[],"-6":[]},"uid":65534,"gid":65534,"capabilities":{k:"0000000000000000" for k in ("CapInh","CapPrm","CapEff","CapBnd","CapAmb")},"no_new_privs":1}}
            run, wait_json, sys.platform, os.geteuid = fake_run, fake_wait, "linux", lambda: 0
            os.chown = lambda *args: None
            os.readlink = lambda path: "net:[100]"
            sys.argv = [sys.argv[0], "--probe", str(probe), "--artifact-root", str(artifact)]
            failed = False
            try: main()
            except RuntimeError: failed = True
            assert failed is (failure is not None), (failure, commands)
            assert any(label.startswith("cleanup-") for label in commands), commands
    run, wait_json, sys.platform, os.geteuid = original_run, original_wait, original_platform, original_geteuid
    os.chown, os.readlink = original_chown, original_readlink

if __name__=='__main__':
    if sys.argv[1:] == ["--self-test"]: self_test()
    else: main()
