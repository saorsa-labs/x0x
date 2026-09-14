#!/bin/sh
set -eu
umask 077

usage() {
  echo "usage: $0 --probe /absolute/probe [--manager user|system] [--artifact-root DIR]" >&2
  exit 64
}

probe=
manager=user
artifact_root=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --probe) [ "$#" -ge 2 ] || usage; probe=$2; shift 2 ;;
    --manager) [ "$#" -ge 2 ] || usage; manager=$2; shift 2 ;;
    --artifact-root) [ "$#" -ge 2 ] || usage; artifact_root=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$probe" ] || usage
[ -x "$probe" ] || { echo "probe is not executable: $probe" >&2; exit 65; }
case "$probe" in /*) ;; *) echo "probe path must be absolute" >&2; exit 65;; esac
case "$manager" in user|system) ;; *) usage;; esac
command -v timeout >/dev/null 2>&1 || { echo "GNU timeout is required" >&2; exit 69; }

run_id="x0x-690-$(date +%s)-$$"
if [ -z "$artifact_root" ]; then artifact_root="/tmp/$run_id"; fi
if [ -e "$artifact_root" ]; then
  [ -d "$artifact_root" ] && [ ! -L "$artifact_root" ] || { echo "artifact root is not a plain directory" >&2; exit 65; }
  chmod 700 "$artifact_root"
else
  mkdir -m 700 "$artifact_root"
fi
artifact_root=$(cd "$artifact_root" && pwd -P)
probe=$(cd "$(dirname "$probe")" && printf '%s/%s\n' "$(pwd -P)" "$(basename "$probe")")
printf '%s\n' "$probe" >"$artifact_root/probe-path.txt"
sha256sum "$probe" >"$artifact_root/probe-sha256.txt"
status_log="$artifact_root/command-statuses.txt"

record_status() {
  label=$1 status=$2
  printf '%s=%s\n' "$label" "$status" >>"$status_log"
}

systemctl_bounded() {
  label=$1 out=$2 err=$3; shift 3
  if [ "$manager" = user ]; then
    if timeout --kill-after=2s 10s systemctl --user "$@" >"$out" 2>"$err"; then status=0; else status=$?; fi
  else
    if timeout --kill-after=2s 10s systemctl "$@" >"$out" 2>"$err"; then status=0; else status=$?; fi
  fi
  record_status "$label" "$status"
  return "$status"
}

systemd_run_bounded() {
  label=$1 out=$2 err=$3; shift 3
  if [ "$manager" = user ]; then
    if timeout --kill-after=2s 15s systemd-run --user "$@" >"$out" 2>"$err"; then status=0; else status=$?; fi
  else
    if timeout --kill-after=2s 15s systemd-run "$@" >"$out" 2>"$err"; then status=0; else status=$?; fi
  fi
  record_status "$label" "$status"
  return "$status"
}

journal_bounded() {
  label=$1 unit=$2 out=$3 err=$4
  if [ "$manager" = user ]; then
    if timeout --kill-after=2s 10s journalctl --user-unit="$unit" --no-pager --output=short-monotonic >"$out" 2>"$err"; then status=0; else status=$?; fi
  else
    if timeout --kill-after=2s 10s journalctl -u "$unit" --no-pager --output=short-monotonic >"$out" 2>"$err"; then status=0; else status=$?; fi
  fi
  record_status "$label" "$status"
  return "$status"
}

if [ "$manager" = user ]; then
  systemctl_bounded manager-probe "$artifact_root/manager-probe.txt" "$artifact_root/manager-probe.err" show -p Version --value || {
    echo "unsupported: no usable user systemd manager; choose --manager system on an approved disposable host" >&2
    exit 69
  }
else
  [ "$(id -u)" -eq 0 ] || { echo "--manager system requires an already-root shell on a disposable host" >&2; exit 77; }
fi
systemctl_bounded systemctl-version "$artifact_root/systemctl-version.txt" "$artifact_root/systemctl-version.err" --version

units=
wait_unit_absent() {
  unit=$1 log=$2 bound=$3
  start=$(date +%s)
  attempt=0
  while :; do
    attempt=$((attempt + 1))
    out="$artifact_root/.load-state-$attempt.out"
    err="$artifact_root/.load-state-$attempt.err"
    if ! systemctl_bounded "absence-$unit-$attempt" "$out" "$err" show "$unit" -p LoadState --value; then
      echo "cleanup query failed for $unit; absence is unproven" >>"$log"
      cat "$err" >>"$log"
      return 1
    fi
    load_state=$(cat "$out")
    cat "$out" "$err" >>"$log"
    rm -f "$out" "$err"
    if [ "$load_state" = not-found ]; then
      echo "unit absent: $unit LoadState=not-found" >>"$log"
      return 0
    fi
    now=$(date +%s)
    [ $((now - start)) -lt "$bound" ] || {
      echo "cleanup timeout: $unit LoadState=$load_state" >>"$log"
      return 1
    }
    sleep 0.1
  done
}

cleanup() {
  original_status=$?
  final_status=$original_status
  trap - EXIT HUP INT TERM
  set +e
  for unit in $units; do
    safe=$(printf '%s' "$unit" | tr -c 'A-Za-z0-9._-' '_')
    [ ! -e "$artifact_root/.cleaned-$safe" ] || continue
    systemctl_bounded "trap-stop-$safe" "$artifact_root/trap-stop-$safe.out" "$artifact_root/trap-stop-$safe.err" stop "$unit" || true
    systemctl_bounded "trap-reset-$safe" "$artifact_root/trap-reset-$safe.out" "$artifact_root/trap-reset-$safe.err" reset-failed "$unit" || true
    if ! wait_unit_absent "$unit" "$artifact_root/cleanup.log" 10; then final_status=1; fi
  done
  printf 'ORIGINAL_EXIT=%s FINAL_EXIT=%s\n' "$original_status" "$final_status" >>"$artifact_root/exit-status.txt"
  exit "$final_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

wait_file() {
  file=$1 bound=$2
  start=$(date +%s)
  while [ ! -s "$file" ]; do
    now=$(date +%s)
    [ $((now - start)) -lt "$bound" ] || { echo "timeout waiting for $file" >&2; return 1; }
    sleep 0.1
  done
}

assert_verdict() {
  file=$1 invocation=$2 expected=$3 expected_unit=$4 expected_manager=$5 expected_reason=$6
  python3 - "$file" "$invocation" "$expected" "$expected_unit" "$expected_manager" "$expected_reason" <<'PY'
import json, sys
p, invocation, expected, unit, manager, reason = sys.argv[1:]
with open(p, encoding="utf-8") as f:
    value = json.load(f)
assert value["schema"] == 1
assert value["invocation"] == int(invocation)
assert isinstance(value["pid"], int) and value["pid"] > 1
assert isinstance(value["invocation_id"], str) and value["invocation_id"]
assert value["verdict"] == expected, value
if int(invocation) == 1:
    assert value["exit_intent"] == "clean_exit_after_release", value
else:
    assert value["exit_intent"] == "wait_for_manager_stop", value
if expected == "verified":
    assert value["unit"] == unit, value
    assert value["user_manager"] is (manager == "user"), value
    assert value["restart"] == "always", value
    assert value["template_version"] == 1, value
else:
    assert isinstance(value["detail"], str) and value["detail"], value
    assert reason in value["detail"], value
PY
}

run_case() {
  case_name=$1 expected=$2 expected_reason=$3 type=$4 restart=$5 prevent=$6 remain=$7
  unit="$run_id-$case_name.service"
  case_dir="$artifact_root/$case_name"
  mkdir -m 700 "$case_dir"
  units="$unit $units"
  systemd_run_bounded "run-$case_name" "$case_dir/systemd-run.out" "$case_dir/systemd-run.err" \
    --unit="$unit" --collect \
    --property="Type=$type" \
    --property="Restart=$restart" \
    --property="RestartPreventExitStatus=$prevent" \
    --property="RemainAfterExit=$remain" \
    --property="StartLimitIntervalSec=0" \
    --setenv=X0X_TEMPLATE_VERSION=1 \
    "$probe" --artifact "$case_dir"
  wait_file "$case_dir/invocation-1.json" 20
  systemctl_bounded "show-first-$case_name" "$case_dir/systemctl-show-first.txt" "$case_dir/systemctl-show-first.err" show "$unit" \
    -p Id -p MainPID -p InvocationID -p Restart -p RestartPreventExitStatus \
    -p RemainAfterExit -p Type -p StartLimitIntervalUSec -p StartLimitBurst \
    -p ActiveEnterTimestampMonotonic -p ExecStart -p Environment
  assert_verdict "$case_dir/invocation-1.json" 1 "$expected" "$unit" "$manager" "$expected_reason"
  : >"$case_dir/release-first"
  if [ "$expected" = verified ]; then
    wait_file "$case_dir/invocation-2.json" 25
    assert_verdict "$case_dir/invocation-2.json" 2 verified "$unit" "$manager" ""
    systemctl_bounded "show-respawn-$case_name" "$case_dir/systemctl-show-respawn.txt" "$case_dir/systemctl-show-respawn.err" show "$unit" \
      -p MainPID -p InvocationID -p Result -p ExecMainCode -p ExecMainStatus -p NRestarts
    python3 - "$case_dir/invocation-1.json" "$case_dir/invocation-2.json" "$case_dir/systemctl-show-respawn.txt" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f: first=json.load(f)
with open(sys.argv[2], encoding="utf-8") as f: second=json.load(f)
props={}
with open(sys.argv[3], encoding="utf-8") as f:
    for line in f:
        key, sep, value=line.rstrip("\n").partition("=")
        if sep: props[key]=value
assert second["pid"] != first["pid"], (first, second)
assert second["invocation_id"] != first["invocation_id"], (first, second)
assert int(props["MainPID"]) == second["pid"], (props, second)
assert props["InvocationID"] == second["invocation_id"], (props, second)
assert int(props["NRestarts"]) >= 1, props
PY
  else
    sleep 1
    [ ! -e "$case_dir/invocation-2.json" ] || { echo "negative $case_name restarted unexpectedly" >&2; return 1; }
  fi
  journal_bounded "journal-$case_name" "$unit" "$case_dir/journal.txt" "$case_dir/journal.err" || true
  systemctl_bounded "stop-$case_name" "$case_dir/stop.out" "$case_dir/stop.err" stop "$unit" || true
  systemctl_bounded "reset-$case_name" "$case_dir/reset.out" "$case_dir/reset.err" reset-failed "$unit" || true
  wait_unit_absent "$unit" "$case_dir/post-cleanup.log" 10
  safe=$(printf '%s' "$unit" | tr -c 'A-Za-z0-9._-' '_')
  : >"$artifact_root/.cleaned-$safe"
}

run_case positive verified "" simple always "" no
run_case on-failure not_guaranteed "Restart=" simple on-failure "" no
run_case prevent-exit-zero not_guaranteed "RestartPreventExitStatus" simple always 0 no
run_case remain-after-exit not_guaranteed "RemainAfterExit=yes" simple always "" yes

cat >"$artifact_root/oneshot-limit.txt" <<'EOF_LIMIT'
A loaded Type=oneshot + RemainAfterExit=yes job cannot simultaneously use Restart=always or
Restart=on-success: systemd rejects those combinations before process execution. The executable
RemainAfterExit negative therefore uses Type=simple so the production readback reaches and rejects
the loaded RemainAfterExit policy. Type=oneshot is covered by source/unit parsing tests; it cannot
supply a real first-process readback under a clean-exit-guaranteeing Restart policy.
EOF_LIMIT
printf 'PASS artifact_root=%s\n' "$artifact_root"
