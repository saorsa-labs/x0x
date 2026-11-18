#!/usr/bin/env bash
# Isolated launchd acceptance for a launcher-bound job (#1379).
#
# Loads a throwaway job (its own label, plist and roots in a temporary
# directory) into this user's GUI domain. The job runs the given
# x0x-launcher in the trial form, which runs a fake daemon. Nothing of the
# real `com.saorsalabs.x0xd` job, the real data directories or x0xd is
# touched. The cases check:
#   1. a daemon that ends on SIGTERM is stopped at once by `bootout`, with
#      its process group;
#   2. ExitTimeOut: a daemon that ignores SIGTERM is SIGKILLed only after
#      the job's ExitTimeOut (25 s here), not launchd's 20 s default, and
#      its group goes with it;
#   3. when the job's main process (the launcher) is SIGKILLed, launchd
#      ends the rest of its process group (a child that ends on SIGTERM).
# It also reports how often launchd restarts the job when the daemon path
# is missing.
# It also reports a measured limit (18 Nov 2026, macOS 27): launchd's
# process-group cleanup sends SIGTERM only, so a group member that ignores
# SIGTERM outlives both `bootout` and a crash of the main process. The
# script kills such a survivor itself.
#
# Usage: scripts/ci/macos-launchd-acceptance.sh /abs/path/x0x-launcher
set -euo pipefail

launcher=${1:?usage: $0 /abs/path/x0x-launcher}
[[ "$launcher" = /* && -x "$launcher" ]] || { echo "launcher must be an absolute executable" >&2; exit 64; }
[[ "$(uname)" = Darwin ]] || { echo "macOS only" >&2; exit 64; }

domain="gui/$(id -u)"
work=$(cd "$(mktemp -d)" && pwd -P)
chmod 700 "$work"
label="com.saorsalabs.x0x-acceptance.$$"
plist="$work/$label.plist"
pids="$work/pids"
cleanup() {
    launchctl bootout "$domain/$label" >/dev/null 2>&1 || true
    if [[ -f "$pids" ]]; then
        read -r main child <"$pids" || true
        kill -9 "${main:-}" "${child:-}" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

# The fake daemon records its pid and a child's, then waits.
# MAIN_IGNORES_TERM / CHILD_IGNORES_TERM make either ignore SIGTERM.
daemon="$work/x0xd"
cat >"$daemon" <<'EOF'
#!/bin/bash
[[ "${MAIN_IGNORES_TERM:-0}" = 1 ]] && trap '' TERM
( if [[ "${CHILD_IGNORES_TERM:-0}" = 1 ]]; then trap '' TERM; else trap - TERM; fi
  while :; do sleep 1; done ) &
echo "$$ $!" >"$PIDS"
while :; do sleep 1; done
EOF
chmod 755 "$daemon"

write_job() { # main_ignores_term child_ignores_term exit_timeout [daemon]
    cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$label</string>
    <key>ProgramArguments</key>
    <array>
        <string>$launcher</string>
        <string>--host-root</string><string>$work</string>
        <string>--instance</string><string>acceptance</string>
        <string>--</string>
        <string>${4:-$daemon}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PIDS</key><string>$pids</string>
        <key>MAIN_IGNORES_TERM</key><string>$1</string>
        <key>CHILD_IGNORES_TERM</key><string>$2</string>
    </dict>
    <key>KeepAlive</key><true/>
    <key>ExitTimeOut</key><integer>$3</integer>
    <key>StandardErrorPath</key><string>$work/stderr.log</string>
</dict>
</plist>
EOF
}

alive() { kill -0 "$1" 2>/dev/null; }

run_case() { # name main_ignores child_ignores exit_timeout min_secs max_secs
    local name=$1
    rm -f "$pids"
    write_job "$2" "$3" "$4"
    launchctl bootstrap "$domain" "$plist"
    for _ in $(seq 50); do [[ -s "$pids" ]] && break; sleep 0.2; done
    [[ -s "$pids" ]] || { echo "FAIL $name: the daemon did not start"; cat "$work/stderr.log" 2>/dev/null; exit 1; }
    read -r main child <"$pids"
    if ! alive "$main" || ! alive "$child"; then echo "FAIL $name: daemon not running"; exit 1; fi
    local start end elapsed
    start=$(date +%s)
    launchctl bootout "$domain/$label"
    for _ in $(seq 300); do
        alive "$main" || alive "$child" || break
        sleep 0.1
    done
    end=$(date +%s)
    elapsed=$((end - start))
    if alive "$main" || alive "$child"; then
        echo "FAIL $name: process group survived bootout (main=$main child=$child)"
        exit 1
    fi
    if (( elapsed < $5 || elapsed > $6 )); then
        echo "FAIL $name: stopped after ${elapsed}s, expected ${5}-${6}s"
        exit 1
    fi
    echo "PASS $name: group gone after ${elapsed}s"
}


start_job() { # main_ignores child_ignores exit_timeout
    rm -f "$pids"
    write_job "$1" "$2" "$3"
    launchctl bootstrap "$domain" "$plist"
    for _ in $(seq 50); do [[ -s "$pids" ]] && break; sleep 0.2; done
    [[ -s "$pids" ]] || { echo "FAIL: the daemon did not start"; cat "$work/stderr.log" 2>/dev/null; exit 1; }
    read -r main child <"$pids"
}

crash_case() { # name child_ignores -> prints whether the child survived
    start_job 0 "$2" 25
    kill -9 "$main"
    sleep 3
    if alive "$child"; then
        kill -9 "$child" 2>/dev/null || true
        survived=1
    else
        survived=0
    fi
    launchctl bootout "$domain/$label" >/dev/null 2>&1 || true
    sleep 1
    read -r main child <"$pids" || true
    kill -9 "$main" "$child" 2>/dev/null || true
}

limit_case() { # bootout with a child that ignores SIGTERM
    start_job 0 1 25
    launchctl bootout "$domain/$label"
    sleep 3
    if alive "$child"; then
        kill -9 "$child" 2>/dev/null || true
        echo "LIMIT bootout: a group member that ignores SIGTERM survived (killed by this script)"
    else
        echo "LIMIT bootout: not observed (the member was ended)"
    fi
}

run_case "term-stops-at-once" 0 0 60 0 5
run_case "exit-timeout-honoured" 1 0 25 24 32
crash_case "crash-ends-group" 0
(( survived == 0 )) || { echo "FAIL crash-ends-group: a child that ends on SIGTERM survived the launcher's crash"; exit 1; }
echo "PASS crash-ends-group: launchd ended the group when the launcher was SIGKILLed"
crash_case "crash-limit" 1
if (( survived == 1 )); then
    echo "LIMIT crash: a group member that ignores SIGTERM survived the launcher's crash (killed by this script)"
else
    echo "LIMIT crash: not observed (the member was ended)"
fi
limit_case

# A daemon path that no longer exists (a Homebrew upgrade removes the
# versioned Cellar path the job pins). Measured, not a pass/fail case.
missing_case() {
    rm -f "$work/stderr.log"
    write_job 0 0 25 "$work/missing/x0xd"
    launchctl bootstrap "$domain" "$plist"
    sleep 30
    local starts
    starts=$(grep -c 'cannot exec' "$work/stderr.log" 2>/dev/null || true)
    launchctl bootout "$domain/$label" >/dev/null 2>&1 || true
    echo "LIMIT missing-daemon: the launcher exited at once each time; launchd started it ${starts:-0} times in 30 s (KeepAlive restart loop)"
}
missing_case
echo "PASS launchd acceptance ($label)"
