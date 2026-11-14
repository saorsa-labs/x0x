#!/usr/bin/env bash
# Hermetic test for scripts/ci/apt-install.sh (#1871).
#
# Usage: scripts/ci/test_apt_install.sh [path-to-apt-install.sh]
#
# Fake dpkg-query, apt-get, sleep and sudo commands are first on PATH, so the
# test changes no host packages, needs no network and does not wait. The fake
# sudo is necessary: the real one resets PATH and would find the real apt-get.
#
# Fake controls (environment):
#   FAKE_INSTALLED     packages that dpkg-query shows as installed
#   FAKE_UPDATE_FAILS  number of `apt-get update` calls that fail first
#   FAKE_INSTALL_FAILS number of `apt-get install` calls that fail first
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="${1:-$here/apt-install.sh}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fakes="$work/bin"
mkdir -p "$fakes"

cat >"$fakes/dpkg-query" <<'FAKE'
#!/usr/bin/env bash
# The package name is the last argument.
for pkg in "$@"; do :; done
for have in ${FAKE_INSTALLED:-}; do
  if [ "$have" = "$pkg" ]; then
    printf 'install ok installed'
    exit 0
  fi
done
echo "dpkg-query: no packages found matching $pkg" >&2
exit 1
FAKE

cat >"$fakes/apt-get" <<'FAKE'
#!/usr/bin/env bash
# Record the call, then fail the first N calls of each subcommand.
echo "DEBIAN_FRONTEND=${DEBIAN_FRONTEND:-} $*" >>"$FAKE_STATE/apt.log"
sub=""
for arg in "$@"; do
  case "$arg" in update | install) sub="$arg" && break ;; esac
done
count_file="$FAKE_STATE/$sub.count"
count=$(($(cat "$count_file" 2>/dev/null || echo 0) + 1))
echo "$count" >"$count_file"
case "$sub" in
  update) fails="${FAKE_UPDATE_FAILS:-0}" ;;
  install) fails="${FAKE_INSTALL_FAILS:-0}" ;;
  *) exit 2 ;;
esac
if [ "$count" -le "$fails" ]; then
  echo "E: fake apt-get $sub failure $count" >&2
  exit 100
fi
FAKE

cat >"$fakes/sleep" <<'FAKE'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_STATE/sleep.log"
FAKE

cat >"$fakes/sudo" <<'FAKE'
#!/usr/bin/env bash
exec "$@"
FAKE
chmod +x "$fakes"/*

failures=0
case_name=""
fail() {
  failures=$((failures + 1))
  echo "  FAIL [$case_name] $*"
}

# run <name> <apt-install.sh arguments ...>: fresh fake state, then the script.
# Results: $rc, $state/out (stdout), $state/err (stderr), $state/*.log.
run() {
  case_name="$1"
  shift
  state="$work/$case_name"
  mkdir -p "$state"
  rc=0
  FAKE_STATE="$state" PATH="$fakes:$PATH" bash "$script" "$@" \
    >"$state/out" 2>"$state/err" || rc=$?
  echo "case $case_name: exit $rc"
}

expect_rc() {
  [ "$rc" -eq "$1" ] || fail "exit code $rc, expected $1"
}

# expect_calls <update|install> <n>
expect_calls() {
  local got
  got="$(cat "$state/$1.count" 2>/dev/null || echo 0)"
  [ "$got" -eq "$2" ] || fail "apt-get $1 called $got times, expected $2"
}

# expect_sleeps "<space-separated seconds>"
expect_sleeps() {
  local got=""
  if [ -f "$state/sleep.log" ]; then
    got="$(tr '\n' ' ' <"$state/sleep.log" | sed 's/ $//')"
  fi
  [ "$got" = "$1" ] || fail "sleeps '$got', expected '$1'"
}

# expect_line <out|err|apt.log> <fixed text>
expect_line() {
  grep -qF -- "$2" "$state/$1" 2>/dev/null || fail "no '$2' in $1"
}

unset APT_INSTALL_WAITS FAKE_INSTALLED FAKE_UPDATE_FAILS FAKE_INSTALL_FAILS

# 1. All packages are installed: apt is not called.
FAKE_INSTALLED="pkg-a pkg-b" run skip pkg-a pkg-b
expect_rc 0
expect_calls update 0
expect_calls install 0
expect_sleeps ""
expect_line out "all packages are installed (pkg-a pkg-b); apt not called"

# 2. The install fails two times, then succeeds: default waits 30 and 90 s.
FAKE_INSTALLED="pkg-a" FAKE_INSTALL_FAILS=2 \
  run install-recovery --no-install-recommends pkg-a pkg-b
expect_rc 0
expect_calls update 3
expect_calls install 3
expect_sleeps "30 90"
expect_line out "to install: pkg-b"
expect_line out "installed on attempt 3"
expect_line out "::warning::apt-install.sh: attempt 2 of 5 failed; next attempt in 90 s"
expect_line apt.log "DEBIAN_FRONTEND=noninteractive -o Acquire::Retries=5 -o APT::Update::Error-Mode=any update"
expect_line apt.log "APT::Update::Error-Mode=any install -y --no-install-recommends pkg-a pkg-b"

# 3. The update fails but the install succeeds: one attempt, warning only.
FAKE_UPDATE_FAILS=1 run update-failure pkg-a
expect_rc 0
expect_calls update 1
expect_calls install 1
expect_sleeps ""
expect_line out "::warning::apt-install.sh: apt-get update failed on attempt 1"
expect_line out "installed on attempt 1"

# 4. All attempts fail: exit 1, the full wait schedule and the ::error:: line.
FAKE_UPDATE_FAILS=99 FAKE_INSTALL_FAILS=99 run all-fail pkg-a pkg-b
expect_rc 1
expect_calls update 5
expect_calls install 5
expect_sleeps "30 90 180 300"
expect_line err "::error::apt-install.sh: apt could not install (pkg-a pkg-b) in 5 attempts"

# 5. APT_INSTALL_WAITS sets the schedule; the attempts are the waits plus one.
APT_INSTALL_WAITS="1 2" FAKE_INSTALL_FAILS=99 run custom-waits pkg-a
expect_rc 1
expect_calls install 3
expect_sleeps "1 2"
expect_line err "in 3 attempts"

# 6. Bad input: exit 2 and apt is not called.
run no-packages --no-install-recommends
expect_rc 2
expect_calls install 0
APT_INSTALL_WAITS="30 x" run bad-waits pkg-a
expect_rc 2
expect_calls install 0

if [ "$failures" -ne 0 ]; then
  echo "test_apt_install.sh: $failures check(s) FAILED"
  exit 1
fi
echo "test_apt_install.sh: all checks passed"
