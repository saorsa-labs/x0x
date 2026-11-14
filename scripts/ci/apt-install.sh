#!/usr/bin/env bash
# Install apt packages on a CI runner and survive a short mirror outage.
#
# Usage: scripts/ci/apt-install.sh [--apt-install-option ...] <package> ...
#
# Arguments that start with "-" go to `apt-get install` unchanged (for
# example --no-install-recommends). All other arguments are package names.
# Write an option and its value as one word (-oName=value).
#
# Why: on 11 Nov 2026 the runners could not resolve archive.ubuntu.com for
# some minutes at a time. A plain `apt-get update` then exits 0 with only a
# warning, the stale package index stays, and `apt-get install` exits 100.
#
# What this script does:
#   1. If dpkg shows all packages as installed, it does not call apt.
#   2. If not, it runs `apt-get update` and `apt-get install` in up to 5
#      attempts. APT::Update::Error-Mode=any makes a failed index download
#      an error, and Acquire::Retries=5 retries each download in apt.
#      A failed update gives a warning only; the install result decides
#      the attempt. Thus a broken source that the packages do not need
#      (for example a third-party repository on the runner image) does not
#      fail the job, as it did not before this script.
#   3. Between attempts it waits 30, 90, 180 and 300 s (600 s in total), so
#      an outage of about 10 minutes does not fail the job.
#   4. After the last failed attempt it exits 1 with an ::error:: line.
#
# APT_INSTALL_WAITS (seconds, space-separated) replaces the waits; the
# number of attempts is the number of waits plus one. Tests use it.
set -euo pipefail

me="apt-install.sh"
options=()
packages=()
for arg in "$@"; do
  case "$arg" in
    -*) options+=("$arg") ;;
    *) packages+=("$arg") ;;
  esac
done

if [ "${#packages[@]}" -eq 0 ]; then
  echo "usage: $me [--apt-install-option ...] <package> ..." >&2
  exit 2
fi

read -r -a waits <<<"${APT_INSTALL_WAITS-30 90 180 300}"
for wait_s in ${waits[@]+"${waits[@]}"}; do
  case "$wait_s" in
    '' | *[!0-9]*)
      echo "$me: APT_INSTALL_WAITS must be whole seconds, got '$wait_s'" >&2
      exit 2
      ;;
  esac
done
attempts=$((${#waits[@]} + 1))

# Print the packages that dpkg does not show as fully installed.
missing_packages() {
  local pkg status
  for pkg in "${packages[@]}"; do
    status="$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)"
    if [ "$status" != "install ok installed" ]; then
      printf '%s\n' "$pkg"
    fi
  done
}

missing="$(missing_packages)"
if [ -z "$missing" ]; then
  echo "$me: all packages are installed (${packages[*]}); apt not called"
  exit 0
fi
echo "$me: to install: $(echo "$missing" | tr '\n' ' ')"

as_root=()
if [ "$(id -u)" -ne 0 ]; then
  as_root=(sudo)
fi

apt_get() {
  ${as_root[@]+"${as_root[@]}"} env DEBIAN_FRONTEND=noninteractive apt-get \
    -o Acquire::Retries=5 -o APT::Update::Error-Mode=any "$@"
}

attempt=1
while :; do
  echo "$me: attempt $attempt of $attempts"
  if ! apt_get update; then
    echo "::warning::$me: apt-get update failed on attempt $attempt; the install result decides"
  fi
  if apt_get install -y ${options[@]+"${options[@]}"} "${packages[@]}"; then
    echo "$me: installed on attempt $attempt"
    exit 0
  fi
  if [ "$attempt" -ge "$attempts" ]; then
    break
  fi
  wait_s="${waits[$((attempt - 1))]}"
  echo "::warning::$me: attempt $attempt of $attempts failed; next attempt in ${wait_s} s"
  sleep "$wait_s"
  attempt=$((attempt + 1))
done

echo "::error::$me: apt could not install (${packages[*]}) in $attempts attempts" >&2
exit 1
