#!/usr/bin/env bash
# CMake wrapper for CI. It adds -DCMAKE_POLICY_VERSION_MINIMUM=3.5 to each
# configure call, then runs the real cmake.
#
# Why: ubuntu-26.04 runner images ship CMake 4, which rejects
# cmake_minimum_required(VERSION < 3.5). audiopus_sys 0.2.2 bundles opus
# with such a line. The CMAKE_POLICY_VERSION_MINIMUM environment variable
# alone did not take effect with the runner's CMake (#1816 CI log), and the
# `cmake` crate (0.1.58) has no CMAKE_ARGS knob. It does read the CMAKE (or
# CMAKE_<target>) environment variable as the cmake executable.
# The workflows point CMAKE_x86_64_unknown_linux_gnu at this file (#1816).
# Other targets (macOS, Windows, cross builds) do not read that variable.
#
# Build, install, script and tool modes (--build, --install, -E, -P, ...)
# pass through unchanged, because those modes reject -D arguments.
# Do not pin or downgrade cmake.
set -euo pipefail

real_cmake="$(command -v cmake)" || {
  echo "cmake-policy-min.sh: no cmake on PATH" >&2
  exit 127
}

for arg in "$@"; do
  case "$arg" in
    --build | --install | --open | -E | -P | --find-package | --version | --help | -h | --workflow)
      exec "$real_cmake" "$@"
      ;;
  esac
done

exec "$real_cmake" -DCMAKE_POLICY_VERSION_MINIMUM=3.5 "$@"
