#!/usr/bin/env bash
set -euo pipefail

runner_source=$1
helper_source=$2
install_root=${3:-/}
network=$4

case "$network" in
    prod|testnet) ;;
    *) echo "invalid runner network: $network" >&2; exit 2 ;;
esac
[ -f "$runner_source" ] && [ -f "$helper_source" ] || {
    echo "runner bundle source missing" >&2
    exit 2
}

if command -v sha256sum >/dev/null 2>&1; then
    bundle_id=$(cat "$runner_source" "$helper_source" | sha256sum | awk '{print $1}')
else
    bundle_id=$(cat "$runner_source" "$helper_source" | shasum -a 256 | awk '{print $1}')
fi
prefix=${install_root%/}/usr/local
bundle_root="$prefix/lib/x0x-test-runner/$network/bundles"
bundle="$bundle_root/$bundle_id"
stage="$bundle.stage.$$"
runnable="$prefix/bin/x0x-test-runner-$network.py"
candidate="$runnable.new.$$"
cleanup() { rm -rf "$stage"; rm -f "$candidate"; }
trap cleanup EXIT

install -d -m 755 "$bundle_root" "$prefix/bin"
install -d -m 755 "$stage"
install -m 755 "$runner_source" "$stage/x0x-test-runner.py"
if [ "${X0X_INSTALL_FAIL_AFTER_RUNNER:-0}" = "1" ]; then
    echo "injected runner bundle staging failure" >&2
    exit 70
fi
install -m 644 "$helper_source" "$stage/result_framing.py"
if [ ! -d "$bundle" ]; then
    mv "$stage" "$bundle"
fi
ln -s "$bundle/x0x-test-runner.py" "$candidate"
mv -f "$candidate" "$runnable"
