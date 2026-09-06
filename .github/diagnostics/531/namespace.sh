#!/usr/bin/env bash
# All mutations below are in the disposable child mount/network namespaces.
set -euo pipefail
uid=$1 gid=$2 source_root=$3 evidence=$4 nextest=$5 parent_netns=$6
[ "$(readlink /proc/self/ns/net)" != "$parent_netns" ]
[ "$(id -u)" = 0 ]
mount --make-rprivate /
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp
mkdir /tmp/x0x-nextest-home
chown "$uid:$gid" /tmp/x0x-nextest-home
ip link set lo up
python3 - "$evidence" <<'PY'
import json, pathlib, subprocess, sys
p=pathlib.Path(sys.argv[1])
links=json.loads(subprocess.check_output(['ip','-j','link']))
assert [x['ifname'] for x in links]==['lo'], links
routes={f:json.loads(subprocess.check_output(['ip',f,'-j','route','show','table','all'])) for f in ('-4','-6')}
assert all(r.get('dev')=='lo' and r.get('dst')!='default' and 'gateway' not in r for rows in routes.values() for r in rows), routes
(p/'namespace.json').write_text(json.dumps({'links':links,'routes':routes,'netns':pathlib.Path('/proc/self/ns/net').readlink().as_posix()},indent=2))
PY
# Install only into this newly created namespace, never flush host rules.
nft --check --file "$source_root/.github/diagnostics/531/fence.nft"
nft --file "$source_root/.github/diagnostics/531/fence.nft"
nft --json list ruleset > "$evidence/firewall-before.json"
exec python3 "$source_root/.github/diagnostics/531/diagnostic.py" supervise \
  "$evidence" "$uid" "$gid" "$nextest"
