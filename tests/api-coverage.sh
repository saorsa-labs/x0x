#!/usr/bin/env bash
set -euo pipefail

# x0x API Coverage Report
# Compares routes defined in x0xd.rs against endpoints tested in E2E scripts.
# Usage:
#   bash tests/api-coverage.sh          # standard report
#   bash tests/api-coverage.sh -v       # show all routes with suite coverage
#   bash tests/api-coverage.sh --test-endpoints  # show raw extracted endpoints

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

X0XD="$PROJECT_DIR/src/bin/x0xd.rs"

if [[ ! -f "$X0XD" ]]; then
    echo "ERROR: $X0XD not found" >&2
    exit 1
fi

export PROJECT_DIR

python3 - "$@" << 'PYTHON_EOF'
import re
import sys
import os

project_dir = os.environ["PROJECT_DIR"]
x0xd_path = os.path.join(project_dir, "src/bin/x0xd.rs")
test_dir = os.path.join(project_dir, "tests")

def extract_routes(filepath):
    """Parse .route("PATH", method(handler)) patterns including multiline and compound."""
    with open(filepath) as f:
        content = f.read()
    flat = re.sub(r'\s+', ' ', content)

    routes = set()
    i = 0
    marker = '.route('
    while True:
        pos = flat.find(marker, i)
        if pos < 0:
            break
        start = pos + len(marker)
        depth = 1
        j = start
        while j < len(flat) and depth > 0:
            ch = flat[j]
            if ch == '"':
                j += 1
                while j < len(flat) and flat[j] != '"':
                    if flat[j] == '\\':
                        j += 1
                    j += 1
            elif ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            j += 1
        inner = flat[start:j-1].strip()
        i = j

        path_match = re.match(r'"(/[^"]*)"', inner)
        if not path_match:
            continue
        path = path_match.group(1)
        rest = inner[path_match.end():].strip()
        if rest.startswith(','):
            rest = rest[1:].strip()

        methods = re.findall(r'\b(get|post|put|patch|delete)\s*\(', rest)
        for method in methods:
            routes.add((method.upper(), path))
    return routes


def extract_test_endpoints(filepath):
    """Extract (METHOD, PATH) from a bash test script by analysing curl + helper calls."""
    if not os.path.exists(filepath):
        return set()
    with open(filepath) as f:
        content = f.read()

    # Join backslash-continued bash lines so multi-line `curl ... \\\n url`
    # invocations are seen as a single logical line by the regex helpers.
    content = re.sub(r'\\\n[ \t]*', ' ', content)

    endpoints = set()

    # Helper function patterns and their HTTP methods:
    # full_audit: get /path, post /path body, put /path body, pat /path body, del /path
    #             bget /path, bpst /path body
    #             http_status /path, http_del /path, ws_connect /path
    # vps:        vps_get $ip $tk /path, vps_post $ip $tk /path body
    #             vps_del $ip $tk /path, vps_put $ip $tk /path body
    #             vps_patch $ip $tk /path body
    # lan:        s1_curl /path, s2_curl /path, s3_curl /path
    #             s1_post /path body, s2_post /path body
    #             s1_raw /path

    # Character class for API path segments (inside optional quotes)
    P = r'[a-zA-Z0-9/_:.{}\$-]+'

    helper_patterns = [
        # full_audit helpers: func /path or func "/path" or func /path body
        (r'\bget\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bbget\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bcget\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bpost\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bbpst\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bcpst\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bpost_slow\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bput\b\s+["\']?(' + P + r')', 'PUT'),
        (r'\bbput\b\s+["\']?(' + P + r')', 'PUT'),
        (r'\bpat\b\s+["\']?(' + P + r')', 'PATCH'),
        (r'\bbpat\b\s+["\']?(' + P + r')', 'PATCH'),
        (r'\bdel\b\s+["\']?(' + P + r')', 'DELETE'),
        (r'\bbdel\b\s+["\']?(' + P + r')', 'DELETE'),
        (r'\bhttp_status\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bhttp_del\b\s+["\']?(' + P + r')', 'DELETE'),
        (r'\bws_connect\b\s+["\']?(' + P + r')', 'GET'),
        # comprehensive/full/live/stress helpers: A/B/C = GET, Ap/Bp/Cp = POST, Apu/Bpu = PUT, Apa/Bpa = PATCH, Ad/Bd = DELETE
        (r'\bA\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bB\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bC\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bAp\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bBp\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bCp\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bApu\b\s+["\']?(' + P + r')', 'PUT'),
        (r'\bBpu\b\s+["\']?(' + P + r')', 'PUT'),
        (r'\bApa\b\s+["\']?(' + P + r')', 'PATCH'),
        (r'\bBpa\b\s+["\']?(' + P + r')', 'PATCH'),
        (r'\bAd\b\s+["\']?(' + P + r')', 'DELETE'),
        (r'\bBd\b\s+["\']?(' + P + r')', 'DELETE'),
        # vps helpers: vps_get "$ip" "$tk" /path
        (r'\bvps_get\b\s+["\$][^\s]*\s+["\$][^\s]*\s+["\']?(' + P + r')', 'GET'),
        (r'\bvps_post\b\s+["\$][^\s]*\s+["\$][^\s]*\s+["\']?(' + P + r')', 'POST'),
        (r'\bvps_put\b\s+["\$][^\s]*\s+["\$][^\s]*\s+["\']?(' + P + r')', 'PUT'),
        (r'\bvps_del\b\s+["\$][^\s]*\s+["\$][^\s]*\s+["\']?(' + P + r')', 'DELETE'),
        (r'\bvps_patch\b\s+["\$][^\s]*\s+["\$][^\s]*\s+["\']?(' + P + r')', 'PATCH'),
        # lan helpers: s1_curl /path, s1_post /path, s1_raw /path
        (r'\bs[123]_curl\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bs[123]_post\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bs[123]_put\b\s+["\']?(' + P + r')', 'PUT'),
        (r'\bs[123]_patch\b\s+["\']?(' + P + r')', 'PATCH'),
        (r'\bs[123]_raw\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bs[123]_delete\b\s+["\']?(' + P + r')', 'DELETE'),
        # Named-groups dedicated runner uppercase helpers (alice/bob/charlie).
        (r'\bGET\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bBGET\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bCGET\b\s+["\']?(' + P + r')', 'GET'),
        (r'\bPOST\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bBPOST\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bCPOST\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bPOST_SOFT\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bBPOST_SOFT\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bCPOST_SOFT\b\s+["\']?(' + P + r')', 'POST'),
        (r'\bPATCH\b\s+["\']?(' + P + r')', 'PATCH'),
        (r'\bBPATCH\b\s+["\']?(' + P + r')', 'PATCH'),
        (r'\bDEL\b\s+["\']?(' + P + r')', 'DELETE'),
        (r'\bBDEL\b\s+["\']?(' + P + r')', 'DELETE'),
        (r'\bCDEL\b\s+["\']?(' + P + r')', 'DELETE'),
        # node ws helper invocations in shell proof scripts
        (r'ws_probe\.mjs\s+hold\s+["\']?(' + P + r')', 'GET'),
        (r'ws_probe\.mjs\s+direct-receive\s+["\$][^\s]*\s+["\$][^\s]*\s+["\']?(/ws/direct)', 'GET'),
        # cli_chk: cli_chk "subcommand" "field" — these test CLI, not REST
        # curl with a URL starting at $HOST_VAR and extending through any number
        # of path/var segments. We capture only what follows $HOST_VAR (first $VAR
        # looks like an API base URL), treating subsequent $VAR occurrences as
        # path params. Restrict to realistic curl URL terminators (quote or space).
        (
            r'curl\b[^|]*?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?'
            r'((?:/(?:\$\{?[A-Za-z0-9_]+\}?|[a-zA-Z0-9_:.-]+))+)',
            None,
        ),
    ]

    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue

        for pattern, default_method in helper_patterns:
            for m in re.finditer(pattern, line):
                raw_path = m.group(1)
                # Clean path
                path = re.sub(r'\$\{?[A-Za-z_]+\}?', ':param', raw_path)
                path = re.sub(r'["\'\s]+$', '', path)
                path = re.sub(r'/+', '/', path)
                if len(path) > 1:
                    path = path.rstrip('/')
                if any(p in path for p in ['/tmp/', '/root/', '/etc/', '/usr/', '/var/']):
                    continue
                if not path.startswith('/'):
                    continue

                if default_method:
                    method = default_method
                else:
                    # Infer from curl flags
                    mm = re.search(r'-X\s+(GET|POST|PUT|DELETE|PATCH)', line)
                    has_data = bool(re.search(r'\s-d[\s"\']|\s--data[\s"\']', line))
                    method = mm.group(1) if mm else ('POST' if has_data else 'GET')

                endpoints.add((method, path))

    return endpoints


def match_route(t_method, t_path, r_method, r_path):
    if t_method != r_method:
        return False
    rp = r_path.strip('/').split('/')
    tp = t_path.strip('/').split('/')
    if len(rp) != len(tp):
        return False
    for r, t in zip(rp, tp):
        if r.startswith(':') or t == ':param':
            continue
        if r != t:
            return False
    return True


def find_tested(test_eps, defined):
    tested = set()
    for rm, rp in defined:
        for tm, tp in test_eps:
            if match_route(tm, tp, rm, rp):
                tested.add((rm, rp))
                break
    return tested


# --- Run ---
defined_routes = extract_routes(x0xd_path)
suites = {
    "full_audit":    os.path.join(test_dir, "e2e_full_audit.sh"),
    "comprehensive": os.path.join(test_dir, "e2e_comprehensive.sh"),
    "full":          os.path.join(test_dir, "e2e_full.sh"),
    "vps":           os.path.join(test_dir, "e2e_vps.sh"),
    "lan":           os.path.join(test_dir, "e2e_lan.sh"),
    "live":          os.path.join(test_dir, "e2e_live_network.sh"),
    "stress":        os.path.join(test_dir, "e2e_stress.sh"),
    "named_groups":  os.path.join(test_dir, "e2e_named_groups.sh"),
}
suite_tested = {}
all_tested = set()
for name, path in suites.items():
    eps = extract_test_endpoints(path)
    tested = find_tested(eps, defined_routes)
    suite_tested[name] = tested
    all_tested |= tested

untested = defined_routes - all_tested
total = len(defined_routes)
covered = len(all_tested)
pct = (covered / total * 100) if total > 0 else 0

# --- Report ---
print()
print("x0x API Coverage Report")
print("=" * 50)
print(f"Routes in x0xd.rs:     {total:>3}")
for name in suites:
    exists = os.path.exists(suites[name])
    count = len(suite_tested[name]) if exists else 0
    label = name.replace('_', ' ')
    status = "" if exists else " (file not found)"
    print(f"Tested in {label + ':':14s} {count:>3}{status}")
print(f"Tested in ANY suite:   {covered:>3}")
print(f"UNTESTED anywhere:     {len(untested):>3}")
print(f"Coverage:              {pct:.1f}%")
print()

if untested:
    print("UNTESTED ROUTES:")
    for method, path in sorted(untested, key=lambda x: (x[1], x[0])):
        print(f"  {method:6s} {path}")
    print()

if "--verbose" in sys.argv or "-v" in sys.argv:
    print("ALL DEFINED ROUTES:")
    for method, path in sorted(defined_routes, key=lambda x: (x[1], x[0])):
        hits = [n for n in suites if (method, path) in suite_tested[n]]
        tag = " [TESTED: " + ", ".join(hits) + "]" if hits else " [UNTESTED]"
        print(f"  {method:6s} {path}{tag}")
    print()

if "--test-endpoints" in sys.argv:
    for name, path in suites.items():
        eps = extract_test_endpoints(path)
        if eps:
            print(f"ENDPOINTS IN {name}:")
            for m, p in sorted(eps, key=lambda x: (x[1], x[0])):
                print(f"  {m:6s} {p}")
            print()
PYTHON_EOF
