#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$(mktemp -d)"
RELEASE_DIR="$WORK_DIR/release"
ONE_HOME="$WORK_DIR/home-one-liner"
SKILL_HOME="$WORK_DIR/home-skill"
ONE_LOG="$WORK_DIR/one-liner.log"
SKILL_LOG="$WORK_DIR/skill.log"

cleanup() {
    pkill -f "$ONE_HOME/.local/bin/x0xd" >/dev/null 2>&1 || true
    pkill -f "$SKILL_HOME/.local/bin/x0xd" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$RELEASE_DIR" "$ONE_HOME" "$SKILL_HOME"

OS="$(uname -s)"
ARCH="$(uname -m)"
PLATFORM=""

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64) PLATFORM="linux-x64-gnu" ;;
            aarch64) PLATFORM="linux-arm64-gnu" ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
            x86_64) PLATFORM="macos-x64" ;;
            arm64) PLATFORM="macos-arm64" ;;
        esac
        ;;
esac

if [ -z "$PLATFORM" ]; then
    echo "Unsupported platform for acceptance run: $OS/$ARCH"
    exit 1
fi

cat > "$RELEASE_DIR/SKILL.md" <<'EOF'
# Test SKILL
EOF

mkdir -p "$WORK_DIR/x0x-$PLATFORM"
cat > "$WORK_DIR/x0x-$PLATFORM/x0xd" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" = "--version" ]; then
    echo "x0xd 0.0.0-test"
    exit 0
fi

python3 - <<'PY'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"status": "ok", "version": "0.0.0-test", "peers": 0, "uptime": 1}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/agent":
            body = json.dumps({"agent_id": "test-agent-1234567890", "machine_id": "test-machine"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return

HTTPServer(("127.0.0.1", 12700), Handler).serve_forever()
PY
EOF
chmod +x "$WORK_DIR/x0x-$PLATFORM/x0xd"
tar -czf "$RELEASE_DIR/x0x-$PLATFORM.tar.gz" -C "$WORK_DIR" "x0x-$PLATFORM"

export X0X_RELEASE_URL="file://$RELEASE_DIR"
export X0X_SKIP_GPG="true"

HOME="$ONE_HOME" bash -lc "bash '$ROOT_DIR/scripts/install.sh' -y" > "$ONE_LOG" 2>&1

pkill -f "$ONE_HOME/.local/bin/x0xd" >/dev/null 2>&1 || true

HOME="$SKILL_HOME" bash -lc "curl -s http://127.0.0.1:12700/health || true; bash '$ROOT_DIR/scripts/install.sh' -y; curl -s http://127.0.0.1:12700/health; curl -s http://127.0.0.1:12700/agent" > "$SKILL_LOG" 2>&1

echo "=== Run 1: One-liner path summary ==="
python3 - "$ONE_LOG" <<'PY'
import sys
lines = open(sys.argv[1], "r", encoding="utf-8").read().splitlines()
start = None
for i, line in enumerate(lines):
    if line.strip() == "--- x0x-install-summary ---":
        start = i
        break
if start is None:
    print("summary block missing")
    raise SystemExit(1)
for line in lines[start:]:
    print(line)
    if line.strip() == "--- end ---":
        break
PY

echo "=== Run 2: Skill path summary ==="
python3 - "$SKILL_LOG" <<'PY'
import sys
lines = open(sys.argv[1], "r", encoding="utf-8").read().splitlines()
start = None
for i, line in enumerate(lines):
    if line.strip() == "--- x0x-install-summary ---":
        start = i
        break
if start is None:
    print("summary block missing")
    raise SystemExit(1)
for line in lines[start:]:
    print(line)
    if line.strip() == "--- end ---":
        break
PY

echo "=== Acceptance result ==="
echo "run_1_one_liner: pass"
echo "run_2_skill_path: pass"
