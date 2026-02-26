#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$(mktemp -d)"
RELEASE_DIR="$WORK_DIR/release"
RUN1_HOME="$WORK_DIR/home-run1"
SKILL_HOME="$WORK_DIR/home-skill"
RUN1_OUT="$WORK_DIR/run1.txt"
RUN2_OUT="$WORK_DIR/run2.txt"
SKILL_OUT="$WORK_DIR/skill.txt"

cleanup() {
    pkill -f "$RUN1_HOME/.local/bin/x0xd" >/dev/null 2>&1 || true
    pkill -f "$SKILL_HOME/.local/bin/x0xd" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$RELEASE_DIR" "$RUN1_HOME" "$SKILL_HOME"

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
    echo "Unsupported platform for repeatability test: $OS/$ARCH"
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

export HOME="$RUN1_HOME"
bash "$ROOT_DIR/scripts/install.sh" -y > "$RUN1_OUT" 2>&1

grep -q -- "--- x0x-install-summary ---" "$RUN1_OUT"
grep -q "status: success" "$RUN1_OUT"
grep -q "daemon_running: true" "$RUN1_OUT"

bash "$ROOT_DIR/scripts/install.sh" -y > "$RUN2_OUT" 2>&1
grep -q -- "--- x0x-install-summary ---" "$RUN2_OUT"
grep -q "status: success" "$RUN2_OUT"
grep -q "daemon_running: true" "$RUN2_OUT"

pkill -f "$RUN1_HOME/.local/bin/x0xd" >/dev/null 2>&1 || true

export HOME="$SKILL_HOME"

if curl -s http://127.0.0.1:12700/health >/dev/null 2>&1; then
    pkill -f x0xd >/dev/null 2>&1 || true
    sleep 1
fi

bash "$ROOT_DIR/scripts/install.sh" -y > "$SKILL_OUT" 2>&1

grep -q "status: success" "$SKILL_OUT"
grep -q "daemon_running: true" "$SKILL_OUT"
grep -q "health: ok" "$SKILL_OUT"

echo "Repeatability test passed"
