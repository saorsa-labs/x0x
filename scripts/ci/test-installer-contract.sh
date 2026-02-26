#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$(mktemp -d)"
HOME_DIR="$WORK_DIR/home"
RELEASE_DIR="$WORK_DIR/release"
OUTPUT_FILE="$WORK_DIR/install-output.txt"

cleanup() {
    if [ -f "$HOME_DIR/.local/bin/x0xd" ]; then
        pkill -f "$HOME_DIR/.local/bin/x0xd" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$HOME_DIR" "$RELEASE_DIR"

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
    echo "Unsupported runner platform for installer contract test: $OS/$ARCH"
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

export HOME="$HOME_DIR"
export X0X_RELEASE_URL="file://$RELEASE_DIR"
export X0X_SKIP_GPG="true"

/usr/bin/env bash "$ROOT_DIR/scripts/install.sh" -y > "$OUTPUT_FILE" 2>&1

grep -q -- "--- x0x-install-summary ---" "$OUTPUT_FILE"
grep -q "status: success" "$OUTPUT_FILE"
grep -q "skill_installed: true" "$OUTPUT_FILE"
grep -q "daemon_installed: true" "$OUTPUT_FILE"
grep -q "daemon_running: true" "$OUTPUT_FILE"
grep -q "health: ok" "$OUTPUT_FILE"

test -f "$HOME_DIR/.local/share/x0x/SKILL.md"
test -x "$HOME_DIR/.local/bin/x0xd"

echo "Installer contract test passed"
