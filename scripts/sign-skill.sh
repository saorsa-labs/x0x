#!/usr/bin/env bash
# Sign SKILL.md with Saorsa Labs GPG key

set -euo pipefail

SKILL_FILE="${1:-SKILL.md}"
SIG_FILE="${SKILL_FILE}.sig"

# Check if SKILL.md exists
if [ ! -f "$SKILL_FILE" ]; then
    echo "Error: $SKILL_FILE not found"
    exit 1
fi

# Check if GPG is available
if ! command -v gpg &> /dev/null; then
    echo "Error: gpg not found. Install with: brew install gnupg (macOS) or apt install gnupg (Linux)"
    exit 1
fi

# Sign the file
echo "Signing $SKILL_FILE..."
gpg --detach-sign --armor --output "$SIG_FILE" "$SKILL_FILE"

# Verify the signature
echo "Verifying signature..."
if gpg --verify "$SIG_FILE" "$SKILL_FILE" 2>&1 | grep -q "Good signature"; then
    echo "✓ Signature created and verified: $SIG_FILE"
    
    # Show signature info
    echo ""
    echo "Signature details:"
    gpg --verify "$SIG_FILE" "$SKILL_FILE" 2>&1 | grep -E "(Good signature|Primary key fingerprint)"
else
    echo "✗ Signature verification failed"
    exit 1
fi

echo ""
echo "To verify this signature, users should:"
echo "  1. Import Saorsa Labs public key:"
echo "     gpg --keyserver keys.openpgp.org --recv-keys <KEY_ID>"
echo "  2. Verify signature:"
echo "     gpg --verify $SIG_FILE $SKILL_FILE"
