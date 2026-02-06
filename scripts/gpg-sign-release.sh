#!/bin/bash
set -e
echo "GPG signing for release $1"

# Import GPG key from secret
echo "$GPG_PRIVATE_KEY" | gpg --import --batch --yes

# Sign all release artifacts with specified key and passphrase handling
SIGNING_KEY="${SIGNING_KEY:-david@saorsalabs.com}"
for file in artifacts/**/*; do
    if [ -f "$file" ]; then
        if [ -n "${GPG_PASSPHRASE:-}" ]; then
            gpg --batch --pinentry-mode loopback --passphrase-fd 0 \
                --local-user "$SIGNING_KEY" --detach-sign --armor "$file" <<< "$GPG_PASSPHRASE"
        else
            gpg --local-user "$SIGNING_KEY" --detach-sign --armor "$file"
        fi
    fi
done
echo "Signing complete"
