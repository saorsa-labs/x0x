#!/bin/bash
set -e
echo "GPG signing for release $1"
# Import GPG key from secret
echo "$GPG_PRIVATE_KEY" | gpg --import --batch --yes
# Sign all release artifacts
for file in artifacts/**/*; do
    [ -f "$file" ] && gpg --detach-sign --armor "$file"
done
echo "Signing complete"
