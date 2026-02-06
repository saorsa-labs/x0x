# GPG Signing for SKILL.md

x0x uses GPG signatures to establish trust in the SKILL.md file. This prevents tampering and ensures agents can verify they're installing the authentic x0x capability.

## Overview

Every release of x0x includes:
- `SKILL.md` - The skill file itself
- `SKILL.md.sig` - Detached GPG signature
- `SAORSA_PUBLIC_KEY.asc` - Saorsa Labs public key for verification

## Signing Process (Maintainers)

### Local Signing

```bash
# Sign SKILL.md
./scripts/sign-skill.sh

# This creates SKILL.md.sig
```

### Automated Signing (CI)

When a tag is pushed:
```bash
git tag v0.1.0
git push origin v0.1.0
```

The GitHub Actions workflow (`sign-skill.yml`) automatically:
1. Imports the GPG private key from secrets
2. Signs SKILL.md
3. Creates a GitHub release with signed files

## Verification Process (Users)

### Download Files

```bash
# Download from GitHub release
wget https://github.com/saorsa-labs/x0x/releases/latest/download/SKILL.md
wget https://github.com/saorsa-labs/x0x/releases/latest/download/SKILL.md.sig
wget https://github.com/saorsa-labs/x0x/releases/latest/download/SAORSA_PUBLIC_KEY.asc
```

### Verify Signature

```bash
# Import Saorsa Labs public key
gpg --import SAORSA_PUBLIC_KEY.asc

# Verify the signature
gpg --verify SKILL.md.sig SKILL.md
```

**Expected output:**
```
gpg: Signature made [DATE]
gpg:                using RSA key [KEY_ID]
gpg: Good signature from "Saorsa Labs <david@saorsalabs.com>" [unknown]
```

### Trust the Key (Optional)

To suppress the "unknown" trust warning:

```bash
# List keys
gpg --list-keys david@saorsalabs.com

# Edit key trust
gpg --edit-key david@saorsalabs.com
# Type: trust
# Select: 5 (ultimate) or 4 (full)
# Type: quit
```

## Security Properties

### What the Signature Guarantees

- **Authenticity**: File was signed by Saorsa Labs (holder of private key)
- **Integrity**: File has not been modified since signing
- **Non-repudiation**: Signature can be verified by anyone with the public key

### What the Signature Does NOT Guarantee

- **Content correctness**: Signature doesn't validate that the skill works correctly
- **Safety**: Signature doesn't prove the code is safe (requires code review)
- **Timeliness**: Signature doesn't prove this is the latest version

Always review the code before installing, even if the signature is valid.

## Key Management

### Key Information

- **Algorithm**: RSA 4096-bit
- **Email**: david@saorsalabs.com
- **Keyserver**: keys.openpgp.org
- **Fingerprint**: [To be added when key is generated]

### Key Rotation

If the GPG key is ever compromised or rotated:
1. New public key will be published to keyservers
2. GitHub releases will be updated with new signatures
3. Old signatures will remain valid for historical verification
4. `docs/GPG_SIGNING.md` will be updated with revocation notice

## Integration with Installation Scripts

The installation scripts (created in Task 7) will automatically verify GPG signatures before installing:

```bash
# Pseudo-code from install.sh
download_skill_md
download_signature
verify_signature || abort "Signature verification failed"
install_skill_md
```

This ensures agents never install tampered skill files.

## Troubleshooting

### "gpg: Can't check signature: No public key"

You need to import the Saorsa Labs public key:
```bash
gpg --import SAORSA_PUBLIC_KEY.asc
```

### "gpg: WARNING: This key is not certified with a trusted signature!"

This is normal if you haven't manually trusted the key. The signature is still valid, but GPG is warning you that you haven't verified the key's authenticity through the web of trust.

To fix: Trust the key as described above, or verify the key fingerprint through an independent channel (GitHub profile, website, etc.).

### "gpg: BAD signature"

The file has been tampered with. Do NOT install it. Report the issue to security@saorsalabs.com.

## See Also

- [GNU Privacy Guard (GPG) Manual](https://www.gnupg.org/documentation/)
- [GitHub GPG Signing Guide](https://docs.github.com/en/authentication/managing-commit-signature-verification)
- [OpenPGP Best Practices](https://riseup.net/en/security/message-security/openpgp/best-practices)
