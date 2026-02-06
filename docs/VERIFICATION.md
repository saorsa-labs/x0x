# Verifying x0x SKILL.md Signatures

This guide explains how to verify the GPG signature on SKILL.md to ensure it hasn't been tampered with.

## Quick Verification (Automated)

Use the provided verification script:

```bash
# Download files
wget https://github.com/saorsa-labs/x0x/releases/latest/download/SKILL.md
wget https://github.com/saorsa-labs/x0x/releases/latest/download/SKILL.md.sig

# Run verification script
./scripts/verify-skill.sh

# Expected output:
# ✓ Signature verification PASSED
```

## Manual Verification

### Step 1: Install GPG

**macOS:**
```bash
brew install gnupg
```

**Ubuntu/Debian:**
```bash
apt install gnupg
```

**Fedora/RHEL:**
```bash
dnf install gnupg
```

### Step 2: Download Files

Download three files from the latest release:

```bash
wget https://github.com/saorsa-labs/x0x/releases/latest/download/SKILL.md
wget https://github.com/saorsa-labs/x0x/releases/latest/download/SKILL.md.sig
wget https://github.com/saorsa-labs/x0x/releases/latest/download/SAORSA_PUBLIC_KEY.asc
```

### Step 3: Import Public Key

```bash
gpg --import SAORSA_PUBLIC_KEY.asc
```

**Output:**
```
gpg: key [KEY_ID]: public key "Saorsa Labs <david@saorsalabs.com>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

### Step 4: Verify Signature

```bash
gpg --verify SKILL.md.sig SKILL.md
```

**Expected output (success):**
```
gpg: Signature made [DATE] using RSA key [KEY_ID]
gpg: Good signature from "Saorsa Labs <david@saorsalabs.com>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: [FINGERPRINT]
```

The "Good signature" line indicates success. The warning about trust is normal unless you've manually trusted the key (see below).

**Output if file is tampered:**
```
gpg: Signature made [DATE] using RSA key [KEY_ID]
gpg: BAD signature from "Saorsa Labs <david@saorsalabs.com>" [unknown]
```

**DO NOT install if you see "BAD signature".**

### Step 5: Trust the Key (Optional)

To remove the "not certified" warning, you can manually trust the key after verifying its fingerprint through an independent channel (GitHub profile, website, etc.):

```bash
# Verify fingerprint matches official source
gpg --fingerprint david@saorsalabs.com

# Edit key trust
gpg --edit-key david@saorsalabs.com
trust
5  # Ultimate trust (or 4 for Full trust)
quit
```

Now `gpg --verify` will not show the warning.

## Verification from Keyserver

Instead of downloading the public key from GitHub releases, you can fetch it from a keyserver:

```bash
# From keys.openpgp.org
gpg --keyserver keys.openpgp.org --recv-keys [KEY_ID]

# Then verify
gpg --verify SKILL.md.sig SKILL.md
```

## What the Signature Proves

A valid signature proves:
- ✓ The file was signed by Saorsa Labs (holder of the private key)
- ✓ The file has not been modified since it was signed
- ✓ The signature timestamp indicates when it was signed

A valid signature does NOT prove:
- ✗ The content is safe or correct (you must review the code)
- ✗ This is the latest version (check GitHub releases)
- ✗ The file will work on your system (compatibility check separately)

**Always review the code before installing, even with a valid signature.**

## Troubleshooting

### "No public key"

```
gpg: Can't check signature: No public key
```

**Solution:** Import the public key (Step 3 above).

### "BAD signature"

```
gpg: BAD signature from "Saorsa Labs <david@saorsalabs.com>"
```

**Solution:** The file has been tampered with. Re-download from the official source. If the problem persists, report to security@saorsalabs.com.

### "keyserver receive failed"

```
gpg: keyserver receive failed: Server indicated a failure
```

**Solution:** Try a different keyserver or download the key directly from GitHub releases.

### "This key is not certified"

This is a warning, not an error. It means you haven't manually verified the key's authenticity through the web of trust. The signature is still valid.

**Solution:** Verify the key fingerprint through an independent channel, then trust the key (Step 5).

## Verifying Older Releases

Each release has its own signature:

```bash
# For version 0.1.0
wget https://github.com/saorsa-labs/x0x/releases/download/v0.1.0/SKILL.md
wget https://github.com/saorsa-labs/x0x/releases/download/v0.1.0/SKILL.md.sig

# Verify
gpg --verify SKILL.md.sig SKILL.md
```

## Security Considerations

### Key Revocation

If the GPG key is ever compromised:
1. A revocation certificate will be published to keyservers
2. A notice will be posted to the GitHub repository
3. Future releases will use a new key

Check for revocation:
```bash
gpg --refresh-keys david@saorsalabs.com
```

If revoked, you'll see:
```
gpg: key [KEY_ID]: "Saorsa Labs <david@saorsalabs.com>" revocation certificate imported
```

### Web of Trust

GPG uses a "web of trust" model. If you don't personally know the Saorsa Labs team, you can:
1. **Verify fingerprint through multiple channels**: GitHub profile, website, Twitter, etc.
2. **Check if trusted contacts have signed the key**: `gpg --check-sigs david@saorsalabs.com`
3. **Build trust over time**: If signatures consistently verify across releases, confidence grows

### Alternative Verification

If you don't want to use GPG, you can verify file integrity using checksums:

```bash
# Download checksum file
wget https://github.com/saorsa-labs/x0x/releases/latest/download/SHA256SUMS

# Verify
sha256sum --check SHA256SUMS
```

Note: Checksums only prove file integrity, not authenticity (anyone can generate a checksum).

## See Also

- [GPG Signing Documentation](GPG_SIGNING.md)
- [GNU Privacy Guard Manual](https://www.gnupg.org/documentation/)
- [GPG Quick Start Guide](https://www.gnupg.org/gph/en/manual/c14.html)
