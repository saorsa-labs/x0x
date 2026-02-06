# OpenAI Codex External Review

**Session**: 019c3247-d8d2-7cd2-ac7e-b9488f6fef8b
**Model**: gpt-5.2-codex (research preview)
**Date**: 2026-02-06
**Status**: COMPLETE

## Review Summary

The new signing workflow and script have conditional correctness gaps: CI will fail when using passphrase-protected keys, and local signing can silently use the wrong key, producing unverifiable releases. These issues affect release reliability and should be addressed.

## Findings

### Priority 2 - Handle passphrase-protected GPG keys in CI

**File**: `.github/workflows/sign-skill.yml` (lines 26-28)

**Issue**: If `SAORSA_GPG_PRIVATE_KEY` is passphrase-protected (the default for most GPG keys), `gpg --detach-sign` will attempt to prompt for a passphrase and fail in GitHub Actions because there's no TTY/pinentry available, so the workflow never produces a signature.

**Recommendation**: Supply a passphrase with `--pinentry-mode loopback`/`--passphrase` or explicitly document that the secret must be an unencrypted private key.

**Severity**: HIGH - Blocks release signing in CI

### Priority 3 - Ensure local signing uses the Saorsa Labs key

**File**: `scripts/sign-skill.sh` (lines 22-23)

**Issue**: The signing command relies on the GPG default key. If the maintainer has multiple keys or a different default, the script will sign with the wrong key and still report success. This means users can't verify with the published Saorsa public key.

**Recommendation**: Specify the intended key ID (e.g., via `--local-user` or an env var) to avoid accidental mismatches.

**Severity**: MEDIUM - Can produce unverifiable releases

## Analyzed Changes

**Files Reviewed**:
- `.github/workflows/sign-skill.yml` - GPG signing workflow for releases
- `scripts/sign-skill.sh` - Local signing script for SKILL.md
- `scripts/gpg-sign-release.sh` - Release artifact signing
- `docs/GPG_SIGNING.md` - Signing documentation

**Files Modified**:
- `.planning/STATE.json` - Task state updates
- `.planning/reviews/sign-skill.log` - Review tracking

## Key Observations

1. **Workflow Design**: Uses `actions/checkout@v4` and GPG key import via environment variable
2. **Script Reliability**: Bash scripts with `set -euo pipefail` for safety
3. **Documentation**: Clear GPG_SIGNING.md explaining the process to maintainers
4. **Missing Elements**:
   - No passphrase handling in CI workflow
   - No key ID specification in local signing script
   - Verification relies on locale-specific output parsing

## Recommendations

**Immediate Fixes Required**:
1. Add `--pinentry-mode loopback` to GPG signing in workflow
2. Add `--local-user <KEY_ID>` to specify signing key in scripts
3. Handle non-English locale output for verification

**Documentation Updates**:
1. Clarify if GPG private key secret must be unencrypted
2. Document required passphrase environment variables
3. Include fingerprint verification instructions for users

## Grade

**Overall Quality**: PASS with Conditionals

- Implementation exists and is functional for common cases
- Critical issues identified that must be fixed
- Affects release reliability and verification trust

---

**Reviewed by**: OpenAI Codex v0.93.0
**Reasoning Effort**: xhigh (extended reasoning)
**Sandbox**: read-only
