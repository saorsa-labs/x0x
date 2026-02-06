# Phase 2.3: CI/CD Pipeline

## Overview

Create comprehensive GitHub Actions workflows for automated testing, building, and publishing of the x0x project across multiple platforms. This phase establishes CI/CD infrastructure for Rust core, Node.js (npm), and Python (PyPI) distributions with security auditing, GPG signing, and provenance attestations.

## Task List

### Task 1: Create Basic CI Workflow
**Description**: Create `.github/workflows/ci.yml` with Rust quality checks (fmt, clippy, basic tests)
**Files**:
- Create: `.github/workflows/ci.yml`
**Dependencies**: None
**Acceptance Criteria**:
- [ ] Workflow runs on push to main and PRs
- [ ] cargo fmt --check passes
- [ ] cargo clippy -- -D warnings passes
- [ ] Uses cache for faster builds
**Estimated Lines**: ~50

### Task 2: Add Comprehensive Test Job to CI
**Description**: Extend CI workflow with nextest unit tests for all workspace members
**Files**:
- Modify: `.github/workflows/ci.yml`
**Dependencies**: Task 1
**Acceptance Criteria**:
- [ ] cargo nextest run executes for all workspace members
- [ ] Uses latest stable Rust
- [ ] Test results are uploaded as artifacts
**Estimated Lines**: ~30

### Task 3: Add Documentation Build to CI
**Description**: Add cargo doc job to CI workflow to ensure documentation builds without warnings
**Files**:
- Modify: `.github/workflows/ci.yml`
**Dependencies**: Task 1
**Acceptance Criteria**:
- [ ] cargo doc --all-features --no-deps passes
- [ ] Documentation warnings treated as errors
- [ ] Runs on Linux (fast)
**Estimated Lines**: ~25

### Task 4: Create Security Audit Workflow
**Description**: Create `.github/workflows/security.yml` with cargo audit and unwrap/panic scanning
**Files**:
- Create: `.github/workflows/security.yml`
- Create: `scripts/check-panics.sh` (scan for unwrap/expect/panic)
**Dependencies**: None
**Acceptance Criteria**:
- [ ] cargo audit runs on schedule (daily) and PRs
- [ ] Panic scanner checks src/ and x0x/ (not tests/)
- [ ] Fails on any findings
**Estimated Lines**: ~60

### Task 5: Create Multi-Platform Build Matrix Workflow
**Description**: Create `.github/workflows/build.yml` with matrix for Linux/macOS/Windows builds
**Files**:
- Create: `.github/workflows/build.yml`
**Dependencies**: Task 1 (CI must pass first)
**Acceptance Criteria**:
- [ ] Matrix includes: ubuntu (x64-gnu, x64-musl, arm64), macos (x64, arm64), windows (x64)
- [ ] Uses cross-compilation where needed
- [ ] Artifacts uploaded for each platform
**Estimated Lines**: ~80

### Task 6: Add WASM Build to Build Matrix
**Description**: Integrate existing WASM build into main build workflow
**Files**:
- Modify: `.github/workflows/build.yml`
- Update: `.github/workflows/build-wasm.yml` (mark as deprecated or remove)
**Dependencies**: Task 5
**Acceptance Criteria**:
- [ ] wasm32-wasip1-threads target builds successfully
- [ ] WASM artifact uploaded
- [ ] Existing WASM workflow consolidated
**Estimated Lines**: ~40

### Task 7: Create Release Workflow Structure
**Description**: Create `.github/workflows/release.yml` triggered on v* tags with build matrix
**Files**:
- Create: `.github/workflows/release.yml`
**Dependencies**: Task 5 (reuses build matrix)
**Acceptance Criteria**:
- [ ] Triggers only on tags matching v*
- [ ] Runs full build matrix
- [ ] Creates GitHub release draft
- [ ] Uploads all platform artifacts
**Estimated Lines**: ~70

### Task 8: Add crates.io Publishing to Release
**Description**: Add layered crates.io publishing (types → core → napi → python) to release workflow
**Files**:
- Modify: `.github/workflows/release.yml`
- Create: `scripts/publish-crates.sh` (layered publishing with delays)
**Dependencies**: Task 7
**Acceptance Criteria**:
- [ ] Publishes in correct order with dependency resolution
- [ ] Uses CARGO_REGISTRY_TOKEN secret
- [ ] Waits for each crate to be available before publishing dependents
- [ ] Handles already-published errors gracefully
**Estimated Lines**: ~60

### Task 9: Add npm Publishing to Release
**Description**: Add npm publishing with provenance attestations to release workflow
**Files**:
- Modify: `.github/workflows/release.yml`
**Dependencies**: Task 7
**Acceptance Criteria**:
- [ ] Publishes @x0x/core and all platform packages
- [ ] Uses --provenance flag for Sigstore attestations
- [ ] Uses NPM_TOKEN secret
- [ ] Sets id-token: write permission for provenance
**Estimated Lines**: ~45

### Task 10: Add PyPI Publishing to Release
**Description**: Add maturin-based PyPI publishing to release workflow
**Files**:
- Modify: `.github/workflows/release.yml`
**Dependencies**: Task 7
**Acceptance Criteria**:
- [ ] Builds Python wheels with maturin
- [ ] Publishes to PyPI using PYPI_TOKEN secret
- [ ] Supports multiple platforms (manylinux, macosx, win)
**Estimated Lines**: ~50

### Task 11: Add GPG Signing to Release
**Description**: Add GPG signing for release artifacts and SKILL.md
**Files**:
- Modify: `.github/workflows/release.yml`
- Create: `scripts/gpg-sign-release.sh`
**Dependencies**: Task 7
**Acceptance Criteria**:
- [ ] Imports GPG key from GPG_PRIVATE_KEY secret
- [ ] Signs all release artifacts (tarballs, checksums)
- [ ] Signs SKILL.md (to be created in Phase 2.4)
- [ ] Uploads .sig files to release
**Estimated Lines**: ~55

### Task 12: Add Workflow Status Badges to README
**Description**: Update README.md with GitHub Actions status badges for CI, security, and release workflows
**Files**:
- Modify: `README.md`
**Dependencies**: Tasks 1, 4, 7
**Acceptance Criteria**:
- [ ] CI badge at top of README
- [ ] Security audit badge visible
- [ ] Release badge shows latest version
- [ ] Links to workflow runs
**Estimated Lines**: ~15

## Notes

- **Secrets Required**: CARGO_REGISTRY_TOKEN, NPM_TOKEN, PYPI_TOKEN, GPG_PRIVATE_KEY
- **Permissions**: id-token: write required for npm provenance
- **Build Times**: Use caching (actions/cache) for Cargo dependencies
- **Platform Limits**: GitHub Actions has limited arm64 runners - use cross-compilation
- **Publishing Order**: crates.io must be published before npm/PyPI (they depend on published Rust crates)
- **Testing**: Each workflow should be tested with workflow_dispatch trigger before relying on automatic triggers

## Success Criteria

- [ ] All CI checks pass on every push
- [ ] Security audit runs daily and on PRs
- [ ] Multi-platform builds produce artifacts for all targets
- [ ] Release workflow publishes to crates.io, npm, and PyPI on tags
- [ ] All releases are GPG signed
- [ ] npm packages have Sigstore provenance attestations
- [ ] Documentation builds without warnings
- [ ] Zero warnings, zero panics in production code
