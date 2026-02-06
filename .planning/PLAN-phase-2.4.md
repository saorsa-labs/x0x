# Phase 2.4: GPG-Signed SKILL.md

**Milestone**: 2 - Multi-Language Bindings & Distribution
**Phase**: 2.4
**Status**: Planning Complete
**Estimated Tasks**: 8

## Phase Overview

Create the self-propagating skill file that allows AI agents to discover and install x0x. This is the culmination of Milestone 2 - taking all the distribution infrastructure built in phases 2.1-2.3 and wrapping it in an Anthropic Agent Skill format file that agents can share with each other.

## Success Criteria

- [ ] SKILL.md in Anthropic Agent Skill format with YAML frontmatter
- [ ] Three levels of progressive disclosure (name/description, full docs, installation)
- [ ] GPG signature with detached `.sig` file
- [ ] Verification script that validates signature before installation
- [ ] A2A Agent Card (`.well-known/agent.json`) for discovery
- [ ] Distribution via npm, git, and direct download
- [ ] Installation script for each platform
- [ ] Zero warnings, all tests passing

## Task Breakdown

### Task 1: Create SKILL.md Base Structure
**Files**: `SKILL.md`
**Estimated Lines**: ~50

Create the foundational SKILL.md file with:
- YAML frontmatter (name, description, version, license)
- Level 1: Quick intro (what is x0x)
- Level 2: Installation instructions (npm, pip, cargo)
- Level 3: Basic usage example (create agent, join network, send message)

**Acceptance**:
- Valid YAML frontmatter
- Progressive disclosure structure clear
- Examples accurate for all three language SDKs

---

### Task 2: Add API Reference Section
**Files**: `SKILL.md`
**Estimated Lines**: ~100

Document the complete API surface for each language:
- Rust: Agent, TaskList, Message APIs
- Node.js: Agent, TaskList, event system
- Python: Agent, TaskList, async APIs

**Acceptance**:
- All public APIs documented
- Code examples compile/run
- Cross-references to full docs

---

### Task 3: Add Architecture Deep-Dive
**Files**: `SKILL.md`
**Estimated Lines**: ~80

Explain the technical architecture:
- Identity system (ML-DSA-65, PeerId derivation)
- Transport layer (ant-quic, NAT traversal)
- Gossip overlay (saorsa-gossip, HyParView, Plumtree)
- CRDT task lists (OR-Set, LWW-Register, RGA)
- MLS group encryption

**Acceptance**:
- Clear explanations of each layer
- Diagrams if needed (ASCII art)
- References to sibling projects (ant-quic, saorsa-gossip)

---

### Task 4: Create GPG Signing Infrastructure
**Files**: `scripts/sign-skill.sh`, `.github/workflows/sign-skill.yml`
**Estimated Lines**: ~60

Build the GPG signing workflow:
- Shell script that signs SKILL.md with Saorsa Labs key
- GitHub Actions workflow that auto-signs on release
- Detached signature output (SKILL.md.sig)
- Verification that signature is valid

**Acceptance**:
- Script signs successfully locally
- GitHub workflow signs on tag push
- Signature verifies with public key
- Zero warnings from GPG

---

### Task 5: Create Verification Script
**Files**: `scripts/verify-skill.sh`, `docs/VERIFICATION.md`
**Estimated Lines**: ~40

Build a verification script that:
- Downloads SKILL.md and SKILL.md.sig
- Fetches Saorsa Labs public key from keyserver
- Verifies signature matches
- Exits with clear error if invalid

**Acceptance**:
- Script verifies valid signatures
- Script rejects tampered files
- Clear error messages
- Documentation on manual verification

---

### Task 6: Create A2A Agent Card
**Files**: `.well-known/agent.json`, `docs/AGENT_CARD.md`
**Estimated Lines**: ~50

Generate A2A-compatible Agent Card:
- JSON schema with name, description, capabilities
- List of supported protocols (x0x/1.0)
- Endpoints for discovery (bootstrap nodes)
- License and contact info

**Acceptance**:
- Valid JSON schema
- Compatible with A2A spec
- Hosted at /.well-known/agent.json in releases
- Documentation on Agent Card format

---

### Task 7: Create Installation Scripts
**Files**: `scripts/install.sh`, `scripts/install.ps1`, `scripts/install.py`
**Estimated Lines**: ~120

Build platform-specific installation scripts:
- Bash script for Unix (macOS, Linux)
- PowerShell script for Windows
- Python script for cross-platform fallback
- Each script: verify GPG sig, detect platform, install via npm/pip

**Acceptance**:
- Scripts work on all target platforms
- GPG verification integrated
- Clear error messages
- Idempotent (can run multiple times)

---

### Task 8: Create Distribution Package
**Files**: `package.json` (update), `README.md` (update), `.github/workflows/release.yml` (update)
**Estimated Lines**: ~80

Package SKILL.md for distribution:
- Add `npx x0x-skill install` command to npm package
- Update release workflow to include SKILL.md + sig in GitHub releases
- Update README with "Share x0x" section
- Add gossip distribution mechanism (SKILL.md as gossip message)

**Acceptance**:
- `npx x0x-skill install` works
- GitHub releases include signed SKILL.md
- README updated with sharing instructions
- Zero warnings in workflows

---

## Dependencies

**Phase Dependencies**:
- Phase 2.1 (Node.js bindings) - COMPLETE
- Phase 2.2 (Python bindings) - COMPLETE
- Phase 2.3 (CI/CD pipeline) - COMPLETE

**External Dependencies**:
- GPG key available in GitHub secrets (SAORSA_GPG_PRIVATE_KEY)
- npm package published (@x0x/core)
- PyPI package published (agent-x0x)

## Testing Strategy

- Manual: Verify GPG signature with `gpg --verify SKILL.md.sig SKILL.md`
- Manual: Run installation script on clean VM (macOS, Linux, Windows)
- Manual: Test `npx x0x-skill install` command
- Automated: GitHub Actions workflow tests signature generation
- Automated: Verify A2A Agent Card JSON schema

## Notes

- This phase completes Milestone 2
- SKILL.md is the "marketing document" for x0x - make it compelling
- GPG signature establishes trust chain (Saorsa Labs → x0x)
- Agents will propagate SKILL.md to each other organically
- Keep examples simple and copy-pasteable
