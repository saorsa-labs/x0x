# WASM Support Roadmap

## Current Status (Phase 2.1)

### What Works
- `.cargo/config.toml` configured for `wasm32-wasip1-threads` target
- `npm run build:wasm` script in package.json
- `.github/workflows/build-wasm.yml` placeholder for Phase 2.3 CI/CD implementation
- WASM target registered in napi-rs build configuration

### What Doesn't Work (Phase 3+ Feature)
WASM compilation currently fails due to cryptographic library dependencies:

**Root Cause:** The x0x core library depends on:
- `ant-quic` - uses `aws-lc-rs` (AWS cryptographic library)
- `saorsa-pqc` - Post-quantum cryptography with C bindings
- `aws-lc-sys` - Requires C standard library headers (stdlib.h, etc.)

WASI environment does not provide C standard library headers, so these cryptographic primitives cannot compile to WASM.

### Error Example
```
aws-lc-sys@0.37.0: /path/to/stdlib.h: file not found
error: failed to run custom build command for `aws-lc-sys v0.37.0`
```

## Path to Full WASM Support (Phase 3+)

### Phase 3.1: Crypto Abstraction Layer
Create an abstract cryptography trait:
```rust
pub trait CryptographyProvider {
    fn create_keypair() -> Result<Keypair>;
    fn sign(data: &[u8]) -> Result<Signature>;
    fn verify(sig: &Signature) -> Result<bool>;
}
```

### Phase 3.2: WASM-Compatible Crypto Implementation
Options:
1. **Use rust-crypto crates** (pure Rust, WASM-compatible)
   - `ed25519-dalek` (signatures)
   - `aes-gcm` (encryption)
   - Downside: Less audited than aws-lc

2. **Use JavaScript crypto for WASM**
   - Call out to `crypto` module from Node.js
   - Downside: Different security properties

3. **Use pre-compiled WASM crypto libraries**
   - `blake3-wasm`, `ed25519-wasm`
   - Downside: Complex dependency management

### Phase 3.3: Conditional Compilation
Build system changes:
```toml
[target.'cfg(target_family = "wasm")'.dependencies]
x0x-crypto-wasm = { version = "0.1" }

[target.'cfg(not(target_family = "wasm"))'.dependencies]
x0x-crypto-native = { version = "0.1" }
```

### Phase 3.4: WASM-Specific Limitations
Document and handle:
- No filesystem persistence (in-memory keys only)
- No native socket operations (relayed through JS)
- No thread-local storage (use SharedArrayBuffer)
- Performance: 2-5x slower than native

### Phase 3.5: WASM Testing Infrastructure
- Add WASM test target to CI/CD
- Test crypto operations in WASM context
- Test message passing and gossip in WASM nodes
- Benchmark performance overhead

## Current Workarounds (Phase 2.1-2.2)

For JavaScript/TypeScript/Python users needing WASM support:

1. **Node.js Runtime** (Recommended)
   - Use native `.node` bindings (7 platforms supported)
   - No WASM needed - full performance and features

2. **Browser Environment** (Future)
   - Keep WASM support disabled until Phase 3
   - Use server-side x0x agent for browser-client communication
   - Or use wasm-compatible pure-JS implementations

3. **Electron Apps**
   - Use x0x Node.js native bindings
   - Full feature support, no WASM limitations

## Timeline

| Phase | Task | Timeline | Status |
|-------|------|----------|--------|
| 2.1 | Configure WASM target | Feb 2026 | In Progress |
| 2.2 | Python bindings (no WASM issues) | Feb 2026 | Pending |
| 2.3 | CI/CD pipeline | Feb 2026 | Pending |
| 3.0+ | Crypto abstraction layer | Q2 2026+ | Planned |
| 3.0+ | Full WASM support | Q2 2026+ | Planned |

## Summary

**Phase 2.1 Status:** WASM configuration complete, full compilation support deferred to Phase 3.

The WASM target is properly configured and documented. Actual WASM compilation requires significant refactoring of the cryptography layer, which is appropriate for Phase 3 after the core x0x functionality stabilizes across native platforms.

This design decision allows:
- Phase 2.1 to complete with full native platform support
- Phase 2.2-2.3 to proceed without WASM blocking
- Phase 3+ to systematically address WASM support with proper crypto layer refactoring

---

**Document created:** 2026-02-06
**Phase:** 2.1 - napi-rs Node.js Bindings
**Status:** WASM Support - Configuration Complete
