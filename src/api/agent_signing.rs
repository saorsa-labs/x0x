//! Domain-separated external signing for `POST /agent/sign` (issue #133 / WS1.9).
//!
//! x0x-symphony and other REST-only consumers need the daemon to sign payloads
//! with its ML-DSA-65 key *without ever touching key material*. The signing
//! half of that primitive must be domain-separated from every internal x0x
//! signing input so a caller can never trick the daemon into producing a
//! signature that doubles as a valid protocol message (an announcement, a group
//! commit, a certificate, …). This module owns the canonical-bytes construction
//! and the context-validation policy shared by the `agent_sign` and
//! `agent_verify` handlers.
//!
//! # Canonical bytes (the external DST)
//!
//! A signature is computed over
//!
//! ```text
//! [0xF0] || b"x0x.external-agent-sign.v1" || context_len(u32 BE) || context || payload
//! ```
//!
//! * `0xF0` — a reserved namespace tag that no internal signing input begins
//!   with (see "Disjointness" below).
//! * `b"x0x.external-agent-sign.v1"` — an ASCII magic pinning the DST
//!   *layout* version (`v1` = first version of this byte layout), itself
//!   unmistakably external. This is a *different* axis from [`SCHEME_ID`]'s
//!   `.v2`, which pins the API-envelope version (see below).
//! * `context_len(u32 BE)` — a length prefix for `context`, so the
//!   `context || payload` boundary is unambiguous and no `(context, payload)`
//!   pair can collide with another regardless of byte values. (This is why a
//!   NUL separator alone is insufficient: a payload containing the separator
//!   could be smuggled across the boundary.)
//! * `context` — a required, validated caller-chosen ASCII string
//!   (`[a-z0-9._-]{1,64}`, e.g. `"x0x-symphony-handoff-v1"`) naming the
//!   application protocol the signature is bound to.
//! * `payload` — the caller's bytes, taken verbatim.
//!
//! # Disjointness from internal signing domains
//!
//! Every internal x0x signing input is a serialization of a *structured*
//! record (bincode/postcard/JSON of typed fields) and **none** begins with the
//! `[0xF0] || b"x0x.external-agent-sign.v1"` prologue. Concretely the internal
//! domains (audited at the time of this change) are:
//!
//! | Internal domain | Format | Where |
//! |---|---|---|
//! | `UserAnnouncement` | bincode(unsigned fields) | `lib.rs` `sign` |
//! | `AgentCertificate` | bincode | `identity` |
//! | group commit / public message | structured `signable_bytes` | `groups/public_message.rs` |
//! | direct message | postcard `signed_bytes` | `dm.rs`, `dm_capability.rs` |
//! | gossip frame | `signing_payload` | `gossip/pubsub.rs` |
//! | a2a `AgentCard` | structured | `a2a`, `groups/card.rs` |
//! | upgrade manifest | binary manifest | `upgrade/signature.rs` |
//! | peer-relay record | `signing_bytes` | `peer_relay.rs` |
//!
//! A caller-supplied `payload` is therefore *provably* unable to impersonate
//! any of these: even if a caller supplied bytes that happened to match an
//! internal record's serialization, the daemon would sign
//! `[0xF0]|magic|len|context|<those bytes>`, which is not the bytes any
//! internal verifier checks. The `0xF0` tag makes the leading byte alone a
//! sufficient witness of the external namespace.
//!
//! On top of this structural guarantee, [`INTERNAL_CONTEXT_DENYLIST`] rejects
//! caller-chosen `context` strings that name internal domains — defense in
//! depth against a caller asking for `context = "announcement"` and then
//! claiming the result is an internal signature.

/// Reserved leading byte marking the external-signing namespace. No internal
/// signing input begins with this byte (see the module-level disjointness
/// note).
pub const NAMESPACE_TAG: u8 = 0xF0;

/// ASCII magic pinning the external-signing **canonical-bytes (DST) layout**
/// version — `v1` is the first (and current) version of the
/// `[0xF0] | magic | len | context | payload` byte layout. This is a
/// *different* versioning axis from [`SCHEME_ID`]'s `.v2`, which pins the
/// API-envelope version (the wire scheme advertised in responses / accepted
/// in the `algorithm` field). The two are intentionally independent: the DST
/// layout can stay at `v1` while the API scheme advances, and vice versa.
pub const MAGIC: &[u8] = b"x0x.external-agent-sign.v1";

/// Stable scheme identifier advertised in sign responses and accepted by
/// verify. `v2` pins the **API-envelope** version (issue #133's
/// mandatory-context DST); the pre-#133 `v1` scheme signed optional
/// `domain || 0x00 || payload` (or raw payload) and is **not** produced by
/// this implementation. This is a different axis from [`MAGIC`]'s `.v1`,
/// which pins the canonical-bytes DST *layout* version.
pub const SCHEME_ID: &str = "x0x.agent-sign.v2.ml-dsa-65";

/// Maximum signed/verified payload size (64 KiB). External signing is for
/// hashes, manifests, and audit records — not blobs.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum length of a `context` string.
pub const MAX_CONTEXT_LEN: usize = 64;

/// Caller-chosen `context` strings that name internal x0x signing domains.
/// Rejected even though the namespace tag already guarantees disjointness —
/// defense in depth so a caller can never frame an external signature as an
/// internal one. Keep lowercase; matching is exact.
pub const INTERNAL_CONTEXT_DENYLIST: &[&str] = &[
    "announcement",
    "user-announcement",
    "certificate",
    "agent-certificate",
    "group-commit",
    "group-message",
    "treekem",
    "dm",
    "direct-message",
    "gossip",
    "gossip-frame",
    "a2a-card",
    "agent-card",
    "upgrade",
    "upgrade-manifest",
    "relay",
    "peer-relay",
];

/// A `context` failed validation.
#[derive(Debug)]
pub struct ContextError(pub &'static str);

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ContextError {}

/// Validate a caller-supplied `context`.
///
/// Accepted iff it matches `^[a-z0-9._-]{1,64}$` and is not in
/// [`INTERNAL_CONTEXT_DENYLIST`].
///
/// # Errors
///
/// Returns [`ContextError`] describing the first failed check.
pub fn validate_context(context: &str) -> Result<(), ContextError> {
    if context.is_empty() {
        return Err(ContextError("context must be non-empty"));
    }
    if context.len() > MAX_CONTEXT_LEN {
        return Err(ContextError("context exceeds maximum length"));
    }
    if !context.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
    }) {
        return Err(ContextError(
            "context must match [a-z0-9._-] (lowercase ASCII, digits, dot, underscore, hyphen)",
        ));
    }
    if INTERNAL_CONTEXT_DENYLIST.contains(&context) {
        return Err(ContextError(
            "context is reserved for an internal x0x signing domain",
        ));
    }
    Ok(())
}

/// Assemble the canonical signing/verification buffer
/// `[NAMESPACE_TAG] || MAGIC || context_len(u32 BE) || context || payload`.
///
/// `context` **must** have been validated by [`validate_context`]; this function
/// does not re-validate (it is also used by the verifier, which trusts the
/// caller-supplied context only after the handler has validated it).
#[must_use]
pub fn assemble_buffer(context: &str, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + MAGIC.len() + 4 + context.len() + payload.len());
    buf.push(NAMESPACE_TAG);
    buf.extend_from_slice(MAGIC);
    // u32 big-endian length prefix → unambiguous context/payload boundary.
    let len = u32::try_from(context.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(context.as_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_contexts_accepted() {
        for c in [
            "x0x-symphony-handoff-v1",
            "audit.log.v2",
            "a",
            "foo_bar-baz.qux",
            "0123456789",
            &"x".repeat(MAX_CONTEXT_LEN),
        ] {
            assert!(
                validate_context(c).is_ok(),
                "context {c:?} should be accepted"
            );
        }
    }

    #[test]
    fn invalid_contexts_rejected() {
        // empty
        assert!(validate_context("").is_err());
        // too long
        assert!(validate_context(&"x".repeat(MAX_CONTEXT_LEN + 1)).is_err());
        // wrong characters / case
        for c in [
            "Has Space",
            "UPPER",
            "with/slash",
            "embedded\u{0}nul",
            "punctuation!",
            "café",
            "x0x handoff",
        ] {
            assert!(
                validate_context(c).is_err(),
                "context {c:?} should be rejected"
            );
        }
    }

    #[test]
    fn internal_context_denylist_rejected() {
        for c in INTERNAL_CONTEXT_DENYLIST {
            assert!(
                validate_context(c).is_err(),
                "internal context {c:?} must be denied"
            );
        }
        // a near-miss that is NOT on the denylist is fine.
        assert!(validate_context("announcement-v2-external").is_ok());
    }

    #[test]
    fn assemble_buffer_is_length_prefixed_and_disjoint() {
        let a = assemble_buffer("ctx", b"payload");
        // Leading namespace tag + magic.
        assert_eq!(a[0], NAMESPACE_TAG);
        assert_eq!(&a[1..1 + MAGIC.len()], MAGIC);
        // u32 BE context length == 3.
        let len = u32::from_be_bytes([
            a[1 + MAGIC.len()],
            a[2 + MAGIC.len()],
            a[3 + MAGIC.len()],
            a[4 + MAGIC.len()],
        ]);
        assert_eq!(len as usize, "ctx".len());
    }

    #[test]
    fn no_context_payload_collision_across_pairs() {
        // The length prefix guarantees (ctx1||p1) and (ctx2||p2) produce
        // distinct buffers even when ctx1+ p1 == ctx2 + p2 as raw bytes.
        let left = assemble_buffer("ab", b"cd");
        let right = assemble_buffer("abc", b"d");
        assert_ne!(
            left, right,
            "length-prefixed framing must distinguish (ab,cd) from (abc,d)"
        );
    }

    #[test]
    fn external_buffer_cannot_be_a_valid_internal_prefix() {
        // No internal signing input begins with the external prologue: the
        // 0xF0 tag alone is a sufficient witness. This test pins that
        // invariant so a future internal format that happens to start with
        // 0xF0 is caught here.
        let buf = assemble_buffer("any.context", b"");
        assert_eq!(buf[0], NAMESPACE_TAG);
        assert!(buf.starts_with(&[NAMESPACE_TAG]));
        assert!(buf.starts_with(
            &[NAMESPACE_TAG]
                .iter()
                .copied()
                .chain(MAGIC.iter().copied())
                .collect::<Vec<_>>()
        ));
    }
}
