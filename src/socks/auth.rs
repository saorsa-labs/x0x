//! RFC 1929 username/password auth against the daemon API token.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Constant-time API-token comparison (same digest path as `server::auth`).
///
/// Intentionally duplicated so this slice does not touch `src/server/auth.rs`
/// (#1482 loopback/auth behaviour stays untouched).
#[must_use]
pub(crate) fn token_eq(candidate: &str, api_token: &str) -> bool {
    // An empty daemon token never matches, including an empty password.
    // The candidate is not a reason to return early: a real token still
    // runs the digest compare, so an empty password fails closed there.
    if api_token.is_empty() {
        return false;
    }
    let ha = Sha256::digest(candidate.as_bytes());
    let hb = Sha256::digest(api_token.as_bytes());
    ha.ct_eq(&hb).into()
}
