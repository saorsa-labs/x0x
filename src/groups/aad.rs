//! AEAD additional-authenticated-data (AAD) wire binding for
//! `SecureShareDelivered` group-key envelopes.
//!
//! [`secure_share_aad`] is the single source of truth for the byte layout that
//! binds a sealed group secret to `(group_id, recipient, secret_epoch)`. Both
//! the production sealing path (`seal_group_secret_to_recipient`) and the
//! opening path (`open_group_secret`) reconstruct this exact binding, so the
//! sealer and opener must share it verbatim. Test fixtures that exercise the
//! live sealing path must call this function rather than duplicate the binding.

/// Construct the AEAD additional-authenticated-data binding for a
/// `SecureShareDelivered` envelope.
///
/// The layout is `b"x0x.group.share.v2|" | group_id | b"|" | recipient_hex |
/// b"|" | secret_epoch.to_le_bytes()` and must match exactly between sealer
/// and opener. Public so that production call paths and integration-test
/// fixtures share one binding instead of duplicating the wire format.
#[must_use]
pub fn secure_share_aad(group_id: &str, recipient_hex: &str, secret_epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(128);
    aad.extend_from_slice(b"x0x.group.share.v2|");
    aad.extend_from_slice(group_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(recipient_hex.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(&secret_epoch.to_le_bytes());
    aad
}
