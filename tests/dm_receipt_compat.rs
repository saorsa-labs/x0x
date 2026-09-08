//! #461 compatibility fixture: a DOWNSTREAM crate (integration test target)
//! must keep constructing `DmReceipt` with the original four-field struct
//! literal. If a required field is ever added to the public struct, this
//! file fails to compile — the discriminating patch-compatibility control.

use x0x::dm::{DmPath, DmReceipt};

#[test]
fn dm_receipt_original_literal_still_compiles() {
    let receipt = DmReceipt {
        request_id: [7u8; 16],
        accepted_at: std::time::Instant::now(),
        retries_used: 0,
        path: DmPath::GossipInbox,
    };
    assert_eq!(receipt.retries_used, 0);
}
