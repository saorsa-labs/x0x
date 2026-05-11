#![no_main]
use libfuzzer_sys::fuzz_target;
use x0x::exec::{decode_frame_payload, encode_frame_payload, ExecFrame, EXEC_DM_PREFIX};

fuzz_target!(|data: &[u8]| {
    // 1. Try to decode raw bytes as an exec payload (with prefix)
    let mut prefixed = Vec::new();
    prefixed.extend_from_slice(EXEC_DM_PREFIX);
    prefixed.extend_from_slice(data);
    let _ = decode_frame_payload(&prefixed);

    // 2. Try without prefix — should always return MissingPrefix, not crash
    let _ = decode_frame_payload(data);

    // 3. If it decodes, try re-encoding to ensure no panic in serialization
    if let Ok(frame) = decode_frame_payload(&prefixed) {
        match frame {
            // Skip frames that carry large binary blobs — fuzzing the inner
            // payload is not useful; we care about deserialization safety.
            ExecFrame::Request { .. }
            | ExecFrame::Stdout { .. }
            | ExecFrame::Stderr { .. } => {}
            _ => {
                let _ = encode_frame_payload(&frame);
            }
        }
    }
});
