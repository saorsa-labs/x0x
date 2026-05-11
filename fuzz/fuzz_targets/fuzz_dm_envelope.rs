#![no_main]
use libfuzzer_sys::fuzz_target;
use x0x::dm::DmEnvelope;

fuzz_target!(|data: &[u8]| {
    // DmEnvelope::from_wire_bytes uses postcard internally with a size cap.
    // Fuzz to ensure no panic on malformed input, oversized data, or
    // truncated postcard streams.
    let _ = DmEnvelope::from_wire_bytes(data);
});
