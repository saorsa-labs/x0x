#![no_main]
use libfuzzer_sys::fuzz_target;
use x0x::files::FileMessage;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<FileMessage>(data);
});
