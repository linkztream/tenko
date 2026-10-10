#![no_main]

// The KEK transfer between controllers (ADR 0014): the frame check, the opening with a
// key the input was not sealed to, and the payload decoder that runs after a successful
// opening. None may panic or allocate without bound on any input.

use libfuzzer_sys::fuzz_target;
use tenko_vault::transfer::{self, TransferKey};

fuzz_target!(|data: &[u8]| {
    let _ = transfer::check_frame(data);
    let _ = transfer::fuzzing::decode(data);
    if let Ok(key) = TransferKey::generate() {
        let context = transfer::fetch_context(tenko_core::NodeId(1001));
        let _ = key.open(transfer::FORMAT, data, &context);
    }
});
