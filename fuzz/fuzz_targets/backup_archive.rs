#![no_main]

//! The backup file reader (TKBK1): the header and its key slots, the chunk stream, the
//! manifest and the key generation part. None may panic or allocate without bound on any
//! input. The first byte of the input picks the entry point: the header parser, the file
//! opened with a fixed key (the main path), the key generation decoder, or the rest of the
//! input taken as the plain stream (manifest and parts) and sealed with the fixed key
//! first, so that mutations of the manifest JSON and the parts get past the AEAD.

use libfuzzer_sys::fuzz_target;
use tenko::backup::archive::fuzzing;

fuzz_target!(|data: &[u8]| match data.split_first() {
    // The header alone.
    Some((&0, rest)) => drop(fuzzing::header(rest)),
    // A complete file, read with the fixed key.
    Some((&1, rest)) => drop(fuzzing::open_with_fixed_key(rest)),
    // The `kek.generations` part.
    Some((&2, rest)) => drop(fuzzing::keks(rest)),
    // A plain stream, sealed with the fixed key and then read.
    Some((_, rest)) => {
        if let Ok(sealed) = fuzzing::seal_with_fixed_key(rest) {
            let _ = fuzzing::open_with_fixed_key(&sealed);
        }
    }
    None => {}
});
