//! The hashes of the engine: FNV-1a over octets with a final mix, and a [`Hasher`] of the
//! same kind for identifiers that implement [`Hash`]. Neither allocates.

use std::hash::{Hash, Hasher};

const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a, finished with the splitmix64 mix so that nearby inputs spread over the range.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fnv(u64);

impl Default for Fnv {
    fn default() -> Self {
        Self(OFFSET)
    }
}

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        mix(self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(PRIME);
        }
    }
}

/// The splitmix64 finaliser.
pub(crate) fn mix(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// The hash of an octet string (a client identity).
pub(crate) fn of_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = Fnv::default();
    hasher.write(bytes);
    hasher.finish()
}

/// The hash of a value through its [`Hash`] implementation.
pub(crate) fn of<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = Fnv::default();
    value.hash(&mut hasher);
    hasher.finish()
}
