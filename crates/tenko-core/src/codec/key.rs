//! Order-preserving binary keys.
//!
//! Store keys sort as raw bytes, so every key type encodes such that
//! `a < b` if and only if `encode(a) < encode(b)` (byte-wise), and every encoding is
//! self-delimiting, which makes the concatenation of components (a composite key, encoded
//! as a tuple) sort like the tuple. Layouts:
//!
//! | Type | Encoding |
//! |---|---|
//! | `()` | nothing |
//! | `bool` | `0x00` or `0x01` |
//! | `u8`, `u16`, `u32`, `u64`, `u128` | big-endian, fixed width |
//! | `i64`, `i128` | big-endian with the sign bit flipped, fixed width |
//! | `String`, `Vec<u8>`, `Bytes` | every `0x00` byte as `0x00 0xFF`, then the terminator `0x00 0x01` |
//! | `Uuid` and every identifier | the 16 bytes of the UUID |
//! | `Ipv4Addr`, `Ipv6Addr` | the 4 or 16 octets |
//! | `IpAddr` | family byte (`0x04` or `0x06`) plus the octets |
//! | `Ipv4Net`, `Ipv6Net` | the octets of the address, then the prefix length byte |
//! | `IpNet` | family byte plus the `Ipv4Net` or `Ipv6Net` encoding |
//! | `Option<T>` | `0x00` for `None`, `0x01` followed by `T` for `Some` |
//! | tuples up to 6 | the components concatenated |
//!
//! The escape and terminator for variable-length strings follow the "ordered code" scheme:
//! the terminator `0x00 0x01` sorts below an escaped NUL `0x00 0xFF` and below every other
//! byte, so a string sorts before all of its extensions regardless of what follows it in a
//! composite key.
//!
//! Domain types implement [`KeyCodec`] next to their definition (identifiers, revisions,
//! timestamps, MAC addresses, object references, DNS names).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use uuid::Uuid;

use crate::error::Coded;

/// A type with an order-preserving, self-delimiting binary key encoding.
pub trait KeyCodec: Sized {
    /// Appends the encoding of `self` to `out`.
    fn encode_key(&self, out: &mut Vec<u8>);

    /// Decodes one value from the front of `input` and advances `input` past it.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] if the input is truncated or malformed.
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError>;
}

/// Encodes a key into a new buffer.
pub fn encode_key<K: KeyCodec>(key: &K) -> Bytes {
    let mut out = Vec::new();
    key.encode_key(&mut out);
    Bytes::from(out)
}

/// Decodes a key that must span the whole input.
///
/// # Errors
///
/// Returns [`KeyError`] if the input is truncated, malformed or has trailing bytes.
pub fn decode_key<K: KeyCodec>(mut input: &[u8]) -> Result<K, KeyError> {
    let key = K::decode_key(&mut input)?;
    if input.is_empty() {
        Ok(key)
    } else {
        Err(KeyError::Trailing(input.len()))
    }
}

/// The smallest byte string greater than every string that starts with `prefix`, or `None`
/// if no such string exists (the prefix is empty or all `0xFF`). Used as the exclusive end
/// of a prefix scan.
pub fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xFF {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

/// A key could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The input ended inside a component.
    #[error("key is truncated")]
    Truncated,
    /// A complete key was followed by this many unexpected bytes.
    #[error("key has {0} trailing bytes")]
    Trailing(usize),
    /// A component is malformed.
    #[error("key is malformed: {0}")]
    Invalid(&'static str),
}

impl Coded for KeyError {
    fn code(&self) -> &'static str {
        "sys.codec.key"
    }
    fn http_status(&self) -> u16 {
        500
    }
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], KeyError> {
    if input.len() < len {
        return Err(KeyError::Truncated);
    }
    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

fn take_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], KeyError> {
    let bytes = take(input, N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(bytes);
    Ok(array)
}

/// Appends the escaped, terminated encoding of a byte string.
pub fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.reserve(bytes.len() + 2);
    for &byte in bytes {
        if byte == 0x00 {
            out.extend_from_slice(&[0x00, 0xFF]);
        } else {
            out.push(byte);
        }
    }
    out.extend_from_slice(&[0x00, 0x01]);
}

/// Decodes an escaped, terminated byte string from the front of `input`.
///
/// # Errors
///
/// Returns [`KeyError`] if the terminator is missing or an escape is malformed.
pub fn decode_bytes(input: &mut &[u8]) -> Result<Vec<u8>, KeyError> {
    let mut out = Vec::new();
    let mut index = 0;
    loop {
        let Some(&byte) = input.get(index) else {
            return Err(KeyError::Truncated);
        };
        if byte == 0x00 {
            match input.get(index + 1) {
                Some(0x01) => {
                    *input = &input[index + 2..];
                    return Ok(out);
                }
                Some(0xFF) => {
                    out.push(0x00);
                    index += 2;
                }
                Some(_) => return Err(KeyError::Invalid("bad escape in byte string")),
                None => return Err(KeyError::Truncated),
            }
        } else {
            out.push(byte);
            index += 1;
        }
    }
}

/// Appends the encoding of a string slice (same layout as [`String`]).
pub fn encode_str(value: &str, out: &mut Vec<u8>) {
    encode_bytes(value.as_bytes(), out);
}

impl KeyCodec for () {
    fn encode_key(&self, _out: &mut Vec<u8>) {}
    fn decode_key(_input: &mut &[u8]) -> Result<Self, KeyError> {
        Ok(())
    }
}

impl KeyCodec for bool {
    fn encode_key(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        match take_array::<1>(input)? {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(KeyError::Invalid("bool is neither 0 nor 1")),
        }
    }
}

macro_rules! unsigned_key {
    ($($ty:ty),+) => {$(
        impl KeyCodec for $ty {
            fn encode_key(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
            fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
                Ok(<$ty>::from_be_bytes(take_array(input)?))
            }
        }
    )+};
}

unsigned_key!(u8, u16, u32, u64, u128);

macro_rules! signed_key {
    ($($ty:ty => $unsigned:ty),+) => {$(
        impl KeyCodec for $ty {
            fn encode_key(&self, out: &mut Vec<u8>) {
                // Flipping the sign bit maps MIN..=MAX onto 0..=MAX of the unsigned type
                // in order.
                let flipped = self.cast_unsigned() ^ (1 << (<$unsigned>::BITS - 1));
                out.extend_from_slice(&flipped.to_be_bytes());
            }
            fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
                let flipped = <$unsigned>::from_be_bytes(take_array(input)?);
                Ok((flipped ^ (1 << (<$unsigned>::BITS - 1))).cast_signed())
            }
        }
    )+};
}

signed_key!(i64 => u64, i128 => u128);

impl KeyCodec for String {
    fn encode_key(&self, out: &mut Vec<u8>) {
        encode_str(self, out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        String::from_utf8(decode_bytes(input)?)
            .map_err(|_| KeyError::Invalid("string is not UTF-8"))
    }
}

impl KeyCodec for Vec<u8> {
    fn encode_key(&self, out: &mut Vec<u8>) {
        encode_bytes(self, out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        decode_bytes(input)
    }
}

impl KeyCodec for Bytes {
    fn encode_key(&self, out: &mut Vec<u8>) {
        encode_bytes(self, out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        decode_bytes(input).map(Bytes::from)
    }
}

impl KeyCodec for Uuid {
    fn encode_key(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        Ok(Uuid::from_bytes(take_array(input)?))
    }
}

impl KeyCodec for Ipv4Addr {
    fn encode_key(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.octets());
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        Ok(Ipv4Addr::from(take_array::<4>(input)?))
    }
}

impl KeyCodec for Ipv6Addr {
    fn encode_key(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.octets());
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        Ok(Ipv6Addr::from(take_array::<16>(input)?))
    }
}

/// Family byte of IPv4 values in [`IpAddr`] and [`IpNet`] keys.
pub const FAMILY_V4: u8 = 0x04;
/// Family byte of IPv6 values in [`IpAddr`] and [`IpNet`] keys.
pub const FAMILY_V6: u8 = 0x06;

impl KeyCodec for IpAddr {
    fn encode_key(&self, out: &mut Vec<u8>) {
        match self {
            IpAddr::V4(addr) => {
                out.push(FAMILY_V4);
                addr.encode_key(out);
            }
            IpAddr::V6(addr) => {
                out.push(FAMILY_V6);
                addr.encode_key(out);
            }
        }
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        match u8::decode_key(input)? {
            FAMILY_V4 => Ipv4Addr::decode_key(input).map(IpAddr::V4),
            FAMILY_V6 => Ipv6Addr::decode_key(input).map(IpAddr::V6),
            _ => Err(KeyError::Invalid("unknown address family")),
        }
    }
}

impl KeyCodec for Ipv4Net {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.addr().encode_key(out);
        out.push(self.prefix_len());
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        let addr = Ipv4Addr::decode_key(input)?;
        let len = u8::decode_key(input)?;
        Ipv4Net::new(addr, len).map_err(|_| KeyError::Invalid("IPv4 prefix length above 32"))
    }
}

impl KeyCodec for Ipv6Net {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.addr().encode_key(out);
        out.push(self.prefix_len());
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        let addr = Ipv6Addr::decode_key(input)?;
        let len = u8::decode_key(input)?;
        Ipv6Net::new(addr, len).map_err(|_| KeyError::Invalid("IPv6 prefix length above 128"))
    }
}

impl KeyCodec for IpNet {
    fn encode_key(&self, out: &mut Vec<u8>) {
        match self {
            IpNet::V4(net) => {
                out.push(FAMILY_V4);
                net.encode_key(out);
            }
            IpNet::V6(net) => {
                out.push(FAMILY_V6);
                net.encode_key(out);
            }
        }
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        match u8::decode_key(input)? {
            FAMILY_V4 => Ipv4Net::decode_key(input).map(IpNet::V4),
            FAMILY_V6 => Ipv6Net::decode_key(input).map(IpNet::V6),
            _ => Err(KeyError::Invalid("unknown network family")),
        }
    }
}

impl<T: KeyCodec> KeyCodec for Option<T> {
    fn encode_key(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(0x00),
            Some(value) => {
                out.push(0x01);
                value.encode_key(out);
            }
        }
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        match u8::decode_key(input)? {
            0x00 => Ok(None),
            0x01 => T::decode_key(input).map(Some),
            _ => Err(KeyError::Invalid("option marker is neither 0 nor 1")),
        }
    }
}

macro_rules! tuple_key {
    ($($name:ident),+) => {
        impl<$($name: KeyCodec),+> KeyCodec for ($($name,)+) {
            #[allow(non_snake_case)]
            fn encode_key(&self, out: &mut Vec<u8>) {
                let ($($name,)+) = self;
                $($name.encode_key(out);)+
            }
            fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
                Ok(($($name::decode_key(input)?,)+))
            }
        }
    };
}

tuple_key!(A);
tuple_key!(A, B);
tuple_key!(A, B, C);
tuple_key!(A, B, C, D);
tuple_key!(A, B, C, D, E);
tuple_key!(A, B, C, D, E, F);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_escape_nul_and_terminate() {
        let key = encode_key(&"a\0b".to_owned());
        assert_eq!(&key[..], b"a\x00\xffb\x00\x01");
        assert_eq!(decode_key::<String>(&key).expect("decode"), "a\0b");
    }

    #[test]
    fn string_sorts_before_its_extensions_in_composites() {
        // The case that breaks a single-byte terminator: ("a", 0xFFFF) against ("a\0\x01", 0).
        let short = encode_key(&("a".to_owned(), 0xFFFF_u16));
        let long = encode_key(&("a\0\x01".to_owned(), 0_u16));
        assert!(short < long);
    }

    #[test]
    fn signed_integers_sort_numerically() {
        let values = [i64::MIN, -2, -1, 0, 1, i64::MAX];
        let keys: Vec<_> = values.iter().map(encode_key).collect();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        for value in values {
            assert_eq!(decode_key::<i64>(&encode_key(&value)), Ok(value));
        }
    }

    #[test]
    fn addresses_sort_v4_before_v6() {
        let v4: IpAddr = "203.0.113.255".parse().expect("address");
        let v6: IpAddr = "2001:db8::".parse().expect("address");
        assert!(encode_key(&v4) < encode_key(&v6));
        assert_eq!(encode_key(&v4).len(), 5);
        assert_eq!(encode_key(&v6).len(), 17);
    }

    #[test]
    fn decode_rejects_trailing_and_truncated_input() {
        assert_eq!(decode_key::<u16>(&[0, 1, 2]), Err(KeyError::Trailing(1)));
        assert_eq!(decode_key::<u32>(&[0, 1]), Err(KeyError::Truncated));
        assert_eq!(decode_key::<String>(b"abc"), Err(KeyError::Truncated));
        assert!(matches!(
            decode_key::<String>(b"a\x00\x02"),
            Err(KeyError::Invalid(_))
        ));
        assert!(matches!(
            decode_key::<Ipv4Net>(&[192, 0, 2, 0, 33]),
            Err(KeyError::Invalid(_))
        ));
    }

    #[test]
    fn prefix_successor_bounds_prefix_scans() {
        assert_eq!(prefix_successor(b"ab"), Some(b"ac".to_vec()));
        assert_eq!(prefix_successor(&[0x01, 0xFF]), Some(vec![0x02]));
        assert_eq!(prefix_successor(&[0xFF, 0xFF]), None);
        assert_eq!(prefix_successor(&[]), None);
    }
}
