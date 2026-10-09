//! Typed table definitions over the untyped store.
//!
//! The store sees tables of byte keys and byte values. A [`TableDef`] fixes the key type
//! (an order-preserving [`KeyCodec`]) and the value type (CBOR through serde) of one table,
//! so the owning package declares its tables once:
//!
//! ```
//! use tenko_core::{id::PrefixId, ipam::Prefix, table::TableDef};
//!
//! pub const PREFIXES: TableDef<PrefixId, Prefix> = TableDef::new("ipam.prefixes");
//! ```

use std::{fmt, marker::PhantomData};

use bytes::Bytes;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    codec::{
        cbor::{CodecError, from_cbor, to_cbor},
        key::{KeyCodec, KeyError, decode_key, encode_key},
    },
    names::TableName,
};

/// A store table with typed keys and values.
pub struct TableDef<K, V> {
    name: TableName,
    _types: PhantomData<fn() -> (K, V)>,
}

impl<K, V> TableDef<K, V> {
    /// Declares a table.
    ///
    /// # Panics
    ///
    /// Panics (at compile time in a `const` item) if `name` is not a namespaced name.
    pub const fn new(name: &'static str) -> Self {
        Self {
            name: TableName::from_static(name),
            _types: PhantomData,
        }
    }

    /// The table name.
    pub const fn name(&self) -> &TableName {
        &self.name
    }
}

impl<K: KeyCodec, V: Serialize + DeserializeOwned> TableDef<K, V> {
    /// Encodes a key.
    pub fn key(&self, key: &K) -> Bytes {
        encode_key(key)
    }

    /// Decodes a key.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] if the bytes are not a key of this table.
    pub fn decode_key(&self, bytes: &[u8]) -> Result<K, KeyError> {
        decode_key(bytes)
    }

    /// Encodes a value.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if the value cannot be serialized.
    pub fn encode(&self, value: &V) -> Result<Bytes, CodecError> {
        to_cbor(value)
    }

    /// Decodes a value.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if the bytes do not decode as `V`.
    pub fn decode(&self, bytes: &[u8]) -> Result<V, CodecError> {
        from_cbor(bytes)
    }
}

impl<K, V> Clone for TableDef<K, V> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            _types: PhantomData,
        }
    }
}

impl<K, V> fmt::Debug for TableDef<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TableDef({})", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::VrfId;

    const NAMES: TableDef<(VrfId, String), u64> = TableDef::new("ipam.test_names");

    #[test]
    fn table_def_encodes_keys_and_values() {
        let key = (VrfId::generate(), "a".to_owned());
        let bytes = NAMES.key(&key);
        assert_eq!(NAMES.decode_key(&bytes), Ok(key));
        let value = NAMES.encode(&42).expect("encode");
        assert_eq!(NAMES.decode(&value), Ok(42));
        assert_eq!(NAMES.name().as_str(), "ipam.test_names");
    }
}
