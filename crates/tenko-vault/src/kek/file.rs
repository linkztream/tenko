//! The file KEK provider: an explicit key file for containers and CI.

use std::{fs, path::Path};

use aws_lc_rs::digest;
use zeroize::Zeroizing;

use super::{
    DataKey, KekProtection, KekProvider, LocalKek,
    dir::{create_private_dir, write_private},
};
use crate::VaultError;

/// A KEK read from an explicit file: 32 raw bytes, 64 hexadecimal digits, or 44 characters
/// of standard base64 (surrounding whitespace ignored), for example a container secret
/// made with `openssl rand -hex 32`. The identifier is `file-` and the first eight
/// hexadecimal digits of the key's SHA-256, so a different key in the same place never
/// matches existing envelopes. Every open logs a loud warning: the key has no OS
/// protection beyond file permissions.
#[derive(Debug)]
pub struct FileKek(LocalKek);

impl FileKek {
    /// Opens an existing key file.
    ///
    /// # Errors
    ///
    /// [`VaultError::KekUnavailable`] if the file is missing, unreadable or not a key.
    pub fn open(path: &Path) -> Result<Self, VaultError> {
        let raw = Zeroizing::new(fs::read(path).map_err(|e| {
            VaultError::kek_unavailable(format!("cannot read KEK file {}: {e}", path.display()))
        })?);
        let key = parse_key(&raw).ok_or_else(|| {
            VaultError::kek_unavailable(format!(
                "{} is not a 256-bit key (32 raw bytes, 64 hex digits or base64)",
                path.display()
            ))
        })?;
        let kek = Self::from_key(&key)?;
        tracing::warn!(
            kek = %kek.0.id(),
            path = %path.display(),
            "THE KEY-ENCRYPTION KEY IS A PLAIN FILE. Anyone who can read {} can decrypt \
             every secret in the vault. Use this provider only for containers with a \
             mounted secret and for CI; use DPAPI or systemd-creds on a host.",
            path.display()
        );
        Ok(kek)
    }

    /// Opens the key file, creating it with a random key (hexadecimal, mode 0600) when it
    /// does not exist. For first runs only.
    ///
    /// # Errors
    ///
    /// As [`open`](FileKek::open), plus I/O errors while creating.
    pub fn open_or_create(path: &Path) -> Result<Self, VaultError> {
        if !path.exists() {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                create_private_dir(parent)?;
            }
            let mut key = Zeroizing::new([0u8; DataKey::LEN]);
            aws_lc_rs::rand::fill(key.as_mut()).map_err(|_| VaultError::Crypto {
                operation: "random KEK",
            })?;
            let mut hex = Zeroizing::new(String::with_capacity(DataKey::LEN * 2 + 1));
            for byte in key.iter() {
                hex.push(char::from(HEX[usize::from(byte >> 4)]));
                hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
            hex.push('\n');
            write_private(path, hex.as_bytes())?;
            tracing::info!(path = %path.display(), "created a key-encryption key file");
        }
        Self::open(path)
    }

    fn from_key(key: &Zeroizing<[u8; DataKey::LEN]>) -> Result<Self, VaultError> {
        let hash = digest::digest(&digest::SHA256, key.as_ref());
        let id = format!("file-{}", super::hex(&hash.as_ref()[..4]));
        Ok(Self(LocalKek::new(id, KekProtection::PlainFile, key)?))
    }
}

impl KekProvider for FileKek {
    fn id(&self) -> &str {
        self.0.id()
    }

    fn protection(&self) -> KekProtection {
        self.0.protection()
    }

    fn wrap(&self, dek: &DataKey, aad: &[u8]) -> Result<Vec<u8>, VaultError> {
        self.0.wrap(dek, aad)
    }

    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<DataKey, VaultError> {
        self.0.unwrap(wrapped, aad)
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Parses 32 raw bytes, 64 hex digits or standard base64 of 32 bytes.
fn parse_key(raw: &[u8]) -> Option<Zeroizing<[u8; DataKey::LEN]>> {
    let mut key = Zeroizing::new([0u8; DataKey::LEN]);
    if raw.len() == DataKey::LEN {
        key.copy_from_slice(raw);
        return Some(key);
    }
    let text = raw.trim_ascii();
    if text.len() == DataKey::LEN * 2 {
        for (slot, pair) in key.iter_mut().zip(text.as_chunks::<2>().0) {
            *slot = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
        }
        return Some(key);
    }
    if text.len() == 44 && text.ends_with(b"=") && !text.ends_with(b"==") {
        let mut bits: u32 = 0;
        let mut count = 0u32;
        let mut out = 0usize;
        for &c in &text[..43] {
            bits = (bits << 6) | u32::from(base64_value(c)?);
            count += 6;
            if count >= 8 {
                count -= 8;
                let byte = u8::try_from((bits >> count) & 0xff).ok()?;
                *key.get_mut(out)? = byte;
                out += 1;
                bits &= (1 << count) - 1;
            }
        }
        return (out == DataKey::LEN).then_some(key);
    }
    None
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn base64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!(
                "tenko-vault-{name}-{}",
                tenko_core::SecretId::generate()
            ))
            .join("kek.key")
    }

    #[test]
    fn keys_parse_from_raw_hex_and_base64() {
        let raw: Vec<u8> = (0u8..32).collect();
        let expected = parse_key(&raw).expect("raw");
        let hex = super::super::hex(&raw).to_uppercase();
        assert_eq!(
            parse_key(format!("  {hex}\n").as_bytes())
                .expect("hex")
                .as_ref(),
            expected.as_ref()
        );
        // base64 of 0x00..0x1f.
        let b64 = b"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n";
        assert_eq!(parse_key(b64).expect("b64").as_ref(), expected.as_ref());
        assert!(parse_key(b"short").is_none());
        assert!(parse_key(&[b'z'; 64]).is_none());
    }

    #[test]
    fn missing_file_is_unavailable_and_create_round_trips() {
        let path = temp_path("file-kek");
        assert!(matches!(
            FileKek::open(&path),
            Err(VaultError::KekUnavailable { .. })
        ));
        let created = FileKek::open_or_create(&path).expect("create");
        assert!(created.id().starts_with("file-"));
        let opened = FileKek::open(&path).expect("open");
        assert_eq!(opened.id(), created.id());
        let dek = DataKey::generate().expect("dek");
        let wrapped = created.wrap(&dek, b"aad").expect("wrap");
        assert_eq!(
            opened.unwrap(&wrapped, b"aad").expect("unwrap").as_bytes(),
            dek.as_bytes()
        );
        assert_eq!(opened.protection(), KekProtection::PlainFile);
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn a_non_key_file_is_unavailable() {
        let path = temp_path("file-kek-bad");
        create_private_dir(path.parent().expect("parent")).expect("dir");
        fs::write(&path, b"not a key").expect("write");
        assert!(matches!(
            FileKek::open(&path),
            Err(VaultError::KekUnavailable { .. })
        ));
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }
}
