//! Backup keys: the recipient key pair of unattended backups and the passphrase rule.
//!
//! A recipient key file holds one X25519 private key. Its public half, the recipient, is
//! what the server keeps in its backup settings: it can write backups for the recipient but
//! cannot read them. The file is text:
//!
//! ```text
//! # Tenko backup key. It opens every backup made for its recipient; keep it offline.
//! # recipient: tkbr1:<base64url of the public key>
//! tkbk1:<base64url of the private key>
//! ```
//!
//! Lines starting with `#` and blank lines are ignored; exactly one key line must remain.

use std::{fmt, fs, io::Write as _, path::Path};

use aws_lc_rs::{
    agreement::{PrivateKey, X25519},
    encoding::AsBigEndian as _,
};
use sha2::{Digest as _, Sha256};
use tenko_auth::encoding::{base64url_decode, base64url_encode};
use zeroize::Zeroizing;

use super::BackupError;

/// The prefix of a recipient (a public key).
pub const RECIPIENT_PREFIX: &str = "tkbr1:";

/// The prefix of the key line of a recipient key file (a private key).
pub const KEY_PREFIX: &str = "tkbk1:";

/// The minimum length of a backup passphrase, in characters.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// The length of an X25519 key.
pub const KEY_LEN: usize = 32;

/// The public key that backups are wrapped to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Recipient(pub [u8; KEY_LEN]);

impl Recipient {
    /// Parses `tkbr1:<base64url>`.
    ///
    /// # Errors
    ///
    /// [`BackupError::InvalidKey`] for anything else.
    pub fn parse(text: &str) -> Result<Self, BackupError> {
        let invalid = || {
            BackupError::InvalidKey(format!(
                "a backup recipient is `{RECIPIENT_PREFIX}` followed by 43 base64url characters \
                 (`tenko backup keygen` prints it)"
            ))
        };
        let encoded = text
            .trim()
            .strip_prefix(RECIPIENT_PREFIX)
            .ok_or_else(invalid)?;
        let bytes = base64url_decode(encoded).map_err(|_| invalid())?;
        let key: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| invalid())?;
        if key.iter().all(|byte| *byte == 0) {
            return Err(invalid());
        }
        Ok(Self(key))
    }

    /// The first 8 bytes of the SHA-256 of the key: which key file opens a slot.
    pub fn tag(&self) -> [u8; 8] {
        let digest = Sha256::digest(self.0);
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&digest[..8]);
        tag
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{RECIPIENT_PREFIX}{}", base64url_encode(&self.0))
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient({self})")
    }
}

/// The private key of a recipient key file. `Debug` shows the recipient only; the bytes are
/// zeroized on drop.
pub struct BackupKey {
    private: Zeroizing<[u8; KEY_LEN]>,
    recipient: Recipient,
}

impl fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupKey")
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

impl BackupKey {
    /// A fresh key.
    ///
    /// # Errors
    ///
    /// [`BackupError::Internal`] if the random number generator fails.
    pub fn generate() -> Result<Self, BackupError> {
        let private = PrivateKey::generate(&X25519)
            .map_err(|_| BackupError::Internal("key generation failed".to_owned()))?;
        let seed: aws_lc_rs::encoding::Curve25519SeedBin<'_> = private
            .as_be_bytes()
            .map_err(|_| BackupError::Internal("key export failed".to_owned()))?;
        let bytes: [u8; KEY_LEN] = seed
            .as_ref()
            .try_into()
            .map_err(|_| BackupError::Internal("key export failed".to_owned()))?;
        Self::from_bytes(Zeroizing::new(bytes))
    }

    /// The key with these private bytes.
    ///
    /// # Errors
    ///
    /// [`BackupError::InvalidKey`] if the bytes are not an X25519 private key.
    pub fn from_bytes(private: Zeroizing<[u8; KEY_LEN]>) -> Result<Self, BackupError> {
        let invalid = || BackupError::InvalidKey("not an X25519 private key".to_owned());
        let key = PrivateKey::from_private_key(&X25519, private.as_ref()).map_err(|_| invalid())?;
        let public = key.compute_public_key().map_err(|_| invalid())?;
        let recipient = Recipient(public.as_ref().try_into().map_err(|_| invalid())?);
        Ok(Self { private, recipient })
    }

    /// The recipient of this key.
    pub fn recipient(&self) -> Recipient {
        self.recipient
    }

    /// The private bytes (for the key agreement of a slot).
    pub(crate) fn private_bytes(&self) -> &[u8; KEY_LEN] {
        &self.private
    }

    /// Parses the text of a recipient key file.
    ///
    /// # Errors
    ///
    /// [`BackupError::InvalidKey`] when it holds no key line, several, or a malformed one.
    pub fn parse_file(text: &str) -> Result<Self, BackupError> {
        let invalid = |detail: &str| {
            BackupError::InvalidKey(format!("not a Tenko backup key file: {detail}"))
        };
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'));
        let line = lines.next().ok_or_else(|| invalid("no key line"))?;
        if lines.next().is_some() {
            return Err(invalid("more than one key line"));
        }
        let encoded = line
            .strip_prefix(KEY_PREFIX)
            .ok_or_else(|| invalid("the key line does not start with `tkbk1:`"))?;
        let bytes =
            Zeroizing::new(base64url_decode(encoded).map_err(|_| invalid("bad base64url"))?);
        let private: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid("the key has the wrong length"))?;
        Self::from_bytes(Zeroizing::new(private))
    }

    /// Reads a recipient key file.
    ///
    /// # Errors
    ///
    /// [`BackupError::Io`] or [`BackupError::InvalidKey`].
    pub fn read(path: &Path) -> Result<Self, BackupError> {
        let text =
            Zeroizing::new(fs::read_to_string(path).map_err(|error| BackupError::io(path, error))?);
        Self::parse_file(&text)
    }

    /// The text of the key file.
    pub fn file_text(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "# Tenko backup key. It opens every backup made for its recipient; keep it offline.\n\
             # recipient: {}\n\
             {KEY_PREFIX}{}\n",
            self.recipient,
            base64url_encode(self.private.as_ref())
        ))
    }

    /// Writes the key file to `path`, readable by the owner only; refuses to replace a file.
    ///
    /// # Errors
    ///
    /// [`BackupError::Io`], also when `path` exists.
    pub fn write_new(&self, path: &Path) -> Result<(), BackupError> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|error| BackupError::io(path, error))?;
        file.write_all(self.file_text().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| BackupError::io(path, error))
    }
}

/// Checks the passphrase rule: at least [`MIN_PASSPHRASE_CHARS`] characters.
///
/// # Errors
///
/// [`BackupError::PassphraseWeak`].
pub fn check_passphrase(passphrase: &str) -> Result<(), BackupError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(BackupError::PassphraseWeak {
            min: MIN_PASSPHRASE_CHARS,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_file_round_trips_and_names_its_recipient() {
        let key = BackupKey::generate().expect("key");
        let text = key.file_text();
        let parsed = BackupKey::parse_file(&text).expect("parse");
        assert_eq!(parsed.recipient(), key.recipient());
        let recipient = Recipient::parse(&key.recipient().to_string()).expect("recipient");
        assert_eq!(recipient, key.recipient());
        assert!(text.contains(&format!("# recipient: {recipient}")));
        assert!(!format!("{key:?}").contains(&text[text.rfind(KEY_PREFIX).unwrap_or(0)..]));
    }

    #[test]
    fn malformed_keys_and_recipients_are_refused() {
        for text in ["", "# only a comment\n", "tkbk1:abc\n", "tkbk2:AAAA\n"] {
            assert!(BackupKey::parse_file(text).is_err(), "{text:?}");
        }
        let key = BackupKey::generate().expect("key");
        let twice = format!("{}{}", key.file_text().as_str(), key.file_text().as_str());
        assert!(BackupKey::parse_file(&twice).is_err());
        for text in [
            "",
            "tkbr1:",
            "tkbr2:AAAA",
            "tkbr1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(Recipient::parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn short_passphrases_are_refused() {
        assert!(check_passphrase("eleven char").is_err());
        assert!(check_passphrase("twelve chars").is_ok());
        assert!(check_passphrase("åäöåäöåäöåäö").is_ok());
    }

    #[test]
    fn the_key_file_is_private() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("backup.key");
        let key = BackupKey::generate().expect("key");
        key.write_new(&path).expect("write");
        assert!(key.write_new(&path).is_err(), "never replaces a key file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(
            BackupKey::read(&path).expect("read").recipient(),
            key.recipient()
        );
    }
}
