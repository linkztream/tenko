//! The systemd credential KEK provider (Linux).
//!
//! The unit passes the KEK as an encrypted credential:
//!
//! ```text
//! LoadCredentialEncrypted=tenko_kek:/etc/tenko/kek.cred
//! ```
//!
//! The service manager (root) decrypts it with the host key and, when the credential was
//! made with one, the TPM2, and hands the plain key to the service as a read-only file in
//! a RAM-backed directory that only the service account can read: `$CREDENTIALS_DIRECTORY`
//! (`/run/credentials/tenko.service/`). At rest the key is the encrypted `kek.cred`, sealed
//! to the host. The service account cannot seal anything with the host key itself, so
//! generations made later (a rotation, a transfer from another controller) are wrapped under
//! the credential in the generation directory ([`super::WrapSealer`]) and share its
//! protection.
//!
//! The key file holds 32 raw bytes, 64 hexadecimal digits or base64, as for the `file`
//! provider, and its identifier is computed the same way (`file-` and eight hexadecimal
//! digits of its SHA-256): an installation that passed the credential to the `file`
//! provider (the unit of Slice 2) switches to this provider without touching an envelope.
//!
//! Tenko cannot see which key encrypted the credential; the protection reads "TPM2" only
//! when the configuration declares `with_key = "tpm2"`, and "host key" otherwise.

use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
};

use super::{
    CredsKey, KekOptions, KekProtection, KekProvider, LocalKek, Rooted,
    file::{file_id, read_key},
};
use crate::VaultError;

/// The environment variable in which the service manager names the credentials directory.
pub const CREDENTIALS_DIRECTORY: &str = "CREDENTIALS_DIRECTORY";

/// The provider: the credential `name` and its retired predecessors from the credentials
/// directory (`directory`, else `$CREDENTIALS_DIRECTORY`), and the generations of `dir`.
pub(crate) fn rooted(
    name: &str,
    retired: &[String],
    dir: &Path,
    with_key: CredsKey,
    directory: Option<&Path>,
    options: &KekOptions,
) -> Result<Rooted, VaultError> {
    let directory = credentials_directory(directory)?;
    let protection = KekProtection::SystemdCreds {
        tpm2: with_key == CredsKey::Tpm2,
    };
    let mut roots: Vec<Arc<dyn KekProvider>> = Vec::with_capacity(retired.len() + 1);
    for name in retired.iter().map(String::as_str).chain([name]) {
        roots.push(Arc::new(open_credential(&directory, name, protection)?));
    }
    Rooted::new(roots, Some(dir), protection, options)
}

fn credentials_directory(directory: Option<&Path>) -> Result<PathBuf, VaultError> {
    if let Some(directory) = directory {
        return Ok(directory.to_path_buf());
    }
    match env::var_os(CREDENTIALS_DIRECTORY) {
        Some(directory) if !directory.is_empty() => Ok(PathBuf::from(directory)),
        _ => Err(VaultError::kek_unavailable(
            "kek.provider = \"systemd_credential\" needs the service manager's credentials \
             directory, but CREDENTIALS_DIRECTORY is not set: run tenko serve from a unit with \
             LoadCredentialEncrypted=, or use another provider",
        )),
    }
}

fn open_credential(
    directory: &Path,
    name: &str,
    protection: KekProtection,
) -> Result<LocalKek, VaultError> {
    if name.is_empty() || name.contains(['/', '\0']) || name == "." || name == ".." {
        return Err(VaultError::kek_unavailable(format!(
            "{name:?} is not a credential name"
        )));
    }
    let path = directory.join(name);
    let key = read_key(&path).map_err(|error| match error {
        VaultError::KekUnavailable { reason } => VaultError::kek_unavailable(format!(
            "the systemd credential {name}: {reason}; check LoadCredentialEncrypted={name}:… \
             in the unit"
        )),
        other => other,
    })?;
    let kek = LocalKek::new(file_id(&key), protection, &key)?;
    tracing::info!(
        kek = %kek.id(),
        credential = name,
        protection = protection.describe(),
        "loaded the key-encryption key from a systemd credential"
    );
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::kek::{KekConfig, KekInit};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tenko-vault-credential-{name}-{}",
                tenko_core::SecretId::generate()
            ));
            fs::create_dir_all(&dir).expect("temp dir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn config(temp: &TempDir, with_key: CredsKey) -> KekConfig {
        KekConfig::SystemdCredential {
            name: "tenko_kek".to_owned(),
            retired: Vec::new(),
            dir: temp.0.join("kek"),
            with_key,
            directory: Some(temp.0.join("creds")),
        }
    }

    fn write_credential(temp: &TempDir, name: &str, hex: &str) {
        fs::create_dir_all(temp.0.join("creds")).expect("creds");
        fs::write(temp.0.join("creds").join(name), format!("{hex}\n")).expect("credential");
    }

    #[test]
    fn the_credential_loads_with_the_id_of_the_file_provider() {
        let temp = TempDir::new("load");
        let hex = "11".repeat(32);
        write_credential(&temp, "tenko_kek", &hex);
        let ring = config(&temp, CredsKey::Auto)
            .load(KekInit::Require)
            .expect("load");
        assert_eq!(
            ring.active().protection(),
            KekProtection::SystemdCreds { tpm2: false }
        );
        // The same key passed to the file provider has the same identifier.
        let path = temp.0.join("creds").join("tenko_kek");
        let file = KekConfig::File {
            path,
            retired: Vec::new(),
        }
        .load(KekInit::Require)
        .expect("file");
        assert_eq!(ring.active().id(), file.active().id());
        let tpm2 = config(&temp, CredsKey::Tpm2)
            .load(KekInit::Require)
            .expect("load");
        assert_eq!(
            tpm2.active().protection(),
            KekProtection::SystemdCreds { tpm2: true }
        );
    }

    #[test]
    fn a_missing_credential_or_directory_is_unavailable() {
        let temp = TempDir::new("missing");
        let Err(VaultError::KekUnavailable { reason }) =
            config(&temp, CredsKey::Auto).load(KekInit::Require)
        else {
            panic!("a missing credential must stop the load");
        };
        assert!(reason.contains("tenko_kek"), "{reason}");
        assert!(reason.contains("LoadCredentialEncrypted"), "{reason}");
        let bad = KekConfig::SystemdCredential {
            name: "../escape".to_owned(),
            retired: Vec::new(),
            dir: temp.0.join("kek"),
            with_key: CredsKey::Auto,
            directory: Some(temp.0.clone()),
        };
        assert!(bad.load(KekInit::Require).is_err());
    }

    #[test]
    fn rotation_wraps_generations_under_the_credential() {
        let temp = TempDir::new("rotate");
        write_credential(&temp, "tenko_kek", &"22".repeat(32));
        let config = config(&temp, CredsKey::Host);
        let first = config.load(KekInit::Require).expect("load");
        let next = config.create_next().expect("next");
        assert!(next.id().starts_with("wrap-1-"), "{}", next.id());
        assert_eq!(
            next.protection(),
            KekProtection::SystemdCreds { tpm2: false }
        );
        let sealed = fs::read(temp.0.join("kek").join("kek-000001.wrap")).expect("wrapped");
        assert!(!sealed.starts_with(b"TKEK"));
        let ring = config.load(KekInit::Require).expect("load");
        assert_eq!(ring.active().id(), next.id());
        assert_eq!(
            ring.retired_ids().collect::<Vec<_>>(),
            [first.active().id()]
        );
        // The root key cannot be removed, the retired generation can once another is newer.
        assert!(config.remove_retired(first.active().id()).is_err());
        // A plain file dropped beside the wrapped generations is refused (R15).
        fs::write(temp.0.join("kek").join("kek-000009.plain"), b"anything").expect("drop");
        let ring = config.load(KekInit::Require).expect("load");
        assert_eq!(ring.active().id(), next.id());
        assert_eq!(ring.refused().len(), 1);
        assert_eq!(ring.refused()[0].generation, 9);
    }
}
