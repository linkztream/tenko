//! The DPAPI KEK sealer (Windows).
//!
//! [`DpapiSealer`] protects the bytes of a KEK generation file with the Windows Data
//! Protection API (`CryptProtectData` / `CryptUnprotectData`), in the user scope of the
//! service account or in the machine scope.
//!
//! The Win32 calls live in the `windows-dpapi` crate, which exposes a safe interface, so
//! this crate stays free of FFI. Every seal mixes `tenko-kek-v1:` followed by the
//! label (the file stem, for example `kek-000001`) into DPAPI as optional entropy, so a
//! blob only unseals under the file name it was written for: renaming or copying a
//! generation file makes it unreadable. The wrapper passes no prompt structure and no
//! description string, so a seal never shows a dialog and the blob does not carry the
//! label in clear text.
//!
//! The `windows-dpapi` crate cannot pass `CRYPTPROTECT_UI_FORBIDDEN`. A blob whose
//! header asks for a prompt (a damaged file, or one not written by Tenko) would therefore
//! block the unseal on a dialog that nobody can answer, which hangs the start of a service.
//! [`DpapiSealer::unseal`](KekSealer::unseal) reads the flags of the blob header first and
//! refuses such a blob, which has the same effect as the flag.

use std::fmt;

use windows_dpapi::{Scope, decrypt_data, encrypt_data};
use zeroize::Zeroizing;

use super::{DpapiScope, KekProtection, KekSealer};
use crate::VaultError;

/// The fixed part of the entropy that is mixed into every seal.
const ENTROPY_PREFIX: &[u8] = b"tenko-kek-v1:";

/// Offset of the little-endian `dwFlags` field of a DPAPI blob: the version (4 bytes), the
/// provider GUID (16), the master key version (4) and the master key GUID (16) precede it.
const BLOB_FLAGS_OFFSET: usize = 40;

/// Blob flags that make `CryptUnprotectData` prompt the user:
/// `CRYPTPROTECT_PROMPT_ON_UNPROTECT` (0x1) and `CRYPTPROTECT_PROMPT_ON_PROTECT` (0x2).
const BLOB_PROMPT_FLAGS: u32 = 0x3;

/// Seals KEK generation files with DPAPI (`CryptProtectData`) in user or machine scope.
#[derive(Debug, Clone, Copy)]
pub struct DpapiSealer {
    scope: DpapiScope,
}

impl DpapiSealer {
    /// A sealer for the given scope.
    pub fn new(scope: DpapiScope) -> Self {
        Self { scope }
    }

    /// The scope this sealer protects with.
    pub fn scope(&self) -> DpapiScope {
        self.scope
    }
}

impl KekSealer for DpapiSealer {
    fn name(&self) -> &'static str {
        "dpapi"
    }

    fn protection(&self) -> KekProtection {
        KekProtection::Dpapi { scope: self.scope }
    }

    fn seal(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        encrypt_data(plaintext, api_scope(self.scope), Some(&entropy(label)))
            .map_err(|cause| seal_error(label, &cause))
    }

    fn unseal(&self, label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if asks_for_a_prompt(sealed) {
            return Err(unseal_error(
                self.scope,
                label,
                &"the blob asks for an interactive prompt",
            ));
        }
        decrypt_data(sealed, api_scope(self.scope), Some(&entropy(label)))
            .map(Zeroizing::new)
            .map_err(|cause| unseal_error(self.scope, label, &cause))
    }
}

fn api_scope(scope: DpapiScope) -> Scope {
    match scope {
        DpapiScope::User => Scope::User,
        DpapiScope::Machine => Scope::Machine,
    }
}

/// The DPAPI entropy of a label: `tenko-kek-v1:` followed by the label bytes.
fn entropy(label: &str) -> Vec<u8> {
    let mut entropy = Vec::with_capacity(ENTROPY_PREFIX.len() + label.len());
    entropy.extend_from_slice(ENTROPY_PREFIX);
    entropy.extend_from_slice(label.as_bytes());
    entropy
}

/// The flags of a DPAPI blob header, or `None` when the blob is too short to have them.
fn blob_flags(blob: &[u8]) -> Option<u32> {
    let bytes = blob.get(BLOB_FLAGS_OFFSET..BLOB_FLAGS_OFFSET + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Whether the header of `blob` asks `CryptUnprotectData` to prompt the user. A blob too
/// short to have flags is left to DPAPI, which rejects it at once.
fn asks_for_a_prompt(blob: &[u8]) -> bool {
    blob_flags(blob).is_some_and(|flags| flags & BLOB_PROMPT_FLAGS != 0)
}

/// `cause` is the Win32 failure of the call (an API name and an operating-system message);
/// it never holds key material.
fn seal_error(label: &str, cause: &impl fmt::Display) -> VaultError {
    VaultError::provider("dpapi", format!("cannot seal {label}: {cause:#}"))
}

fn unseal_error(scope: DpapiScope, label: &str, cause: &impl fmt::Display) -> VaultError {
    let owner = match scope {
        DpapiScope::User => "Windows account",
        DpapiScope::Machine => "machine",
    };
    VaultError::kek_unavailable(format!(
        "DPAPI could not unseal {label}: it was sealed by another {owner}, under another \
         name, or the file is damaged ({cause:#})"
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::mpsc,
        thread,
        time::Duration,
    };

    use super::*;
    use crate::kek::{KekConfig, KekInit, hex};

    const SCOPES: [DpapiScope; 2] = [DpapiScope::User, DpapiScope::Machine];

    /// A temporary directory that is removed on drop, also when a test fails.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tenko-vault-dpapi-{name}-{}",
                tenko_core::SecretId::generate()
            ));
            let _ = fs::remove_dir_all(&dir);
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample_key() -> Vec<u8> {
        (0u8..32)
            .map(|i| i.wrapping_mul(7).wrapping_add(0x41))
            .collect()
    }

    /// Bytes shaped like a KEK file: header, identifier, then 32 key bytes.
    fn sample_plaintext() -> Vec<u8> {
        let id = b"dpapi-1-0a1b2c3d";
        let mut plain = b"TKEK".to_vec();
        plain.push(1);
        plain.extend_from_slice(&1u32.to_be_bytes());
        plain.push(u8::try_from(id.len()).expect("id length"));
        plain.extend_from_slice(id);
        plain.extend_from_slice(&sample_key());
        plain
    }

    /// Unseals on a worker thread, so that a call which blocks on a DPAPI dialog fails the
    /// test instead of hanging it.
    fn unseal_within_a_deadline(
        sealer: DpapiSealer,
        blob: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(sealer.unseal("kek-000001", &blob));
        });
        receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("the unseal blocked, probably on a DPAPI prompt")
    }

    fn set_blob_flags(blob: &mut [u8], flags: u32) {
        blob[BLOB_FLAGS_OFFSET..BLOB_FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn reports_its_name_and_protection() {
        for scope in SCOPES {
            let sealer = DpapiSealer::new(scope);
            assert_eq!(sealer.name(), "dpapi");
            assert_eq!(sealer.protection(), KekProtection::Dpapi { scope });
            assert_eq!(sealer.scope(), scope);
        }
        assert_eq!(
            DpapiSealer::new(DpapiScope::default()).scope(),
            DpapiScope::User
        );
    }

    #[test]
    fn entropy_is_the_prefix_and_the_label() {
        assert_eq!(entropy("kek-000001"), b"tenko-kek-v1:kek-000001");
        assert_eq!(entropy(""), b"tenko-kek-v1:");
    }

    #[test]
    fn round_trips_in_user_scope() {
        let sealer = DpapiSealer::new(DpapiScope::User);
        let plain = sample_plaintext();
        let blob = sealer.seal("kek-000001", &plain).expect("seal");
        let back = sealer.unseal("kek-000001", &blob).expect("unseal");
        assert_eq!(back.as_slice(), plain.as_slice());
    }

    #[test]
    fn round_trips_in_machine_scope() {
        let sealer = DpapiSealer::new(DpapiScope::Machine);
        let plain = sample_plaintext();
        let blob = sealer.seal("kek-000001", &plain).expect("seal");
        let back = sealer.unseal("kek-000001", &blob).expect("unseal");
        assert_eq!(back.as_slice(), plain.as_slice());
    }

    #[test]
    fn sealed_bytes_hide_the_plaintext() {
        for scope in SCOPES {
            let sealer = DpapiSealer::new(scope);
            let plain = sample_plaintext();
            let blob = sealer.seal("kek-000001", &plain).expect("seal");
            assert_ne!(blob, plain);
            assert!(!blob.starts_with(b"TKEK"));
            assert!(!contains(&blob, &plain));
            assert!(!contains(&blob, &sample_key()));
            assert!(!contains(&blob, b"dpapi-1-0a1b2c3d"));
            assert!(
                !contains(&blob, b"kek-000001"),
                "the label stays out of the blob"
            );
        }
    }

    #[test]
    fn sealing_twice_gives_different_blobs() {
        let sealer = DpapiSealer::new(DpapiScope::User);
        let plain = sample_plaintext();
        let first = sealer.seal("kek-000001", &plain).expect("seal");
        let second = sealer.seal("kek-000001", &plain).expect("seal");
        assert_ne!(first, second);
    }

    #[test]
    fn a_different_label_fails_to_unseal() {
        for scope in SCOPES {
            let sealer = DpapiSealer::new(scope);
            let blob = sealer
                .seal("kek-000001", &sample_plaintext())
                .expect("seal");
            let Err(VaultError::KekUnavailable { reason }) = sealer.unseal("kek-000002", &blob)
            else {
                panic!("a blob must not unseal under another label");
            };
            assert!(
                reason.contains("DPAPI could not unseal kek-000002"),
                "{reason}"
            );
            assert!(
                reason.contains("another Windows account") || reason.contains("another machine"),
                "{reason}"
            );
            assert!(
                !reason.contains(&hex(&sample_key())),
                "the reason must not echo key material"
            );
        }
    }

    #[test]
    fn a_tampered_blob_fails_to_unseal() {
        for scope in SCOPES {
            let sealer = DpapiSealer::new(scope);
            let blob = sealer
                .seal("kek-000001", &sample_plaintext())
                .expect("seal");
            for index in [0, blob.len() / 2, blob.len() - 1] {
                let mut damaged = blob.clone();
                damaged[index] ^= 0x55;
                assert!(
                    matches!(
                        sealer.unseal("kek-000001", &damaged),
                        Err(VaultError::KekUnavailable { .. })
                    ),
                    "flipping byte {index} must fail the unseal"
                );
            }
            let truncated = &blob[..blob.len() - 1];
            assert!(sealer.unseal("kek-000001", truncated).is_err());
            assert!(sealer.unseal("kek-000001", &[]).is_err());
            assert!(
                sealer
                    .unseal("kek-000001", b"TKEK not a dpapi blob")
                    .is_err()
            );
        }
    }

    #[test]
    fn errors_name_the_label_and_carry_no_key_material() {
        let cause = std::io::Error::other("The parameter is incorrect. (os error 87)");
        let VaultError::Provider { provider, reason } = seal_error("kek-000003", &cause) else {
            panic!("seal errors are provider errors");
        };
        assert_eq!(provider, "dpapi");
        assert!(
            reason.contains("kek-000003") && reason.contains("os error 87"),
            "{reason}"
        );
        let VaultError::KekUnavailable { reason } =
            unseal_error(DpapiScope::Machine, "kek-000003", &cause)
        else {
            panic!("unseal errors are KEK-unavailable errors");
        };
        assert!(
            reason.starts_with("DPAPI could not unseal kek-000003"),
            "{reason}"
        );
        assert!(reason.contains("another machine"), "{reason}");
    }

    #[test]
    fn sealed_blobs_have_the_header_layout_the_prompt_guard_reads() {
        const LOCAL_MACHINE: u32 = 0x4;
        for scope in SCOPES {
            let blob = DpapiSealer::new(scope)
                .seal("kek-000001", &sample_plaintext())
                .expect("seal");
            let flags = blob_flags(&blob).expect("a blob has flags");
            assert_eq!(flags & BLOB_PROMPT_FLAGS, 0, "{scope:?}: {flags:#x}");
            assert_eq!(
                flags & LOCAL_MACHINE != 0,
                scope == DpapiScope::Machine,
                "{scope:?}: {flags:#x}"
            );
        }
    }

    #[test]
    fn blobs_that_ask_for_a_prompt_fail_instead_of_blocking() {
        for scope in SCOPES {
            let sealer = DpapiSealer::new(scope);
            let blob = sealer
                .seal("kek-000001", &sample_plaintext())
                .expect("seal");
            let flags = blob_flags(&blob).expect("a blob has flags");
            for prompt in [0x1, 0x2, 0x3] {
                let mut damaged = blob.clone();
                set_blob_flags(&mut damaged, flags | prompt);
                let Err(VaultError::KekUnavailable { reason }) =
                    unseal_within_a_deadline(sealer, damaged)
                else {
                    panic!("a blob that asks for a prompt must not unseal");
                };
                assert!(reason.contains("interactive prompt"), "{reason}");
            }
            // The undamaged blob still unseals.
            let back = unseal_within_a_deadline(sealer, blob).expect("unseal");
            assert_eq!(back.as_slice(), sample_plaintext().as_slice());
        }
    }

    #[test]
    fn blobs_too_short_for_flags_are_left_to_dpapi() {
        assert_eq!(blob_flags(&[]), None);
        assert_eq!(blob_flags(&[0xff; BLOB_FLAGS_OFFSET + 3]), None);
        assert_eq!(blob_flags(&[0xff; BLOB_FLAGS_OFFSET + 4]), Some(u32::MAX));
        assert!(!asks_for_a_prompt(&[0xff; BLOB_FLAGS_OFFSET + 3]));
        assert!(asks_for_a_prompt(&[0xff; BLOB_FLAGS_OFFSET + 4]));
        for scope in SCOPES {
            let short = [0u8; BLOB_FLAGS_OFFSET + 3];
            assert!(unseal_within_a_deadline(DpapiSealer::new(scope), short.to_vec()).is_err());
        }
    }

    fn generations_through_the_config(scope: DpapiScope) {
        let temp = TempDir::new("config");
        let dir = temp.path();
        let config = KekConfig::Dpapi {
            dir: dir.to_path_buf(),
            scope,
        };

        assert!(matches!(
            config.load(KekInit::Require),
            Err(VaultError::KekUnavailable { .. })
        ));
        let ring = config.load(KekInit::CreateIfMissing).expect("create");
        let first = ring.active().id().to_owned();
        assert!(first.starts_with("dpapi-1-"), "{first}");
        assert_eq!(ring.active().protection(), KekProtection::Dpapi { scope });
        assert_eq!(ring.retired_ids().count(), 0);

        let file = dir.join("kek-000001.dpapi");
        let on_disk = fs::read(&file).expect("generation file");
        assert!(
            !on_disk.starts_with(b"TKEK"),
            "the header must not be in clear text"
        );
        assert!(
            !contains(&on_disk, first.as_bytes()),
            "the identifier must not be in clear text"
        );

        let again = config.load(KekInit::Require).expect("load");
        assert_eq!(again.active().id(), first);

        let next = config.create_next().expect("next generation");
        assert!(next.id().starts_with("dpapi-2-"), "{}", next.id());
        assert!(dir.join("kek-000002.dpapi").exists());
        let rotated = config.load(KekInit::Require).expect("load both");
        assert_eq!(rotated.active().id(), next.id());
        assert_eq!(rotated.retired_ids().collect::<Vec<_>>(), [first.as_str()]);

        // A generation file copied under another name no longer unseals.
        let copy = dir.join("kek-000003.dpapi");
        fs::copy(&file, &copy).expect("copy");
        assert!(matches!(
            config.load(KekInit::Require),
            Err(VaultError::KekUnavailable { .. })
        ));
        fs::remove_file(&copy).expect("remove copy");
        assert!(config.load(KekInit::Require).is_ok());
    }

    #[test]
    fn generations_in_user_scope() {
        generations_through_the_config(DpapiScope::User);
    }

    #[test]
    fn generations_in_machine_scope() {
        generations_through_the_config(DpapiScope::Machine);
    }
}
