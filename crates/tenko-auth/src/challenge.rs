//! Pending ceremonies between their start and finish requests: second-factor challenges,
//! WebAuthn ceremonies and TOTP enrolments.
//!
//! They live in memory, bounded and short-lived, and are never written to the store: an
//! unauthenticated client can start a WebAuthn login at will, and that must not reach the
//! replicated log. A controller restart cancels open ceremonies; the user starts again.
//! With several controllers (Slice 3) the load balancer keeps a client on one controller for
//! the few seconds of a ceremony.

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use tenko_core::{AuthStrength, SessionId, Timestamp, UserId};
use zeroize::Zeroizing;

use crate::{encoding::base64url_encode, error::AuthError, random};

/// How long a ceremony stays open.
pub const CEREMONY_TTL: Duration = Duration::from_secs(300);

/// Wrong second-factor codes accepted per challenge before it is dropped.
pub const MAX_CODE_ATTEMPTS: u32 = 5;

/// What a pending ceremony remembers.
#[derive(Clone)]
pub enum Pending {
    /// The password was correct; a second factor is required.
    SecondFactor {
        /// The user.
        user: UserId,
        /// The strength of the first factor (PIN or password).
        first: AuthStrength,
        /// Wrong codes so far.
        attempts: u32,
    },
    /// A WebAuthn login.
    WebAuthnLogin {
        /// The challenge.
        challenge: [u8; 32],
        /// The expected user, when the login named one or continues a password login.
        user: Option<UserId>,
        /// Whether the allow list was empty (a discoverable login needs the user handle).
        discoverable: bool,
        /// Whether the login continues a password login (the passkey is a second factor).
        continuation: bool,
    },
    /// A WebAuthn registration for a signed-in user.
    WebAuthnRegister {
        /// The challenge.
        challenge: [u8; 32],
        /// The user.
        user: UserId,
        /// The session that started it.
        session: SessionId,
        /// The label for the new credential.
        label: String,
        /// Whether a hardware security key with attestation was requested.
        hardware_key: bool,
    },
    /// A TOTP enrolment: the new seed until the user proves it with a code.
    TotpEnrolment {
        /// The user.
        user: UserId,
        /// The session that started it.
        session: SessionId,
        /// The seed. Zeroized on drop.
        secret: Zeroizing<Vec<u8>>,
    },
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::SecondFactor { .. } => "SecondFactor",
            Self::WebAuthnLogin { .. } => "WebAuthnLogin",
            Self::WebAuthnRegister { .. } => "WebAuthnRegister",
            Self::TotpEnrolment { .. } => "TotpEnrolment",
        };
        write!(f, "Pending::{kind}(<redacted>)")
    }
}

struct Entry {
    pending: Pending,
    expires_at: Timestamp,
}

/// The bounded store of pending ceremonies.
pub struct Ceremonies {
    entries: Mutex<HashMap<String, Entry>>,
    capacity: usize,
}

impl std::fmt::Debug for Ceremonies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ceremonies")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl Ceremonies {
    /// A store for at most `capacity` open ceremonies.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Opens a ceremony and returns its id (128 random bits, base64url).
    ///
    /// # Errors
    ///
    /// [`AuthError::Internal`] if the random source fails.
    pub fn open(&self, pending: Pending, now: Timestamp) -> Result<String, AuthError> {
        let id = base64url_encode(&random::array::<16>()?);
        let expires_at = now.checked_add(CEREMONY_TTL).unwrap_or(now);
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= self.capacity {
            entries.retain(|_, entry| entry.expires_at > now);
        }
        if entries.len() >= self.capacity {
            // Still full: drop the ceremony that expires first.
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            id.clone(),
            Entry {
                pending,
                expires_at,
            },
        );
        Ok(id)
    }

    /// Takes a ceremony out (one use).
    ///
    /// # Errors
    ///
    /// [`AuthError::ChallengeInvalid`] if it is unknown or expired.
    pub fn take(&self, id: &str, now: Timestamp) -> Result<Pending, AuthError> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        match entries.remove(id) {
            Some(entry) if entry.expires_at > now => Ok(entry.pending),
            _ => Err(AuthError::ChallengeInvalid),
        }
    }

    /// Puts a ceremony back under its id after a wrong code, open for another
    /// [`CEREMONY_TTL`]; [`MAX_CODE_ATTEMPTS`] bounds how often that happens.
    pub fn put_back(&self, id: String, pending: Pending, now: Timestamp) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let expires_at = now.checked_add(CEREMONY_TTL).unwrap_or(now);
        entries.insert(
            id,
            Entry {
                pending,
                expires_at,
            },
        );
    }

    /// The number of open ceremonies.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether no ceremony is open.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, MockClock};

    fn second_factor() -> Pending {
        Pending::SecondFactor {
            user: UserId::generate(),
            first: AuthStrength::Password,
            attempts: 0,
        }
    }

    #[test]
    fn ceremonies_are_single_use_and_expire() {
        let clock = MockClock::fixed();
        let ceremonies = Ceremonies::new(10);
        let id = ceremonies.open(second_factor(), clock.now()).expect("open");
        assert!(ceremonies.take(&id, clock.now()).is_ok());
        assert!(matches!(
            ceremonies.take(&id, clock.now()),
            Err(AuthError::ChallengeInvalid)
        ));
        let id = ceremonies.open(second_factor(), clock.now()).expect("open");
        clock.advance(CEREMONY_TTL);
        assert!(ceremonies.take(&id, clock.now()).is_err());
    }

    #[test]
    fn capacity_is_bounded() {
        let clock = MockClock::fixed();
        let ceremonies = Ceremonies::new(3);
        for _ in 0..10 {
            ceremonies.open(second_factor(), clock.now()).expect("open");
            clock.advance(Duration::from_secs(1));
        }
        assert_eq!(ceremonies.len(), 3);
    }

    #[test]
    fn debug_output_hides_secrets() {
        let pending = Pending::TotpEnrolment {
            user: UserId::generate(),
            session: SessionId::generate(),
            secret: Zeroizing::new(vec![1, 2, 3]),
        };
        assert_eq!(format!("{pending:?}"), "Pending::TotpEnrolment(<redacted>)");
    }
}
