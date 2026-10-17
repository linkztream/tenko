//! DNS cookies (RFC 7873) with the interoperable server cookie of RFC 9018.
//!
//! The server cookie is 16 octets: version 1, three reserved octets, a 32-bit timestamp in
//! seconds and an 8-octet SipHash-2-4 of the client cookie, those 8 octets and the client
//! address under a 16-octet secret. A cookie verifies when its hash matches the current or
//! the previous secret and its timestamp is at most an hour old and at most five minutes
//! ahead. The secret belongs to the node: [`CookieSecret`] is created at start with a random
//! secret and rotated daily ([`CookieSecret::rotate`]), the previous one staying valid for a
//! day so that clients holding a cookie never see a failure at the rotation.
//!
//! Everything on the query path is allocation-free: one secret load, one or two `SipHash`
//! runs over at most 32 octets.

use std::{net::IpAddr, sync::Arc};

use arc_swap::ArcSwap;

use crate::codec::Cookie;

/// The length of a server cookie of RFC 9018.
pub const SERVER_COOKIE_LEN: usize = 16;

/// The length of the cookie option the server answers with: client and server cookie.
pub const COOKIE_OPTION_LEN: usize = 8 + SERVER_COOKIE_LEN;

/// How long a server cookie stays valid (RFC 9018, section 4.3).
pub const COOKIE_LIFETIME_SECS: u32 = 3600;

/// How far a server cookie may be ahead of the clock (RFC 9018, section 4.3).
pub const COOKIE_SKEW_SECS: u32 = 300;

/// How cookies are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CookieMode {
    /// Cookie options are ignored and never answered.
    Off,
    /// A query with a cookie gets a server cookie back; a missing or invalid server cookie
    /// is answered normally with a fresh one (RFC 7873, section 5.2.3, choice 3).
    #[default]
    On,
    /// As `On`, but a UDP query whose client sent a cookie without a valid server cookie
    /// gets BADCOOKIE with a fresh cookie (choice 2), so that a forged source address gets
    /// no answer. TCP never gets BADCOOKIE: the handshake already proved the address.
    Required,
}

/// SipHash-2-4 of `message` under the 16-octet `key` (Aumasson and Bernstein).
pub fn siphash24(key: &[u8; 16], message: &[u8]) -> u64 {
    let mut k0 = [0u8; 8];
    let mut k1 = [0u8; 8];
    k0.copy_from_slice(&key[..8]);
    k1.copy_from_slice(&key[8..]);
    let (k0, k1) = (u64::from_le_bytes(k0), u64::from_le_bytes(k1));
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let (words, rest) = message.as_chunks::<8>();
    for word in words {
        let m = u64::from_le_bytes(*word);
        v[3] ^= m;
        round(&mut v);
        round(&mut v);
        v[0] ^= m;
    }
    let mut last = [0u8; 8];
    last[..rest.len()].copy_from_slice(rest);
    // The length modulo 256 goes into the top octet.
    #[allow(clippy::cast_possible_truncation)]
    {
        last[7] = message.len() as u8;
    }
    let m = u64::from_le_bytes(last);
    v[3] ^= m;
    round(&mut v);
    round(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

#[derive(Debug, Clone, Copy)]
struct Secrets {
    current: [u8; 16],
    previous: Option<[u8; 16]>,
}

/// The node's cookie secret: the current one and the one before the last rotation.
#[derive(Debug, Clone)]
pub struct CookieSecret {
    secrets: Arc<ArcSwap<Secrets>>,
}

impl CookieSecret {
    /// A random secret.
    ///
    /// # Errors
    ///
    /// When the system random generator fails.
    pub fn random() -> Result<Self, aws_lc_rs::error::Unspecified> {
        Ok(Self::with_secret(random_secret()?))
    }

    /// A given secret (tests, and nodes that share one).
    pub fn with_secret(secret: [u8; 16]) -> Self {
        Self {
            secrets: Arc::new(ArcSwap::from_pointee(Secrets {
                current: secret,
                previous: None,
            })),
        }
    }

    /// Replaces the secret with a random one; the current one stays valid as the previous.
    ///
    /// # Errors
    ///
    /// When the system random generator fails; the secret is then unchanged.
    pub fn rotate(&self) -> Result<(), aws_lc_rs::error::Unspecified> {
        self.rotate_to(random_secret()?);
        Ok(())
    }

    /// Replaces the secret with `secret`; the current one stays valid as the previous.
    pub fn rotate_to(&self, secret: [u8; 16]) {
        let current = self.secrets.load().current;
        self.secrets.store(Arc::new(Secrets {
            current: secret,
            previous: Some(current),
        }));
    }

    /// The server cookie for a client cookie and address at a time (seconds since 1970).
    pub fn server_cookie(&self, client: &[u8; 8], address: IpAddr, now: u64) -> [u8; 16] {
        let secrets = self.secrets.load();
        // The timestamp is serial-number arithmetic on 32 bits (RFC 9018, section 4.2).
        #[allow(clippy::cast_possible_truncation)]
        let timestamp = (now as u32).to_be_bytes();
        let mut cookie = [0u8; 16];
        cookie[0] = 1;
        cookie[4..8].copy_from_slice(&timestamp);
        let hash = hash(&secrets.current, *client, &cookie[..8], address);
        cookie[8..].copy_from_slice(&hash);
        cookie
    }

    /// Whether the server part of `cookie` is one this node made for the client within its
    /// lifetime.
    pub fn verify(&self, cookie: &Cookie, address: IpAddr, now: u64) -> bool {
        let server = cookie.server();
        if server.len() != SERVER_COOKIE_LEN || server[0] != 1 {
            return false;
        }
        let stamp = u32::from_be_bytes([server[4], server[5], server[6], server[7]]);
        #[allow(clippy::cast_possible_truncation)]
        let age = (now as u32).wrapping_sub(stamp);
        // Older than the lifetime, or more than the skew ahead (a negative age wraps).
        if age > COOKIE_LIFETIME_SECS && age <= u32::MAX - COOKIE_SKEW_SECS {
            return false;
        }
        let secrets = self.secrets.load();
        let expected = hash(&secrets.current, *cookie.client(), &server[..8], address);
        if constant_eq(&expected, &server[8..]) {
            return true;
        }
        secrets.previous.is_some_and(|previous| {
            let expected = hash(&previous, *cookie.client(), &server[..8], address);
            constant_eq(&expected, &server[8..])
        })
    }

    /// The cookie option of an answer: the client cookie and a fresh server cookie.
    pub fn answer_option(&self, cookie: &Cookie, address: IpAddr, now: u64) -> [u8; 24] {
        let mut option = [0u8; COOKIE_OPTION_LEN];
        option[..8].copy_from_slice(cookie.client());
        option[8..].copy_from_slice(&self.server_cookie(cookie.client(), address, now));
        option
    }
}

fn random_secret() -> Result<[u8; 16], aws_lc_rs::error::Unspecified> {
    let mut secret = [0u8; 16];
    aws_lc_rs::rand::fill(&mut secret)?;
    Ok(secret)
}

/// SipHash-2-4 over client cookie, version, reserved, timestamp and address.
fn hash(secret: &[u8; 16], client: [u8; 8], head: &[u8], address: IpAddr) -> [u8; 8] {
    let mut input = [0u8; 32];
    input[..8].copy_from_slice(&client);
    input[8..16].copy_from_slice(head);
    let len = match address.to_canonical() {
        IpAddr::V4(v4) => {
            input[16..20].copy_from_slice(&v4.octets());
            20
        }
        IpAddr::V6(v6) => {
            input[16..32].copy_from_slice(&v6.octets());
            32
        }
    };
    siphash24(secret, &input[..len]).to_le_bytes()
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn siphash_matches_the_reference_vectors() {
        let key: [u8; 16] = std::array::from_fn(|index| u8::try_from(index).expect("index"));
        let message: Vec<u8> = (0u8..64).collect();
        // The first, second and sixteenth vectors of the reference implementation.
        assert_eq!(siphash24(&key, &message[..0]), 0x726f_db47_dd0e_0e31);
        assert_eq!(siphash24(&key, &message[..1]), 0x74f8_39c5_93dc_67fd);
        assert_eq!(siphash24(&key, &message[..15]), 0xa129_ca61_49be_45e5);
    }

    fn cookie(option: &str) -> Cookie {
        Cookie::from_option(&hex(option)).expect("cookie")
    }

    #[test]
    fn rfc_9018_appendix_a_vectors() {
        let secret: [u8; 16] = hex("e5e973e5a6b2a43f48e7dc849e37bfcf")
            .try_into()
            .expect("secret");
        let cookies = CookieSecret::with_secret(secret);
        // A.1: a new server cookie for an IPv4 client.
        let first = cookie("2464c4abcf10c957");
        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 100));
        assert_eq!(
            cookies
                .answer_option(&first, address, 1_559_731_985)
                .to_vec(),
            hex("2464c4abcf10c957010000005cf79f111f8130c3eee29480")
        );
        // A.2: forty minutes later the cookie verifies and is renewed.
        let sent = cookie("2464c4abcf10c957010000005cf79f111f8130c3eee29480");
        assert!(cookies.verify(&sent, address, 1_559_734_385));
        assert_eq!(
            cookies
                .answer_option(&sent, address, 1_559_734_385)
                .to_vec(),
            hex("2464c4abcf10c957010000005cf7a871d4a564a1442aca77")
        );
        // A.3: another client whose cookie has the reserved octets set.
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 203));
        let sent = cookie("fc93fc62807ddb8601abcdef5cf78f71a314227b6679ebf5");
        assert!(cookies.verify(&sent, address, 1_559_727_985));
        assert_eq!(
            cookies
                .answer_option(&sent, address, 1_559_734_700)
                .to_vec(),
            hex("fc93fc62807ddb86010000005cf7a9acf73a7810aca2381e")
        );
        // A.4: an IPv6 client across a rotation of the secret.
        let cookies = CookieSecret::with_secret(
            hex("dd3bdf9344b678b185a6f5cb60fca715")
                .try_into()
                .expect("secret"),
        );
        cookies.rotate_to(
            hex("445536bcd2513298075a5d379663c962")
                .try_into()
                .expect("secret"),
        );
        let address = IpAddr::V6("2001:db8:220:1:59de:d0f4:8769:82b8".parse().expect("v6"));
        let sent = cookie("22681ab97d52c298010000005cf7c57926556bd0934c72f8");
        assert!(cookies.verify(&sent, address, 1_559_741_961));
        assert_eq!(
            cookies
                .answer_option(&sent, address, 1_559_741_961)
                .to_vec(),
            hex("22681ab97d52c298010000005cf7c609a6bb79d16625507a")
        );
    }

    #[test]
    fn cookies_expire_and_survive_one_rotation() {
        let cookies = CookieSecret::with_secret([7; 16]);
        let address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let client = [1u8; 8];
        let now = 1_790_000_000;
        let option = cookies.answer_option(
            &Cookie::from_option(&client).expect("client only"),
            address,
            now,
        );
        let cookie = Cookie::from_option(&option).expect("cookie");
        assert!(cookies.verify(&cookie, address, now));
        assert!(cookies.verify(&cookie, address, now + 3600));
        assert!(!cookies.verify(&cookie, address, now + 3601), "expired");
        assert!(
            cookies.verify(&cookie, address, now - 300),
            "within the skew"
        );
        assert!(
            !cookies.verify(&cookie, address, now - 301),
            "too far ahead"
        );
        assert!(
            !cookies.verify(&cookie, IpAddr::V6(Ipv6Addr::UNSPECIFIED), now),
            "another address"
        );
        cookies.rotate_to([8; 16]);
        assert!(cookies.verify(&cookie, address, now), "the previous secret");
        cookies.rotate_to([9; 16]);
        assert!(!cookies.verify(&cookie, address, now), "two rotations ago");
        let mut forged = option;
        forged[23] ^= 1;
        let forged = Cookie::from_option(&forged).expect("cookie");
        assert!(!cookies.verify(&forged, address, now));
        assert!(CookieSecret::random().is_ok());
    }
}
