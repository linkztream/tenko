//! Who writes which record, and what the reply's option 81 says about it (RFC 4702
//! section 4, plan section 2.9, ADR 0020 point 4).
//!
//! Tenko always writes the PTR record. It writes the A record too unless the client asked
//! to write it itself (flag S clear, or flag N set) and the scope allows that
//! (`client_may_update_a`, off by default: clients cannot write into Tenko zones without
//! a key). The reply's flags:
//!
//! | Scope | Client | Reply |
//! |---|---|---|
//! | DDNS off | any | N, and O when the client asked for S |
//! | DDNS on, the server writes A | S set | S |
//! | DDNS on, the server writes A | S clear | S and O (the server overrode the client) |
//! | DDNS on, the client writes A | S clear | none of S, O, N: the server writes the PTR only |
//!
//! E is echoed. The reply is built before the update runs, so it says what the server will
//! do; a name refused later (name protection, a zone that does not allow DHCP) shows on
//! the lease and in `tenko_dhcp_ddns_total`, as with other servers.

use tenko_core::dhcp::DdnsPolicy;

use crate::v4::ClientFqdn;

/// Whether the server writes the A record for a client that sent `client_flags` (none:
/// the client sent no option 81, or the row predates the flags; the server writes it).
pub fn server_writes_a(policy: &DdnsPolicy, client_flags: Option<u8>) -> bool {
    let client_writes = client_flags
        .is_some_and(|flags| flags & ClientFqdn::FLAG_S == 0 || flags & ClientFqdn::FLAG_N != 0);
    !(policy.client_may_update_a && client_writes)
}

/// The flags of the reply's option 81 for a client that sent `client` under `policy`.
pub fn reply_flags(policy: &DdnsPolicy, client: u8) -> u8 {
    let echo = client & ClientFqdn::FLAG_E;
    let asked_s = client & ClientFqdn::FLAG_S != 0;
    if !policy.enabled {
        let mut flags = ClientFqdn::FLAG_N | echo;
        if asked_s {
            flags |= ClientFqdn::FLAG_O;
        }
        return flags;
    }
    if server_writes_a(policy, Some(client)) {
        let mut flags = ClientFqdn::FLAG_S | echo;
        if !asked_s {
            flags |= ClientFqdn::FLAG_O;
        }
        flags
    } else {
        echo
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u8 = ClientFqdn::FLAG_S;
    const O: u8 = ClientFqdn::FLAG_O;
    const E: u8 = ClientFqdn::FLAG_E;
    const N: u8 = ClientFqdn::FLAG_N;

    #[test]
    fn the_reply_says_what_the_server_does() {
        let off = DdnsPolicy::default();
        assert_eq!(reply_flags(&off, S | E), N | O | E);
        assert_eq!(reply_flags(&off, 0), N);
        let on = DdnsPolicy {
            enabled: true,
            ..DdnsPolicy::default()
        };
        assert_eq!(reply_flags(&on, S | E), S | E);
        assert_eq!(reply_flags(&on, E), S | O | E);
        assert_eq!(reply_flags(&on, N), S | O);
        let client_a = DdnsPolicy {
            client_may_update_a: true,
            ..on.clone()
        };
        assert_eq!(reply_flags(&client_a, S | E), S | E);
        assert_eq!(reply_flags(&client_a, E), E);
        assert!(!server_writes_a(&client_a, Some(E)));
        assert!(server_writes_a(&client_a, Some(S)));
        assert!(server_writes_a(&client_a, None));
        assert!(server_writes_a(&on, Some(0)));
    }
}
