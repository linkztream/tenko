//! The compact lease row of the role's table (E32, M30, OPS-15) and the view the DORA path
//! reads through.
//!
//! The table used to keep each `tenko_core::dhcp::Lease` inline in its hash map: 536
//! octets a row, and with the map's spare buckets and the client index about 1 KiB per
//! lease, twice the 50 MiB that M30 allows 100,000 leases. A row is now split in two:
//!
//! - **The hot part** ([`Row`]), inline in the map: what the DORA path reads (the scope,
//!   the binding state, the client transaction time and the end of the state) and what the
//!   table keeps for itself (the revision that wrote the row, the node), 88 octets;
//! - **the rest**, one boxed byte string per row ([`Row::blob`]): the client (hardware
//!   type, `chaddr`, client identifier) first, then only the fields the row has of the
//!   partner times, the pool share, the names, the option 81 flags, the DDNS policy and
//!   outcome, the fingerprint, the relay, the observation time of earlier versions and the
//!   grant time (ADR 0031), in a compact encoding of this module.
//!
//! The DORA path reads the client from the start of the byte string without allocating
//! ([`ClientView`]); everything else is decoded only when a whole [`Lease`] is wanted (the
//! committer's batch, the API, the comparisons with the store), off the DORA path. The
//! store's rows and the wire format do not change: the encoding lives in memory only, and
//! [`Row::to_lease`] gives back the row as the store holds it (`tests/lease_table.rs`
//! checks the round trip on random rows). A timestamp of the cold part keeps its instant
//! in UTC, as the store's RFC 3339 text does.

use std::net::Ipv4Addr;

use tenko_core::{
    NodeId, PrefixId, Revision, Timestamp, VrfId,
    dhcp::{
        BindingState, ClientKey, DdnsPolicy, DdnsState, Fingerprint, Lease, PoolShare, RelayInfo,
        lease::{MAX_IDENTITY, write_identity},
    },
    dns::DnsName,
    serde_util::HexBytes,
};

/// What the DORA path reads of a lease, borrowed from the table without allocating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseView<'a> {
    /// The address.
    pub addr: Ipv4Addr,
    /// The VRF of the scope's prefix.
    pub vrf: VrfId,
    /// The scope.
    pub scope: PrefixId,
    /// The binding state.
    pub state: BindingState,
    /// The client's last transaction time.
    pub cltt: Timestamp,
    /// When the state ends.
    pub ends: Timestamp,
    /// The client.
    pub client: ClientView<'a>,
}

impl<'a> LeaseView<'a> {
    /// The view of a whole lease (the reference table's rows).
    pub fn of(lease: &'a Lease) -> Self {
        Self {
            addr: lease.addr,
            vrf: lease.vrf,
            scope: lease.scope,
            state: lease.state,
            cltt: lease.cltt,
            ends: lease.ends,
            client: ClientView::of(&lease.client),
        }
    }

    /// Whether the lease holds its address for the client at `now`
    /// ([`Lease::is_bound`]).
    pub fn is_bound(&self, now: Timestamp) -> bool {
        self.state == BindingState::Active && self.ends > now
    }

    /// Whether the address may not be given to another client at `now`
    /// ([`Lease::blocks`]).
    pub fn blocks(&self, now: Timestamp) -> bool {
        self.state.holds_address() && self.ends > now
    }
}

/// The client of a lease as the DORA path reads it: from a whole lease, or from the start
/// of a row's byte string, parsed when asked.
#[derive(Clone, Copy)]
pub struct ClientView<'a>(Client<'a>);

#[derive(Clone, Copy)]
enum Client<'a> {
    Key(&'a ClientKey),
    Encoded(&'a [u8]),
}

impl std::fmt::Debug for ClientView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (htype, chaddr, client_id) = self.parts();
        f.debug_struct("ClientView")
            .field("htype", &htype)
            .field("chaddr", &format_args!("{chaddr:02x?}"))
            .field("client_id", &client_id.map(|id| format!("{id:02x?}")))
            .finish()
    }
}

impl PartialEq for ClientView<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.parts() == other.parts()
    }
}

impl Eq for ClientView<'_> {}

impl<'a> ClientView<'a> {
    /// The view of a client key.
    pub fn of(key: &'a ClientKey) -> Self {
        Self(Client::Key(key))
    }

    fn parts(&self) -> (u8, &'a [u8], Option<&'a [u8]>) {
        match self.0 {
            Client::Key(key) => (
                key.htype,
                key.chaddr.0.as_slice(),
                key.client_id.as_ref().map(|id| id.0.as_slice()),
            ),
            Client::Encoded(blob) => {
                let mut reader = Reader::new(blob);
                let client = reader.client();
                debug_assert!(reader.ok, "a row's client decodes");
                client
            }
        }
    }

    /// The hardware type.
    pub fn htype(&self) -> u8 {
        self.parts().0
    }

    /// The hardware address, `hlen` octets of `chaddr`.
    pub fn chaddr(&self) -> &'a [u8] {
        self.parts().1
    }

    /// The client identifier (option 61), when the client sent one.
    pub fn client_id(&self) -> Option<&'a [u8]> {
        self.parts().2
    }

    /// The client's identity ([`ClientKey::identity`]), written into `out`; its length.
    pub fn identity(&self, out: &mut [u8; MAX_IDENTITY]) -> usize {
        let (htype, chaddr, client_id) = self.parts();
        write_identity(htype, chaddr, client_id, out)
    }

    /// Whether the client has `identity` ([`ClientKey::identity`]).
    pub fn is(&self, identity: &[u8]) -> bool {
        let mut held = [0u8; MAX_IDENTITY];
        let len = self.identity(&mut held);
        &held[..len] == identity
    }

    /// The Ethernet address, when the hardware type is Ethernet and `chaddr` six octets.
    pub fn mac(&self) -> Option<[u8; 6]> {
        let (htype, chaddr, _) = self.parts();
        if htype == 1 {
            <[u8; 6]>::try_from(chaddr).ok()
        } else {
            None
        }
    }

    /// The client key (allocates).
    pub fn to_key(&self) -> ClientKey {
        let (htype, chaddr, client_id) = self.parts();
        ClientKey {
            htype,
            chaddr: HexBytes(chaddr.to_vec()),
            client_id: client_id.map(|id| HexBytes(id.to_vec())),
        }
    }
}

/// One row of the table: the hot fields inline, the client and the rest in [`Row::blob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    /// The scope.
    pub scope: PrefixId,
    /// The client's last transaction time.
    pub cltt: Timestamp,
    /// When the state ends.
    pub ends: Timestamp,
    /// The revision that wrote the row (`Revision::ZERO` when unknown).
    pub revision: Revision,
    /// The node that wrote the row.
    pub node: NodeId,
    /// The binding state.
    pub state: BindingState,
    /// The client, then the cold fields the row has.
    pub blob: Box<[u8]>,
}

impl Row {
    /// The row of `lease` written at `revision`; `scratch` is the encoder's buffer, kept by
    /// the table so that one row costs one allocation of its exact size.
    pub fn new(lease: &Lease, revision: Revision, scratch: &mut Vec<u8>) -> Self {
        scratch.clear();
        encode(lease, scratch);
        Self {
            scope: lease.scope,
            cltt: lease.cltt,
            ends: lease.ends,
            revision,
            node: lease.node,
            state: lease.state,
            blob: Box::from(scratch.as_slice()),
        }
    }

    /// The view of the row at `vrf` and `addr`.
    pub fn view(&self, vrf: VrfId, addr: Ipv4Addr) -> LeaseView<'_> {
        LeaseView {
            addr,
            vrf,
            scope: self.scope,
            state: self.state,
            cltt: self.cltt,
            ends: self.ends,
            client: ClientView(Client::Encoded(&self.blob)),
        }
    }

    /// The client.
    pub fn client(&self) -> ClientView<'_> {
        ClientView(Client::Encoded(&self.blob))
    }

    /// The whole lease at `vrf` and `addr`, as the store holds it (allocates).
    pub fn to_lease(&self, vrf: VrfId, addr: Ipv4Addr) -> Lease {
        let mut reader = Reader::new(&self.blob);
        let (htype, chaddr, client_id) = reader.client();
        let mut lease = Lease {
            addr,
            vrf,
            scope: self.scope,
            client: ClientKey {
                htype,
                chaddr: HexBytes(chaddr.to_vec()),
                client_id: client_id.map(|id| HexBytes(id.to_vec())),
            },
            state: self.state,
            cltt: self.cltt,
            ends: self.ends,
            tstp: None,
            tsfp: None,
            atsfp: None,
            node: self.node,
            share: None,
            hostname: None,
            fqdn: None,
            fqdn_flags: None,
            ddns_policy: None,
            ddns: DdnsState::default(),
            fingerprint: None,
            relay: None,
            observed_at: None,
            granted: None,
        };
        decode_cold(&mut reader, &mut lease);
        debug_assert!(reader.ok && reader.at == self.blob.len(), "a row decodes");
        lease
    }
}

// The cold fields, by bit of the presence mask.
const TSTP: u32 = 1;
const TSFP: u32 = 1 << 1;
const ATSFP: u32 = 1 << 2;
const SHARE: u32 = 1 << 3;
const HOSTNAME: u32 = 1 << 4;
const FQDN: u32 = 1 << 5;
const FQDN_FLAGS: u32 = 1 << 6;
const DDNS_POLICY: u32 = 1 << 7;
const DDNS: u32 = 1 << 8;
const FINGERPRINT: u32 = 1 << 9;
const RELAY: u32 = 1 << 10;
const OBSERVED_AT: u32 = 1 << 11;
// ADR 0031: the grant time of the binding.
const GRANTED: u32 = 1 << 12;

/// The encoding: the hardware type, `chaddr` with its length, the client identifier's
/// length plus one (zero: none) and its octets, the presence mask of the cold fields, then
/// each present field in the order of the mask's bits. Lengths and numbers are LEB128,
/// signed ones zigzag; a timestamp is its Unix time in nanoseconds.
fn encode(lease: &Lease, out: &mut Vec<u8>) {
    let client = &lease.client;
    out.push(client.htype);
    put_bytes(out, &client.chaddr.0);
    match &client.client_id {
        Some(id) => {
            put_varint(out, id.0.len() as u128 + 1);
            out.extend_from_slice(&id.0);
        }
        None => put_varint(out, 0),
    }
    let policy = lease.ddns_policy.as_ref().and_then(|policy| {
        tenko_core::codec::cbor::to_cbor(policy)
            .ok()
            .map(|bytes| bytes.to_vec())
    });
    debug_assert_eq!(
        policy.is_some(),
        lease.ddns_policy.is_some(),
        "a policy encodes"
    );
    let mask = [
        (TSTP, lease.tstp.is_some()),
        (TSFP, lease.tsfp.is_some()),
        (ATSFP, lease.atsfp.is_some()),
        (SHARE, lease.share.is_some()),
        (HOSTNAME, lease.hostname.is_some()),
        (FQDN, lease.fqdn.is_some()),
        (FQDN_FLAGS, lease.fqdn_flags.is_some()),
        (DDNS_POLICY, policy.is_some()),
        (DDNS, lease.ddns != DdnsState::default()),
        (FINGERPRINT, lease.fingerprint.is_some()),
        (RELAY, lease.relay.is_some()),
        (OBSERVED_AT, lease.observed_at.is_some()),
        (GRANTED, lease.granted.is_some()),
    ]
    .iter()
    .filter(|(_, present)| *present)
    .fold(0, |mask, (bit, _)| mask | bit);
    put_varint(out, u128::from(mask));
    for time in [lease.tstp, lease.tsfp, lease.atsfp].into_iter().flatten() {
        put_time(out, time);
    }
    if let Some(share) = lease.share {
        out.push(match share {
            PoolShare::Primary => 0,
            PoolShare::Secondary => 1,
        });
    }
    if let Some(hostname) = &lease.hostname {
        put_bytes(out, hostname.as_bytes());
    }
    if let Some(fqdn) = &lease.fqdn {
        put_bytes(out, fqdn.as_bytes());
    }
    if let Some(flags) = lease.fqdn_flags {
        out.push(flags);
    }
    if let Some(policy) = &policy {
        put_bytes(out, policy);
    }
    if mask & DDNS != 0 {
        put_ddns(out, &lease.ddns);
    }
    if let Some(fingerprint) = &lease.fingerprint {
        put_fingerprint(out, fingerprint);
    }
    if let Some(relay) = &lease.relay {
        put_relay(out, relay);
    }
    if let Some(time) = lease.observed_at {
        put_time(out, time);
    }
    if let Some(time) = lease.granted {
        put_time(out, time);
    }
}

fn put_ddns(out: &mut Vec<u8>, ddns: &DdnsState) {
    let flags = u8::from(ddns.forward.is_some())
        | u8::from(ddns.reverse.is_some()) << 1
        | u8::from(ddns.dhcid.is_some()) << 2
        | u8::from(ddns.last_error.is_some()) << 3
        | u8::from(ddns.updated.is_some()) << 4;
    out.push(flags);
    for name in [&ddns.forward, &ddns.reverse].into_iter().flatten() {
        put_bytes(out, name.as_str().as_bytes());
    }
    if let Some(dhcid) = &ddns.dhcid {
        put_bytes(out, &dhcid.0);
    }
    if let Some(error) = &ddns.last_error {
        put_bytes(out, error.as_bytes());
    }
    if let Some(time) = ddns.updated {
        put_time(out, time);
    }
}

fn put_fingerprint(out: &mut Vec<u8>, fingerprint: &Fingerprint) {
    put_bytes(out, &fingerprint.parameters.0);
    let flags = u8::from(fingerprint.user_class)
        | u8::from(fingerprint.client_fqdn) << 1
        | u8::from(fingerprint.vendor_class.is_some()) << 2
        | u8::from(fingerprint.architecture.is_some()) << 3;
    out.push(flags);
    if let Some(vendor) = &fingerprint.vendor_class {
        put_bytes(out, vendor.as_bytes());
    }
    if let Some(architecture) = fingerprint.architecture {
        out.extend_from_slice(&architecture.to_le_bytes());
    }
}

fn put_relay(out: &mut Vec<u8>, relay: &RelayInfo) {
    out.extend_from_slice(&relay.giaddr.octets());
    let flags = u8::from(relay.circuit_id.is_some())
        | u8::from(relay.remote_id.is_some()) << 1
        | u8::from(relay.link_selection.is_some()) << 2
        | u8::from(relay.server_id_override.is_some()) << 3;
    out.push(flags);
    for id in [&relay.circuit_id, &relay.remote_id].into_iter().flatten() {
        put_bytes(out, &id.0);
    }
    for addr in [relay.link_selection, relay.server_id_override]
        .into_iter()
        .flatten()
    {
        out.extend_from_slice(&addr.octets());
    }
    put_bytes(out, &relay.raw.0);
}

fn decode_cold(reader: &mut Reader<'_>, lease: &mut Lease) {
    let mask = u32::try_from(reader.varint()).unwrap_or_else(|_| {
        reader.ok = false;
        0
    });
    let has = |bit: u32| mask & bit != 0;
    if has(TSTP) {
        lease.tstp = Some(reader.time());
    }
    if has(TSFP) {
        lease.tsfp = Some(reader.time());
    }
    if has(ATSFP) {
        lease.atsfp = Some(reader.time());
    }
    if has(SHARE) {
        lease.share = Some(if reader.byte() == 0 {
            PoolShare::Primary
        } else {
            PoolShare::Secondary
        });
    }
    if has(HOSTNAME) {
        lease.hostname = Some(reader.text());
    }
    if has(FQDN) {
        lease.fqdn = Some(reader.text());
    }
    if has(FQDN_FLAGS) {
        lease.fqdn_flags = Some(reader.byte());
    }
    if has(DDNS_POLICY) {
        let bytes = reader.bytes();
        lease.ddns_policy = tenko_core::codec::cbor::from_cbor::<DdnsPolicy>(bytes).ok();
        reader.ok &= lease.ddns_policy.is_some();
    }
    if has(DDNS) {
        lease.ddns = reader.ddns();
    }
    if has(FINGERPRINT) {
        lease.fingerprint = Some(reader.fingerprint());
    }
    if has(RELAY) {
        lease.relay = Some(reader.relay());
    }
    if has(OBSERVED_AT) {
        lease.observed_at = Some(reader.time());
    }
    if has(GRANTED) {
        lease.granted = Some(reader.time());
    }
}

fn put_varint(out: &mut Vec<u8>, mut value: u128) {
    loop {
        // The low seven bits, and the flag that more follow.
        #[allow(clippy::cast_possible_truncation, reason = "seven bits of the value")]
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_varint(out, bytes.len() as u128);
    out.extend_from_slice(bytes);
}

fn put_time(out: &mut Vec<u8>, time: Timestamp) {
    let nanos = time.unix_nanos();
    // Zigzag: small magnitudes of either sign take few octets.
    #[allow(
        clippy::cast_sign_loss,
        reason = "the zigzag encoding of a signed value"
    )]
    let zigzag = ((nanos << 1) ^ (nanos >> 127)) as u128;
    put_varint(out, zigzag);
}

/// The decoder of a row's byte string. A string this module did not write is not expected;
/// a short or malformed one clears `ok` and yields empty values instead of panicking.
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
    ok: bool,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            at: 0,
            ok: true,
        }
    }

    fn byte(&mut self) -> u8 {
        if let Some(&byte) = self.buf.get(self.at) {
            self.at += 1;
            byte
        } else {
            self.ok = false;
            0
        }
    }

    fn take(&mut self, len: usize) -> &'a [u8] {
        let Some(slice) = self
            .at
            .checked_add(len)
            .and_then(|end| self.buf.get(self.at..end))
        else {
            self.ok = false;
            return &[];
        };
        self.at += len;
        slice
    }

    fn varint(&mut self) -> u128 {
        let mut value = 0u128;
        for shift in (0..128).step_by(7) {
            let byte = self.byte();
            value |= u128::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
        }
        self.ok = false;
        value
    }

    fn len(&mut self) -> usize {
        usize::try_from(self.varint()).unwrap_or_else(|_| {
            self.ok = false;
            0
        })
    }

    fn bytes(&mut self) -> &'a [u8] {
        let len = self.len();
        self.take(len)
    }

    fn text(&mut self) -> String {
        let bytes = self.bytes();
        String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| {
            self.ok = false;
            String::new()
        })
    }

    fn time(&mut self) -> Timestamp {
        let zigzag = self.varint();
        #[allow(
            clippy::cast_possible_wrap,
            reason = "the zigzag encoding of a signed value"
        )]
        let nanos = ((zigzag >> 1) as i128) ^ -((zigzag & 1) as i128);
        Timestamp::from_unix_nanos(nanos).unwrap_or_else(|_| {
            self.ok = false;
            Timestamp::UNIX_EPOCH
        })
    }

    fn client(&mut self) -> (u8, &'a [u8], Option<&'a [u8]>) {
        let htype = self.byte();
        let chaddr = self.bytes();
        let client_id = match self.len() {
            0 => None,
            len => Some(self.take(len - 1)),
        };
        (htype, chaddr, client_id)
    }

    fn name(&mut self) -> DnsName {
        let text = self.text();
        DnsName::new(&text).unwrap_or_else(|_| {
            self.ok = false;
            DnsName::root()
        })
    }

    fn ddns(&mut self) -> DdnsState {
        let flags = self.byte();
        let has = |bit: u8| flags & (1 << bit) != 0;
        DdnsState {
            forward: has(0).then(|| self.name()),
            reverse: has(1).then(|| self.name()),
            dhcid: has(2).then(|| HexBytes(self.bytes().to_vec())),
            last_error: has(3).then(|| self.text()),
            updated: has(4).then(|| self.time()),
        }
    }

    fn fingerprint(&mut self) -> Fingerprint {
        let parameters = HexBytes(self.bytes().to_vec());
        let flags = self.byte();
        let vendor_class = (flags & 4 != 0).then(|| self.text());
        let architecture = (flags & 8 != 0).then(|| {
            let octets = self.take(2);
            <[u8; 2]>::try_from(octets).map_or_else(
                |_| {
                    self.ok = false;
                    0
                },
                u16::from_le_bytes,
            )
        });
        Fingerprint {
            parameters,
            vendor_class,
            user_class: flags & 1 != 0,
            client_fqdn: flags & 2 != 0,
            architecture,
        }
    }

    fn addr(&mut self) -> Ipv4Addr {
        let octets = self.take(4);
        <[u8; 4]>::try_from(octets).map_or_else(
            |_| {
                self.ok = false;
                Ipv4Addr::UNSPECIFIED
            },
            Ipv4Addr::from,
        )
    }

    fn relay(&mut self) -> RelayInfo {
        let giaddr = self.addr();
        let flags = self.byte();
        let has = |bit: u8| flags & (1 << bit) != 0;
        let circuit_id = has(0).then(|| HexBytes(self.bytes().to_vec()));
        let remote_id = has(1).then(|| HexBytes(self.bytes().to_vec()));
        let link_selection = has(2).then(|| self.addr());
        let server_id_override = has(3).then(|| self.addr());
        let raw = HexBytes(self.bytes().to_vec());
        RelayInfo {
            giaddr,
            circuit_id,
            remote_id,
            link_selection,
            server_id_override,
            raw,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> Lease {
        let now = Timestamp::now();
        Lease {
            addr: Ipv4Addr::new(192, 0, 2, 10),
            vrf: VrfId::generate(),
            scope: PrefixId::generate(),
            client: ClientKey {
                htype: 1,
                chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]),
                client_id: None,
            },
            state: BindingState::Active,
            cltt: now,
            ends: now,
            tstp: None,
            tsfp: None,
            atsfp: None,
            node: NodeId(1),
            share: None,
            hostname: None,
            fqdn: None,
            fqdn_flags: None,
            ddns_policy: None,
            ddns: DdnsState::default(),
            fingerprint: None,
            relay: None,
            observed_at: None,
            granted: None,
        }
    }

    fn round_trip(lease: &Lease) -> (Lease, usize) {
        let row = Row::new(lease, Revision(7), &mut Vec::new());
        (row.to_lease(lease.vrf, lease.addr), row.blob.len())
    }

    #[test]
    fn the_hot_part_stays_small() {
        assert!(
            std::mem::size_of::<Row>() <= 88,
            "{}",
            std::mem::size_of::<Row>()
        );
    }

    #[test]
    fn a_bare_row_takes_a_few_octets() {
        let lease = lease();
        let (back, len) = round_trip(&lease);
        assert_eq!(back, lease);
        assert_eq!(
            len,
            1 + 1 + 6 + 1 + 1,
            "htype, chaddr, no identifier, no field"
        );
    }

    #[test]
    fn every_field_survives() {
        let mut lease = lease();
        let now = Timestamp::now();
        lease.client.client_id = Some(HexBytes(vec![1, 0, 0, 0x5e, 0, 0x53, 1]));
        lease.tstp = Some(now);
        lease.tsfp = Some(Timestamp::UNIX_EPOCH);
        lease.atsfp = Timestamp::from_unix_nanos(-1_000).ok();
        lease.share = Some(PoolShare::Secondary);
        lease.hostname = Some("printer".to_owned());
        lease.fqdn = Some("printer.example.com".to_owned());
        lease.fqdn_flags = Some(0b0101);
        lease.ddns_policy = Some(DdnsPolicy::default());
        lease.ddns = DdnsState {
            forward: DnsName::new("printer.example.com.").ok(),
            reverse: DnsName::new("10.2.0.192.in-addr.arpa").ok(),
            dhcid: Some(HexBytes(vec![0, 1, 2, 3])),
            last_error: Some("the zone refused".to_owned()),
            updated: Some(now),
        };
        lease.fingerprint = Some(Fingerprint {
            parameters: HexBytes(vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249]),
            vendor_class: Some("MSFT 5.0".to_owned()),
            user_class: true,
            client_fqdn: true,
            architecture: Some(7),
        });
        lease.relay = Some(RelayInfo {
            giaddr: Ipv4Addr::new(192, 0, 2, 1),
            circuit_id: Some(HexBytes(vec![1, 2])),
            remote_id: Some(HexBytes(vec![3, 4, 5])),
            link_selection: Some(Ipv4Addr::new(198, 51, 100, 1)),
            server_id_override: Some(Ipv4Addr::new(203, 0, 113, 1)),
            raw: HexBytes(vec![1, 2, 1, 2, 2, 3, 3, 4, 5]),
        });
        lease.observed_at = Some(now);
        // ADR 0031: the grant time of the binding.
        lease.granted = Timestamp::from_unix_nanos(now.unix_nanos() - 3_600_000_000_000).ok();
        let (back, _) = round_trip(&lease);
        assert_eq!(back, lease);
    }

    #[test]
    fn the_view_reads_the_client_without_the_rest() {
        let mut lease = lease();
        lease.client.client_id = Some(HexBytes(vec![0xff; 300]));
        lease.hostname = Some("laptop".to_owned());
        let row = Row::new(&lease, Revision::ZERO, &mut Vec::new());
        let view = row.view(lease.vrf, lease.addr);
        assert_eq!(view, LeaseView::of(&lease));
        assert!(view.client.is(&lease.client.identity()));
        assert!(!view.client.is(&[0, 1, 0, 0, 0x5e, 0, 0x53, 1]));
        assert_eq!(view.client.mac(), lease.client.mac());
        assert_eq!(view.client.to_key(), lease.client);
        assert_eq!(row.to_lease(lease.vrf, lease.addr), lease);
    }
}
