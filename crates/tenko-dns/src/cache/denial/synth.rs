//! The synthesised answer, written into the worker's buffer without allocating (RFC 8198
//! section 5): the client's id and question, RA, its RD and CD, AD for secure records when
//! the client asked with AD or DO; NXDOMAIN and NODATA with the SOA in the authority
//! section and, for a client with DO, the NSEC or NSEC3 records of the proof and every
//! signature; a wildcard answer with the wildcard's records under the name asked and, for
//! DO, the proof that the name itself does not exist. Every TTL is the smallest left of
//! the records used (a negative answer no longer than the SOA's MINIMUM, RFC 2308).

use tenko_core::dns::SecurityState;

use super::store::{Set, Synth};
use crate::{
    cache::{Client, push_opt},
    wire::HEADER_LEN,
};

/// Writes `synth` for `client` into `out` at `now`; returns the RCODE, or `None` when the
/// client's question cannot be echoed.
pub fn write(synth: &Synth<'_>, client: &Client<'_>, now: u32, out: &mut Vec<u8>) -> Option<u8> {
    let question_end = client.question_end;
    if question_end < HEADER_LEN + 5 || client.message.len() < question_end {
        return None;
    }
    let state = if synth.secure {
        SecurityState::Secure
    } else {
        SecurityState::Insecure
    };
    let rendering = state.render(client.flags(), None);
    let dnssec = rendering.dnssec_records;
    let mut ttl = synth.sets().map(|set| set.left(now)).min()?;
    if let Some(minimum) = synth.soa.and_then(Set::soa_minimum) {
        ttl = ttl.min(minimum);
    }
    if ttl == 0 {
        return None;
    }
    out.clear();
    out.extend_from_slice(&client.id.to_be_bytes());
    out.push(0x80 | u8::from(client.rd));
    let ad = if rendering.ad { 0x20 } else { 0 };
    let cd = if client.cd { 0x10 } else { 0 };
    out.push(0x80 | ad | cd | synth.rcode);
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&client.message[HEADER_LEN..question_end]);
    let (mut answers, mut authority) = (0u16, 0u16);
    if let Some(set) = synth.answer {
        // The wildcard's records under the name asked, in the client's case.
        let qname = &client.message[HEADER_LEN..question_end - 4];
        answers = push_set(out, qname, set, dnssec, ttl);
    }
    if let Some(soa) = synth.soa {
        authority += push_set(out, &soa.owner, soa, dnssec, ttl);
    }
    if dnssec {
        for set in synth.proofs.iter().flatten() {
            authority += push_set(out, &set.owner, set, true, ttl);
        }
    }
    out[6..8].copy_from_slice(&answers.to_be_bytes());
    out[8..10].copy_from_slice(&authority.to_be_bytes());
    let edns = client.edns;
    if let Some(edns) = &edns {
        push_opt(out, edns, None);
    }
    if out.len() > client.max_len {
        out.truncate(question_end);
        out[2] |= 0x02;
        out[6..12].copy_from_slice(&[0; 6]);
        if let Some(edns) = &edns {
            push_opt(out, edns, None);
        }
    }
    for set in synth.sets() {
        set.touch(now);
    }
    Some(synth.rcode)
}

/// Appends the records of `set` under `owner` with `ttl`, the signatures when `sigs`;
/// returns how many.
fn push_set(out: &mut Vec<u8>, owner: &[u8], set: &Set, sigs: bool, ttl: u32) -> u16 {
    let end = if sigs { set.data.len() } else { set.sig_at };
    let mut pos = 0;
    let mut count = 0u16;
    while pos + 10 <= end {
        let len = usize::from(u16::from_be_bytes([set.data[pos + 8], set.data[pos + 9]]));
        out.extend_from_slice(owner);
        out.extend_from_slice(&set.data[pos..pos + 4]);
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&set.data[pos + 8..pos + 10 + len]);
        pos += 10 + len;
        count += 1;
    }
    count
}
