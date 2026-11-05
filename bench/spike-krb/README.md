# Spike: the Kerberos acceptor for GSS-TSIG (WP13.0)

This crate is the spike of [identity-plan.md](../../docs/plans/identity-plan.md), section 2.4,
that decides between design (b), Devolutions' `sspi` with `picky-krb` as the Kerberos acceptor,
and design (b'), Tenko's own acceptor over `picky-krb` alone, for the GSS-TSIG server of
[ADR 0026](../../docs/adr/0026-kerberos-and-directory-identity.md). The verdict and every
figure are in [RESULT.md](RESULT.md). This README describes the code and how to reproduce
the runs; it repeats no measured number.

## Layout

| Path | Content |
| --- | --- |
| `Cargo.toml` | Standalone crate (own `[workspace]`), features `sspi` and `own`, the workspace's release profile |
| `src/acceptor.rs` | The interface `tenko-krb` would expose: `Acceptor::step(token) -> Continue | Established`, `Context`, `ServiceKey`, `Enctype` |
| `src/mic.rs` | RFC 4121 MIC tokens over `aws-lc-rs`: n-fold, the RFC 3961 key derivation, HMAC-SHA1-96; what Tenko computes itself under either design |
| `src/sspi_acceptor.rs` | Design (b): `sspi`'s `Kerberos` and `Negotiate` server side behind the interface (feature `sspi`) |
| `src/own/` | Design (b'): `spnego.rs` (RFC 4178) and `ap.rs` (the AP-REQ checks and the AP-REP, RFC 4120 and 4121) over `picky-krb` (feature `own`) |
| `src/main.rs` | `spike-krb serve`: a TCP acceptor for the MIT peer, with the MIC exchange both ways |
| `src/testkit.rs`, `src/tests.rs` | An in-code initiator over `picky-krb` (tickets, AP-REQs, SPNEGO, AP-REP checks) and the tests of both acceptors |
| `src/fixtures_test.rs`, `fixtures/` | Recorded MIT and Samba exchanges, replayed through the (b') acceptor octet for octet ([fixtures/README.md](fixtures/README.md)) |
| `peer/gss-peer.c` | The MIT side: `gss_init_sec_context`, `gss_get_mic`, `gss_verify_mic`, recording |
| `scripts/lab-mit.sh` | An MIT KDC for `CORP.EXAMPLE.TEST` on the local host |
| `scripts/lab-samba.sh`, `scripts/samba-provision.sh` | A Samba AD domain controller for the same realm in a container, with the Tenko computer account |
| `scripts/run-interop.sh` | One recorded exchange between the peer and an acceptor |
| `scripts/replay-sspi.sh` | Replays the fixtures through `sspi` under libfaketime |
| `scripts/measure.sh` | The timed musl builds, the stripped sizes, the Windows checks and `cargo geiger` |
| `deny.toml` | A copy of the workspace's policy, so that `cargo deny check` runs here |
| `RESULT.md` | The result file: environment, criteria with figures, dependencies, verdict, open items, the ADR paragraph |

## Features

| Feature | Effect |
| --- | --- |
| `sspi` (default) | `sspi` 0.23.1 with `default-features = false`: Kerberos, NTLM and Negotiate are always compiled in; `network_client`, `dns_resolver`, `scard` and `tsssp` stay off, so no reqwest, rustls, tokio, hickory or PKCS#11 |
| `own` (default) | The (b') acceptor over `picky-krb` 0.13.1, `picky-asn1`, `picky-asn1-der`, `picky-asn1-x509` and `oid` |
| none | The MIC module and the server shell alone: the baseline of the size and compile-time figures |

## The exchange

`spike-krb serve` listens for the peer. Frames are a 4-octet big-endian length and the bytes.
The peer sends its tokens until the context is established and the acceptor has answered
with the AP-REP (raw, or inside `negTokenResp`); then the peer sends a message and its MIC,
the acceptor verifies it with `mic.rs` under the context key, answers with its own message
and MIC, which the peer verifies with `gss_verify_mic`; a second MIC from the peer checks
that the sequence number moved, and the acceptor's final frame is `OK` or `FAIL`.

```sh
# The MIT lab, then one exchange per acceptor and mechanism.
bash scripts/lab-mit.sh /opt/mitlab
export KRB5_CONFIG=/opt/mitlab/krb5.conf; echo Client-Pass-1 | kinit alice
KEY=18:2:$(klist -Kek /opt/mitlab/dns.keytab | sed -n 's/.*aes256-cts-hmac-sha1-96) *(0x\([0-9a-f]*\)).*/\1/p' | head -1)
for acc in own sspi; do for mech in krb5 ms-krb5 spnego; do
  bash scripts/run-interop.sh $acc $mech DNS/tenko.corp.example.test /tmp/rec-$acc-$mech --key $KEY
done; done

# The Samba lab (Docker), the same exchanges against AD-style tokens with a PAC.
bash scripts/lab-samba.sh /opt/sambalab   # wait for /opt/sambalab/out/READY
export KRB5_CONFIG=/opt/sambalab/krb5.conf; echo Al1ce-Pass-lab | kinit alice

# The tests: the in-code initiator against both acceptors, and the recorded fixtures.
cargo test
bash scripts/replay-sspi.sh

# The figures.
bash scripts/measure.sh /tmp/measure
cargo deny check
```

The lab passwords and keys are those of two throwaway realms created by the scripts; nothing
of a real domain is used or recorded.
