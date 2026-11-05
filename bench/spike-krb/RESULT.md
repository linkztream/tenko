# WP13.0 spike: the Kerberos acceptor, (b) `sspi` against (b') `picky-krb` alone

Verdict: FAIL ((b) `sspi` fails the `cargo deny` criterion; (b') `picky-krb` alone is the choice)

Date: 2026-11-05. Plan: [identity-plan.md](../../docs/plans/identity-plan.md), section 2.4,
package WP13.0, risks R117 to R119 and R133. ADR: [0026](../../docs/adr/0026-kerberos-and-directory-identity.md).
Code and reproduction: [README.md](README.md).

## 1. Environment

| Item | Value |
| --- | --- |
| Host | Ubuntu 24.04.5 container, x86-64, 4 vCPU, 15 GiB, no swap |
| Toolchain | rustc 1.97.0 (2d8144b78 2026-07-07), cargo 1.97.0, stable channel of `rust-toolchain.toml`; targets `x86_64-unknown-linux-musl` (musl-tools 1.2.4), `x86_64-pc-windows-gnu` (mingw-w64 11), `x86_64-pc-windows-msvc` (no MSVC linker or compiler available) |
| Tools | cargo-deny 0.20.2, cargo-geiger 0.14.0, GNU time, faketime 0.9.10 |
| Kerberos libraries | `sspi` 0.23.1 (the plan names 0.23.0; 0.23.1 is what `=0.23` resolves to today), `picky-krb` 0.13.1, `picky` 7.0.0-rc.27, `rsa` 0.10.0-rc.18, `pkcs1` 0.8.0-rc.4, `aws-lc-rs` 1.18.1 (the workspace's version) |
| Docker | Available: Docker Engine 29.9.2 (the daemon started by hand, no bridge network; containers run on the host network) |
| KDC 1 | MIT Kerberos 1.20.1 (`krb5-kdc`) on the host, realm `CORP.EXAMPLE.TEST`, port 1088 (`scripts/lab-mit.sh`) |
| KDC 2 | Samba 4.19.5 AD domain controller (`samba-tool domain provision`, internal DNS, `interfaces = lo`) in an `ubuntu:24.04` container, realm `CORP.EXAMPLE.TEST`, computer account `tenko$` with SPN `DNS/tenko.corp.example.test` and `msDS-SupportedEncryptionTypes` 24 (`scripts/lab-samba.sh`) |
| Client | MIT Kerberos 1.20.1 GSS-API (`libgssapi_krb5`) on the host through `peer/gss-peer.c`; `python3-gssapi` was broken on this image, `gss-client` and `gss-server` do no MIC exchange, so the C program replaced both |
| Windows | No Windows host, client or domain controller; no recorded Windows token exists in the repository |

Everything in the fixtures comes from the two lab realms above; no token or key of a real
domain was used.

## 2. Criterion 1: `sspi` as the acceptor

`src/sspi_acceptor.rs` drives `sspi::Kerberos::new_server_from_config` with
`ServerProperties { ticket_decryption_key, service_name, max_time_skew: 300 s, authenticators_cache }`
for raw Kerberos tokens and `sspi::Negotiate::new_server` with `package_list = "kerberos,!ntlm"` for
SPNEGO, dispatching on the OID of the InitialContextToken. The MIC is Tenko's
(`src/mic.rs`, RFC 4121 section 4.2.6.1 over `aws-lc-rs`: n-fold, the RFC 3961 derived key
`DK(key, usage || 0x99)` with the AES block function, HMAC-SHA1-96) from the key
`query_context_session_key` returns. Each exchange: the peer's token, the acceptor's answer, a
message and MIC from the peer verified by Tenko's code, a message and MIC from the acceptor verified by
MIT's `gss_verify_mic`, a second MIC from the peer to check the sequence number.

| Initiator and KDC | Mechanism | Ticket, session key | `sspi` acceptor | (b') acceptor |
| --- | --- | --- | --- | --- |
| MIT client, MIT KDC | raw krb5 (1.2.840.113554.1.2.2) | AES-256, AES-256 | PASS, MICs both ways | PASS |
| MIT client, MIT KDC | raw ms-krb5 (1.2.840.48018.1.2.2) | AES-256, AES-256 | FAIL: MIT refuses the AP-REP ("Invalid token was supplied"): `sspi` wraps it under 1.2.840.113554.1.2.2 whatever OID the request carried | PASS |
| MIT client, MIT KDC | SPNEGO (MIT lists krb5 only) | AES-256, AES-256 | PASS; MIT flags the acceptor's MIC as a gap token (`GSS_S_GAP_TOKEN`) because `Negotiate` hides the acceptor's sequence number (S4 below) | PASS, no supplementary status |
| MIT client, MIT KDC | raw krb5 and SPNEGO | AES-128, AES-128 | FAIL: `InvalidParameter: invalid key length. actual: 16. expected: 32` (S5) | PASS |
| MIT client, Samba AD DC (PAC in the ticket, 1,481-octet token) | raw krb5 | AES-256, AES-256 | PASS | PASS |
| MIT client, Samba AD DC | raw ms-krb5 | AES-256, AES-256 | FAIL, as above | PASS |
| MIT client, Samba AD DC | SPNEGO | AES-256, AES-256 | PASS, gap token flagged | PASS |
| MIT client, Samba AD DC | raw krb5 and SPNEGO | AES-256 ticket, AES-128 session key (`default_tgs_enctypes`) | FAIL, invalid key length (S5) | PASS |
| In-code initiator (`src/testkit.rs`), Windows-shaped list [ms-krb5, krb5, NegoEx, NTLM] | SPNEGO | AES-256 | `negTokenResp` says `supportedMech` ms-krb5 and `accept-completed`, the AP-REP inside is under the krb5 OID (S3); whether Windows accepts that is the open Windows item | PASS, the inner OID echoes the request |
| Windows client | SPNEGO | | not run: no Windows token (open) | not run (open) |

Replay of the eight krb5 and SPNEGO fixtures through `sspi` under libfaketime
(`scripts/replay-sspi.sh`): the four with an AES-256 session key are accepted, the four with an
AES-128 session key are refused with `invalid key length` (S5).

Samba-issued token: yes, accepted (the `samba-*` fixtures). Windows-issued token: none; open
for the owner's lab (the commands are the same as for MIT, `peer/gss-peer.c` records the
tokens, `src/fixtures_test.rs` replays them).

Observations on `sspi` 0.23.1's server side, each asserted by a test in `src/tests.rs`
(`sspi_observations`), numbered S1 to S9:

- **S1** The client realm comes back lowercased: `query_context_names` builds a UPN
  `alice@corp.example.test` from the ticket's `CORP.EXAMPLE.TEST`.
- **S2** The initiator's sequence number (from the authenticator) and the GSS flags of the
  RFC 4121 checksum (mutual, replay, sequence, integrity, DCE style) are not exposed. Tenko
  cannot enforce the initiator's sequence window from what `sspi` gives it; the spike learns
  the number from the first MIC.
- **S3** The AP-REP is always wrapped under the standard Kerberos OID, also when the request
  used the Microsoft OID (raw, or negotiated through SPNEGO where Windows lists it first).
  MIT refuses the raw case; MIT's own acceptor echoes the Microsoft OID on purpose for
  Windows initiators, which is why the SPNEGO case is the first thing to replay with a
  Windows token.
- **S4** Behind `Negotiate` the inner `Kerberos` is private: the acceptor's sequence number
  carried in the AP-REP cannot be read. For a raw `Kerberos` context `next_seq_number()` gives
  it (it pre-increments, and the AP-REP carried `seq + 1`). The spike's SPNEGO sessions
  therefore signed with sequence 0 and MIT reported a gap token; Windows' `VerifySignature`
  with sequence detection on would refuse such a TSIG MAC.
- **S5** The AP-REP is encrypted and the acceptor subkey generated with
  `DEFAULT_ENCRYPTION_TYPE` (AES-256) whatever the ticket's enctype; the server path never sets
  `encryption_params.encryption_type` from the ticket. An AES-128 session key fails with
  `invalid key length`. AD issues AES-128 session keys to clients that offer only AES-128.
- **S6** The replay cache (`authenticators_cache`) lives in `ServerProperties`, which every
  `Kerberos` instance clones, so two negotiations accept the same AP-REQ. RFC 4120 section
  3.2.3 requires a shared cache. Harmless for GSS-TSIG (the replayer gets a context under a
  fresh subkey it cannot use) but not what the RFC asks.
- **S7** The 0x8003 checksum (flags, channel bindings) and the ticket flags are not read: a
  ticket with the INVALID flag and a DCE-style request are accepted as a normal context.
- **S8** `ServerProperties` takes one `ticket_decryption_key` per service name, without
  enctype or key version. One AES-256 and one AES-128 key under the same SPN cannot both be
  registered; with the AES-128 key configured an AES-256 ticket fails with
  `TryFromSliceError`. Tenko would decode the AP-REQ and read `etype` and `kvno` itself to
  pick the key before calling `sspi`.
- **S9** `sspi` reads the system clock (`OffsetDateTime::now_utc()`); there is no clock to
  inject. Recorded tokens are refused after 300 s, so tests on recorded Windows, Samba and
  MIT tokens (R131's plan) need libfaketime (`scripts/replay-sspi.sh`) or regenerated tokens.
  The (b') acceptor takes its clock from the configuration.

Not exposed either: the decrypted ticket (so no PAC, no `authorization-data`, no end time),
which the ownership rules of the plan (section 3.6) need. Tenko would decrypt the ticket a
second time with its own key, which is most of (b').

What `sspi` did right: the ticket and authenticator decryption, the name and realm
comparison, the skew and lifetime checks, the acceptor subkey in the AP-REP and
`query_context_session_key` returning that subkey (the MICs under it verified both ways with
MIT), the SPNEGO wrapping and `mechListMIC` logic, and the refusal of a mechanism list without
Kerberos (`package_list = "kerberos,!ntlm"`).

## 3. Criterion 2: (b') over `picky-krb` alone

`src/own/` is the same acceptance written over `picky-krb`'s types and ciphers, up to the AP-REQ
checks and the AP-REP, with the SPNEGO layer. It passed every exchange above, replays the ten
recorded exchanges octet for octet (`src/fixtures_test.rs`: with the recorded clock and the
recorded acceptor subkey, the MIC Tenko computes equals the one MIT verified), and refuses in
the tests: a wrong key, an unknown kvno, an expired ticket, a skew above 300 s, another SPN,
another realm, the INVALID flag, DCE style, a request without mutual authentication, a replay,
and a mechanism list without Kerberos.

Size, counted without blank and comment lines (`wc -l` minus `grep -c`):

| File | Code lines | Content |
| --- | --- | --- |
| `src/own/ap.rs` | 294 | InitialContextToken, AP-REQ, ticket, authenticator, 0x8003 checksum, replay cache, AP-REP (about 45 of them test helpers) |
| `src/own/spnego.rs` | 143 | `negTokenInit`, mechanism choice, `negTokenResp`, `mechListMIC` both ways (about 20 of them a test helper) |
| `src/own/mod.rs` | 122 | configuration, state machine over the two, the clock |
| Total (b') | 559 | |
| `src/mic.rs` | 164 | shared by both designs |
| `src/sspi_acceptor.rs` | about 150 | the glue (b) needs |

The decisions taken on the way, the price the plan asked for (each is a `Decision` comment in
the code):

1. Dispatch on the OID of the InitialContextToken: SPNEGO, krb5 or ms-krb5; a raw Kerberos token
   is accepted (MIT clients may send one).
2. The AP-REP's InitialContextToken carries the OID of the request (MIT refuses the other one;
   Windows is the open check).
3. RFC 4178 section 5: the mechanism chosen is the first Kerberos OID in the initiator's order;
   when it is the initiator's first choice the MIC exchange is skipped and the context is
   established in one round trip (what Windows DNS expects of TKEY); when it is not, or the
   initiator sent a `mechListMIC`, the acceptor's MIC goes out and the initiator's must come
   back in a `negTokenResp` (a second TKEY round trip). `sspi` instead prefers ms-krb5 wherever
   it is in the list, which forces the MIC exchange on a client that lists krb5 first.
4. The `mechListMIC` is `GSS_GetMIC` over the DER of the mechanism list and consumes the
   acceptor's first sequence number, so the first TSIG MIC carries `seq + 1`.
5. The final token after the MIC leg is `accept-completed` without a response token.
6. The replay key is client name, realm, `ctime` and `cusec`; the service name is fixed per
   acceptor. The spike's cache only grows; Tenko's expires entries after the skew.
7. The 0x8003 checksum is required (GSS-API initiators always send it), `Lgth` must be 16, the
   delegation option is skipped, extensions are ignored, and any channel binding is accepted
   because DNS has none.
8. DCE style (flag 0x1000, a third leg with the initiator's AP-REP) is refused rather than
   implemented; GSS-TSIG clients do not use it.
9. A request without mutual authentication is refused: GSS-TSIG needs the AP-REP for its key
   and sequence number.
10. An acceptor subkey of the session key's enctype is generated, and the acceptor's sequence
    number stays below 2^30 so that its DER INTEGER is positive and MIT's masking agrees
    (`sspi` writes `seq + 1` as a 4-octet big-endian INTEGER, negative for values above 2^31).
11. The context key is the acceptor subkey when sent, else the initiator's subkey, else the
    session key (RFC 4121 section 2), with the subkey flag 0x04 in every MIC accordingly.
12. The key is selected by the ticket's `etype` and `kvno` among the configured keys; the realm
    and the SPN components must match; the enctype of the session key decides the cipher of
    the authenticator and the AP-REP (fixes S5 and S8).

What (b') still does not do, for WP13.1: the PAC (parse `AD-IF-RELEVANT`/`AD-WIN2K-PAC`, check
the server signature with the service key, read the SIDs), expiry of the replay cache, the
Kerberos client half (AS, TGS, change password), fuzz targets. `picky-krb` has the PAC types
(`pac.rs`, 190 lines) and the AES ciphers; the DES3 cipher, NegoEx, CredSSP and PKINIT parts of
it (3,300 of its 9,446 lines) stay unused.

## 4. Criterion 3: the figures

Four variants of the same binary (`spike-krb serve`, the MIC code and the server shell), built
clean with `cargo build --release --locked --target x86_64-unknown-linux-musl` under the
workspace's release profile (`lto = "fat"`, `codegen-units = 1`), stripped with `strip`
(`scripts/measure.sh`). The baseline already holds `aws-lc-rs`, `time`, `zeroize` and
`getrandom`, which Tenko links today, so the deltas are what each design adds to Tenko.

| Variant (features) | Crates in the graph | Stripped size | Delta over the baseline | Clean build, wall (user) | Peak RSS of the build |
| --- | --- | --- | --- | --- | --- |
| baseline (none) | 17 | 451,120 B (0.43 MiB) | | 32.4 s (68.6 s) | 333 MiB |
| (b') `own` | 57 | 918,496 B (0.88 MiB) | +467,376 B (+0.45 MiB) | 47.5 s (104.4 s) | 331 MiB |
| (b) `sspi` | 136 | 2,242,304 B (2.14 MiB) | +1,791,184 B (+1.71 MiB); +1,323,808 B (+1.26 MiB) over (b') | 88.1 s (203.5 s) | 838 MiB |
| both | 136 | 2,369,344 B (2.26 MiB) | | 89.5 s (209.6 s) | 839 MiB |

All four are `ELF 64-bit LSB pie executable, x86-64, static-pie linked, stripped`. Compile
times are one run each on 4 vCPU with nothing else building; the three variants that include
`aws-lc-sys` pay its C build in the baseline already.

**musl build.** `sspi` 0.23.1 with `default-features = false` builds for
`x86_64-unknown-linux-musl` without a patch: PASS. (The `default` feature `aws-lc-rs` only picks
the rustls provider of the optional `network_client` and `tsssp` features; with it off,
nothing of `rustls`, `reqwest`, `tokio` or `hickory` enters the graph. There is no feature for
"Kerberos server only": NTLM, CredSSP, PKU2U, the Kerberos client and Remote Credential Guard
are always compiled in.)

**Windows build.** `cargo check` of a package depending on `sspi` alone: PASS on
`x86_64-pc-windows-gnu` and on `x86_64-pc-windows-msvc` (19 to 25 s each). On Windows `sspi` adds
`windows` 0.62 and `windows-registry` 0.6. The whole spike checks on the gnu target; on the
msvc target the check stops in `aws-lc-sys`'s build script for want of an MSVC compiler in this
container, which is about this environment, not about `sspi` (the workspace builds `aws-lc-rs`
on Windows in its own CI).

**`cargo deny check`** with the workspace's `deny.toml` copied beside the spike:

| Graph | advisories | bans | licenses | sources |
| --- | --- | --- | --- | --- |
| all features ((b) and (b')) | FAILED: RUSTSEC-2023-0071, `rsa` 0.10.0-rc.18, the Marvin timing attack; "No safe upgrade is available", `patched = []` is intentional upstream; pulled by `sspi` directly and by `picky` | ok, 4 `duplicate` warnings (bitflags 1 and 2, getrandom 0.3 and 0.4, r-efi, syn 2 and 3; the workspace already carries each pair) | ok | ok |
| (b') alone (`--no-default-features --features own`, `all-features = false`) | ok | ok | ok | ok |

The one exception (b) needs: `ignore = ["RUSTSEC-2023-0071"]` with the reason that Tenko's
Kerberos path never performs an RSA operation (`rsa` serves `sspi`'s PKU2U, PKINIT and CredSSP
code, which Tenko never calls). The reason is true, but the ignore would be permanent (upstream
says no fix is coming), it covers a pre-release crate, and the only reason `rsa` is in the
graph is code Tenko has no use for. Licenses: every added crate is on the allow list (MIT OR
Apache-2.0 for most; Unicode-3.0 for the 18 `icu` and `zerovec` family crates that `url`
brings; BSD-3-Clause for `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek`, `subtle`;
`Zlib OR Apache-2.0 OR MIT` for `bytemuck`; `Unlicense OR MIT` for `byteorder`). Nothing
copyleft, no OpenSSL. `yanked = "deny"` passed.

**`unsafe` in the dependency graph.** `cargo geiger` 0.14.0 ran but did not honor the feature
flags and dropped the `sspi` subtree from its table while printing `Failed to match package
serdect@0.4.3` (its known lock-matching problem); its totals for the tree it did walk are
47 of 183 `unsafe` functions used, 4,320 of 12,949 expressions, 58 of 67 impls, 70 of 390 methods.
The figures below are a count of lines containing the `unsafe` keyword in each crate's `src/`
in the registry (comments and `unsafe_code` lint attributes excluded), per tree
(`scripts/measure.sh` writes them as `unsafe-<variant>.txt`):

| Tree | Crates | Crates with `unsafe` lines | `unsafe` lines | Largest |
| --- | --- | --- | --- | --- |
| baseline | 17 | 11 | 14,232 | aws-lc-sys 12,505, libc 810, aws-lc-rs 367, time 272, getrandom 93, syn 78, deranged 74, zeroize 20 |
| (b') | 57 | 34 | 14,896 (+664) | getrandom 0.4 114, syn 3 97, chacha20 66, base64 63, aes 60, byteorder 44, hybrid-array 43, inout 31, cmov 28, uuid 25, block-buffer 22, rand 20, crypto-bigint 18, cpufeatures 11, sha1 7, serde_bytes 5, picky-asn1 2 |
| (b) | 136 | 78 | 16,634 (+1,738 over (b')) | bytemuck 376, widestring 303, zerovec 249, yoke 126, smallvec 83, generic-array 78, once_cell 51, sha2 39, curve25519-dalek 38, icu_normalizer 36, tracing-core 33, sspi 32, utf_types 31, stable_deref_trait 28, tinystr 22, icu_provider 20, idna 17, icu_collections 17, utf8_iter 16, picky 4 |

The Kerberos crates themselves: `picky-krb` 0, `picky-asn1-der` 0, `picky-asn1-x509` 0, `oid` 0,
`rsa` 0; `picky-asn1` 2 (two `unsafe fn new_unchecked` constructors); `picky` 4 (two pointer
casts in `key/mod.rs`, two in `x509/date.rs`); `crypto-bigint` 14; `sspi` 32, of which 28 are
compiled only on Windows or with the `scard` feature (`dns.rs` 5, `pku2u/cert_utils/win_extraction.rs`
18, `smartcard.rs` 5) and 4 on every platform (`utf16string.rs`: an `unsafe fn from_pcwstr`
over `widestring`, and `as_mut_slice` in a `Zeroize` impl). None of them is in a Kerberos code
path. The design (b) crates with the most `unsafe` are `bytemuck` and `widestring` (UTF-16
handling for NTLM and CredSSP) and the `icu` family under `url`, all unused by an acceptor.

**The dependency tree added.** Unique crates (name and version) per
`cargo tree -e normal --prefix none | sort -u`: baseline 17, (b') 57, (b) 136.

(b') adds 40 crates over the baseline, of which 17 names the workspace does not have today:
`aes`, `block-padding`, `cbc`, `cipher`, `cpubits`, `crypto-bigint`, `des`, `hmac`, `inout`, `oid`,
`pbkdf2`, `picky-asn1`, `picky-asn1-der`, `picky-asn1-x509`, `picky-krb`, `serde_bytes`, `sha1`.
The other 23 are in the workspace's `Cargo.lock` at the same or a semver-compatible version
(`base64`, `block-buffer`, `byteorder`, `chacha20`, `cmov`, `const-oid`, `cpufeatures`,
`crypto-common`, `ctutils`, `digest`, `getrandom` 0.4, `hybrid-array`, `num-traits`, `rand` 0.10,
`rand_core` 0.10, `serde`, `serde_core`, `serde_derive`, `syn` 3, `thiserror` 2,
`thiserror-impl`, `typenum`, `uuid`). Of the 17 new ones, `des` is pulled by `picky-krb` for the
DES3 cipher Tenko never selects (a feature request upstream would remove it), `pbkdf2` is the
string-to-key function Tenko needs, and `picky-asn1-x509` is only there for its OID table.

(b) adds 79 crates over (b'), of which 41 names the workspace does not have today:
`async-recursion`, `base16ct`, `bytemuck`, `crypto-mac`, `crypto-primes`, `curve25519-dalek`,
`curve25519-dalek-derive`, `der`, `ecdsa`, `ed25519`, `ed25519-dalek`, `elliptic-curve`, `ff`,
`generic-array`, `group`, `hex`, `hkdf`, `keccak`, `md-5`, `md4`, `num-derive`, `p256`, `p384`,
`p521`, `pem-rfc7468`, `picky`, `pkcs1`, `pkcs8`, `primefield`, `primeorder`, `rfc6979`, `rsa`,
`sec1`, `sha3`, `signature`, `spki`, `sponge-cursor`, `sspi`, `utf_types`, `wnaf`, `x25519-dalek`;
and 38 the workspace has (`url`, `idna`, the `icu` and `zerovec` family, `tracing`, `smallvec`,
`once_cell`, `sha2`, `subtle`, `widestring`, `bitflags`, `displaydoc`, `synstructure`, and so on),
several at a newer patch (`icu_*` 2.4.0 against 2.3.0, `sha2` 0.11.1 against 0.11.0, `uuid`
1.29.0 against 1.27.0, `smallvec`, `yoke`, `zerovec`), which would unify on a workspace update.

The exact pre-release pins and what they pull: `picky = "=7.0.0-rc.27"` (with
`default-features = false`, still non-optional: `rsa`, `ed25519-dalek`, `x25519-dalek`, `p256`,
`p384`, `p521`, `sha3`, `pkcs1`, `hex`, `md-5`, `base64`; 21,999 lines, of which `sspi` uses
`key`, `oids`, `hash`, `signature` and `x509` for PKU2U and CredSSP, none of it Kerberos);
`rsa = "=0.10.0-rc.18"` (pulls `crypto-primes`, `pkcs1` 0.8.0-rc.4, `pkcs8`, `spki`, `signature`,
`const-oid`, `crypto-bigint`); `pkcs1 = "=0.8.0-rc.4"` (through both). An `sspi` upgrade moves
these pins in lockstep, which is R118: every `sspi` release is a dependency review of three
pre-release crates.

**Use share, for the dependency decision** (lines of `src/`, `wc -l`):

| Crate | Lines | Tenko would use | Share |
| --- | --- | --- | --- |
| `sspi` 0.23.1 | 41,746 | `kerberos/server` 976, the shared Kerberos code 1,574, the SPNEGO server side 1,573, `crypto` 246, and part of the SSPI shell (`lib.rs`, builders, buffers; 8,292 in all) for the acceptor; `kerberos/client` 3,093 for the controller's AS, TGS and change-password exchanges | about 10 to 15 % for the acceptor, about 20 % with the client; compiled in and unused: NTLM 5,601, CredSSP 4,699, PKU2U 5,070, Remote Credential Guard 8,518, the SSPI shell's remainder |
| `picky-krb` 0.13.1 | 9,446 | `data_types`, `messages`, `constants`, `gss_api`, `pac`, `lib` 4,265; the AES ciphers, checksum, n-fold and key derivation 1,834 | about 65 %; unused: DES3 650, Diffie-Hellman 160, NegoEx 1,248, CredSSP 378, PKINIT 911 |
| `picky` 7.0.0-rc.27 | 21,999 | nothing directly | 0 % (only through `sspi`) |
| `picky-asn1` 0.10.2, `picky-asn1-der` 0.5.7 | | the ASN.1 wrappers and the DER serializer, everything Kerberos is encoded with | most of them |
| `picky-asn1-x509` 0.15.6 | | the OID table (`oids::krb5`, `ms_krb5`, `spnego`, `ntlm_ssp`, `negoex`) | a few lines; `picky-krb` needs the crate anyway |

## 5. Criterion 4: the verdict

| Criterion of section 2.4 | `sspi` | (b') |
| --- | --- | --- |
| Builds on musl | PASS | PASS |
| Builds on the Windows target | PASS (`cargo check`, gnu and msvc) | PASS (gnu; msvc blocked by `aws-lc-sys` in this container, not by the Kerberos crates) |
| `cargo deny` passes without an exception Tenko cannot justify | FAIL as it stands: RUSTSEC-2023-0071 on `rsa` 0.10.0-rc.18 needs a permanent ignore for code Tenko never calls | PASS, no exception |
| The acceptor completes the Windows exchange | OPEN (no Windows token); with MIT and Samba it completes krb5 and SPNEGO and fails raw ms-krb5 and AES-128 session keys | OPEN (no Windows token); with MIT and Samba it completes every framing and both key sizes |
| Adds at most 3 MiB to the stripped musl binary | PASS: +1.71 MiB over the baseline, +1.26 MiB over (b') | +0.45 MiB |

**(b') is the choice**, and `sspi` is kept as the reference, as the plan says when a criterion
fails. The failing criterion is `cargo deny`: the graph carries `rsa` 0.10.0-rc.18 with an
advisory upstream has declared permanent, through `sspi` itself and through `picky`, for RSA
operations Tenko never performs. An ignore with that reason is defensible in words, but it
would be a permanent exception for a pre-release crate in a code path Tenko has no use for,
and the lead would carry it on every `sspi` upgrade (R118, R119). Three more findings weigh
the same way even though they are not criteria: the interface does not give an acceptor what
GSS-TSIG needs (the initiator's sequence number, the acceptor's behind SPNEGO, the GSS flags,
the ticket's PAC and end time, a clock; S2, S4, S7, S9), so Tenko would decode the AP-REQ and
decrypt the ticket itself anyway, which is most of (b'); the acceptor is wrong on two inputs AD
can produce (the Microsoft OID in the response, AES-128 session keys; S3, S5), both proven
against MIT; and the price is 79 crates, 41 of them new to the workspace, 1.26 MiB and 41 s of
clean build over (b'), for about 4,400 lines of `sspi` used out of 41,746.

The cost of (b'), from criterion 2: 559 lines of acceptor code over `picky-krb` (plus the 164
lines of MIC code either design needs), twelve decisions listed above, each taken against RFC
4120, 4121 and 4178 and checked against MIT's and Samba's behavior, and the Windows quirks
still to be met in the lab (the Microsoft OID is handled; `mechListMIC`, DCE style and
acceptor subkeys are decided as above). WP13.1 adds the PAC, the replay cache expiry, the
client half and the fuzz targets, as planned. The dependency decision for the owner is then
`picky-krb` 0.13.1 (65 % used) with `picky-asn1`, `picky-asn1-der`, `picky-asn1-x509` and `oid`,
17 new crate names and no pre-release pin, no advisory, no exception.

What the spike would have needed to recommend (b): `sspi` without `picky` and `rsa` for the
Kerberos acceptor (a feature split upstream), the response OID echoing the request (S3), the
ticket's enctype driving the AP-REP (S5), `ServerProperties` keyed by enctype and kvno (S8), and
accessors for the sequence numbers, the GSS flags and the ticket's authorization data (S2, S4).
Each is a small upstream change; together they are an issue list for Devolutions and the
reason `tenko-krb` keeps the `Acceptor` interface so that `sspi` could return later behind it.

## 6. Open items

- **A Windows-issued token.** None exists; the owner's lab (plan, section 10, during WP13.0)
  records one with `peer/gss-peer.c` on a domain-joined MIT client or, better, a capture of a
  Windows DNS client's TKEY against a Tenko node once WP13.2 exists. `src/fixtures_test.rs`
  replays any recorded exchange through (b'); `scripts/replay-sspi.sh` through `sspi`. The two
  questions a Windows token answers: whether Windows accepts an AP-REP under the standard OID
  when it negotiated the Microsoft one (S3), and the exact mechanism list and flags Windows
  sends (NegoEx first or not, `mechListMIC` or not).
- **The PAC** is parsed by neither acceptor in the spike; `picky-krb::pac` has the buffers; the
  server-signature check and the SID extraction are WP13.1.
- **`cargo geiger`** did not produce a trustworthy per-crate table here; the `unsafe` figures are
  line counts from the registry sources. A geiger run on a machine where it matches the lock
  would refine them, not change the ranking.
- **MSVC check of the whole spike** needs a Windows host with MSVC (for `aws-lc-sys`); the
  Kerberos crates alone pass on both Windows targets.
- **Upstream reports** worth filing against `sspi` from the observations: S3, S5, S6, S8 and the
  negative DER INTEGER of the AP-REP sequence number above 2^31; and against `picky-krb` a
  feature flag for DES3.
- **Not measured:** idle memory per context (M48) and TKEY throughput (M46) belong to WP13.8.

## 7. Proposed refinement of ADR 0026, point 1

> **Refined by the spike of WP13.0 (2026-11-05).** The Kerberos library under `tenko-krb` is
> `picky-krb` 0.13.1 alone, with Tenko's own acceptor and client over its types and ciphers;
> `sspi` 0.23.1 is kept as a reference and not depended on. The spike built both: `sspi` builds
> on `x86_64-unknown-linux-musl` and checks on both Windows targets, adds 1.71 MiB to the
> stripped static musl binary over a baseline that already links `aws-lc-rs` (1.26 MiB over the
> `picky-krb` design), 79 crates (41 new to the workspace, among them the exact pre-release pins
> `picky` 7.0.0-rc.27, `rsa` 0.10.0-rc.18 and `pkcs1` 0.8.0-rc.4) and 41 s to a clean release
> build; `cargo deny` fails on RUSTSEC-2023-0071 (`rsa`, declared unfixable upstream) and would
> need a permanent ignore for an RSA path Tenko never calls. Its acceptor completed the MIT and
> Samba exchanges under the standard Kerberos OID in raw and SPNEGO form, with the MICs
> computed by Tenko over `aws-lc-rs` verified by MIT both ways, but answered the Microsoft
> Kerberos OID under the standard one (refused by MIT), failed AES-128 session keys, keeps the
> replay cache per context, ignores the authenticator's GSS checksum and the ticket flags, and
> exposes neither the sequence numbers nor the ticket contents an acceptor needs for GSS-TSIG
> and the PAC. The `picky-krb` design adds 0.45 MiB, 40 crates (17 new names, no pre-release
> pin), passes `cargo deny` without an exception, and completed every exchange of the spike
> with both key sizes and all three framings in 559 lines of acceptor code whose twelve
> decisions are recorded in `bench/spike-krb/RESULT.md`. No Windows-issued token was available;
> the Windows exchange stays the first check of the owner's lab, replayed through the spike's
> fixtures. The `Acceptor` interface of `tenko-krb` is the one the spike used, so that `sspi`
> can return behind it if upstream splits its Kerberos acceptor from `picky` and `rsa`.
