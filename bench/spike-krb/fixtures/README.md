# Recorded exchanges

Each directory is one GSS-API exchange between MIT Kerberos' `gss_init_sec_context` (the
program in `../peer/gss-peer.c`, krb5 1.20.1 on Ubuntu 24.04) and the spike's (b') acceptor,
recorded by the peer. The KDC was either the MIT KDC of `../scripts/lab-mit.sh` or the
Samba AD domain controller of `../scripts/lab-samba.sh`; both serve the fictitious realm
`CORP.EXAMPLE.TEST`, and the keys in `keys.txt` are the lab keys of those throwaway realms.
No token or key of a real domain is in here.

| File | Content |
| --- | --- |
| `meta.txt` | mechanism asked of MIT, target, flags MIT returned, time of the recording (unix seconds), the SPN and realm, the KDC |
| `keys.txt` | the service account's keys: `enctype kvno hex`, one per line |
| `init0.hex` | the initiator's token (SPNEGO `negTokenInit` or a raw Kerberos InitialContextToken with the AP-REQ) |
| `accept0.hex` | the acceptor's answer (the AP-REP, wrapped as the mechanism requires) |
| `msg.hex`, `initmic.hex` | the initiator's first message and its MIC (`gss_get_mic`) |
| `accmsg.hex`, `accmic.hex` | the acceptor's message and the MIC MIT verified with `gss_verify_mic` |
| `msg2.hex`, `initmic2.hex` | the initiator's second message and MIC (sequence number plus one) |
| `ctxkey.hex` | the context key MIT ended with (`GSS_C_INQ_SSPI_SESSION_KEY`): the acceptor subkey |

The names: `mit-` or `samba-` for the KDC; `aes256` or `aes128` for the ticket and session
key enctype; `skey128` for Samba's AES-256 ticket with an AES-128 session key (asked with
`default_tgs_enctypes`); `krb5`, `ms-krb5` or `spnego` for the mechanism MIT was asked to use.
The Samba tokens carry a PAC (about 1,500 octets against MIT's 750).

`src/fixtures_test.rs` replays every directory through the (b') acceptor with the recorded
clock and the recorded subkey and requires the acceptor's MIC to come out octet for octet.
`../scripts/replay-sspi.sh` replays them through `sspi` under libfaketime.
