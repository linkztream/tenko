# Recorded exchanges

A copy of `bench/spike-krb/fixtures/` (the spike of the identity plan), so that the crate's
tests do not depend on the spike's directory. Each directory is one GSS-API exchange between
MIT Kerberos' `gss_init_sec_context` (krb5 1.20.1) and the spike's acceptor, recorded
against the MIT KDC or the Samba AD domain controller of the spike's lab, in the fictitious
realm `CORP.EXAMPLE.TEST`. The keys in `keys.txt` are the lab keys of those throwaway
realms; no token or key of a real domain is in here.

| File | Content |
| --- | --- |
| `meta.txt` | mechanism asked of MIT, target, flags MIT returned, time of the recording (Unix seconds), the SPN and realm, the KDC |
| `keys.txt` | the service account's keys: `enctype kvno hex`, one per line |
| `init0.hex` | the initiator's token (SPNEGO `negTokenInit` or a raw Kerberos `InitialContextToken` with the AP-REQ) |
| `accept0.hex` | the acceptor's answer (the AP-REP, wrapped as the mechanism requires) |
| `msg.hex`, `initmic.hex` | the initiator's first message and its MIC (`gss_get_mic`) |
| `accmsg.hex`, `accmic.hex` | the acceptor's message and the MIC MIT verified with `gss_verify_mic` |
| `msg2.hex`, `initmic2.hex` | the initiator's second message and MIC (sequence number plus one) |
| `ctxkey.hex` | the context key MIT ended with: the acceptor subkey |

The Samba tokens carry a PAC.
