# Results of the Windows interop lab (E44)

Fill in one row per step of [README.md](README.md) as you run it: **Pass** or **Fail**, the
files you kept (under `results/` and `captures/`), and what you saw that the step did not
expect. A step that fails stops the lab until the lead has read it with you.

- Date of the run:
- Tenko commit and version (`tenko --version`):
- Tenko node's platform (Linux distribution or Windows Server version):
- Windows Server version of `dc1` and `dc2` (`winver`, build):
- Windows 11 version of `pc1` (build):
- SHA-256 of the saved block of section 4.1 (W3):

| Step | What it shows | Pass or fail | Kept | Notes |
|---|---|---|---|---|
| W0 | The node: version, profile Standard, the DNS role answers | | `results/w0-node.txt` | |
| W1 | The domain with the DNS Server role on `dc1`, aging on, `printer1` static, `srv1` joined | | | |
| W2 | The starting state: records with and without timestamps, the zone exports with `[AGE:n]` | | `results/w2/` | |
| W3 | The block of section 4.1 creates `TENKO-DNS$`; Tenko adopts it; versions agree; no finding | | `results/w3-account.txt` | |
| W4 | The Windows-dialect import: dynamic records `ad`, `printer1` manual; the secure-only policy set | | `results/w4-import.txt`, `results/w4-settings.png` | |
| W5 | `dc1` registers every record of its `Netlogon.dns` with GSS-TSIG; owns `dc1`; no refusal | | `captures/w5-dc1.pcapng`, `results/w5/` | |
| W6 | The DNS Server role removed from `dc1`; registration still succeeds; dcdiag | | `results/w6-dcdiag.txt` | |
| W7 | `dc2` promoted without the role through Tenko; registers every record; replication clean | | `captures/w7-dc2.pcapng`, `results/w7/` | |
| W8 | The hourly registration: answered NOERROR; a pure refresh writes nothing | | `captures/w8-dc1.pcapng`, `results/w8.txt` | |
| W9 | `UpdateSecurityLevel` 256 by group policy and the Hardened profile: registrations succeed | | `results/w9.txt` | |
| W10 | `pc1` (Windows 11) joins through Tenko and registers its A (and PTR) as `PC1$` | | `captures/w10-pc1*.pcapng`, `results/w10.txt` | |
| W11 | `srv1` claims its imported A and PTR names (`claimed`) and refreshes them | | `results/w11.txt` | |
| W12 | `pc1` cannot overwrite the PTR name `srv1` owns: refused, record unchanged | | `results/w12.txt` | |
| W13 | After a restart of the node: BADKEY, a new TKEY, the update succeeds, on `dc1` and `pc1` | | `captures/w13-*.pcapng`, `results/w13.txt` | |
| W14 | `dcdiag /test:dns`, `dcdiag` and `repadmin /replsummary` on both controllers | | `results/w14/` | |

## The questions of R120 (from W5, W8 and W13)

| Question | Answer |
|---|---|
| Does Windows send TKEY over TCP only, and its updates over UDP or TCP? | |
| Which mechanisms does it offer in SPNEGO, and does the negotiation take one TKEY leg? | |
| Does it accept the signed TKEY answer and sign its update on the same context? | |
| Does it reuse a context for several updates, and for how long? | |
| What does it do after BADKEY on a dropped context (W13)? | |
| Is any update refused, and why? | |

## The questions of R121 (from W2, W5, W11 and W12)

| Question | Answer |
|---|---|
| Does a record registered while aging was off get a timestamp at its next refresh once aging is on? | |
| `TombstoneInterval` of the domain (how long Windows keeps a deleted name and its owner) | |
| Do the controllers register their own host records (`dc1`, `dc2`) through Netlogon or through the DNS client, and under which principal? | |
| Does the DNS client register the PTR record itself, and under which principal? | |
| Which event does the DNS client log when an update is refused for ownership (8018, 8020, other)? | |

## The dcdiag tests that need the DNS Server role (W6, W14)

List each test of `dcdiag /test:dns` that fails without the role, with its message, so that
the runbook can name them as known.

| Test | Message |
|---|---|
| | |
