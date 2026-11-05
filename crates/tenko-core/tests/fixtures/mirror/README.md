# The mirror fixtures

The envelope a mirrored source pushes (`tenko_core::ir::MirrorSnapshot`, `docs/plans/windows-takeover-plan.md` sections 3.1 and 3.4, ADR 0033), for the fictitious domain `corp.example.test`. `snapshot.json` is the contract between the exporter of `deploy/windows/mirror/` and the server: the exporter's Pester suite produces it byte for byte from recorded cmdlet output, and `tests/mirror_model.rs` holds it to the types the same way. Its field names are those of section 3.1 and of the IR; nothing else is added.

| File | Content |
|---|---|
| `snapshot.json` | Sequence 1, taken at `2026-11-01T08:00:00Z` by `dc1.corp.example.test`: one active scope `192.0.2.0/24` (pool `.100` to `.199`, exclusion `.100` to `.109`, lease time eight days), thirty reservations at `.10` to `.39` named in every way of section 2.9, options at the server, scope and reservation level, the server-level and the scope's DDNS settings, sixty leases (forty-eight pool leases at `.110` to `.157`: sixteen `LAPTOP-NN` and sixteen `desk-NN` names keyed by a MAC address, sixteen `phone-NN` names keyed by an RFC 4361 identifier; ten leases of the reservations with a bare name; two declined addresses at `.158` and `.159`), and a loss report with one policy, one filter, one superscope and one lease in another state |
| `snapshot-inactive.json` | The same with the scope inactive, at sequence 2 and one minute later: the push the takeover waits for (section 2.7, step 2) |

Documentation data only (RFC 5737 addresses, RFC 7042 MAC addresses `00:00:5e:00:53:xx`, names under `.test`). Regenerate both with `TENKO_REGENERATE_FIXTURES=1 cargo test -p tenko-core --test mirror_model` and review the diff: a change here is a change of the contract. The AD zones that go with the snapshot are `crates/tenko-dns/tests/fixtures/ad-zones/`, derived from it.
