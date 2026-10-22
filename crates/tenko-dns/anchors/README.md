# Shipped DNS root trust anchors and root hints

The recursive resolver starts from two files that are compiled into the binary
(`include_str!` in `src/recursion/shipped.rs`). Both are committed byte for byte as fetched.

| File | Source | Fetched | SHA-256 |
|---|---|---|---|
| `root-anchors.xml` | <https://data.iana.org/root-anchors/root-anchors.xml> (IANA, RFC 7958) | 2026-10-22 | `3ccaab38830025ee0a0f6c1f25769427544f81ea2865aa860468f3ef5278b908` |
| `named.root` | <https://www.internic.net/domain/named.root> (InterNIC) | 2026-10-22 | `934d65ebb95b8b0e23169fe9e2875e2f5eec9b90f46d68a9737f0aef942f819c` |

## What they hold

`root-anchors.xml`, trust anchor `0C05FDD6-422C-4910-8ED6-430ED15E11C2` for the root zone:

| Key tag | Algorithm | Digest type | Valid from | Valid until |
|---|---|---|---|---|
| 19036 | 8 | 2 | 2010-07-15 | 2019-01-11 |
| 20326 | 8 | 2 | 2017-02-02 | not set |
| 38696 | 8 | 2 | 2024-07-18 | not set |

`named.root`: the 13 root servers `a` to `m`.root-servers.net, each with an A and an AAAA
record. Last update 2026-10-21, related version of the root zone 2026102101.

`tenko --version` prints the key tags without a `validUntil` and the hints' date.

## Refresh

1. Fetch both files again from the URLs above and replace them, keeping the bytes as served
   (no editor, no line-ending conversion).
2. Run `node scripts/root-anchors.mjs`. It rewrites `src/recursion/shipped.rs` (generated, do not
   edit it by hand) with the key digests, the SHA-256 of the XML file and the hints' date and
   serial.
3. Update the table above (fetch date, SHA-256, keys, hints date and serial).
4. Run `cargo nextest run -p tenko-dns --test root_anchors` and `node --test "scripts/*.test.mjs"`,
   then commit the two files, `shipped.rs` and this file together. `node scripts/root-anchors.mjs
   --check` fails when `shipped.rs` does not match the files.
