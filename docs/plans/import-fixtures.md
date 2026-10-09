# Import fixtures: the spreadsheet patterns WP1.5 must handle

- Status: Specification for WP1.5 (Import and export)
- Date: 2026-10-09

The reference spreadsheet lives outside the repository and is never committed (API-13). This document describes its structure with every value replaced by documentation-range data (RFC 5737, RFC 3849, RFC 7042, `example.test`), so that WP1.5 can build a fixture workbook under `crates/tenko-ipam/tests/fixtures/` that exercises the same patterns. Where the real file has more networks than the documentation ranges allow, the fixture repeats a pattern inside a sub-range.

## Workbook shape

One `.xlsx` with about ten sheets, no merged cells, no formulas, one table per sheet starting in `A1`.

| Sheet (fixture name) | Pattern | Rows |
|---|---|---|
| `Index` | Network list. No header row. `A` = CIDR (`192.0.2.0/24`) or a single address (`192.0.2.9`), `B` = free-text description (`Network gear, hypervisors`, `NAS`, `Alarm`, `Servers`, `Printers`, `DHCP`). Not every network with its own sheet appears here, and one listed network has an empty sheet | 7 |
| `192.0.2.0` | **Pre-filled address list**: header `IP | Beteckning | Login | Pass`, then every address of the /24 in order (255 rows). Only about 20 rows carry a name; a few carry login or password. Empty name means a free address, not a host | 256 |
| `203.0.113.0` | Same layout, 125 rows, sparse names (`dc-a1`, `dc-a2`, `store7`), one text value in the `IP` column, one stray value in an unlabeled column `E` | 126 |
| `192.0.2.64` (sub-range) | Same header, five rows, all named, one row with login and password. The first data row uses the network address itself as a host address (`.64`) | 6 |
| `198.51.100.0` | **Device-centric layout**: header `Enhet | Nic1 | Nic2 | Nic3 | Nic4 | login | pass` (lowercase credentials). One row per device, one address per NIC column, and one device whose four NICs sit in four different networks (`198.51.100.3`, `198.51.100.67`, `203.0.113.3`, `192.0.2.3` in the fixture) | 5 |
| `192.0.2.128` (sub-range) | **No header row**: data starts in row 1 with `IP | label | login | pass` positions implied. Two rows, labels with spaces and a dash (`idrac - host1`) | 2 |
| `192.0.2.9` | Single-host sheet named after the address: header, one row, numeric password-like value | 2 |
| `203.0.113.128` (sub-range) | Four rows, names only; the sheet name is a network that is not in `Index` | 5 |
| `192.0.2.192` (sub-range) | One row | 2 |
| `198.51.100.128` (sub-range) | **Empty sheet** (listed in `Index` as printers) | 0 |

Header vocabulary seen (Swedish and English, mixed case): `IP`, `Beteckning` (designation, the host name or description), `Login`, `login`, `Pass`, `pass`, `Enhet` (device), `Nic1` to `Nic4`.

## Value patterns

- Addresses are plain IPv4, one per cell. No CIDR in address columns, no ranges, no IPv6. The fixture adds one `192.0.2.10-20` range cell and one `2001:db8::10` cell so the transforms are tested, and marks them as additions.
- Names: short host names (`dc-a1`, `store7`, `hyper3`), product names (`MX-9200`, `ups41`), labels with spaces and underscores (`SW_Attic`, `idrac - host1`, `Wifi Controller Hall`), and a model string in the `Login` column for one switch (`Acme SG-2448`), which is a misplaced description, not a login.
- Credentials: a few rows have a login and a password in plain text; one password is a four-digit number (read as an integer by spreadsheet tools, so leading zeros may be lost).
- Most rows in the pre-filled sheets are an address and nothing else.

## Mapping rules the importer must derive (and the preview must show)

1. **Sheet name to prefix.** A sheet named like an address is a network. Its mask comes from `Index` when the network is listed there, else from the row count (255 rows means /24), else the user chooses in the mapping step. A sheet named after a single address that is listed as a single address in `Index` is one host, not a network.
2. **Header detection by shape.** If the first row contains an address where the `IP` column is expected, there is no header; column roles are inferred from value shapes and the user confirms them.
3. **Column roles by synonym and shape.** `IP`/`Nic*` are addresses; `Beteckning`/`Enhet`/`Name`/`Hostname`/`Namn` are names; `Login`/`Användare`/`User` and `Pass`/`Lösen`/`Password` are **credential columns**. Credential columns are never imported as IPAM fields: they become operator secrets in the vault attached to the host (IAM-15, IAM-16), the preview says so in plain words, and the import refuses to proceed with credential columns when the vault is not enabled or when the account's authentication strength is below the IAM-07 threshold.
4. **Device-centric sheets** create one host with one interface and one address per `Nic*` column; addresses outside the sheet's network land in their own prefixes, creating a proposal for a missing prefix rather than failing the row.
5. **Pre-filled address lists**: a row with an address and no other value creates nothing and is counted as "free address" in the preview; the prefix utilization comes from the rows that do carry data.
6. **Loss report entries** (location, code, detail), expected for the fixture: text in an address column (`import.address.unparsable`), a value in an unlabeled column (`import.column.unmapped`), a login that looks like a description (`import.credential.suspicious`, warning only), a host address equal to the network address (`import.address.is_network`, warning), a four-digit numeric password (`import.credential.numeric`, warning about lost leading zeros), a network not present in `Index` (`import.prefix.unlisted`, information), an empty sheet (`import.sheet.empty`, information).
7. **Round trip (E1).** Exporting the imported data to CSV and importing that CSV into an empty instance previews zero changes. Credentials are excluded from the export.

## Fixture deliverables

- `tenko-ipam/tests/fixtures/ip-plan.xlsx` built by a small script committed next to it (so the workbook can be regenerated), plus the same content as `.csv` per sheet and one `.ods`.
- `tenko-ipam/tests/fixtures/ip-plan.expected.json`: the expected IR (prefixes, hosts, interfaces, addresses, secrets by reference) and the expected loss report.
- A test that imports the fixture, compares with the expected IR, exports to CSV, re-imports and asserts an empty plan.
