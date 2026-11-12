# Shared code plan: one place per fact

Status: accepted by the owner on 2026-11-12, with the answers in section 6. Counted on
`main` at `6595569b`, rebased onto `640c0322`. Nothing in this plan has been built.

## 0. Summary and terms

A review of the whole code base on 2026-11-12, read as its future maintainers would read it,
found that the code is about as small as its job allows, but that 52 facts (a rule, a limit, a
name, a helper) are written in two to seven places and kept equal by hand, and that 41 of them
already differ between their copies. This plan says where shared code lives from now on, the
rule a builder follows to add to it, where each of the 52 facts goes, the packages that move
them, and what a library cannot do.

The decisions in short:

- **Thirteen homes** with a one-line charter each (section 1): one new leaf crate,
  `tenko-net`, for standard network rules; fixed modules in `tenko-core`, `tenko-store`,
  `tenko-api`, `tenko-dns`, `tenko-jobs` and the command-line client; two rules for values
  that their producer exports (error codes, metric names, setting bounds); one directory of
  shared script code; three places in the UI.
- **The rule** (section 2): an addition inside a home's charter needs no permission; it is
  reviewed at the gate. A change to what an existing shared item does still goes through the
  lead. A copy is kept from coming back by a copy lint whose baseline only shrinks, by
  `clippy` bans where a type or method marks the copy, and by tests that collect every
  instance of a fact across the workspace.
- **The 52 facts** (section 3): 43 move to one place (30 with packages of this plan, 13 by
  repair packages already proposed or by approved cleanups alone), 7 are already in flight,
  and 2 are not one fact and stay apart on purpose. Six of the 43 waited for an owner
  decision; the owner answered on 2026-11-12.
- **Twenty-seven packages** of one to three builder-days, 67 builder-days in all (section 4).
- **Eleven questions** for the owner, all answered on 2026-11-12; the eleventh came out of
  the answer to the third (section 6).

Terms used below, explained once. A **crate** is one Rust library or program, the unit the
compiler builds; the **workspace** is the 19 crates under `crates/`. A crate's **dependents**
are the crates that use it, directly or through another crate; a change in a crate
**rebuilds** it and all its dependents. A **leaf crate** depends on no other workspace crate.
**Unit-seconds** are the compiler's work summed over all its runs (from the build economics
plan, `docs/plans/build-economics-plan.md`). A **home** is the one place where a kind of shared
code lives. A **copy** is a second implementation of a fact a home already holds. The
**gate** is the lead's merge check that runs every test before a merge; a **builder** is a
session that builds one package in its own worktree. **Clippy** is Rust's linter; its
`disallowed-methods` and `disallowed-types` settings turn the use of a named method or type
into a warning, which CI treats as an error. **OpenAPI** is the machine-readable description of
the HTTP API (`docs/api/openapi.json`); the UI's TypeScript types are generated from it. A
**DTO** (data transfer object) is a type that exists to be sent over the API. **CLI** is the
command-line client in the `tenko` binary. A **golden file** holds bytes a test compares
against. A **differential test** runs two implementations of the same rule on the same input
and fails when they disagree.

Protocol and format names, in the order they appear: **RCODE** is the result code of a DNS
answer; **CBOR** a compact binary data format (the store keeps records in it); **PEM** the
text form of a certificate or key, **DER** its binary encoding; **PROXY protocol** a header a
load balancer puts before a connection to pass on the client's address; **SNMP** the protocol
for reading counters and tables from network equipment; **LLDP** the protocol by which
switches announce themselves to their neighbors; **DUID** the identifier a DHCPv6 client
sends; **PTR** the DNS record that maps an address back to a name; **Raft** the agreement
protocol of the replicated store; **Kea** another DHCP server, to which Tenko can export its
configuration; **PXE** booting a machine over the network; **DDNS** DNS records a DHCP server
writes for its clients; **TSIG** shared-key signatures on DNS messages; **Pester** the test
framework of PowerShell; **ESLint** the linter of the UI's code. HTTP status codes: 401 not
signed in, 403 not allowed, 409 conflict, 412 the object changed since it was read, 415 wrong
body type, 422 a well-formed request with invalid content, 501 not built, 503 not available
now.

## 1. The homes

### 1.1 What decided them

Three facts from the call sites and the build measurements decided where shared code lives.

**A home rebuilds its dependents, not its users.** The crate graph, read from the manifests
on `6595569b`:

| Crate a change lands in | Dependents that rebuild | Measured rebuild of all test binaries (build economics plan) |
|---|---|---|
| `tenko-core` | 16 of 18 | 237 s, 2,104 of 2,513 unit-seconds (84 %) |
| `tenko-store` | 14 | not measured; close to `tenko-core` (it spares `tenko-krb` and `tenko-core` itself) |
| `tenko-jobs` | 11 | not measured |
| `tenko-net` (new, users below) | 10 | not measured; spares `tenko-core`, `tenko-store`, `tenko-vault`, `tenko-jobs`, `tenko-krb`, `tenko-auth`, `tenko-cluster` |
| `tenko-dns` | 5 | not measured |
| `tenko-dhcp` | 2 | 167 s, 1,210 unit-seconds |
| `tenko-api` | 1 | 151 s, 907 unit-seconds |

A helper in `tenko-core` that two crates use costs the gate the 237 s of the first row at
every change. The same helper in the lowest crate both users already depend on costs only that
crate's row. So the rule for placing code is: **the lowest crate that every caller already
depends on, and not `tenko-core` unless a type in `tenko-core` needs it.**

**The rebuild was not the main reason for copying.** The gate rebuilds after a change in
`tenko-core` in 237 s against 167 s after a change in `tenko-dhcp`: about 70 s more per gate
run. A builder who builds with `-p <crate>` rebuilds only the chain under that crate. The
larger reason was the rule that `tenko-core` holds contracts only the lead may edit, and the
rule "one owner per file": for a builder who needs a helper that lives in someone else's file,
writing a local copy was the path that needed nobody's permission. Section 2 replaces that.

**`tenko-core` changes rarely, and one module carries most of its changes.** Of 756 commits on
`main`, 63 touched `tenko-core` (8 %). Of those, 22 touched the DNS model (`dns.rs` and
`dns/`), 11 the DHCP model, and no other module more than 8.

### 1.2 The homes and their charters

| # | Home | Charter, one line |
|---|---|---|
| H1 | `crates/tenko-net` (new leaf crate) | Network rules a published standard defines, over `std::net` and `ipnet` types: address classes, reverse names, the client address behind proxies. |
| H2 | `tenko-core` | Contracts between crates: identifiers, principals, the stored models, the error trait and code lists, the codecs (CBOR, keys, byte text forms), the metrics registry, test support. |
| H3 | `tenko-store`: `layout`, `fs`, `follow`, `feed`, `codes` | Everything that puts bytes durably on disk or follows what the store changed. |
| H4 | `tenko-api`: `request` and the answer groups beside `problem` | What a request must look like and what an operation can answer. |
| H5 | `tenko-dns`: `wire` | The DNS wire format: layout, name compression, RCODE and type numbers, one exchange with a server. |
| H6 | Each producing crate: `codes`, `metrics::names` | Error codes and metric family names, exported as constants by the crate that produces them. |
| H7 | Each setting's owning type | A setting's bounds and default, published through OpenAPI; every other reader reads them. |
| H8 | `tenko-jobs`: `read` and `handoff` | How other crates read job tables, and the inline hand-off of work to a job. |
| H9 | `tenko`: `client::common` | Helpers every client command shares: paging, usage, printing, idempotency keys, waiting for a job. |
| H10 | `scripts/lib/`, `deploy/compose/driver/api.sh`, `bench/lib/node.sh` | Code shared by repository scripts, by the labs, by the benchmarks. |
| H11 | `ui/src/components/form/` | The form model, the field kit and the mapping from a field error to its sentence. |
| H12 | `ui/src/api/` (`cache.ts`, `paginate.ts`, `live.ts`, typed list items) | Reading from the server: object cache, paging, live queries, list item types. |
| H13 | `ui/src/app/format/`, `ui/src/app/clipboard.ts` | Formatting values for display, and the clipboard. |

For each home: what goes in, what never goes in, who may depend on it, what a change rebuilds.

**H1 `tenko-net`.** In: functions whose rule an RFC or IEEE text defines and that take and
return `std::net`, `ipnet` or plain byte and string types. Inhabitants: address classes
(link-local, special-purpose, IPv4-mapped, the reserved addresses of a subnet), the reverse
name of an address and the address of a reverse name, the client address from a PROXY
protocol header or a forwarded-for chain with a list of trusted hops. It differs from
`tenko_core::net`, which holds the stored types of network identifiers (MAC address, DUID,
host and domain names) with their parsing: a type that a stored record holds lives in
`tenko-core`; a rule over addresses that no stored type needs lives here. Never: a workspace
crate as dependency, `serde` or `utoipa` derives, a setting or a default Tenko chooses (a caller passes those in), input or
output, `async`, logging, a domain type (zone, scope, prefix, host). Parsers of network input
here get a fuzz target, as every parser does. May be used by any crate except `tenko-core`;
`tenko-core` never depends on it, so that a change in it never rebuilds the 16 dependents of
`tenko-core`. Its users today would be `tenko-dns`, `tenko-ipam`, `tenko-scan`, `tenko-dhcp`,
`tenko-connect` and the three connectors, `tenko-api` and `tenko`: a change rebuilds those 10.

**H2 `tenko-core`.** Stays: the identifiers, principals and authorization, the IPAM, DNS and
DHCP models, observations, audit, names, the error trait, the codecs, the metrics registry,
secret references, roles, `testing`. Gains, in one package so that the rebuild of its 16
dependents is paid once (section 4, S2): the byte text forms (hexadecimal, moved from
`serde_util`; base64; PEM; DER definite lengths; civil dates), a `codes!` macro that declares
a crate's codes as constants with their list and their names, a metrics registry that refuses
a duplicate family, and methods on the DNS record origin type. The text forms belong here and
not in H1 because their users include `tenko-krb` and `tenko-auth`, which sit directly on
`tenko-core`, and because a type in `tenko-core` (`HexBytes`) needs one of them. Never: code
only one or two crates use (it goes to the lowest crate those callers share), input or output,
policy (a default, a limit an operator can set). Any crate may depend on it.

**H3 `tenko-store`.** In: `layout` (the store's file names, built in flight by the store
package), `fs` (the private-file writer and the atomic replace, with their guarantees stated on the
module and tested there), `follow` (follow one table's changes from a
revision, with reset after a gap; built in flight inside `tenko-dns` by the DNS secondaries
package and moved here), `feed` (the generic feed that sends tables to a node), `codes` (the
store's error codes as constants). Every crate that writes a private file or follows a table
already depends on `tenko-store`. Never: a domain type, a table of another crate. A change
rebuilds 14 dependents.

**H4 `tenko-api` request and answers.** In: the typed `If-Match` header, the typed path
identifier, the JSON body and the query extractors that refuse what they do not know, the
paging parameters and page type, and the grouped answer types that both the handler and its
OpenAPI annotation use. Built by the strict-requests repair package (the request half) and by
this plan (the answers). Never: anything a crate below `tenko-api` needs. Used by the route
modules of `tenko-api`; the `tenko` crate reads its origin normalization for the
configuration check. A change rebuilds `tenko-api` and `tenko` (151 s).

**H5 `tenko-dns::wire`.** The module exists. In: the record data layout and name
decompression for every record type, the RCODE and type numbers, one exchange with a remote
server with an error that keeps its cause. Never: resolution policy, caches, zone data. Used
by `tenko-dns`; `tenko-dhcp` and `tenko-scan` (both already dependents of `tenko-dns`) may use
it. A change rebuilds `tenko-dns` and its 5 dependents.

**H6 Producer exports.** Each crate that produces error codes declares them with `codes!` in
its own `codes` module; each crate that registers metric families exports their names as
constants in `metrics::names`. A consumer imports the constant; it never writes the string. A
test in the `tenko` crate, which depends on every crate, collects all code lists and all
family names and fails on a duplicate or on a code without a `sys.`, area or crate prefix that
its owner declares. Families registered by the `tenko` crate that `tenko-api` reads (a crate
cannot import from a crate above it) move their names to the crate whose code they measure.

**H7 Settings.** A setting's bounds and default live as constants and `Default` on the type
that holds the setting, in the crate that owns it (password presets in `tenko-auth`, scan
defaults in `tenko-scan`, the configuration file in `tenko`, a connector's settings in its
crate). The API uses the type itself. The OpenAPI document carries the bounds and the default
(`minimum`, `maximum`, `default`), and the UI's generator writes them into a generated values
file next to the generated types. Documentation tables of defaults are written by a command
from the code and checked by a test, as `docs/api/openapi.json` is today. The example
configuration file is checked by a test against `Config::default()` and must name every key.

**H8 `tenko-jobs`.** In: read functions over the job tables (by state, by owner) so that no
other crate knows the key layout, a typed "stage inside the step or propose" function that
replaces matching on an error string, and the generic inline hand-off that three crates copy.
A change rebuilds 11 dependents.

**H9 `tenko::client::common`.** In: what every client command repeats (paging through a list,
the usage text, the detail printer, the idempotency key, waiting for a job, the not-found
message, the text of an absent value). The command path comes from the parsed arguments, not
from a hand-written name per command. A change rebuilds `tenko` only.

**H10 Scripts.** `scripts/lib/` holds code shared by the Node scripts (one Rust lexer for
`test-lint`, the label catalog and the requirement trace). `deploy/compose/driver/api.sh`
holds setup, sign-in and API calls with timeouts for every lab (built by the lab helper
repair package); `bench/lib/node.sh` the same for the benchmarks. Never: product logic.

**H11 to H13 UI.** `components/form/` holds `createFormModel` (base values, draft, what
counts as changed, the revision the values came from), one field component per input kind,
and one mapper from a problem's field errors to sentences, built on `api/problem.ts`. `api/`
holds `createObjectCache` with one sign-out registry, `pages()` as the only paging helper,
`latest()` as the only guard for reading a resource, and list item types taken from the
generated path types. `app/format/` holds every display formatter (bytes in base 1024 with
KiB, MiB, GiB, as the owner decided); `app/clipboard.ts` the one clipboard writer. A change
in the UI rebuilds no Rust crate.

### 1.3 What stays in `tenko-core`, and what moves out

Everything in `tenko-core` today stays. Considered and not moved now:

- **The egress policy** (368 lines; outside `tenko-core` only `tenko-api` and `tenko` use
  it). The block-list type of the DNS model validates its URLs with the policy's URL shape
  check, so a move would either split one rule between two crates or take the validation out
  of the stored type. It changed once in 34 days; the gain does not pay for either.

- **The DNS model** (8,450 lines; 22 of the 63 commits that touched `tenko-core`). Eight
  crates use it, three of which do not depend on `tenko-dns` (`tenko-auth`, `tenko-cluster`,
  `tenko-krb`). Moving it would add dependency edges or a new crate, and the gain cannot be
  shown from today's figures. Revisit when the plan is done, if commits touching
  `tenko-core/src/dns*` stay above one in ten of all commits.
- **The migration module** (884 lines; only `tenko-api` imports it). It changed once. Move it
  into the crate that builds the Windows takeover when that work starts, if that work changes
  it often.
- **The DHCP model.** Five crates use it (`tenko-api`, `tenko-auth`, `tenko-cluster`,
  `tenko-dhcp`, `tenko-ipam`); the shared family core in flight will show whether it churns.

## 2. The rule for adding to a home

Until now a builder who needed a change in a file another package owned, or in `tenko-core`,
asked the lead first. For shared code this section replaces that practice; every other file
keeps one owner per package. The index of section 2.3 goes into `CONTRIBUTING.md` with a
short form of these rules.

### 2.1 For a builder

1. **Look first.** Before writing a helper, a constant, a limit, a validation or an error code,
   read the index in `CONTRIBUTING.md` (section 2.3) and search the home it names. If the
   thing exists, use it.
2. **Add without asking** when the addition is inside a home's charter and is additive: a new
   function, constant, type or module, or a new variant your code alone produces. Write a doc
   comment that names the rule and its source (an RFC, a requirement, an ADR), put unit tests
   in the home, and in the same package move every copy of the same fact that sits in a file
   your package owns. Copies in files other packages own stay listed in the copy lint's
   baseline (2.2) and in your hand-over note; their owners move them.
3. **Ask the lead** before you change what an existing shared item does or its signature,
   create a new home, put something outside a charter, or change a stored format (that rule is
   unchanged).
4. **`tenko-core` follows the same rule**, with one addition: say in your first message to the
   lead that your package changes `tenko-core`, because a change there touches every other
   open package's rebuild and is merged first at the gate.
5. **Shared lines are append-only.** The module list and re-exports of a home (`lib.rs` of
   `tenko-net`, `mod.rs` files of the homes, `index.ts` of a UI home) and the target list of
   `fuzz/Cargo.toml` are exempt from file ownership: parallel packages may each append a
   line; nobody edits or reorders another package's line. The gate resolves append conflicts.
6. **The review.** The gate lists the changes to home files apart from the rest, and the lead
   reads them. The fresh review of every package asks whether the package wrote a copy of
   something a home holds.

### 2.2 What keeps a copy from coming back

| Mechanism | What it catches | Example entries |
|---|---|---|
| Copy lint, `scripts/copy-lint.mjs` (new, S1) | A product-code definition of a name a home reserves; a string literal that is another crate's error code or metric family; a UI clipboard write or paging loop outside its home. The baseline only shrinks; an exception is a comment `copy-lint: allow <rule> <reason>`, as for the test lint. | `write_private`, `write_atomic`, `to_hex`, `reverse_name`, `ptr_name`, `"sys.store.`, `"tenko_dns_`, `navigator.clipboard` |
| `clippy.toml` `disallowed-types` and `disallowed-methods` | A type or method that only a home may use; the home's module carries `#[allow]` with the reason. | `axum::Json`, `axum::extract::Query`, `axum::extract::Path` (the request module only); `std::os::unix::fs::OpenOptionsExt::mode` (`tenko_store::fs` only) |
| Tests that collect | Every instance of a fact across the workspace, checked against its one definition. | all error codes unique and owned; all metric families unique; every node table decoded or listed as skipped; the example configuration equals the defaults; every stored type decodes an extra field and an extra variant |
| ESLint `no-restricted-properties` and `no-restricted-imports` | A UI module that reaches past a home. | `navigator.clipboard` outside `app/clipboard.ts`; hand-written fetch loops outside `api/` (the existing network rule) |

The copy lint shares one Rust lexer with the test lint (S1 moves the test lint's lexer into
`scripts/lib/`), runs in the lint job of CI and in the gate, and starts with a baseline that
counts every copy the plan removes. That baseline is the plan's measure: each package states
how many entries it removes, and the last package (S24) leaves it empty.

### 2.3 The index a builder reads

Section "Where shared code lives" in `CONTRIBUTING.md`, after "Workspace layout". Draft:

> ## Where shared code lives
>
> Before you write a helper, a limit, a validation, an error code or a metric name, look here.
> If it exists, use it. If it belongs in one of these homes and is missing, add it there
> (additions inside the charter need no permission; see `docs/plans/shared-code-plan.md`,
> section 2). `node scripts/copy-lint.mjs` reports a copy.
>
> | You need | Use | Home |
> |---|---|---|
> | Is this address link-local, mapped, special-purpose, a subnet's reserved address? | `tenko_net::addr` | `crates/tenko-net` |
> | The reverse name of an address, or the address of a reverse name | `tenko_net::reverse` | `crates/tenko-net` |
> | May the server connect to this address on an operator's behalf? | `tenko_core::egress` | `crates/tenko-core` |
> | A stored MAC address, DUID, host or domain name, and its parsing | `tenko_core::net` | `crates/tenko-core` |
> | The client's address behind a proxy | `tenko_net::proxy` | `crates/tenko-net` |
> | Hexadecimal, base64, PEM, DER lengths, civil dates | `tenko_core::codec` | `crates/tenko-core` |
> | Declare error codes | `tenko_core::codes!` in your crate's `codes` module | your crate |
> | Use another crate's error code | its `codes::*` constant, never the string | the producing crate |
> | Use a metric family name | the producer's `metrics::names::*` | the producing crate |
> | A setting's bound or default | the constant or `Default` on the setting's type | the owning crate |
> | Write a private file, or replace a file atomically | `tenko_store::fs` | `crates/tenko-store` |
> | Follow a table's changes | `tenko_store::follow` | `crates/tenko-store` |
> | Send tables to a node | `tenko_store::feed` | `crates/tenko-store` |
> | Read job tables, or stage inside a job step | `tenko_jobs::read`, `tenko_jobs::stage_or_propose` | `crates/tenko-jobs` |
> | Parse `If-Match`, a path id, a JSON body, query parameters, paging | `tenko_api::request` | `crates/tenko-api` |
> | Declare what an operation answers | the answer groups beside `tenko_api::problem` | `crates/tenko-api` |
> | DNS record layout, name decompression, RCODE and type numbers | `tenko_dns::wire` | `crates/tenko-dns` |
> | Paging, usage and printing in a client command | `tenko::client::common` | `crates/tenko` |
> | Test support (wait, free port, temporary directory) | `tenko_core::testing`, `ui/src/app/testing`, `ui/e2e/support` | as named |
> | A form, a field, a field error's sentence | `ui/src/components/form/` | UI |
> | Cache an object, page a list, read a live resource | `ui/src/api/cache.ts`, `paginate.ts`, `live.ts` | UI |
> | Format bytes, times, addresses; copy to the clipboard | `ui/src/app/format/`, `ui/src/app/clipboard.ts` | UI |
> | Call the API from a lab or a benchmark | `deploy/compose/driver/api.sh`, `bench/lib/node.sh` | scripts |
> | Lex Rust source in a script | `scripts/lib/` | scripts |

## 3. The 52 facts, placed

The rows follow the review's ranking: rows 1 to 23 have drifted with an effect a user or an
operator can see, rows 24 to 41 have drifted with an effect that is latent or only in tests,
rows 42 to 52 have not drifted yet. "Repair" names a package of the review's repair list,
which this plan does not re-plan; "S" names a package of section 4. "Agree" says whether the
copies agree today; where they do not, the column says which behavior the single place takes
and why. Six rows (6, 11, 13, 25, 35, 41) waited for an owner decision; the owner answered on
2026-11-12 (section 6), and they move to one place with the answers given. Rows 47 and 49
carried a question on one detail only, answered the same day.

| # | Fact | Home | Copies today | What happens to the copies | Agree, and the behavior taken | Outcome |
|---|---|---|---|---|---|---|
| 1 | The server's behavior as the UI's tests see it | Recorded answers of the real server (`docs/plans/ui-mock-plan.md`) | 2: the server, and the UI's mock server (about 40,000 lines, 153 test files) | Replaced by the mock plan's packages | No (units, import vocabulary, scan defaults, event kinds). The server is right. | In flight |
| 2 | Response fields the CLI reads, and which version the command on the path is | The API's DTOs (feature `client` of `tenko-api`); the command-on-path rule of ADR 0023 | about 600 reads by field name in the client; the DTOs | Client reads by type, command by command, decoding tolerantly with a warning on a version difference (decided); the command on the path becomes a link to the running version (decided 2026-10-24) | No. The server's encoding is right. | One place (repair: client version skew; command on the path) |
| 3 | The tolerance rule for stored and cross-version formats | The rule in `docs/upgrades.md`, one decode test per stored type, golden files per format | The rule in one document; about 96 stored enumerations in `tenko-core` alone and more types in 8 other crates that do not follow it | Unknown fields ignored, unknown values an explicit unknown arm (decided); a format raise where that is unsafe | No. The documented rule is right. | One place (repair: tolerance, one package per crate; the store's golden files are in flight) |
| 4 | Second implementations that tests prove instead of production | `tenko-store`: one staging core used by both stores; the DNS and DHCP reference twins removed; the IPAM VLAN double behind a test feature | Store: memory and Raft staging (161 test files see the memory one); DNS 2 caches; DHCP 5 twins; IPAM 1 double (1,053 lines) | Store: one staging core, and the conformance suite gains the journal byte limit, counter overflow and decode failure (S8). DNS: the resolver repair (in flight). DHCP: the DHCP test twins repair. VLAN double: S15. | No. Production is right. The two store backends themselves stay two on purpose, held equal by the conformance suite. | One place (S8, S15; repairs) |
| 5 | DHCPv4 and DHCPv6 behavior at every layer | The shared family core, step by step (decided) | 10 layers in 2 families | The server's slot table and commit loop first, with differential scenarios across both families | No. | In flight. The protocol layers (message formats, IA handling) stay two on purpose. |
| 6 | What a form counts as changed, which revision it sends, how it shows errors | `ui/src/components/form/` `createFormModel` | about 45 forms in 40 files | Every form moves to the model (S10); the two forms that send the live object's revision are fixed first (repair: UI forms and zone page) | No. Sending the revision the values came from is right; it is the only way a save cannot undo another operator's change. What the form does when the object changes under it is visible: SC-Q1. | One place (S10) |
| 7 | Settings bounds and defaults | The owning type (H7), published through OpenAPI | PIN minimum 7 (`tenko-auth`, UI 3, installer, OpenAPI text, mock); config defaults 2 (code, example file); scan defaults 4 (code, docs, UI, mock); DHCP profile defaults 4 (API, `tenko-dhcp`, server, mock); connector defaults 2 per connector | Readers generated or checked (S7, S18) | No. The server is right for the PIN minimum (6, raised deliberately) and for the worker count (0 to 64; the example file follows). The Proxmox page size takes 10 (1 is a typing error). The configuration section list gains the missing section. | One place (S7, S18) |
| 8 | Error codes and error text used as contracts | H6: codes exported by their owner, collected by a test | Store codes as literals in other crates (about 20); a code the store never produces (1); the job-stage code in 9 files of 6 crates; DNS error text matched in the API (2); one retry keyed on error text; 3 codes defined twice; enrollment refusals in 4 places | Constants and typed errors (S5; repairs: controller removal and store, in flight; IPAM unattended writes) | No. The producer is right. An enrollment refusal of roles answers 403 (decided). | One place (S5; repairs) |
| 9 | The API handler contract, written twice | H4 answer groups, and a conformance test beside the scope table | 426 annotations against the handlers; the 401 answer in 281 copies and 12 wordings, 503 in 84, 403 in 76, 409 in 36, 415 in 18, 412 in 20 | Annotations take their answers from the groups the handlers return; the scope text comes from the scope types (S9) | No. The handler is right; the description follows it. Planned routes stay and are marked planned (decided). | One place (S9) |
| 10 | Request rules in the API | H4 request module | `If-Match` 3; path ids 25; JSON bodies 7 plus 7 plain; query 4 plus about 50 plain; allowed origins 2 | Strict requests (decided) | No. | One place (repair: strict requests) |
| 11 | Network rules | H1 for address classes and reverse names; `tenko-ipam::query` for the most specific prefix; `tenko-scan` for LLDP identifiers; `tenko-ipam` for a reservation's identity; `tenko-dns` for the closest enclosing zone of the planners; `tenko-connect`'s normalization for connector inventories | Reverse names 7 functions in 4 crates; LLDP 2; reservation identity 3; subnet edge addresses 2; most specific prefix 5; closest enclosing zone 6 in 3 crates; connector address and MAC rules 10 sites in 4 crates; DHCPv4 option parsing 2 | S6 creates the functions and moves the copies in `tenko-dns` and the IPAM observation code; the IPAM network rules repair, the DDNS worker repair, S14 (the Kea export) and the store and connector guards repair move theirs; S26 makes the LLDP format one | No, all of them. The subnet-router anycast address is refused (RFC 4291 2.6.1); split options are joined (RFC 3396); link-local addresses are filtered from inventories as the connector documentation says; a reservation is keyed by MAC when there is no DUID (the DHCP role's rule). Owner: mapped addresses (SC-Q2), the LLDP format (SC-Q3), VRF ties (SC-Q4). The query-path zone index of `tenko-dns` stays separate (wire bytes, a speed-bound path). The scanner's DHCPv4 parser stays separate for now, held to the server's codec by a differential fuzz target, because `tenko-scan` sits below `tenko-dhcp`. | One place (S6, S26; repairs) |
| 12 | The server's start sequence and what it records | One `prepare_server` in `tenko` | 2 (command line, Windows service) | One function | No. The command-line start is right. | One place (repair: server start and shutdown) |
| 13 | Conflict and "gone" in IPAM | One definition each in `tenko-ipam::reconcile` | Conflict 2 (rules, view); gone 2 | One function each (S15) | No; the two differ on unmanaged hosts and abandoned leases, and on the lease time used. Visible on the discovery page: SC-Q5. | One place (S15) |
| 14 | Ending an account's access, and per-controller memory | One function in `tenko-auth` | 5 paths | Built | — | In flight |
| 15 | Release manifest limits, and the release tools' view of the server | Constants in Rust source, a problem-details fixture written by a Rust test | Manifest limits 2; the mirror's error shape 2; the mirror's version 2 | Script tests read the Rust constants and the fixture | No. The server is right. | One place (repairs: release path; Windows installer and mirror) |
| 16 | The privilege layout of ADR 0023 against what ships | The ADR, with an implementation-state table checked by the installer's unit test | 4 documents and files | The shipped files follow the ADR | The shipped files are brought to the ADR (decided 2026-10-24). | One place (repair: command on the path) |
| 17 | Documents that say a check runs | The workflow files; a check that every such claim names a workflow job that exists | 5 documents; the changelog override rule in 4 texts | Claims reworded to what runs, and restored when the labs run from inside the lab network (decided); the override rule made per commit (S16; repair: release and CI checks) | No. The workflows are the truth; for the override rule the three texts are right and the script follows them. | One place (S16; repair) |
| 18 | UI field kits, field-error meaning, list types, caches, paging, read guards, formatters, clipboard | H11, H12, H13 | Field kits 5; field-error mappers 3; message arguments 2; list item types typed by hand at 82 sites; caches 5; paging 5; read guards 3; byte formatters 3; clipboard writers 8 | S10, S11, S23; the caches and sign-out by the UI sign-out and caches repair | No. The mapper of `api/problem.ts` is right; bytes in base 1024 (decided). | One place (S10, S11, S23; repair) |
| 19 | Configuration of a running node read from several sources | One "profile in force" function, one roles reader, one "recursion on" rule in `tenko` | Profile 6 sites plus 2 checks; roles 3 sources; recursion 2 | One function each (S13) | The single place reads the stored settings, the source the documentation names. | One place (S13) |
| 20 | Unsetting a DHCP field | One convention: absent means unchanged, with an explicit clear | 6 conventions | Decided: absent means unchanged | No. | One place (repair: DHCP unset convention) |
| 21 | The Kea export against the engine's decisions | The engine's constants and functions, imported by the export; a differential property test | 6 pairs (architecture, PXE, policy order, expressions, lifetimes, declined flags) | The export imports (S14) | No. The engine is right: the export exists to reproduce it. | One place (S14) |
| 22 | DNS record data and wire handling, server health and choice | H5 for layout, decompression and the exchange; one health statistic | Layout and decompression 4 plus 2 partial; health 2; exchange 2 | One each (S12; the DNS wire facts repair moves the layout) | No. The complete type table is right. The two ways of choosing a server (configured forwarders, delegated name servers) stay two on purpose; the statistic under them becomes one, with its window measured and chosen in S12. | One place (S12; repair) |
| 23 | Store-watch loops and feed machinery | H3 `follow` and `feed` | Watch loops: 4 in `tenko-dns` plus the DNSSEC signer's own, 16 in 7 files of the server, more in `tenko-auth` and `tenko-connect`; feeds 2 plus 2 | The follower is built in flight; S4 moves it into `tenko-store`, S19 makes the feed generic; the server start repair moves the server's loops | No. The follower's stated contract is right. | One place (S4, S19) |
| 24 | Metric family names | H6 `metrics::names`; a registry that refuses a duplicate | About 30 literals in `tenko-api` against their producers | Imported (repair: DNS wire facts and metric names); registry (S2) | Yes today. | One place (S2; repair) |
| 25 | The drop-reason vocabulary in DHCP | One enumeration with its label | 5 places | One enumeration (S18) | No: no family label, one reason used for two causes. Labels are visible to whoever queries metrics: SC-Q6. | One place (S18) |
| 26 | DNS ownership and origin rules | Methods on the origin type in `tenko-core` (the type's crate) | Static origins 3; has served records 3; hold end 2; origin list 4; replace rule 1 | Methods (S2); callers moved (S12) | The code agrees; the replace rule's documentation is wrong and is corrected. | One place (S2, S12) |
| 27 | A record type as stored | A pinning test; storing the number waits for the next format raise | 2 | Pinning test (repair: DNS wire facts) | No (one type stored by its generic name). | One place (repair) |
| 28 | Tables the DNS feed decodes | The node table list, with a test that each is decoded or listed as skipped | 2 | Test (repair: DNS wire facts) | No (4 of 14 not decoded). | One place (repair) |
| 29 | The query-log entry and its admission | One builder | 2 | One builder (repair: DNS query path) | No. | One place (repair) |
| 30 | The client address behind proxies | H1 `proxy` | 2 (`tenko-dns`, `tenko-api`) | One parser with a security review and its fuzz target (S3) | No. The single place takes the documented rule: the configured list of trusted hops. | One place (S3) |
| 31 | Small utilities | Text forms in H2; the private-file writer in H3 | Hexadecimal 12; base64 4 or more; PEM 2; DER lengths 3; civil date 5; DNSSEC key tag 2; private-file writers 8 in 5 crates | One each (S2, S4); the key tag's copy calls the one in `tenko-core` | No. Hexadecimal per RFC 4648 (no sign accepted); a PEM block that does not decode is an error; the writer's guarantees are stated on the home and tested there. | One place (S2, S4) |
| 32 | The store's file layout and "format of a store" answers | H3 `layout`; one format answer | 2 and 3 | Built | No. | In flight |
| 33 | The list of offline commands and their privilege classes | An exhaustive match | 2 | Built | — | In flight |
| 34 | Shapes exchanged between binary versions | The typed reader; a versioned record of an update attempt | 2 readers; 1 borrowed API type | Built | No. | In flight |
| 35 | The connector web layer and certificate pinning | The connector SDK's HTTP module | 4 crates and 2 documents | One health path with fingerprint capture, one JSON GET, one send with retries (S22) | No; the documents teach two pinning flows. Visible to operators: SC-Q7. | One place (S22) |
| 36 | The job step contract and its codes | `tenko-jobs`: the contract on the step trait, one code constant | 3 | Repair: job engine | No. | One place (repair) |
| 37 | Tables of one crate read as the API of others | H8 `read`; shared constants for plugin names and guardrail codes | Job table key 4 crates; probe scopes 2; plugin names 2; guardrail codes 2 | S17 | No (a renamed field decodes as empty). | One place (S17) |
| 38 | Interactive-only kinds, security settings fields, code lists | Exhaustive matches; serialize-and-compare; `codes!` | 3 lists, 15 hand-written name ladders (131 lines) | `codes!` (S2); kinds (S5); settings comparison (repair: audit export and vault rotation) | No (a test lists 7 of 9 kinds). | One place (S2, S5; repair) |
| 39 | Order of DNS names against the order of their store keys | Two orders on purpose: text order for display, reversed-label order for keys | 2 | Stays two; the difference is documented on the type, and the key-order test gains the nine key types it omits (S12) | Not one fact. | Stays separate |
| 40 | Deploy and script code that repeats itself | H10 | Lab helpers about 20; Rust lexers in scripts 3; benchmark result parsers 3; test rule texts 4 | Lab helpers (repair: lab helper); one lexer (S1); results reader, generated rules table (S16) | No. | One place (S1, S16; repair) |
| 41 | The Windows data directory, and how `tenko.toml` is written | One source of the data directory; the configuration written through the product | Data directory 3; configuration writers 2 on Linux (a template and an editor) and 1 on Windows | Data directory: repair (Windows installer and mirror). Writer: S25, the product with an editor of its own (SC-Q8). | No. | One place (S25; repair) |
| 42 | Stored types used as API types | Made two on purpose: a stored type and an API type; a placement rule and an allowlist test | 20 flattened domain types in `tenko-api` | The allowlist test stops new ones (S9); own API types as each area is touched | Not one fact: the stored shape changes with the data format, the API shape with the API version. | Stays separate |
| 43 | IPAM paging, receipts and enumeration names | One module each in `tenko-ipam`; names from `codes!` | Paging 3; receipts 3; hand-written names 4 | S15 | Not yet. | One place (S15) |
| 44 | API paging, sort keys, the default VRF, capacity, the DHCP family | H4 paging; `tenko-ipam::query`; the existing family type | Paging 7 structures; sort keys 2; default VRF 2; capacity 1 plus a test copy; family as strings 3 | S20 | Not yet. | One place (S20) |
| 45 | The OpenAPI document as an input at run time | Computed once when the route table is sealed | 2 | S20 | Not yet. | One place (S20) |
| 46 | Module ownership tables and start order in file headers | The start order once, beside the code that holds it; ownership columns removed | 4 headers | The comment cleanup the owner approved | Not yet. | One place (comment cleanup) |
| 47 | The client's command tree and helpers | H9 | Every subcommand 4 times (56 functions, 208 name arms); helpers 2 to 7 times each | S21 | The absent-value text differs ("" and "-"): SC-Q10. | One place (S21) |
| 48 | Install step kinds and release file lists | An enumeration of step kinds; `release-files.sh` as the one list; the installer's validators sourced, not copied | Step kinds 2; release file list 6; validators 2 | S16 | Not yet. | One place (S16) |
| 49 | Small DHCP facts | One constant or function each; the engine hands its scope to the probe; the inline job hand-off in H8 | Renewal rule 3; refusal log 2; uniqueness 3; offer bound 2; client MAC 2; probe scope 2; job hand-off 3 | S18 | The client MAC rule differs: SC-Q9. | One place (S18) |
| 50 | Smaller DNS duplicates | H5 for RCODE and type numbers; one TSIG refusal mapping; versions derived from the key set; one segment walk; one cache-insert policy; one NS parser | 38 local constants in 11 files; 2 each for the rest | S12; the query-log documentation by the DNS query path repair | One documentation pair differs; the code agrees. | One place (S12; repair) |
| 51 | Kerberos exchange fixtures | The crate's own fixtures | 2, byte-identical | The benchmark copy is removed with its spike when the Kerberos line closes | Yes. | One place (removal) |
| 52 | Test helpers and fixtures copied between test files | `tenko_core::testing` and per-crate test support | Many | Built in part (merged today), the rest per crate | — | In flight |

Count: one place 43 (30 rows carried by packages of this plan, alone or with a repair
package; 13 by repair packages or approved cleanups alone), in flight 7, stays separate 2. Within rows that move to one place, parts stay two on purpose: the two
store backends (row 4), the protocol layers of the two DHCP families (row 5), the query-path zone index and, for now, the
scanner's DHCPv4 parser (row 11), and the two ways of choosing a DNS server (row 22).

## 4. The order and the packages

### 4.1 Rules the packages follow

- One to three builder-days; the files owned are named; no two packages that run at the same
  time own the same file (the append-only lines of section 2.1 excepted).
- The measure is counted after the merge: entries removed from the copy lint's baseline,
  copies from N to 1, a check that now passes.
- A copy in a file an open repair package owns is moved by that package, into the home this
  plan creates; the lead adds one line to its brief. A package here never edits such a file.
- New tests go into existing test files or in-file test modules, so the build economics
  plan's merge of test binaries is not multiplied.
- A package that moves a public item between crates (most of them) also builds the fuzz
  package once (`cd fuzz && cargo check --locked`): it calls into most crates and no
  workspace check compiles it.
- First the homes, then the facts drifted with an effect (rows 1 to 23), security first by the
  owner's order, then the rest.

### 4.2 The packages

| Package | Days | Owns | Measure (baseline → target) | Waits for |
|---|---|---|---|---|
| **S1 Homes, rule, index, copy lint** | 3 | The workspace `Cargo.toml` (a `tenko-net` entry in `[workspace.dependencies]`); `crates/tenko-net/**` (new: manifest, charter, empty module list); `CONTRIBUTING.md`; `clippy.toml`; `scripts/lib/` (the Rust lexer moved out of the test lint) and the test lint's import of it; `scripts/copy-lint.mjs`, its test and baseline; the lint step of `.github/workflows/ci.yml` (a region apart from the lines the release and CI checks repair owns; whichever merges second rebases) | Copy lint baseline written, every copy of section 3 counted (the plan's figures are the expected size); `tenko-net` has no workspace dependency (a test reads its manifest); Rust lexers in scripts 3 → 2 | Nothing |
| **S2 `tenko-core` additions, paid once** | 3 | `tenko-core/src/{error.rs, codec/**, serde_util.rs, metrics/registry.rs, dns.rs (origin methods only), lib.rs}`; the copies in `tenko-krb/src/der/reader.rs`, `tenko-auth/src/webauthn/der.rs`, `tenko-auth/src/testing/authenticator.rs`, the hexadecimal and civil-date copies in files no open package owns | Hexadecimal 12 → 1, base64 4 → 1, PEM 2 → 1, DER lengths 3 → 1, civil date 5 → 1 (copies in owned files left in the baseline); hand-written code-name ladders 15 → 0; a duplicate metric family is an error (silent → refused) | The DNS secondaries repair (in flight; touches `dns.rs`) |
| **S3 Client address behind proxies** (security) | 2 | `tenko-net/src/proxy.rs`; `tenko-dns/src/tls/proxy.rs`; `tenko-api/src/server/proxy_protocol.rs`, `forwarded.rs`; their fuzz targets | Parsers 2 → 1; one fuzz target covers it; tests for chains of trusted and untrusted hops | S1 |
| **S4 Store homes: follower and private writer** | 3 | `tenko-store/src/{follow.rs, fs.rs, lib.rs}`; `tenko-dns/src/zone/follow.rs` (moved) and the import lines of its callers; `tenko-cluster/src/buffer.rs`, `identity.rs`; `tenko-scan/src/status.rs` | Private-file writers 8 → 1 when the owners of the other files have moved theirs (this package: 8 → at most 4); follower implementations in `tenko-dns` outside the home 2 → 0; the home's guarantees stated and tested | S1; the DNS secondaries, store, and offline command guard repairs merged |
| **S5 Error codes owned and collected** | 3 | `tenko-jobs/src/stage.rs` and the callers keyed on its code: `tenko-ipam/src/jobs.rs`, `moves/steps.rs`, `moves/lease.rs`, `vlan/steps.rs`, `tenko-scan/src/control/steps.rs`, `tenko-dhcp/src/config/jobs.rs`, `tenko-dns/src/zone/jobs.rs`, `tenko-connect/src/host/service/steps.rs`; `tenko-cluster/src/registry.rs` (enrollment refusals and its stage-code use); `tenko-dns/src/recurse/net.rs`; `tenko-api/src/routes/dns/blocking.rs`, `nodes.rs`; `tenko-auth/src/roles.rs`; the collecting test in `tenko` | Literal codes of another crate: about 30 → 0; codes defined twice 3 → 0; crates whose codes a uniqueness test covers 2 → all; the interactive-only kinds matched exhaustively (a test listing 7 of 9 → a match the compiler checks) | S2; the controller removal repair (in flight), the resolver repair and the IPAM unattended writes repair merged |
| **S6 Address rules and reverse names** | 2 | `tenko-net/src/{addr.rs, reverse.rs}` with tests and a fuzz target for the reverse-name parser; `tenko-dns/src/zone/import/claim.rs` and `tenko-ipam/src/observe/dns.rs` (their reverse-name functions) | Reverse-name functions 7 → 5 here, → 1 once the IPAM network rules repair, the DDNS worker repair and S14 move theirs; subnet edge rules 2 → 1 with the IPAM network rules repair; link-local filters 4 → 1 once the connector guards repair moves its own | S1 |
| **S7 Settings bounds and defaults published** | 3 | `tenko-auth/src/password/policy.rs`; `ui/src/auth/account/PasswordSection.tsx`, `ui/src/settings/toggles.ts`, `ToggleEditors.tsx`; `tenko/src/config.rs` (section list, example test); `deploy/tenko.example.toml`; `tenko-scan/src/config.rs` (defaults); `docs/scanning.md` tables; `ui/src/scans/model.ts`; `tenko-connect-proxmox/src/lib.rs`; the value generation in `ui/scripts/api-types.mjs` | PIN minimum 7 → 2 (the installer's copy goes with the command-on-path repair, which owns `deploy/install.sh`), then → 1; configuration keys documented nowhere 4 → 0; scan default tables written from code; connectors whose stored and described defaults differ 1 → 0, a test per connector | S1; the UI grid and build checks repair if it has started (it owns `api-types.mjs`) |
| **S8 Store staging core** | 3 | `tenko-store/src/mem.rs`, `raft/apply.rs`, `raft/watch.rs`, a new `staging.rs`; the conformance suite | Implementations of staging 2 → 1; conformance cases added 3 (journal byte limit, counter overflow, decode failure), run against both stores | The store repair merged (in flight) |
| **S9 API answers from one set of types** | 3 | `tenko-api/src/problem.rs` and a new answers module; `routes/scope_table.rs` and its conformance test; the route files of DHCP and DNS | Hand-written 401 answers in DHCP and DNS routes → 0; operations whose listed answers differ from what the test observes → 0 for those areas; flattened stored types in the API: an allowlist test, new ones refused | The strict-requests and event-stream repairs, and the marking of planned routes; runs alone in `tenko-api/src/routes` |
| **S10 UI form kit, field errors, form model** | 3 | `ui/src/components/form/**` (new); `dns/Parts.tsx`, `dhcp/Parts.tsx`, `ipam/formKit.tsx`, `ipam/tenancy/FormDialog.tsx`, `settings/fields.tsx`; `api/problem.ts`; the forms moved first: `nodes/ScanConfigForm.tsx` with `nodes/scanDraft.ts` (the model's source), `hosts/HostForm.tsx`, `dhcp/policies/PoliciesPage.tsx`, `dns/ZoneSettings.tsx`, `dhcp/ScopeSettings.tsx` | Field kits 5 → 1; field-error mappers 3 → 1; forms on the model 1 → 5 (the rest by area afterwards) | The UI forms and zone page repair; S7 (the `settings/` editors); the mock plan's packages that edit the same test kits |
| **S11 UI data helpers** | 2 | `api/paginate.ts`, `api/live.ts`, `grid/source.ts`, `dns/log/LogPage.tsx`, `settings/dns/InfraSection.tsx`, `ipam/history/HistoryPanel.tsx`, `secrets/api.ts`; `app/format/**`, `nodes/format.ts`, `discovery/AddressConflictActions.tsx`, `discovery/dialogs.tsx`; `app/clipboard.ts` (new, from `secrets/clipboard.ts`) and the clipboard writers `components/RecoveryCodes.tsx`, `setup/steps/Result.tsx`, `shell/BugReport.tsx`, `updates/InstallPanel.tsx`; `ui/eslint.config.js` | Paging helpers 5 → 1; read guards 3 → 1, with a lint rule; byte formatters 3 → 1 in base 1024; clipboard writers → 1 (the account page's by the UI sign-out repair) | The UI sign-out and caches repair (it owns several of the cache files and the account page) |
| **S12 DNS wire, health, exchange, ownership** | 3 | `tenko-dns/src/wire.rs` and its numbers module; `pool.rs`, `infra/servers.rs`, `recurse/net.rs`, `upstream.rs`; `update/mod.rs` (TSIG mapping), `update/apply.rs`, `xfr/out.rs`; `querylog/read.rs`, `querylog/stats.rs`; `zone/ownership.rs`, `zone/mod.rs`, `zone/records.rs`; `tenko-core/tests/key_order.rs` | Local RCODE and type constants 38 → 0; health statistics 2 → 1; exchanges 2 → 1; TSIG refusal mappings 2 → 1; segment walks 2 → 1; origin rules in `tenko-dns` → 1 (the DHCP copy by the DDNS worker repair) | S2, S5 (shares `recurse/net.rs`); the resolver, DNS secondaries, DNS wire facts and DNS query path repairs; any open work in `update/` |
| **S13 Server configuration sources** | 2 | `tenko/src/plugin/serve.rs`, `serve/dhcp.rs`, `serve/dns.rs`, `serve/tls.rs`, `node_roles.rs`, `config.rs` (the readers) | Places that decide the profile in force 8 → 1; role readers 3 → 1; "recursion on" rules 2 → 1 | The update-path and server start repairs (they own `serve/mod.rs`, `prepared.rs`); S7 (`config.rs`) |
| **S14 Kea export reads the engine** | 2 | `tenko-dhcp/src/export/kea/**` (with its reverse-name copy); the engine's exported constants in `v4/engine/boot.rs`, `class.rs`; the property test | Constants copied into the export → 0; policy sort keys 3 → 1; a differential property test of admission | The relay trust work (in flight), the family core's first step, S6 |
| **S15 IPAM shared modules** | 3 | `tenko-ipam/src/query.rs`, `observe/view.rs`, `findings/index.rs`, `plan/planner.rs`, `vlan/provision.rs`, `moves/submit.rs`, `export/mod.rs`, `import/transform.rs`, `findings/model.rs`, `reconcile/rules.rs`, `reconcile/view.rs`, `vlan/memory.rs` | Paging 3 → 1; receipts 3 → 1; hand-written names 4 → 0; conflict and gone definitions 2 + 2 → 1 + 1; the VLAN double out of the product (1,053 product lines → test support) | The IPAM unattended writes repair; S17 (shares `findings/index.rs`) |
| **S16 Scripts, deploy lists, documented checks** | 2 | `scripts/label-catalog.mjs`, `requirement-trace.mjs` (onto the shared lexer); `docs/testing/rules.md` (generated table); `deploy/proxmox/ct/tenko.sh`, `release-files.sh`, `test/dry-run-test.sh`, `deploy/proxmox/README.md`; `tenko/src/upgrade/steps.rs` (step kinds); the benchmark results reader in test support; a check of documented runs | Lexers 2 → 1; results parsers 3 → 1; rule texts 4 → 1 (generated); release file lists 6 → 1; step kinds as strings → an enumeration; documented runs without a workflow job → 0 | S1; the lab helper, release path, release and CI checks, and update-path repairs |
| **S17 Tables read through their owner** | 2 | `tenko-jobs/src/read.rs` (new); `tenko-ipam/src/findings/index.rs`, `scope.rs`, `reconcile/scopes.rs`, `reconcile/names.rs`, `vlan/controllers.rs`; `tenko-dns/src/zone/import.rs`; `tenko-scan/src/control/steps.rs`; `tenko-cluster/src/probe.rs`; `tenko-connect/src/network.rs` | Crates that know the job key layout 4 → 1; probe scope decoders 2 → 1; plugin name lists 2 → 1; guardrail code lists 2 → 1 | S5 (shares `control/steps.rs`); the job engine repair; the IPAM unattended writes repair |
| **S18 DHCP small facts and defaults** | 2 | `tenko-dhcp/src/limits.rs`, `relay.rs`, `class/facts.rs`, `conflict/rules.rs`, `config/jobs.rs`, `lease/metrics.rs`, `v4/engine/metrics.rs`, `role/metrics.rs`, `lease/history.rs`; `tenko-jobs/src/handoff.rs` (new); `tenko-api/src/routes/dhcp/settings.rs` (profile defaults); `tenko-cluster/src/identity.rs` (renewal constant) | Drop-reason places 5 → 1; offer bounds 2 → 1; client MAC rules 2 → 1; inline job hand-offs 3 → 1; DHCP profile defaults 4 → 1 | The relay trust work, the DHCP failure visibility repair, the DHCP unset convention repair, S4 (shares `identity.rs`), S5 (shares `config/jobs.rs`) |
| **S19 Generic store feed** | 3 | `tenko-store/src/feed.rs` (new); `tenko-dns/src/feed.rs`, `store_feed.rs`; `tenko-dhcp/src/feed.rs`, `store_feed.rs` | Feed implementations 2 + 2 → 1 | S4; the DNS wire facts repair; the family core's first step |
| **S20 API paging, sort keys, the dry-run set** | 2 | `tenko-api/src/request` paging; `routes/common.rs` sort keys; `routes/prefixes.rs`; `routes/dhcp/scopes.rs`; `middleware/quorum.rs`; the route table | Paging structures 7 → 1; sort keys back to strings 2 → 0; default VRF 2 → 1; family strings 3 → 0; OpenAPI built at run time 2 → 1 | S9 |
| **S21 Client common** | 3 | `tenko/src/client/common.rs` (new), `mod.rs`, `dns.rs`, `dns_view.rs`, `dns_recursion.rs`, `dhcp.rs`, `prefix.rs`, `migrate.rs`, `ipam.rs`, `import.rs`, `auth.rs`, `access.rs` | Name arms 208 → 0 (path from the parsed arguments); pagination 6 → 1; usage 7 → 1; detail printers 6 → 1; idempotency keys 7 → 1; not-found 4 → 1; job waits 2 → 1; absent-value texts 3 → 1 | The client version-skew and server start repairs |
| **S22 Connector web layer** | 3 | `tenko-connect/src/sdk/http.rs`; `tenko-connect-hass/src/lib.rs`; `tenko-connect-proxmox/src/lib.rs`, `api.rs`; `tenko-connect-unifi/src/settings.rs`, `plugin.rs`, `http.rs`, `detect.rs`; `docs/connectors.md`, `docs/connectors-unifi.md`, `docs/plugins.md` | Health paths 3 → 1, with fingerprint capture; JSON GET helpers 3 → 1; send paths with retries: one shared path for all three connectors; pinning flows in the documents 2 → 1 | S7 (`tenko-connect-proxmox/src/lib.rs`); the store and connector guards repair (it owns UniFi's `plugin.rs` and Proxmox's `api.rs`) |
| **S23 UI list item types** | 2 | The files under `ui/src/` that call `fetchAll`, `fetchPage` or `createListSource` (63 on `6595569b`), except files an open package owns at the start; those are listed and moved by their owners | List items typed by hand 82 → 0, each read through the generated path types | S10, S11 |
| **S25 Configuration written by the product** | 3 | `tenko/src/config/edit.rs` (new: the editor) and its `mod` line in `config.rs`; `config_init.rs`; the `config` subcommands in `tenko/src/lib.rs` (`set`, `get`, `sections` beside `init`); a fuzz target for the editor; `deploy/install.sh` (the TOML helpers and the reconfigure path) and `deploy/proxmox/test/install-sh-test.sh`; `deploy/windows/wix/Package.wxs` (a reconfigure edits the kept file instead of replacing it) and `deploy/windows/msi-smoke.ps1` | Writers of `tenko.toml` 3 → 1 (the shell template, the awk editor and `config init` → the product); awk TOML code in the installer about 150 lines → 0; the editor about 300 product lines and 250 test lines, no new dependency; every edit re-read with the `toml` parser the product already uses and refused unless the result is the old document with exactly the requested change; comments, blank lines and key order kept (golden tests); a key it cannot edit safely (a dotted key, an inline table) refused with its name, never guessed | The command-on-path repair (it owns `deploy/install.sh`), the Windows installer and mirror repair; S7 (`config.rs`); S16 (`deploy/proxmox/`) |
| **S26 LLDP identifiers and device names** | 2 | A new `tenko-scan/src/lldp_id.rs` (one formatter per identifier subtype); `tenko-scan/src/frame/lldp.rs` and the LLDP columns of `snmp/mib.rs` onto it; `tenko-ipam/src/topology/model.rs`, `build.rs` (the naming order); one data migration in `tenko/src/upgrade/migrations/` (the lead assigns its number); `tenko-ipam/tests/topology.rs` | LLDP formatters 2 → 1, with a test that feeds one switch through frames and through SNMP and gets one name; stored devices renamed once at the upgrade, each rename in the audit log; a device whose address has a name in DNS is called by that name before its LLDP name | S1; the IPAM unattended writes repair |
| **S27 LLDP names proposed to DNS** (security) | 2 | A new reconciler rule `tenko-ipam/src/reconcile/lldp_names.rs` and its line in `reconcile/mod.rs`; the proposal kind in `tenko-ipam/src/proposals/model.rs`; the setting in `reconcile/settings.rs`; `ui/src/discovery/ProposalsView.tsx` (the proposal text), `ui/src/settings/reconciler/model.ts`, `ReconcilerPage.tsx` (the setting); tests in the reconciler's test module | A device without a DNS name and with an LLDP name gives one proposal; the setting is off by default and refused under the Hardened profile (a test per case); each guard rule of SC-Q11 has a test that a proposal breaking it is never made and never applied, also when accepted automatically; records written this way carry an origin a manual record never has; no new writer to DNS (the IPAM DNS actuator's existing path) | S26; S13 (the one function for the profile in force); S17 (`reconcile/names.rs` beside it) and S15 (`reconcile/rules.rs`) merged |
| **S24 Copy lint at zero** | 1 | The copy lint's baseline and rules; the index | Baseline entries → 0; every home in the index | All of the above, and the repair packages that hold copies |

Total: 67 builder-days in 27 packages. S25, S26 and S27 came with the owner's answers of
2026-11-12 (SC-Q8, SC-Q3, SC-Q11); S24 stays the last.

### 4.3 What runs in parallel

Three builders at a time, the load rule's limit, in four waves. Packages in one wave own
disjoint files.

| Wave | Packages | Why together |
|---|---|---|
| A | S1, S2, S8 | Disjoint files: S1 scripts, `tenko-net` and the index; S2 `tenko-core`; S8 store files (3 days of calendar, 9 builder-days) |
| B | S3, S4, S5, S6, S7 | All after S1 or S2; disjoint files (`tenko-net` modules and fuzz targets are appended, section 2.1) |
| C | S9, S10, S11, S12, S13, S14, S17, S26, then S15 | Each waits for its repair packages; S12 and S17 after S5, S14 after S6, S15 after S17 |
| D | S16, S18, S19, S20, S21, S22, S23, S25, S27, then S24 | The rest; S25 after S7 and S16; S27 after S13, S15, S17 and S26; S24 last |

At three builders, about 23 working days of calendar if the repair packages they wait for
merge in time; the repair packages share the same builder slots, so the lead interleaves the
two lists by the owner's order (security first).

## 5. What this does not solve

A library removes copies inside the server. Four kinds of copy remain, and each gets its own
mechanism.

- **The command-line client.** It is compiled from the same source, but the binary on the
  path can be another version than the running server. The mechanism is shared types (the
  client decodes the API's own DTOs, feature `client` of `tenko-api`), tolerant decoding with
  a warning when the versions differ (decided), and the command on the path linked to the
  running version (decided). The client's own helpers go to H9.
- **The UI.** TypeScript cannot import Rust. The mechanism is generation: the OpenAPI
  document already gives the UI its types; this plan extends it to values (bounds, defaults,
  enumeration values, error codes with their fields), written by the generator next to the
  types and checked in CI as the types are. For behavior, recorded answers of the real server
  replace the mock (the mock plan).
- **The documentation, scripts and the PowerShell mirror.** The mechanism is a test that reads
  both: tables of defaults and codes written from code by a command and compared by a test
  (as `docs/api/openapi.json` is); script tests that read constants from the Rust source (as
  `scripts/root-anchors.test.mjs` does); a fixture written by a Rust test and read by the
  mirror's Pester tests; a check that every document claiming a check runs names a workflow
  job that exists.
- **Two implementations kept on purpose.** A library would make them one; these stay two
  because they change for different reasons, so a differential test holds them equal: the
  memory and Raft stores (the conformance suite), the DHCPv4 and DHCPv6 protocol layers
  (differential scenarios, decided with the family core), the scanner's DHCPv4 parser and
  the server's codec (a differential fuzz target), the query-path zone index and the
  planners' zone lookup (the existing index oracle), the Kea export and the engine (a
  property test), and the existing differentials against `hickory` and `domain`.

Two things are outside any library: **stored data across versions**, which the tolerance rule
and its golden files hold (decided), and **contracts with outside software** (a third-party
connector, a Kea configuration, a monitoring query), which only their documentation and
release notes can hold.

## 6. Questions for the owner

Each question changes something a user or an operator notices. The options are ranked by the
owner's order: security, performance, usability, features.

The owner answered SC-Q1 to SC-Q10 on 2026-11-12: the recommended option each time, with two
particulars (SC-Q3 and SC-Q8). Each answer stands in one line under its question. SC-Q11 came
out of the answer to SC-Q3 and was answered the same day.

**SC-Q1. A form whose object another operator changes while it is open.** Today one form
keeps the values it loaded and one follows the live object; neither should send a revision
other than the one its values came from (that is fixed in either case).
- (a) Fields the user has not touched follow the live object; touched fields keep the user's
  value; saving sends the revision of the values; if the object changed meanwhile the save is
  refused (412) and the form shows what changed, with "reload" and "keep mine and save again".
  The scan configuration form works this way today.
- (b) The form freezes at open; a refused save offers only "reload", which drops the edits.
- (c) The last save wins.

Recommended: **(a)**. It never undoes another operator's change (security of the data), and it
keeps the user's work (usability). (c) loses changes silently.

**Answer, 2026-11-12:** (a), as recommended (S10).

**SC-Q2. An IPv4 address written as an IPv6 address (`::ffff:192.0.2.1`).** Today the scanner
treats it as IPv4 and IPAM as IPv6, so its reverse name lands in two different zones.
- (a) It is the IPv4 address: every input (API, import, scan, connectors) converts it, and it
  is stored, shown and reversed as `192.0.2.1` (`in-addr.arpa`).
- (b) It stays IPv6 everywhere (`ip6.arpa`).
- (c) It is refused at every input.

Recommended: **(a)**. One spelling per address, so every rule, filter and reverse zone sees the
same address (security); dual-stack listeners report addresses in this form, so refusing it
(c) would drop real observations.

**Answer, 2026-11-12:** (a), as recommended (S6).

**SC-Q3. The format of LLDP identifiers** (how switches name themselves and their ports).
Today a switch read from its frames and the same switch read over SNMP get differently
formatted names and do not join in the topology.
- (a) One format per identifier subtype of IEEE 802.1AB (a MAC as a MAC, an address as an
  address, a name as text when it is printable, otherwise hexadecimal), for frames and SNMP
  alike; stored devices are renamed once at the upgrade, with an audit record.
- (b) Keep both display forms, join on a normalized key, rename nothing.
- (c) Leave it.

Recommended: **(a)**: one device, one name (usability); the rename happens once and is
recorded.

**Answer, 2026-11-12:** (a), as recommended, with a rule for what a device is called: a name in DNS for the device's address goes before its LLDP name, and the LLDP name is used when DNS has none (S26). How the LLDP name then reaches DNS is SC-Q11.

**SC-Q4. Two prefixes with the same address range in two VRFs** (routing tables). When the
topology joins an observed address to a prefix, today the first entry wins.
- (a) Join only when the address falls in exactly one VRF, or when the observation's source
  names its VRF; otherwise no join, and a finding says the VRF is ambiguous.
- (b) The default VRF wins a tie.
- (c) Keep today's behavior.

Recommended: **(a)**. A wrong join attributes devices to the wrong network; no join with a
finding is honest and fixable.

**Answer, 2026-11-12:** (a), as recommended.

**SC-Q5. Conflicts in IPAM for unmanaged hosts and abandoned leases.** The reconciler does not
count an address as a conflict when its MAC belongs to a host the operator marked unmanaged, or
when the lease is abandoned; the discovery page and the system status do, and show a conflict
with nothing to do about it. The two also judge "gone" by different lease times.
- (a) The reconciler's definition everywhere, and "gone" by the effective lease configuration.
- (b) The view's definition everywhere, with a proposal for each such conflict.

Recommended: **(a)**. On the security side, a host marked unmanaged could be one whose
address another device has taken, and (a) would no longer raise that as a conflict. The
operator chose "unmanaged" explicitly, and the address history and the observations still
show the second device. A conflict also has to come with an action (usability). So (a) wins,
and the help text of the unmanaged mark says that such hosts are not checked for conflicts.

**Answer, 2026-11-12:** (a), as recommended (S15).

**SC-Q6. DHCP drop counters.** Today the counter of dropped packets has no label for the
address family, and one reason covers two causes.
- (a) One list of reasons with a `family` label (`v4`, `v6`) and a separate reason for replies
  too large to send; a query that sums by reason keeps working; the CHANGELOG says what
  changed.
- (b) Fix only the code; keep the labels.

Recommended: **(a)**: an operator can tell which family drops and why.

**Answer, 2026-11-12:** (a), as recommended (S18).

**SC-Q7. Certificate pinning for connectors.** The two connector documents teach opposite
steps, and one connector's health check answers a TLS failure differently from the others.
- (a) One flow for all: on a TLS failure the health check answers "unreachable" with the
  fingerprint the server presented; the operator compares it with the fingerprint shown on the
  device's own console, and confirms it in the connector's settings only if they match. The
  UI and the documents state the comparison as a required step.
- (b) The operator reads the fingerprint on the device's own console and types it in; the
  health check shows no fingerprint.

Recommended: **(a)**. A fingerprint shown from the same connection proves nothing by itself,
since a device in the path would present its own; the comparison with the device's console
is what makes it safe. With that step, (a) and (b) are equally strong on security; without
it, (b) is stronger, because the operator must read the console. (a) wins on usability: the
operator compares two strings instead of copying one by hand.

**Answer, 2026-11-12:** (a), as recommended (S22).

**SC-Q8. How the Linux installer writes `tenko.toml`.** Today a shell template writes it and
an awk script edits it on reinstall; on Windows the product writes it (`tenko config init`).
- (a) The installer uses the product on both platforms: `tenko config init` and a new
  `tenko config set`, run from the installer's own root-owned binary, never from a file the
  service account can write. Keeping comments when editing needs a TOML editor that keeps
  them: `toml_edit` is in the dependency tree today only as a build-time dependency, so using
  it in the product is a new dependency for you to approve; writing a small editor ourselves is
  the other way.
- (b) Keep the awk editor and give it tests for dotted keys and multi-line strings.

Recommended: **(a)** with `toml_edit` if you approve it: one writer of the configuration
format, the same on both platforms, and a parser instead of text patterns. Without the
dependency, (b) until a small editor of our own exists.

**Answer, 2026-11-12:** (a): the product writes and edits `tenko.toml` on both platforms, with a small editor of our own that keeps comments (S25). The owner did not approve `toml_edit` as a dependency; the product does not use it.

**SC-Q9. Which DHCPv4 clients have a MAC address.** Classes require the Ethernet hardware type;
filters take any six-octet hardware address.
- (a) Any six-octet hardware address counts as the MAC, for classes and filters alike.
- (b) Only the Ethernet hardware type (1) and IEEE 802 (6), for both.

Recommended: **(a)**. A client cannot avoid a deny filter by announcing another hardware type
(security); a class then matches the clients its filter matches.

**Answer, 2026-11-12:** (a), as recommended (S18).

**SC-Q10. How the CLI prints an absent value.** Today some commands print nothing and some
print `-`.
- (a) `-` in tables and plain text; the field is left out of JSON output.
- (b) Nothing.

Recommended: **(a)**: a column with a dash reads as "no value", an empty column as a broken
table. A cosmetic change, so it is yours to decide.

**Answer, 2026-11-12:** (a), as recommended (S21).

**SC-Q11. How a device's LLDP name reaches DNS.** The answer to SC-Q3 calls a device by its
name in DNS and falls back to its LLDP name; the owner also asked that the LLDP name then be
written into DNS. LLDP is not authenticated: a device plugged into a switch port can announce
any name, so a name written from it unchecked would let anything on a port create DNS names.
The options were a proposal the operator accepts, with an opt-in to accept such proposals
automatically; a dynamic record always written, within guard rules; and display only.

**Answer, 2026-11-12:** a proposal. The LLDP name of a device that has no name in DNS is offered
as a proposal in the reconciliation, which the operator accepts. A setting may accept such
proposals automatically; it is off by default and refused under the Hardened profile. In both
cases the guard rules hold: never over an existing record; never a reserved name or a service
label; only for addresses in managed prefixes; only in zones this installation is primary for;
and the record's origin marked so it can be told from a manual one (S27).
