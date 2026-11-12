// Copy lint for Tenko DDI: reports, in product code, a copy of a fact that a home of shared
// code holds (CONTRIBUTING.md, "Where shared code lives"), and compares what it finds with a
// committed baseline of known copies that only shrinks.
//
//   node scripts/copy-lint.mjs                   check against scripts/copy-lint.baseline.json
//   node scripts/copy-lint.mjs --list            print every finding, baseline included
//   node scripts/copy-lint.mjs --prune           remove the baseline entries nothing matches
//   node scripts/copy-lint.mjs --write-baseline  FIRST RUN ONLY: write a baseline where none is
//   node scripts/copy-lint.mjs --grown-since <ref>  fail when a rule has more baseline
//                                                entries than at the git ref
//   [--root <dir>] [--baseline <file>]           another tree or baseline (the tests use them)
//
// Exit codes as scripts/test-lint.mjs, whose machinery this shares (scripts/lib/): 0 nothing
// new and nothing stale, 1 a copy outside the baseline, a baseline entry that no longer
// matches, a malformed exception comment, or a baseline that grew, 2 bad command line or a
// problem with the environment.
//
// What is scanned: product code. In Rust `crates/*/src/**/*.rs`, without the code under
// `#[cfg(test)]` and the module files only tests reach (`tests/`, `benches/`, `bench/` and
// `fuzz/` are never read); code behind a `testing` feature is read, because it ships in a
// build that enables the feature. In the UI `ui/src/**/*.ts(x)`, without unit tests, the dev
// mock (`ui/src/api/mock/`), the generated types (`ui/src/api/generated/`) and the test
// support (`ui/src/app/testing/`). A rule never reports its own home.
//
// The check is lexical, on the shared lexers of scripts/lib/lex.mjs: comments are blanked, a
// string literal is read whole, functions and test regions are recognized, nothing is
// type-checked. A rule names a copy only by what marks it precisely (a function name, a
// literal, a pattern); a copy under another name is not seen. Each rule says what it cannot see.
//
// Rust
//   hex           A function named as a hexadecimal encoder or decoder (`hex`, `to_hex`,
//                 `from_hex`, `hex_encode`, `decode_hex`, `push_hex`, `hex_value`, ...) outside
//                 `tenko_core::codec`. Blind: hexadecimal written inline with `{:02x}` or
//                 `from_str_radix` inside a function of another name (`digest`, `fmt`, ...).
//   base64        A function named as a base64 or base64url encoder or decoder outside
//                 `tenko_core::codec`. Blind: generic names (`encode`, `decode` in a module
//                 named `base64`), an encoder inline in a larger function.
//   pem           A function that reads or writes PEM blocks (`pem`, `pem_certificates`)
//                 outside `tenko_core::codec`. Blind: a `-----BEGIN` check inline in a validator.
//   der-length    A DER or BER definite-length writer (`push_len`, `push_length`) outside
//                 `tenko_core::codec`. Blind: the readers, which sit inside methods named `read`.
//   civil-date    A function that converts days since 1970 to a civil date or back, by name
//                 (`days_from_civil`, `civil_from_days`) or by the constant of that arithmetic
//                 (`719_468`, once per function), outside `tenko_core::codec`. Blind: the same
//                 arithmetic with other constants.
//   key-tag       A DNSSEC key tag function (RFC 4034 appendix B) outside the one in
//                 `tenko_core`. Blind: the sum written inline.
//   private-file  A function that writes a file or creates a directory only its owner may
//                 read, or replaces a file atomically (`write_private`, `create_private_dir`,
//                 `write_atomic`, ...), outside `tenko_store::fs`. Blind: writers named `write`,
//                 `write_file`, `write_new`, `write_marker`; the `mode(0o600)` call itself,
//                 which the home's clippy ban covers once every writer has moved.
//   reverse-name  A function that builds the reverse name of an address or reads the address
//                 of a reverse name (`reverse_name`, `reverse_address`, `ptr_name`,
//                 `ptr_address`) outside `tenko_net::reverse`. Blind: a reverse name built
//                 inline with `in-addr.arpa` in a larger function.
//   link-local    A hand-written link-local test, by name (`is_link_local`) or by the IPv6
//                 mask `0xffc0` (once per function), outside `tenko_net::addr`. Blind: calls
//                 of the standard library's `is_link_local`, which are not copies.
//   proxy-client  A parser of the client address behind a proxy (`parse_v1`, `parse_v2`,
//                 `read_v2` of a PROXY protocol header; `forwarded_for`, `walk_forwarded_for`,
//                 `parse_forwarded_address` of a forwarded-for chain) outside
//                 `tenko_net::proxy`. Blind: the same under a generic name (`parse`).
//   dns-number    A local `u8` or `u16` constant that names a DNS RCODE, record type or class
//                 (`TYPE_SOA`, `RCODE_NOTAUTH`, `CLASS_IN`, a bare RCODE name such as
//                 `NXDOMAIN`, and in `tenko-dns` and `tenko-scan` a bare type name such as
//                 `SOA`) outside `tenko_dns::wire`. Blind: a number written inline (`41`), a
//                 constant of another name or type.
//   store-code    A string literal that is one of the store's error codes (`sys.store.*`)
//                 outside `tenko-store`. Blind: a code built with `format!` or `concat!`, and a
//                 constant that holds it (only its definition is seen, not its uses).
//   job-code      A string literal that is the job engine's stage code (`jobs.stage.*`)
//                 outside `tenko-jobs`. Blind as `store-code`.
//   metric-name   A string literal that is a metric family name (`tenko_*`, with `_total`,
//                 `_bucket`, `_sum` or `_count` cut) that another crate registers with
//                 `Desc::counter`, `Desc::gauge` or `Desc::histogram`. Blind: a family
//                 registered through a constant, a name built from a prefix, names in doc
//                 comments.
//   duplicate-code  A `&str` constant whose value is a dotted code (`ipam.not_found`) that
//                 another file declares as a constant too; every declaration is reported until
//                 one remains. Blind: a code written as a literal at its use, a code built at
//                 run time. Job kinds and plugin names have the same shape and are reported
//                 alike: they are facts too.
//   name-ladder   In `tenko-core`, a hand-written ladder `fn as_str(self) -> &'static str`
//                 (or `fn name`) whose body is one `match self` with a string literal in every
//                 arm, which the code-list macro replaces. Blind: ladders outside `tenko-core`,
//                 ladders with an arm that is not a literal.
//
// UI
//   clipboard     `navigator.clipboard` outside `ui/src/app/clipboard.ts`. Blind: the
//                 clipboard reached through a variable that holds `navigator`.
//   byte-format   A function `format...Bytes`, `...Size`, `...Memory` or `...Megabytes` outside
//                 `ui/src/app/format/`. Blind: `/ 1024` inline.
//   read-guard    A second `function latest` outside `ui/src/api/live.ts`, and the guard written
//                 inline (`x.error ? undefined : x.latest`). Blind: a guard spelled otherwise.
//   paging        A cursor taken from a page to fetch the next one (`cursor = page.next_cursor`,
//                 `setNext(page.next_cursor ...)`, `next: page.next_cursor`) outside
//                 `ui/src/api/paginate.ts`. Not reported: reading `next_cursor` only to say that
//                 more exists. Blind: a cursor under another field name.
//   object-cache  A module-level `new Map<..., Promise<...>>` outside `ui/src/api/cache.ts`.
//                 Blind: a cache of another shape (an object, a `Map` of values).
//   field-kit     A form field component (`Field`, `TextField`, `SelectField`, `SelectInput`,
//                 `FieldRow`, `FieldNote`, `FieldHelp`) defined outside
//                 `ui/src/components/form/`. Blind: a field component of another name.
//   field-error   A mapper from a problem's field errors to sentences (`fieldErrors`,
//                 `fieldMessage(s)`, `messageArgs`) outside `ui/src/api/problem.ts` and
//                 `ui/src/components/form/`. Blind: the same under another name.
//   list-type     A list item type written by hand as the type argument of `fetchAll`,
//                 `fetchPage` or `createListSource` outside `ui/src/api/`, instead of the item
//                 type the generated path types give. Not reported: the definitions, and a
//                 generic helper that passes its own type parameter on (`fetchAll<T>`). Blind:
//                 a hand-written type passed another way (a cast, an annotation on the result).
//
// Facts of docs/plans/shared-code-plan.md, section 3, that no rule here can see are listed in
// that plan's packages with their own measure (behavior, configuration read from several
// sources, tables read across crates): a lexical rule would only guess at them.
//
// An exception is a comment `copy-lint: allow <rule> <reason>` on the line of the finding or
// the line above; the reason is required, and an exception that suppresses nothing is an
// error. The baseline (scripts/copy-lint.baseline.json) lists today's copies by rule, file,
// scope (the function or constant) and the matched text, never by line. Whoever moves a copy
// to its home removes its entry in the same commit (`--prune`). Node's standard library only.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { lintKit } from "./lib/baseline.mjs";
import { lineOf, lineStarts, maskRust, maskTs, parseRust, rel, rustTestModules, walk } from "./lib/lex.mjs";

const CORE_CODEC = "tenko_core::codec";

/** Each rule: its message and its home, as a path prefix (a file or a directory). */
const HOMES = {
  hex: [`hexadecimal text; use ${CORE_CODEC}`, ["crates/tenko-core/src/codec"]],
  base64: [`base64 text; use ${CORE_CODEC}`, ["crates/tenko-core/src/codec"]],
  pem: [`PEM text; use ${CORE_CODEC}`, ["crates/tenko-core/src/codec"]],
  "der-length": [`a DER definite length; use ${CORE_CODEC}`, ["crates/tenko-core/src/codec"]],
  "civil-date": [`a civil date from days; use ${CORE_CODEC}`, ["crates/tenko-core/src/codec"]],
  "key-tag": ["a DNSSEC key tag; use the one in tenko_core", ["crates/tenko-core/src/dns/recursion.rs"]],
  "private-file": ["a private or atomic file writer; use tenko_store::fs", ["crates/tenko-store/src/fs"]],
  "reverse-name": ["a reverse name; use tenko_net::reverse", ["crates/tenko-net/src/reverse"]],
  "link-local": ["a link-local test written by hand; use tenko_net::addr", ["crates/tenko-net/src/addr"]],
  "proxy-client": ["the client address behind a proxy; use tenko_net::proxy", ["crates/tenko-net/src/proxy"]],
  "dns-number": ["a DNS RCODE, type or class number; use tenko_dns::wire", ["crates/tenko-dns/src/wire"]],
  "store-code": ["a store error code as a string; use the store's codes constant", ["crates/tenko-store/"]],
  "job-code": ["the job engine's stage code as a string; use tenko_jobs", ["crates/tenko-jobs/"]],
  "metric-name": ["another crate's metric family as a string; use its metrics::names constant", []],
  "duplicate-code": ["a code declared in two places; declare it once with its producer", []],
  "name-ladder": ["a hand-written code-name ladder; declare the list with the code-list macro", []],
  clipboard: ["the clipboard; use ui/src/app/clipboard.ts", ["ui/src/app/clipboard.ts"]],
  "byte-format": ["a byte formatter; use ui/src/app/format/", ["ui/src/app/format/"]],
  "read-guard": ["a read guard; use latest() of ui/src/api/live.ts", ["ui/src/api/live.ts"]],
  paging: ["a paging loop; use pages() or fetchAll() of ui/src/api/paginate.ts", ["ui/src/api/paginate.ts"]],
  "object-cache": ["an object cache; use ui/src/api/cache.ts", ["ui/src/api/cache.ts"]],
  "field-kit": ["a form field component; use ui/src/components/form/", ["ui/src/components/form/"]],
  "field-error": ["a field error mapper; use ui/src/api/problem.ts or ui/src/components/form/", ["ui/src/api/problem.ts", "ui/src/components/form/"]],
  "list-type": ["a list item typed by hand; take the item type from the generated path types", ["ui/src/api/"]],
};

export const RULES = Object.fromEntries(Object.entries(HOMES).map(([rule, [message]]) => [rule, message]));

const inHome = (rule, file) => HOMES[rule][1].some((home) => file === home || file.startsWith(home.endsWith("/") ? home : `${home}/`) || file === `${home}.rs`);

/** Rust function names that mark a copy, by rule. */
const FUNCTIONS = {
  hex: /^(?:hex|to_hex|from_hex|unhex|hex_encode|hex_decode|encode_hex|decode_hex|hex_upper|hex_into|push_hex|hex_value|hex_bytes|hex_literal|colon_hex|hex_with_colons|random_hex|sha1_hex_upper)$/,
  base64: /^(?:base64|base64_encode|base64_decode|base64_value|base64url_encode|base64url_decode|base64url_value|decode_base64url|decode_base64url_32|push_base64url)$/,
  pem: /^(?:pem|pem_certificates|parse_pem|decode_pem|encode_pem|to_pem)$/,
  "der-length": /^(?:push_len|push_length|der_length|read_length)$/,
  "civil-date": /^(?:civil_from_days|days_from_civil)$/,
  "key-tag": /^key_tag$/,
  "private-file": /^(?:write_private|write_atomic|write_atomically|write_then_rename|private_file|create_private|create_private_dir|create_private_file|create_file_private|create_dir_private)$/,
  "reverse-name": /^(?:reverse_name|reverse_name6|reverse_address|ptr_name|ptr_address)$/,
  "proxy-client": /^(?:parse_v1|parse_v2|read_v2|forwarded_for|walk_forwarded_for|parse_forwarded_address)$/,
  "link-local": /^is_link_local$/,
};

/**
 * Literals that only one rule's arithmetic uses: a function that holds one is a copy of that
 * rule, reported once per function and not again when its name was already reported.
 */
const MARKERS = {
  "civil-date": /\b719_?468\b/g,
  "link-local": /\b0x[fF]{2}[cC]0\b/g,
};

/** DNS mnemonics: record types and RCODEs. */
const DNS_TYPES = "A|NS|CNAME|SOA|PTR|MX|TXT|AAAA|SRV|NAPTR|DNAME|OPT|DS|SSHFP|RRSIG|NSEC|DNSKEY|NSEC3|NSEC3PARAM|TLSA|CDS|CDNSKEY|SVCB|HTTPS|CAA|TKEY|TSIG|IXFR|AXFR|MAILB|MAILA|ANY";
const DNS_RCODES = "NOERROR|FORMERR|SERVFAIL|NXDOMAIN|NOTIMP|REFUSED|YXDOMAIN|YXRRSET|NXRRSET|NOTAUTH|NOTZONE|BADVERS|BADSIG|BADKEY|BADTIME|BADMODE|BADNAME|BADALG|BADTRUNC|BADCOOKIE";
/**
 * A `u8` or `u16` constant that names a DNS RCODE, record type or class: prefixed anywhere
 * (`TYPE_SOA`, `RCODE_NOTAUTH`, `CLASS_IN`) or a bare RCODE name, and a bare record type name
 * (`SOA`) in the crates that speak DNS.
 */
const DNS_CONST = new RegExp(String.raw`\bconst\s+(RCODE_[A-Z0-9_]+|(?:Q?TYPE|RR_?TYPE)_(?:${DNS_TYPES})|Q?CLASS_(?:IN|CH|HS|NONE|ANY)|${DNS_RCODES})\s*:\s*u(?:8|16)\s*=`, "g");
const DNS_BARE_TYPE = new RegExp(String.raw`\bconst\s+(${DNS_TYPES})\s*:\s*u16\s*=`, "g");
const DNS_CRATES = /^crates\/(?:tenko-dns|tenko-scan)\//;

/** String literal values that are another crate's fact, by rule. */
const LITERALS = { "store-code": /^sys\.store\.[a-z0-9_.]+$/, "job-code": /^jobs\.stage\.[a-z0-9_.]+$/ };

/** A dotted code: the shape of error codes, job kinds and audit actions. */
const CODE = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$/;
const FAMILY = /^tenko_[a-z0-9_]+$/;
const REGISTER = /\bDesc\s*::\s*(?:counter|gauge|histogram)\s*\(\s*"(tenko_[a-z0-9_]+)"/g;
const crateOf = (file) => /^crates\/([^/]+)\//.exec(file)?.[1] ?? "";
const family = (name) => name.replace(/_(?:total|bucket|sum|count)$/, "");

// ---------------------------------------------------------------------------------------
// Rust

/** The string literals of masked Rust: `{ at, value }`, `at` the offset of the opening quote. */
function literals(src, masked) {
  const out = [];
  let open = -1;
  for (let i = masked.indexOf('"'); i !== -1; i = masked.indexOf('"', i + 1)) {
    if (open === -1) open = i;
    else {
      out.push({ at: open, value: src.slice(open + 1, i) });
      open = -1;
    }
  }
  return out;
}

/** The scope of an offset: the innermost function, else the constant or static declared there. */
function scopeAt(fns, masked, at) {
  let best = null;
  for (const f of fns) if (f.start <= at && at <= f.end && (!best || f.start > best.start)) best = f;
  if (best) return best.name;
  const head = masked.slice(Math.max(0, at - 300), at);
  const start = Math.max(head.lastIndexOf(";"), head.lastIndexOf("{"), head.lastIndexOf("}")) + 1;
  return /\b(?:const|static)\s+([A-Za-z_]\w*)/.exec(head.slice(start))?.[1] ?? "";
}

/** One Rust product file: its findings, and its `&str` code constants and registered families. */
export function scanRust(src, file) {
  const masked = maskRust(src);
  const { fns, regions } = parseRust(src, masked, false);
  const inTest = (at) => regions.some(([a, b]) => at >= a && at <= b);
  const starts = lineStarts(src);
  const findings = [];
  const add = (rule, at, scope, text) => {
    if (!inHome(rule, file)) findings.push({ rule, line: lineOf(starts, at), scope, text, message: RULES[rule] });
  };

  for (const f of fns) {
    if (f.test) continue;
    for (const [rule, names] of Object.entries(FUNCTIONS)) if (names.test(f.name)) add(rule, f.start, f.name, `fn ${f.name}`);
    if (file.startsWith("crates/tenko-core/src/") && /^(?:as_str|name)$/.test(f.name) && isLadder(src, masked, f)) {
      findings.push({ rule: "name-ladder", line: lineOf(starts, f.start), scope: f.name, text: `fn ${f.name}`, message: RULES["name-ladder"] });
    }
  }
  for (const m of masked.matchAll(DNS_CONST)) if (!inTest(m.index)) add("dns-number", m.index, m[1], `const ${m[1]}`);
  if (DNS_CRATES.test(file)) for (const m of masked.matchAll(DNS_BARE_TYPE)) if (!inTest(m.index)) add("dns-number", m.index, m[1], `const ${m[1]}`);
  for (const [rule, marker] of Object.entries(MARKERS)) {
    const seen = new Set(findings.filter((x) => x.rule === rule).map((x) => x.scope));
    for (const m of masked.matchAll(marker)) {
      if (inTest(m.index)) continue;
      const scope = scopeAt(fns, masked, m.index);
      if (seen.has(scope)) continue;
      seen.add(scope);
      add(rule, m.index, scope, `${m[0]} in ${scope || "a constant"}`);
    }
  }

  const codes = [];
  const families = [];
  const used = [];
  const plain = maskRust(src, { strings: false });
  for (const m of plain.matchAll(REGISTER)) if (!inTest(m.index)) families.push(m[1]);
  for (const { at, value } of literals(src, masked)) {
    if (inTest(at)) continue;
    const scope = scopeAt(fns, masked, at);
    let taken = false;
    for (const [rule, shape] of Object.entries(LITERALS)) {
      if (shape.test(value)) {
        add(rule, at, scope, `"${value}"`);
        taken = true;
      }
    }
    if (taken) continue;
    if (FAMILY.test(value)) used.push({ at, value, scope, line: lineOf(starts, at) });
    else if (CODE.test(value) && /\bconst\s+[A-Za-z_]\w*\s*:\s*&\s*(?:'static\s+)?str\s*=\s*$/.test(masked.slice(Math.max(0, at - 120), at))) {
      codes.push({ value, scope, line: lineOf(starts, at) });
    }
  }
  return { findings, codes, families, used };
}

/** Whether the function is one `match self` whose every arm is a string literal. */
function isLadder(src, masked, f) {
  if (!/\bself\b[^)]*\)\s*->\s*&\s*'static\s+str\s*$/.test(masked.slice(f.start, f.body))) return false;
  const body = src.slice(f.body + 1, f.end).replace(/\/\/[^\n]*/g, "").trim();
  const m = /^match\s+\*?self\s*\{([\s\S]*)\}$/.exec(body);
  if (!m) return false;
  const arms = m[1].split(/,\s*(?=[A-Za-z_(|])/).map((a) => a.trim().replace(/,$/, "")).filter(Boolean);
  return arms.length > 1 && arms.every((a) => /=>\s*"[^"]*"$/.test(a));
}

// ---------------------------------------------------------------------------------------
// TypeScript

const TS_RULES = [
  { rule: "clipboard", re: /\bnavigator\s*\.\s*clipboard\b/g },
  { rule: "byte-format", re: /\b(?:function\s+|const\s+)(format\w*(?:Bytes|Size|Memory|Megabytes))\b/g },
  { rule: "read-guard", re: /\bfunction\s+(latest)\b|\.error\s*\?\s*undefined\s*:\s*[\w$.()]+\.latest\b/g },
  { rule: "paging", re: /(?:\w*[cC]ursor\w*\s*[:=]|\bset\w*\s*\(|\bnext\s*[:=])\s*[\w$.]*\.next_cursor\b/g },
  { rule: "object-cache", re: /^(?:export\s+)?const\s+([\w$]+)\s*=\s*new\s+Map\s*<[^;\n]*\bPromise\s*</gm },
  { rule: "field-kit", re: /\b(?:function\s+|const\s+)(Field|TextField|SelectField|SelectInput|FieldRow|FieldNote|FieldHelp)\b/g },
  { rule: "field-error", re: /\b(?:function\s+|const\s+)(fieldErrors|fieldMessages?|messageArgs)\b/g },
  // Not the definitions, and not a generic helper that passes its own type parameter on.
  { rule: "list-type", re: /(?<!\bfunction\s+)\b(fetchAll|fetchPage|createListSource)\s*<(?![A-Z]\s*>)/g },
];

/** One UI product file: its findings. */
export function scanTs(src, file) {
  const masked = maskTs(src);
  const starts = lineStarts(src);
  const findings = [];
  for (const { rule, re } of TS_RULES) {
    if (inHome(rule, file)) continue;
    for (const m of masked.matchAll(re)) {
      const text = m[0].replace(/\s+/g, " ").trim();
      findings.push({ rule, line: lineOf(starts, m.index), scope: m[1] ?? "", text, message: RULES[rule] });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------------------
// The tree

const kit = lintKit({
  tool: "copy-lint",
  rules: RULES,
  docs: 'CONTRIBUTING.md, "Where shared code lives"',
  about: "Known copies of scripts/copy-lint.mjs (CONTRIBUTING.md, \"Where shared code lives\"). This list only shrinks: a copy not listed fails the check, and so does an entry nothing matches. Whoever moves a copy to its home removes its entry in the same commit (node scripts/copy-lint.mjs --prune).",
  fix: "use the home",
});
export const { applyAllows, parseBaseline, compare, growth } = kit;

/** Every finding of the tree under `root`, exceptions applied: `{ findings, errors }`. */
export function lintTree(root) {
  const findings = [];
  const errors = [];
  const take = (file, text, found) => {
    const { kept, errors: errs } = applyAllows(found, text, file);
    for (const f of kept) findings.push({ ...f, file });
    errors.push(...errs);
  };

  const rs = [];
  walk(path.join(root, "crates"), rs, (f) => /[\\/]crates[\\/][^\\/]+[\\/]src[\\/].*\.rs$/.test(f));
  const cache = new Map();
  const read = (f) => {
    if (!cache.has(f)) cache.set(f, readFileSync(f, "utf8"));
    return cache.get(f);
  };
  const testOnly = rustTestModules(rs, read);
  const scans = [];
  for (const f of rs) {
    if (testOnly.has(f)) continue;
    const file = rel(root, f);
    scans.push({ file, text: read(f), ...scanRust(read(f), file) });
  }

  // Families: who registers each, then the literals in another crate.
  const registrar = new Map();
  for (const s of scans) for (const name of s.families) if (!registrar.has(name)) registrar.set(name, crateOf(s.file));
  // Codes declared as constants in more than one file.
  const declared = new Map();
  for (const s of scans) for (const c of s.codes) declared.set(c.value, (declared.get(c.value) ?? new Set()).add(s.file));

  for (const s of scans) {
    const found = [...s.findings];
    for (const u of s.used) {
      const owner = registrar.get(family(u.value));
      if (owner && owner !== crateOf(s.file)) found.push({ rule: "metric-name", line: u.line, scope: u.scope, text: `"${u.value}"`, message: RULES["metric-name"] });
    }
    for (const c of s.codes) {
      if (declared.get(c.value).size > 1) found.push({ rule: "duplicate-code", line: c.line, scope: c.scope, text: `"${c.value}"`, message: RULES["duplicate-code"] });
    }
    take(s.file, s.text, found);
  }

  const ts = [];
  walk(path.join(root, "ui", "src"), ts, (f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f));
  for (const f of ts) {
    const file = rel(root, f);
    if (/^ui\/src\/(?:api\/mock|api\/generated|app\/testing)\//.test(file)) continue;
    const text = readFileSync(f, "utf8");
    take(file, text, scanTs(text, file));
  }

  findings.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0)));
  return { findings, errors };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = kit.main(lintTree, { defaultRoot: path.dirname(path.dirname(fileURLToPath(import.meta.url))), defaultBaseline: "scripts/copy-lint.baseline.json" });
}
