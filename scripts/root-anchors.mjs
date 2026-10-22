// Conversion of the embedded DNS root trust anchors and root hints into Rust.
//
//   node scripts/root-anchors.mjs                write crates/tenko-dns/src/recursion/shipped.rs
//   node scripts/root-anchors.mjs --check        exit 1 when the committed file is stale
//   node scripts/root-anchors.mjs --stdout       print the file instead of writing it
//
// Input: crates/tenko-dns/anchors/root-anchors.xml (the IANA trust anchor file, RFC 7958) and
// crates/tenko-dns/anchors/named.root (the InterNIC root hints). Both are committed byte for
// byte as fetched; crates/tenko-dns/anchors/README.md says how to refresh them.
// Output: the Rust constants of crates/tenko-dns/src/recursion/shipped.rs, written the way
// rustfmt writes them. Node's standard library only; the output is deterministic and has LF
// line endings.
//
// Exit codes: 0 success, 1 the committed file is stale, 2 bad command line or a problem with
// the environment (an input is missing or malformed, the output cannot be written).

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { isMainModule } from "./changelog.mjs";

/** Repository-relative path of the trust anchor file. */
export const ANCHORS_PATH = "crates/tenko-dns/anchors/root-anchors.xml";
/** Repository-relative path of the root hints file. */
export const HINTS_PATH = "crates/tenko-dns/anchors/named.root";
/** Repository-relative path of the generated Rust file. */
export const OUTPUT_PATH = "crates/tenko-dns/src/recursion/shipped.rs";

/** Digest lengths in octets by DS digest type (RFC 4034, RFC 4509, RFC 6605). */
const DIGEST_LENGTHS = new Map([
  [1, 20],
  [2, 32],
  [4, 48],
]);

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/;

const MONTHS = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];

// ---------------------------------------------------------------------------------------
// XML (the subset RFC 7958 files use)

/**
 * @typedef {{ name: string, attrs: Record<string, string>, children: XmlElement[], text: string }} XmlElement
 */

/**
 * @param {string} text
 * @returns {string}
 */
function unescapeXml(text) {
  return text.replace(/&(#x[0-9a-fA-F]+|#\d+|lt|gt|amp|quot|apos);/g, (_, entity) => {
    if (entity.startsWith("#x")) return String.fromCodePoint(parseInt(entity.slice(2), 16));
    if (entity.startsWith("#")) return String.fromCodePoint(parseInt(entity.slice(1), 10));
    return { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" }[entity];
  });
}

/**
 * Parses an XML document made of elements, attributes, text, comments and a prolog. No
 * DTD, CDATA or namespaces; those are errors, not silently skipped.
 * @param {string} xml
 * @returns {XmlElement} the root element
 */
export function parseXml(xml) {
  let pos = 0;
  const fail = (/** @type {string} */ message) => {
    const line = xml.slice(0, pos).split("\n").length;
    throw new Error(`root-anchors.xml: ${message} (line ${line})`);
  };
  const skipSpace = () => {
    while (pos < xml.length && /\s/.test(xml[pos])) pos += 1;
  };
  const skipMisc = () => {
    for (;;) {
      skipSpace();
      if (xml.startsWith("<?", pos)) {
        const end = xml.indexOf("?>", pos);
        if (end < 0) fail("unterminated processing instruction");
        pos = end + 2;
      } else if (xml.startsWith("<!--", pos)) {
        const end = xml.indexOf("-->", pos);
        if (end < 0) fail("unterminated comment");
        pos = end + 3;
      } else if (xml.startsWith("<!", pos)) {
        fail("DTDs and CDATA are not supported");
      } else {
        return;
      }
    }
  };
  /** @returns {XmlElement} */
  const element = () => {
    if (xml[pos] !== "<") fail("an element was expected");
    pos += 1;
    const nameMatch = /^[A-Za-z_][A-Za-z0-9_.-]*/.exec(xml.slice(pos));
    if (nameMatch === null) fail("an element name was expected");
    const name = /** @type {RegExpExecArray} */ (nameMatch)[0];
    pos += name.length;
    /** @type {Record<string, string>} */
    const attrs = {};
    for (;;) {
      skipSpace();
      if (xml.startsWith("/>", pos)) {
        pos += 2;
        return { name, attrs, children: [], text: "" };
      }
      if (xml[pos] === ">") {
        pos += 1;
        break;
      }
      const attr = /^([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/.exec(xml.slice(pos));
      if (attr === null) fail(`bad attribute in <${name}>`);
      const [whole, key, dq, sq] = /** @type {RegExpExecArray} */ (attr);
      if (key in attrs) fail(`attribute ${key} twice in <${name}>`);
      attrs[key] = unescapeXml(dq ?? sq);
      pos += whole.length;
    }
    /** @type {XmlElement[]} */
    const children = [];
    let text = "";
    for (;;) {
      const lt = xml.indexOf("<", pos);
      if (lt < 0) fail(`<${name}> is not closed`);
      text += xml.slice(pos, lt);
      pos = lt;
      if (xml.startsWith("</", pos)) {
        const close = `</${name}>`;
        if (!xml.startsWith(close, pos)) fail(`<${name}> is closed by another tag`);
        pos += close.length;
        return { name, attrs, children, text: unescapeXml(text) };
      }
      if (xml.startsWith("<!--", pos)) {
        const end = xml.indexOf("-->", pos);
        if (end < 0) fail("unterminated comment");
        pos = end + 3;
      } else if (xml.startsWith("<!", pos) || xml.startsWith("<?", pos)) {
        fail("unsupported markup inside an element");
      } else {
        children.push(element());
      }
    }
  };
  skipMisc();
  const root = element();
  skipMisc();
  if (pos !== xml.length) fail("content after the root element");
  return root;
}

// ---------------------------------------------------------------------------------------
// The trust anchor file

/**
 * @typedef {{
 *   id: string, keyTag: number, algorithm: number, digestType: number, digest: number[],
 *   validFrom: string, validUntil: string | null,
 * }} Anchor
 * @typedef {{ id: string, source: string, zone: string, anchors: Anchor[] }} AnchorFile
 */

/**
 * @param {XmlElement} parent
 * @param {string} name
 * @returns {string}
 */
function onlyChildText(parent, name) {
  const found = parent.children.filter((c) => c.name === name);
  if (found.length !== 1) {
    throw new Error(`root-anchors.xml: <${parent.name}> needs exactly one <${name}>, found ${found.length}`);
  }
  return found[0].text.trim();
}

/**
 * @param {string} text
 * @param {string} what
 * @param {number} max
 * @returns {number}
 */
function decimal(text, what, max) {
  const value = Number(text);
  if (!/^\d+$/.test(text) || value > max) {
    throw new Error(`root-anchors.xml: ${what} "${text}" is not a number from 0 to ${max}`);
  }
  return value;
}

/**
 * Reads the trust anchor file (RFC 7958 section 2).
 * @param {string} xml
 * @returns {AnchorFile}
 */
export function parseAnchors(xml) {
  const root = parseXml(xml);
  if (root.name !== "TrustAnchor") {
    throw new Error(`root-anchors.xml: the root element is <${root.name}>, not <TrustAnchor>`);
  }
  const { id, source } = root.attrs;
  if (id === undefined || source === undefined) {
    throw new Error("root-anchors.xml: <TrustAnchor> needs id and source attributes");
  }
  const zone = onlyChildText(root, "Zone");
  /** @type {Anchor[]} */
  const anchors = [];
  for (const digest of root.children.filter((c) => c.name === "KeyDigest")) {
    const { id: digestId, validFrom, validUntil } = digest.attrs;
    if (digestId === undefined || validFrom === undefined) {
      throw new Error("root-anchors.xml: <KeyDigest> needs id and validFrom attributes");
    }
    for (const stamp of [validFrom, validUntil].filter((s) => s !== undefined)) {
      if (!RFC3339.test(stamp)) {
        throw new Error(`root-anchors.xml: "${stamp}" is not an RFC 3339 time with seconds`);
      }
    }
    const digestType = decimal(onlyChildText(digest, "DigestType"), "DigestType", 255);
    const hex = onlyChildText(digest, "Digest");
    if (!/^(?:[0-9a-fA-F]{2})+$/.test(hex)) {
      throw new Error(`root-anchors.xml: the Digest of ${digestId} is not hexadecimal octets`);
    }
    const octets = hex.match(/../g).map((pair) => parseInt(pair, 16));
    const expected = DIGEST_LENGTHS.get(digestType);
    if (expected !== undefined && octets.length !== expected) {
      throw new Error(
        `root-anchors.xml: the Digest of ${digestId} has ${octets.length} octets, digest type ${digestType} needs ${expected}`,
      );
    }
    anchors.push({
      id: digestId,
      keyTag: decimal(onlyChildText(digest, "KeyTag"), "KeyTag", 65535),
      algorithm: decimal(onlyChildText(digest, "Algorithm"), "Algorithm", 255),
      digestType,
      digest: octets,
      validFrom,
      validUntil: validUntil ?? null,
    });
  }
  if (anchors.length === 0) throw new Error("root-anchors.xml: no <KeyDigest>");
  if (zone !== ".") throw new Error(`root-anchors.xml: the zone is "${zone}", not the root`);
  return { id, source, zone, anchors };
}

// ---------------------------------------------------------------------------------------
// The root hints file

/**
 * Reads the date and the zone serial from the comment header of named.root.
 * @param {string} text
 * @returns {{ date: string, serial: number }}
 */
export function parseHints(text) {
  const dateMatch = /^;\s*last update:\s*([A-Za-z]+) (\d{1,2}), (\d{4})\s*$/m.exec(text);
  const serialMatch = /^;\s*related version of root zone:\s*(\d+)\s*$/m.exec(text);
  if (dateMatch === null) throw new Error("named.root: no 'last update' comment line");
  if (serialMatch === null) throw new Error("named.root: no 'related version of root zone' comment line");
  const month = MONTHS.indexOf(dateMatch[1]) + 1;
  const day = Number(dateMatch[2]);
  if (month === 0 || day < 1 || day > 31) {
    throw new Error(`named.root: "${dateMatch[0].trim()}" is not a date`);
  }
  const serial = Number(serialMatch[1]);
  if (!Number.isSafeInteger(serial) || serial > 0xffffffff) {
    throw new Error(`named.root: the zone serial ${serialMatch[1]} does not fit 32 bits`);
  }
  const date = `${dateMatch[3]}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
  return { date, serial };
}

// ---------------------------------------------------------------------------------------
// Rust

/**
 * A byte slice literal as rustfmt lays it out: elements packed to 100 columns.
 * @param {number[]} octets
 * @param {string} indent the indentation of the line holding `digest:`
 * @returns {string[]} the lines, starting with the one that opens the slice
 */
function digestLines(octets, indent) {
  const inner = `${indent}    `;
  const lines = [`${indent}digest: &[`];
  let current = inner;
  for (const octet of octets) {
    const item = `0x${octet.toString(16).padStart(2, "0")},`;
    if (current === inner) {
      current += item;
    } else if (current.length + 1 + item.length <= 100) {
      current += ` ${item}`;
    } else {
      lines.push(current);
      current = inner + item;
    }
  }
  lines.push(current, `${indent}],`);
  return lines;
}

/**
 * @param {string} value
 * @returns {string} a Rust string literal (the inputs hold plain ASCII, no escapes needed)
 */
function rustString(value) {
  if (!/^[\x20-\x7e]*$/.test(value) || /["\\]/.test(value)) {
    throw new Error(`"${value}" cannot be written as a plain Rust string`);
  }
  return `"${value}"`;
}

const HEADER = `//! The root trust anchors and root hints shipped in the binary.
//!
//! This file is generated by \`scripts/root-anchors.mjs\` from \`anchors/root-anchors.xml\` and
//! \`anchors/named.root\`; do not edit it by hand. \`node scripts/root-anchors.mjs --check\`
//! fails when it is stale (\`anchors/README.md\` says how to refresh the inputs).

/// One key digest of the IANA root trust anchor file (RFC 7958 section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShippedAnchor {
    /// The \`id\` attribute of the \`KeyDigest\` element.
    pub id: &'static str,
    /// The key tag of the key signing key (RFC 4034 appendix B).
    pub key_tag: u16,
    /// The DNSSEC algorithm number of the key.
    pub algorithm: u8,
    /// The DS digest type.
    pub digest_type: u8,
    /// The digest octets (the DS record's digest field).
    pub digest: &'static [u8],
    /// The start of the validity, an RFC 3339 time as written in the file.
    pub valid_from: &'static str,
    /// The end of the validity, an RFC 3339 time as written in the file; \`None\` for a key
    /// the file does not retire.
    pub valid_until: Option<&'static str>,
}
`;

const FOOTER = `
/// The anchors valid at \`unix_secs\`: \`valid_from\` at or before it, \`valid_until\` absent or
/// after it.
pub fn valid_at(unix_secs: i64) -> impl Iterator<Item = &'static ShippedAnchor> {
    ROOT_ANCHORS.iter().filter(move |anchor| {
        let from = parse_rfc3339(anchor.valid_from);
        let until = anchor.valid_until.map(parse_rfc3339);
        from.is_some_and(|from| from <= unix_secs)
            && until.is_none_or(|until| until.is_some_and(|until| unix_secs < until))
    })
}

/// A one-line description of what is shipped, for \`tenko --version\`: the key tags of the
/// anchors the file does not retire (in file order) and the date of the root hints.
pub fn summary() -> String {
    let tags: Vec<String> = ROOT_ANCHORS
        .iter()
        .filter(|anchor| anchor.valid_until.is_none())
        .map(|anchor| anchor.key_tag.to_string())
        .collect();
    format!(
        "root anchors {}; root hints {ROOT_HINTS_DATE}",
        tags.join(", ")
    )
}

/// Seconds since the Unix epoch of an RFC 3339 time with seconds (\`YYYY-MM-DDTHH:MM:SS\` and
/// \`Z\` or \`+HH:MM\`), the only form the trust anchor file uses.
fn parse_rfc3339(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if !matches!(bytes.len(), 20 | 25)
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let number = |from: usize, to: usize| -> Option<i64> {
        text.get(from..to)?.bytes().try_fold(0_i64, |acc, digit| {
            digit
                .is_ascii_digit()
                .then(|| acc * 10 + i64::from(digit - b'0'))
        })
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let offset = match (bytes.len(), bytes[19]) {
        (20, b'Z') => 0,
        (25, sign @ (b'+' | b'-')) if bytes[22] == b':' => {
            let seconds = number(20, 22)? * 3600 + number(23, 25)? * 60;
            if sign == b'+' { seconds } else { -seconds }
        }
        _ => return None,
    };
    // Days since 1970-01-01 of the proleptic Gregorian date (days from civil).
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}
`;

/**
 * Renders shipped.rs.
 * @param {string} xml the content of root-anchors.xml
 * @param {string} hints the content of named.root
 * @param {string} xmlSha256 the SHA-256 of the XML file's bytes, in hexadecimal
 * @returns {string}
 */
export function renderRust(xml, hints, xmlSha256) {
  const file = parseAnchors(xml);
  const { date, serial } = parseHints(hints);
  const out = [HEADER];
  out.push("/// The `id` attribute of the `TrustAnchor` element of the shipped file.");
  out.push(`pub const ROOT_ANCHORS_ID: &str = ${rustString(file.id)};`, "");
  out.push("/// The key digests of the shipped file, in file order, retired keys included.");
  out.push("pub const ROOT_ANCHORS: &[ShippedAnchor] = &[");
  for (const a of file.anchors) {
    out.push("    ShippedAnchor {");
    out.push(`        id: ${rustString(a.id)},`);
    out.push(`        key_tag: ${a.keyTag},`);
    out.push(`        algorithm: ${a.algorithm},`);
    out.push(`        digest_type: ${a.digestType},`);
    out.push(...digestLines(a.digest, "        "));
    out.push(`        valid_from: ${rustString(a.validFrom)},`);
    out.push(`        valid_until: ${a.validUntil === null ? "None" : `Some(${rustString(a.validUntil)})`},`);
    out.push("    },");
  }
  out.push("];", "");
  out.push("/// The trust anchor file as shipped, byte for byte.");
  out.push('pub const ROOT_ANCHORS_XML: &str = include_str!("../../anchors/root-anchors.xml");', "");
  out.push("/// The SHA-256 of [`ROOT_ANCHORS_XML`], in lowercase hexadecimal.");
  out.push(`pub const ROOT_ANCHORS_SHA256: &str =\n    ${rustString(xmlSha256)};`, "");
  out.push("/// The root hints file as shipped, byte for byte (zone file format).");
  out.push('pub const ROOT_HINTS: &str = include_str!("../../anchors/named.root");', "");
  out.push('/// The "last update" date of the root hints, as `YYYY-MM-DD`.');
  out.push(`pub const ROOT_HINTS_DATE: &str = ${rustString(date)};`, "");
  out.push('/// The "related version of root zone" serial of the root hints.');
  // Clippy (pedantic) wants digit groups in long literals.
  const grouped = String(serial).replace(/\B(?=(\d{3})+$)/g, "_");
  out.push(`pub const ROOT_HINTS_SERIAL: u32 = ${grouped};`);
  out.push(FOOTER);
  return out.join("\n");
}

// ---------------------------------------------------------------------------------------
// Files and command line

/**
 * @param {string} root the repository root
 * @returns {string} the text shipped.rs should hold
 */
export function generate(root) {
  const read = (/** @type {string} */ rel) => {
    try {
      return readFileSync(path.join(root, ...rel.split("/")));
    } catch (error) {
      throw new Error(`cannot read ${rel}: ${/** @type {Error} */ (error).message}`);
    }
  };
  const xml = read(ANCHORS_PATH);
  const hints = read(HINTS_PATH);
  const sha256 = createHash("sha256").update(xml).digest("hex");
  return renderRust(xml.toString("utf8"), hints.toString("utf8"), sha256);
}

const USAGE = `usage:
  node scripts/root-anchors.mjs [--root <dir>]            write ${OUTPUT_PATH}
  node scripts/root-anchors.mjs --check [--root <dir>]    exit 1 when the file is stale
  node scripts/root-anchors.mjs --stdout [--root <dir>]   print instead of writing
`;

const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Runs the command line and returns the exit code.
 * @param {string[]} argv
 * @returns {number}
 */
export function main(argv) {
  /** @type {ReturnType<typeof parseArgs>} */
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        check: { type: "boolean" },
        stdout: { type: "boolean" },
        root: { type: "string" },
        help: { type: "boolean", short: "h" },
      },
      allowPositionals: false,
    });
  } catch (error) {
    process.stderr.write(`root-anchors: ${/** @type {Error} */ (error).message}\n\n${USAGE}`);
    return 2;
  }
  const { check, stdout, root, help } = parsed.values;
  if (help === true) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (check === true && stdout === true) {
    process.stderr.write(`root-anchors: --check and --stdout exclude each other\n\n${USAGE}`);
    return 2;
  }
  const base = path.resolve(typeof root === "string" ? root : defaultRoot);
  const file = path.join(base, ...OUTPUT_PATH.split("/"));
  try {
    const text = generate(base);
    if (check === true) {
      let committed;
      try {
        committed = readFileSync(file, "utf8");
      } catch {
        committed = null;
      }
      if (committed === text) {
        process.stdout.write(`${OUTPUT_PATH} is current\n`);
        return 0;
      }
      const message = `${OUTPUT_PATH} is stale; run: node scripts/root-anchors.mjs`;
      if (process.env.GITHUB_ACTIONS === "true") {
        process.stdout.write(`::error file=${OUTPUT_PATH}::${message}\n`);
      }
      process.stderr.write(`${message}\n`);
      return 1;
    }
    if (stdout === true) {
      process.stdout.write(text);
      return 0;
    }
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, text, "utf8");
    process.stdout.write(`wrote ${OUTPUT_PATH}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`root-anchors: ${/** @type {Error} */ (error).message}\n`);
    return 2;
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
