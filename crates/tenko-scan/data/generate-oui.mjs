// Builds data/oui.tsv, the table of vendor names that tenko-scan compiles in, from the CSV
// file of the IEEE Registration Authority (the MA-L registry of 24-bit OUI blocks).
//
//   node generate-oui.mjs <path to oui.csv> [out]
//
// Get the CSV from https://standards-oui.ieee.org/oui/oui.csv. The columns are
// "Registry,Assignment,Organization Name,Organization Address"; only the rows of the registry
// MA-L are kept. The output goes to `oui.tsv` next to this script unless `out` is given: a
// header of comment lines (source, date, number of entries), then one line per OUI with six
// upper-case hexadecimal digits, a tab and the name of the organization, sorted by OUI and
// ended by LF. A name is trimmed, its runs of white space become one space, control
// characters are dropped and it is cut to 96 characters; the first row wins when an OUI
// occurs twice. Node.js 22, no dependencies.
//
// Exit codes: 0 success, 1 the CSV is not in the expected format, 2 bad command line or a
// file that cannot be read or written.

import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const SOURCE = "https://standards-oui.ieee.org/oui/oui.csv";
export const MAX_NAME_LENGTH = 96;
const EXPECTED_HEADER = ["registry", "assignment", "organization name", "organization address"];

/**
 * Splits CSV text into rows of fields. Fields may be quoted, with doubled quotes for a quote
 * and any character, line breaks included, between the quotes. A leading byte order mark is
 * ignored and LF, CRLF and CR all end a row.
 *
 * @param {string} text
 * @returns {string[][]}
 */
export function parseCsv(text) {
  const input = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  let started = false; // something was read for the current row
  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    if (quoted) {
      if (c === '"') {
        if (input[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      quoted = true;
      started = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
      started = true;
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && input[i + 1] === "\n") i++;
      if (started || field !== "") {
        row.push(field);
        rows.push(row);
      }
      row = [];
      field = "";
      started = false;
    } else {
      field += c;
      started = true;
    }
  }
  if (started || field !== "") {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/**
 * The name of an organization as it is stored: white space collapsed, control characters
 * dropped, trimmed and cut to `MAX_NAME_LENGTH` characters.
 *
 * @param {string} name
 * @returns {string}
 */
export function normalizeName(name) {
  const collapsed = name.replace(/\s+/gu, " ").replace(/\p{Cc}/gu, "").trim();
  const characters = Array.from(collapsed);
  if (characters.length <= MAX_NAME_LENGTH) return collapsed;
  return characters.slice(0, MAX_NAME_LENGTH).join("").trimEnd();
}

/**
 * Reads the rows of the registry CSV into sorted `[oui, name]` pairs.
 *
 * @param {string} csv
 * @returns {{ entries: [string, string][], skipped: string[] }}
 */
export function readRegistry(csv) {
  const rows = parseCsv(csv);
  const header = (rows[0] ?? []).map((name) => name.trim().toLowerCase());
  if (EXPECTED_HEADER.some((name, i) => header[i] !== name)) {
    throw new FormatError(
      "the first row must name the columns Registry, Assignment, Organization Name, " +
        `Organization Address; found: ${JSON.stringify(rows[0] ?? [])}`,
    );
  }
  const seen = new Map();
  const skipped = [];
  for (const [index, row] of rows.slice(1).entries()) {
    if ((row[0] ?? "").trim() !== "MA-L") continue;
    const oui = (row[1] ?? "").trim().toUpperCase();
    const name = normalizeName(row[2] ?? "");
    if (!/^[0-9A-F]{6}$/u.test(oui) || name === "") {
      skipped.push(`row ${index + 2}: ${JSON.stringify(row.slice(0, 3))}`);
      continue;
    }
    if (!seen.has(oui)) seen.set(oui, name);
  }
  const entries = [...seen.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return { entries, skipped };
}

/**
 * The text of the table.
 *
 * @param {[string, string][]} entries
 * @param {string} generated the date, `YYYY-MM-DD`
 * @returns {string}
 */
export function formatTable(entries, generated) {
  const header = [
    "# Vendor names for MAC addresses, by the OUI (the first three octets).",
    `# source: ${SOURCE}`,
    "# registry: IEEE Registration Authority, MA-L (24-bit blocks)",
    `# generated: ${generated}`,
    `# entries: ${entries.length}`,
    "# format: six upper-case hexadecimal digits, a tab, the name of the organization; sorted by OUI",
  ];
  const lines = entries.map(([oui, name]) => `${oui}\t${name}`);
  return `${[...header, ...lines].join("\n")}\n`;
}

class FormatError extends Error {}

function main(argv) {
  const [input, output, ...rest] = argv;
  if (!input || rest.length > 0 || input === "--help" || input === "-h") {
    process.stderr.write("usage: node generate-oui.mjs <path to oui.csv> [out]\n");
    return input === "--help" || input === "-h" ? 0 : 2;
  }
  const out =
    output ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "oui.tsv");
  let csv;
  try {
    csv = readFileSync(input, "utf8");
  } catch (error) {
    process.stderr.write(`cannot read ${input}: ${error.message}\n`);
    return 2;
  }
  let registry;
  try {
    registry = readRegistry(csv);
  } catch (error) {
    if (!(error instanceof FormatError)) throw error;
    process.stderr.write(`${input}: ${error.message}\n`);
    return 1;
  }
  if (registry.entries.length === 0) {
    process.stderr.write(`${input}: no MA-L rows found\n`);
    return 1;
  }
  for (const line of registry.skipped) {
    process.stderr.write(`skipped ${line}\n`);
  }
  const generated = new Date().toISOString().slice(0, 10);
  try {
    writeFileSync(out, formatTable(registry.entries, generated), "utf8");
  } catch (error) {
    process.stderr.write(`cannot write ${out}: ${error.message}\n`);
    return 2;
  }
  process.stdout.write(`${out}: ${registry.entries.length} entries\n`);
  return 0;
}

/**
 * Whether this module is the one node was started with.
 *
 * @returns {boolean}
 */
function isMainModule() {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    const a = realpathSync(path.resolve(entry));
    const b = realpathSync(fileURLToPath(import.meta.url));
    return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
  } catch {
    return false;
  }
}

if (isMainModule()) {
  process.exitCode = main(process.argv.slice(2));
}
