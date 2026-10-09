// Readers of the mock: a CSV file becomes one sheet of cells, a workbook (xlsx, xls, ods)
// becomes the canned workbook of import-workbook.ts, because the mock cannot unpack one
// (crates/tenko-ipam/src/import/read).
import { isBlank, textCell, type Cell, type SourceFile, type SourceFormat } from "./import-cells";
import { cannedWorkbook } from "./import-workbook";

const DELIMITERS = [",", ";", "\t"] as const;
const SNIFF_LINES = 20;

/** Why a file cannot be read. */
export class ReadError extends Error {
  constructor(
    readonly kind: "unsupported" | "malformed",
    message: string,
  ) {
    super(message);
    this.name = "ReadError";
  }
}

interface Decoded {
  text: string;
  encoding: string;
  bom: boolean;
}

function startsWith(bytes: Uint8Array, prefix: readonly number[]): boolean {
  return prefix.every((b, i) => bytes[i] === b);
}

/** UTF-16 with a byte order mark, UTF-8 with or without one, Windows-1252 otherwise. */
function decode(bytes: Uint8Array): Decoded {
  if (startsWith(bytes, [0xff, 0xfe])) {
    return { text: new TextDecoder("utf-16le").decode(bytes.subarray(2)), encoding: "UTF-16LE", bom: true };
  }
  if (startsWith(bytes, [0xfe, 0xff])) {
    return { text: new TextDecoder("utf-16be").decode(bytes.subarray(2)), encoding: "UTF-16BE", bom: true };
  }
  const bom = startsWith(bytes, [0xef, 0xbb, 0xbf]);
  const body = bom ? bytes.subarray(3) : bytes;
  try {
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(body), encoding: "UTF-8", bom };
  } catch {
    return { text: new TextDecoder("windows-1252").decode(body), encoding: "windows-1252", bom };
  }
}

/** The delimiter counts of each of the first lines, outside quoted sections. */
function sampleCounts(text: string): number[][] {
  const samples: number[][] = [];
  let counts = [0, 0, 0];
  let inQuotes = false;
  let fieldStart = true;
  let blank = true;
  for (let i = 0; i < text.length && samples.length < SNIFF_LINES; i += 1) {
    const c = text[i] as string;
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') i += 1;
        else inQuotes = false;
      }
      continue;
    }
    if (c === "\n" || c === "\r") {
      if (!blank) samples.push(counts);
      counts = [0, 0, 0];
      fieldStart = true;
      blank = true;
      continue;
    }
    const slot = (DELIMITERS as readonly string[]).indexOf(c);
    if (slot >= 0) {
      counts[slot] = (counts[slot] ?? 0) + 1;
      fieldStart = true;
      blank = false;
    } else if (c === '"' && fieldStart) {
      inQuotes = true;
      fieldStart = false;
      blank = false;
    } else {
      fieldStart = false;
      blank = blank && /\s/.test(c);
    }
  }
  if (!blank && samples.length < SNIFF_LINES) samples.push(counts);
  return samples;
}

/**
 * Picks the delimiter from the first lines: a candidate qualifies when one non-zero count
 * repeats on at least half of the sampled lines; the one with the most such lines wins, then
 * the higher count (so a decimal comma in a semicolon file does not win). A single column is
 * read with a comma.
 */
function sniffDelimiter(text: string): string {
  const samples = sampleCounts(text);
  let bestLines = 0;
  let bestCount = 0;
  let best = ",";
  for (const [slot, delimiter] of DELIMITERS.entries()) {
    let lines = 0;
    let count = 0;
    for (const line of samples) {
      const candidate = line[slot] ?? 0;
      if (candidate === 0) continue;
      const same = samples.filter((l) => l[slot] === candidate).length;
      if (same > lines || (same === lines && candidate > count)) {
        lines = same;
        count = candidate;
      }
    }
    if (lines === 0 || lines * 2 < samples.length) continue;
    if (lines > bestLines || (lines === bestLines && count > bestCount)) {
      bestLines = lines;
      bestCount = count;
      best = delimiter;
    }
  }
  return best;
}

/** Fields per RFC 4180: a quote opens a quoted field only at the start of a field. */
function parseRows(text: string, delimiter: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let fieldStart = true;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i] as string;
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
      continue;
    }
    if (c === '"' && fieldStart) {
      inQuotes = true;
      fieldStart = false;
    } else if (c === delimiter) {
      row.push(field);
      field = "";
      fieldStart = true;
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i += 1;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
      fieldStart = true;
    } else {
      field += c;
      fieldStart = false;
    }
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/** The sheet name of a CSV file: the file name without directory and `.csv`, `.tsv` or `.txt`. */
export function sheetNameOf(name: string): string {
  const file = name.split(/[\\/]/).pop() ?? name;
  const match = /^(.+)\.(csv|tsv|txt)$/i.exec(file);
  return match?.[1] ?? file;
}

/** Reads one CSV file into a sheet named after the file. */
export function readCsv(name: string, bytes: Uint8Array): SourceFile {
  const decoded = decode(bytes);
  const delimiter = sniffDelimiter(decoded.text);
  const rows: Cell[][] = parseRows(decoded.text, delimiter).map((fields) => {
    const cells = fields.map(textCell);
    return cells.every(isBlank) ? [] : cells;
  });
  while (rows.length > 0 && (rows[rows.length - 1] ?? []).length === 0) rows.pop();
  return {
    name,
    format: "csv",
    size: bytes.length,
    sheets: [{ name: sheetNameOf(name), rows }],
    text: { encoding: decoded.encoding, bom: decoded.bom, delimiter },
  };
}

// ---------------------------------------------------------------------------------
// Files

/** The format a file name suggests, null for an unknown or missing extension. */
function formatFromName(name: string): SourceFormat | null {
  const file = name.split(/[\\/]/).pop() ?? name;
  const dot = file.lastIndexOf(".");
  if (dot < 0) return null;
  switch (file.slice(dot + 1).toLowerCase()) {
    case "xlsx":
    case "xlsm":
    case "xltx":
    case "xltm":
      return "xlsx";
    case "xls":
      return "xls";
    case "ods":
      return "ods";
    case "csv":
    case "tsv":
    case "txt":
      return "csv";
    default:
      return null;
  }
}

const BINARY_MAGICS: readonly (readonly number[])[] = [
  [0x25, 0x50, 0x44, 0x46, 0x2d],
  [0x89, 0x50, 0x4e, 0x47],
  [0xff, 0xd8, 0xff],
  [0x1f, 0x8b],
  [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c],
];
const MARKUP = ["<?xml", "<html", "<!doctype", "<table"];

/** Refuses content that is not text: NUL bytes early on, well-known binary formats, markup. */
function checkText(bytes: Uint8Array): void {
  if (startsWith(bytes, [0xff, 0xfe]) || startsWith(bytes, [0xfe, 0xff])) return;
  const head = bytes.subarray(0, 8 * 1024);
  if (head.includes(0) || BINARY_MAGICS.some((magic) => startsWith(head, magic))) {
    throw new ReadError("unsupported", "the file is not a CSV file or a workbook");
  }
  const text = new TextDecoder("utf-8").decode(startsWith(head, [0xef, 0xbb, 0xbf]) ? head.subarray(3) : head);
  const start = text.trimStart().slice(0, 16).toLowerCase();
  if (MARKUP.some((m) => start.startsWith(m))) {
    throw new ReadError("unsupported", "the file is markup, not a CSV file or a workbook");
  }
}

/**
 * Reads one uploaded file. A workbook extension, or the magic number of a zip archive or an
 * OLE file, gives the canned workbook; anything else must be text and is read as CSV.
 */
export function readFile(name: string, bytes: Uint8Array): SourceFile {
  const format = formatFromName(name);
  if (format && format !== "csv") return { name, format, size: bytes.length, sheets: cannedWorkbook(), canned: true };
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04])) {
    return { name, format: "xlsx", size: bytes.length, sheets: cannedWorkbook(), canned: true };
  }
  if (startsWith(bytes, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) {
    return { name, format: "xls", size: bytes.length, sheets: cannedWorkbook(), canned: true };
  }
  checkText(bytes);
  return readCsv(name, bytes);
}
