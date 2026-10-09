// Helpers of the import scenario (WP1.11, scenario 4): the fixture workbook and its expected
// outcome, a session strong enough to store credentials, an upload through the API, paged
// reads of the lists, and a small CSV reader for the exports.

import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { Api, Schemas } from "./api";

const FIXTURES = resolve(import.meta.dirname, "..", "..", "..", "crates", "tenko-ipam", "tests", "fixtures");

/** The absolute path of a file in `crates/tenko-ipam/tests/fixtures`. */
export function fixturePath(name: string): string {
  return resolve(FIXTURES, name);
}

interface Origin {
  sheet: string | null;
  row: number | null;
  column: string | null;
}

export interface ExpectedColumn {
  column: string;
  target: string;
  interface?: string;
}

export interface ExpectedSheetMapping {
  sheet: string;
  kind: string;
  cidr?: string;
  header_row?: number;
  columns: ExpectedColumn[];
}

export interface ExpectedSheetCounts {
  sheet: string;
  kind: string;
  cidr?: string;
  rows: number;
  free: number;
  imported: number;
  skipped: number;
}

/** `ip-plan.expected.json`: what importing `ip-plan.xlsx` must produce. */
export interface Expected {
  loss: { entries: Array<{ code: string; detail: string; location: Origin }> };
  mapping: { options: { conflict: string; credentials: string }; sheets: ExpectedSheetMapping[] };
  model: {
    prefixes: Array<{ cidr: string }>;
    hosts: Array<{ name: string; interfaces?: Array<{ name: string }> }>;
    addresses: Array<{ ip: string; host: string; interface: string }>;
    credentials: Array<{ host: string; login: boolean; password: boolean }>;
    vlans: unknown[];
  };
  proposals: Array<{ accepted: boolean; addresses: string[]; cidr: string; origin: Origin }>;
  sheets: ExpectedSheetCounts[];
}

export function loadExpected(): Expected {
  return JSON.parse(readFileSync(fixturePath("ip-plan.expected.json"), "utf8")) as Expected;
}

/**
 * Raises the session of the browser context from a PIN to password plus one-time code:
 * credential columns are stored as operator secrets, which needs a session of password
 * strength or more (IAM-07). The cookie is shared with the page, so navigate afterwards.
 */
export async function raiseSession(api: Api): Promise<Schemas["SessionInfo"]> {
  const { authenticator } = await api.enrolTotp();
  await api.logout();
  return api.signIn(authenticator);
}

/** Uploads a fixture through the API (the arrangement of a scenario that starts later). */
export async function uploadFixture(api: Api, name: string): Promise<Schemas["ImportView"]> {
  const response = await api.request.post(`${api.origin}/api/v1/imports`, {
    // An upload carries no Idempotency-Key: the server buffers keyed requests under a smaller limit.
    headers: { Origin: api.origin },
    multipart: { files: { name, mimeType: "application/octet-stream", buffer: await readFile(fixturePath(name)) } },
  });
  if (!response.ok()) throw new Error(`upload of ${name}: HTTP ${response.status()} ${await response.text()}`);
  return (await response.json()) as Schemas["ImportView"];
}

interface PageOf<T> {
  items: T[];
  next_cursor?: string | null;
}

/** Every item of a paged list, followed through `next_cursor`. */
export async function listAll<T>(api: Api, path: string, query: Record<string, string | number | boolean> = {}): Promise<T[]> {
  const items: T[] = [];
  let cursor: string | null | undefined;
  do {
    const page = await api.get<PageOf<T>>(path, { limit: 100, ...query, ...(cursor ? { cursor } : {}) });
    items.push(...page.items);
    cursor = page.next_cursor;
  } while (cursor);
  return items;
}

/** The records of a CSV text (RFC 4180: quoted fields may hold separators and line breaks). */
export function parseCsv(text: string): string[][] {
  const records: string[][] = [];
  let record: string[] = [];
  let field = "";
  let quoted = false;
  let started = false;
  for (let at = 0; at < text.length; at += 1) {
    const char = text.charAt(at);
    if (quoted) {
      if (char === '"' && text.charAt(at + 1) === '"') {
        field += '"';
        at += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
    } else if (char === '"') {
      quoted = true;
      started = true;
    } else if (char === ",") {
      record.push(field);
      field = "";
      started = true;
    } else if (char === "\n" || char === "\r") {
      if (char === "\r" && text.charAt(at + 1) === "\n") at += 1;
      if (started || field !== "") {
        record.push(field);
        records.push(record);
      }
      record = [];
      field = "";
      started = false;
    } else {
      field += char;
      started = true;
    }
  }
  if (started || field !== "") {
    record.push(field);
    records.push(record);
  }
  return records;
}
