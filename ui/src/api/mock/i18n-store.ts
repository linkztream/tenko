// The state of the language packs mock (API-21), after crates/tenko-api/src/i18n/service.rs: per
// language tag an active version and a candidate, each with its messages and its report. The
// HTTP side is routes-i18n.ts.
//
// What the mock simplifies: there is no key set of the running UI to check a pack against, so
// the report counts the units of the uploaded document itself (`total` is the number of
// units, `translated` the units with a usable target, `missing` the others) and has no
// `extra` or `stale` keys. The XLIFF is read with regular expressions, not an XML parser: the
// root element, `srcLang`, `trgLang`, `version`, the language-pack metadata and the units with
// their `<source>` and `<target>`. A target with an inline element is left out with a problem
// `i18n.pack.markup`.
//
// Life cycle (as on the server): an upload becomes the candidate of its language, a preview
// marks it previewed, an activation (only of a previewed candidate) makes it the active
// version. The built-in languages are `en` and `sv`; the rest of the tags exist while they have
// an active version or a candidate. Nothing is seeded: every reset starts without packs.
//
// `seedPack` and `announcePacks` are the helpers tests use.
import { messageKeys } from "../../i18n/generated/keys";
import type { components } from "../generated/schema";
import { AUDIT_SEED_IDS, principalNow, testDigest } from "./audit-store";
import { commit, db, onMockReset } from "./db";
import { Problem, fieldError } from "./reply";
import { iso } from "./util";

type S = components["schemas"];

export type PackInfo = S["PackInfo"];
export type PackList = S["PackList"];
export type PackVersion = S["PackVersion"];
export type PackReport = S["PackReport"];
export type PackProblem = S["PackProblem"];
export type PackMessages = S["PackMessages"];
export type LanguageList = S["LanguageList"];
export type PackPrincipal = S["Principal"];

/** The largest pack the server accepts (2 MiB). */
export const MAX_PACK_BYTES = 8 * 1024 * 1024;
/** The longest display name of a pack, in characters. */
const MAX_NAME_CHARS = 64;

/** The tables an `i18n.*` event names, which the UI reloads its languages on. */
export const PACK_TABLES: readonly string[] = ["i18n.packs", "i18n.pack_slots"];

/** The `settings` singleton the audit records of the packs refer to. */
export const PACK_OBJECT = { kind: "settings", id: AUDIT_SEED_IDS.settings } as const;

/** The languages the UI has built in, source language first. */
export const BUILT_IN_LANGUAGES: readonly { tag: string; name: string }[] = [
  { tag: "en", name: "English" },
  { tag: "sv", name: "Svenska" },
];

/** A few messages of the built-in documents, the content of the mock's templates. */
const SAMPLE_MESSAGES: readonly { key: string; en: string; sv: string }[] = [
  { key: "common.action.cancel", en: "Cancel", sv: "Avbryt" },
  { key: "common.action.save", en: "Save", sv: "Spara" },
  { key: "common.action.close", en: "Close", sv: "Stäng" },
];

// ---------------------------------------------------------------------------------
// State

/** One version of a pack: what the API shows of it, its messages and its report. */
export interface StoredVersion {
  version: PackVersion;
  /** The usable translations by key. */
  messages: Record<string, string>;
  /** The English text of each unit, when the document had one. */
  sources: Record<string, string>;
  report: PackReport;
}

export interface Slots {
  active: StoredVersion | null;
  candidate: StoredVersion | null;
}

const state = { slots: new Map<string, Slots>() };

export function isBuiltInTag(tag: string): boolean {
  return BUILT_IN_LANGUAGES.some((l) => l.tag === tag);
}

/** Whether a path segment is shaped like a language tag (`fr`, `pt-BR`, `ar-XB`). */
export function isLanguageTag(tag: string): boolean {
  return tag.length <= 64 && /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{1,8})*$/.test(tag);
}

export function slotsOf(tag: string): Slots {
  return state.slots.get(tag) ?? { active: null, candidate: null };
}

/** Stores the slots of a tag; a tag without versions is forgotten. */
function setSlots(tag: string, slots: Slots): void {
  if (slots.active === null && slots.candidate === null) state.slots.delete(tag);
  else state.slots.set(tag, slots);
}

function statusOf(slots: Slots): PackInfo["status"] {
  if (slots.active) return "active";
  if (slots.candidate) return slots.candidate.version.previewed_at ? "previewed" : "uploaded";
  return "built_in";
}

/** A language with its versions, as `GET /i18n/packs` lists it. */
export function packInfo(tag: string): PackInfo {
  const slots = slotsOf(tag);
  const builtIn = BUILT_IN_LANGUAGES.find((l) => l.tag === tag);
  const info: PackInfo = {
    tag,
    name: slots.active?.version.display_name ?? slots.candidate?.version.display_name ?? builtIn?.name ?? tag,
    built_in: builtIn !== undefined,
    status: statusOf(slots),
  };
  if (slots.active) info.active = { ...slots.active.version };
  if (slots.candidate) info.candidate = { ...slots.candidate.version };
  return info;
}

/** Every language with its versions: the built-in ones first, then the others by tag. */
export function packList(): PackList {
  const others = [...state.slots.keys()].filter((tag) => !isBuiltInTag(tag)).sort();
  return {
    packs: [...BUILT_IN_LANGUAGES.map((l) => l.tag), ...others].map(packInfo),
    keys: messageKeys.length,
  };
}

/** The languages everyone may choose (`GET /i18n/languages`). */
export function languageList(): LanguageList {
  const languages: LanguageList["languages"] = [];
  for (const pack of packList().packs) {
    if (!pack.built_in && !pack.active) continue;
    const info: LanguageList["languages"][number] = { tag: pack.tag, name: pack.name, built_in: pack.built_in };
    if (pack.active) info.hash = pack.active.hash;
    languages.push(info);
  }
  return { languages, default_language: db.installation.language };
}

/** The messages of the active version (`candidate` false) or of the candidate; null without one. */
export function messagesOf(tag: string, candidate: boolean): PackMessages | null {
  const slots = slotsOf(tag);
  const stored = candidate ? slots.candidate : slots.active;
  if (!stored) return null;
  return { tag, hash: stored.version.hash, messages: { ...stored.messages } };
}

/** The report of the candidate, else of the active version; null when nothing is uploaded. */
export function reportOf(tag: string): PackReport | null {
  const slots = slotsOf(tag);
  const stored = slots.candidate ?? slots.active;
  return stored ? structuredClone(stored.report) : null;
}

// ---------------------------------------------------------------------------------
// Reading a document

/** What is read from a document that is a usable pack. */
interface Parsed {
  tag: string;
  displayName: string;
  author: string;
  version: string;
  messages: Record<string, string>;
  sources: Record<string, string>;
  total: number;
  missing: string[];
  problems: PackProblem[];
}

/** A document that is no usable pack: the first code, the tag when the document names one, and the problems. */
export interface Refusal {
  code: string;
  tag: string | null;
  problems: PackProblem[];
}

function problem(severity: PackProblem["severity"], code: string, detail: string, key?: string, line?: number): PackProblem {
  const out: PackProblem = { severity, code, detail };
  if (key !== undefined) out.key = key;
  if (line !== undefined) out.line = line;
  return out;
}

function refuse(code: string, detail: string, tag: string | null = null): Refusal {
  return { code, tag, problems: [problem("error", code, detail)] };
}

/** Decodes the five predefined entities and numeric character references. */
export function decodeEntities(text: string): string {
  return text.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-fA-F]+);/g, (whole, name: string) => {
    switch (name) {
      case "lt":
        return "<";
      case "gt":
        return ">";
      case "amp":
        return "&";
      case "quot":
        return '"';
      case "apos":
        return "'";
      default: {
        const code = name.startsWith("#x") ? Number.parseInt(name.slice(2), 16) : Number.parseInt(name.slice(1), 10);
        return Number.isInteger(code) && code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
      }
    }
  });
}

function attributes(source: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const match of source.matchAll(/([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) {
    const name = match[1];
    if (name !== undefined) out[name] = decodeEntities(match[2] ?? match[3] ?? "");
  }
  return out;
}

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let at = text.indexOf("\n"); at !== -1 && at < index; at = text.indexOf("\n", at + 1)) line += 1;
  return line;
}

function metaValue(text: string, type: string): string {
  const match = new RegExp(`<(?:[\\w.-]+:)?meta\\b[^>]*\\btype\\s*=\\s*["']${type}["'][^>]*>([\\s\\S]*?)</(?:[\\w.-]+:)?meta>`).exec(text);
  return decodeEntities((match?.[1] ?? "").trim());
}

/** Reads a pack: a `Refusal` when the document is not usable at all, else the units and the problems. */
export function parsePack(raw: string): Parsed | Refusal {
  const text = raw.replace(/^\uFEFF/, "");
  if (/<!DOCTYPE/i.test(text)) return refuse("i18n.pack.xml", "the document has a DOCTYPE");
  const root = /^\s*(?:<\?xml[\s\S]*?\?>\s*)?(?:<!--[\s\S]*?-->\s*)*<([A-Za-z_][\w.:-]*)([^>]*)>/.exec(text);
  if (!root) return refuse("i18n.pack.xml", "the document is not well-formed XML");
  const rootName = (root[1] ?? "").split(":").pop();
  if (rootName !== "xliff") return refuse("i18n.pack.root", `the root element is ${root[1]}, not xliff`);
  const attrs = attributes(root[2] ?? "");
  if (attrs["version"] !== "2.0") {
    return refuse("i18n.pack.version", `the XLIFF version is ${attrs["version"] ?? "missing"}, not 2.0`, attrs["trgLang"] ?? null);
  }

  // The checks of the document as a whole report every problem they find.
  const tag = attrs["trgLang"] ?? null;
  const documentProblems: PackProblem[] = [];
  if (attrs["srcLang"] !== "en") {
    documentProblems.push(problem("error", "i18n.pack.src_lang", `srcLang is ${attrs["srcLang"] ?? "missing"}, a pack translates from en`));
  }
  if (tag === null) {
    documentProblems.push(problem("error", "i18n.pack.trg_lang", "the trgLang attribute is missing: it names the language of the pack"));
  } else if (!isLanguageTag(tag)) {
    documentProblems.push(problem("error", "i18n.pack.tag", `trgLang ${JSON.stringify(tag)} is not a valid language tag`));
  }
  const displayName = metaValue(text, "displayName");
  if (displayName === "") {
    documentProblems.push(problem("error", "i18n.pack.metadata", 'the pack has no displayName (mda:meta type="displayName")'));
  } else if (Array.from(displayName).length > MAX_NAME_CHARS || /\p{Cc}/u.test(displayName)) {
    documentProblems.push(
      problem("error", "i18n.pack.metadata", `the displayName has more than ${MAX_NAME_CHARS} characters or control characters`),
    );
  }
  const first = documentProblems[0];
  if (first) return { code: first.code, tag, problems: documentProblems };

  const author = metaValue(text, "author");
  const version = metaValue(text, "version");
  const problems: PackProblem[] = [];
  if (author === "" || version === "") {
    problems.push(problem("warning", "i18n.pack.metadata", "the pack has no author or no version in its metadata"));
  }

  const messages: Record<string, string> = {};
  const sources: Record<string, string> = {};
  const missing: string[] = [];
  const seen = new Set<string>();
  let total = 0;
  for (const match of text.matchAll(/<unit\b([^>]*?)(?:\/>|>([\s\S]*?)<\/unit>)/g)) {
    const line = lineOf(text, match.index ?? 0);
    const id = attributes(match[1] ?? "")["id"] ?? "";
    if (id === "") {
      problems.push(problem("error", "i18n.pack.structure", "a <unit> has no id", undefined, line));
      continue;
    }
    if (seen.has(id)) {
      problems.push(problem("error", "i18n.pack.duplicate", "the unit id appears more than once; the first one is used", id, line));
      continue;
    }
    seen.add(id);
    total += 1;
    const body = match[2] ?? "";
    const source = /<source\b[^>]*>([\s\S]*?)<\/source>/.exec(body);
    if (source) sources[id] = decodeEntities(source[1] ?? "");
    const target = /<target\b[^>]*?(?:\/>|>([\s\S]*?)<\/target>)/.exec(body);
    const inner = target?.[1] ?? "";
    if (inner === "") {
      missing.push(id);
    } else if (/<[A-Za-z/]/.test(inner)) {
      // An inline element is markup, and a translation is text.
      problems.push(problem("error", "i18n.pack.markup", "the target contains an inline element; a translation is text", id, line));
      missing.push(id);
    } else {
      messages[id] = decodeEntities(inner);
    }
  }

  if (Object.keys(messages).length === 0) {
    const errors = problems.filter((p) => p.severity === "error");
    return {
      code: "i18n.pack.empty",
      tag,
      problems: [problem("error", "i18n.pack.empty", "the pack translates no message of the running user interface"), ...errors],
    };
  }
  // Errors first, as the server's report lists them.
  problems.sort((a, b) => Number(a.severity === "warning") - Number(b.severity === "warning"));
  return { tag: tag ?? "", displayName, author, version, messages, sources, total, missing, problems };
}

export function isRefusal(parsed: Parsed | Refusal): parsed is Refusal {
  return "problems" in parsed && "code" in parsed;
}

/** The 422 `i18n.pack.invalid` problem of a refusal, with one `errors` entry per problem. */
export function refusalProblem(refusal: Refusal): Problem {
  const errors = refusal.problems
    .filter((p) => p.severity === "error")
    .map((p) => {
      const params: Record<string, string> = { detail: p.detail };
      if (p.line !== undefined) params["line"] = String(p.line);
      return fieldError(p.key ?? "file", p.code, params);
    });
  const params: Record<string, string> = { reason: refusal.code };
  if (refusal.tag) params["tag"] = refusal.tag;
  return new Problem("i18n.pack.invalid", {
    status: 422,
    detail: `the language pack is refused: ${refusal.problems[0]?.detail ?? refusal.code}`,
    params,
    errors,
  });
}

// ---------------------------------------------------------------------------------
// Versions

/** A stable string derived from the messages (any order of the members gives the same one). */
export function messagesHash(messages: Readonly<Record<string, string>>): string {
  const sorted = Object.keys(messages)
    .sort()
    .map((key) => [key, messages[key]]);
  return testDigest(JSON.stringify(sorted));
}

function percentOf(translated: number, total: number): number {
  return total === 0 ? 100 : Math.floor((translated * 100) / total);
}

interface NewVersion {
  /** The id: a digest of the document. */
  id: string;
  tag: string;
  displayName: string;
  author: string;
  version: string;
  messages: Record<string, string>;
  sources: Record<string, string>;
  total: number;
  missing: string[];
  problems: PackProblem[];
  uploadedBy: PackPrincipal;
  origin?: PackVersion["origin"];
}

function newVersion(input: NewVersion): StoredVersion {
  const translated = Object.keys(input.messages).length;
  const percent = percentOf(translated, input.total);
  const version: PackVersion = {
    id: input.id,
    hash: messagesHash(input.messages),
    display_name: input.displayName,
    author: input.author,
    version: input.version,
    translated,
    total: input.total,
    percent,
    origin: input.origin ?? "upload",
    uploaded_at: iso(Date.now()),
    uploaded_by: input.uploadedBy,
  };
  const report: PackReport = {
    tag: input.tag,
    display_name: input.displayName,
    author: input.author,
    version: input.version,
    total: input.total,
    translated,
    percent,
    missing: [...input.missing],
    extra: [],
    stale: [],
    problems: input.problems.map((p) => ({ ...p })),
  };
  return { version, messages: { ...input.messages }, sources: { ...input.sources }, report };
}

export interface UploadResult {
  pack: PackInfo;
  report: PackReport;
  /** False when the document was the active version or the candidate already: nothing changed. */
  changed: boolean;
}

/** Makes a document the candidate of its language (a refused one throws the 422 problem). */
export function storeUpload(document: string): UploadResult {
  const parsed = parsePack(document);
  if (isRefusal(parsed)) throw refusalProblem(parsed);
  const id = testDigest(document);
  const slots = slotsOf(parsed.tag);
  const known = [slots.active, slots.candidate].find((s) => s?.version.id === id);
  if (known) return { pack: packInfo(parsed.tag), report: structuredClone(known.report), changed: false };
  const stored = newVersion({ ...parsed, id, uploadedBy: principalNow() });
  setSlots(parsed.tag, { active: slots.active, candidate: stored });
  return { pack: packInfo(parsed.tag), report: structuredClone(stored.report), changed: true };
}

/** Marks the candidate previewed by the signed-in user; null without a candidate. */
export function markPreviewed(tag: string): PackInfo | null {
  const slots = slotsOf(tag);
  if (!slots.candidate) return null;
  const candidate = slots.candidate;
  if (!candidate.version.previewed_at) {
    candidate.version.previewed_at = iso(Date.now());
    candidate.version.previewed_by = principalNow();
  }
  setSlots(tag, slots);
  return packInfo(tag);
}

/** Result of an activation: the language, the id of the version that was replaced. */
export type Activation = { pack: PackInfo; version: string; previous: string | null } | "no_candidate" | "not_previewed";

export function activateCandidate(tag: string): Activation {
  const slots = slotsOf(tag);
  if (!slots.candidate) return "no_candidate";
  if (!slots.candidate.version.previewed_at) return "not_previewed";
  const previous = slots.active?.version.id ?? null;
  const version = slots.candidate.version.id;
  setSlots(tag, { active: slots.candidate, candidate: null });
  return { pack: packInfo(tag), version, previous };
}

/** Drops the candidate; null without one. */
export function dropCandidate(tag: string): { pack: PackInfo; version: string } | null {
  const slots = slotsOf(tag);
  if (!slots.candidate) return null;
  const version = slots.candidate.version.id;
  setSlots(tag, { active: slots.active, candidate: null });
  return { pack: packInfo(tag), version };
}

/** Removes everything uploaded for a tag; the ids of the versions that went. */
export function dropAll(tag: string): { active: string | null; candidate: string | null } {
  const slots = slotsOf(tag);
  setSlots(tag, { active: null, candidate: null });
  return { active: slots.active?.version.id ?? null, candidate: slots.candidate?.version.id ?? null };
}

// ---------------------------------------------------------------------------------
// The template

function xml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/**
 * The XLIFF 2.0 template of a language, built from the mock's own data: the units of its
 * candidate, else of its active version, else a few built-in messages. Well formed, nothing more.
 */
export function templateFor(tag: string): string {
  const slots = slotsOf(tag);
  const stored = slots.candidate ?? slots.active;
  let name = BUILT_IN_LANGUAGES.find((l) => l.tag === tag)?.name ?? tag;
  let author = "Tenko DDI";
  let version = "0.1.0";
  let units: { key: string; source: string; target: string | undefined }[];
  if (stored) {
    name = stored.version.display_name;
    author = stored.version.author ?? author;
    version = stored.version.version ?? version;
    units = Object.keys({ ...stored.sources, ...stored.messages })
      .sort()
      .map((key) => ({ key, source: stored.sources[key] ?? "", target: stored.messages[key] }));
  } else {
    units = SAMPLE_MESSAGES.map((m) => ({
      key: m.key,
      source: m.en,
      target: tag === "en" ? m.en : tag === "sv" ? m.sv : undefined,
    }));
  }
  const rows = units.map(
    (u) =>
      `    <unit id="${xml(u.key)}">\n      <segment><source>${xml(u.source)}</source>${
        u.target === undefined ? "" : `<target>${xml(u.target)}</target>`
      }</segment>\n    </unit>`,
  );
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<xliff xmlns="urn:oasis:names:tc:xliff:document:2.0" xmlns:mda="urn:oasis:names:tc:xliff:metadata:2.0" version="2.0" srcLang="en" trgLang="${xml(tag)}">`,
    '  <file id="tenko-ui">',
    "    <mda:metadata>",
    '      <mda:metaGroup category="language-pack">',
    `        <mda:meta type="displayName">${xml(name)}</mda:meta>`,
    `        <mda:meta type="author">${xml(author)}</mda:meta>`,
    `        <mda:meta type="version">${xml(version)}</mda:meta>`,
    '        <mda:meta type="sourceLanguage">en</mda:meta>',
    "      </mda:metaGroup>",
    "    </mda:metadata>",
    ...rows,
    "  </file>",
    "</xliff>",
    "",
  ].join("\n");
}

// ---------------------------------------------------------------------------------
// Helpers for tests

export interface SeedPackInput {
  tag: string;
  /** The language's name in itself; the tag by default. */
  name?: string;
  /** The usable translations by key. */
  messages: Record<string, string>;
  /** Default `active`. */
  state?: "active" | "candidate" | "previewed";
  author?: string;
  version?: string;
  /** The units of the document; the translated ones by default. */
  total?: number;
}

/**
 * Puts a version straight into the state, replacing the slot it goes to: no validation, no
 * event, no audit record (`announcePacks` tells the open clients). Returns the language.
 */
export function seedPack(input: SeedPackInput): PackInfo {
  const keys = Object.keys(input.messages);
  const total = Math.max(input.total ?? keys.length, keys.length);
  const stored = newVersion({
    id: testDigest(`seed|${input.tag}|${JSON.stringify(input.messages)}|${Date.now()}`),
    tag: input.tag,
    displayName: input.name ?? input.tag,
    author: input.author ?? "Example Translators",
    version: input.version ?? "1.0.0",
    messages: input.messages,
    sources: {},
    total,
    missing: Array.from({ length: total - keys.length }, (_, i) => `seed.missing.key${i + 1}`),
    problems: [],
    uploadedBy: principalNow(),
  });
  const kind = input.state ?? "active";
  if (kind === "previewed") {
    stored.version.previewed_at = iso(Date.now());
    stored.version.previewed_by = principalNow();
  }
  const slots = slotsOf(input.tag);
  setSlots(input.tag, kind === "active" ? { active: stored, candidate: slots.candidate } : { active: slots.active, candidate: stored });
  return packInfo(input.tag);
}

/** Raises the `system` event of a change to the packs, as every write of the routes does. */
export function announcePacks(): void {
  commit("system", { objects: [PACK_OBJECT], tables: [...PACK_TABLES] });
}

// ---------------------------------------------------------------------------------
// Reset

onMockReset(() => {
  state.slots = new Map();
});
