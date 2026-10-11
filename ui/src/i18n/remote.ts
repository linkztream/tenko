// Language packs uploaded to the server (API-21): the languages that are not built in, and
// the uploaded overrides of the built-in ones. GET /i18n/languages (public, the sign-in page
// needs it) names every language with the content hash of its active pack; each such pack is
// registered with the runtime (index.ts) and fetched only when the UI switches to it, as ICU
// text that the full message parser reads. The parser is loaded with the first pack, so users
// of the built-in languages never download it. A key a pack lacks falls back to the built-in
// language of the same tag, then to English; every message renders as text.
//
// The list is read again when an `i18n.*` table changes (topic `system`): an activation, a
// revert or a removal reaches every open client without a reload.
//
// A preview shows an administrator the uploaded candidate of a language before it is activated,
// in this browser tab only (sessionStorage): the candidate is registered under its tag and the
// UI is forced into it until the preview ends (forceLocale). A bar, loaded only then, says so.
import { createSignal } from "solid-js";
import { api } from "../api/client";
import { events, type ApiEvent } from "../api/events";
import { forceLocale, registerLanguage, unregisterLanguage, type IcuParse, type RuntimeTable } from ".";

const PREVIEW_KEY = "tenko-i18n-preview";
/** How long the first page load waits for the language list before it goes on without. */
const LIST_TIMEOUT_MS = 3000;

/** A language the UI previews: the candidate of `tag`. */
export interface Preview {
  readonly tag: string;
  readonly name: string;
}

let parser: Promise<IcuParse> | undefined;

/** The ICU message parser, loaded on first use (markup in a message is text). */
export function icuParser(): Promise<IcuParse> {
  parser ??= import("virtual:tenko-i18n/parser").then((m) => m.parse);
  return parser;
}

async function sourceTable(messages: Readonly<Record<string, string>>): Promise<RuntimeTable> {
  return { kind: "source", messages, parse: await icuParser() };
}

/** The content hash of the active pack registered per tag. */
const registered = new Map<string, string>();
const [preview, setPreview] = createSignal<Preview | undefined>();
let watching = false;
let timer: ReturnType<typeof setTimeout> | undefined;

function storedPreview(): Preview | undefined {
  try {
    const value: unknown = JSON.parse(sessionStorage.getItem(PREVIEW_KEY) ?? "null");
    if (value && typeof value === "object" && "tag" in value && "name" in value) {
      const { tag, name } = value as Record<string, unknown>;
      if (typeof tag === "string" && typeof name === "string") return { tag, name };
    }
  } catch {
    // No storage, or nothing usable in it.
  }
  return undefined;
}

function storePreview(value: Preview | undefined): void {
  try {
    if (value) sessionStorage.setItem(PREVIEW_KEY, JSON.stringify(value));
    else sessionStorage.removeItem(PREVIEW_KEY);
  } catch {
    // Storage unavailable: the preview lasts for this page only.
  }
}

/** The preview in progress in this tab, if any. Reactive. */
export { preview as currentPreview };

/** Whether an event of topic `system` changed the language packs (an `i18n.*` table). */
export function isPackEvent(event: ApiEvent): boolean {
  const tables = event.data["tables"];
  return Array.isArray(tables) && tables.some((table) => typeof table === "string" && table.startsWith("i18n."));
}

function watch(): void {
  if (watching) return;
  watching = true;
  const later = () => {
    clearTimeout(timer);
    timer = setTimeout(() => void loadLanguages(), 250);
  };
  events.subscribe("system", (event) => {
    if (isPackEvent(event)) later();
  });
  events.onReset("system", later);
}

/**
 * Reads the languages of the server and registers their active packs; a pack that is no
 * longer active is unregistered. Called once before the first render (index.tsx) and again on
 * every change of the packs. A server that cannot be reached leaves the built-in languages.
 */
export async function loadLanguages(): Promise<void> {
  watch();
  let languages;
  try {
    const signal = typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(LIST_TIMEOUT_MS) : undefined;
    languages = (await api.get("/api/v1/i18n/languages", { signal })).languages;
  } catch {
    return;
  }
  const seen = new Set<string>();
  for (const { tag, name, hash } of languages) {
    if (!hash) continue;
    seen.add(tag);
    if (registered.get(tag) === hash) continue;
    registered.set(tag, hash);
    // The candidate stays registered under its tag while it is previewed.
    if (preview()?.tag === tag) continue;
    await registerLanguage({
      code: tag,
      name,
      load: async () => sourceTable((await api.get("/api/v1/i18n/packs/{tag}", { path: { tag }, query: { hash } })).messages),
    });
  }
  for (const tag of [...registered.keys()]) {
    if (seen.has(tag)) continue;
    registered.delete(tag);
    if (preview()?.tag !== tag) await unregisterLanguage(tag);
  }
  const stored = preview() ? undefined : storedPreview();
  if (stored) {
    try {
      await startPreview(stored);
    } catch {
      // The candidate is gone or this browser is no longer an administrator's.
      storePreview(undefined);
    }
  }
}

/**
 * Starts a preview of the candidate of a language in this tab: its messages are fetched (an
 * administrator's request), registered under the tag and forced on the UI.
 */
export async function startPreview(next: Preview): Promise<void> {
  const { tag } = next;
  const table = await sourceTable((await api.get("/api/v1/i18n/packs/{tag}/candidate", { path: { tag } })).messages);
  const before = preview();
  if (before && before.tag !== tag) await dropPreview(before.tag);
  setPreview(next);
  storePreview(next);
  await registerLanguage({ code: tag, name: next.name, load: async () => table });
  await forceLocale(tag);
  void import("./PreviewBar").then((m) => m.showPreviewBar());
}

async function dropPreview(tag: string): Promise<void> {
  await unregisterLanguage(tag);
  // The active pack of the tag, if any, is registered again by the next read of the list.
  registered.delete(tag);
}

/** Tests: forgets every registered pack and the preview, and returns the UI to English. */
export async function resetLanguagesForTest(): Promise<void> {
  const tags = [...registered.keys()];
  const previewed = preview()?.tag;
  registered.clear();
  setPreview(undefined);
  storePreview(undefined);
  clearTimeout(timer);
  for (const tag of previewed ? [...tags, previewed] : tags) await unregisterLanguage(tag);
  await forceLocale(undefined);
}

/** Ends the preview of this tab: the UI returns to the language it would have shown. */
export async function endPreview(): Promise<void> {
  const ended = preview();
  setPreview(undefined);
  storePreview(undefined);
  if (ended) await dropPreview(ended.tag);
  await loadLanguages();
  await forceLocale(undefined);
}
