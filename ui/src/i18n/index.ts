// The runtime half of the language packs (API-21). The built-in languages come from
// ui/i18n/*.xlf, compiled at build time into tables of plain strings and pre-parsed ICU
// syntax trees (scripts/vite-plugin-i18n.mjs), so the browser parses no message syntax for
// them. A language that is not built in (an uploaded pack, or a test locale) is registered at
// run time with registerLanguage(); its messages are looked up before the built-in ones of the
// same language, and a key it lacks falls back to the built-in language, then to English.
//
// The document's `lang` and `dir` follow the UI language (direction.ts).
//
// Use `t(key, args)` for text and attributes, `tx(key, values)` when a placeholder must
// be an element, and the `format*` helpers for numbers, dates and lists. All of them read
// the current locale, so anything rendered through them follows a language switch.
//
// Language resolution (API-08): the language fixed on the user's account, else a choice
// made on this browser before sign-in, else the first browser language that is built in,
// else the installation default, else English.
import { IntlMessageFormat } from "intl-messageformat";
import { createSignal, type JSX } from "solid-js";
import en from "virtual:tenko-i18n/en";
import { loaders, locales, packs, sourceLocale } from "virtual:tenko-i18n/meta";
import { textDirection, type TextDirection } from "./direction";
import type { MessageArgs, MessageKey } from "./generated/keys";
import "./bidi.css";

export { textDirection, type TextDirection } from "./direction";
export type { MessageArgs, MessageKey } from "./generated/keys";
export type MessageTable = Readonly<Record<string, string | readonly unknown[]>>;

/** Arguments of `t(key, ...)`: required for keys that take arguments, absent otherwise. */
export type ArgsOf<K extends MessageKey> = K extends keyof MessageArgs ? [args: MessageArgs[K]] : [];

const STORED_KEY = "tenko-lang";

type MutableTable = Record<string, string | readonly unknown[]>;

/** The source table: the core messages plus every message pack loaded so far. */
const source: MutableTable = { ...en };
const tables = new Map<string, MutableTable>([[sourceLocale, source]]);
const [locale, setLocaleSignal] = createSignal<string>(sourceLocale);
/** Message packs loaded so far (see loadPacks). */
const loadedPacks = new Set<string>();
/**
 * Counts pack arrivals, so a text read before its pack arrived (a route title, say) is
 * read again once it is there.
 */
const [packRevision, setPackRevision] = createSignal(0);

/** The current UI language (BCP 47). */
export { locale };

/** The writing direction of the current UI language. */
export function direction(): TextDirection {
  return textDirection(locale());
}

/** A language the UI offers: built in, or registered at run time. */
export interface Language {
  /** BCP 47 tag. */
  readonly code: string;
  /** The language's own name. */
  readonly name: string;
}

/** Parses ICU message text into the syntax tree that intl-messageformat formats. */
export type IcuParse = (message: string) => readonly unknown[];

/**
 * The messages of a language registered at run time. A `compiled` table holds what the build
 * produces for the built-in languages (literal text, or an ICU syntax tree); a `source` table
 * holds ICU message text, parsed on first use with `parse` (whoever registers the language
 * loads the parser lazily, so the first page load does not carry it).
 */
export type RuntimeTable =
  | { readonly kind: "compiled"; readonly messages: MessageTable }
  | { readonly kind: "source"; readonly messages: Readonly<Record<string, string>>; readonly parse: IcuParse };

/** A language registered at run time, with the loader of its messages. */
export interface RuntimeLanguage extends Language {
  readonly load: () => Promise<RuntimeTable>;
}

/** Languages registered at run time, in registration order. */
const [registered, setRegistered] = createSignal<readonly RuntimeLanguage[]>([]);
/** The loaded messages of registered languages, by code. */
const runtime = new Map<string, { kind: "compiled" | "source"; messages: MutableTable; parse?: IcuParse }>();

/**
 * Registers a language that is not compiled in, or replaces the registration of the same code
 * (a new version of a pack). A registration with the code of a built-in language overrides its
 * messages key by key. When the language is the current one, its messages are loaded again.
 */
export async function registerLanguage(language: RuntimeLanguage): Promise<void> {
  setRegistered((list) => [...list.filter((l) => l.code !== language.code), language]);
  runtime.delete(language.code);
  forget(language.code);
  if (locale() === language.code) await setLocale(language.code);
}

/** Removes a registered language; the UI falls back to the built-in one or to English. */
export async function unregisterLanguage(code: string): Promise<void> {
  if (!registered().some((l) => l.code === code)) return;
  setRegistered((list) => list.filter((l) => l.code !== code));
  runtime.delete(code);
  forget(code);
  if (locale() === code) await setLocale(code);
}

/** The built-in languages, source language first, then the registered ones. */
export function availableLocales(): readonly Language[] {
  const more = registered().filter((l) => !isBuiltIn(l.code));
  return more.length === 0 ? locales : [...locales, ...more.map(({ code, name }) => ({ code, name }))];
}

export function isBuiltIn(code: string | null | undefined): code is string {
  return !!code && locales.some((l) => l.code === code);
}

/** Whether a language is built in or registered. */
export function isAvailable(code: string | null | undefined): code is string {
  return !!code && availableLocales().some((l) => l.code === code);
}

/** Matches a language tag against the available languages: exact tag, then primary subtag. */
export function matchLocale(tag: string | null | undefined): string | undefined {
  if (!tag) return undefined;
  const lower = tag.toLowerCase();
  const all = availableLocales();
  const exact = all.find((l) => l.code.toLowerCase() === lower);
  if (exact) return exact.code;
  const primary = lower.split("-")[0];
  return all.find((l) => l.code.toLowerCase().split("-")[0] === primary)?.code;
}

export interface LocaleInputs {
  /** The language fixed on the user's account. */
  user?: string | null | undefined;
  /** A language picked on this browser (sign-in page, wizard). */
  stored?: string | null | undefined;
  /** The browser's languages in order of preference. */
  browser?: readonly string[] | undefined;
  /** The installation default set by an administrator. */
  installation?: string | null | undefined;
}

/** Applies the resolution order of API-08 and returns an available language. */
export function resolveLocale(inputs: LocaleInputs): string {
  const first = matchLocale(inputs.user) ?? matchLocale(inputs.stored);
  if (first) return first;
  for (const tag of inputs.browser ?? []) {
    const m = matchLocale(tag);
    if (m) return m;
  }
  return matchLocale(inputs.installation) ?? sourceLocale;
}

/** The language picked on this browser before sign-in, if any. */
export function storedLocale(): string | null {
  try {
    return localStorage.getItem(STORED_KEY);
  } catch {
    return null;
  }
}

/** Remembers a language picked before sign-in (or forgets it with null). */
export function storeLocale(code: string | null): void {
  try {
    if (code) localStorage.setItem(STORED_KEY, code);
    else localStorage.removeItem(STORED_KEY);
  } catch {
    // Storage unavailable: the choice lasts for this page only.
  }
}

export function browserLocales(): readonly string[] {
  if (typeof navigator === "undefined") return [];
  return navigator.languages?.length ? navigator.languages : [navigator.language];
}

/**
 * Loads a language if needed and switches the UI to it. Unknown codes fall back to English,
 * and so does a registered language whose messages cannot be loaded (a registered override of
 * a built-in language falls back to the built-in messages).
 */
export async function setLocale(code: string): Promise<void> {
  let target = isAvailable(code) ? code : sourceLocale;
  const extra = registered().find((l) => l.code === target);
  if (extra && !runtime.has(target)) {
    try {
      const table = await extra.load();
      // A registration replaced while this one loaded wins; its own call loads it.
      if (registered().includes(extra)) {
        const messages: MutableTable = { ...table.messages };
        runtime.set(
          target,
          table.kind === "source" ? { kind: "source", messages, parse: table.parse } : { kind: "compiled", messages },
        );
      }
    } catch (err) {
      if (import.meta.env.DEV) console.warn(`i18n: cannot load the language ${target}`, err);
      if (!isBuiltIn(target)) target = sourceLocale;
    }
  }
  if (isBuiltIn(target) && !tables.has(target)) {
    const load = loaders[target];
    if (!load) return;
    const mod = await load();
    const table: MutableTable = { ...mod.default };
    // The packs in use (or on their way), in the new language too.
    await Promise.all(pending.values());
    await Promise.all([...loadedPacks].map((name) => mergePack(table, name, target)));
    tables.set(target, table);
  }
  setLocaleSignal(target);
  // Texts of the same language whose messages were replaced are read again.
  setPackRevision((n) => n + 1);
  if (typeof document !== "undefined") {
    document.documentElement.lang = target;
    document.documentElement.dir = textDirection(target);
  }
}

async function mergePack(table: MutableTable, name: string, code: string): Promise<void> {
  const load = packs[name]?.[code];
  if (!load) return;
  Object.assign(table, (await load()).default);
}

const pending = new Map<string, Promise<void>>();

/**
 * Loads message packs (the messages of lazily loaded areas, see scripts/vite-plugin-i18n.mjs)
 * in the source language and in every language loaded so far. Unknown names are ignored, so
 * a build without packs (tests) needs no special case.
 */
export function loadPacks(names: readonly string[]): Promise<void> {
  return Promise.all(
    names.map((name) => {
      if (loadedPacks.has(name) || !packs[name]) return Promise.resolve();
      let p = pending.get(name);
      if (!p) {
        p = Promise.all([...tables].map(([code, table]) => mergePack(table, name, code))).then(() => {
          loadedPacks.add(name);
          pending.delete(name);
          setPackRevision((n) => n + 1);
        });
        pending.set(name, p);
      }
      return p;
    }),
  ).then(() => undefined);
}

/**
 * Wraps the loader of a lazy route so its message packs arrive with its code:
 * `lazy(withPacks(["ipam"], () => import("./IpamView")))`.
 */
export function withPacks<T>(names: readonly string[], load: () => Promise<T>): () => Promise<T> {
  return () => Promise.all([loadPacks(names), load()]).then(([, mod]) => mod);
}

const formatters = new Map<string, IntlMessageFormat>();

/** Drops the formatters of a language whose messages changed. */
function forget(code: string): void {
  const prefix = `${code}\u0000`;
  for (const id of formatters.keys()) if (id.startsWith(prefix)) formatters.delete(id);
}

/** ICU text without arguments or quoting: the text is the message. */
const PLAIN = /^[^{}']*$/;

function lookup(code: string, key: string): { loc: string; msg: string | readonly unknown[] } | undefined {
  const extra = runtime.get(code);
  const own = extra?.messages[key];
  if (extra && own !== undefined) {
    if (extra.kind === "compiled" || typeof own !== "string" || PLAIN.test(own)) return { loc: code, msg: own };
    try {
      // Parsed once: the syntax tree replaces the text in the table.
      const ast = extra.parse?.(own);
      if (ast) {
        extra.messages[key] = ast;
        return { loc: code, msg: ast };
      }
    } catch (err) {
      if (import.meta.env.DEV) console.warn(`i18n: cannot parse ${key} in ${code}`, err);
    }
    // A message that cannot be parsed falls back like a missing one.
  }
  const builtIn = tables.get(code)?.[key];
  if (builtIn !== undefined) return { loc: code, msg: builtIn };
  const fallback = source[key];
  return fallback === undefined ? undefined : { loc: sourceLocale, msg: fallback };
}

/**
 * The English messages loaded so far (the core table and the message packs), for tools that
 * derive a language from them, such as the pseudo-locales of the tests (pseudo.ts).
 */
export function sourceMessages(): MessageTable {
  return source;
}

function compiled(loc: string, key: string, ast: readonly unknown[]): IntlMessageFormat {
  const id = `${loc}\u0000${key}`;
  let f = formatters.get(id);
  if (!f) {
    // The tables hold syntax trees produced by @formatjs/icu-messageformat-parser.
    f = new IntlMessageFormat(ast as never, loc, undefined, { ignoreTag: true });
    formatters.set(id, f);
  }
  return f;
}

function render(key: string, values: Record<string, unknown> | undefined): string | unknown[] {
  const code = locale();
  packRevision();
  const found = lookup(code, key);
  if (!found) return key;
  if (typeof found.msg === "string") return found.msg;
  try {
    return compiled(found.loc, key, found.msg).format(values as never) as string | unknown[];
  } catch (err) {
    if (import.meta.env.DEV) console.warn(`i18n: cannot format ${key}`, err);
    return key;
  }
}

/** The text of a message in the current language. Reactive: re-runs on a language switch. */
export function t<K extends MessageKey>(key: K, ...args: ArgsOf<K>): string {
  const out = render(key, args[0] as Record<string, unknown> | undefined);
  return typeof out === "string" ? out : out.map(String).join("");
}

/**
 * A message whose placeholders may be elements, for example a bold name or a link inside
 * a sentence. Returns text and nodes for JSX; the message text itself never becomes markup.
 */
export function tx(key: MessageKey, values: Record<string, JSX.Element | string | number | Date>): JSX.Element {
  return render(key, values) as JSX.Element;
}

/** Whether a key exists (for keys built at run time, such as error codes). */
export function hasMessage(key: string): key is MessageKey {
  packRevision();
  return source[key] !== undefined;
}

/** A message for a key built at run time; `undefined` when the key does not exist. */
export function tDynamic(key: string, args?: Record<string, unknown>): string | undefined {
  if (!hasMessage(key)) return undefined;
  const out = render(key, args);
  return typeof out === "string" ? out : out.map(String).join("");
}

// ---------------------------------------------------------------------------------
// Numbers, dates and lists through Intl, in the current language.

const intlCache = new Map<string, unknown>();
function cached<T>(kind: string, options: object | undefined, make: (loc: string) => T): T {
  const loc = locale();
  const id = `${kind}\u0000${loc}\u0000${options ? JSON.stringify(options) : ""}`;
  let v = intlCache.get(id) as T | undefined;
  if (v === undefined) {
    v = make(loc);
    intlCache.set(id, v);
  }
  return v;
}

export function formatNumber(value: number, options?: Intl.NumberFormatOptions): string {
  return cached("n", options, (loc) => new Intl.NumberFormat(loc, options)).format(value);
}

export function formatDate(
  value: Date | number | string,
  options: Intl.DateTimeFormatOptions = { dateStyle: "medium" },
): string {
  return cached("d", options, (loc) => new Intl.DateTimeFormat(loc, options)).format(toDate(value));
}

export function formatDateTime(
  value: Date | number | string,
  options: Intl.DateTimeFormatOptions = { dateStyle: "medium", timeStyle: "short" },
): string {
  return cached("d", options, (loc) => new Intl.DateTimeFormat(loc, options)).format(toDate(value));
}

export function formatTime(value: Date | number | string): string {
  return formatDateTime(value, { timeStyle: "short" });
}

const RELATIVE_STEPS: readonly [Intl.RelativeTimeFormatUnit, number][] = [
  ["second", 60],
  ["minute", 60],
  ["hour", 24],
  ["day", 7],
  ["week", 4.35],
  ["month", 12],
  ["year", Number.POSITIVE_INFINITY],
];

/** "3 minutes ago", "in 2 days". */
export function formatRelative(value: Date | number | string, now: Date | number = Date.now()): string {
  let delta = (toDate(value).getTime() - toDate(now).getTime()) / 1000;
  const rtf = cached("r", undefined, (loc) => new Intl.RelativeTimeFormat(loc, { numeric: "auto" }));
  for (const [unit, size] of RELATIVE_STEPS) {
    if (Math.abs(delta) < size) return rtf.format(Math.round(delta), unit);
    delta /= size;
  }
  return rtf.format(Math.round(delta), "year");
}

export function formatList(items: readonly string[], type: Intl.ListFormatType = "conjunction"): string {
  return cached("l", { type }, (loc) => new Intl.ListFormat(loc, { style: "long", type })).format(items);
}

/** A duration in seconds in its largest whole unit: "12 h", "5 min", "30 s". */
export function formatDuration(seconds: number): string {
  const units: readonly [string, number][] = [
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
  ];
  for (const [unit, size] of units) {
    if (seconds >= size && seconds % size === 0) {
      return formatNumber(seconds / size, { style: "unit", unit, unitDisplay: "short" });
    }
  }
  return formatNumber(seconds, { style: "unit", unit: "second", unitDisplay: "short" });
}

function toDate(value: Date | number | string): Date {
  return value instanceof Date ? value : new Date(value);
}
