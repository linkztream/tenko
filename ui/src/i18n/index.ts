// The runtime half of the language packs (API-21). Messages come from ui/i18n/*.xlf,
// compiled at build time into tables of plain strings and pre-parsed ICU syntax trees
// (scripts/vite-plugin-i18n.mjs), so the browser never parses message syntax.
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
import { loaders, locales, sourceLocale } from "virtual:tenko-i18n/meta";
import type { MessageArgs, MessageKey } from "./generated/keys";

export type { MessageArgs, MessageKey } from "./generated/keys";
export type MessageTable = Readonly<Record<string, string | readonly unknown[]>>;

/** Arguments of `t(key, ...)`: required for keys that take arguments, absent otherwise. */
export type ArgsOf<K extends MessageKey> = K extends keyof MessageArgs ? [args: MessageArgs[K]] : [];

const STORED_KEY = "tenko-lang";

const tables = new Map<string, MessageTable>([[sourceLocale, en]]);
const [locale, setLocaleSignal] = createSignal<string>(sourceLocale);

/** The current UI language (BCP 47). */
export { locale };

/** The built-in languages, source language first. */
export function availableLocales() {
  return locales;
}

export function isBuiltIn(code: string | null | undefined): code is string {
  return !!code && locales.some((l) => l.code === code);
}

/** Matches a language tag against the built-in languages: exact tag, then primary subtag. */
export function matchLocale(tag: string | null | undefined): string | undefined {
  if (!tag) return undefined;
  const lower = tag.toLowerCase();
  const exact = locales.find((l) => l.code.toLowerCase() === lower);
  if (exact) return exact.code;
  const primary = lower.split("-")[0];
  return locales.find((l) => l.code.toLowerCase().split("-")[0] === primary)?.code;
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

/** Applies the resolution order of API-08 and returns a built-in language. */
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

/** Loads a language if needed and switches the UI to it. Unknown codes fall back to English. */
export async function setLocale(code: string): Promise<void> {
  const target = isBuiltIn(code) ? code : sourceLocale;
  if (!tables.has(target)) {
    const load = loaders[target];
    if (!load) return;
    const mod = await load();
    tables.set(target, mod.default);
  }
  setLocaleSignal(target);
  if (typeof document !== "undefined") document.documentElement.lang = target;
}

const formatters = new Map<string, IntlMessageFormat>();

function lookup(code: string, key: string): { loc: string; msg: string | readonly unknown[] } | undefined {
  const own = tables.get(code)?.[key];
  if (own !== undefined) return { loc: code, msg: own };
  const fallback = en[key];
  return fallback === undefined ? undefined : { loc: sourceLocale, msg: fallback };
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
  return en[key] !== undefined;
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
