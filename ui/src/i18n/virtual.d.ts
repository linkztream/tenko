// Modules generated at build time from ui/i18n/*.xlf by scripts/vite-plugin-i18n.mjs.
// A message table maps a key to its text, or to the pre-parsed ICU syntax tree when the
// message has arguments.

declare module "virtual:tenko-i18n/meta" {
  /** A built-in language, from the metadata of its XLIFF file. */
  export interface CatalogLocale {
    /** BCP 47 tag, for example `sv`. */
    readonly code: string;
    /** The language's own name, for example `Svenska`. */
    readonly name: string;
    readonly author: string;
    readonly version: string;
  }
  /** The language every key is defined in and every other language falls back to. */
  export const sourceLocale: string;
  /** Built-in languages, source language first. */
  export const locales: readonly CatalogLocale[];
  /** Lazy loaders of every language except the source language. */
  export const loaders: Readonly<
    Record<string, () => Promise<{ default: Readonly<Record<string, string | readonly unknown[]>> }>>
  >;
  /**
   * Message packs: per pack, a loader per language (the source language included) of the
   * keys that only lazily loaded areas use. Empty under test, where the core table holds
   * every key.
   */
  export const packs: Readonly<
    Record<string, Readonly<Record<string, () => Promise<{ default: Readonly<Record<string, string | readonly unknown[]>> }>>>>
  >;
}

declare module "virtual:tenko-i18n/en" {
  const table: Readonly<Record<string, string | readonly unknown[]>>;
  export default table;
}
