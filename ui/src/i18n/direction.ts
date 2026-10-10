// The writing direction of a language. The document's `dir` follows the UI language (set by
// setLocale), and the style sheets use logical properties only (scripts/css-logical.mjs), so
// a right-to-left language mirrors the layout without style sheets of its own.
//
// The direction comes from the script: an explicit script subtag decides (`ku-Arab` is
// right to left, `uz-Latn` left to right); without one, the language's usual script does.
// The lists are fixed rather than read from `Intl.Locale.prototype.getTextInfo`, which not
// every browser has, so the same tag gives the same direction everywhere.

export type TextDirection = "ltr" | "rtl";

/** ISO 15924 codes (lower case) of the scripts written right to left. */
const RTL_SCRIPTS: ReadonlySet<string> = new Set([
  "adlm", // Adlam
  "arab", // Arabic
  "hebr", // Hebrew
  "mand", // Mandaic
  "mend", // Mende Kikakui
  "nkoo", // N'Ko
  "rohg", // Hanifi Rohingya
  "samr", // Samaritan
  "syrc", // Syriac
  "thaa", // Thaana
  "yezi", // Yezidi
]);

/** Languages (lower case) whose usual script is written right to left. */
const RTL_LANGUAGES: ReadonlySet<string> = new Set([
  "ar", // Arabic
  "arc", // Aramaic
  "azb", // South Azerbaijani
  "ckb", // Central Kurdish
  "dv", // Dhivehi
  "fa", // Persian
  "glk", // Gilaki
  "he", // Hebrew
  "iw", // Hebrew (deprecated tag)
  "ji", // Yiddish (deprecated tag)
  "khw", // Khowar
  "ks", // Kashmiri
  "lrc", // Northern Luri
  "mzn", // Mazanderani
  "nqo", // N'Ko
  "pnb", // Western Panjabi
  "prs", // Dari
  "ps", // Pashto
  "sd", // Sindhi
  "sdh", // Southern Kurdish
  "syr", // Syriac
  "ug", // Uyghur
  "ur", // Urdu
  "yi", // Yiddish
]);

/** The writing direction of a BCP 47 language tag; left to right for anything unknown. */
export function textDirection(tag: string | null | undefined): TextDirection {
  if (!tag) return "ltr";
  const subtags = tag.toLowerCase().split(/[-_]/);
  const language = subtags[0] ?? "";
  // The script subtag is the four-letter subtag after the language (and its extlangs), before
  // any extension or private-use part (which start with a single-letter subtag).
  const singleton = subtags.findIndex((s, i) => i > 0 && s.length === 1);
  const main = singleton < 0 ? subtags.slice(1) : subtags.slice(1, singleton);
  const script = main.find((s) => /^[a-z]{4}$/.test(s));
  if (script !== undefined) return RTL_SCRIPTS.has(script) ? "rtl" : "ltr";
  return RTL_LANGUAGES.has(language) ? "rtl" : "ltr";
}
