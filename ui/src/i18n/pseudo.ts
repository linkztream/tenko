// Pseudo-locales: English messages transformed so that a test sees which texts went through
// the language layer and how the layout copes, without a real translation.
//
//   ar-XB  pseudo right to left: the document is right to left (the tag's language is Arabic)
//          and every text run is wrapped in RIGHT-TO-LEFT OVERRIDE ... POP DIRECTIONAL
//          FORMATTING, so the English letters show mirrored; the layout mirrors as it would
//          for Arabic, Hebrew, Persian or Urdu.
//   en-XA  pseudo accents: letters replaced by accented look-alikes and each message in
//          brackets, which shows untranslated literals, cut-off text and missing fallbacks.
//
// The tags use the private-use regions XA and XB, as Android and Chromium do. Arguments,
// plural and select keywords and the message structure stay as they are; only literal text
// changes.
import { registerLanguage, setLocale, sourceMessages, type MessageTable } from ".";

export type PseudoKind = "rtl" | "accents";

/** The pseudo-locales, by tag. */
export const PSEUDO_LOCALES = {
  "ar-XB": { kind: "rtl", name: "Pseudo RTL" },
  "en-XA": { kind: "accents", name: "Pseudo accents" },
} as const satisfies Record<string, { kind: PseudoKind; name: string }>;

export type PseudoTag = keyof typeof PSEUDO_LOCALES;

/** RIGHT-TO-LEFT OVERRIDE and POP DIRECTIONAL FORMATTING. */
export const RLO = "‮";
export const PDF = "‬";

const ACCENTED: Readonly<Record<string, string>> = {
  a: "å", b: "ƀ", c: "ç", d: "ð", e: "é", f: "ƒ", g: "ĝ", h: "ĥ", i: "î", j: "ĵ", k: "ķ", l: "ļ", m: "ɱ",
  n: "ñ", o: "ö", p: "þ", q: "ǫ", r: "ŕ", s: "š", t: "ţ", u: "û", v: "ṽ", w: "ŵ", x: "ẋ", y: "ý", z: "ž",
  A: "Å", B: "Ɓ", C: "Ç", D: "Ð", E: "É", F: "Ƒ", G: "Ĝ", H: "Ĥ", I: "Î", J: "Ĵ", K: "Ķ", L: "Ļ", M: "Ṁ",
  N: "Ñ", O: "Ö", P: "Þ", Q: "Ǫ", R: "Ŕ", S: "Š", T: "Ţ", U: "Û", V: "Ṽ", W: "Ŵ", X: "Ẋ", Y: "Ý", Z: "Ž",
};

/** One run of literal text in a pseudo-locale. Whitespace-only runs stay as they are. */
export function pseudoText(text: string, kind: PseudoKind): string {
  if (text.trim() === "") return text;
  if (kind === "rtl") return `${RLO}${text}${PDF}`;
  return text.replace(/[A-Za-z]/g, (c) => ACCENTED[c] ?? c);
}

// The node types of @formatjs/icu-messageformat-parser that hold text or nested messages.
const LITERAL = 0;
const SELECT = 5;
const PLURAL = 6;
const TAG = 8;

type Node = { type: number; value?: unknown; options?: Record<string, { value: Node[] }>; children?: Node[] };

function mapNodes(nodes: readonly Node[], kind: PseudoKind): Node[] {
  return nodes.map((node) => {
    if (node.type === LITERAL && typeof node.value === "string") return { ...node, value: pseudoText(node.value, kind) };
    if ((node.type === SELECT || node.type === PLURAL) && node.options) {
      const options: Record<string, { value: Node[] }> = {};
      for (const [name, option] of Object.entries(node.options)) {
        options[name] = { ...option, value: mapNodes(option.value, kind) };
      }
      return { ...node, options };
    }
    if (node.type === TAG && node.children) return { ...node, children: mapNodes(node.children, kind) };
    return node;
  });
}

/** One compiled message (literal text or an ICU syntax tree) in a pseudo-locale. */
export function pseudoMessage(message: string | readonly unknown[], kind: PseudoKind): string | readonly unknown[] {
  if (typeof message === "string") return kind === "accents" ? `[${pseudoText(message, kind)}]` : pseudoText(message, kind);
  const nodes = mapNodes(message as readonly Node[], kind);
  if (kind !== "accents") return nodes;
  return [{ type: LITERAL, value: "[" }, ...nodes, { type: LITERAL, value: "]" }];
}

/** A compiled message table in a pseudo-locale. */
export function pseudoMessages(table: MessageTable, kind: PseudoKind): Record<string, string | readonly unknown[]> {
  const out: Record<string, string | readonly unknown[]> = {};
  for (const [key, message] of Object.entries(table)) out[key] = pseudoMessage(message, kind);
  return out;
}

/**
 * Registers a pseudo-locale built from the English messages loaded so far and switches the UI
 * to it. Tests load every key in the core table, so the pseudo-locale covers the whole UI.
 */
export async function usePseudoLocale(tag: PseudoTag): Promise<void> {
  const { kind, name } = PSEUDO_LOCALES[tag];
  await registerLanguage({
    code: tag,
    name,
    load: async () => ({ kind: "compiled", messages: pseudoMessages(sourceMessages(), kind) }),
  });
  await setLocale(tag);
}
