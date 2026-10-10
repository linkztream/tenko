// The rendering of a page in one language (API-08): the document language is the one asked
// for, and no message key shows instead of its text. The UI renders the key itself when a
// message is missing (src/i18n/index.ts), so a key of ui/i18n/en.xlf that appears as a word
// of the visible text, or of an `aria-label`, `title` or `placeholder`, is a missing or
// unloaded message. No translated text is asserted, so wording changes break nothing.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, type Locator, type Page, type TestInfo } from "@playwright/test";

let keys: Set<string> | undefined;

/** Every message key of the UI, from the English source table. */
export function messageKeys(): Set<string> {
  if (!keys) {
    const xlf = readFileSync(resolve(import.meta.dirname, "..", "..", "i18n", "en.xlf"), "utf8");
    keys = new Set([...xlf.matchAll(/<unit id="([^"]+)"/g)].map((match) => match[1]!));
  }
  return keys;
}

/**
 * The message keys that show as text or as an accessible name inside `root`. Codes the UI
 * shows on purpose in a monospace face (audit actions, rule codes: `code`, `kbd`, `samp`,
 * `pre`, `.mono`) are not text of the UI and are left out.
 */
export async function rawKeys(root: Locator): Promise<string[]> {
  const texts = await root.evaluate((element) => {
    const out: string[] = [];
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const parent = node.parentElement;
      if (!parent || parent.closest("code, kbd, samp, pre, .mono, script, style")) continue;
      if (!parent.checkVisibility()) continue;
      out.push(node.textContent ?? "");
    }
    for (const el of element.querySelectorAll("[aria-label],[title],[placeholder]")) {
      for (const name of ["aria-label", "title", "placeholder"]) {
        const value = el.getAttribute(name);
        if (value) out.push(value);
      }
    }
    return out;
  });
  const known = messageKeys();
  const found = new Set<string>();
  for (const text of texts) {
    for (const word of text.split(/[^A-Za-z0-9_.-]+/)) {
      const token = word.replace(/^[.-]+|[.-]+$/g, "");
      if (known.has(token)) found.add(token);
    }
  }
  return [...found].sort();
}

/**
 * Asserts that the page is in `language` and that `root` shows no message key, waiting for
 * the message packs to arrive; attaches a screenshot named `<name>-<language>` when `testInfo`
 * is given.
 */
export async function expectRendered(page: Page, root: Locator, language: "en" | "sv", testInfo?: TestInfo, name?: string): Promise<void> {
  await expect.poll(() => page.evaluate(() => document.documentElement.lang)).toBe(language);
  await expect(root).toBeVisible();
  await expect.poll(() => rawKeys(root), { message: "message keys shown instead of their text" }).toEqual([]);
  if (testInfo) {
    const label = `${name ?? "page"}-${language}`;
    await testInfo.attach(label, { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });
  }
}
