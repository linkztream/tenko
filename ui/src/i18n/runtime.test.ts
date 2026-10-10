import { parse } from "@formatjs/icu-messageformat-parser";
import { afterEach, describe, expect, it } from "vitest";
import {
  availableLocales,
  direction,
  isAvailable,
  locale,
  matchLocale,
  registerLanguage,
  resolveLocale,
  setLocale,
  t,
  tx,
  unregisterLanguage,
} from ".";
import { PDF, pseudoMessage, pseudoText, RLO, usePseudoLocale } from "./pseudo";

const parseIcu = (message: string) => parse(message, { ignoreTag: true });

afterEach(async () => {
  for (const code of ["fr", "sv", "ar-XB", "en-XA", "he"]) await unregisterLanguage(code);
  await setLocale("en");
});

describe("the document follows the language", () => {
  it("sets lang and dir", async () => {
    await setLocale("sv");
    expect(document.documentElement.lang).toBe("sv");
    expect(document.documentElement.dir).toBe("ltr");
    expect(direction()).toBe("ltr");
    await registerLanguage({ code: "he", name: "עברית", load: async () => ({ kind: "compiled", messages: {} }) });
    await setLocale("he");
    expect(document.documentElement.lang).toBe("he");
    expect(document.documentElement.dir).toBe("rtl");
    expect(direction()).toBe("rtl");
    await setLocale("en");
    expect(document.documentElement.dir).toBe("ltr");
  });
});

describe("languages registered at run time", () => {
  const french = {
    code: "fr",
    name: "Français",
    load: async () => ({
      kind: "source" as const,
      parse: parseIcu,
      messages: {
        "common.action.cancel": "Annuler",
        "common.greeting": "Connecté en tant que {name}",
        "common.count.items": "{count, plural, one {# élément} other {# éléments}}",
        "common.action.save": "<b>Enregistrer</b>",
      },
    }),
  };

  it("are offered beside the built-in languages and matched by tag", async () => {
    expect(isAvailable("fr")).toBe(false);
    await registerLanguage(french);
    expect(availableLocales().map((l) => l.code)).toEqual(["en", "sv", "fr"]);
    expect(isAvailable("fr")).toBe(true);
    expect(matchLocale("fr-CA")).toBe("fr");
    expect(resolveLocale({ browser: ["fr-FR", "en"] })).toBe("fr");
    await unregisterLanguage("fr");
    expect(availableLocales().map((l) => l.code)).toEqual(["en", "sv"]);
    expect(resolveLocale({ browser: ["fr-FR", "en"] })).toBe("en");
  });

  it("parse ICU text on use and fall back to English per key", async () => {
    await registerLanguage(french);
    await setLocale("fr");
    expect(locale()).toBe("fr");
    expect(t("common.action.cancel")).toBe("Annuler");
    expect(t("common.greeting", { name: "alex" })).toBe("Connecté en tant que alex");
    expect(t("common.count.items", { count: 1 })).toBe("1 élément");
    expect(t("common.count.items", { count: 1234 })).toMatch(/^1\s?234 éléments$/);
    // Not in the pack: English.
    expect(t("common.action.close")).toBe("Close");
  });

  it("render markup in a translation as text", async () => {
    await registerLanguage(french);
    await setLocale("fr");
    expect(t("common.action.save")).toBe("<b>Enregistrer</b>");
    expect(tx("common.greeting", { name: "<i>alex</i>" })).toBe("Connecté en tant que <i>alex</i>");
  });

  it("fall back to English for a message that does not parse", async () => {
    await registerLanguage({
      code: "fr",
      name: "Français",
      load: async () => ({ kind: "source", parse: parseIcu, messages: { "common.greeting": "Bonjour {name" } }),
    });
    await setLocale("fr");
    expect(t("common.greeting", { name: "alex" })).toBe("Signed in as alex");
  });

  it("fall back to English when the pack cannot be loaded", async () => {
    await registerLanguage({
      code: "fr",
      name: "Français",
      load: () => Promise.reject(new Error("offline")),
    });
    await setLocale("fr");
    expect(locale()).toBe("en");
  });

  it("override a built-in language key by key and can be reverted", async () => {
    await registerLanguage({
      code: "sv",
      name: "Svenska",
      load: async () => ({ kind: "compiled", messages: { "common.action.cancel": "Avbryt nu" } }),
    });
    expect(availableLocales().map((l) => l.code)).toEqual(["en", "sv"]);
    await setLocale("sv");
    expect(t("common.action.cancel")).toBe("Avbryt nu");
    // Not in the override: the built-in Swedish message.
    expect(t("shell.status.running", { count: 2 })).toBe("2 körs");
    await unregisterLanguage("sv");
    expect(locale()).toBe("sv");
    expect(t("common.action.cancel")).toBe("Avbryt");
  });

  it("reload the current language when a new version is registered", async () => {
    await registerLanguage(french);
    await setLocale("fr");
    expect(t("common.action.cancel")).toBe("Annuler");
    await registerLanguage({
      code: "fr",
      name: "Français",
      load: async () => ({ kind: "source", parse: parseIcu, messages: { "common.action.cancel": "Abandonner" } }),
    });
    expect(locale()).toBe("fr");
    expect(t("common.action.cancel")).toBe("Abandonner");
    expect(t("common.greeting", { name: "alex" })).toBe("Signed in as alex");
  });
});

describe("pseudo-locales", () => {
  it("wrap text runs in a right-to-left override and keep the structure", () => {
    expect(pseudoText("Cancel", "rtl")).toBe(`${RLO}Cancel${PDF}`);
    expect(pseudoText("  ", "rtl")).toBe("  ");
    expect(pseudoText("Cancel", "accents")).toBe("Çåñçéļ");
    const ast = parseIcu("{count, plural, one {# item} other {# items}} in {name}");
    const out = pseudoMessage(ast, "rtl") as typeof ast;
    expect(JSON.stringify(out)).toContain(`${RLO} items${PDF}`);
    expect(JSON.stringify(out)).toContain(`${RLO} in ${PDF}`);
    expect(pseudoMessage("Close", "accents")).toBe("[Çļöšé]");
  });

  it("mirror the document in the pseudo right-to-left locale", async () => {
    await usePseudoLocale("ar-XB");
    expect(locale()).toBe("ar-XB");
    expect(document.documentElement.dir).toBe("rtl");
    expect(t("common.action.cancel")).toBe(`${RLO}Cancel${PDF}`);
    expect(t("common.greeting", { name: "alex" })).toBe(`${RLO}Signed in as ${PDF}alex`);
  });

  it("show every text of the pseudo accent locale in brackets", async () => {
    await usePseudoLocale("en-XA");
    expect(document.documentElement.dir).toBe("ltr");
    expect(t("common.action.cancel")).toBe("[Çåñçéļ]");
    expect(t("common.greeting", { name: "alex" })).toBe("[Šîĝñéð îñ åš alex]");
  });
});
