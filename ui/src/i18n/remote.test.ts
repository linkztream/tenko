import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { activatePack, previewPack, removePack, uploadPack } from "../settings/languages/api";
import { signInAs } from "../settings/testkit";
import { server } from "../api/mock/node";
import type { ApiEvent } from "../api/events";
import { availableLocales, isAvailable, locale, setLocale, t } from ".";
import { currentPreview, endPreview, isPackEvent, loadLanguages, resetLanguagesForTest, startPreview } from "./remote";

const PREVIEW_KEY = "tenko-i18n-preview";

beforeEach(async () => {
  await signInAs();
});

afterEach(async () => {
  await resetLanguagesForTest();
  await setLocale("en");
});

/** A minimal XLIFF 2.0 pack: the real keys of the core messages given, `trgLang` and a display name. */
function xliff(tag: string, name: string, units: Record<string, string>): string {
  const rows = Object.entries(units).map(
    ([id, target]) => `    <unit id="${id}"><segment><source>x</source><target>${target}</target></segment></unit>`,
  );
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<xliff xmlns="urn:oasis:names:tc:xliff:document:2.0" xmlns:mda="urn:oasis:names:tc:xliff:metadata:2.0" version="2.0" srcLang="en" trgLang="${tag}">`,
    '  <file id="f">',
    '    <mda:metadata><mda:metaGroup category="language-pack">',
    `      <mda:meta type="displayName">${name}</mda:meta>`,
    '      <mda:meta type="author">Example Translators</mda:meta>',
    '      <mda:meta type="version">1.0.0</mda:meta>',
    "    </mda:metaGroup></mda:metadata>",
    ...rows,
    "  </file>",
    "</xliff>",
  ].join("\n");
}

const FRENCH = xliff("fr", "Francais", { "common.action.cancel": "Annuler", "common.action.save": "Enregistrer" });

/** Uploads a pack as the administrator; optionally previews and activates it. */
async function upload(document: string, tag: string, stage: "uploaded" | "active" = "uploaded"): Promise<void> {
  await uploadPack(new File([document], `${tag}.xlf`, { type: "application/xliff+xml" }));
  if (stage === "active") {
    await previewPack(tag);
    await activatePack(tag);
  }
}

function event(data: Record<string, unknown>): ApiEvent {
  return { topic: "system", type: "system", objects: [], deleted: [], revision: undefined, data };
}

describe("isPackEvent", () => {
  it("is true when an i18n table changed", () => {
    expect(isPackEvent(event({ tables: ["settings", "i18n.packs"] }))).toBe(true);
    expect(isPackEvent(event({ tables: ["i18n.pack_slots"] }))).toBe(true);
  });

  it("is false for other tables, an empty list and a missing or malformed list", () => {
    expect(isPackEvent(event({ tables: ["settings", "users"] }))).toBe(false);
    expect(isPackEvent(event({ tables: [] }))).toBe(false);
    expect(isPackEvent(event({ tables: ["i18nx"] }))).toBe(false);
    expect(isPackEvent(event({ tables: "i18n.packs" }))).toBe(false);
    expect(isPackEvent(event({ tables: [7] }))).toBe(false);
    expect(isPackEvent(event({}))).toBe(false);
  });
});

describe("loadLanguages", () => {
  it("leaves the built-in languages when the server has no pack", async () => {
    await loadLanguages();
    expect(availableLocales().map((l) => l.code)).toEqual(["en", "sv"]);
  });

  it("registers an active uploaded pack, renders its texts and falls back to English for a missing key", async () => {
    await upload(FRENCH, "fr", "active");
    expect(isAvailable("fr")).toBe(false);
    await loadLanguages();
    expect(isAvailable("fr")).toBe(true);
    expect(availableLocales().find((l) => l.code === "fr")?.name).toBe("Francais");

    await setLocale("fr");
    expect(locale()).toBe("fr");
    expect(t("common.action.cancel")).toBe("Annuler");
    expect(t("common.action.save")).toBe("Enregistrer");
    // The pack lacks this key: the English text shows.
    expect(t("common.action.close")).toBe("Close");
  });

  it("does not register a candidate that is not active", async () => {
    await upload(FRENCH, "fr");
    await loadLanguages();
    expect(isAvailable("fr")).toBe(false);
  });

  it("unregisters a pack that was removed and returns the UI to English", async () => {
    await upload(FRENCH, "fr", "active");
    await loadLanguages();
    await setLocale("fr");
    expect(t("common.action.cancel")).toBe("Annuler");

    await removePack("fr");
    await loadLanguages();
    expect(isAvailable("fr")).toBe(false);
    expect(locale()).toBe("en");
    expect(t("common.action.cancel")).toBe("Cancel");
  });

  it("registers an override of a built-in language key by key", async () => {
    await upload(xliff("sv", "Svenska", { "common.action.cancel": "Ångra" }), "sv", "active");
    await loadLanguages();
    await setLocale("sv");
    expect(t("common.action.cancel")).toBe("Ångra");
    // Built-in Swedish text for the key the pack lacks.
    expect(t("common.action.save")).toBe("Spara");
    await removePack("sv");
    await loadLanguages();
    expect(t("common.action.cancel")).toBe("Avbryt");
  });

  it("leaves the built-in languages when the server cannot be reached", async () => {
    server.use(http.get("/api/v1/i18n/languages", () => HttpResponse.error()));
    await expect(loadLanguages()).resolves.toBeUndefined();
    expect(availableLocales().map((l) => l.code)).toEqual(["en", "sv"]);

    server.use(
      http.get("/api/v1/i18n/languages", () =>
        HttpResponse.json({ code: "server.unavailable", status: 503, title: "Unavailable", detail: "", params: {} }, { status: 503, headers: { "content-type": "application/problem+json" } }),
      ),
    );
    await expect(loadLanguages()).resolves.toBeUndefined();
    expect(availableLocales().map((l) => l.code)).toEqual(["en", "sv"]);
  });

  it("keeps the registered packs when a later read fails", async () => {
    await upload(FRENCH, "fr", "active");
    await loadLanguages();
    server.use(http.get("/api/v1/i18n/languages", () => HttpResponse.error()));
    await loadLanguages();
    expect(isAvailable("fr")).toBe(true);
  });
});

describe("the preview", () => {
  it("forces the candidate's language, stores the preview in the session and ends it", async () => {
    await upload(FRENCH, "fr");
    expect(currentPreview()).toBeUndefined();

    await startPreview({ tag: "fr", name: "Francais" });
    expect(currentPreview()).toEqual({ tag: "fr", name: "Francais" });
    expect(JSON.parse(sessionStorage.getItem(PREVIEW_KEY) ?? "null")).toEqual({ tag: "fr", name: "Francais" });
    expect(locale()).toBe("fr");
    expect(t("common.action.cancel")).toBe("Annuler");

    // Whatever else asks for a language, the preview stays.
    await setLocale("sv");
    expect(locale()).toBe("fr");

    await endPreview();
    expect(currentPreview()).toBeUndefined();
    expect(sessionStorage.getItem(PREVIEW_KEY)).toBeNull();
    // The language last asked for returns; the candidate is not a registered language.
    expect(locale()).toBe("sv");
    expect(isAvailable("fr")).toBe(false);
    await setLocale("en");
    expect(t("common.action.cancel")).toBe("Cancel");
  });

  it("returns to English when it ends and nothing else was asked for", async () => {
    await upload(FRENCH, "fr");
    await startPreview({ tag: "fr", name: "Francais" });
    await endPreview();
    expect(locale()).toBe("en");
  });

  it("refuses to start for a language without a candidate", async () => {
    await expect(startPreview({ tag: "fr", name: "Francais" })).rejects.toBeTruthy();
    expect(currentPreview()).toBeUndefined();
    expect(sessionStorage.getItem(PREVIEW_KEY)).toBeNull();
  });

  it("is resumed by loadLanguages from the session storage", async () => {
    await upload(FRENCH, "fr");
    sessionStorage.setItem(PREVIEW_KEY, JSON.stringify({ tag: "fr", name: "Francais" }));
    await loadLanguages();
    expect(currentPreview()).toEqual({ tag: "fr", name: "Francais" });
    expect(locale()).toBe("fr");
  });

  it("is dropped silently by loadLanguages when its candidate is gone", async () => {
    sessionStorage.setItem(PREVIEW_KEY, JSON.stringify({ tag: "fr", name: "Francais" }));
    await loadLanguages();
    expect(currentPreview()).toBeUndefined();
    expect(sessionStorage.getItem(PREVIEW_KEY)).toBeNull();
    expect(locale()).toBe("en");
  });

  it("ignores a stored preview that is not shaped like one", async () => {
    sessionStorage.setItem(PREVIEW_KEY, JSON.stringify({ tag: 7 }));
    await loadLanguages();
    expect(currentPreview()).toBeUndefined();
    sessionStorage.setItem(PREVIEW_KEY, "not json");
    await loadLanguages();
    expect(currentPreview()).toBeUndefined();
  });
});
