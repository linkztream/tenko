// Language packs (API-21, WP3.7): packs made from the server's own template, uploaded,
// checked, previewed in the administrator's tab, activated for everyone and reverted. The
// packs are pseudo-locales of the English template (src/i18n/pseudo.ts does the same in the
// unit tests): `en-XA` replaces letters with accented look-alikes, `ar-XB` wraps every run of
// text in RIGHT-TO-LEFT OVERRIDE and POP DIRECTIONAL FORMATTING and is right to left; the
// `fr` pack of the acceptance is the accented text with a tenth of the keys left out.
// Elements are found by test id; the texts asserted are the ones the packs put there.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parse, TYPE, type MessageFormatElement } from "@formatjs/icu-messageformat-parser";
import { printAST } from "@formatjs/icu-messageformat-parser/printer.js";
import type { APIRequestContext, Page } from "@playwright/test";
import type { Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { openAccountMenu, withKey } from "./support/ui";

type PackList = Schemas["PackList"];
type LanguageList = Schemas["LanguageList"];

const RLO = "‮";
const PDF = "‬";
const ACCENTS: Readonly<Record<string, string>> = Object.fromEntries(
  [..."abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"].map((c, i) => [c, [..."åƀçðéƒĝĥîĵķļɱñöþǫŕšţûṽŵẋýžÅƁÇÐÉƑĜĤÎĴĶĻṀÑÖÞǪŔŠŢÛṼŴẊÝŽ"][i]!]),
);

type Pseudo = "accents" | "rtl";

function pseudoText(text: string, kind: Pseudo): string {
  if (text.trim() === "") return text;
  return kind === "rtl" ? `${RLO}${text}${PDF}` : text.replace(/[A-Za-z]/g, (c) => ACCENTS[c] ?? c);
}

function pseudoNodes(nodes: MessageFormatElement[], kind: Pseudo): MessageFormatElement[] {
  return nodes.map((node) => {
    if (node.type === TYPE.literal) return { ...node, value: pseudoText(node.value, kind) };
    if (node.type === TYPE.select || node.type === TYPE.plural) {
      const options = Object.fromEntries(
        Object.entries(node.options).map(([name, option]) => [name, { ...option, value: pseudoNodes(option.value, kind) }]),
      );
      return { ...node, options } as MessageFormatElement;
    }
    return node;
  });
}

/** One ICU message in a pseudo-locale: literal text changes, the message structure stays. */
function pseudoMessage(message: string, kind: Pseudo): string {
  return printAST(pseudoNodes(parse(message, { ignoreTag: true }), kind));
}

function decode(text: string): string {
  return text.replace(/&(lt|gt|amp|quot|apos|#(\d+));/g, (_, name: string, code: string | undefined) =>
    code ? String.fromCodePoint(Number(code)) : ({ lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" } as Record<string, string>)[name]!,
  );
}

/** Element text the server's reader returns unchanged: line breaks as references, so no edge is trimmed. */
function encode(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\n/g, "&#10;");
}

interface PackOptions {
  tag: string;
  name: string;
  kind: Pseudo;
  /** Keys whose target is left out (they show in English). */
  omit?: ReadonlySet<string>;
  /** Targets written as given (raw ICU text), instead of the pseudo text. */
  targets?: Readonly<Record<string, string>>;
}

/** A pack made from the English template of the server: every target in a pseudo-locale. */
function makePack(template: string, options: PackOptions): string {
  return template
    .replace(/trgLang="en"/, `trgLang="${options.tag}"`)
    .replace(/<mda:meta type="displayName">[^<]*<\/mda:meta>/, `<mda:meta type="displayName">${encode(options.name)}</mda:meta>`)
    .replace(/<mda:meta type="author">[^<]*<\/mda:meta>/, `<mda:meta type="author">Example translators</mda:meta>`)
    .replace(/<mda:meta type="version">[^<]*<\/mda:meta>/, `<mda:meta type="version">1.0</mda:meta>`)
    .replace(/<unit id="([^"]+)">[\s\S]*?<\/unit>/g, (unit, key: string) => {
      if (options.omit?.has(key)) return unit.replace(/\s*<target>[\s\S]*?<\/target>/, "");
      const own = options.targets?.[key];
      return unit.replace(/<target>([\s\S]*?)<\/target>/, (_, raw: string) => {
        const text = own ?? pseudoMessage(decode(raw), options.kind);
        return `<target>${encode(text)}</target>`;
      });
    });
}

/** The message keys of a template, in its order. */
function templateKeys(template: string): string[] {
  return [...template.matchAll(/<unit id="([^"]+)">/g)].map((m) => m[1]!);
}

async function englishTemplate(page: Page, origin: string): Promise<string> {
  const response = await page.request.get(`${origin}/api/v1/i18n/template.xlf`);
  expect(response.status()).toBe(200);
  return response.text();
}

async function uploadByApi(request: APIRequestContext, origin: string, name: string, document: string): Promise<Schemas["PackUpload"]> {
  const response = await request.post(`${origin}/api/v1/i18n/packs`, {
    headers: { Origin: origin },
    multipart: { file: { name, mimeType: "application/xliff+xml", buffer: Buffer.from(document, "utf8") } },
  });
  expect(response.status(), await response.text()).toBe(201);
  return (await response.json()) as Schemas["PackUpload"];
}

async function activateByApi(request: APIRequestContext, origin: string, tag: string): Promise<void> {
  for (const step of ["preview", "activate"]) {
    const response = await request.post(`${origin}/api/v1/i18n/packs/${tag}/${step}`, { headers: { Origin: origin } });
    expect(response.status(), await response.text()).toBe(200);
  }
}

/** The title of the page head: the heading's own text, without its subtitle. */
async function pageTitle(page: Page, testid: string): Promise<string | null> {
  return page.getByTestId(testid).locator("h1").evaluate((h1) => h1.firstChild?.textContent ?? null);
}

async function documentLanguage(page: Page): Promise<{ lang: string; dir: string }> {
  return page.evaluate(() => ({ lang: document.documentElement.lang, dir: document.documentElement.dir }));
}

async function openLanguagesPage(page: Page): Promise<void> {
  await page.goto("/settings/languages");
  await expect(page.getByTestId("page-languages")).toBeVisible();
  await expect(withKey(page.getByTestId("grid-languages"), "row", "en")).toBeVisible();
}

async function uploadInPage(page: Page, name: string, document: string): Promise<void> {
  await page.getByTestId("field-file").setInputFiles({ name, mimeType: "application/xliff+xml", buffer: Buffer.from(document, "utf8") });
  await page.getByTestId("languages-upload").click();
}

test.describe("language packs", () => {
  test.use({ locale: "en-US" });

  test("a pack with ninety percent of the keys is reported, previewed in the tab, activated and offered before sign-in", async ({
    page,
    server,
    signedIn,
    browser,
  }, testInfo) => {
    expect(signedIn.session.roles).toContain("admin");
    const template = await englishTemplate(page, server.url);
    const keys = templateKeys(template);
    // Every tenth key stays English, but the page title is translated and the settings tab of
    // the page is not, so both cases show on one page.
    const omit = new Set(keys.filter((key, i) => i % 10 === 9 && key !== "languages.title"));
    if (!omit.has("settings.nav.languages")) {
      omit.delete([...omit].at(-1)!);
      omit.add("settings.nav.languages");
    }
    expect(omit.size).toBe(Math.floor(keys.length / 10));
    const fr = makePack(template, { tag: "fr", name: "Français", kind: "accents", omit });

    await openLanguagesPage(page);
    await uploadInPage(page, "fr.xlf", fr);
    const report = page.getByTestId("languages-report");
    await expect(report).toHaveAttribute("data-key", "fr");
    await expect(page.getByTestId("languages-report-complete")).toHaveAttribute("data-percent", "90");
    await expect(page.getByTestId("languages-report-missing")).toHaveAttribute("data-count", String(omit.size));
    const row = withKey(page.getByTestId("grid-languages"), "row", "fr");
    await expect(row).toHaveAttribute("data-status", "uploaded");
    await expect(row.getByTestId("languages-activate")).toBeDisabled();

    // The preview renders this tab in the pack: its texts where it has them, English elsewhere.
    await row.getByTestId("languages-preview").click();
    await expect(page.getByTestId("languages-preview-bar")).toHaveAttribute("data-key", "fr");
    await expect.poll(() => documentLanguage(page)).toEqual({ lang: "fr", dir: "ltr" });
    await expect.poll(() => pageTitle(page, "page-languages")).toBe(pseudoText("Languages", "accents"));
    await expect(withKey(page, "settings-nav-link", "languages")).toHaveText("Languages");
    await testInfo.attach("languages-fr-preview", { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });

    // Nobody else sees it yet.
    const before = await page.request.get(`${server.url}/api/v1/i18n/languages`);
    expect(((await before.json()) as LanguageList).languages.map((l) => l.tag)).toEqual(["en", "sv"]);

    await expect(row).toHaveAttribute("data-status", "previewed");
    await row.getByTestId("languages-activate").click();
    await page.getByTestId("dialog-activate").getByTestId("confirm-ok").click();
    await expect(row).toHaveAttribute("data-status", "active");
    // The activation ends the preview; the tab returns to the language it would have shown.
    await expect(page.getByTestId("languages-preview-bar")).toHaveCount(0);
    await expect.poll(() => documentLanguage(page)).toEqual({ lang: "en", dir: "ltr" });

    // A French browser that nobody signed in to gets the pack, without a restart.
    const visitor = await browser.newContext({ locale: "fr-FR", baseURL: server.url });
    const signin = await visitor.newPage();
    await signin.goto("/signin");
    await expect(signin.getByTestId("page-signin")).toBeVisible();
    await expect.poll(() => documentLanguage(signin)).toEqual({ lang: "fr", dir: "ltr" });
    await visitor.close();
  });

  test("the pseudo right-to-left pack mirrors the layout", async ({ page, server, signedIn }, testInfo) => {
    expect(signedIn.session.user.id).toBeTruthy();
    const template = await englishTemplate(page, server.url);
    const upload = await uploadByApi(page.request, server.url, "ar-XB.xlf", makePack(template, { tag: "ar-XB", name: "Pseudo RTL", kind: "rtl" }));
    expect(upload.report.percent).toBe(100);
    await activateByApi(page.request, server.url, "ar-XB");

    // The language is offered in the account menu once the client has read the change.
    await openLanguagesPage(page);
    const menu = await openAccountMenu(page);
    await expect(menu.getByTestId("field-language").locator('option[value="ar-XB"]')).toHaveCount(1);
    await menu.getByTestId("field-language").selectOption("ar-XB");
    await expect.poll(() => documentLanguage(page)).toEqual({ lang: "ar-XB", dir: "rtl" });
    await page.keyboard.press("Escape");

    // The settings tabs run from right to left.
    const first = await withKey(page, "settings-nav-link", "security").boundingBox();
    const second = await withKey(page, "settings-nav-link", "users").boundingBox();
    expect(first && second && first.x > second.x).toBe(true);
    await testInfo.attach("languages-ar-XB", { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });
  });

  test("markup in a translation shows as literal text", async ({ page, server, signedIn }) => {
    expect(signedIn.session.user.id).toBeTruthy();
    const template = await englishTemplate(page, server.url);
    const markup = "<b>Ļåñĝûåĝéš</b>";
    const pack = makePack(template, { tag: "en-XA", name: "Pseudo accents", kind: "accents", targets: { "languages.title": markup } });
    await openLanguagesPage(page);
    await uploadInPage(page, "en-XA.xlf", pack);
    await expect(page.getByTestId("languages-report")).toHaveAttribute("data-key", "en-XA");
    await expect(page.getByTestId("languages-report-clean")).toBeVisible();
    const row = withKey(page.getByTestId("grid-languages"), "row", "en-XA");
    await row.getByTestId("languages-preview").click();
    await expect.poll(() => documentLanguage(page)).toEqual({ lang: "en-XA", dir: "ltr" });
    await expect.poll(() => pageTitle(page, "page-languages")).toBe(markup);
    await expect(page.getByTestId("page-languages").locator("h1 b")).toHaveCount(0);
    await page.getByTestId("languages-preview-end").click();
    await expect.poll(() => documentLanguage(page)).toEqual({ lang: "en", dir: "ltr" });
  });

  test("the exported template re-imports at one hundred percent and a built-in language reverts", async ({ page, signedIn }) => {
    expect(signedIn.session.user.id).toBeTruthy();
    await openLanguagesPage(page);
    const download = page.waitForEvent("download");
    await page.getByTestId("languages-template").click();
    const file = await (await download).path();
    const template = await readFile(file, "utf8");
    expect(template).toContain('trgLang="en"');

    await uploadInPage(page, "tenko-en.xlf", template);
    await expect(page.getByTestId("languages-report")).toHaveAttribute("data-key", "en");
    await expect(page.getByTestId("languages-report-complete")).toHaveAttribute("data-percent", "100");
    await expect(page.getByTestId("languages-report-clean")).toBeVisible();
    const row = withKey(page.getByTestId("grid-languages"), "row", "en");
    await expect(row).toHaveAttribute("data-status", "uploaded");

    // Preview and activate an override of English, then revert to the built-in texts.
    await row.getByTestId("languages-preview").click();
    await expect(page.getByTestId("languages-preview-bar")).toHaveAttribute("data-key", "en");
    await row.getByTestId("languages-activate").click();
    await page.getByTestId("dialog-activate").getByTestId("confirm-ok").click();
    await expect(row).toHaveAttribute("data-status", "active");
    await row.getByTestId("languages-revert").click();
    await page.getByTestId("dialog-remove").getByTestId("confirm-ok").click();
    await expect(row).toHaveAttribute("data-status", "built_in");
  });

  test("a pack in the data directory is imported at start as an upload by the system", async ({ page, server, signedIn }) => {
    expect(signedIn.session.user.id).toBeTruthy();
    const template = await englishTemplate(page, server.url);
    await server.halt();
    await mkdir(join(server.dataDir, "i18n"), { recursive: true });
    await writeFile(join(server.dataDir, "i18n", "de.xlf"), makePack(template, { tag: "de", name: "Deutsch (test)", kind: "accents" }));
    await server.restart();

    const response = await page.request.get(`${server.url}/api/v1/i18n/packs`);
    expect(response.status()).toBe(200);
    const de = ((await response.json()) as PackList).packs.find((pack) => pack.tag === "de");
    expect(de?.status).toBe("uploaded");
    expect(de?.candidate?.origin).toBe("data_dir");
    expect(de?.candidate?.uploaded_by).toMatchObject({ kind: "system" });

    await openLanguagesPage(page);
    await expect(withKey(page.getByTestId("grid-languages"), "row", "de")).toHaveAttribute("data-status", "uploaded");
  });
});
