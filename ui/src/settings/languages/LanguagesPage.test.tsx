import { createMemoryHistory, MemoryRouter } from "@solidjs/router";
import { fireEvent, render, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "../../api/problem";
import { seedPack } from "../../api/mock/i18n-store";
import { resetMockDb } from "../../api/mock/db";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { buildRoutes, Root } from "../../App";
import { alex } from "../../auth/account/testkit";
import { loadSession, setSessionForTest } from "../../auth/session";
import { isAvailable, loadPacks, locale, setLocale } from "../../i18n";
import { currentPreview, resetLanguagesForTest } from "../../i18n/remote";
import { SETTINGS_PATH, signInAs } from "../testkit";
import { activatePack, previewPack, uploadPack } from "./api";
import LanguagesPage from "./LanguagesPage";

beforeEach(async () => {
  await loadPacks(["settings", "languages"]);
  await signInAs();
});

afterEach(async () => {
  setSessionForTest(null);
  await resetLanguagesForTest();
  await setLocale("en");
});

/** A minimal XLIFF 2.0 pack; a unit with an empty target is untranslated. */
function xliff(tag: string, units: Record<string, string>, options: { version?: string; name?: string } = {}): string {
  const rows = Object.entries(units).map(
    ([id, target]) => `    <unit id="${id}"><segment><source>x</source><target>${target}</target></segment></unit>`,
  );
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<xliff xmlns="urn:oasis:names:tc:xliff:document:2.0" xmlns:mda="urn:oasis:names:tc:xliff:metadata:2.0" version="${options.version ?? "2.0"}" srcLang="en" trgLang="${tag}">`,
    '  <file id="f">',
    '    <mda:metadata><mda:metaGroup category="language-pack">',
    `      <mda:meta type="displayName">${options.name ?? "Francais"}</mda:meta>`,
    '      <mda:meta type="author">Example Translators</mda:meta>',
    '      <mda:meta type="version">1.0.0</mda:meta>',
    "    </mda:metaGroup></mda:metadata>",
    ...rows,
    "  </file>",
    "</xliff>",
  ].join("\n");
}

/** Two of four messages translated. */
const PARTIAL = xliff("fr", {
  "common.action.cancel": "Annuler",
  "common.action.save": "Enregistrer",
  "common.action.close": "",
  "common.action.edit": "",
});

async function openPage() {
  const view = renderRoute(LanguagesPage, { url: "/settings/languages", path: SETTINGS_PATH });
  await screen.findAllByTestId("row");
  return view;
}

function row(tag: string): HTMLElement {
  const el = document.querySelector<HTMLElement>(`tr[data-testid="row"][data-key="${tag}"]`);
  if (!el) throw new Error(`no row for ${tag}`);
  return el;
}

function chooseFile(document: string, name = "pack.xlf") {
  const input = screen.getByTestId("field-file") as HTMLInputElement;
  fireEvent.change(input, { target: { files: [new File([document], name, { type: "application/xliff+xml" })] } });
}

/** Uploads through the page and waits for the report. */
async function uploadThroughPage(document: string) {
  chooseFile(document);
  fireEvent.click(screen.getByTestId("languages-upload"));
  return screen.findByTestId("languages-report");
}

/** A pack that is the active version of its language, put there through the API. */
async function activeThroughApi(document: string, tag: string) {
  await uploadPack(new File([document], `${tag}.xlf`));
  await previewPack(tag);
  await activatePack(tag);
}

describe("the languages page", () => {
  it("lists English and Swedish as built-in rows", async () => {
    await openPage();
    const rows = screen.getAllByTestId("row");
    expect(rows.map((r) => r.dataset["key"])).toEqual(["en", "sv"]);
    for (const tag of ["en", "sv"]) {
      expect(row(tag).dataset["status"]).toBe("built_in");
      const badge = within(row(tag)).getByTestId("status-badge");
      expect(badge.dataset["status"]).toBe("built_in");
      expect(badge.textContent).toBe("Built in");
      expect(within(row(tag)).getByText("Built-in texts")).toBeTruthy();
      // A built-in language without an uploaded version has nothing to remove or revert.
      expect(within(row(tag)).queryByTestId("languages-revert")).toBeNull();
      expect(within(row(tag)).queryByTestId("languages-remove")).toBeNull();
    }
    expect(within(row("sv")).getByText("Svenska")).toBeTruthy();
  });

  it("links the template to the API", async () => {
    await openPage();
    const link = screen.getByTestId("languages-template") as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/api/v1/i18n/template.xlf");
    expect(link.textContent).toBe("Download template");
    const swedish = within(row("sv")).getByTestId("languages-template-language");
    expect(swedish.getAttribute("href")).toBe("/api/v1/i18n/template.xlf?language=sv");
  });

  it("keeps the upload button off until a file is chosen", async () => {
    await openPage();
    const button = screen.getByTestId("languages-upload") as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    chooseFile(PARTIAL);
    expect(button.disabled).toBe(false);
  });

  it("uploads a valid partial pack, shows its report and a candidate row", async () => {
    await openPage();
    const report = await uploadThroughPage(PARTIAL);
    expect(report.dataset["key"]).toBe("fr");
    const complete = within(report).getByTestId("languages-report-complete");
    expect(complete.dataset["percent"]).toBe("50");
    expect(complete.dataset["translated"]).toBe("2");
    expect(complete.dataset["total"]).toBe("4");
    expect(complete.textContent).toContain("2 of 4 messages translated");
    expect(within(report).getByTestId("languages-report-missing").dataset["count"]).toBe("2");
    expect(within(report).getByTestId("languages-report-clean")).toBeTruthy();
    expect(await screen.findByText("Francais uploaded: 50 percent translated")).toBeTruthy();

    await waitFor(() => expect(screen.getAllByTestId("row").map((r) => r.dataset["key"])).toEqual(["en", "sv", "fr"]));
    expect(row("fr").dataset["status"]).toBe("uploaded");
    expect(within(row("fr")).getByTestId("status-badge").textContent).toBe("Uploaded");
    expect(within(row("fr")).getByTestId("languages-previewed").dataset["state"]).toBe("waiting");
    // The chosen file is cleared once it is sent.
    expect((screen.getByTestId("languages-upload") as HTMLButtonElement).disabled).toBe(true);
  });

  it("refuses a pack of the wrong version with one problem", async () => {
    await openPage();
    chooseFile(xliff("fr", { "common.action.cancel": "Annuler" }, { version: "1.2" }));
    fireEvent.click(screen.getByTestId("languages-upload"));
    const list = await screen.findByTestId("languages-refusal");
    const problems = within(list).getAllByTestId("languages-refusal-problem");
    expect(problems).toHaveLength(1);
    expect(problems[0]?.dataset["code"]).toBe("i18n.pack.version");
    expect(screen.queryByTestId("languages-report")).toBeNull();
    expect(screen.getAllByTestId("row")).toHaveLength(2);
  });

  it("refuses a pack of inline markup with one problem per unit", async () => {
    await openPage();
    chooseFile(
      xliff("fr", { "common.action.cancel": "<b>Annuler</b>", "common.action.save": "Enreg<br/>istrer" }),
    );
    fireEvent.click(screen.getByTestId("languages-upload"));
    const list = await screen.findByTestId("languages-refusal");
    const problems = within(list).getAllByTestId("languages-refusal-problem");
    // The pack translates nothing, then one problem for each unit with markup.
    expect(problems.map((p) => p.dataset["code"])).toEqual(["i18n.pack.empty", "i18n.pack.markup", "i18n.pack.markup"]);
    expect(problems.map((p) => p.dataset["key"])).toEqual(["file", "common.action.cancel", "common.action.save"]);
    expect(within(problems[1] as HTMLElement).getByText(/^line \d+$/)).toBeTruthy();
    expect(screen.getAllByTestId("row")).toHaveLength(2);
  });

  it("clears a refusal when another file is chosen", async () => {
    await openPage();
    chooseFile(xliff("fr", { "common.action.cancel": "Annuler" }, { version: "1.2" }));
    fireEvent.click(screen.getByTestId("languages-upload"));
    await screen.findByTestId("languages-refusal");
    chooseFile(PARTIAL);
    expect(screen.queryByTestId("languages-refusal")).toBeNull();
  });

  it("requires a preview before the pack can be activated", async () => {
    await openPage();
    await uploadThroughPage(PARTIAL);
    await waitFor(() => expect(document.querySelector('tr[data-key="fr"]')).toBeTruthy());
    const activate = within(row("fr")).getByTestId("languages-activate") as HTMLButtonElement;
    expect(activate.disabled).toBe(true);
    expect(activate.title).toBe("Preview the uploaded version first");
    fireEvent.click(activate);
    expect(screen.queryByRole("dialog")).toBeNull();

    // The server holds the same rule: activating without a preview is a 409.
    const error = await activatePack("fr").catch((err: unknown) => err);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(409);
    expect((error as ApiError).code).toBe("i18n.pack.not_previewed");
  });

  it("previews the pack in this tab, then activates it through the confirm dialog", async () => {
    await openPage();
    await uploadThroughPage(PARTIAL);
    await waitFor(() => expect(document.querySelector('tr[data-key="fr"]')).toBeTruthy());

    fireEvent.click(within(row("fr")).getByTestId("languages-preview"));
    expect(await screen.findByText("Previewing Francais in this tab")).toBeTruthy();
    await waitFor(() => expect(currentPreview()).toEqual({ tag: "fr", name: "Francais" }));
    expect(locale()).toBe("fr");
    await waitFor(() => expect(row("fr").dataset["status"]).toBe("previewed"));
    expect(within(row("fr")).getByTestId("languages-previewed").dataset["state"]).toBe("previewed");
    const activate = within(row("fr")).getByTestId("languages-activate") as HTMLButtonElement;
    expect(activate.disabled).toBe(false);

    fireEvent.click(activate);
    const dialog = await screen.findByTestId("dialog-activate");
    expect(within(dialog).getByText("Activate Francais?")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));

    await waitFor(() => expect(screen.queryByTestId("dialog-activate")).toBeNull());
    await waitFor(() => expect(row("fr").dataset["status"]).toBe("active"));
    expect(within(row("fr")).getByTestId("status-badge").textContent).toBe("Active");
    expect(within(row("fr")).queryByTestId("languages-activate")).toBeNull();
    expect(within(row("fr")).getByTestId("languages-remove")).toBeTruthy();
    // The preview ended with the activation and the language is registered for everyone.
    expect(currentPreview()).toBeUndefined();
    expect(isAvailable("fr")).toBe(true);
    expect(await screen.findByText("Francais is active")).toBeTruthy();
  });

  it("discards a candidate", async () => {
    await openPage();
    await uploadThroughPage(PARTIAL);
    await waitFor(() => expect(document.querySelector('tr[data-key="fr"]')).toBeTruthy());

    fireEvent.click(within(row("fr")).getByTestId("languages-discard"));
    const dialog = await screen.findByTestId("dialog-discard");
    expect(within(dialog).getByText("Discard the uploaded version of Francais?")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));

    await waitFor(() => expect(document.querySelector('tr[data-key="fr"]')).toBeNull());
    expect(screen.getAllByTestId("row").map((r) => r.dataset["key"])).toEqual(["en", "sv"]);
    // The report of the discarded pack closes with it.
    expect(screen.queryByTestId("languages-report")).toBeNull();
    expect(await screen.findByText("The uploaded version of Francais was discarded")).toBeTruthy();
  });

  it("keeps the dialog open and says so when the candidate is gone", async () => {
    await openPage();
    await uploadThroughPage(PARTIAL);
    await waitFor(() => expect(document.querySelector('tr[data-key="fr"]')).toBeTruthy());
    fireEvent.click(within(row("fr")).getByTestId("languages-discard"));
    const dialog = await screen.findByTestId("dialog-discard");
    // Another administrator discarded it first.
    resetMockDb("signed-in");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    expect(await within(dialog).findByTestId("error-notice")).toBeTruthy();
  });

  it("removes a language that is not built in", async () => {
    await activeThroughApi(PARTIAL, "fr");
    await openPage();
    expect(row("fr").dataset["status"]).toBe("active");
    expect(within(row("fr")).queryByTestId("languages-revert")).toBeNull();

    fireEvent.click(within(row("fr")).getByTestId("languages-remove"));
    const dialog = await screen.findByTestId("dialog-remove");
    expect(within(dialog).getByText("Remove Francais?")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));

    await waitFor(() => expect(document.querySelector('tr[data-key="fr"]')).toBeNull());
    expect(await screen.findByText("Francais was removed")).toBeTruthy();
    expect(screen.getAllByTestId("row").map((r) => r.dataset["key"])).toEqual(["en", "sv"]);
  });

  it("reverts an overridden built-in language to its own texts", async () => {
    seedPack({ tag: "sv", name: "Svenska", messages: { "common.action.cancel": "Ångra" } });
    await openPage();
    expect(row("sv").dataset["status"]).toBe("active");
    expect(within(row("sv")).queryByTestId("languages-remove")).toBeNull();

    fireEvent.click(within(row("sv")).getByTestId("languages-revert"));
    const dialog = await screen.findByTestId("dialog-remove");
    expect(within(dialog).getByText("Revert Svenska to its built-in texts?")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));

    await waitFor(() => expect(row("sv").dataset["status"]).toBe("built_in"));
    expect(within(row("sv")).queryByTestId("languages-revert")).toBeNull();
    // A built-in language stays in the list.
    expect(screen.getAllByTestId("row").map((r) => r.dataset["key"])).toEqual(["en", "sv"]);
    expect(await screen.findByText("Svenska uses its built-in texts again")).toBeTruthy();
  });

  it("opens the report of a language on demand and closes it", async () => {
    seedPack({ tag: "fr", name: "Francais", messages: { "common.action.cancel": "Annuler" }, total: 4 });
    await openPage();
    expect(screen.queryByTestId("languages-report")).toBeNull();
    fireEvent.click(within(row("fr")).getByTestId("languages-report-open"));
    const report = await screen.findByTestId("languages-report");
    expect(within(report).getByTestId("languages-report-complete").dataset["percent"]).toBe("25");
    fireEvent.click(within(report).getByTestId("languages-report-close"));
    expect(screen.queryByTestId("languages-report")).toBeNull();
  });

  it("has no accessibility violations: the page with a candidate and a report, and a dialog", async () => {
    await activeThroughApi(PARTIAL, "fr");
    seedPack({ tag: "sv", name: "Svenska", messages: { "common.action.cancel": "Ångra" } });
    const view = await openPage();
    await uploadThroughPage(xliff("de", { "common.action.cancel": "Abbrechen" }, { name: "Deutsch" }));
    await waitFor(() => expect(document.querySelector('tr[data-key="de"]')).toBeTruthy());
    expect(await axeViolations(view.container)).toEqual([]);

    fireEvent.click(within(row("fr")).getByTestId("languages-remove"));
    const dialog = await screen.findByRole("dialog");
    expect(await axeViolations(dialog)).toEqual([]);
  });
});

describe("the languages page for other roles", () => {
  async function renderApp(url: string, roles: string[]) {
    resetMockDb("signed-in");
    alex().roles = roles as never;
    setSessionForTest(null, "loading");
    const history = createMemoryHistory();
    history.set({ value: url });
    const result = render(() => (
      <MemoryRouter history={history} root={Root}>
        {buildRoutes()}
      </MemoryRouter>
    ));
    await loadSession();
    return result;
  }

  for (const role of ["operator", "viewer", "auditor"]) {
    it(`is forbidden to ${role}`, async () => {
      await renderApp("/settings/languages", [role]);
      expect(await screen.findByText("Administrators only", {}, { timeout: 5000 })).toBeTruthy();
      expect(screen.queryByTestId("page-languages")).toBeNull();
      expect(screen.queryByTestId("settings-nav")).toBeNull();
    });
  }

  it("shows the server's refusal when the page is rendered without the route guard", async () => {
    alex().roles = ["viewer"] as never;
    renderRoute(LanguagesPage, { url: "/settings/languages", path: SETTINGS_PATH });
    const notice = await screen.findByTestId("error-notice");
    expect(notice.getAttribute("data-code")).toBe("auth.forbidden");
    expect(screen.queryAllByTestId("row")).toHaveLength(0);
  });
});
