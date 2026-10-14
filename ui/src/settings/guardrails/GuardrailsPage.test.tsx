import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { db } from "../../api/mock/db";
import { server } from "../../api/mock/node";
import { guardrailsState } from "../../api/mock/routes-guardrails";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { signInAs } from "../testkit";
import GuardrailsPage from "./GuardrailsPage";
import { normalizeMac, parallelOf, pathKey, pathOfDraft, wholeNumber, EMPTY_DRAFT } from "./model";

const NO_SHELL = { disable: ["region"] } as const;

beforeEach(async () => {
  await setLocale("en");
  await signInAs();
});

afterEach(() => setSessionForTest(null));

async function openPage() {
  const view = renderRoute(GuardrailsPage, { url: "/settings/guardrails", path: "/settings/guardrails" });
  await screen.findByTestId("guardrails-form");
  return view;
}

const save = () => fireEvent.click(screen.getByTestId("form-submit"));

async function addPath(kind: string, fields: Record<string, string>) {
  fireEvent.click(screen.getByTestId("guardrails-add"));
  const dialog = await screen.findByTestId("dialog-guardrail-path");
  fireEvent.change(within(dialog).getByTestId("field-kind"), { target: { value: kind } });
  for (const [id, value] of Object.entries(fields)) {
    fireEvent.input(await within(dialog).findByTestId(`field-${id}`), { target: { value } });
  }
  fireEvent.click(within(dialog).getByTestId("form-submit"));
  return dialog;
}

describe("the guardrails page", () => {
  it("shows the default: ten parallel writes, no paths and the note about uplinks", async () => {
    await openPage();
    expect((screen.getByTestId("field-max_parallel") as HTMLInputElement).value).toBe("10");
    expect(screen.getByTestId("guardrails-empty")).toBeTruthy();
    expect(screen.getByTestId("guardrails-note").textContent).toContain("Uplinks and the management path are always protected");
    expect(document.getElementById("gr-parallel-limits")?.textContent).toBe("1 to 64, default 10");
  });

  it("adds a VLAN and a client, and saves both with the revision of the read", async () => {
    await openPage();
    await addPath("vlan", { vid: "30" });
    await waitFor(() => expect(screen.queryByTestId("dialog-guardrail-path")).toBeNull());
    await addPath("client", { mac: "00-00-5E-00-53-01" });
    await waitFor(() => expect(screen.getAllByTestId("guardrail-path")).toHaveLength(2));
    // Nothing is sent before Save.
    expect(guardrailsState.guardrails.protected).toEqual([]);
    save();
    await waitFor(() => expect(guardrailsState.guardrails.protected).toHaveLength(2));
    expect(guardrailsState.guardrails.protected).toEqual([
      { type: "vlan", vid: 30 },
      { type: "client", mac: "00:00:5e:00:53:01" },
    ]);
    const rows = await screen.findAllByTestId("guardrail-path");
    expect(rows.map((r) => r.getAttribute("data-key"))).toEqual(["vlan:30", "client:00:00:5e:00:53:01"]);
  });

  it("adds a port and a network by their identifiers", async () => {
    await openPage();
    await addPath("port", { device: "switch-1.example.test", port: "12" });
    await waitFor(() => expect(screen.queryByTestId("dialog-guardrail-path")).toBeNull());
    await addPath("network", { network: "net-lab" });
    await waitFor(() => expect(screen.getAllByTestId("guardrail-path")).toHaveLength(2));
    expect(screen.getAllByTestId("guardrail-path")[0]?.textContent).toContain("switch-1.example.test, port 12");
    save();
    await waitFor(() => expect(guardrailsState.guardrails.protected).toHaveLength(2));
  });

  it("removes one path and saves the other alone", async () => {
    guardrailsState.guardrails = { max_parallel: 10, protected: [{ type: "vlan", vid: 30 }, { type: "vlan", vid: 40 }] };
    await openPage();
    const rows = screen.getAllByTestId("guardrail-path");
    fireEvent.click(within(rows[0] as HTMLElement).getByTestId("guardrail-remove"));
    expect(screen.getAllByTestId("guardrail-path")).toHaveLength(1);
    expect(document.activeElement).toBe(screen.getByTestId("guardrails-add"));
    save();
    await waitFor(() => expect(guardrailsState.guardrails.protected).toEqual([{ type: "vlan", vid: 40 }]));
  });

  it("refuses wrong fields in the dialog and keeps it open", async () => {
    await openPage();
    const dialog = await addPath("vlan", { vid: "4095" });
    expect(within(dialog).getByTestId("field-error").getAttribute("data-field")).toBe("vid");
    fireEvent.change(within(dialog).getByTestId("field-kind"), { target: { value: "client" } });
    fireEvent.input(await within(dialog).findByTestId("field-mac"), { target: { value: "00:00:5e:00:53" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(within(dialog).getByTestId("field-error").getAttribute("data-field")).toBe("mac");
    expect(screen.queryAllByTestId("guardrail-path")).toHaveLength(0);
  });

  it("refuses a path that is already listed", async () => {
    guardrailsState.guardrails = { max_parallel: 10, protected: [{ type: "vlan", vid: 30 }] };
    await openPage();
    const dialog = await addPath("vlan", { vid: "30" });
    expect(within(dialog).getByTestId("guardrails-duplicate")).toBeTruthy();
    expect(screen.getAllByTestId("guardrail-path")).toHaveLength(1);
  });

  it("refuses max_parallel outside 1 to 64 before anything is sent", async () => {
    await openPage();
    fireEvent.input(screen.getByTestId("field-max_parallel"), { target: { value: "0" } });
    expect(screen.getByTestId("field-error").getAttribute("data-field")).toBe("max_parallel");
    save();
    expect(guardrailsState.guardrails.max_parallel).toBe(10);
    fireEvent.input(screen.getByTestId("field-max_parallel"), { target: { value: "65" } });
    expect(screen.getByTestId("field-error")).toBeTruthy();
    fireEvent.input(screen.getByTestId("field-max_parallel"), { target: { value: "20" } });
    save();
    await waitFor(() => expect(guardrailsState.guardrails.max_parallel).toBe(20));
  });

  it("reloads with a notice when someone else saved first", async () => {
    await openPage();
    guardrailsState.guardrails = { max_parallel: 4, protected: [{ type: "vlan", vid: 99 }] };
    guardrailsState.revision = db.revision + 10;
    fireEvent.input(screen.getByTestId("field-max_parallel"), { target: { value: "12" } });
    save();
    expect(await screen.findByTestId("guardrails-reloaded")).toBeTruthy();
    await waitFor(() => expect((screen.getByTestId("field-max_parallel") as HTMLInputElement).value).toBe("4"));
    expect(screen.getAllByTestId("guardrail-path")).toHaveLength(1);
    expect(guardrailsState.guardrails.max_parallel).toBe(4);
  });

  it("shows the refusal of a save by its code and field", async () => {
    await openPage();
    server.use(
      http.put("/api/v1/settings/guardrails", () =>
        HttpResponse.json(
          { type: "about:blank", status: 422, code: "connect.guardrails.invalid", title: "x", detail: "x", params: { field: "protected[0]" } },
          { status: 422, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    save();
    const notice = await screen.findByTestId("error-notice");
    expect(notice.getAttribute("data-code")).toBe("connect.guardrails.invalid");
    expect(notice.textContent).toBe("The server refused protected[0]. Check the value and try again.");
  });

  it("has no accessibility violations, with and without the dialog, and works in Swedish", async () => {
    const view = await openPage();
    expect(await axeViolations(view.container, NO_SHELL)).toEqual([]);
    fireEvent.click(screen.getByTestId("guardrails-add"));
    const dialog = await screen.findByTestId("dialog-guardrail-path");
    expect(await axeViolations(dialog, NO_SHELL)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("form-cancel"));
    await setLocale("sv");
    await waitFor(() => expect(screen.getByTestId("page-guardrails").textContent).toContain("Parallella skrivningar"));
    expect(document.getElementById("gr-parallel-limits")?.textContent).toBe("1 till 64, standard 10");
  });
});

describe("the guardrails model", () => {
  it("normalizes a MAC and refuses anything that is not six pairs", () => {
    expect(normalizeMac("00-00-5E-00-53-01")).toBe("00:00:5e:00:53:01");
    expect(normalizeMac("0000.5e00.5301")).toBe("00:00:5e:00:53:01");
    expect(normalizeMac("00:00:5e:00:53")).toBeNull();
    expect(normalizeMac("00:00:5e:00:53:0g")).toBeNull();
  });

  it("reads whole numbers in a range", () => {
    expect(wholeNumber("4094", 1, 4094)).toBe(4094);
    expect(wholeNumber("4095", 1, 4094)).toBeNull();
    expect(wholeNumber("1.5", 1)).toBeNull();
    expect(wholeNumber("", 0)).toBeNull();
    expect(parallelOf("64")).toBe(64);
    expect(parallelOf("0")).toBeNull();
  });

  it("builds the path of a draft, trims references and keys paths apart", () => {
    const port = pathOfDraft({ ...EMPTY_DRAFT, kind: "port", device: " sw1.example.test ", port: "3" });
    expect(port).toEqual({ path: { type: "port", device: "sw1.example.test", port: 3 } });
    expect(pathKey({ type: "port", device: "sw1.example.test", port: 3 })).toBe("port:sw1.example.test/3");
    expect(pathOfDraft({ ...EMPTY_DRAFT, kind: "port", device: "", port: "x" })).toEqual({ errors: expect.objectContaining({ device: expect.any(String), port: expect.any(String) }) });
    expect(pathOfDraft({ ...EMPTY_DRAFT, kind: "network", network: "x".repeat(129) })).toHaveProperty("errors.network");
  });
});
