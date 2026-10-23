// The negative trust anchors of the recursion page (WP10.4, RFC 7646): the empty state, creating
// one (the local checks of the zone, the lifetime and the reason, the refusals of the server, the
// expiry the lifetime makes), the rows in the order of their expiry, a row past its expiry, the
// deletion after a confirmation, what a viewer sees, Swedish, and no accessibility violations.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { server } from "../../api/mock/node";
import { dnsAnchorsState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { resetToasts, signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { recordWrites } from "../testkit";
import type { NtaItem } from "./anchors";
import RecursionPage from "./RecursionPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  resetToasts();
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(RecursionPage, { url: "/dns/recursion", path: "/dns/recursion" });

const DAY = 86_400_000;
const PROBLEM = { type: "about:blank", params: {} };

function nta(id: number, zone: string, expiresInMs: number, reason = "The operator broke the signatures"): NtaItem {
  return {
    id: `0190d1c2-0000-7000-8000-00000000be${String(id).padStart(2, "0")}`,
    zone,
    reason,
    created_at: new Date(Date.now() - DAY).toISOString(),
    created_by: { kind: "system", component: "api" },
    expires_at: new Date(Date.now() + expiresInMs).toISOString(),
    revision: 1,
  } as NtaItem;
}

const rows = () => screen.queryAllByTestId("dns-nta");
const zones = () => rows().map((r) => r.dataset.key);

function row(zone: string): HTMLElement {
  const found = rows().find((r) => r.dataset.key === zone);
  if (!found) throw new Error(`no row ${zone}: ${zones().join(", ")}`);
  return found;
}

async function openAdd(): Promise<HTMLElement> {
  fireEvent.click(await screen.findByTestId("dns-nta-add"));
  return screen.findByTestId("dialog-nta-add");
}

function fieldError(dialog: HTMLElement, field: string): string | undefined {
  return dialog.querySelector(`[data-testid="field-error"][data-field="${field}"]`)?.textContent ?? undefined;
}

function fill(dialog: HTMLElement, values: { zone?: string; lifetime?: string; reason?: string }) {
  if (values.zone !== undefined) fireEvent.input(within(dialog).getByTestId("field-nta-zone"), { target: { value: values.zone } });
  if (values.lifetime !== undefined) fireEvent.input(within(dialog).getByTestId("field-nta-lifetime"), { target: { value: values.lifetime } });
  if (values.reason !== undefined) fireEvent.input(within(dialog).getByTestId("field-nta-reason"), { target: { value: values.reason } });
}

function paths(calls: { method: string; url: string }[]): string[] {
  return calls.map((call) => `${call.method} ${new URL(call.url, "http://x").pathname}`);
}

describe("the negative trust anchors", () => {
  it("says there are none at first, and that every signed zone is validated", async () => {
    const view = open();
    const none = await screen.findByTestId("dns-nta-none");
    expect(none.textContent).toBe("No negative trust anchor: every signed zone is validated.");
    expect(screen.queryByTestId("dns-nta-table")).toBeNull();
    expect(screen.getByTestId("dns-nta-add").textContent).toBe("Add a negative trust anchor");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("lists the anchors by their expiry with the reason, the time left and who created them", async () => {
    dnsAnchorsState().ntas.push(nta(1, "later.example.test", 5 * DAY, "Waiting for the zone's operator"), nta(2, "sooner.example.test", 2 * DAY, "The signatures expired"));
    const view = open();
    await waitFor(() => expect(zones()).toEqual(["sooner.example.test", "later.example.test"]));
    const sooner = row("sooner.example.test");
    expect(sooner.dataset.state).toBe("active");
    expect(within(sooner).getByTestId("dns-nta-expires").textContent).toMatch(/2 days/);
    expect(within(sooner).getByTestId("dns-nta-expires").getAttribute("title")).toBeTruthy();
    expect(within(sooner).getAllByRole("cell")[2]?.textContent).toBe("The signatures expired");
    expect(within(row("later.example.test")).getByTestId("dns-nta-expires").textContent).toMatch(/5 days/);
    expect(within(sooner).queryByTestId("dns-nta-expired")).toBeNull();
    expect(screen.queryByTestId("dns-nta-none")).toBeNull();
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent).filter((t) => t !== "")).toContain("Reason");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows an anchor past its expiry as expired until the server removes it", async () => {
    // The server removes an expired anchor shortly after its expiry; a read in that moment sees it.
    const past = nta(3, "gone.example.test", -60_000);
    server.use(http.get("/api/v1/dns/ntas", () => HttpResponse.json({ items: [past, nta(4, "kept.example.test", DAY)], revision: 1, next_cursor: null })));
    open();
    await waitFor(() => expect(zones()).toEqual(["gone.example.test", "kept.example.test"]));
    const gone = row("gone.example.test");
    expect(gone.dataset.state).toBe("expired");
    expect(within(gone).getByTestId("dns-nta-expired").textContent).toBe("Expired");
    expect(row("kept.example.test").dataset.state).toBe("active");
  });

  it("turns a row to expired when its time passes while the page is open", async () => {
    dnsAnchorsState().ntas.push(nta(5, "soon.example.test", 1_300));
    open();
    await waitFor(() => expect(zones()).toEqual(["soon.example.test"]));
    expect(row("soon.example.test").dataset.state).toBe("active");
    await waitFor(() => expect(row("soon.example.test").dataset.state).toBe("expired"), { timeout: 4000 });
    expect(within(row("soon.example.test")).getByTestId("dns-nta-expired")).toBeTruthy();
  });
});

describe("creating a negative trust anchor", () => {
  it("asks for the zone, a lifetime of one day to begin with, and the reason", async () => {
    open();
    const dialog = await openAdd();
    expect(within(dialog).getByRole("heading", { level: 2 }).textContent).toBe("Add a negative trust anchor");
    expect((within(dialog).getByTestId("field-nta-zone") as HTMLInputElement).value).toBe("");
    expect((within(dialog).getByTestId("field-nta-lifetime") as HTMLInputElement).value).toBe("1d");
    expect((within(dialog).getByTestId("field-nta-reason") as HTMLTextAreaElement).value).toBe("");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("form-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-nta-add")).toBeNull());
  });

  it("checks the zone, the lifetime and the reason before it sends anything", async () => {
    const writes = recordWrites();
    open();
    const dialog = await openAdd();
    fill(dialog, { lifetime: "8d" });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["nta-zone", "nta-expires", "nta-reason"]));
    expect(fieldError(dialog, "nta-zone")).toBe("Enter the name of the zone.");
    expect(fieldError(dialog, "nta-expires")).toBe("Enter a lifetime of at most seven days, such as 12h or 2d.");
    expect(fieldError(dialog, "nta-reason")).toBe("Say why the zone is exempted.");
    expect(within(dialog).getByTestId("field-nta-lifetime").getAttribute("aria-invalid")).toBe("true");
    expect(writes()).toHaveLength(0);
    expect(await axeViolations(dialog)).toEqual([]);
  });

  it("refuses the root, a name that is not one, a lifetime of nothing and a reason that is too long", async () => {
    const writes = recordWrites();
    open();
    const dialog = await openAdd();
    fill(dialog, { zone: ".", lifetime: "0s", reason: "x".repeat(501) });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "nta-zone")).toBe("The root cannot be exempted from validation."));
    expect(fieldError(dialog, "nta-expires")).toContain("at most seven days");
    expect(fieldError(dialog, "nta-reason")).toBe("At most 500 characters.");
    fill(dialog, { zone: "not a name", lifetime: "x", reason: "fine" });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "nta-zone")).toBe("Enter the name of the zone."));
    expect(fieldError(dialog, "nta-reason")).toBeUndefined();
    expect(writes()).toHaveLength(0);
  });

  it("creates the anchor with an expiry the lifetime gives and lists it", async () => {
    const writes = recordWrites();
    open();
    await screen.findByTestId("dns-nta-none");
    const dialog = await openAdd();
    const before = Date.now();
    fill(dialog, { zone: " Broken.Example.Test. ", lifetime: "2d", reason: "  The operator broke the signatures  " });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-nta-add")).toBeNull());
    const after = Date.now();
    expect((await screen.findByTestId("toast")).textContent).toContain("broken.example.test is exempted from validation until the anchor expires");
    const posts = writes();
    expect(paths(posts)).toEqual(["POST /api/v1/dns/ntas"]);
    const body = posts[0]?.body as { zone: string; expires_at: string; reason: string };
    expect(body.zone).toBe("broken.example.test");
    expect(body.reason).toBe("The operator broke the signatures");
    const expires = Date.parse(body.expires_at);
    expect(expires).toBeGreaterThanOrEqual(before + 2 * DAY);
    expect(expires).toBeLessThanOrEqual(after + 2 * DAY);
    await waitFor(() => expect(zones()).toEqual(["broken.example.test"]));
    expect(row("broken.example.test").dataset.state).toBe("active");
    expect(within(row("broken.example.test")).getByTestId("dns-nta-expires").textContent).toMatch(/2 days/);
    expect(screen.queryByTestId("dns-nta-none")).toBeNull();
    expect(dnsAnchorsState().ntas).toHaveLength(1);
  });

  it("accepts a lifetime written in several units", async () => {
    const writes = recordWrites();
    open();
    const dialog = await openAdd();
    const before = Date.now();
    fill(dialog, { zone: "lab.example.test", lifetime: "1d12h", reason: "Testing" });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-nta-add")).toBeNull());
    const expires = Date.parse((writes()[0]?.body as { expires_at: string }).expires_at);
    expect(expires - before).toBeGreaterThanOrEqual(36 * 3_600_000);
    expect(expires - before).toBeLessThan(36 * 3_600_000 + 5_000);
  });

  it("shows the refusal of the server under the field it names", async () => {
    server.use(
      http.post("/api/v1/dns/ntas", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 400, code: "dns.nta.invalid", title: "Invalid", detail: "reason: a reason is required", params: { field: "reason", reason: "the reason is a placeholder" } },
          { status: 400, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    const dialog = await openAdd();
    fill(dialog, { zone: "lab.example.test", reason: "todo" });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "nta-reason")).toBe("the reason is a placeholder"));
    expect(within(dialog).queryByTestId("error-notice")).toBeNull();
    expect(screen.getByTestId("dialog-nta-add")).toBeTruthy();
  });

  it("shows a refusal of the expiry under the lifetime", async () => {
    server.use(
      http.post("/api/v1/dns/ntas", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 400, code: "dns.nta.invalid", title: "Invalid", detail: "expires_at: in the past", params: { field: "expires_at", reason: "in the past" } },
          { status: 400, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    const dialog = await openAdd();
    fill(dialog, { zone: "lab.example.test", reason: "Testing" });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "nta-expires")).toBe("in the past"));
  });

  it("shows another failure of the create as an error in the form", async () => {
    server.use(
      http.post("/api/v1/dns/ntas", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 500, code: "sys.internal", title: "Internal Server Error", detail: "the store failed" },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    const dialog = await openAdd();
    fill(dialog, { zone: "lab.example.test", reason: "Testing" });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByRole("alert")).toBeTruthy();
    expect((within(dialog).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("deleting a negative trust anchor", () => {
  it("deletes the anchor after a confirmation and says there are none left", async () => {
    const [kept, doomed] = [nta(6, "kept.example.test", 3 * DAY), nta(7, "doomed.example.test", DAY)];
    dnsAnchorsState().ntas.push(kept, doomed);
    const writes = recordWrites();
    open();
    await waitFor(() => expect(zones()).toEqual(["doomed.example.test", "kept.example.test"]));
    fireEvent.click(within(row("doomed.example.test")).getByTestId("dns-nta-delete"));
    const dialog = await screen.findByTestId("dialog-nta-delete");
    expect(dialog.textContent).toContain("Delete the negative trust anchor of doomed.example.test?");
    expect(dialog.textContent).toContain("Answers under doomed.example.test are validated again at once");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-nta-delete")).toBeNull());
    expect(writes()).toHaveLength(0);
    fireEvent.click(within(row("doomed.example.test")).getByTestId("dns-nta-delete"));
    fireEvent.click(within(await screen.findByTestId("dialog-nta-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(zones()).toEqual(["kept.example.test"]));
    expect(paths(writes())).toEqual([`DELETE /api/v1/dns/ntas/${doomed.id}`]);
    expect((await screen.findByTestId("toast")).textContent).toContain("The negative trust anchor of doomed.example.test was deleted");
    fireEvent.click(within(row("kept.example.test")).getByTestId("dns-nta-delete"));
    fireEvent.click(within(await screen.findByTestId("dialog-nta-delete")).getByTestId("confirm-ok"));
    expect(await screen.findByTestId("dns-nta-none")).toBeTruthy();
  });

  it("deletes an expired row as well", async () => {
    const past = nta(8, "gone.example.test", -60_000);
    dnsAnchorsState().ntas.push(past);
    server.use(http.get("/api/v1/dns/ntas", () => HttpResponse.json({ items: dnsAnchorsState().ntas, revision: 1, next_cursor: null })));
    open();
    await waitFor(() => expect(zones()).toEqual(["gone.example.test"]));
    expect(row("gone.example.test").dataset.state).toBe("expired");
    fireEvent.click(within(row("gone.example.test")).getByTestId("dns-nta-delete"));
    fireEvent.click(within(await screen.findByTestId("dialog-nta-delete")).getByTestId("confirm-ok"));
    expect(await screen.findByTestId("dns-nta-none")).toBeTruthy();
  });

  it("shows a refusal of the deletion in the dialog", async () => {
    dnsAnchorsState().ntas.push(nta(9, "lab.example.test", DAY));
    server.use(
      http.delete("/api/v1/dns/ntas/:id", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 404, code: "dns.nta.not_found", title: "Not found", detail: "no such anchor", params: { id: "x" } },
          { status: 404, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await waitFor(() => expect(zones()).toEqual(["lab.example.test"]));
    fireEvent.click(within(row("lab.example.test")).getByTestId("dns-nta-delete"));
    const dialog = await screen.findByTestId("dialog-nta-delete");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    expect(await within(dialog).findByRole("alert")).toBeTruthy();
    expect(zones()).toEqual(["lab.example.test"]);
  });
});

describe("who may change the negative trust anchors", () => {
  it("shows a viewer the anchors without a button or an actions column", async () => {
    await signInWithRoles(["viewer"]);
    dnsAnchorsState().ntas.push(nta(10, "lab.example.test", DAY));
    open();
    await waitFor(() => expect(zones()).toEqual(["lab.example.test"]));
    expect(screen.queryByTestId("dns-nta-add")).toBeNull();
    expect(screen.queryAllByTestId("dns-nta-delete")).toHaveLength(0);
    expect(within(screen.getByTestId("dns-nta-table")).getAllByRole("columnheader")).toHaveLength(4);
  });

  it("holds the buttons back from an operator, who does not hold the keys", async () => {
    await signInWithRoles(["operator"]);
    dnsAnchorsState().ntas.push(nta(11, "lab.example.test", DAY));
    open();
    await waitFor(() => expect(zones()).toEqual(["lab.example.test"]));
    expect(screen.queryByTestId("dns-nta-add")).toBeNull();
    expect(screen.queryAllByTestId("dns-nta-delete")).toHaveLength(0);
  });

  it("gives an administrator the column of actions", async () => {
    dnsAnchorsState().ntas.push(nta(12, "lab.example.test", DAY));
    open();
    await waitFor(() => expect(zones()).toEqual(["lab.example.test"]));
    expect(within(screen.getByTestId("dns-nta-table")).getAllByRole("columnheader")).toHaveLength(5);
  });
});

describe("the language", () => {
  it("speaks Swedish", async () => {
    await setLocale("sv");
    dnsAnchorsState().ntas.push(nta(13, "gone.example.test", -60_000));
    server.use(http.get("/api/v1/dns/ntas", () => HttpResponse.json({ items: dnsAnchorsState().ntas, revision: 1, next_cursor: null })));
    open();
    await waitFor(() => expect(zones()).toEqual(["gone.example.test"]));
    expect(screen.getByRole("heading", { level: 2, name: "Negativa förtroendeankare" })).toBeTruthy();
    expect(within(row("gone.example.test")).getByTestId("dns-nta-expired").textContent).toBe("Utgånget");
    expect(within(row("gone.example.test")).getByTestId("dns-nta-delete").textContent).toBe("Radera");
    fireEvent.click(screen.getByTestId("dns-nta-add"));
    const dialog = await screen.findByTestId("dialog-nta-add");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "nta-zone")).toBe("Ange zonens namn."));
    expect(fieldError(dialog, "nta-reason")).toBe("Ange varför zonen undantas.");
  });
});
