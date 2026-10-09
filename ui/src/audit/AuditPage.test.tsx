import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { appendAudit, AUDIT_SEED_IDS, audit, tamperAuditRecord } from "../api/mock/audit-store";
import { MOCK_USER_IDS } from "../api/mock/fixtures";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import AuditPage from "./AuditPage";
import { toRfc3339 } from "./filters";
import { bridgeMockEvents, scrollGridTo } from "./testkit";

// The view is rendered without the shell's <main>, which holds all page content in the app.
const NO_SHELL = { disable: ["region"] } as const;

let stopBridge: (() => void) | undefined;

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  setSessionForTest(null);
});

const rows = () => screen.queryAllByTestId("row");
const keys = () => rows().map((r) => r.getAttribute("data-key"));
const chain = () => screen.getByTestId("audit-chain");

async function openLog(url = "/audit", options: { live?: boolean } = {}) {
  await signInAlex();
  if (options.live) stopBridge = bridgeMockEvents();
  const view = renderRoute(AuditPage, { url, path: "/audit" });
  await screen.findByTestId("grid-audit");
  await waitFor(() => expect(rows().length).toBeGreaterThan(0));
  return { ...view, params: () => new URL(view.location(), "http://localhost").searchParams };
}

/** Sequence numbers of the seeded records for which `keep` holds, newest first. */
function expected(keep: (record: (typeof audit.records)[number]) => boolean): string[] {
  return audit.records
    .filter(keep)
    .map((r) => String(r.seq))
    .reverse();
}

describe("the audit log", () => {
  it("lists the records newest first with principal, action and outcome in words", async () => {
    await openLog();
    expect(keys()[0]).toBe("39");
    expect(keys()[1]).toBe("38");
    const first = rows()[0]!;
    expect(within(first).getByText("Alex Example (you)")).toBeTruthy();
    expect(within(first).getByText("ipam.host.update")).toBeTruthy();
    expect(within(first).getByText("Success")).toBeTruthy();
    expect(within(first).getByText(/Host/)).toBeTruthy();
    // A record by another user shows the name, a failed login the word Denied and its source.
    const sam = rows().find((r) => r.getAttribute("data-key") === "28")!;
    expect(await within(sam).findByText("Sam Example")).toBeTruthy();
    const denied = rows().find((r) => r.getAttribute("data-key") === "17")!;
    expect(within(denied).getByText("Denied")).toBeTruthy();
    expect(within(denied).getByText("auth.login.failure")).toBeTruthy();
    expect(within(denied).getByText("203.0.113.77")).toBeTruthy();
    expect(within(denied).getByText("Tenko (auth)")).toBeTruthy();
  });

  it("narrows the list with a filter in the URL and shows the filter in its field", async () => {
    await openLog("/audit?action=ipam.");
    const want = expected((r) => r.draft.action.startsWith("ipam."));
    await waitFor(() => expect(keys()).toEqual(want.slice(0, keys().length)));
    expect(keys().length).toBe(want.length);
    for (const row of rows()) expect(row.querySelector('td[data-col="action"]')?.textContent).toMatch(/^ipam\./);
    expect((screen.getByTestId("audit-filter-action") as HTMLInputElement).value).toBe("ipam.");
    expect(screen.getByTestId("audit-filter-clear")).toBeTruthy();
  });

  it("filters by outcome and shows the code of a failure", async () => {
    const view = await openLog("/audit");
    fireEvent.change(screen.getByTestId("audit-filter-outcome"), { target: { value: "failed" } });
    await waitFor(() => expect(keys()).toEqual(expected((r) => r.draft.outcome.kind === "failed")));
    expect(view.params().get("outcome")).toBe("failed");
    expect(screen.getByText("ipam.prefix.overlap")).toBeTruthy();
    expect(screen.getByText("jobs.step.failed")).toBeTruthy();
    for (const row of rows()) expect(within(row).getByText("Failed").closest(".outcome")?.getAttribute("data-outcome")).toBe("failed");
  });

  it("filters by outcome denied from the URL", async () => {
    await openLog("/audit?outcome=denied");
    await waitFor(() => expect(keys()).toEqual(expected((r) => r.draft.outcome.kind === "denied")));
    expect((screen.getByTestId("audit-filter-outcome") as HTMLSelectElement).value).toBe("denied");
  });

  it("switches the order and keeps it in the URL", async () => {
    const view = await openLog();
    expect(keys()[0]).toBe("39");
    const order = screen.getByTestId("audit-filter-order");
    fireEvent.click(within(order).getByRole("button", { name: "Oldest first" }));
    await waitFor(() => expect(keys()[0]).toBe("1"));
    expect(view.params().get("order")).toBe("asc");
    expect(within(order).getByRole("button", { name: "Oldest first" }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(within(order).getByRole("button", { name: "Newest first" }));
    await waitFor(() => expect(keys()[0]).toBe("39"));
    expect(view.params().has("order")).toBe(false);
  });

  it("applies a typed action filter to the URL and the list", async () => {
    const view = await openLog();
    fireEvent.input(screen.getByTestId("audit-filter-action"), { target: { value: "ipam.prefix." } });
    await waitFor(() => expect(view.params().get("action")).toBe("ipam.prefix."));
    await waitFor(() => expect(keys()).toEqual(expected((r) => r.draft.action.startsWith("ipam.prefix."))));
  });

  it("explains an action that cannot be a filter and does not send it", async () => {
    await openLog("/audit?action=Nonsense");
    expect(screen.getByText(/Use a full action such as ipam.prefix.create/)).toBeTruthy();
    expect(screen.getByTestId("audit-filter-action").getAttribute("aria-invalid")).toBe("true");
    // The list is not filtered and shows no request error.
    expect(keys()[0]).toBe("39");
    expect(screen.queryByText("The request was not accepted.")).toBeNull();
  });

  it("filters by the time range in the URL and edits it in local time", async () => {
    const from = new Date(Date.now() - 30 * 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z");
    const view = await openLog(`/audit?from=${encodeURIComponent(from)}`);
    const want = expected((r) => Date.parse(r.at) >= Date.parse(from));
    await waitFor(() => expect(keys()).toEqual(want));
    expect(want.length).toBeGreaterThan(0);
    expect(want.length).toBeLessThan(39);

    const input = screen.getByTestId("audit-filter-to") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "2099-01-02T03:04" } });
    await waitFor(() => expect(view.params().get("to")).toBe(toRfc3339("2099-01-02T03:04")));
    expect(view.params().get("to")).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    fireEvent.change(input, { target: { value: "" } });
    await waitFor(() => expect(view.params().has("to")).toBe(false));
  });

  it("warns when the range ends before it starts", async () => {
    await signInAlex();
    renderRoute(AuditPage, { url: "/audit?from=2026-10-09T10:00:00Z&to=2026-10-09T09:00:00Z", path: "/audit" });
    expect(await screen.findByText("The end is before the start, so no record can match.")).toBeTruthy();
    expect(await screen.findByTestId("audit-empty")).toBeTruthy();
  });

  it("filters by a user chosen by name and by a system component", async () => {
    const view = await openLog();
    const option = `datalist option[value="user:${MOCK_USER_IDS.sam}"]`;
    await waitFor(() => expect(document.querySelector(option)).toBeTruthy());
    const input = screen.getByTestId("audit-filter-principal") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "sam" } });
    fireEvent.blur(input);
    await waitFor(() => expect(view.params().get("principal")).toBe(`user:${MOCK_USER_IDS.sam}`));
    expect(input.value).toBe(`user:${MOCK_USER_IDS.sam}`);
    await waitFor(() => expect(keys()).toEqual(expected((r) => r.principal.kind === "user" && r.principal.id === MOCK_USER_IDS.sam)));

    fireEvent.input(input, { target: { value: "system:ipam" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(view.params().get("principal")).toBe("system:ipam"));
    await waitFor(() => expect(keys()).toEqual(expected((r) => r.principal.kind === "system" && r.principal.component === "ipam")));
  });

  it("says a principal is not valid when the name is unknown", async () => {
    await openLog();
    const input = screen.getByTestId("audit-filter-principal") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "nobody" } });
    fireEvent.blur(input);
    expect(await screen.findByText(/Use user:ID, token:ID, node:NUMBER or system:NAME/)).toBeTruthy();
    expect(keys()[0]).toBe("39");
  });

  it("filters by an object kind and by one object", async () => {
    const view = await openLog("/audit?object=host");
    await waitFor(() => expect(keys()).toEqual(expected((r) => (r.draft.objects ?? []).some((o) => o.kind === "host"))));
    const input = screen.getByTestId("audit-filter-object") as HTMLInputElement;
    fireEvent.input(input, { target: { value: `host:${AUDIT_SEED_IDS.hostNas}` } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(view.params().get("object")).toBe(`host:${AUDIT_SEED_IDS.hostNas}`));
    await waitFor(() =>
      expect(keys()).toEqual(expected((r) => (r.draft.objects ?? []).some((o) => o.id === AUDIT_SEED_IDS.hostNas))),
    );
  });

  it("clears every filter at once", async () => {
    const view = await openLog("/audit?action=ipam.&outcome=failed&order=asc");
    await waitFor(() => expect(keys().length).toBe(1));
    fireEvent.click(screen.getByTestId("audit-filter-clear"));
    await waitFor(() => expect(view.location()).toBe("/audit"));
    await waitFor(() => expect(keys()[0]).toBe("39"));
    expect((screen.getByTestId("audit-filter-action") as HTMLInputElement).value).toBe("");
    expect(screen.queryByTestId("audit-filter-clear")).toBeNull();
  });

  it("says so when no record matches and offers the way back", async () => {
    await signInAlex();
    renderRoute(AuditPage, { url: "/audit?action=nothing.here", path: "/audit" });
    const empty = await screen.findByTestId("audit-empty");
    expect(within(empty).getByText("No record matches these filters.")).toBeTruthy();
    expect(within(empty).getByText("Change the filters or clear them to see more.")).toBeTruthy();
  });

  it("opens the focused record with Enter", async () => {
    const view = await openLog();
    const grid = within(screen.getByTestId("grid-audit")).getByRole("grid");
    // The focus starts on the first row; one step down is the second record (38).
    fireEvent.keyDown(grid, { key: "ArrowDown" });
    fireEvent.keyDown(grid, { key: "Enter" });
    await waitFor(() => expect(view.location()).toBe("/audit/38"));
  });

  it("links the number of every record", async () => {
    await openLog();
    const link = within(rows()[0]!).getByRole("link", { name: "39" });
    expect(link.getAttribute("href")).toBe("/audit/39");
  });

  it("opens a record with a click on its row", async () => {
    const view = await openLog();
    const row = rows().find((r) => r.getAttribute("data-key") === "13")!;
    fireEvent.click(within(row).getByText("ipam.host.update"));
    await waitFor(() => expect(view.location()).toBe("/audit/13"));
  });

  it("links the objects of a record where the UI has a page", async () => {
    await openLog();
    const create = rows().find((r) => r.getAttribute("data-key") === "9")!;
    const host = within(create).getByRole("link", { name: "nas.example.test" });
    expect(host.getAttribute("href")).toBe("/ipam/hosts/nas.example.test");
    const job = rows().find((r) => r.getAttribute("data-key") === "32")!;
    expect(within(job).getByRole("link", { name: AUDIT_SEED_IDS.jobRolledBack.slice(0, 8) }).getAttribute("href")).toBe(
      `/jobs/${AUDIT_SEED_IDS.jobRolledBack}`,
    );
    // A host update names no label: kind and short id, no link.
    const update = rows().find((r) => r.getAttribute("data-key") === "13")!;
    expect(within(update).queryByRole("link", { name: AUDIT_SEED_IDS.hostNas.slice(0, 8) })).toBeNull();
    expect(within(update).getByText(AUDIT_SEED_IDS.hostNas.slice(0, 8))).toBeTruthy();
  });
});

describe("the chain status", () => {
  it("shows an intact chain with the head hash, the time of the check and a button", async () => {
    await openLog();
    await waitFor(() => expect(chain().getAttribute("data-state")).toBe("intact"));
    expect(within(chain()).getByText("Chain intact: 39 records verified up to record 39")).toBeTruthy();
    const head = audit.records[audit.records.length - 1]!.hash;
    const shown = within(chain()).getByTitle(head);
    expect(shown.textContent).toBe(head.slice(0, 12));
    expect(within(chain()).getByText(/^Checked /)).toBeTruthy();
    expect(within(chain()).getByTestId("audit-verify").textContent).toContain("Verify again");
  });

  it("shows a broken chain loudly with the record, the reason and a link", async () => {
    await signInAlex();
    tamperAuditRecord(5);
    renderRoute(AuditPage, { url: "/audit", path: "/audit" });
    await waitFor(() => expect(chain().getAttribute("data-state")).toBe("broken"));
    const alert = within(chain()).getByRole("alert");
    expect(within(alert).getByText("Chain broken at record 5")).toBeTruthy();
    expect(within(alert).getByText(/no longer matches its own hash/)).toBeTruthy();
    expect(within(alert).getByText(/audit record 5 has been altered/)).toBeTruthy();
    expect(within(alert).getByText(/4 records before it verified/)).toBeTruthy();
    expect(within(alert).getByRole("link", { name: "Open record 5" }).getAttribute("href")).toBe("/audit/5");
    expect(within(alert).getByText(/security incident/)).toBeTruthy();
  });

  it("explains a gap and a broken link in the chain", async () => {
    await signInAlex();
    audit.records.splice(6, 1);
    renderRoute(AuditPage, { url: "/audit", path: "/audit" });
    await waitFor(() => expect(chain().getAttribute("data-state")).toBe("broken"));
    expect(within(chain()).getByText("Chain broken at record 8")).toBeTruthy();
    expect(within(chain()).getByText(/The sequence has a gap/)).toBeTruthy();
    expect(within(chain()).getByText(/6 records before it verified/)).toBeTruthy();
  });

  it("explains a record that does not link to the one before it", async () => {
    await signInAlex();
    audit.records[8]!.prev = "f".repeat(64);
    renderRoute(AuditPage, { url: "/audit", path: "/audit" });
    await waitFor(() => expect(chain().getAttribute("data-state")).toBe("broken"));
    expect(within(chain()).getByText("Chain broken at record 9")).toBeTruthy();
    expect(within(chain()).getByText(/does not link to the one before it/)).toBeTruthy();
  });

  it("checks again on request and notices a change", async () => {
    await openLog();
    await waitFor(() => expect(chain().getAttribute("data-state")).toBe("intact"));
    tamperAuditRecord(3);
    fireEvent.click(screen.getByTestId("audit-verify"));
    await waitFor(() => expect(chain().getAttribute("data-state")).toBe("broken"));
    expect(within(chain()).getByText("Chain broken at record 3")).toBeTruthy();
    expect(within(chain()).getByText(/2 records before it verified/)).toBeTruthy();
  });

  it("refreshes when a record arrives", async () => {
    await openLog("/audit", { live: true });
    await waitFor(() => expect(chain().getAttribute("data-state")).toBe("intact"));
    appendAudit({ action: "auth.login.success", context: { method: "passkey" } });
    expect(
      await within(chain()).findByText("Chain intact: 40 records verified up to record 40", {}, { timeout: 4000 }),
    ).toBeTruthy();
  });
});

describe("new records while the log is open", () => {
  const newHostUpdate = () =>
    appendAudit({
      action: "ipam.host.update",
      objects: [{ kind: "host", id: AUDIT_SEED_IDS.hostNas }],
      changes: [{ field: "mode", old: "reserved", new: "static" }],
    });

  it("shows a new record at once when the list is newest first and at the top", async () => {
    await openLog("/audit", { live: true });
    const seq = newHostUpdate();
    await waitFor(() => expect(keys()[0]).toBe(String(seq)));
    expect(keys()[1]).toBe("39");
    expect(screen.queryByTestId("audit-show-new")).toBeNull();
  });

  it("announces new records instead of moving the rows when the list is scrolled", async () => {
    await openLog("/audit", { live: true });
    const grid = screen.getByTestId("grid-audit");
    const foot = () => screen.getByTestId("grid-foot").textContent ?? "";
    expect(foot()).toContain("39");
    scrollGridTo(grid, 300);
    newHostUpdate();
    appendAudit({ action: "auth.login.success", context: { method: "passkey" } });
    const button = await screen.findByTestId("audit-show-new");
    expect(screen.getByTestId("audit-new").textContent).toContain("2 new records");
    expect(button.textContent).toBe("Show");
    // The rows did not change.
    expect(foot()).toContain("39");
    expect(foot()).not.toContain("41");

    fireEvent.click(button);
    await waitFor(() => expect(foot()).toContain("41"));
    expect(screen.queryByTestId("audit-show-new")).toBeNull();
    // The browser reports the move to the top; the new rows are the first ones.
    fireEvent.scroll(grid.querySelector(".grid-wrap")!);
    await waitFor(() => expect(keys()[0]).toBe("41"));
  });

  it("reads the new records in when the list is scrolled back to the top", async () => {
    await openLog("/audit", { live: true });
    const grid = screen.getByTestId("grid-audit");
    scrollGridTo(grid, 300);
    newHostUpdate();
    await screen.findByTestId("audit-show-new");
    scrollGridTo(grid, 0);
    await waitFor(() => expect(screen.queryByTestId("audit-show-new")).toBeNull());
    await waitFor(() => expect(keys()[0]).toBe("40"));
  });

  it("reads the new records in when the list is back at the top before they were counted", async () => {
    await openLog("/audit", { live: true });
    const grid = screen.getByTestId("grid-audit");
    scrollGridTo(grid, 300);
    newHostUpdate();
    scrollGridTo(grid, 0);
    await waitFor(() => expect(keys()[0]).toBe("40"));
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(screen.queryByTestId("audit-show-new")).toBeNull();
  });

  it("announces new records of an oldest-first list and shows the newest first on request", async () => {
    const view = await openLog("/audit?order=asc", { live: true });
    expect(keys()[0]).toBe("1");
    const seq = newHostUpdate();
    const button = await screen.findByTestId("audit-show-new");
    expect(screen.getByTestId("audit-new").textContent).toContain("1 new record");
    expect(button.textContent).toBe("Show newest first");
    fireEvent.click(button);
    await waitFor(() => expect(view.params().has("order")).toBe(false));
    await waitFor(() => expect(keys()[0]).toBe(String(seq)));
  });

  it("says when there are a hundred or more new records", async () => {
    await openLog("/audit", { live: true });
    scrollGridTo(screen.getByTestId("grid-audit"), 300);
    for (let i = 0; i < 100; i += 1) appendAudit({ action: "auth.login.success", context: { method: "passkey" } });
    await screen.findByTestId("audit-show-new");
    expect(screen.getByTestId("audit-new").textContent).toContain("100 or more new records");
  });

  it("counts only the new records that match the filters", async () => {
    await openLog("/audit?action=auth.&order=asc", { live: true });
    await waitFor(() => expect(keys().length).toBe(expected((r) => r.draft.action.startsWith("auth.")).length));
    newHostUpdate();
    // Wait past the pause before the count is taken: nothing matches, so there is no bar.
    await new Promise((resolve) => setTimeout(resolve, 700));
    expect(screen.queryByTestId("audit-show-new")).toBeNull();
    appendAudit({ action: "auth.login.success", context: { method: "passkey" } });
    await screen.findByTestId("audit-show-new");
    expect(screen.getByTestId("audit-new").textContent).toContain("1 new record");
  });
});

describe("accessibility", () => {
  it("has no violations with an intact chain", async () => {
    await openLog();
    await waitFor(() => expect(chain().getAttribute("data-state")).toBe("intact"));
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });

  it("has no violations with a broken chain, an error in a filter and an empty list", async () => {
    await signInAlex();
    tamperAuditRecord(5);
    renderRoute(AuditPage, { url: "/audit?action=Nonsense&outcome=failed&principal=system:jobs", path: "/audit" });
    await waitFor(() => expect(chain().getAttribute("data-state")).toBe("broken"));
    await waitFor(() => expect(rows().length).toBe(1));
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });
});
