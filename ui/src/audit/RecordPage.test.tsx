import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { appendAudit, AUDIT_SEED_IDS, audit } from "../api/mock/audit-store";
import { MOCK_USER_IDS } from "../api/mock/fixtures";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import RecordPage from "./RecordPage";

// The view is rendered without the shell's <main>, which holds all page content in the app.
const NO_SHELL = { disable: ["region"] } as const;

afterEach(() => setSessionForTest(null));

async function openRecord(seq: number | string) {
  await signInAlex();
  const view = renderRoute(RecordPage, { url: `/audit/${seq}`, path: "/audit/:seq" });
  await screen.findByTestId("page-audit-record");
  return view;
}

/** The sequence number of the first seeded record for which `keep` holds. */
function seqWhere(keep: (record: (typeof audit.records)[number]) => boolean): number {
  const found = audit.records.find(keep);
  if (!found) throw new Error("no such seed record");
  return found.seq;
}

const heading = () => screen.getByRole("heading", { level: 1 });

describe("one audit record", () => {
  it("shows the before and after of a host update", async () => {
    const seq = seqWhere(
      (r) =>
        r.draft.action === "ipam.host.update" &&
        (r.draft.details?.changes ?? []).some((c) => c.field === "mode" && c.old === "static" && c.new === "reserved"),
    );
    await openRecord(seq);
    const table = await screen.findByTestId("audit-changes");
    expect(heading().textContent).toContain(`Record ${seq}`);
    const head = within(table).getAllByRole("columnheader").map((h) => h.textContent);
    expect(head).toEqual(["Field", "Before", "After"]);
    const body = within(table).getAllByRole("row").slice(1);
    expect(body).toHaveLength(1);
    expect(within(body[0]!).getAllByRole("cell").map((c) => c.textContent)).toEqual(["mode", "static", "reserved"]);

    // Overview and principal.
    expect(screen.getByText("ipam.host.update")).toBeTruthy();
    expect(screen.getByText("Success")).toBeTruthy();
    expect(screen.getByText("192.0.2.50")).toBeTruthy();
    expect(await screen.findByText("Sam Example")).toBeTruthy();
    expect(screen.getByText("Password")).toBeTruthy();
    expect(screen.getByText(MOCK_USER_IDS.sam)).toBeTruthy();
  });

  it("shows the context, the denied outcome and the source of a failed login", async () => {
    const seq = seqWhere((r) => r.draft.action === "auth.login.failure");
    await openRecord(seq);
    const context = await screen.findByTestId("audit-context");
    expect(within(context).getByText("user").textContent).toBe("user");
    expect(within(context).getByText("admin")).toBeTruthy();
    expect(screen.getByText("Denied")).toBeTruthy();
    expect(screen.getByText("203.0.113.77")).toBeTruthy();
    expect(screen.getByText("Tenko (auth)")).toBeTruthy();
    expect(screen.getByText("Component of Tenko")).toBeTruthy();
    expect(screen.getByText("This record lists no field changes.")).toBeTruthy();
    expect(screen.getByText("This action names no object.")).toBeTruthy();
    expect(screen.queryByTestId("audit-changes")).toBeNull();
  });

  it("shows the code of a failed action and its context", async () => {
    const seq = seqWhere((r) => r.draft.outcome.kind === "failed" && r.draft.action === "ipam.prefix.create");
    await openRecord(seq);
    expect(await screen.findByText("Failed")).toBeTruthy();
    expect(screen.getByText("ipam.prefix.overlap")).toBeTruthy();
    expect(within(screen.getByTestId("audit-context")).getByText("192.0.2.128/25")).toBeTruthy();
  });

  it("shows both hashes in the data font with the note about the chain", async () => {
    await openRecord(5);
    const prev = await screen.findByTestId("audit-prev-hash");
    const hash = screen.getByTestId("audit-hash");
    expect(prev.textContent).toBe(audit.records[3]!.hash);
    expect(hash.textContent).toBe(audit.records[4]!.hash);
    expect(prev.classList.contains("hash")).toBe(true);
    expect(hash.classList.contains("hash")).toBe(true);
    expect(screen.getByText(/Each record carries the hash of the record before it/)).toBeTruthy();
    expect(screen.queryByText("The first record has no record before it.")).toBeNull();
  });

  it("says the first record has nothing before it", async () => {
    await openRecord(1);
    expect((await screen.findByTestId("audit-prev-hash")).textContent).toBe("0".repeat(64));
    expect(screen.getByText("The first record has no record before it.")).toBeTruthy();
  });

  it("links to the records before and after, and moves between them", async () => {
    const view = await openRecord(5);
    const prev = await screen.findByTestId("audit-prev");
    const next = screen.getByTestId("audit-next");
    expect(prev.getAttribute("href")).toBe("/audit/4");
    expect(next.getAttribute("href")).toBe("/audit/6");
    fireEvent.click(next);
    await waitFor(() => expect(view.location()).toBe("/audit/6"));
    await waitFor(() => expect(heading().textContent).toContain("Record 6"));
    expect(await screen.findByTestId("audit-hash")).toBeTruthy();
    await waitFor(() => expect(screen.getByTestId("audit-hash").textContent).toBe(audit.records[5]!.hash));
  });

  it("has no previous record before the first and no next record after the newest", async () => {
    await openRecord(1);
    await screen.findByTestId("audit-hash");
    expect(screen.queryByTestId("audit-prev")).toBeNull();
    expect((screen.getByRole("button", { name: /Previous record/ }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId("audit-next")).toBeTruthy();
  });

  it("disables next on the newest record once it knows the newest", async () => {
    await openRecord(39);
    await waitFor(() => expect((screen.getByRole("button", { name: /Next record/ }) as HTMLButtonElement).disabled).toBe(true));
    expect(screen.queryByTestId("audit-next")).toBeNull();
    expect(screen.getByTestId("audit-prev").getAttribute("href")).toBe("/audit/38");
  });

  it("links the objects to their pages and to the log of the object", async () => {
    // The host create of seed 9 names the host.
    await openRecord(9);
    const objects = await screen.findByTestId("audit-objects");
    expect(within(objects).getByRole("link", { name: "nas.example.test" }).getAttribute("href")).toBe("/ipam/hosts/nas.example.test");
    expect(within(objects).getByText(AUDIT_SEED_IDS.hostNas)).toBeTruthy();
    expect(within(objects).getByRole("link", { name: "All records for this object" }).getAttribute("href")).toBe(
      paths.audit({ object: `host:${AUDIT_SEED_IDS.hostNas}` }),
    );
    expect(screen.getByRole("link", { name: "All records by this principal" }).getAttribute("href")).toBe(
      paths.audit({ principal: `user:${MOCK_USER_IDS.alex}` }),
    );
  });

  it("links a job by its id and a prefix by its CIDR", async () => {
    await openRecord(32);
    const job = await screen.findByRole("link", { name: AUDIT_SEED_IDS.jobRolledBack.slice(0, 8) });
    expect(job.getAttribute("href")).toBe(`/jobs/${AUDIT_SEED_IDS.jobRolledBack}`);
  });

  it("shows a prefix by its CIDR when the changes name it", async () => {
    await openRecord(5);
    const objects = await screen.findByTestId("audit-objects");
    expect(within(objects).getByRole("link", { name: "192.0.2.0/24" }).getAttribute("href")).toBe("/ipam/prefixes/192.0.2.0/24");
  });

  it("shows a removed value as a dash that screen readers read as no value", async () => {
    const seq = seqWhere((r) => r.draft.action === "ipam.address.delete");
    await openRecord(seq);
    const table = await screen.findByTestId("audit-changes");
    const after = table.querySelector('td[data-col="new"]')!;
    expect(after.textContent).toContain("–");
    expect(within(after as HTMLElement).getByText("no value")).toBeTruthy();
    // The deleted address is named but not linked.
    expect(within(screen.getByTestId("audit-objects")).queryByRole("link", { name: "192.0.2.35" })).toBeNull();
    expect(within(screen.getByTestId("audit-objects")).getByText("192.0.2.35")).toBeTruthy();
  });

  it("says a change without values is not recorded and names the object of each change", async () => {
    await signInAlex();
    const seq = appendAudit({
      action: "settings.secret.update",
      objects: [
        { kind: "secret", id: AUDIT_SEED_IDS.settings },
        { kind: "connector", id: AUDIT_SEED_IDS.hostNas },
      ],
      changes: [
        { field: "password", old: null, new: null, object: { kind: "secret", id: AUDIT_SEED_IDS.settings } },
        { field: "enabled", old: "no", new: "yes", object: { kind: "connector", id: AUDIT_SEED_IDS.hostNas } },
      ],
    });
    renderRoute(RecordPage, { url: `/audit/${seq}`, path: "/audit/:seq" });
    const table = await screen.findByTestId("audit-changes");
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Object", "Field", "Before", "After"]);
    expect(within(table).getByText("Changed; the value is not recorded")).toBeTruthy();
    expect(within(table).getByText("Secret")).toBeTruthy();
    expect(within(table).getByText("Connector")).toBeTruthy();
  });

  it("shows a translated message for a record that does not exist", async () => {
    await openRecord(999);
    const missing = await screen.findByTestId("audit-not-found");
    expect(within(missing).getByText("There is no audit record 999.")).toBeTruthy();
    expect(within(missing).getByRole("link", { name: "Back to the audit log" }).getAttribute("href")).toBe("/audit");
    expect(await within(missing).findByRole("link", { name: "Open the newest record, 39" })).toBeTruthy();
    expect(screen.queryByTestId("audit-changes")).toBeNull();
  });

  it("treats a number that is not a record number as missing without asking the server", async () => {
    await openRecord("abc");
    expect(await screen.findByText("There is no audit record abc.")).toBeTruthy();
    expect(heading().textContent).toBe("Audit log");
  });

  it("has no accessibility violations on a record with changes, on a failed login and on a missing record", async () => {
    const withChanges = seqWhere((r) => (r.draft.details?.changes ?? []).length > 0);
    const view = await openRecord(withChanges);
    await screen.findByTestId("audit-changes");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
    view.unmount();

    const login = seqWhere((r) => r.draft.action === "auth.login.failure");
    const second = renderRoute(RecordPage, { url: `/audit/${login}`, path: "/audit/:seq" });
    await screen.findByTestId("audit-context");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
    second.unmount();

    renderRoute(RecordPage, { url: "/audit/999", path: "/audit/:seq" });
    await screen.findByTestId("audit-not-found");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });
});
