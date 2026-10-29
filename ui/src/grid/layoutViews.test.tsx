// The saved layout of five lists, end to end against the mock API: a hidden column is saved to
// the server, is still hidden on a fresh page whose layout comes only from the server, and comes
// back with "Reset columns", which deletes the key on the server.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mockPreferences } from "../api/mock/routes-preferences";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { session, setSessionForTest } from "../auth/session";
import FindingsView from "../discovery/FindingsView";
import { resetRefs } from "../discovery/refs";
import DhcpLeasesPage from "../dhcp/leases/LeasesPage";
import ZonesPage from "../dns/ZonesPage";
import AddressesView from "../ipam/address/AddressesView";
import { chooseVrf } from "../ipam/scope";
import { resetJobDetails } from "../jobs/data";
import JobsView from "../jobs/JobsView";
import { resetGroupStateForTest } from "./groups";
import { resetLayoutStoreForTest, setLayoutTimingForTest, syncLayoutsForTest } from "./layoutStore";

interface Case {
  /** The grid id, which names the key `table:<id>` on the server. */
  id: string;
  /** A column that is shown by default and is not fixed. */
  column: string;
  view: () => JSX.Element;
  path: string;
  url: string;
  /** The list has no column chooser (it has its own toolbar); only the server's layout is applied. */
  noChooser?: boolean;
}

const CASES: Case[] = [
  { id: "addresses", column: "mac", view: AddressesView, path: "/ipam/addresses", url: "/ipam/addresses" },
  { id: "dns-zones", column: "serial", view: ZonesPage, path: "/dns", url: "/dns", noChooser: true },
  { id: "dhcp-leases", column: "ends", view: DhcpLeasesPage, path: "/dhcp/leases", url: "/dhcp/leases", noChooser: true },
  { id: "jobs", column: "by", view: JobsView, path: "/jobs", url: "/jobs" },
  { id: "findings", column: "subject", view: FindingsView, path: "/discovery/:id?", url: "/discovery" },
];

const userId = () => session()?.user.id ?? null;

beforeEach(async () => {
  chooseVrf(null);
  resetRefs();
  resetGroupStateForTest();
  resetJobDetails();
  localStorage.clear();
  await signInAlex();
  setLayoutTimingForTest({ debounce: 30, retry: 50 });
  await syncLayoutsForTest(userId());
});

afterEach(() => {
  setSessionForTest(null);
  chooseVrf(null);
  localStorage.clear();
});

const header = (column: string) => document.querySelector(`th[data-col="${column}"]`);

async function render(c: Case) {
  const view = renderRoute(c.view, { url: c.url, path: c.path });
  await waitFor(() => expect(screen.queryAllByTestId("row").length).toBeGreaterThan(0), { timeout: 3000 });
  return view;
}

function openChooser(): HTMLElement {
  fireEvent.click(screen.getByRole("button", { name: "Choose columns" }));
  return screen.getByTestId("column-chooser-panel");
}

describe("the saved layout of a list", () => {
  it.each(CASES.filter((c) => !c.noChooser))("$id: a hidden column is saved on the server, survives a fresh page and returns on reset", async (c) => {
    const key = `table:${c.id}`;
    const hiddenOnServer = () => (mockPreferences()[key] as { hidden?: string[] } | undefined)?.hidden ?? [];

    const first = await render(c);
    expect(header(c.column)).not.toBeNull();
    const box = openChooser().querySelector<HTMLInputElement>(`li[data-col="${c.column}"] input[type="checkbox"]`);
    expect(box).not.toBeNull();
    expect(box?.checked).toBe(true);
    expect(box?.disabled).toBe(false);
    fireEvent.click(box as HTMLInputElement);
    expect(header(c.column)).toBeNull();
    await waitFor(() => expect(hiddenOnServer()).toContain(c.column), { timeout: 3000 });
    first.unmount();

    // A fresh page: nothing in this browser, the layout comes only from the server.
    resetLayoutStoreForTest();
    localStorage.clear();
    setLayoutTimingForTest({ debounce: 30, retry: 50 });
    await syncLayoutsForTest(userId());
    const second = await render(c);
    expect(document.querySelector("th[data-col]")).not.toBeNull();
    expect(header(c.column)).toBeNull();

    fireEvent.click(within(openChooser()).getByRole("button", { name: "Reset columns" }));
    await waitFor(() => expect(header(c.column)).not.toBeNull());
    await waitFor(() => expect(mockPreferences()[key]).toBeUndefined(), { timeout: 3000 });
    second.unmount();
  });
});

// The zone list and the lease list have their own toolbars and no column chooser yet: the layout
// saved on the server (from another browser, say) is applied to them, and a reset elsewhere
// returns the default.
describe("the saved layout of a list without a column chooser", () => {
  it.each(CASES.filter((c) => c.noChooser))("$id: the hidden columns on the server apply on a fresh page", async (c) => {
    const key = `table:${c.id}`;
    const put = await fetch(`${location.origin}/api/v1/auth/preferences/${key}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: 1, hidden: [c.column] }),
    });
    expect(put.status).toBe(200);
    resetLayoutStoreForTest();
    localStorage.clear();
    setLayoutTimingForTest({ debounce: 30, retry: 50 });
    await syncLayoutsForTest(userId());
    const view = await render(c);
    expect(document.querySelector("th[data-col]")).not.toBeNull();
    expect(header(c.column)).toBeNull();
    view.unmount();

    // Reset in another browser: the default applies again.
    expect((await fetch(`${location.origin}/api/v1/auth/preferences/${key}`, { method: "DELETE" })).status).toBeLessThan(300);
    resetLayoutStoreForTest();
    await syncLayoutsForTest(userId());
    const again = await render(c);
    expect(header(c.column)).not.toBeNull();
    again.unmount();
  });
});
