// Display gating of the tenancy collections (IAM-01): a scoped operator sees no write action
// outside its scope, a viewer none at all, an administrator all. casey's seeded grants are
// prefix rules, which reach no site or VLAN, so the tests add an operator grant on the site Home
// (and below). The mock does not filter reads, so casey sees every VLAN and site anyway.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { access, ACCESS_IDS, seedAccess, SCOPED_OPERATOR } from "../../api/mock/access-store";
import { startSession } from "../../api/mock/auth";
import { api } from "../../api/client";
import { findUserByName, resetMockDb } from "../../api/mock/db";
import { IPAM_IDS } from "../../api/mock/ipam/api";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { anchorIndexLoaded } from "../../auth/gate";
import { signInScopedOperator, signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import CustomFieldsView from "./CustomFieldsView";
import SitesView from "./SitesView";
import TenancyView from "./TenancyView";
import VlansView from "./VlansView";

/** casey with, in addition to the seeded grants, an operator grant on the site Home and below. */
async function signInSiteOperator(): Promise<void> {
  resetMockDb("signed-in");
  seedAccess();
  access.grants.push({
    id: "0190d1c2-0000-7000-8000-0000000f0f01",
    subject: ACCESS_IDS.scopedOperator,
    role: "operator",
    scope: { kind: "site", value: { id: IPAM_IDS.site.home, subtree: true } },
    delegable: false,
    granted_by: null,
    granted_at: new Date().toISOString(),
    parent: null,
  });
  const casey = findUserByName(SCOPED_OPERATOR.name);
  if (!casey) throw new Error("no casey");
  startSession(casey, "password");
  setSessionForTest(await api.get("/api/v1/auth/session"));
  await waitFor(() => {
    if (!anchorIndexLoaded()) throw new Error("the anchor index is not loaded yet");
  });
}

const rowOf = (grid: HTMLElement, key: string): HTMLElement => {
  const row = within(grid).queryAllByTestId("row").find((r) => r.dataset.key === key);
  if (!row) throw new Error(`no row ${key}`);
  return row;
};

/** The ids of the items of the row menu of a row. */
async function menuOf(grid: HTMLElement, key: string): Promise<string[]> {
  fireEvent.click(rowOf(grid, key).querySelector(".row-menu") as HTMLElement);
  const menu = await screen.findByTestId("row-menu");
  const ids = [...menu.querySelectorAll<HTMLElement>("[data-item]")].map((el) => el.dataset.item ?? "");
  fireEvent.keyDown(menu, { key: "Escape" });
  return ids;
}

const ALL_ROW = ["edit", "history", "restore", "delete"];
const READ_ROW = ["history"];

describe("gating of the VLANs", () => {
  const HOME = "10 LAN"; // site Home
  const LAB = "20 Lab"; // site Lab, outside the grant
  const HEAD = ["vlan-provision", "vlan-create"];
  const head = () => HEAD.filter((id) => screen.queryByTestId(id));

  async function open() {
    renderRoute(VlansView, { url: "/ipam/vlans" });
    const grid = await screen.findByTestId("grid-vlans");
    await waitFor(() => expect(within(grid).queryAllByTestId("row").length).toBe(6));
    return grid;
  }

  it("shows an administrator every action", async () => {
    await signInAlex();
    const grid = await open();
    expect(head()).toEqual(HEAD);
    expect(await menuOf(grid, LAB)).toEqual(["edit", "history", "restore", "delete", "provision", "prefixes"]);
  });

  it("shows a scoped operator create and the row actions inside its sites, never provisioning", async () => {
    await signInSiteOperator();
    const grid = await open();
    expect(head()).toEqual(["vlan-create"]);
    expect(await menuOf(grid, HOME)).toEqual([...ALL_ROW, "prefixes"]);
    expect(await menuOf(grid, LAB)).toEqual([...READ_ROW, "prefixes"]);
  });

  it("hides every write action from a scoped operator whose grants reach no site", async () => {
    await signInScopedOperator();
    const grid = await open();
    expect(head()).toEqual([]);
    expect(await menuOf(grid, HOME)).toEqual([...READ_ROW, "prefixes"]);
  });

  it("hides every write action from a viewer", async () => {
    await signInWithRoles(["viewer"]);
    const grid = await open();
    expect(head()).toEqual([]);
    expect(await menuOf(grid, HOME)).toEqual([...READ_ROW, "prefixes"]);
  });
});

describe("gating of the sites", () => {
  const HOME = "Home";
  const GARAGE = "Garage"; // below Home
  const LAB = "Lab";

  async function open() {
    renderRoute(SitesView, { url: "/ipam/sites" });
    const grid = await screen.findByTestId("grid-sites");
    await waitFor(() => expect(within(grid).queryAllByTestId("row").length).toBe(3));
    return grid;
  }

  it("shows an administrator every action", async () => {
    await signInAlex();
    const grid = await open();
    expect(screen.getByTestId("site-create")).toBeTruthy();
    expect(await menuOf(grid, LAB)).toEqual(ALL_ROW);
  });

  it("shows a scoped operator the actions on its sites only", async () => {
    await signInSiteOperator();
    const grid = await open();
    expect(screen.getByTestId("site-create")).toBeTruthy();
    expect(await menuOf(grid, HOME)).toEqual(ALL_ROW);
    expect(await menuOf(grid, GARAGE)).toEqual(ALL_ROW);
    expect(await menuOf(grid, LAB)).toEqual(READ_ROW);
  });

  it("hides every write action from a scoped operator whose grants reach no site", async () => {
    await signInScopedOperator();
    const grid = await open();
    expect(screen.queryByTestId("site-create")).toBeNull();
    expect(await menuOf(grid, HOME)).toEqual(READ_ROW);
  });

  it("hides every write action from a viewer", async () => {
    await signInWithRoles(["viewer"]);
    const grid = await open();
    expect(screen.queryByTestId("site-create")).toBeNull();
    expect(await menuOf(grid, HOME)).toEqual(READ_ROW);
  });
});

describe("gating of the global-only collections", () => {
  async function openTenancy() {
    renderRoute(TenancyView, { url: "/ipam/tenancy" });
    const grid = await screen.findByTestId("grid-tenants");
    await waitFor(() => expect(within(grid).queryAllByTestId("row").length).toBeGreaterThan(0));
    return grid;
  }

  it("shows an administrator tenants, VRFs and custom fields to change", async () => {
    await signInAlex();
    const grid = await openTenancy();
    expect(screen.getByTestId("tenant-create")).toBeTruthy();
    expect(screen.getByTestId("vrf-create")).toBeTruthy();
    const key = within(grid).getAllByTestId("row")[0]?.dataset.key ?? "";
    expect(await menuOf(grid, key)).toEqual(ALL_ROW);
  });

  it.each(["scoped", "viewer"])("hides the tenant and VRF actions from a %s principal", async (who) => {
    if (who === "scoped") await signInSiteOperator();
    else await signInWithRoles(["viewer"]);
    const grid = await openTenancy();
    expect(screen.queryByTestId("tenant-create")).toBeNull();
    expect(screen.queryByTestId("vrf-create")).toBeNull();
    const key = within(grid).getAllByTestId("row")[0]?.dataset.key ?? "";
    expect(await menuOf(grid, key)).toEqual(READ_ROW);
  });

  it("shows an administrator the creation of custom fields", async () => {
    await signInAlex();
    renderRoute(CustomFieldsView, { url: "/ipam/custom-fields" });
    await screen.findByTestId("grid-custom-fields");
    expect(screen.getByTestId("custom-field-create")).toBeTruthy();
  });

  it("hides custom field creation from a global operator, who may still change them", async () => {
    await signInWithRoles(["operator"]);
    renderRoute(CustomFieldsView, { url: "/ipam/custom-fields" });
    const grid = await screen.findByTestId("grid-custom-fields");
    await waitFor(() => expect(within(grid).queryAllByTestId("row").length).toBeGreaterThan(0));
    expect(screen.queryByTestId("custom-field-create")).toBeNull();
    const key = within(grid).getAllByTestId("row")[0]?.dataset.key ?? "";
    expect(await menuOf(grid, key)).toEqual(["edit", "delete"]);
  });

  it("hides every custom field action from a viewer and a scoped operator", async () => {
    for (const signIn of [() => signInWithRoles(["viewer"]), () => signInSiteOperator()]) {
      await signIn();
      const view = renderRoute(CustomFieldsView, { url: "/ipam/custom-fields" });
      const grid = await screen.findByTestId("grid-custom-fields");
      await waitFor(() => expect(within(grid).queryAllByTestId("row").length).toBeGreaterThan(0));
      expect(screen.queryByTestId("custom-field-create")).toBeNull();
      expect(grid.querySelector(".row-menu")).toBeNull();
      view.unmount();
    }
  });
});
