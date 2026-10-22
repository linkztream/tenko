// WP7.5: the DHCP leases and their history against the real server running the `dhcp` role. An IPAM
// network 192.0.2.0/24 with a range of the role DHCP pool and a scope for it are made through the
// API; a relay agent (support/dhcp-client.ts, UDP on the loopback, subnet selection naming the
// network) takes a lease for a client; the leases page shows it with its state, MAC address and name;
// a second client takes a lease while the page is open and its row appears without a reload (the live
// view); the first lease is released through the dialog and its state changes; the history shows the
// events of both clients. Swedish rendering of the leases page.
//
// NO FAKES: the lease, history, node and scope routes, the DHCP engine and its feed from the store
// are the real ones. Documentation values only: 192.0.2.0/24, MAC 00:00:5e:00:53:xx.

import { test as base, expect } from "./support/fixtures";
import type { Api, Schemas } from "./support/api";
import { freeDhcpPorts, RelayClient, type DhcpPorts } from "./support/dhcp-client";
import { expectRendered } from "./support/i18n";
import { rowMenuItem } from "./support/ipam";
import { cell, gridRow } from "./support/ui";

/** The server runs the role on ports found for this test; a relay agent is bound to the reply port. */
const test = base.extend<{ ports: DhcpPorts; relay: RelayClient }>({
  // eslint-disable-next-line no-empty-pattern -- a Playwright fixture without dependencies
  ports: async ({}, use) => {
    await use(await freeDhcpPorts());
  },
  serverOptions: async ({ ports }, use) => {
    await use({ dhcp: ports });
  },
  relay: async ({ ports }, use) => {
    const relay = await RelayClient.open(ports);
    try {
      await use(relay);
    } finally {
      await relay.close();
    }
  },
});

const NETWORK = "192.0.2.0";
const FIRST_MAC = "00:00:5e:00:53:01";
const SECOND_MAC = "00:00:5e:00:53:02";

/** The network 192.0.2.0/24, a pool 192.0.2.100 to 192.0.2.199 and a scope for the network. */
async function arrange(api: Api): Promise<Schemas["Prefix"]> {
  const prefix = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: `${NETWORK}/24`, description: "Office" })).item!;
  await api.post(`/prefixes/${prefix.id}/ranges`, { first: "192.0.2.100", last: "192.0.2.199", role: "dhcp_pool" });
  await api.post("/dhcp/scopes", { prefix: prefix.id, description: "Office LAN" });
  return prefix;
}

/** The address a client of the pool got. */
function inPool(address: string): void {
  expect(address).toMatch(/^192\.0\.2\.(1\d\d)$/);
}

test("shows the leases of relayed clients live, releases one and keeps the history", async ({ page, api, signedIn, relay }) => {
  void signedIn;
  await arrange(api);

  const first = await relay.dora({ mac: FIRST_MAC, hostname: "client-a", network: NETWORK });
  inPool(first);

  await page.goto("/dhcp/leases");
  await expect(page.getByTestId("page-dhcp-leases")).toBeVisible();
  await expect(page.getByTestId("dhcp-nav").locator('[data-key="leases"]')).toHaveAttribute("aria-current", "page");
  const firstRow = gridRow(page, "dhcp-leases", first);
  await expect(firstRow).toBeVisible();
  await expect(firstRow.getByTestId("lease-state")).toHaveAttribute("data-key", "active");
  await expect(cell(firstRow, "mac")).toHaveText(FIRST_MAC);
  await expect(cell(firstRow, "name")).toContainText("client-a");
  await expect(cell(firstRow, "scope")).toHaveText(`${NETWORK}/24`);

  // The status strip of the role.
  const strip = page.getByTestId("dhcp-strip");
  await expect(strip).toBeVisible();
  await expect(strip.getByTestId("strip-serving")).toHaveAttribute("class", /ok/);
  await expect(strip.getByTestId("strip-listeners")).toContainText("1");

  // A second client takes a lease while the page is open: its row appears without a reload.
  await expect(page.getByTestId("leases-live")).toBeChecked();
  const second = await relay.dora({ mac: SECOND_MAC, hostname: "client-b", network: NETWORK });
  inPool(second);
  expect(second).not.toBe(first);
  const secondRow = gridRow(page, "dhcp-leases", second);
  await expect(secondRow).toBeVisible();
  await expect(cell(secondRow, "mac")).toHaveText(SECOND_MAC);
  await expect(cell(secondRow, "name")).toContainText("client-b");

  // The filters narrow the list.
  await page.getByTestId("filter-mac").fill(SECOND_MAC);
  await expect(gridRow(page, "dhcp-leases", first)).toHaveCount(0);
  await expect(secondRow).toBeVisible();
  await page.getByTestId("leases-reset").click();
  await expect(firstRow).toBeVisible();

  // Release the first lease through the dialog.
  await firstRow.getByRole("button", { name: /Actions for/ }).click();
  await rowMenuItem(page, "release").click();
  const dialog = page.getByTestId("dialog-lease-release");
  await expect(dialog).toBeVisible();
  await dialog.getByTestId("field-reason").fill("Moved to another desk");
  await dialog.getByTestId("confirm-ok").click();
  await expect(dialog).toHaveCount(0);
  await expect(firstRow.getByTestId("lease-state")).toHaveAttribute("data-key", "released");
  await expect(secondRow.getByTestId("lease-state")).toHaveAttribute("data-key", "active");
  const stored = await api.get<Schemas["DhcpLeaseItem"]>(`/dhcp/leases/${first}`);
  expect(stored.state).toBe("released");

  // The history holds the events of both clients; a link leads from a lease to its history.
  await secondRow.getByTestId("lease-history-link").click();
  await expect(page).toHaveURL(/\/dhcp\/history\?addr=/);
  await expect(gridRow(page, "dhcp-history", `${second} granted`)).toBeVisible();
  await expect(gridRow(page, "dhcp-history", `${first} granted`)).toHaveCount(0);

  await page.getByTestId("history-reset").click();
  const granted = gridRow(page, "dhcp-history", `${first} granted`);
  await expect(granted).toBeVisible();
  await expect(cell(granted, "mac")).toHaveText(FIRST_MAC);
  await expect(cell(granted, "name")).toContainText("client-a");
  // An operator's release is recorded as the address reclaimed (LeaseEventKind::Reclaimed).
  await expect(gridRow(page, "dhcp-history", `${first} reclaimed`)).toBeVisible();
  const secondGranted = gridRow(page, "dhcp-history", `${second} granted`);
  await expect(secondGranted).toBeVisible();
  await expect(cell(secondGranted, "mac")).toHaveText(SECOND_MAC);
  await expect(secondGranted.getByTestId("event-kind")).toHaveAttribute("data-key", "granted");
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the leases and the history in Swedish", async ({ page, api, signedIn, relay }, testInfo) => {
    void signedIn;
    await arrange(api);
    const address = await relay.dora({ mac: FIRST_MAC, hostname: "client-a", network: NETWORK });
    inPool(address);

    await page.goto("/dhcp/leases");
    await expect(gridRow(page, "dhcp-leases", address)).toBeVisible();
    await expect(page.getByTestId("dhcp-strip")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dhcp-leases"), "sv", testInfo, "dhcp-leases");

    await page.goto("/dhcp/history");
    await expect(gridRow(page, "dhcp-history", `${address} granted`)).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dhcp-history"), "sv", testInfo, "dhcp-history");
  });
});
