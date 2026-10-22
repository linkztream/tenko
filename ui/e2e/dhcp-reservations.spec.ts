// WP8.6: the DHCP reservations block of the host page against the real server running the `dhcp`
// role. An IPAM network 192.0.2.0/24 with a pool and a scope is made through the API, a `reserved`
// host with a MAC address and an address outside the pool, and a second `reserved` host without a
// MAC or client identifier. The first host's page shows its reservation in the served scope with
// no lease yet; once a relay agent of the test (support/dhcp-client.ts) took the lease for the
// host's MAC, the block shows the reserved address leased and active, without a reload. The second
// host shows the IPAM-18 case: no identity, so no reservation. Swedish rendering of the block.
//
// NO FAKES: the IPAM, scope and lease routes, the DHCP engine and its feed from the store are the
// real ones. Documentation values only: 192.0.2.0/24, MAC 00:00:5e:00:53:xx.

import { test as base, expect } from "./support/fixtures";
import type { Api, Schemas } from "./support/api";
import { freeDhcpPorts, RelayClient, type DhcpPorts } from "./support/dhcp-client";
import { expectRendered } from "./support/i18n";
import { withKey } from "./support/ui";

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
const PRINTER = "printer.example.test";
const PRINTER_MAC = "00:00:5e:00:53:21";
const PRINTER_IP = "192.0.2.20";
const CAMERA = "camera.example.test";

type Items<T> = { items: T[] };

/** A `reserved` host with one interface (with `mac` when given) and one address on it. */
async function reservedHost(api: Api, name: string, ip: string, mac?: string): Promise<void> {
  const created = await api.post<Schemas["WriteResponse_Host"]>("/hosts", {
    name,
    mode: "reserved",
    interfaces: [mac ? { name: "eth0", mac } : { name: "eth0" }],
  });
  const host = created.item!;
  const interfaces = await api.get<Items<Schemas["Interface"]>>(`/hosts/${host.id}/interfaces`);
  await api.post("/addresses", { ip, interface: interfaces.items[0]!.id });
}

/** The network with a pool 192.0.2.100 to 192.0.2.199 and a scope; the printer and the camera. */
async function arrange(api: Api): Promise<Schemas["Prefix"]> {
  const prefix = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: `${NETWORK}/24`, description: "Office" })).item!;
  await api.post(`/prefixes/${prefix.id}/ranges`, { first: "192.0.2.100", last: "192.0.2.199", role: "dhcp_pool" });
  await api.post("/dhcp/scopes", { prefix: prefix.id });
  await reservedHost(api, PRINTER, PRINTER_IP, PRINTER_MAC);
  await reservedHost(api, CAMERA, "192.0.2.21");
  return prefix;
}

test("the host page shows the reservation, its scope and its lease as the client takes it", async ({ page, api, signedIn, relay }) => {
  void signedIn;
  await arrange(api);

  await page.goto(`/ipam/hosts/${PRINTER}`);
  const block = page.getByTestId("host-reservations");
  await expect(block).toBeVisible();
  await expect(block).toHaveAttribute("data-count", "1");
  const row = withKey(block, "host-reservation", PRINTER_IP);
  await expect(row).toHaveAttribute("data-state", "served");
  await expect(row).toHaveAttribute("data-lease", "none");
  await expect(row.getByTestId("host-reservation-identity")).toContainText(PRINTER_MAC);
  await expect(row.getByTestId("host-reservation-scope")).toHaveAttribute("data-key", `${NETWORK}/24`);
  await expect(row.getByTestId("host-reservation-no-lease")).toBeVisible();

  // The printer asks: it gets its reserved address, and the block follows without a reload.
  const leased = await relay.dora({ mac: PRINTER_MAC, hostname: "printer", network: NETWORK });
  expect(leased).toBe(PRINTER_IP);
  await expect(row).toHaveAttribute("data-lease", "active");
  await expect(row.getByTestId("host-reservation-lease-state")).toHaveAttribute("data-key", "active");
  await expect(row.getByTestId("host-reservation-mismatch")).toHaveCount(0);
  await expect(row.getByTestId("host-reservation-history")).toHaveAttribute("href", `/dhcp/history?addr=${encodeURIComponent(PRINTER_IP)}`);

  // The scope link opens the scope.
  await row.getByTestId("host-reservation-scope").click();
  await expect(page.getByTestId("page-dhcp-scope")).toBeVisible();
});

test("a reserved host without a MAC address or client identifier has no reservation (IPAM-18)", async ({ page, api, signedIn }) => {
  void signedIn;
  await arrange(api);
  await page.goto(`/ipam/hosts/${CAMERA}`);
  const row = withKey(page.getByTestId("host-reservations"), "host-reservation", "192.0.2.21");
  await expect(row).toHaveAttribute("data-state", "no_identity");
  await expect(row.getByTestId("host-reservation-identity")).toHaveAttribute("data-kind", "none");
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the reservations block in Swedish", async ({ page, api, signedIn }, testInfo) => {
    void signedIn;
    await arrange(api);
    await page.goto(`/ipam/hosts/${PRINTER}`);
    const block = page.getByTestId("host-reservations");
    await expect(withKey(block, "host-reservation", PRINTER_IP)).toHaveAttribute("data-state", "served");
    await expectRendered(page, block, "sv", testInfo, "host-reservations");
  });
});
