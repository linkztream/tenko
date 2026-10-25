// WP9.4: the lease list with DHCPv4 and DHCPv6 leases side by side. The list shows both families,
// each row with its family and what it holds; the family filter narrows the list and lives in the
// URL; a DHCPv6 row shows the DUID of its client (the whole of it in a title) and its IAID; a client
// that has a lease in both families links to the other one, and the link leads to its DHCPv4 lease.
// The status strip counts both families. WP9.2: a delegated prefix (IA_PD) shows as a prefix with its
// length, the kind filter narrows the list to prefixes and lives in the URL, a prefix in the address
// filter reaches the server, and the prefix links to the address lease of its client. Swedish rendering.
//
// THE LEASE, HISTORY AND NODE ROUTES ARE FAKED (support/dhcp6-leases-mock.ts, which says why): the
// e2e server has no DHCPv6 client behind it. The real routes are proven in Rust
// (crates/tenko-api/tests/dhcp_leases.rs and crates/tenko-dhcp/tests/history_both.rs).
// Documentation values only: 192.0.2.0/24, 2001:db8:0:10::/64, MACs 00:00:5e:00:53:xx.

import { FakeLeases } from "./support/dhcp6-leases-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { cell, gridRow } from "./support/ui";

const GRID = "dhcp-leases";
const V4 = "192.0.2.100";
const V6 = "2001:db8:0:10::100";
const V6_NO_MAC = "2001:db8:0:10::101";
/** WP9.2: the prefix 2001:db8:1:110::/60 delegated to the client of ::100. */
const PD = "2001:db8:1:110::";

test("lists DHCPv4 and DHCPv6 leases, filters to one family and follows the link to the other family's lease", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeLeases.install(page);
  await page.goto("/dhcp/leases");
  await expect(page.getByTestId("page-dhcp-leases")).toBeVisible();

  // Both families, DHCPv4 first, each row with its family and what it holds.
  const rows = page.getByTestId(`grid-${GRID}`).getByTestId("row");
  await expect(rows).toHaveCount(17);
  const v4Row = gridRow(page, GRID, V4);
  const v6Row = gridRow(page, GRID, V6);
  await expect(v4Row.getByTestId("lease-family")).toHaveAttribute("data-key", "v4");
  await expect(v6Row.getByTestId("lease-family")).toHaveAttribute("data-key", "v6");
  await expect(v4Row.getByTestId("lease-kind")).toHaveAttribute("data-key", "address");
  await expect(v6Row.getByTestId("lease-kind")).toHaveAttribute("data-key", "address");
  await expect(rows.nth(11)).toHaveAttribute("data-key", "192.0.2.111");
  await expect(rows.nth(12)).toHaveAttribute("data-key", V6);
  await expect(rows.nth(16)).toHaveAttribute("data-key", PD);

  // The status strip counts both families.
  const strip = page.getByTestId("dhcp-strip");
  await expect(strip.getByTestId("strip-scopes")).toContainText("1 DHCPv4 and 1 DHCPv6");
  await expect(strip.locator('[data-testid="strip-leases"][data-key="active"]')).toHaveAttribute("data-v6", "4");

  // Filter to DHCPv6: the URL gets the family and the request carries it.
  await page.getByTestId("filter-family").selectOption("v6");
  await expect(page).toHaveURL(/family=v6/);
  await expect(rows).toHaveCount(5);
  await expect(v4Row).toHaveCount(0);
  await expect(page.getByTestId("lease-family")).toHaveCount(5);
  await expect.poll(() => fake.to("/api/v1/dhcp/leases").at(-1)?.query.family).toBe("v6");

  // The DUID of a DHCPv6 row, whole in its title, and its IAID.
  await expect(v6Row.getByTestId("lease-duid")).toHaveAttribute("data-key", "0003000100005e005310");
  await expect(v6Row.getByTestId("lease-duid")).toHaveAttribute("title", "00:03:00:01:00:00:5e:00:53:10");
  await expect(v6Row.getByTestId("lease-iaid")).toHaveAttribute("data-key", "1");
  await expect(cell(v6Row, "mac")).toHaveText("00:00:5e:00:53:10");
  // A DUID that holds no MAC address shows none, and has no link to another family.
  const noMac = gridRow(page, GRID, V6_NO_MAC);
  await expect(cell(noMac, "mac")).toHaveText("");
  await expect(noMac.getByTestId("lease-peer")).toHaveCount(0);

  // The client of ::100 is also a DHCPv4 client: the link leads to that lease.
  await expect(v6Row.getByTestId("lease-peer")).toHaveAttribute("data-family", "v4");
  await v6Row.getByTestId("lease-peer-link").click();
  await expect(page).toHaveURL(/addr=192\.0\.2\.100/);
  await expect(page).not.toHaveURL(/family=/);
  await expect(rows).toHaveCount(1);
  await expect(v4Row).toBeVisible();
  // ... which links back to the DHCPv6 lease.
  await expect(v4Row.getByTestId("lease-peer")).toHaveAttribute("data-family", "v6");
  await expect(v4Row.getByTestId("lease-peer-link")).toHaveText(V6);

  // The reset leaves the whole list again.
  await page.getByTestId("leases-reset").click();
  await expect(rows).toHaveCount(17);
});

test("shows a delegated prefix with its length, narrows the list to prefixes and links the prefix to the address lease of its client", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeLeases.install(page);
  await page.goto("/dhcp/leases");
  await expect(page.getByTestId("page-dhcp-leases")).toBeVisible();
  const rows = page.getByTestId(`grid-${GRID}`).getByTestId("row");
  await expect(rows).toHaveCount(17);

  // The row of the prefix: the address with its length, and what it holds.
  const pdRow = gridRow(page, GRID, PD);
  await expect(pdRow.getByTestId("lease-history-link")).toHaveText("2001:db8:1:110::/60");
  await expect(pdRow.getByTestId("lease-kind")).toHaveText("Prefix");
  await expect(pdRow.getByTestId("lease-kind")).toHaveAttribute("data-key", "prefix");
  await expect(pdRow.getByTestId("lease-family")).toHaveAttribute("data-key", "v6");
  await expect(gridRow(page, GRID, V6).getByTestId("lease-kind")).toHaveAttribute("data-key", "address");

  // The kind filter leaves only the prefix, lives in the URL and goes to the server as `kind`.
  await page.getByTestId("filter-kind").selectOption("pd");
  await expect(page).toHaveURL(/kind=pd/);
  await expect(rows).toHaveCount(1);
  await expect(pdRow).toBeVisible();
  await expect.poll(() => fake.to("/api/v1/dhcp/leases").at(-1)?.query.kind).toBe("pd");

  // A page that is opened with the kind in the link shows the same.
  await page.reload();
  await expect(page.getByTestId("filter-kind")).toHaveValue("pd");
  await expect(rows).toHaveCount(1);

  // The prefix links to the address lease of its client, the address the router itself holds.
  await expect(pdRow.getByTestId("lease-address-lease")).toHaveAttribute("data-state", "active");
  await expect(pdRow.getByTestId("lease-address-lease-link")).toHaveText(V6);
  await pdRow.getByTestId("lease-address-lease-link").click();
  await expect.poll(() => new URL(page.url()).searchParams.get("addr")).toBe(V6);
  await expect(page).not.toHaveURL(/kind=/);
  await expect(rows).toHaveCount(1);
  const addressRow = gridRow(page, GRID, V6);
  await expect(addressRow.getByTestId("lease-kind")).toHaveAttribute("data-key", "address");
  await expect(addressRow.getByTestId("lease-address-lease")).toHaveCount(0);

  // An IPv6 prefix in the address filter reaches the server as typed and finds the prefix that lies inside it.
  await page.getByTestId("filter-addr").fill("2001:db8:1::/48");
  await page.getByTestId("filter-addr").press("Enter");
  await expect.poll(() => fake.to("/api/v1/dhcp/leases").at(-1)?.query.addr).toBe("2001:db8:1::/48");
  await expect(rows).toHaveCount(1);
  await expect(pdRow).toBeVisible();
  await expect(page.getByTestId("field-help")).toContainText("2001:db8:1::/48");
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the leases of both families in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await FakeLeases.install(page);
    await page.goto("/dhcp/leases");
    await expect(gridRow(page, GRID, V6)).toBeVisible();
    await expect(gridRow(page, GRID, PD).getByTestId("lease-kind")).toHaveText("Prefix");
    await expect(page.getByRole("combobox", { name: "Innehåller" })).toBeVisible();
    await expect(page.getByTestId("dhcp-strip")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dhcp-leases"), "sv", testInfo, "dhcp6-leases");
  });
});
