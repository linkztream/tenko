// WP8.2, U4: the reconciliation view (/ipam/reconcile) and the OS block of the host page: open the
// view from the IPAM navigation, see one grouped table (groups by severity and kind in the order
// act, review, info, the rule said once per group where every row shares it, the winning truth
// marked by a check glyph and the outcome of each row), narrow the page to one kind, open a row in
// the side panel (a conflict with the MAC addresses on its address, a rogue with a proposal, a
// row without one), and see the OS field of the DHCP fingerprint and the vendors on a host page.
// The page in Swedish.
//
// THE ROUTE IS FAKED: the reconciliation view derives its rows from leases, sightings and DNS
// records that the one controller of the e2e server does not have (no DHCP role, no probe, no
// connector), so `GET /api/v1/ipam/reconcile` is answered in the browser with the rows of the
// mock API (src/api/mock/ipam-reconcile-model.ts, the data the msw handler and the component
// tests use); everything else reaches the real server, among them the host the page is opened
// for and `GET /findings`. The real derivation is proven in Rust:
// crates/tenko-ipam/tests/reconcile_view.rs and the route tests of crates/tenko-api.
//
// Because the rows are the mock's, the real server has no finding for them: every row takes the
// default severity of its kind (conflict act, a rogue with a proposal review and one without
// info, orphan and PTR mismatch review, ghost info) and no row has a default action. The
// proposal of the rogue row is the mock's too, so on the real server `GET /proposals/<id>`
// answers 404 and the docked proposal panel shows its error state; that is what the scenario
// checks (the proposal panel with a real proposal is covered by discovery.spec.ts and the unit
// tests), rather than faking a second route.

import { randomUUID } from "node:crypto";
import type { Locator, Page, Route } from "@playwright/test";
import { filterRows, hostTruths, seedRows, type ReconcileRow } from "../src/api/mock/ipam-reconcile-model";
import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { cell, withId, withKey } from "./support/ui";

const RECONCILE = /\/api\/v1\/ipam\/reconcile(\?|$)/;
const HOST_NAME = "pc-office.example.test";
const MAC = "00:00:5e:00:53:d1";

interface Fake {
  rows: ReconcileRow[];
  proposal: string;
  /** The query strings the UI sent, in order. */
  queries: URLSearchParams[];
}

/** Answers the reconciliation route of `page` with the rows of the mock; call it before the first navigation. */
async function fakeReconcile(page: Page, host: Schemas["Host"]): Promise<Fake> {
  const known = new Map<string, string>();
  const proposal = randomUUID();
  const rows = seedRows({ vrf: randomUUID(), prefix: randomUUID(), host: (name) => known.get(name) ?? (known.set(name, randomUUID()), known.get(name) as string), proposal });
  const fake: Fake = { rows, proposal, queries: [] };
  await page.route(RECONCILE, async (route: Route) => {
    const url = new URL(route.request().url());
    fake.queries.push(url.searchParams);
    const items = filterRows(rows, { kind: url.searchParams.get("kind"), prefix: url.searchParams.get("prefix"), host: url.searchParams.get("host") });
    const body: Record<string, unknown> = { items, next_cursor: null, revision: 1 };
    if (url.searchParams.get("host") === host.id) body.host = hostTruths({ id: host.id, name: host.name, mode: host.mode }, [MAC], ["192.0.2.150"]);
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  return fake;
}

/** The data rows of the grid, without its group rows. */
function dataRows(grid: Locator): Locator {
  return grid.locator('[data-testid="row"]:not([data-key^="group:"])');
}

async function makeHost(api: Api): Promise<Schemas["Host"]> {
  return (await api.post<{ item: Schemas["Host"] }>("/hosts", { name: HOST_NAME, mode: "dynamic" })).item;
}

test("shows one grouped table with the rule and the winner of each row, narrows to one kind and opens a row in the side panel", async ({ page, api, signedIn }) => {
  void signedIn;
  const host = await makeHost(api);
  const fake = await fakeReconcile(page, host);

  await page.goto("/ipam/addresses");
  await page.getByTestId("ipam-nav").locator('[data-tab="reconcile"]').click();
  await expect(page).toHaveURL(/\/ipam\/reconcile$/);
  await expect(page.getByTestId("page-ipam-reconcile")).toBeVisible();
  await expect(page.getByTestId("ipam-nav").locator('[data-tab="reconcile"]')).toHaveAttribute("aria-current", "page");

  // One table, grouped by severity (act, review, info) and kind; its facts count the rows by severity.
  const grid = page.getByTestId("grid-reconcile");
  const groupKeys = ["group:act:conflict", "group:review:rogue", "group:review:orphan", "group:review:ptr_mismatch", "group:info:rogue", "group:info:ghost"];
  await expect(grid.locator('[data-key^="group:"]')).toHaveCount(groupKeys.length);
  expect(await grid.locator('[data-key^="group:"]').evaluateAll((rows) => rows.map((row) => row.getAttribute("data-key")))).toEqual(groupKeys);
  const counts: Record<string, string> = {
    "group:act:conflict": "2",
    "group:review:rogue": "1",
    "group:review:orphan": "2",
    "group:review:ptr_mismatch": "2",
    "group:info:rogue": "1",
    "group:info:ghost": "2",
  };
  for (const [key, count] of Object.entries(counts)) {
    const group = withKey(grid, "row", key);
    await expect(group).toHaveAttribute("data-expanded", "true");
    await expect(group.getByTestId("group-count")).toHaveText(count);
    await expect(group.getByTestId("group-note")).not.toBeEmpty();
  }
  await expect(dataRows(grid)).toHaveCount(10);
  await expect(page.getByTestId("reconcile-facts")).toHaveText(/ · 2 to act on · 5 to review · 3 info$/);
  await expect(page.getByTestId("reconcile-more")).toHaveCount(0);

  // The rule once per group where every row shares it: a conflict never resolves by itself, the
  // rogue rows have one rule each; the rules of the other groups differ per row, so no group says one.
  await expect(withKey(grid, "row", "group:act:conflict").getByTestId("group-sentence")).toContainText("Never resolved automatically");
  await expect(withKey(grid, "row", "group:review:rogue").getByTestId("group-sentence")).toContainText("newest sighting wins");
  for (const key of ["group:review:orphan", "group:review:ptr_mismatch", "group:info:ghost"]) {
    await expect(withKey(grid, "row", key).getByTestId("group-sentence")).toHaveCount(0);
  }
  // The rule column is hidden by default: the rule of a row is in the panel and the column menu.
  const reserved = withKey(grid, "row", "192.0.2.5");
  await expect(reserved).toHaveAttribute("data-id", "192.0.2.5|ghost");
  await expect(cell(reserved, "rule")).toHaveCount(0);
  await expect(cell(reserved, "os")).toHaveCount(0);

  // The truth that wins carries the check glyph, and the outcome says who wins; a conflict has none.
  await expect(cell(reserved, "intent").getByTestId("reconcile-wins")).toHaveAttribute("aria-label", "Wins");
  await expect(reserved.getByTestId("reconcile-wins")).toHaveCount(1);
  await expect(reserved.getByTestId("reconcile-winner")).toHaveAttribute("data-winner", "intent");
  await expect(reserved.getByTestId("reconcile-winner")).toHaveText("Intent wins");
  const lease = withKey(grid, "row", "192.0.2.20");
  await expect(cell(lease, "lease").getByTestId("reconcile-wins")).toHaveCount(1);
  await expect(lease.getByTestId("reconcile-wins")).toHaveCount(1);
  await expect(lease.getByTestId("reconcile-winner")).toHaveAttribute("data-winner", "lease");
  const manual = withKey(grid, "row", "192.0.2.78");
  await expect(cell(manual, "dns").getByTestId("reconcile-wins")).toHaveCount(1);
  await expect(manual.getByTestId("reconcile-winner")).toHaveAttribute("data-winner", "dns");
  await expect(withKey(grid, "row", "192.0.2.151").getByTestId("reconcile-winner")).toHaveAttribute("data-winner", "scan");
  const conflict = withKey(grid, "row", "192.0.2.44");
  await expect(conflict.getByTestId("reconcile-winner")).toHaveAttribute("data-winner", "none");
  await expect(conflict.getByTestId("reconcile-winner")).toHaveText("No winner");
  await expect(conflict.getByTestId("reconcile-wins")).toHaveCount(0);
  // The mock's rows have no finding on the real server, so no row has a default action.
  await expect(grid.getByTestId("finding-action")).toHaveCount(0);

  // Narrow the page to one kind: the ghost groups only, and the chips keep their counts.
  for (const kind of ["conflict", "ghost", "rogue", "orphan", "ptr_mismatch"]) {
    await expect(page.getByTestId(`filter-kind-${kind}`).getByTestId("chip-count")).toHaveText("2");
  }
  // Every kind asked for its own rows once; narrowing the page does not read the other kinds again.
  expect(fake.queries.map((q) => q.get("kind")).sort()).toEqual(["conflict", "ghost", "orphan", "ptr_mismatch", "rogue"]);
  await page.getByTestId("filter-kind-ghost").click();
  await expect(page).toHaveURL(/kind=ghost/);
  await expect(grid.locator('[data-key^="group:"]')).toHaveCount(1);
  await expect(withKey(grid, "row", "group:info:ghost")).toBeVisible();
  await expect(dataRows(grid)).toHaveCount(2);
  expect(fake.queries.map((q) => q.get("kind")).filter((kind) => kind !== "ghost").sort()).toEqual(["conflict", "orphan", "ptr_mismatch", "rogue"]);
  await page.getByTestId("filter-kind-all").click();
  await expect(grid.locator('[data-key^="group:"]')).toHaveCount(groupKeys.length);

  // A closed group hides its rows and keeps its count; opening it brings them back.
  const ghosts = withKey(grid, "row", "group:info:ghost");
  await ghosts.click();
  await expect(ghosts).toHaveAttribute("data-expanded", "false");
  await expect(dataRows(grid)).toHaveCount(8);
  await expect(ghosts.getByTestId("group-count")).toHaveText("2");
  await ghosts.click();
  await expect(ghosts).toHaveAttribute("data-expanded", "true");
  await expect(dataRows(grid)).toHaveCount(10);

  // A conflict opens the side panel with the two MAC addresses on its address first.
  const rowParam = () => new URL(page.url()).searchParams.get("row");
  await cell(conflict, "outcome").click();
  await expect.poll(rowParam).toBe("192.0.2.44|conflict");
  const panel = page.getByTestId("finding-panel");
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId("conflict-lead")).toBeVisible();
  await expect(panel.getByTestId("conflict-mac")).toHaveCount(2);
  await expect(panel.getByTestId("conflict-mac").first()).toHaveAttribute("data-mac", "00:00:5e:00:53:2c");
  await expect(panel.getByTestId("conflict-mac").last()).toHaveAttribute("data-mac", "00:00:5e:00:53:c8");
  await expect(panel.getByTestId("truth-list")).toBeVisible();

  // A rogue without a proposal opens the finding panel with its four truths and no conflict lead.
  await cell(withKey(grid, "row", "192.0.2.151"), "outcome").click();
  await expect.poll(rowParam).toBe("192.0.2.151|rogue");
  await expect(panel.getByTestId("truth-list")).toBeVisible();
  await expect(panel.getByTestId("conflict-lead")).toHaveCount(0);

  // A rogue with a proposal opens the proposal's panel. The proposal is the mock's, so the real
  // server answers 404 and the panel shows its error state (see the header).
  await cell(withKey(grid, "row", "192.0.2.150"), "outcome").click();
  await expect.poll(rowParam).toBe("192.0.2.150|rogue");
  const proposalPanel = withId(page, "proposal-panel", fake.proposal);
  await expect(proposalPanel).toBeVisible();
  await expect(proposalPanel.getByTestId("error-notice")).toBeVisible();
  await expect(panel).toHaveCount(0);
});

test("shows the OS field of the DHCP fingerprint and the vendors on the host page", async ({ page, api, signedIn }) => {
  void signedIn;
  const host = await makeHost(api);
  const fake = await fakeReconcile(page, host);

  await page.goto(`/ipam/hosts/${HOST_NAME}`);
  const observations = page.getByTestId("host-observations");
  await expect(observations).toBeVisible();
  const os = observations.getByTestId("host-reconcile-os");
  await expect(os.getByTestId("reconcile-os-guess")).toHaveText("Windows 10 or 11 (or Server 2016 and later) (85 %)");
  await expect(os.getByTestId("reconcile-os-source")).toHaveText("from dhcp:1 (Lease)");
  await expect(observations.getByTestId("host-reconcile-vendors")).toHaveText("MSFT 5.0");
  expect(fake.queries.some((q) => q.get("host") === host.id && q.get("limit") === "1")).toBe(true);

  // The link opens the view narrowed to the host.
  await observations.getByTestId("host-reconcile-link").click();
  await expect(page).toHaveURL(new RegExp(`/ipam/reconcile\\?host=${host.id}$`));
  await expect(page.getByTestId("filter-host")).toContainText(HOST_NAME);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the reconciliation view in Swedish", async ({ page, api, signedIn }, testInfo) => {
    void signedIn;
    await fakeReconcile(page, await makeHost(api));
    await page.goto("/ipam/reconcile");
    const grid = page.getByTestId("grid-reconcile");
    await expect(withKey(grid, "row", "group:act:conflict").getByTestId("group-count")).toHaveText("2");
    await expect(dataRows(grid)).toHaveCount(10);
    await expect(page.getByTestId("reconcile-facts")).toHaveText(/ · 2 att åtgärda · 5 att granska · 3 info$/);
    await expectRendered(page, page.getByTestId("page-ipam-reconcile"), "sv", testInfo, "ipam-reconcile");
  });
});
