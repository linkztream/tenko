// WP8.2: the reconciliation view (/ipam/reconcile) and the OS block of the host page: open the
// view from the IPAM navigation, see the five lists with the rule in words and the winner of
// each row, narrow the page to one kind, follow the discovered-host proposal of a rogue, and see
// the OS field of the DHCP fingerprint and the vendors on a host page. The page in Swedish.
//
// THE ROUTE IS FAKED: the reconciliation view derives its rows from leases, sightings and DNS
// records that the one controller of the e2e server does not have (no DHCP role, no probe, no
// connector), so `GET /api/v1/ipam/reconcile` is answered in the browser with the rows of the
// mock API (src/api/mock/ipam-reconcile-model.ts, the data the msw handler and the component
// tests use); everything else reaches the real server, among them the host the page is opened
// for. The real derivation is proven in Rust: crates/tenko-ipam/tests/reconcile_view.rs and the
// route tests of crates/tenko-api.

import { randomUUID } from "node:crypto";
import type { Page, Route } from "@playwright/test";
import { filterRows, hostTruths, seedRows, type ReconcileRow } from "../src/api/mock/ipam-reconcile-model";
import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

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

async function makeHost(api: Api): Promise<Schemas["Host"]> {
  return (await api.post<{ item: Schemas["Host"] }>("/hosts", { name: HOST_NAME, mode: "dynamic" })).item;
}

test("shows the five lists with the rule and the winner of each row, narrows to one kind and follows a proposal", async ({ page, api, signedIn }) => {
  void signedIn;
  const host = await makeHost(api);
  const fake = await fakeReconcile(page, host);

  await page.goto("/ipam/addresses");
  await page.getByTestId("ipam-nav").locator('[data-tab="reconcile"]').click();
  await expect(page).toHaveURL(/\/ipam\/reconcile$/);
  await expect(page.getByTestId("page-ipam-reconcile")).toBeVisible();
  await expect(page.getByTestId("ipam-nav").locator('[data-tab="reconcile"]')).toHaveAttribute("aria-current", "page");

  // The five lists, with their counts.
  for (const kind of ["conflict", "ghost", "rogue", "orphan", "ptr_mismatch"]) {
    const section = page.getByTestId(`reconcile-section-${kind}`);
    await expect(section).toBeVisible();
    await expect(section.getByTestId("reconcile-count")).toHaveText("2");
    await expect(section.getByTestId("reconcile-row")).toHaveCount(2);
  }

  // The rule in words and the winner of a row; a conflict has none.
  const reserved = page.locator('[data-testid="reconcile-row"][data-key="192.0.2.5|ghost"]');
  await expect(reserved.getByTestId("reconcile-winner")).toHaveText("Intent wins");
  await expect(reserved.getByTestId("reconcile-rule")).toHaveText("Intent wins: the host is managed, so what intent says stands.");
  await expect(reserved.locator("td[data-winner='true']")).toHaveAttribute("data-truth", "intent");
  const conflict = page.locator('[data-testid="reconcile-row"][data-key="192.0.2.44|conflict"]');
  await expect(conflict.getByTestId("reconcile-winner")).toHaveText("No winner");
  await expect(conflict.getByTestId("reconcile-rule")).toContainText("Never resolved automatically");
  await expect(page.locator('[data-testid="reconcile-row"][data-key="192.0.2.78|orphan"]').getByTestId("reconcile-rule")).toHaveText("Written by hand, so it stays as written.");
  await expect(page.locator('[data-testid="reconcile-row"][data-key="192.0.2.90|ptr_mismatch"]').getByTestId("reconcile-rule")).toContainText("The forward record wins");
  await expect(page.locator('[data-testid="reconcile-row"][data-key="192.0.2.150|rogue"]').getByTestId("reconcile-rule")).toContainText("newest sighting wins");

  // Narrow the page to one kind.
  await page.getByTestId("filter-kind-ghost").click();
  await expect(page).toHaveURL(/kind=ghost/);
  await expect(page.locator("[data-testid^='reconcile-section-']")).toHaveCount(1);
  await expect(page.getByTestId("reconcile-section-ghost").getByTestId("reconcile-row")).toHaveCount(2);
  // Every list asks for its own kind; narrowing the page reads nothing again.
  expect(fake.queries.map((q) => q.get("kind")).sort()).toEqual(["conflict", "ghost", "orphan", "ptr_mismatch", "rogue"]);
  await page.getByTestId("filter-kind-all").click();
  await expect(page.locator("[data-testid^='reconcile-section-']")).toHaveCount(5);

  // The discovered-host proposal of a rogue.
  const link = page.locator('[data-testid="reconcile-row"][data-key="192.0.2.150|rogue"]').getByTestId("reconcile-proposal");
  await expect(link).toHaveAttribute("href", `/discovery/${fake.proposal}`);
  await link.click();
  await expect(page).toHaveURL(new RegExp(`/discovery/${fake.proposal}$`));
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
    await expect(page.getByTestId("reconcile-section-conflict").getByTestId("reconcile-row")).toHaveCount(2);
    await expectRendered(page, page.getByTestId("page-ipam-reconcile"), "sv", testInfo, "ipam-reconcile");
  });
});
