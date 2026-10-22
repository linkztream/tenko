// The blocking view of the DNS area (/dns/blocking): open it from the DNS navigation, see the
// four tiles, the hours and the tables, pause the block lists for 5 minutes and see "Paused
// until", resume, allow a blocked name from the log and see the outcome, switch to 7 days, the
// notice of a log that is off, and the page in Swedish.
//
// THE ROUTES ARE FAKED: the e2e server is one controller without the `dns` role
// (support/server.ts writes `roles = "controller"`), so it has no query log to count. The fake
// (support/dns-blocking-mock.ts) answers `/api/v1/dns/blocking/*` in the browser with the
// service of the mock API (src/api/mock/dns-blocking-model.ts) and lets everything else reach
// the real server. The real figures, the pause and the allow list are proven in Rust:
// crates/tenko-api/tests/dns_blocking.rs.

import { expect, test } from "./support/fixtures";
import { FakeBlocking } from "./support/dns-blocking-mock";
import { expectRendered } from "./support/i18n";

test("opens the blocking view from the DNS navigation, pauses and resumes, and allows a blocked name", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeBlocking.install(page);
  await page.goto("/dns");
  await expect(page.getByTestId("dns-nav")).toBeVisible();
  await page.getByTestId("dns-nav").locator('[data-key="blocking"]').click();
  await expect(page).toHaveURL(/\/dns\/blocking$/);
  await expect(page.getByTestId("page-dns-blocking")).toBeVisible();
  await expect(page.getByTestId("dns-nav").locator('[data-key="blocking"]')).toHaveAttribute("aria-current", "page");

  // The four tiles and the hours of the last day.
  for (const name of ["queries", "blocked", "cached", "clients"]) {
    await expect(page.getByTestId(`blocking-tile-${name}`)).toBeVisible();
  }
  await expect(page.getByTestId("blocking-tile-clients")).toHaveAttribute("data-value", "4");
  await expect(page.getByTestId("blocking-hour")).toHaveCount(24);
  expect(Number(await page.getByTestId("blocking-tile-queries").getAttribute("data-value"))).toBeGreaterThan(0);
  await expect(page.getByTestId("blocking-share")).toHaveText(/^\d+(\.\d)?%$/);
  await expect(page.getByTestId("blocking-list")).toHaveCount(2);
  await expect(page.getByTestId("blocking-recent-row")).toHaveCount(12);
  await expect(page.getByTestId("blocking-pause-status")).toHaveAttribute("data-state", "on");

  // Pause for 5 minutes, see it, resume.
  await page.getByTestId("blocking-pause-5").click();
  await expect(page.getByTestId("blocking-pause-status")).toContainText("Paused until");
  await expect(page.getByTestId("blocking-pause-status")).toHaveAttribute("data-state", "timed");
  await expect(page.getByTestId("blocking-pause-left")).toBeVisible();
  expect(fake.sent.at(-1)).toMatchObject({ method: "POST", body: { minutes: 5 } });
  expect(fake.paused()?.until).toBeTruthy();
  await page.getByTestId("blocking-resume").click();
  await expect(page.getByTestId("blocking-pause-status")).toContainText("Blocking is on");
  await expect(page.getByTestId("blocking-resume")).toHaveCount(0);
  expect(fake.sent.at(-1)).toMatchObject({ method: "DELETE" });
  expect(fake.paused()).toBeNull();

  // Allow the newest blocked name from the log.
  const first = page.getByTestId("blocking-recent-row").first();
  const name = await first.getAttribute("data-key");
  expect(name).toBe("ads.example.test");
  await first.getByTestId("blocking-allow").click();
  const result = first.getByTestId("blocking-allow-result");
  await expect(result).toHaveAttribute("data-state", "added");
  await expect(result).toContainText("Added to the list allowed; the list is compiled now");
  await expect(first.getByTestId("blocking-allow-job")).toBeVisible();
  expect(fake.sent.at(-1)).toMatchObject({ method: "POST", body: { name: "ads.example.test" } });
  expect(fake.state.allowed).toEqual(["ads.example.test"]);

  // The 7-day window.
  await page.getByTestId("blocking-window-7d").click();
  await expect(page.getByTestId("blocking-hour")).toHaveCount(168);
  await expect(page).toHaveURL(/window=7d/);
  expect(fake.reads.at(-1)).toBe("7d");
});

test("says where the query log is turned on when it is off", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeBlocking.install(page);
  fake.state.logOff = true;
  await page.goto("/dns/blocking");
  const off = page.getByTestId("blocking-log-off");
  await expect(off).toBeVisible();
  await expect(off).toContainText("[dns.log]");
  await expect(page.getByTestId("blocking-tile-queries")).toHaveCount(0);
  await off.getByTestId("blocking-settings-link").click();
  await expect(page).toHaveURL(/\/settings\/dns$/);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the blocking view in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await FakeBlocking.install(page);
    await page.goto("/dns/blocking");
    await expect(page.getByTestId("blocking-hour")).toHaveCount(24);
    await expectRendered(page, page.getByTestId("page-dns-blocking"), "sv", testInfo, "dns-blocking");
    await expect(page.getByTestId("blocking-pause-5")).toHaveText("5 minuter");
  });
});
