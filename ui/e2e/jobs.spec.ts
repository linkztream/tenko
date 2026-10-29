// Scenario: the jobs list (IPAM-17, API-09; U5 of the UI plan, docs/jobs.md) against the real
// server, no fakes. Two networks created through the API leave two finished `ipam.edit` jobs of
// the signed-in administrator; the list opens on the default chip "Active and needs you", says in
// one line that nothing runs or waits when the server has no open job, groups the finished jobs
// under Today, says the one starter once instead of a Started by column, names each job by the
// label catalog with the kind as its code and the duration in the Steps column, and takes the
// waiting count of its header from the findings counts that the rail badge reads. The chips
// narrow the list; the page passes axe and renders in Swedish.
//
// What stays with the unit tests (`src/jobs/JobsView.test.tsx`, `layout.test.ts`): the jobs that
// wait for a person and run (no spec here starts a job that waits), Yesterday and Earlier and the
// edges of midnight, ten rows a day with Show the rest, the next page of the history, a second
// starter.
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { Page } from "@playwright/test";
import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { cell, gridRow } from "./support/ui";

type Job = Schemas["JobSummary"];
type Page_ = Schemas["Page_JobSummary"];

/** Runs axe-core in the page (through the debugging protocol, since the CSP refuses injected tags). */
async function axeViolations(page: Page, selector: string): Promise<string[]> {
  await page.evaluate(await readFile(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8"));
  return page.evaluate(async (scope) => {
    const axe = (window as unknown as { axe: { run(context: string): Promise<{ violations: { id: string }[] }> } }).axe;
    return (await axe.run(scope)).violations.map((v) => v.id);
  }, selector);
}

const OPEN_STATES = "queued,running,waiting,rolling_back";
const FINAL_STATES = "succeeded,failed,rolled_back,cancelled";

/** Two networks through the API: two finished IPAM edits by the signed-in administrator. */
async function twoEdits(api: Api): Promise<Job[]> {
  await api.post("/prefixes", { cidr: "198.51.100.0/24", description: "Jobs one" });
  await api.post("/prefixes", { cidr: "203.0.113.0/24", description: "Jobs two" });
  let edits: Job[] = [];
  await expect
    .poll(async () => {
      edits = (await api.get<Page_>("/jobs", { kind: "ipam.edit", state: FINAL_STATES, limit: 100 })).items;
      return edits.length;
    })
    .toBeGreaterThanOrEqual(2);
  return edits;
}

async function openList(page: Page): Promise<void> {
  await page.goto("/jobs");
  await expect(page.getByTestId("page-jobs")).toBeVisible();
  await expect(page.getByTestId("view-active")).toHaveAttribute("aria-pressed", "true");
}

test("the default chip leads with what runs or waits and lists the finished jobs by day", async ({ page, api, signedIn }) => {
  void signedIn;
  const edits = await twoEdits(api);
  const open = (await api.get<Page_>("/jobs", { state: OPEN_STATES, limit: 100 })).items;
  const finished = (await api.get<Page_>("/jobs", { state: FINAL_STATES, limit: 200 })).items;
  await openList(page);

  // Nothing runs or waits on a fresh server: one calm line, the days under it.
  if (open.length === 0) {
    await expect(page.getByTestId("jobs-calm")).toHaveText("Nothing is running and no job waits for you. Finished jobs are below.");
    await expect(page.getByTestId("view-active").getByTestId("chip-count")).toHaveText("0");
  } else {
    await expect(page.getByTestId("jobs-calm")).toHaveCount(0);
  }
  const today = page.locator('[data-testid="group-row"][data-group="today"]');
  await expect(today).toHaveAttribute("data-open", "true");
  await expect(today.getByTestId("group-count")).toHaveText(String(finished.length));

  // A row of each edit: the title from the catalog, the kind as its code, the duration.
  for (const job of edits.slice(0, 2)) {
    const row = gridRow(page, "jobs", job.id);
    await expect(row).toBeVisible();
    await expect(cell(row, "kind")).toHaveText("ipam.edit");
    await expect(cell(row, "title")).not.toContainText("ipam.job.edit");
    await expect(cell(row, "title")).toContainText(/^Edit \d+ IPAM objects?/);
    await expect(row.getByTestId("job-state")).toHaveText(job.state === "succeeded" ? "Done" : /./);
    if (job.state === "succeeded") await expect(row.getByTestId("job-duration")).toHaveText(/^(under 1 s|\d+ (s|min)( \d+ s)?)$/);
    // Every row of the list is one 28 px row (its bottom hairline included).
    const box = await row.boundingBox();
    expect(Math.round(box?.height ?? 0)).toBeGreaterThanOrEqual(28);
    expect(Math.round(box?.height ?? 0)).toBeLessThanOrEqual(29);
  }

  // One starter is said once, and the column is gone; two bring it back.
  const listed = [...open, ...finished];
  const starters = new Set(listed.map((job) => JSON.stringify([job.created.by.kind, "id" in job.created.by ? job.created.by.id : job.created.by.component])));
  if (starters.size === 1) {
    await expect(page.getByTestId("jobs-starter")).toHaveText("Started by · all you");
    await expect(page.getByRole("columnheader", { name: "Started by" })).toHaveCount(0);
  } else {
    await expect(page.getByTestId("jobs-starter")).toHaveCount(0);
    await expect(page.getByRole("columnheader", { name: /^Started by/ })).toBeVisible();
  }

  // The waiting count of the header is the findings store's, the number of the rail badge.
  const counts = await api.get<Schemas["FindingCounts"]>("/findings/counts");
  const waiting = counts.areas.jobs.act + counts.areas.jobs.review;
  await expect(page.getByTestId("page-sub")).toContainText(`${waiting} waiting for you`);
});

test("the chips narrow the list to the finished and the failed jobs", async ({ page, api, signedIn }) => {
  void signedIn;
  const edits = await twoEdits(api);
  await openList(page);
  await page.getByTestId("view-finished").click();
  await expect(page).toHaveURL(/\?view=finished$/);
  await expect(gridRow(page, "jobs", edits[0]!.id)).toBeVisible();
  await expect(page.getByTestId("jobs-calm")).toHaveCount(0);
  await page.getByTestId("view-failed").click();
  await expect(gridRow(page, "jobs", edits[0]!.id)).toHaveCount(0);
  await page.getByTestId("view-active").click();
  await expect(page).toHaveURL(/\/jobs$/);
  await expect(gridRow(page, "jobs", edits[0]!.id)).toBeVisible();
});

test("the page passes axe", async ({ page, api, signedIn }) => {
  void signedIn;
  await twoEdits(api);
  await openList(page);
  await expect(page.locator('[data-testid="group-row"][data-group="today"]')).toBeVisible();
  expect(await axeViolations(page, "[data-testid='page-jobs']")).toEqual([]);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the jobs list in Swedish", async ({ page, api, signedIn }, testInfo) => {
    void signedIn;
    await twoEdits(api);
    await page.goto("/jobs");
    await expect(page.getByTestId("page-jobs")).toBeVisible();
    await expect(page.locator('[data-testid="group-row"][data-group="today"]')).toContainText("I dag");
    await expectRendered(page, page.getByTestId("page-jobs"), "sv", testInfo, "jobs");
  });
});
