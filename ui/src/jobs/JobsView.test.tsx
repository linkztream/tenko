import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Principal } from "../api/types";
import { findJob, jobStore, MOCK_JOB_IDS, MOCK_MOVE_GROUP, recordPastJob } from "../api/mock/job-store";
import { MOCK_USER_IDS } from "../api/mock/fixtures";
import { mockFindingCounts } from "../api/mock/findings-store";
import { server } from "../api/mock/node";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { resetGroupStateForTest } from "../grid/groups";
import { resetJobDetails } from "./data";
import JobDetail from "./JobDetail";
import { dayBefore, startOfDay } from "./layout";
import JobsView from "./JobsView";

// The list reads the clock for its day groups: the seeds are built at 15:00 on 29 October 2026,
// so the done and cancelled seeds finished today and the rolled back one yesterday.
const NOW = new Date(2026, 9, 29, 15, 0, 0);

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ["Date"], now: NOW });
  resetJobDetails();
  resetGroupStateForTest();
  await signInAlex();
});
afterEach(() => {
  setSessionForTest(null);
  vi.useRealTimers();
});

const ALEX: Principal = { kind: "user", id: MOCK_USER_IDS.alex, session: "0190d1c2-0000-7000-8000-0000000e0001", strength: "passkey" };
const SAM: Principal = { kind: "user", id: MOCK_USER_IDS.sam, session: "0190d1c2-0000-7000-8000-0000000e0002", strength: "password" };

function renderList(url = "/jobs") {
  return renderRoute(JobsView, { url, path: "/jobs", routes: { "/jobs/:id": JobDetail } });
}

/** Every line of the grid: group rows, jobs and the last rows of the days. */
function lines(): HTMLElement[] {
  return screen.queryAllByTestId("row");
}

/** The rows of jobs, without group rows and the last rows of the days. */
function rows(): HTMLElement[] {
  return lines().filter((r) => !r.classList.contains("group-row") && !r.classList.contains("group-tail"));
}

function groupRows(): HTMLElement[] {
  return lines().filter((r) => r.classList.contains("group-row"));
}

function groupOf(key: string): HTMLElement {
  const row = screen.queryAllByTestId("group-row").find((g) => g.dataset.group === key);
  if (!row) throw new Error(`no group ${key}`);
  return row;
}

function rowOf(id: string): HTMLElement {
  const row = rows().find((r) => r.dataset.id === id);
  if (!row) throw new Error(`no row for job ${id}`);
  return row;
}

async function listed(count: number) {
  await waitFor(() => expect(rows()).toHaveLength(count));
}

/** Every line of the grid, the ones outside its window included: the grid draws only those in view. */
function lineCount(): number {
  return Number(screen.getByRole("grid", { name: "Jobs" }).getAttribute("aria-rowcount")) - 1;
}

function chip(name: string): HTMLElement {
  return screen.getByRole("button", { name: new RegExp(`^${name}`) });
}

function header(): string[] {
  return screen.getAllByRole("columnheader").map((h) => h.textContent ?? "");
}

/** Only finished jobs: `count` of them by `by`, spread over today, yesterday and earlier. */
function history(counts: { today: number; yesterday: number; earlier: number }, by: Principal = ALEX): void {
  jobStore.jobs = [];
  const now = Date.now();
  const today = startOfDay(now);
  const yesterday = dayBefore(today);
  const add = (finished: number, i: number) =>
    recordPastJob(
      { kind: "ipam.edit", title: "ipam.job.edit", targets: [{ kind: "host", id: `0190d1c2-0000-7000-8000-${String(i).padStart(12, "0")}` }] },
      { created: finished - 130_000, finished, by },
    );
  let i = 0;
  for (let k = 0; k < counts.today; k++) add(today + ((now - today) * (k + 1)) / (counts.today + 1), (i += 1));
  for (let k = 0; k < counts.yesterday; k++) add(yesterday + k * 60_000, (i += 1));
  for (let k = 0; k < counts.earlier; k++) add(yesterday - (k + 1) * 3_600_000, (i += 1));
  // Newest first, as the server lists them.
  jobStore.jobs.sort((a, b) => Date.parse(b.job.created.at) - Date.parse(a.job.created.at));
}

describe("the jobs list", () => {
  it("leads with the job that waits for you, then the running ones, then the finished ones by day", async () => {
    renderList();
    await listed(6);
    expect(groupRows().map((g) => g.dataset.id)).toEqual(["\u0001group:needs", "\u0001group:active", "\u0001group:today", "\u0001group:yesterday"]);
    expect(within(groupOf("needs")).getByText("Waiting for you")).toBeTruthy();
    expect(within(groupOf("active")).getByText("In progress")).toBeTruthy();
    expect(groupOf("today").textContent).toContain("Today");
    expect(within(groupOf("today")).getByTestId("group-count").textContent).toBe("2");
    expect(within(groupOf("today")).getByTestId("group-note").textContent).toBe("finished");
    expect(within(groupOf("yesterday")).getByTestId("group-note").textContent).toBe("failed or rolled back");
    expect(rows().map((r) => r.dataset.id)).toEqual([
      MOCK_JOB_IDS.moveWaiting,
      MOCK_JOB_IDS.importRunning,
      MOCK_JOB_IDS.moveQueued,
      MOCK_JOB_IDS.applySucceeded,
      MOCK_JOB_IDS.applyCancelled,
      MOCK_JOB_IDS.moveRolledBack,
    ]);
  });

  it("says the state in glyph and word, and names the title, the host and the object count", async () => {
    renderList();
    await listed(6);
    expect(within(rowOf(MOCK_JOB_IDS.moveWaiting)).getByText("Waiting for you")).toBeTruthy();
    expect(within(rowOf(MOCK_JOB_IDS.moveQueued)).getByText("Queued")).toBeTruthy();
    expect(within(rowOf(MOCK_JOB_IDS.importRunning)).getByText("Running")).toBeTruthy();
    expect(within(rowOf(MOCK_JOB_IDS.applySucceeded)).getByText("Done")).toBeTruthy();
    expect(within(rowOf(MOCK_JOB_IDS.moveRolledBack)).getByText("Rolled back")).toBeTruthy();
    expect(within(rowOf(MOCK_JOB_IDS.applyCancelled)).getByText("Cancelled")).toBeTruthy();
    expect(within(rowOf(MOCK_JOB_IDS.importRunning)).getByText("Apply an import")).toBeTruthy();
    // A move is titled "Move" and names its host; it changes the host and the target network.
    const move = rowOf(MOCK_JOB_IDS.moveWaiting);
    expect(within(move).getByRole("link", { name: "Move" })).toBeTruthy();
    expect(await within(move).findByRole("link", { name: "thermostat-1" })).toBeTruthy();
    expect(within(move).getByTestId("job-count").textContent).toBe("2 objects");
    expect(within(rowOf(MOCK_JOB_IDS.applySucceeded)).getByTestId("job-count").textContent).toBe("1 object");
    // The kind stays, as the code in the data font.
    expect(rowOf(MOCK_JOB_IDS.moveWaiting).querySelector('[data-col="kind"]')?.textContent).toBe("ipam.move");
  });

  it("shows the steps, the current step only while a job runs or waits, and how long a done job took", async () => {
    renderList();
    await listed(6);
    const waiting = rowOf(MOCK_JOB_IDS.moveWaiting);
    expect(within(waiting).getByText("1 of 6")).toBeTruthy();
    // The step's own words arrive with the job's detail.
    expect(await within(waiting).findByText("Create a DHCP reservation of 198.51.100.41 in the scope of 198.51.100.0/24; keep the old one until cleanup.")).toBeTruthy();
    expect(within(rowOf(MOCK_JOB_IDS.importRunning)).getByText("2 of 3")).toBeTruthy();
    expect(await within(rowOf(MOCK_JOB_IDS.importRunning)).findByText("Apply the planned changes")).toBeTruthy();
    // A job that is over has no current step.
    for (const id of [MOCK_JOB_IDS.moveRolledBack, MOCK_JOB_IDS.applySucceeded, MOCK_JOB_IDS.applyCancelled]) {
      expect(rowOf(id).querySelector('[data-col="step"]')?.textContent).toBe("");
    }
    // A done job says how long it took instead of its steps; the seed ran in no time.
    const took = within(rowOf(MOCK_JOB_IDS.applySucceeded)).getByTestId("job-duration");
    expect(took.textContent).toBe("under 1 s");
    expect(took.getAttribute("title")).toBe("Took under 1 s from submission to end");
    // A job that stopped keeps the steps it reached.
    expect(rowOf(MOCK_JOB_IDS.moveRolledBack).querySelector('[data-col="steps"]')?.textContent).toMatch(/^\d+ of \d+$/);
  });

  it("marks the job that waits for a person in its state, with the edge on its row", async () => {
    renderList();
    await listed(6);
    const marked = screen.getAllByTestId("job-state").filter((s) => s.dataset.needs === "true");
    expect(marked).toHaveLength(1);
    expect(marked[0]?.textContent).toBe("Waiting for you");
    expect(rowOf(MOCK_JOB_IDS.moveWaiting).contains(marked[0] as Node)).toBe(true);
    expect(rowOf(MOCK_JOB_IDS.moveWaiting).classList.contains("needs")).toBe(true);
    expect(rowOf(MOCK_JOB_IDS.moveQueued).classList.contains("needs")).toBe(false);
  });

  it("says the facts in the header, with the waiting count of the findings store", async () => {
    renderList();
    await listed(6);
    const counts = mockFindingCounts();
    const waiting = counts.areas.jobs.act + counts.areas.jobs.review;
    expect(waiting).toBe(1);
    await waitFor(() => expect(screen.getByTestId("page-sub").textContent).toBe(`2 running · ${waiting} waiting for you · 3 finished`));
  });

  it("reads the waiting count from the store, not from the list", async () => {
    server.use(
      http.get("/api/v1/findings/counts", () => {
        const body = mockFindingCounts();
        return HttpResponse.json({ ...body, areas: { ...body.areas, jobs: { act: 4, review: 1, info: 0 } } });
      }),
    );
    renderList();
    await listed(6);
    await waitFor(() => expect(screen.getByTestId("page-sub").textContent).toContain("5 waiting for you"));
    // The list itself still holds the one job that waits.
    expect(within(groupOf("needs")).getByTestId("group-count").textContent).toBe("1");
  });

  it("opens a job from its title and from a click in the row, and a group row only opens and closes", async () => {
    const view = renderList();
    await listed(6);
    fireEvent.click(within(rowOf(MOCK_JOB_IDS.moveQueued)).getByRole("link", { name: "Move" }));
    await waitFor(() => expect(view.location()).toBe(`/jobs/${MOCK_JOB_IDS.moveQueued}`));
    expect(await screen.findByTestId("page-job")).toBeTruthy();
    view.history.set({ value: "/jobs" });
    await listed(6);
    // The state cell has no link of its own: a click on it opens the job as well.
    fireEvent.click(within(rowOf(MOCK_JOB_IDS.applySucceeded)).getByText("Done"));
    await waitFor(() => expect(view.location()).toBe(`/jobs/${MOCK_JOB_IDS.applySucceeded}`));
    view.history.set({ value: "/jobs" });
    await listed(6);
    fireEvent.click(groupOf("today").querySelector(".group-note") as HTMLElement);
    await listed(4);
    expect(view.location()).toBe("/jobs");
  });

  it("opens and closes a group and opens the focused job with Enter", async () => {
    const view = renderList();
    await listed(6);
    const grid = screen.getByRole("grid", { name: "Jobs" });
    fireEvent.focus(grid);
    // The focus starts on the first line, the group of the jobs that wait for you.
    fireEvent.keyDown(grid, { key: "Enter" });
    await listed(5);
    expect(groupOf("needs").closest("tr")?.dataset.expanded).toBe("false");
    fireEvent.keyDown(grid, { key: " " });
    await listed(6);
    fireEvent.keyDown(grid, { key: "ArrowDown" });
    fireEvent.keyDown(grid, { key: "Enter" });
    await waitFor(() => expect(view.location()).toBe(`/jobs/${MOCK_JOB_IDS.moveWaiting}`));
  });

  it("filters by the state chips, with Active and needs you as the default", async () => {
    renderList();
    await listed(6);
    expect(chip("Active and needs you").getAttribute("aria-pressed")).toBe("true");
    expect(within(chip("Active and needs you")).getByTestId("chip-count").textContent).toBe("3");
    expect(within(chip("Failed or rolled back")).getByTestId("chip-count").textContent).toBe("1");
    expect(within(chip("Finished")).queryByTestId("chip-count")).toBeNull();

    fireEvent.click(chip("Failed or rolled back"));
    await listed(1);
    expect(rows()[0]?.dataset.id).toBe(MOCK_JOB_IDS.moveRolledBack);
    expect(groupRows().map((g) => g.dataset.id)).toEqual(["\u0001group:yesterday"]);

    fireEvent.click(chip("Finished"));
    await listed(3);
    expect(rows().map((r) => r.dataset.id)).toEqual([MOCK_JOB_IDS.applySucceeded, MOCK_JOB_IDS.applyCancelled, MOCK_JOB_IDS.moveRolledBack]);
    // Nothing that runs is listed, so there is no current step to show.
    expect(header()).not.toContain("Current step");

    fireEvent.click(chip("All"));
    await listed(6);
    expect(header()).toContain("Current step");

    fireEvent.click(chip("Active and needs you"));
    await listed(6);
  });

  it("takes the chip from the URL, and the former Needs you chip opens the default", async () => {
    renderList("/jobs?view=failed");
    await listed(1);
    expect(chip("Failed or rolled back").getAttribute("aria-pressed")).toBe("true");
  });

  it("opens the default for the former Needs you link", async () => {
    renderList("/jobs?view=needs");
    await listed(6);
    expect(chip("Active and needs you").getAttribute("aria-pressed")).toBe("true");
  });

  it("filters by text over the title, kind and id", async () => {
    renderList();
    await listed(6);
    fireEvent.input(screen.getByTestId("filter-input"), { target: { value: "import" } });
    await listed(1);
    expect(rows()[0]?.dataset.id).toBe(MOCK_JOB_IDS.importRunning);
    fireEvent.input(screen.getByTestId("filter-input"), { target: { value: "no such job" } });
    await waitFor(() => expect(screen.getByTestId("grid-empty").textContent).toContain("No jobs match the filter."));
  });

  it("filters by kind and target from the URL, and the chip removes the filter", async () => {
    const view = renderList("/jobs?kind=ipam.move");
    await listed(3);
    const applied = screen.getByTestId("filter-kind");
    expect(applied.textContent).toContain("Kind: ipam.move");
    fireEvent.click(within(applied).getByRole("button", { name: "Remove filter: Kind: ipam.move" }));
    await listed(6);
    await waitFor(() => expect(view.location()).toBe("/jobs"));
  });

  it("filters by target, naming the object by its kind and short id", async () => {
    renderList(`/jobs?target=host/0190d1c2-0000-7000-8000-0000000b0004`);
    await listed(1);
    expect(rows()[0]?.dataset.id).toBe(MOCK_JOB_IDS.applySucceeded);
    expect(screen.getByTestId("filter-target").textContent).toContain("Target: host 0190d1c2");
  });

  it("explains an empty list", async () => {
    renderList("/jobs?kind=import.nothing");
    await waitFor(() => expect(screen.getByTestId("grid-empty")).toBeTruthy());
    expect(screen.getByTestId("grid-empty").textContent).toContain("No jobs match the filter.");
    expect(screen.queryByTestId("jobs-calm")).toBeNull();
  });

  it("names Started by in a column while two people started the listed jobs", async () => {
    renderList();
    await listed(6);
    // The seeds were started by Alex and by Sam.
    expect(header()).toContain("Started by");
    expect(screen.queryByTestId("jobs-starter")).toBeNull();
  });

  it("has no accessibility violations", async () => {
    const view = renderList();
    await listed(6);
    await screen.findByText("Create a DHCP reservation of 198.51.100.41 in the scope of 198.51.100.0/24; keep the old one until cleanup.");
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("a calm list of finished jobs", () => {
  it("says in one line that nothing runs or waits, with the days under it", async () => {
    for (const id of [MOCK_JOB_IDS.moveWaiting, MOCK_JOB_IDS.moveQueued, MOCK_JOB_IDS.importRunning]) {
      jobStore.jobs = jobStore.jobs.filter((rec) => rec.job.id !== id);
    }
    renderList();
    await listed(3);
    expect(screen.getByTestId("jobs-calm").textContent).toBe("Nothing is running and no job waits for you. Finished jobs are below.");
    expect(groupRows().map((g) => g.dataset.id)).toEqual(["\u0001group:today", "\u0001group:yesterday"]);
    expect(within(chip("Active and needs you")).getByTestId("chip-count").textContent).toBe("0");
    await waitFor(() => expect(screen.getByTestId("page-sub").textContent).toBe("0 running · 0 waiting for you · 3 finished"));
    // Nothing runs: no current step.
    expect(header()).not.toContain("Current step");
  });

  it("draws no calm line under a chip of finished jobs or while a job runs", async () => {
    renderList();
    await listed(6);
    expect(screen.queryByTestId("jobs-calm")).toBeNull();
    fireEvent.click(chip("Finished"));
    await listed(3);
    expect(screen.queryByTestId("jobs-calm")).toBeNull();
  });
});

describe("200 finished jobs by one person", () => {
  it("read as day groups with the starter said once, ten rows a day and the rest on request", async () => {
    history({ today: 30, yesterday: 25, earlier: 145 });
    renderList();
    await listed(20);
    // Today and Yesterday open with their first ten, Earlier closed.
    expect(groupRows().map((g) => g.dataset.id)).toEqual(["\u0001group:today", "\u0001group:yesterday", "\u0001group:earlier"]);
    expect(groupOf("today").dataset.open).toBe("true");
    expect(groupOf("yesterday").dataset.open).toBe("true");
    expect(groupOf("earlier").dataset.open).toBe("false");
    expect(within(groupOf("today")).getByTestId("group-count").textContent).toBe("30");
    expect(within(groupOf("today")).getByTestId("group-note").textContent).toBe("done");
    expect(within(groupOf("earlier")).getByTestId("group-count").textContent).toBe("145");
    // No repeated starter: no Started by column, the one starter said once.
    expect(header()).not.toContain("Started by");
    expect(screen.queryAllByText(/\(you\)/)).toHaveLength(0);
    expect(screen.getByTestId("jobs-starter").textContent).toBe("Started by · all you");
    // The title from the catalog says the count; nothing repeats it.
    expect(within(rows()[0] as HTMLElement).getByText("Edit 1 IPAM object")).toBeTruthy();
    expect(within(rows()[0] as HTMLElement).queryByTestId("job-count")).toBeNull();
    // Done rows say how long they took.
    expect(within(rows()[0] as HTMLElement).getByTestId("job-duration").textContent).toBe("2 min 10 s");
    await waitFor(() => expect(screen.getByTestId("page-sub").textContent).toBe("0 running · 0 waiting for you · 200 finished"));
    expect(screen.queryByTestId("jobs-calm")).not.toBeNull();

    // Three group rows, ten jobs and the last row of each open day.
    expect(lineCount()).toBe(3 + 10 + 1 + 10 + 1);
    const tails = screen.getAllByTestId("jobs-tail");
    expect(tails.map((b) => b.textContent)).toEqual(["Show the rest of today (20 more)", "Show the rest of yesterday (15 more)"]);
    fireEvent.click(tails[1] as HTMLElement);
    await waitFor(() => expect(lineCount()).toBe(3 + 10 + 1 + 25));
    expect(screen.getAllByTestId("jobs-tail").map((b) => b.textContent)).toEqual(["Show the rest of today (20 more)"]);
  });

  it("reaches the rest of a day with the keyboard", async () => {
    history({ today: 12, yesterday: 0, earlier: 0 });
    renderList();
    await listed(10);
    const grid = screen.getByRole("grid", { name: "Jobs" });
    fireEvent.focus(grid);
    // The group row, ten jobs, then the last row of the day.
    fireEvent.keyDown(grid, { key: "ArrowDown", repeat: false });
    for (let i = 0; i < 10; i++) fireEvent.keyDown(grid, { key: "ArrowDown" });
    expect(document.getElementById(grid.getAttribute("aria-activedescendant") ?? "")?.closest("tr")?.classList.contains("group-tail")).toBe(true);
    fireEvent.keyDown(grid, { key: "Enter" });
    await listed(12);
    expect(screen.queryByTestId("jobs-tail")).toBeNull();
  });

  it("offers the older jobs past the first page instead of reading them all", async () => {
    history({ today: 0, yesterday: 0, earlier: 210 });
    renderList();
    await waitFor(() => expect(screen.getByTestId("page-sub").textContent).toBe("0 running · 0 waiting for you · 200+ finished"));
    expect(within(groupOf("earlier")).getByTestId("group-count").textContent).toBe("200+");
    expect(lineCount()).toBe(1);
    fireEvent.click(within(groupOf("earlier")).getByRole("button", { name: /^Open Earlier/ }));
    await listed(10);
    fireEvent.click(screen.getByRole("button", { name: "Show the rest of the earlier jobs (190 more)" }));
    await waitFor(() => expect(lineCount()).toBe(1 + 200 + 1));
    // The last line of the day now offers the next page; the grid does not read on by itself,
    // even with the focus at its end.
    const grid = screen.getByRole("grid", { name: "Jobs" });
    fireEvent.focus(grid);
    fireEvent.keyDown(grid, { key: "End", ctrlKey: true });
    const older = await screen.findByRole("button", { name: "Show older jobs" });
    expect(screen.getByTestId("page-sub").textContent).toBe("0 running · 0 waiting for you · 200+ finished");
    fireEvent.keyDown(grid, { key: "Enter" });
    expect(older).toBeTruthy();
    await waitFor(() => expect(screen.getByTestId("page-sub").textContent).toBe("0 running · 0 waiting for you · 210 finished"));
    await waitFor(() => expect(lineCount()).toBe(1 + 210));
    expect(screen.queryByTestId("jobs-tail")).toBeNull();
  });

  it("brings the Started by column back as soon as a second person started a job", async () => {
    history({ today: 5, yesterday: 0, earlier: 0 });
    const now = Date.now();
    recordPastJob({ kind: "dns.edit", title: "dns.job.edit", targets: [] }, { created: now - 60_000, finished: now - 50_000, by: SAM });
    jobStore.jobs.sort((a, b) => Date.parse(b.job.created.at) - Date.parse(a.job.created.at));
    renderList();
    await listed(6);
    expect(header()).toContain("Started by");
    expect(screen.queryByTestId("jobs-starter")).toBeNull();
    expect(screen.getAllByText(/\(you\)/).length).toBe(5);
  });

  it("has no accessibility violations", async () => {
    history({ today: 12, yesterday: 3, earlier: 4 });
    const view = renderList();
    await listed(13);
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("one group of jobs", () => {
  const url = `/jobs?group=${MOCK_MOVE_GROUP}`;

  it("shows only the jobs of the group, with a chip that removes the filter", async () => {
    const view = renderList(url);
    await listed(3);
    expect(rows().map((r) => r.dataset.id)).toEqual(
      expect.arrayContaining([MOCK_JOB_IDS.moveWaiting, MOCK_JOB_IDS.moveQueued, MOCK_JOB_IDS.moveRolledBack]),
    );
    const applied = screen.getByTestId("filter-group");
    expect(applied.textContent).toContain("Group 0190d1c2");
    fireEvent.click(within(applied).getByRole("button", { name: "Remove filter: Group 0190d1c2" }));
    await listed(6);
    expect(view.location()).toBe("/jobs");
    expect(screen.queryByTestId("job-group")).toBeNull();
  });

  it("summarizes the group by state with its limit", async () => {
    renderList(url);
    await listed(3);
    const summary = screen.getByTestId("job-group-summary");
    await waitFor(() => expect(summary.textContent).toContain("At most 2 run at a time."));
    expect(summary.textContent).toContain("3 jobs in this group");
    expect(summary.textContent).toContain("1 Waiting");
    expect(summary.textContent).toContain("1 Queued");
    expect(summary.textContent).toContain("1 Rolled back");
  });

  it("applies the state chips to the grid but not to the group's summary", async () => {
    renderList(url);
    await listed(3);
    fireEvent.click(chip("Failed or rolled back"));
    await listed(1);
    expect(screen.getByTestId("job-group-summary").textContent).toContain("3 jobs in this group");
  });

  it("lists the tasks that wait in one checklist, grouped by step", async () => {
    renderList(url);
    await listed(3);
    const checklist = screen.getByTestId("job-group-checklist");
    const task = await within(checklist).findByTestId("job-group-task");
    expect(task.dataset.job).toBe(MOCK_JOB_IDS.moveWaiting);
    expect(task.dataset.index).toBe("1");
    // The host is shown next to the task, from the target of the job; the message does not name it.
    expect(await within(task).findByText("thermostat-1")).toBeTruthy();
    expect(task.textContent).toContain("Create a DHCP reservation of 198.51.100.41 in the scope of 198.51.100.0/24; keep the old one until cleanup.");
    expect(within(checklist).getByRole("heading", { name: "Reserve in DHCP (1)" })).toBeTruthy();
    expect(within(checklist).getByText("1 task open")).toBeTruthy();
  });

  it("completes a task from the checklist and shows the next one", async () => {
    renderList(url);
    await listed(3);
    const checklist = screen.getByTestId("job-group-checklist");
    const task = await within(checklist).findByTestId("job-group-task");
    fireEvent.click(within(task).getByRole("button", { name: /^Mark done: Create a DHCP reservation of 198\.51\.100\.41/ }));

    // The DHCP step is done; the job goes on to the DNS step, which now waits for a person.
    await waitFor(() => expect(within(checklist).getByRole("heading", { name: "Update DNS (1)" })).toBeTruthy());
    const next = within(checklist).getByTestId("job-group-task");
    expect(next.dataset.job).toBe(MOCK_JOB_IDS.moveWaiting);
    expect(next.dataset.index).toBe("2");
    expect(next.textContent).toContain(
      "Point thermostat-1.example.test to 198.51.100.41 (address and reverse records); remove the old records at cleanup.",
    );
    expect(within(checklist).queryByRole("heading", { name: /Reserve in DHCP/ })).toBeNull();
    expect(findJob(MOCK_JOB_IDS.moveWaiting)?.job.steps[1]?.state.state).toBe("done");
    // A task marked done from the checklist carries no note.
    const completed = findJob(MOCK_JOB_IDS.moveWaiting)?.transitions.find((row) => row.step === 1 && row.step_state?.state === "done");
    expect(completed?.note ?? null).toBeNull();
    expect(await screen.findByText("Step 2 marked done")).toBeTruthy();
  });

  it("lists the jobs that were not moved with their reason and the tag", async () => {
    renderList(url);
    await listed(3);
    const section = screen.getByTestId("job-group-not-moved");
    expect(within(section).getByRole("heading", { name: "Not moved" })).toBeTruthy();
    const items = within(section).getAllByTestId("job-group-not-moved-item");
    expect(items.map((item) => item.dataset.job)).toEqual([MOCK_JOB_IDS.moveRolledBack]);
    const item = items[0]!;
    expect(item.dataset.state).toBe("rolled_back");
    expect(await within(item).findByText("cam-door")).toBeTruthy();
    expect(within(item).getByTestId("job-group-move-failed").textContent).toBe("move-failed");
    expect(within(item).getByTestId("job-group-not-moved-reason").textContent).not.toBe("");
    expect(within(item).getByTestId("job-group-not-moved-link").getAttribute("href")).toBe(`/jobs/${MOCK_JOB_IDS.moveRolledBack}`);
  });

  it("has no accessibility violations", async () => {
    const view = renderList(url);
    await listed(3);
    await screen.findByTestId("job-group-task");
    expect(await axeViolations(view.container)).toEqual([]);
  });
});
