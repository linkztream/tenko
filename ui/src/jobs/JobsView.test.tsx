import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { findJob, MOCK_JOB_IDS, MOCK_MOVE_GROUP } from "../api/mock/job-store";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { resetJobDetails } from "./data";
import JobDetail from "./JobDetail";
import JobsView from "./JobsView";

beforeEach(async () => {
  resetJobDetails();
  await signInAlex();
});
afterEach(() => setSessionForTest(null));

function renderList(url = "/jobs") {
  return renderRoute(JobsView, { url, path: "/jobs", routes: { "/jobs/:id": JobDetail } });
}

function rows(): HTMLElement[] {
  return screen.queryAllByTestId("row");
}

function rowOf(id: string): HTMLElement {
  const row = rows().find((r) => r.dataset.id === id);
  if (!row) throw new Error(`no row for job ${id}`);
  return row;
}

async function listed(count: number) {
  await waitFor(() => expect(rows()).toHaveLength(count));
}

describe("the jobs list", () => {
  it("lists the seed jobs, newest first, with the state in words", async () => {
    renderList();
    await listed(6);
    // Newest first: the import (8 minutes ago) comes before the job that waits (62 minutes ago).
    expect(rows().map((r) => r.dataset.id)).toEqual([
      MOCK_JOB_IDS.importRunning,
      MOCK_JOB_IDS.applySucceeded,
      MOCK_JOB_IDS.moveQueued,
      MOCK_JOB_IDS.moveWaiting,
      MOCK_JOB_IDS.applyCancelled,
      MOCK_JOB_IDS.moveRolledBack,
    ]);
    expect(within(rowOf(MOCK_JOB_IDS.moveWaiting)).getByText("Waiting")).toBeTruthy();
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
    expect(within(move).getByText("2 objects")).toBeTruthy();
    expect(within(rowOf(MOCK_JOB_IDS.applySucceeded)).getByText("1 object")).toBeTruthy();
  });

  it("shows progress, the current step and its state", async () => {
    renderList();
    await listed(6);
    const waiting = rowOf(MOCK_JOB_IDS.moveWaiting);
    expect(within(waiting).getByText("1 of 6 steps")).toBeTruthy();
    // The step's own words arrive with the job's detail.
    expect(await within(waiting).findByText("Create a DHCP reservation of 198.51.100.41 in the scope of 198.51.100.0/24; keep the old one until cleanup.")).toBeTruthy();
    expect(within(waiting).getByText(/Waiting for you/)).toBeTruthy();
    expect(within(rowOf(MOCK_JOB_IDS.importRunning)).getByText("2 of 3 steps")).toBeTruthy();
    expect(await within(rowOf(MOCK_JOB_IDS.importRunning)).findByText("Apply the planned changes")).toBeTruthy();
    // A job that is over has no current step: a rolled back one points at the step that failed.
    const rolledBack = rowOf(MOCK_JOB_IDS.moveRolledBack);
    expect(await within(rolledBack).findByText("Move the device to the network 198.51.100.0/24.")).toBeTruthy();
    expect(within(rolledBack).getByText(/Failed/)).toBeTruthy();
    for (const id of [MOCK_JOB_IDS.applySucceeded, MOCK_JOB_IDS.applyCancelled]) {
      expect(within(rowOf(id)).queryByText(/Apply the change/)).toBeNull();
      expect(within(rowOf(id)).getAllByText("–").length).toBeGreaterThan(0);
    }
  });

  it("marks the job that waits for a person with an icon and words", async () => {
    renderList();
    await listed(6);
    const marked = screen.getAllByTestId("job-needs");
    expect(marked).toHaveLength(1);
    expect(marked[0]?.textContent).toContain("Needs you");
    expect(marked[0]?.querySelector("svg")).not.toBeNull();
    expect(rowOf(MOCK_JOB_IDS.moveWaiting).contains(marked[0] as Node)).toBe(true);
    expect(rowOf(MOCK_JOB_IDS.moveWaiting).classList.contains("needs")).toBe(true);
  });

  it("opens a job from its title and from a click in the row", async () => {
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
  });

  it("opens the focused job with Enter", async () => {
    const view = renderList();
    await listed(6);
    const grid = screen.getByRole("grid", { name: "Jobs" });
    fireEvent.focus(grid);
    // The focus starts on the first job; one key reaches the second.
    fireEvent.keyDown(grid, { key: "ArrowDown" });
    fireEvent.keyDown(grid, { key: "Enter" });
    await waitFor(() => expect(view.location()).toBe(`/jobs/${MOCK_JOB_IDS.applySucceeded}`));
  });

  it("filters by the state chips", async () => {
    renderList();
    await listed(6);
    const chip = (name: string) => screen.getByRole("button", { name });
    expect(chip("All").getAttribute("aria-pressed")).toBe("true");

    fireEvent.click(chip("Needs you"));
    await listed(1);
    expect(rows()[0]?.dataset.id).toBe(MOCK_JOB_IDS.moveWaiting);
    expect(chip("Needs you").getAttribute("aria-pressed")).toBe("true");

    fireEvent.click(chip("Active"));
    await listed(3);
    expect(rows().map((r) => r.dataset.id)).toEqual(
      expect.arrayContaining([MOCK_JOB_IDS.moveWaiting, MOCK_JOB_IDS.moveQueued, MOCK_JOB_IDS.importRunning]),
    );

    fireEvent.click(chip("Failed or rolled back"));
    await listed(1);
    expect(rows()[0]?.dataset.id).toBe(MOCK_JOB_IDS.moveRolledBack);

    fireEvent.click(chip("Finished"));
    await listed(3);
    expect(rows().map((r) => r.dataset.id)).toEqual(
      expect.arrayContaining([MOCK_JOB_IDS.applySucceeded, MOCK_JOB_IDS.applyCancelled, MOCK_JOB_IDS.moveRolledBack]),
    );

    fireEvent.click(chip("All"));
    await listed(6);
  });

  it("takes the chip from the URL", async () => {
    renderList("/jobs?view=needs");
    await listed(1);
    expect(screen.getByRole("button", { name: "Needs you" }).getAttribute("aria-pressed")).toBe("true");
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
    const chip = screen.getByTestId("filter-kind");
    expect(chip.textContent).toContain("Kind: ipam.move");
    fireEvent.click(within(chip).getByRole("button", { name: "Remove filter: Kind: ipam.move" }));
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
  });

  it("has no accessibility violations", async () => {
    const view = renderList();
    await listed(6);
    await screen.findByText("Create a DHCP reservation of 198.51.100.41 in the scope of 198.51.100.0/24; keep the old one until cleanup.");
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
    const chip = screen.getByTestId("filter-group");
    expect(chip.textContent).toContain("Group 0190d1c2");
    fireEvent.click(within(chip).getByRole("button", { name: "Remove filter: Group 0190d1c2" }));
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
    fireEvent.click(screen.getByRole("button", { name: "Needs you" }));
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
