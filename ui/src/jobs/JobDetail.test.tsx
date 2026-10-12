import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createJob, findJob, MOCK_HOST_IDS, MOCK_JOB_IDS, MOCK_MOVE_GROUP, moveJobInput } from "../api/mock/job-store";
import { encodeMoveL2Output, type MoveL2Output } from "../api/moves";
import type { CodedError } from "../api/types";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { alex, signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { cancelJob, resetJobDetails } from "./data";
import JobDetail from "./JobDetail";
import JobsView from "./JobsView";
import { MAX_NOTE_BYTES } from "./model";

beforeEach(async () => {
  resetJobDetails();
  await signInAlex();
});
afterEach(() => setSessionForTest(null));

async function openJob(id: string) {
  const view = renderRoute(JobDetail, { url: `/jobs/${id}`, path: "/jobs/:id", routes: { "/jobs": JobsView } });
  await screen.findByTestId("job-steps");
  return view;
}

function steps(): HTMLElement[] {
  return screen.getAllByTestId("job-step");
}

function step(index: number): HTMLElement {
  const found = steps().find((s) => s.dataset.index === String(index));
  if (!found) throw new Error(`no step ${index}`);
  return found;
}

function note(index: number): HTMLTextAreaElement {
  return within(step(index)).getByTestId("job-step-note") as HTMLTextAreaElement;
}

function type(el: HTMLTextAreaElement, value: string) {
  fireEvent.input(el, { target: { value } });
}

describe("a job that waits for a person", () => {
  const id = MOCK_JOB_IDS.moveWaiting;

  it("shows the head: title, state in glyph and word, kind and the facts", async () => {
    await openJob(id);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Move");
    const head = screen.getByRole("heading", { level: 1 });
    expect(within(head).getByText("Waiting")).toBeTruthy();
    expect(within(head).getByText("ipam.move")).toBeTruthy();
    const facts = screen.getByTestId("job-facts");
    expect(within(facts).getByText(id)).toBeTruthy();
    expect(facts.textContent).toContain("(you)");
    expect(within(facts).getByText("12 hr")).toBeTruthy();
    expect(within(facts).getByText("Not yet")).toBeTruthy();
  });

  it("links to the group, with its limit", async () => {
    await openJob(id);
    const fact = screen.getByTestId("job-group-fact");
    const link = within(fact).getByRole("link", { name: "Show the jobs of this group" });
    expect(link.getAttribute("href")).toBe(`/jobs?group=${encodeURIComponent(MOCK_MOVE_GROUP)}`);
    expect(fact.textContent).toContain("At most 2 run at a time");
  });

  it("names the target when the host cannot be read, by kind and short id", async () => {
    await openJob(id);
    const targets = screen.getByTestId("job-targets");
    expect(targets.textContent).toMatch(/host 0190d1c2|thermostat/);
  });

  it("lists the six steps in order with their state in words", async () => {
    await openJob(id);
    expect(steps().map((s) => s.dataset.state)).toEqual([
      "done",
      "waiting_for_manual",
      "pending",
      "pending",
      "pending",
      "pending",
    ]);
    expect(within(step(0)).getByText("Add 198.51.100.41 to IPAM as planned; keep 192.0.2.41 until cleanup.")).toBeTruthy();
    expect(within(step(0)).getByText("Done")).toBeTruthy();
    // A step that waits is named in a few words; its task, below, says the rest.
    expect(within(step(1)).getByText("Reserve in DHCP")).toBeTruthy();
    expect(within(step(1)).getByTestId("job-step-task").textContent).toContain(
      "Create a DHCP reservation of 198.51.100.41 in the scope of 198.51.100.0/24; keep the old one until cleanup.",
    );
    expect(within(step(1)).getByText("Waiting for you")).toBeTruthy();
    expect(within(step(2)).getByText("Point thermostat-1.example.test to 198.51.100.41 (address and reverse records); remove the old records at cleanup.")).toBeTruthy();
    expect(step(2).dataset.state).toBe("pending");
    expect(within(step(5)).getByText("Remove 192.0.2.41 and make 198.51.100.41 active.")).toBeTruthy();
    expect(within(step(5)).getByText("Not started")).toBeTruthy();
    expect(within(step(0)).getByText(/1 attempt/)).toBeTruthy();
  });

  it("shows the DHCP task with its arguments and a deadline that counts down", async () => {
    await openJob(id);
    const task = within(step(1)).getByTestId("job-step-task");
    expect(task.textContent).toContain("Create a DHCP reservation of 198.51.100.41 in the scope of 198.51.100.0/24; keep the old one until cleanup.");
    const deadline = within(task).getByTestId("job-deadline");
    // The job started an hour ago and has twelve hours; the countdown shows hours and minutes.
    expect(deadline.textContent).toMatch(/^Deadline in (10 h 59 min|11 h)\. After that the job rolls back automatically\.$/);
    const time = deadline.querySelector("time");
    expect(time?.getAttribute("datetime")).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(time?.getAttribute("title")).toBeTruthy();
    // No live region: a screen reader is not told every second.
    expect(deadline.closest("[aria-live], [role='status'], [role='alert']")).toBeNull();
  });

  it("says that a deadline has passed and that the job rolls back by itself", async () => {
    await openJob(id);
    const job = findJob(id);
    const state = job?.job.steps[1]?.state;
    if (state?.state !== "waiting_for_manual") throw new Error("the seed job should wait for a person");
    state.data.deadline = new Date(Date.now() - 60_000).toISOString();
    resetJobDetails();
    // A new view of the same job reads the changed deadline.
    screen.getByTestId("page-job").remove();
    await openJob(id);
    expect(within(step(1)).getByTestId("job-deadline-passed").textContent).toBe(
      "The deadline has passed. The job rolls back automatically.",
    );
  });

  it("completes the task with a note: the job goes on and the note is in the log", async () => {
    await openJob(id);
    const text = "Reserved 198.51.100.41 in the DHCP server.";
    type(note(1), text);
    expect(within(step(1)).getByTestId("job-step-note-count").textContent).toBe(`${text.length} of 4,096 bytes`);
    fireEvent.click(within(step(1)).getByTestId("job-step-complete"));

    // Step 1 is done and the job waits at the next manual step: the DNS change.
    await waitFor(() => expect(step(1).dataset.state).toBe("done"));
    await waitFor(() => expect(step(2).dataset.state).toBe("waiting_for_manual"));
    expect(within(step(2)).getByTestId("job-step-task").textContent).toContain("Point thermostat-1.example.test to 198.51.100.41 (address and reverse records); remove the old records at cleanup.");
    expect(note(2).value).toBe("");
    expect(await screen.findByText("Step 2 marked done")).toBeTruthy();

    const rows = screen.getAllByTestId("job-log-row");
    const withNote = rows.find((row) => within(row).queryByText(text));
    expect(withNote).toBeTruthy();
    expect(within(withNote as HTMLElement).getByText("Done")).toBeTruthy();
    // The note was sent as typed, and the server kept it in the transition log.
    const logged = findJob(id)?.transitions.find((row) => row.note === text);
    expect(logged?.step).toBe(1);
  });

  it("sends no body when the note is empty", async () => {
    await openJob(id);
    type(note(1), "   ");
    fireEvent.click(within(step(1)).getByTestId("job-step-complete"));
    await waitFor(() => expect(step(1).dataset.state).toBe("done"));
    const logged = findJob(id)?.transitions.find((row) => row.step === 1 && row.step_state?.state === "done");
    expect(logged?.note ?? null).toBeNull();
  });

  it("refuses a note over 4,096 bytes before sending, counting bytes and not characters", async () => {
    await openJob(id);
    const before = findJob(id)?.transitions.length;
    // 2,049 characters of two bytes each: 4,098 bytes, well under 4,096 characters.
    type(note(1), "é".repeat(2049));
    const count = within(step(1)).getByTestId("job-step-note-count");
    expect(count.textContent).toBe("4,098 of 4,096 bytes");
    expect(count.classList.contains("bad")).toBe(true);
    expect(note(1).getAttribute("aria-invalid")).toBe("true");
    const over = within(step(1)).getByTestId("job-step-note-over");
    expect(over.textContent).toContain("The note is 2 bytes too long.");
    expect(over.getAttribute("role")).toBe("alert");

    fireEvent.click(within(step(1)).getByTestId("job-step-complete"));
    // Nothing was sent: the step still waits, the log has no new row, and the focus goes to the note.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(step(1).dataset.state).toBe("waiting_for_manual");
    expect(findJob(id)?.transitions.length).toBe(before);
    expect(document.activeElement).toBe(note(1));

    // Shortened to exactly the limit, the note goes through.
    type(note(1), "é".repeat(MAX_NOTE_BYTES / 2));
    expect(within(step(1)).queryByTestId("job-step-note-over")).toBeNull();
    fireEvent.click(within(step(1)).getByTestId("job-step-complete"));
    await waitFor(() => expect(step(1).dataset.state).toBe("done"));
  });

  it("keeps a note that is being typed when the job changes under it", async () => {
    await openJob(id);
    type(note(1), "half a sentence");
    const element = note(1);
    // The same job gets a new revision from somewhere else; the page reads it again.
    const live = findJob(id);
    if (live) live.job.revision = (live.job.revision ?? 0) + 1;
    expect(note(1)).toBe(element);
    expect(note(1).value).toBe("half a sentence");
  });

  it("has a Cancel button that asks first and a Keep button that changes nothing", async () => {
    await openJob(id);
    fireEvent.click(screen.getByTestId("job-cancel"));
    const dialog = await screen.findByRole("dialog", { name: "Cancel this job?" });
    expect(dialog.textContent).toContain("The steps that already ran are undone.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Keep job" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(findJob(id)?.job.state).toBe("waiting");
  });

  it("has no accessibility violations", async () => {
    const view = await openJob(id);
    expect(await axeViolations(view.container)).toEqual([]);
    fireEvent.click(screen.getByTestId("job-cancel"));
    const dialog = await screen.findByRole("dialog", { name: "Cancel this job?" });
    expect(await axeViolations(dialog)).toEqual([]);
  });
});

describe("a job that has not started", () => {
  const id = MOCK_JOB_IDS.moveQueued;

  it("shows the queued state and cancels after the confirm dialog", async () => {
    await openJob(id);
    const head = screen.getByRole("heading", { level: 1 });
    expect(within(head).getByText("Queued")).toBeTruthy();
    expect(steps().every((s) => s.dataset.state === "pending")).toBe(true);

    fireEvent.click(screen.getByTestId("job-cancel"));
    const dialog = await screen.findByRole("dialog", { name: "Cancel this job?" });
    expect(dialog.textContent).toContain("The job has not started. It is cancelled and never runs.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel job" }));

    expect(await screen.findByText("Job cancelled")).toBeTruthy();
    await waitFor(() => expect(within(screen.getByRole("heading", { level: 1 })).getByText("Cancelled")).toBeTruthy());
    expect(screen.queryByTestId("job-cancel")).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(findJob(id)?.job.state).toBe("cancelled");
    // The reason is in words, not as a code.
    expect(screen.getByTestId("job-error").textContent).toBe("The job was cancelled.");
    expect(within(screen.getByTestId("job-log")).getByText("Cancelled")).toBeTruthy();
  });

  it("says why when the job changed in the meantime", async () => {
    await openJob(id);
    fireEvent.click(screen.getByTestId("job-cancel"));
    const dialog = await screen.findByRole("dialog", { name: "Cancel this job?" });
    // Somebody else cancels it first.
    await cancelJob(id);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel job" }));
    const problem = await within(dialog).findByTestId("job-cancel-error");
    expect(problem.textContent).toContain("The job is in another state now");
    expect(screen.getByRole("dialog")).toBeTruthy();
  });
});

describe("a job that was rolled back", () => {
  const id = MOCK_JOB_IDS.moveRolledBack;

  it("shows the compensated steps, the failed step and the reason in words", async () => {
    await openJob(id);
    expect(within(screen.getByRole("heading", { level: 1 })).getByText("Rolled back")).toBeTruthy();
    expect(steps().map((s) => s.dataset.state)).toEqual([
      "compensated",
      "compensated",
      "compensated",
      "failed",
      "pending",
      "pending",
    ]);
    expect(within(step(0)).getByText("Undone")).toBeTruthy();
    const failure = within(step(3)).getByTestId("job-step-failure");
    expect(failure.textContent).toContain("A step failed.");
    expect(failure.textContent).toContain("No ARP or lease from 00:00:5e:00:53:2b within 5:00.");
    // The step that failed says what it was about to do.
    expect(within(step(3)).getByText("Move the device to the network 198.51.100.0/24.")).toBeTruthy();

    const error = screen.getByTestId("job-error");
    expect(error.textContent).toContain("A step failed.");
    expect(error.textContent).toContain("Detail from the server: No ARP or lease from 00:00:5e:00:53:2b within 5:00.");
    expect(screen.queryByTestId("job-cancel")).toBeNull();
    expect(screen.queryByTestId("job-step-complete")).toBeNull();
  });

  it("keeps the notes of the manual tasks in the log; the rollback needed no person", async () => {
    await openJob(id);
    const log = screen.getByTestId("job-log");
    expect(within(log).getByText("Reserved 198.51.100.43 for cam-door in the DHCP server.")).toBeTruthy();
    expect(within(log).getByText("Updated the A record of cam-door.example.test.")).toBeTruthy();
    // A move has no undo tasks: the rollback undid the three steps by itself.
    expect(within(log).getAllByText("Undone")).toHaveLength(3);
    expect(within(log).getAllByText("Tenko (jobs)").length).toBeGreaterThan(3);
    expect(within(log).getByText("Rollback finished")).toBeTruthy();
    expect(within(log).getAllByText("Rolling back to Rolled back").length).toBeGreaterThan(0);
  });

  it("has no accessibility violations", async () => {
    const view = await openJob(id);
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("a job that rolls back and needs a person to undo a step", () => {
  // The manual steps of a move have no undo task, but the engine can ask for one: this job has it.
  function undoJob(): string {
    const task = {
      instruction: "jobs.task.dhcp_reserve",
      undo: "jobs.task.dhcp_release",
      args: { host: "thermostat-1", mac: "00:00:5e:00:53:29", ip: "198.51.100.41", prefix: "198.51.100.0/24" },
    };
    return createJob({
      kind: "ipam.move",
      title: "ipam.move.title",
      targets: [{ kind: "host", id: MOCK_HOST_IDS.thermostat1 }],
      timeoutSecs: 3600,
      steps: [
        { kind: "ipam.move.intent", automatic: true },
        { kind: "ipam.move.dhcp", automatic: false, manual: task },
      ],
    });
  }

  it("shows the undo task like any task, and finishes the cancel when it is done", async () => {
    // Cancelling a job that waits makes the engine undo the DHCP step by hand.
    const id = undoJob();
    await cancelJob(id);
    await openJob(id);
    const head = screen.getByRole("heading", { level: 1 });
    expect(within(head).getByText("Rolling back")).toBeTruthy();
    expect(screen.queryByTestId("job-cancel")).toBeNull();

    const undo = within(step(1)).getByTestId("job-step-task");
    expect(undo.textContent).toContain("Undo");
    expect(undo.textContent).toContain("Remove the DHCP reservation of 198.51.100.41 for thermostat-1.");
    expect(within(undo).queryByTestId("job-deadline")).toBeNull();

    type(note(1), "Removed the reservation.");
    fireEvent.click(within(step(1)).getByTestId("job-step-complete"));
    await waitFor(() => expect(within(screen.getByRole("heading", { level: 1 })).getByText("Rolled back (cancelled)")).toBeTruthy());
    expect(step(1).dataset.state).toBe("compensated");
    expect(screen.getByText("Removed the reservation.")).toBeTruthy();
  });

  it("cancels a waiting move at once: there is no task to undo", async () => {
    await openJob(MOCK_JOB_IDS.moveWaiting);
    fireEvent.click(screen.getByTestId("job-cancel"));
    const dialog = await screen.findByRole("dialog", { name: "Cancel this job?" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel job" }));
    // Nothing to undo by hand: the job is cancelled for good in one go.
    expect(await screen.findByText("Job cancelled")).toBeTruthy();
    await waitFor(() => expect(within(screen.getByRole("heading", { level: 1 })).getByText("Rolled back (cancelled)")).toBeTruthy());
    expect(steps().map((s) => s.dataset.state).slice(0, 3)).toEqual(["compensated", "compensated", "pending"]);
    expect(screen.queryByTestId("job-step-complete")).toBeNull();
  });
});

describe("an account that may not change jobs", () => {
  it("shows the buttons disabled, with the reason", async () => {
    await signInAlex({
      prepare: (user) => {
        user.roles = ["viewer"];
      },
    });
    expect(alex().roles).toEqual(["viewer"]);
    await openJob(MOCK_JOB_IDS.moveWaiting);
    const cancel = screen.getByTestId("job-cancel") as HTMLButtonElement;
    expect(cancel.disabled).toBe(true);
    expect(cancel.title).toContain("You can read jobs but not change them.");
    expect((within(step(1)).getByTestId("job-step-complete") as HTMLButtonElement).disabled).toBe(true);
    expect(note(1).disabled).toBe(true);
    expect(within(step(1)).getByText(/You can read jobs but not change them/)).toBeTruthy();
  });
});

describe("a job that is not there", () => {
  it("says so in words and offers a way back", async () => {
    renderRoute(JobDetail, { url: "/jobs/0190d1c2-0000-7000-8000-0000000cffff", path: "/jobs/:id" });
    const problem = await screen.findByTestId("job-load-error");
    expect(problem.textContent).toBe("This job does not exist. It may have been removed.");
    expect(screen.getByRole("link", { name: "Jobs" }).getAttribute("href")).toBe("/jobs");
  });
});

describe("a move whose L2 step goes through the network controller", () => {
  const CONNECTOR = "0190d1c2-0000-7000-8000-0000000d0001";
  const SWITCH = "00:00:5e:00:53:03";
  const PATH = `devices/${SWITCH}/ports/7/profile`;
  const HEAD = "Give port 7 of sw-desk the port profile IoT through unifi-lab.";
  const WARNING = "the device on port 7 loses its link for a moment while the switch applies the profile";

  afterEach(async () => {
    await setLocale("en");
  });

  function output(extra: Partial<MoveL2Output> = {}): MoveL2Output {
    return {
      connector: CONNECTOR,
      change: { type: "set_port_profile", data: { device: SWITCH, port: 7, profile: "prof-iot" } },
      diff: [{ path: PATH, before: "LAN", after: "IoT" }],
      warnings: [WARNING],
      read_at: new Date(Date.now() - 6 * 60_000).toISOString(),
      unchanged: false,
      unknown_write: false,
      receipt: {
        connector: CONNECTOR,
        dry_run: false,
        applied_at: new Date(Date.now() - 5 * 60_000).toISOString(),
        verified: true,
        undo_steps: 1,
        token: "00",
      },
      ...extra,
    };
  }

  const l2Args = {
    connector: "unifi-lab",
    device: "sw-desk",
    port: "7",
    profile: "IoT",
    network: "IoT",
    mac: "00:00:5e:00:53:2b",
    path: PATH,
    before: "LAN",
    after: "IoT",
  };

  /**
   * The move of cam-door. A dynamic host with no DNS name has no manual task before the L2 step:
   * the steps are the intent (0), the controller (1), the observation (2) and the cleanup (3).
   * A reserved host adds the DHCP step in front of the controller, which then has not run.
   */
  function controllerInput(options: { reserved?: boolean; undoFails?: boolean; out?: MoveL2Output | null } = {}) {
    const out = options.out === undefined ? output() : options.out;
    return moveJobInput({
      host: { kind: "host", id: MOCK_HOST_IDS.camDoor },
      name: "cam-door",
      mac: "00:00:5e:00:53:2b",
      ip: "198.51.100.43",
      oldIp: "192.0.2.43",
      mode: options.reserved ? "reserved" : "dynamic",
      l2: {
        action: "port_profile",
        args: l2Args,
        changes: [{ kind: "connector", id: CONNECTOR }],
        ...(out ? { output: encodeMoveL2Output(out) } : {}),
        ...(options.undoFails ? { undoFails: true } : {}),
      },
    });
  }

  function controllerJob(options: Parameters<typeof controllerInput>[0] = {}): string {
    return createJob(controllerInput(options));
  }

  const UNDO = "Undo step 1 (Move on the network controller) by hand, then mark this done.";

  it("shows the planned change of a step that has not run", async () => {
    await openJob(controllerJob({ reserved: true }));
    expect(steps().map((s) => s.dataset.state)).toEqual(["done", "waiting_for_manual", "pending", "pending", "pending"]);
    const controller = within(step(2));
    expect(controller.getByText(HEAD)).toBeTruthy();
    expect(controller.getByText("Not started")).toBeTruthy();
    const planned = controller.getByTestId("job-l2-planned");
    expect(within(planned).getByText("Planned change")).toBeTruthy();
    const row = within(planned).getByTestId("job-l2-diff-line");
    expect(within(row).getByRole("rowheader").textContent).toBe(PATH);
    expect(within(row).getAllByRole("cell").map((c) => c.textContent)).toEqual(["LAN", "IoT"]);
    expect(controller.queryByTestId("job-l2-diff")).toBeNull();
    expect(controller.queryByTestId("job-l2-receipt")).toBeNull();
    // The other steps have no such block.
    expect(within(step(0)).queryByTestId("job-l2")).toBeNull();
    expect(within(step(1)).queryByTestId("job-l2")).toBeNull();
  });

  it("shows the diff, the receipt and the warnings of a step that is done", async () => {
    await openJob(controllerJob());
    expect(steps().map((s) => s.dataset.state)).toEqual(["done", "done", "waiting_for_manual", "pending"]);
    const controller = within(step(1));
    expect(controller.getByText(HEAD)).toBeTruthy();
    expect(controller.getByText("Done")).toBeTruthy();
    expect(controller.queryByTestId("job-l2-planned")).toBeNull();

    const diff = controller.getByTestId("job-l2-diff");
    expect(within(diff).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Setting", "Before", "After"]);
    const row = within(diff).getByTestId("job-l2-diff-line");
    expect(within(row).getByRole("rowheader").textContent).toBe(PATH);
    expect(within(row).getAllByRole("cell").map((c) => c.textContent)).toEqual(["LAN", "IoT"]);

    const receipt = controller.getByTestId("job-l2-receipt");
    expect(receipt.textContent).toBe("Written 5 minutes ago, read back and verified; 1 undo step kept for the rollback.");
    expect(controller.queryByTestId("job-l2-no-undo")).toBeNull();
    expect(controller.queryByTestId("job-l2-reverted")).toBeNull();
    const warnings = controller.getByTestId("job-l2-warnings");
    expect(within(warnings).getByText("The network controller warned")).toBeTruthy();
    expect(within(warnings).getByText(WARNING)).toBeTruthy();
  });

  it("shows no diff for output that cannot be read", async () => {
    const input = controllerInput();
    const controller = input.steps.find((s) => s.kind === "ipam.move.controller");
    if (!controller) throw new Error("the job has a controller step");
    controller.output = "not hex";
    await openJob(createJob(input));
    expect(step(1).dataset.state).toBe("done");
    expect(within(step(1)).getByText(HEAD)).toBeTruthy();
    expect(within(step(1)).queryByTestId("job-l2")).toBeNull();
  });

  it("says that a cancelled job put the previous setting back", async () => {
    const id = controllerJob();
    await cancelJob(id);
    await openJob(id);
    expect(within(screen.getByRole("heading", { level: 1 })).getByText("Rolled back (cancelled)")).toBeTruthy();
    // Still the state cancelled, shown as rolled back by the cancellation (WP2.8).
    const chip = within(screen.getByRole("heading", { level: 1 })).getByTestId("job-state");
    expect(chip.dataset.state).toBe("cancelled");
    expect(chip.dataset.rollback).toBe("cancel");
    expect(steps().map((s) => s.dataset.state)).toEqual(["compensated", "compensated", "compensated", "pending"]);
    const controller = within(step(1));
    expect(controller.getByText("Undone")).toBeTruthy();
    expect(controller.getByTestId("job-l2-reverted").textContent).toBe("Rolled back: the network controller has the previous setting again.");
    // What the step had done stays on the page.
    expect(controller.getByTestId("job-l2-diff")).toBeTruthy();
    expect(controller.getByTestId("job-l2-receipt")).toBeTruthy();
    expect(controller.queryByTestId("job-l2-undo-hint")).toBeNull();
    expect(screen.queryByTestId("job-step-complete")).toBeNull();
  });

  it("asks a person to put the setting back when the revert fails, and ends the cancel when it is done", async () => {
    const id = controllerJob({ undoFails: true });
    await cancelJob(id);
    await openJob(id);
    expect(within(screen.getByRole("heading", { level: 1 })).getByText("Rolling back")).toBeTruthy();
    expect(steps().map((s) => s.dataset.state)).toEqual(["compensated", "waiting_for_manual", "compensated", "pending"]);

    const controller = within(step(1));
    const hint = controller.getByTestId("job-l2-undo-hint");
    expect(hint.textContent).toBe(`Put the previous setting back on the network controller: ${PATH} to LAN.`);
    // What was changed is above the hint, and the task with its form below it.
    expect(controller.getByTestId("job-l2-diff")).toBeTruthy();
    const task = controller.getByTestId("job-step-task");
    expect(task.textContent).toContain("Undo");
    expect(task.textContent).toContain(UNDO);
    expect(hint.compareDocumentPosition(task) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(controller.queryByTestId("job-l2-reverted")).toBeNull();

    type(note(1), "Set port 7 of sw-desk back to the profile LAN.");
    fireEvent.click(within(step(1)).getByTestId("job-step-complete"));
    await waitFor(() => expect(within(screen.getByRole("heading", { level: 1 })).getByText("Rolled back (cancelled)")).toBeTruthy());
    expect(step(1).dataset.state).toBe("compensated");
    expect(within(step(1)).getByTestId("job-l2-reverted")).toBeTruthy();
    expect(within(step(1)).queryByTestId("job-l2-undo-hint")).toBeNull();
    expect(screen.getByText("Set port 7 of sw-desk back to the profile LAN.")).toBeTruthy();
  });

  it("warns about a write without an undo step: a rollback asks a person", async () => {
    const out = output();
    const id = controllerJob({ out: { ...out, receipt: out.receipt && { ...out.receipt, undo_steps: 0 } }, undoFails: true });
    await openJob(id);
    const controller = within(step(1));
    expect(controller.getByTestId("job-l2-receipt").textContent).toContain("no undo step kept for the rollback.");
    expect(controller.getByTestId("job-l2-no-undo").textContent).toContain("a rollback asks a person to put the port back");
    expect(controller.queryByTestId("job-l2-undo-hint")).toBeNull();
    await cancelJob(id);
    resetJobDetails();
    screen.getByTestId("page-job").remove();
    await openJob(id);
    expect(step(1).dataset.state).toBe("waiting_for_manual");
    expect(within(step(1)).getByTestId("job-l2-undo-hint")).toBeTruthy();
  });

  it("shows the exact task of an L2 step that a person does", async () => {
    const id = createJob(
      moveJobInput({
        host: { kind: "host", id: MOCK_HOST_IDS.camDoor },
        name: "cam-door",
        mac: "00:00:5e:00:53:2b",
        ip: "198.51.100.43",
        oldIp: "192.0.2.43",
        mode: "dynamic",
        l2: { action: "manual", key: "ipam.move.task.l2_port", args: { connector: "unifi-lab", device: "sw-desk", port: "7", profile: "IoT" } },
      }),
    );
    await openJob(id);
    expect(steps().map((s) => s.dataset.state)).toEqual(["done", "waiting_for_manual", "pending", "pending"]);
    const manual = within(step(1));
    expect(manual.getByText("Move to the new network")).toBeTruthy();
    expect(manual.getByTestId("job-step-task").textContent).toContain(
      "On unifi-lab, give port 7 of sw-desk the port profile IoT (VLAN 30 untagged); writes through this connector are off.",
    );
    expect(manual.queryByTestId("job-l2")).toBeNull();
    expect(manual.getByTestId("job-step-complete")).toBeTruthy();
  });

  it("explains in words why the step failed and nothing was written", async () => {
    const failures: [CodedError, string][] = [
      [
        {
          code: "ipam.move.l2_changed",
          status: 409,
          title: "The network changed",
          detail: "the network changed since the move was submitted: port 7 of sw-desk has another port profile; nothing was written, preview the move again",
          params: { mac: "00:00:5e:00:53:2b", what: "port 7 of sw-desk has another port profile" },
        },
        "The device or its switch port changed on the network controller after the move was started, so nothing was written. Preview the move again.",
      ],
      [
        { code: "connect.guardrail.uplink", status: 422, title: "Guardrail", detail: "port 7 of sw-desk is an uplink" },
        "This switch port is an uplink; Tenko never changes it.",
      ],
    ];
    for (const [error, text] of failures) {
      const input = controllerInput({ out: null });
      const controller = input.steps.find((s) => s.kind === "ipam.move.controller");
      if (!controller) throw new Error("the job has a controller step");
      controller.failsWith = error;
      const view = await openJob(createJob(input));
      expect(step(1).dataset.state).toBe("failed");
      const failure = within(step(1)).getByTestId("job-step-failure");
      expect(failure.textContent).toContain(text);
      expect(failure.textContent).toContain(`Detail from the server: ${error.detail}`);
      // The step wrote nothing: no plan next to the error, no receipt.
      expect(within(step(1)).queryByTestId("job-l2")).toBeNull();
      expect(within(step(1)).getByText(HEAD)).toBeTruthy();
      expect(screen.getByTestId("job-error").textContent).toContain(text);
      view.unmount();
    }
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    const id = controllerJob();
    await cancelJob(id);
    await openJob(id);
    const controller = within(step(1));
    expect(controller.getByText("Ge port 7 på sw-desk portprofilen IoT via unifi-lab.")).toBeTruthy();
    expect(within(controller.getByTestId("job-l2-diff")).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Inställning", "Före", "Efter"]);
    expect(controller.getByTestId("job-l2-receipt").textContent).toMatch(/^Skrevs .*, lästes tillbaka och verifierades; 1 ångrasteg sparat för återställningen\.$/);
    expect(controller.getByTestId("job-l2-reverted").textContent).toBe("Återställd: nätverkskontrollern har den tidigare inställningen igen.");
  });

  it("has no accessibility violations: planned, done, and waiting for a person to undo it", async () => {
    const planned = await openJob(controllerJob({ reserved: true }));
    expect(within(step(2)).getByTestId("job-l2-planned")).toBeTruthy();
    expect(await axeViolations(planned.container)).toEqual([]);
    planned.unmount();

    const done = await openJob(controllerJob());
    expect(within(step(1)).getByTestId("job-l2-diff")).toBeTruthy();
    expect(await axeViolations(done.container)).toEqual([]);
    done.unmount();

    const id = controllerJob({ undoFails: true });
    await cancelJob(id);
    const undo = await openJob(id);
    expect(within(step(1)).getByTestId("job-l2-undo-hint")).toBeTruthy();
    expect(await axeViolations(undo.container)).toEqual([]);
  });
});
