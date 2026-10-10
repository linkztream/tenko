import { render, screen, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it } from "vitest";
import { encodeMoveL2Output, type MoveL2Output } from "../api/moves";
import type { JobState, StepPreview, StepRecord, StepState } from "../api/types";
import { axeViolations } from "../app/testing/axe";
import { IconSprite } from "../components/Icon";
import { setLocale } from "../i18n";
import { L2Step, plannedLine } from "./L2Step";

const CONNECTOR = "0190d1c2-0000-7000-8000-0000000d0001";
const SWITCH = "00:00:5e:00:53:03";
const PATH = `devices/${SWITCH}/ports/7/profile`;

beforeEach(async () => {
  await setLocale("en");
});

function minutesAgo(minutes: number): string {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

/** What the controller step keeps after a port profile was written and read back. */
function written(extra: Partial<MoveL2Output> = {}): MoveL2Output {
  return {
    connector: CONNECTOR,
    change: { type: "set_port_profile", data: { device: SWITCH, port: 7, profile: "prof-iot" } },
    diff: [{ path: PATH, before: "LAN", after: "IoT" }],
    warnings: [],
    read_at: minutesAgo(6),
    unchanged: false,
    unknown_write: false,
    receipt: { connector: CONNECTOR, dry_run: false, applied_at: minutesAgo(5), verified: true, undo_steps: 1, token: "00" },
    ...extra,
  };
}

function stepOf(state: StepState, output?: MoveL2Output | string | null): StepRecord {
  const step: StepRecord = { index: 1, kind: "ipam.move.controller", state, attempts: 1 };
  if (output !== undefined && output !== null) step.output = typeof output === "string" ? output : encodeMoveL2Output(output);
  return step;
}

const PLANNED: StepPreview = {
  summary: "ipam.move.step.controller_port",
  args: { connector: "unifi-lab", device: "sw-desk", port: "7", mac: "00:00:5e:00:53:2b", path: PATH, before: "LAN", after: "IoT" },
  changes: [],
};

function undoTask(): StepState {
  return {
    state: "waiting_for_manual",
    data: { task: { instruction: "jobs.undo.step", args: { step: "1", kind: "ipam.move.controller" } }, deadline: null },
  };
}

function show(step: StepRecord, preview: StepPreview | undefined, jobState: JobState = "running") {
  return render(() => (
    <>
      <IconSprite />
      <L2Step step={step} preview={preview} jobState={jobState} />
    </>
  ));
}

describe("the planned change", () => {
  it("shows the first line of the preview before the step has run", () => {
    show(stepOf({ state: "pending" }), PLANNED);
    const planned = screen.getByTestId("job-l2-planned");
    expect(within(planned).getByText("Planned change")).toBeTruthy();
    expect(within(planned).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Setting", "Before", "After"]);
    const row = within(planned).getByTestId("job-l2-diff-line");
    expect(row.dataset.path).toBe(PATH);
    expect(within(row).getByRole("rowheader").textContent).toBe(PATH);
    expect(within(row).getAllByRole("cell").map((c) => c.textContent)).toEqual(["LAN", "IoT"]);
    // Nothing has been written, so nothing else is claimed.
    expect(screen.queryByTestId("job-l2-diff")).toBeNull();
    expect(screen.queryByTestId("job-l2-receipt")).toBeNull();
    expect(screen.getByTestId("job-l2").getAttribute("aria-label")).toBe("On the network controller");
  });

  it("also shows it while the step runs, and writes a value that is not there as none", () => {
    show(stepOf({ state: "running" }), { ...PLANNED, args: { path: PATH, after: "IoT" } });
    const row = screen.getByTestId("job-l2-diff-line");
    expect(within(row).getAllByRole("cell").map((c) => c.textContent)).toEqual(["none", "IoT"]);
  });

  it("shows nothing without a path in the preview, without a preview or once the step is over", () => {
    expect(plannedLine(undefined)).toBeUndefined();
    expect(plannedLine({ summary: "x", args: { after: "IoT" } })).toBeUndefined();
    expect(plannedLine(PLANNED)).toEqual({ path: PATH, before: "LAN", after: "IoT" });

    show(stepOf({ state: "pending" }), { ...PLANNED, args: { connector: "unifi-lab" } });
    expect(screen.queryByTestId("job-l2")).toBeNull();
    show(stepOf({ state: "pending" }), undefined);
    expect(screen.queryByTestId("job-l2")).toBeNull();
  });

  it("does not show the plan next to a step that is done, failed or undone", () => {
    const failed: StepState = { state: "failed", data: { error: { code: "ipam.move.l2_changed", status: 409, title: "The network changed", detail: "x" } } };
    for (const state of [{ state: "done" }, { state: "skipped" }, { state: "compensated" }, failed] as const) {
      const view = show(stepOf(state), PLANNED);
      expect(screen.queryByTestId("job-l2"), state.state).toBeNull();
      view.unmount();
    }
  });
});

describe("what the step did", () => {
  it("shows the diff as a table with its receipt", () => {
    show(stepOf({ state: "done" }, written()), PLANNED);
    expect(screen.queryByTestId("job-l2-planned")).toBeNull();
    const diff = screen.getByTestId("job-l2-diff");
    expect(within(diff).getByText("What changed")).toBeTruthy();
    expect(within(diff).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Setting", "Before", "After"]);
    const row = within(diff).getByTestId("job-l2-diff-line");
    expect(within(row).getByRole("rowheader").textContent).toBe(PATH);
    expect(within(row).getAllByRole("cell").map((c) => c.textContent)).toEqual(["LAN", "IoT"]);

    const receipt = screen.getByTestId("job-l2-receipt");
    expect(receipt.textContent).toBe("Written 5 minutes ago, read back and verified; 1 undo step kept for the rollback.");
    const time = receipt.querySelector("time");
    expect(time?.getAttribute("datetime")).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(time?.getAttribute("title")).toBeTruthy();
    expect(screen.queryByTestId("job-l2-no-undo")).toBeNull();
    expect(screen.queryByTestId("job-l2-reverted")).toBeNull();
    expect(screen.queryByTestId("job-l2-undo-hint")).toBeNull();
    expect(screen.queryByTestId("job-l2-warnings")).toBeNull();
  });

  it("counts the undo steps of the receipt, and says when there is none", () => {
    const receipt = written().receipt;
    if (!receipt) throw new Error("the fixture has a receipt");
    show(stepOf({ state: "done" }, written({ receipt: { ...receipt, undo_steps: 3 } })), undefined);
    expect(screen.getByTestId("job-l2-receipt").textContent).toContain("3 undo steps kept for the rollback.");
    expect(screen.queryByTestId("job-l2-no-undo")).toBeNull();
  });

  it("warns when a real write has no undo step: a rollback asks a person", () => {
    const receipt = written().receipt;
    if (!receipt) throw new Error("the fixture has a receipt");
    show(stepOf({ state: "done" }, written({ receipt: { ...receipt, undo_steps: 0 } })), undefined);
    expect(screen.getByTestId("job-l2-receipt").textContent).toContain("no undo step kept for the rollback.");
    expect(screen.getByTestId("job-l2-no-undo").textContent).toBe(
      "The receipt has no undo step (the port had no profile on record): a rollback asks a person to put the port back.",
    );
  });

  it("writes a value that is not there as none, in both columns", () => {
    const diff = [
      { path: "devices/x/ports/7/profile", before: null, after: "IoT" },
      { path: "clients/00:00:5e:00:53:2b/network", before: "LAN" },
    ];
    show(stepOf({ state: "done" }, written({ diff })), undefined);
    const rows = screen.getAllByTestId("job-l2-diff-line");
    expect(rows.map((r) => within(r).getAllByRole("cell").map((c) => c.textContent))).toEqual([
      ["none", "IoT"],
      ["LAN", "none"],
    ]);
  });

  it("lists the warnings of the controller under a heading", () => {
    const warnings = ["the device on port 7 loses its link for a moment while the switch applies the profile", "port 7 also carries tagged networks"];
    show(stepOf({ state: "done" }, written({ warnings })), undefined);
    const box = screen.getByTestId("job-l2-warnings");
    expect(within(box).getByText("The network controller warned")).toBeTruthy();
    const list = within(box).getByRole("list", { name: "The network controller warned" });
    expect(within(list).getAllByRole("listitem").map((li) => li.textContent)).toEqual(warnings);
  });

  it("says that the controller had the change already: no table, no receipt", () => {
    show(stepOf({ state: "done" }, written({ diff: [], unchanged: true, receipt: null })), PLANNED);
    expect(screen.getByTestId("job-l2-unchanged").textContent).toBe("The network controller had this change already; nothing was written.");
    expect(screen.queryByTestId("job-l2-diff")).toBeNull();
    expect(screen.queryByTestId("job-l2-receipt")).toBeNull();
    expect(screen.queryByTestId("job-l2-planned")).toBeNull();
  });

  it("says that an interrupted attempt may have written without a receipt", () => {
    show(stepOf({ state: "done" }, written({ diff: [], unknown_write: true, receipt: null })), undefined);
    expect(screen.getByTestId("job-l2-unknown-write").textContent).toBe(
      "An interrupted attempt may have written this change without keeping its receipt; a rollback asks a person.",
    );
    expect(screen.queryByTestId("job-l2-diff")).toBeNull();
    expect(screen.queryByTestId("job-l2-receipt")).toBeNull();
  });

  it("does not call a dry run a write", () => {
    const receipt = written().receipt;
    if (!receipt) throw new Error("the fixture has a receipt");
    show(stepOf({ state: "done" }, written({ receipt: { ...receipt, dry_run: true } })), undefined);
    expect(screen.getByTestId("job-l2-diff")).toBeTruthy();
    expect(screen.queryByTestId("job-l2-receipt")).toBeNull();
  });

  it("shows no diff when the output is absent or cannot be read", () => {
    const cases: (string | null)[] = [
      null,
      "",
      "zz",
      "abc",
      // Hex of text that is not JSON, of JSON that is not an output, and of JSON null.
      Array.from(new TextEncoder().encode("not json"), (b) => b.toString(16).padStart(2, "0")).join(""),
      Array.from(new TextEncoder().encode('{"diff":[]}'), (b) => b.toString(16).padStart(2, "0")).join(""),
      Array.from(new TextEncoder().encode("null"), (b) => b.toString(16).padStart(2, "0")).join(""),
    ];
    for (const output of cases) {
      const view = show(stepOf({ state: "done" }, output), PLANNED);
      expect(screen.queryByTestId("job-l2"), String(output)).toBeNull();
      view.unmount();
    }
  });
});

describe("a rollback", () => {
  it("says that the controller has the previous setting again once the step is undone", () => {
    show(stepOf({ state: "compensated" }, written()), PLANNED, "cancelled");
    expect(screen.getByTestId("job-l2-reverted").textContent).toBe("Rolled back: the network controller has the previous setting again.");
    // What the step had changed stays visible, so the page tells what was undone.
    expect(screen.getByTestId("job-l2-diff")).toBeTruthy();
    expect(screen.queryByTestId("job-l2-undo-hint")).toBeNull();
  });

  it("says nothing about a revert when nothing was written", () => {
    show(stepOf({ state: "compensated" }, written({ diff: [], unchanged: true, receipt: null })), undefined, "rolled_back");
    expect(screen.queryByTestId("job-l2-reverted")).toBeNull();
    expect(screen.getByTestId("job-l2-unchanged")).toBeTruthy();
  });

  it("counts an interrupted attempt as a write: a person undid it", () => {
    show(stepOf({ state: "compensated" }, written({ diff: [], unknown_write: true, receipt: null })), undefined, "cancelled");
    expect(screen.getByTestId("job-l2-reverted")).toBeTruthy();
  });

  it("does not say reverted while the step is done or being undone", () => {
    for (const state of [{ state: "done" }, { state: "compensating" }, { state: "compensation_failed", data: { error: { code: "x", status: 500, title: "x", detail: "x" } } }] as const) {
      const view = show(stepOf(state, written()), undefined, "rolling_back");
      expect(screen.queryByTestId("job-l2-reverted"), state.state).toBeNull();
      view.unmount();
    }
  });

  it("tells a person which setting to put back, above the task", () => {
    show(stepOf(undoTask(), written()), PLANNED, "rolling_back");
    const hint = screen.getByTestId("job-l2-undo-hint");
    expect(hint.textContent).toBe(`Put the previous setting back on the network controller: ${PATH} to LAN.`);
    // The diff and the receipt are above it, so the person reads what was done first.
    const group = screen.getByTestId("job-l2");
    expect(group.lastElementChild).toBe(hint);
    expect(screen.getByTestId("job-l2-diff")).toBeTruthy();
    expect(screen.queryByTestId("job-l2-reverted")).toBeNull();
  });

  it("says none when there was no setting before, and falls back to the plan when the diff is empty", () => {
    show(stepOf(undoTask(), written({ diff: [{ path: PATH, before: null, after: "IoT" }] })), undefined, "rolling_back");
    expect(screen.getByTestId("job-l2-undo-hint").textContent).toBe(`Put the previous setting back on the network controller: ${PATH} to none.`);
  });

  it("falls back to the planned line when an interrupted attempt left an empty diff", () => {
    show(stepOf(undoTask(), written({ diff: [], unknown_write: true, receipt: null })), PLANNED, "rolling_back");
    expect(screen.getByTestId("job-l2-undo-hint").textContent).toBe(`Put the previous setting back on the network controller: ${PATH} to LAN.`);
    expect(screen.getByTestId("job-l2-unknown-write")).toBeTruthy();
  });

  it("gives no hint when nothing names the setting", () => {
    show(stepOf(undoTask(), written({ diff: [] })), undefined, "rolling_back");
    expect(screen.queryByTestId("job-l2-undo-hint")).toBeNull();
  });

  it("gives no hint while the job runs forward", () => {
    // A task that waits during a run is not an undo task.
    show(stepOf(undoTask(), written()), PLANNED, "waiting");
    expect(screen.queryByTestId("job-l2-undo-hint")).toBeNull();
  });
});

describe("in Swedish", () => {
  it("translates every line", async () => {
    await setLocale("sv");
    show(stepOf({ state: "compensated" }, written({ warnings: ["w"] })), undefined, "cancelled");
    expect(screen.getByTestId("job-l2").getAttribute("aria-label")).toBe("I nätverkskontrollern");
    expect(within(screen.getByTestId("job-l2-diff")).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Inställning", "Före", "Efter"]);
    expect(screen.getByTestId("job-l2-receipt").textContent).toMatch(/^Skrevs .*, lästes tillbaka och verifierades; 1 ångrasteg sparat för återställningen\.$/);
    expect(screen.getByTestId("job-l2-reverted").textContent).toBe("Återställd: nätverkskontrollern har den tidigare inställningen igen.");
    expect(within(screen.getByTestId("job-l2-warnings")).getByText("Nätverkskontrollern varnade")).toBeTruthy();
  });
});

describe("accessibility", () => {
  it("has no violations for the plan, the diff with its receipt and warnings, and the hint", async () => {
    const plan = show(stepOf({ state: "pending" }), PLANNED);
    expect(await axeViolations(plan.container)).toEqual([]);
    plan.unmount();

    const done = show(stepOf({ state: "done" }, written({ warnings: ["w1", "w2"] })), PLANNED);
    expect(await axeViolations(done.container)).toEqual([]);
    done.unmount();

    const receipt = written().receipt;
    if (!receipt) throw new Error("the fixture has a receipt");
    const bare = show(stepOf({ state: "done" }, written({ receipt: { ...receipt, undo_steps: 0 } })), PLANNED);
    expect(await axeViolations(bare.container)).toEqual([]);
    bare.unmount();

    const undo = show(stepOf(undoTask(), written()), PLANNED, "rolling_back");
    expect(await axeViolations(undo.container)).toEqual([]);
    undo.unmount();

    const reverted = show(stepOf({ state: "compensated" }, written()), PLANNED, "cancelled");
    expect(await axeViolations(reverted.container)).toEqual([]);
  });
});
