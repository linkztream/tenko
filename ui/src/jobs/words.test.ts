import { beforeEach, describe, expect, it } from "vitest";
import { JOB_STATES } from "../api/types";
import type { JobSummary, ManualTask, StepRecord, StepStateKind } from "../api/types";
import { setLocale, tDynamic } from "../i18n";
import {
  canCancel,
  countdownParts,
  groupLabel,
  kindRank,
  matchesView,
  MAX_NOTE_BYTES,
  needsPerson,
  noteBytes,
  parseView,
  progressPercent,
  STEP_ORDER,
  viewStates,
  VIEWS,
} from "./model";
import {
  codedErrorDetail,
  codedErrorText,
  describeStep,
  jobStateClass,
  jobStateWord,
  jobTitle,
  stepKey,
  stepName,
  stepStateClass,
  stepStateWord,
  stepSummary,
  summaryArgs,
  taskText,
} from "./words";

beforeEach(async () => {
  await setLocale("en");
});

const STEP_STATES: readonly StepStateKind[] = [
  "pending",
  "running",
  "done",
  "skipped",
  "waiting_for_observation",
  "waiting_for_manual",
  "failed",
  "compensating",
  "compensated",
  "compensation_failed",
];

describe("state words and glyph classes", () => {
  it("has a word for every job state and step state", () => {
    for (const state of JOB_STATES) {
      expect(jobStateWord(state)).not.toMatch(/^jobs\./);
      expect(jobStateWord(state)).not.toBe("");
    }
    for (const state of STEP_STATES) {
      expect(stepStateWord(state)).not.toMatch(/^jobs\./);
    }
    expect(jobStateWord("succeeded")).toBe("Done");
    expect(jobStateWord("rolled_back")).toBe("Rolled back");
    expect(stepStateWord("waiting_for_manual")).toBe("Waiting for you");
  });

  it("maps job states to the classes of design.css", () => {
    expect(jobStateClass("queued")).toBe("queued");
    expect(jobStateClass("running")).toBe("running");
    expect(jobStateClass("waiting")).toBe("waiting");
    expect(jobStateClass("succeeded")).toBe("done");
    expect(jobStateClass("failed")).toBe("failed");
    expect(jobStateClass("rolled_back")).toBe("rolledback");
    expect(jobStateClass("rolling_back")).toBe("rolledback");
    // Cancelled is a queued ring with a struck word.
    expect(jobStateClass("cancelled").split(" ")).toEqual(expect.arrayContaining(["queued", "cancelled"]));
  });

  it("maps every step state to a glyph class", () => {
    for (const state of STEP_STATES) expect(stepStateClass(state)).toMatch(/^(queued|running|waiting|done|failed|rolledback)/);
    expect(stepStateClass("waiting_for_observation")).toBe("waiting");
    expect(stepStateClass("compensated")).toBe("rolledback");
  });
});

describe("titles, step summaries and tasks", () => {
  it("translates the titles of the server and shows an unknown key as it is", () => {
    expect(jobTitle({ title: "jobs.title.move" })).toBe("Move host to another network");
    expect(jobTitle({ spec: { title: "jobs.title.import_apply" } })).toBe("Apply an import");
    expect(jobTitle({ title: "jobs.title.something_new" })).toBe("jobs.title.something_new");
  });

  it("builds the summary key of a step kind", () => {
    expect(stepKey("dhcp.manual")).toBe("jobs.step.dhcp_manual");
    expect(stepKey("import.apply_chunk")).toBe("jobs.step.import_apply_chunk");
  });

  it("formats a summary with the arguments of the step", () => {
    expect(stepSummary("ipam.intent", { host: "thermostat-1" })).toBe("Record the new address of thermostat-1");
    expect(stepSummary("dhcp.manual", { host: "thermostat-1", ip: "198.51.100.41", mac: "x", prefix: "y" })).toBe(
      "Reserve 198.51.100.41 for thermostat-1 in DHCP",
    );
    expect(stepSummary("l2.move", { host: "thermostat-1", vlan: "30" })).toBe("Move thermostat-1 to VLAN 30");
    expect(stepSummary("import.parse")).toBe("Read the uploaded sheets");
    expect(stepSummary("ipam.apply")).toBe("Apply the change");
  });

  it("falls back to the name of the step kind when the arguments are missing, never to a key", () => {
    expect(stepSummary("dhcp.manual")).toBe("Reserve in DHCP");
    expect(stepSummary("dns.manual", { name: "a.example.test" })).toBe("Update DNS");
    expect(stepName("l2.move")).toBe("Move to the new VLAN");
  });

  it("shows an unknown step kind as it is", () => {
    expect(stepSummary("vendor.new_thing")).toBe("vendor.new_thing");
    expect(stepName("vendor.new_thing")).toBe("vendor.new_thing");
  });

  it("keeps the table of required arguments in step with the messages", () => {
    // Every message that needs arguments formats with exactly the arguments the table names.
    const keys = [
      "ipam.move.step.intent",
      "ipam.move.step.cleanup",
      "ipam.move.task.dhcp",
      "ipam.move.task.dns",
      "ipam.move.task.device",
      "ipam.move.task.l2",
      "ipam.move.task.observe",
      "ipam.move.task.generic",
      "jobs.step.ipam_intent",
      "jobs.step.dhcp_manual",
      "jobs.step.device_manual",
      "jobs.step.dns_manual",
      "jobs.step.l2_move",
      "jobs.step.observe",
      "jobs.step.cleanup",
    ];
    for (const key of keys) {
      const names = summaryArgs(key);
      expect(names.length, key).toBeGreaterThan(0);
      const text = tDynamic(key, Object.fromEntries(names.map((name) => [name, `<${name}>`])));
      expect(text, key).toBeDefined();
      expect(text, key).not.toBe(key);
      for (const name of names) expect(text, `${key} ${name}`).toContain(`<${name}>`);
    }
  });

  it("writes the texts of a move with the arguments the server always sends", () => {
    // The server sends these with every task; the optional ones (vlan, vid, host, mac) are left out here.
    const always = {
      prefix: "0190d1c2-0000-7000-8000-0000000a0002",
      cidr: "198.51.100.0/24",
      vrf: "0190d1c2-0000-7000-8000-000000020001",
      old_ip: "192.0.2.41",
      new_ip: "198.51.100.41",
      address: "0190d1c2-0000-7000-8000-0000000f0001",
      new_address: "0190d1c2-0000-7000-8000-0000000e0001",
    };
    const texts = {
      "ipam.move.task.dhcp": "Create a DHCP reservation of 198.51.100.41 in the scope of 198.51.100.0/24; keep the old one until cleanup.",
      "ipam.move.task.dns": "Point thermostat-1.example.test to 198.51.100.41 (address and reverse records); remove the old records at cleanup.",
      "ipam.move.task.device": "Reconfigure the device to 198.51.100.41 in 198.51.100.0/24.",
      "ipam.move.task.l2": "Move the device to the network 198.51.100.0/24.",
      "ipam.move.task.observe":
        "Confirm that the device is seen at 198.51.100.41 in 198.51.100.0/24; the move rolls back after 43200 seconds.",
    } as const;
    const extra: Record<string, Record<string, string>> = {
      "ipam.move.task.dns": { name: "thermostat-1.example.test" },
      "ipam.move.task.observe": { timeout_secs: "43200" },
    };
    for (const [instruction, text] of Object.entries(texts)) {
      expect(taskText({ instruction, args: { ...always, ...extra[instruction] } }), instruction).toBe(text);
    }
    // The generic task of a step without its own: only the addresses and the network.
    expect(taskText({ instruction: "ipam.move.task.generic", args: { old_ip: "192.0.2.41", new_ip: "198.51.100.41", cidr: "198.51.100.0/24" } })).toBe(
      "Do this step by hand: move the device from 192.0.2.41 to 198.51.100.41 in 198.51.100.0/24, then mark it done.",
    );
    // The automatic steps name the addresses (and the VLAN id when there is one).
    const step: StepRecord = { index: 0, kind: "ipam.move.intent", state: { state: "done" }, attempts: 1 };
    expect(describeStep(step, { summary: "ipam.move.step.intent", args: { old_ip: "192.0.2.41", new_ip: "198.51.100.41", cidr: "198.51.100.0/24" } })).toBe(
      "Add 198.51.100.41 to IPAM as planned; keep 192.0.2.41 until cleanup.",
    );
    const cleanup: StepRecord = { index: 5, kind: "ipam.move.cleanup", state: { state: "pending" }, attempts: 0 };
    expect(describeStep(cleanup, { summary: "ipam.move.step.cleanup", args: { old_ip: "192.0.2.41", new_ip: "198.51.100.41", cidr: "x", vid: "30" } })).toBe(
      "Remove 192.0.2.41 and make 198.51.100.41 active.",
    );
    expect(jobTitle({ title: "ipam.move.title" })).toBe("Move");
  });

  it("names the steps of a move without a preview, and never shows a key", () => {
    const kinds = ["intent", "dhcp", "dns", "device", "l2", "observe", "cleanup"];
    const names = kinds.map((kind) => stepName(`ipam.move.${kind}`));
    expect(names).toEqual([
      "Add the new address in IPAM",
      "Reserve in DHCP",
      "Update DNS",
      "Reconfigure the device",
      "Move to the new network",
      "Confirm that the device is seen",
      "Clean up the old address",
    ]);
    for (const kind of kinds) {
      const step: StepRecord = { index: 0, kind: `ipam.move.${kind}`, state: { state: "pending" }, attempts: 0 };
      expect(describeStep(step)).toBe(stepName(`ipam.move.${kind}`));
      // A preview whose arguments are missing falls back to the same name.
      const key = kind === "intent" || kind === "cleanup" ? `ipam.move.step.${kind}` : `ipam.move.task.${kind}`;
      expect(describeStep(step, { summary: key, args: {} })).toBe(stepName(`ipam.move.${kind}`));
    }
  });

  it("describes a step from the preview of the job, else from its kind", () => {
    const step: StepRecord = { index: 1, kind: "dhcp.manual", state: { state: "pending" }, attempts: 0 };
    expect(describeStep(step, { summary: "jobs.step.dhcp_manual", args: { host: "h1", ip: "192.0.2.5" } })).toBe(
      "Reserve 192.0.2.5 for h1 in DHCP",
    );
    expect(describeStep(step)).toBe("Reserve in DHCP");
    // A summary key this UI does not know falls back to the kind's name, then to the key.
    expect(describeStep(step, { summary: "vendor.summary", args: {} })).toBe("Reserve in DHCP");
    const other: StepRecord = { index: 0, kind: "vendor.x", state: { state: "pending" }, attempts: 0 };
    expect(describeStep(other, { summary: "vendor.summary", args: {} })).toBe("vendor.summary");
  });

  it("takes the arguments of a waiting task when the job has no preview", () => {
    const task: ManualTask = { instruction: "jobs.task.dhcp_reserve", args: { host: "h1", ip: "192.0.2.5" } };
    const step: StepRecord = {
      index: 1,
      kind: "dhcp.manual",
      state: { state: "waiting_for_manual", data: { task, deadline: null } },
      attempts: 1,
    };
    expect(describeStep(step)).toBe("Reserve 192.0.2.5 for h1 in DHCP");
  });

  it("translates a manual task with its arguments, and its undo text on request", () => {
    const task: ManualTask = {
      instruction: "jobs.task.dns_update",
      args: { name: "a.example.test", old_ip: "192.0.2.5", new_ip: "198.51.100.5" },
      undo: "jobs.task.dns_revert",
    };
    expect(taskText(task)).toBe("Change the DNS record a.example.test from 192.0.2.5 to 198.51.100.5.");
    expect(taskText(task, true)).toBe("Change the DNS record a.example.test back to 192.0.2.5.");
    expect(taskText({ instruction: "vendor.task", args: {} })).toBe("vendor.task");
    expect(taskText({ instruction: "jobs.undo.step", args: { step: "3", kind: "dns.manual" } })).toBe(
      "Undo step 3 (dns.manual) by hand, then mark this done.",
    );
  });

  it("has a Swedish translation for the words", async () => {
    await setLocale("sv");
    expect(jobStateWord("waiting")).toBe("Väntar");
    expect(jobTitle({ title: "jobs.title.move" })).toBe("Flytta värd till ett annat nätverk");
    expect(stepSummary("l2.move", { host: "h1", vlan: "30" })).toBe("Flytta h1 till VLAN 30");
  });
});

describe("errors", () => {
  it("translates the codes of the job engine and keeps the server detail as a second line", () => {
    const error = { code: "jobs.step.failed", status: 502, title: "Step failed", detail: "No ARP or lease within 5:00." };
    expect(codedErrorText(error)).toBe("A step failed.");
    expect(codedErrorDetail(error)).toBe("No ARP or lease within 5:00.");
    expect(codedErrorText({ code: "jobs.timeout", status: 504, title: "t", detail: "d" })).toMatch(/timeout/);
  });

  it("does not repeat a server detail that only says what the translation says", () => {
    const cancelled = { code: "jobs.cancelled", status: 409, title: "Job cancelled", detail: "the job was cancelled" };
    expect(codedErrorText(cancelled)).toBe("The job was cancelled.");
    expect(codedErrorDetail(cancelled)).toBeUndefined();
    expect(codedErrorDetail({ code: "jobs.step.deadline_passed", status: 504, title: "t", detail: "step 2 was still waiting" })).toBeUndefined();
  });

  it("prefers the shared translation of a code, and the server text for a code nobody translated", () => {
    expect(codedErrorText({ code: "auth.forbidden", status: 403, title: "Forbidden", detail: "x" })).not.toBe("x");
    const unknown = { code: "vendor.broken", status: 500, title: "Broken", detail: "The vendor part broke." };
    expect(codedErrorText(unknown)).toBe("The vendor part broke.");
    expect(codedErrorDetail(unknown)).toBeUndefined();
  });

  it("passes numeric parameters as numbers", () => {
    const error = { code: "jobs.note.too_long", status: 400, title: "t", detail: "d", params: { max: "4096" } };
    expect(codedErrorText(error)).toBe("The note is too long. It can have at most 4,096 bytes.");
  });
});

describe("rules of the views", () => {
  const job = (state: JobSummary["state"], manual?: number[]): Pick<JobSummary, "state" | "manual_steps"> =>
    manual ? { state, manual_steps: manual } : { state };

  it("counts a note in bytes, not characters", () => {
    expect(noteBytes("abc")).toBe(3);
    expect(noteBytes("é")).toBe(2);
    expect(noteBytes("é".repeat(2048))).toBe(MAX_NOTE_BYTES);
    expect(noteBytes("é".repeat(2049))).toBe(MAX_NOTE_BYTES + 2);
  });

  it("filters by the chip, and narrows 'needs you' down to jobs with a manual step", () => {
    expect(VIEWS).toEqual(["all", "active", "needs", "failed", "finished"]);
    expect(viewStates("all")).toBeUndefined();
    expect(viewStates("active")).toEqual(["queued", "running", "waiting", "rolling_back"]);
    expect(matchesView("all", job("cancelled"))).toBe(true);
    expect(matchesView("active", job("running"))).toBe(true);
    expect(matchesView("active", job("succeeded"))).toBe(false);
    expect(matchesView("needs", job("waiting", [1]))).toBe(true);
    expect(matchesView("needs", job("waiting"))).toBe(false);
    expect(matchesView("needs", job("rolling_back", [2]))).toBe(true);
    expect(matchesView("needs", job("running", [2]))).toBe(false);
    expect(matchesView("failed", job("rolled_back"))).toBe(true);
    expect(matchesView("failed", job("cancelled"))).toBe(false);
    expect(matchesView("finished", job("cancelled"))).toBe(true);
    expect(matchesView("finished", job("waiting"))).toBe(false);
    expect(needsPerson(job("waiting", []))).toBe(false);
  });

  it("reads the view from the URL and ignores unknown values", () => {
    expect(parseView("needs")).toBe("needs");
    expect(parseView("nonsense")).toBe("all");
    expect(parseView(undefined)).toBe("all");
    expect(parseView(["needs"])).toBe("all");
  });

  it("offers Cancel only while it can work", () => {
    expect(canCancel("queued", false)).toBe(true);
    expect(canCancel("running", false)).toBe(true);
    expect(canCancel("waiting", false)).toBe(true);
    expect(canCancel("waiting", true)).toBe(false);
    expect(canCancel("rolling_back", false)).toBe(false);
    for (const state of ["succeeded", "failed", "rolled_back", "cancelled"] as const) expect(canCancel(state, false)).toBe(false);
  });

  it("shortens a group key to the start of its id", () => {
    expect(groupLabel("ipam.move.0190d1c200007000800000000a0002")).toBe("0190d1c2");
    expect(groupLabel("ipam.move.abcdef0123456789abcdef0123456789")).toBe("abcdef01");
    expect(groupLabel("move-0190d1c2-0000-7000-8000-00000000d006")).toBe("0190d1c2");
    expect(groupLabel("0190d1c2-0000")).toBe("0190d1c2");
    expect(groupLabel("batch")).toBe("batch");
  });

  it("orders the checklist like the job of a move, unknown kinds last", () => {
    expect(STEP_ORDER).toEqual([
      "ipam.move.intent",
      "ipam.move.dhcp",
      "ipam.move.dns",
      "ipam.move.device",
      "ipam.move.l2",
      "ipam.move.observe",
      "ipam.move.cleanup",
    ]);
    expect(STEP_ORDER.map(kindRank)).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(kindRank("vendor.step")).toBe(STEP_ORDER.length);
    // The kinds of earlier versions keep their place.
    expect(["ipam.intent", "dhcp.manual", "dns.manual", "device.manual", "l2.move", "observe", "cleanup"].map(kindRank)).toEqual([0, 1, 2, 3, 4, 5, 6]);
  });

  it("keeps the progress between 0 and 100", () => {
    expect(progressPercent(3, 6)).toBe(50);
    expect(progressPercent(0, 0)).toBe(0);
    expect(progressPercent(9, 6)).toBe(100);
  });

  it("shows the two largest units of a countdown", () => {
    expect(countdownParts(10 * 3600 + 59 * 60 + 59)).toEqual([
      { unit: "h", value: 10 },
      { unit: "min", value: 59 },
    ]);
    expect(countdownParts(11 * 3600)).toEqual([{ unit: "h", value: 11 }]);
    expect(countdownParts(2 * 86_400 + 3 * 3600)).toEqual([
      { unit: "d", value: 2 },
      { unit: "h", value: 3 },
    ]);
    expect(countdownParts(75)).toEqual([
      { unit: "min", value: 1 },
      { unit: "s", value: 15 },
    ]);
    expect(countdownParts(20)).toEqual([{ unit: "s", value: 20 }]);
    expect(countdownParts(0)).toEqual([{ unit: "s", value: 0 }]);
    expect(countdownParts(-5)).toEqual([{ unit: "s", value: 0 }]);
  });
});
