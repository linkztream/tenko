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
  cancelRolledBack,
  jobStateText,
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

  it("labels a job by its kind when its title key has no message", () => {
    expect(jobTitle({ title: "ipam.job.edit", kind: "ipam.move", targets: [] })).toBe("Move a host to a new address");
    expect(jobTitle({ spec: { title: "ipam.job.edit", kind: "ipam.edit", targets: [{}, {}, {}] } })).toBe("Edit 3 IPAM objects");
    expect(jobTitle({ title: "ipam.job.edit", kind: "ipam.edit", targets: [{}] })).toBe("Edit 1 IPAM object");
    // The message of the title key wins over the label of the kind.
    expect(jobTitle({ title: "jobs.title.move", kind: "ipam.edit", targets: [] })).toBe("Move host to another network");
  });

  it("falls back to the title key for a kind without a label", () => {
    expect(jobTitle({ title: "vendor.job.title", kind: "vendor.unknown", targets: [] })).toBe("vendor.job.title");
    expect(jobTitle({ title: "vendor.job.title" })).toBe("vendor.job.title");
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
      "ipam.move.step.controller_port",
      "ipam.move.step.controller_client",
      "ipam.move.task.l2_vlan",
      "ipam.move.task.l2_port",
      "ipam.move.task.l2_client",
      "ipam.move.task.l2_port_vlan",
      "ipam.move.task.l2_shared_port",
      "ipam.move.task.l2_ssid",
      "ipam.move.task.l2_network",
      "ipam.move.task.l2_refused",
      "ipam.move.task.observe",
      "ipam.move.task.generic",
      "jobs.step.ipam_intent",
      "jobs.step.dhcp_manual",
      "jobs.step.device_manual",
      "jobs.step.dns_manual",
      "jobs.step.l2_move",
      "jobs.step.observe",
      "jobs.step.cleanup",
      "ipam.vlan.step.intent",
      "ipam.vlan.step.controller",
      "ipam.vlan.step.activate",
      "ipam.vlan.task.network",
    ];
    for (const key of keys) {
      const names = summaryArgs(key);
      expect(names.length, key).toBeGreaterThan(0);
      // A count is a number for a plural; every other argument is text.
      const sample = (name: string) => (name === "count" ? "2" : `<${name}>`);
      const text = tDynamic(key, Object.fromEntries(names.map((name) => [name, sample(name)])));
      expect(text, key).toBeDefined();
      expect(text, key).not.toBe(key);
      for (const name of names) expect(text, `${key} ${name}`).toContain(sample(name));
    }
  });

  it("writes the texts of a VLAN provision job with the arguments the server always sends", () => {
    // The server sends vid and name with every step; cidr and connector only when they exist.
    const args = { vid: "30", name: "IoT" };
    expect(taskText({ instruction: "ipam.vlan.task.network", args })).toBe(
      "Create the network IoT on VLAN 30 on the switches and access points, then mark this step done.",
    );
    expect(stepName("ipam.vlan.controller")).toBe("Create on the network controller");
    expect(stepName("ipam.vlan.manual")).toBe("Create the network by hand");
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

  it("words the DHCP preparation of a move: the mark, the wait for the short lease and its manual task", () => {
    const args = { old_ip: "192.0.2.41", new_ip: "198.51.100.41", cidr: "198.51.100.0/24" };
    const prepare: StepRecord = { index: 0, kind: "ipam.move.prepare", state: { state: "done" }, attempts: 1 };
    const lease: StepRecord = { index: 4, kind: "ipam.move.lease", state: { state: "pending" }, attempts: 0 };
    expect(stepName("ipam.move.prepare")).toBe("Mark the device as moving");
    expect(stepName("ipam.move.lease")).toBe("Wait for the short lease");
    expect(describeStep(prepare, { summary: "ipam.move.step.prepare", args })).toBe(
      "Mark the device as moving from 192.0.2.41 to 198.51.100.41 in 198.51.100.0/24, so Tenko DHCP follows its DHCP messages.",
    );
    expect(describeStep(lease, { summary: "ipam.move.step.short_lease", args })).toBe(
      "Wait for the device at 192.0.2.41 to renew with the short lease before it moves to 198.51.100.41 in 198.51.100.0/24.",
    );
    // The task names the expected renewal as a date and a time and the short lease in seconds.
    const task = { instruction: "ipam.move.task.short_lease", args: { ...args, mac: "00:00:5e:00:53:29", short_secs: "120", next_activity: "2026-10-26T10:42:00Z" } };
    expect(taskText(task)).toMatch(
      /^Wait until 00:00:5e:00:53:29 renews 192\.0\.2\.41 \(expected .*2026.*\); it then gets a short lease of 120 s and moves to 198\.51\.100\.41 in 198\.51\.100\.0\/24\. Mark this step done to move it at once\.$/,
    );
    // A time that does not parse counts as missing: the name of the step stands in, never a key.
    expect(describeStep(lease, { summary: "ipam.move.task.short_lease", args: { ...task.args, next_activity: "soon" } })).toBe("Wait for the short lease");
  });

  it("names and summarizes the L2 step through the network controller", async () => {
    expect(stepName("ipam.move.controller")).toBe("Move on the network controller");
    const port = { connector: "unifi-lab", device: "sw-desk", port: "7", after: "IoT", mac: "00:00:5e:00:53:2b" };
    const step: StepRecord = { index: 1, kind: "ipam.move.controller", state: { state: "pending" }, attempts: 0 };
    expect(describeStep(step, { summary: "ipam.move.step.controller_port", args: port })).toBe(
      "Give port 7 of sw-desk the port profile IoT through unifi-lab.",
    );
    expect(describeStep(step, { summary: "ipam.move.step.controller_client", args: port })).toBe(
      "Set the VLAN override of 00:00:5e:00:53:2b to the network IoT through unifi-lab.",
    );
    // The preview has no diff line when the controller had nothing to change: the name stands in, never a key.
    const { after: _after, ...noAfter } = port;
    expect(describeStep(step, { summary: "ipam.move.step.controller_port", args: noAfter })).toBe("Move on the network controller");
    const { port: _port, ...noPort } = port;
    expect(describeStep(step, { summary: "ipam.move.step.controller_port", args: noPort })).toBe("Move on the network controller");
    expect(describeStep(step, { summary: "ipam.move.step.controller_client", args: { connector: "unifi-lab", after: "IoT" } })).toBe(
      "Move on the network controller",
    );
    expect(describeStep(step)).toBe("Move on the network controller");

    await setLocale("sv");
    expect(stepName("ipam.move.controller")).toBe("Flytta via nätverkskontrollern");
    expect(describeStep(step, { summary: "ipam.move.step.controller_port", args: port })).toBe("Ge port 7 på sw-desk portprofilen IoT via unifi-lab.");
    expect(describeStep(step, { summary: "ipam.move.step.controller_client", args: port })).toBe(
      "Sätt VLAN-överstyrningen för 00:00:5e:00:53:2b till nätet IoT via unifi-lab.",
    );
  });

  it("names and summarizes the bounce of a port and the kick of a client", async () => {
    expect(stepName("ipam.move.nudge")).toBe("Bounce the port or disconnect the device");
    const args = { port: "5", down_secs: "5", reappear_secs: "30", connector: "unifi-lab", device: "sw1", mac: "00:00:5e:00:53:2b", old_ip: "192.0.2.43", new_ip: "198.51.100.43" };
    const step: StepRecord = { index: 2, kind: "ipam.move.nudge", state: { state: "pending" }, attempts: 0 };
    expect(describeStep(step, { summary: "ipam.move.step.nudge_bounce", args })).toBe(
      "If the device is not back within 30 s, bounce port 5 of sw1 (down for 5 s) through unifi-lab.",
    );
    expect(describeStep(step, { summary: "ipam.move.step.nudge_kick", args })).toBe(
      "If 00:00:5e:00:53:2b is not back within 30 s, disconnect it from sw1 through unifi-lab so that it connects again.",
    );
    // A summary that lacks an argument it needs gives way to the name of the step, never a key.
    const { port: _port, ...noPort } = args;
    expect(describeStep(step, { summary: "ipam.move.step.nudge_bounce", args: noPort })).toBe("Bounce the port or disconnect the device");
    expect(summaryArgs("ipam.move.step.nudge_kick")).toEqual(["reappear_secs", "connector", "device", "mac"]);
    // The step of the preview and of the job share their place in the checklist.
    expect(kindRank("l2.nudge")).toBe(kindRank("ipam.move.nudge"));

    await setLocale("sv");
    expect(stepName("ipam.move.nudge")).toBe("Starta om porten eller koppla ned enheten");
    expect(describeStep(step, { summary: "ipam.move.step.nudge_bounce", args })).toBe(
      "Om enheten inte är tillbaka inom 30 s: starta om port 5 på sw1 (nere i 5 s) via unifi-lab.",
    );
  });

  it("words the port that did not come up again", async () => {
    const error = {
      code: "connect.port_stuck",
      status: 502,
      title: "t",
      detail: "port 5 of sw1 did not come up",
      params: { connector: "unifi-lab", device: "sw1", device_id: "00:00:5e:00:53:03", port: "5", cause: "timeout" },
    };
    expect(codedErrorText(error)).toBe("Port 5 of sw1 on unifi-lab did not come up again after the bounce (timeout). Tenko keeps trying; you can also switch it on at the controller.");
    await setLocale("sv");
    expect(codedErrorText(error)).toBe("Port 5 på sw1 i unifi-lab kom inte upp igen efter omstarten (timeout). Tenko fortsätter att försöka; du kan också slå på den i kontrollern.");
  });

  it("writes the manual L2 tasks of a move exactly, with the arguments the server sends", async () => {
    // The base arguments of every task come first; the L2 ones follow (crates/tenko-ipam/src/moves/l2.rs, args).
    const base = { cidr: "198.51.100.0/24", old_ip: "192.0.2.41", new_ip: "198.51.100.41", vid: "30" };
    const l2 = { connector: "unifi-lab", device: "sw-desk", port: "7", profile: "IoT", network: "IoT", mac: "00:00:5e:00:53:2b", ssid: "iot.example.test", count: "1", rule: "connect.guardrail.uplink" };
    const texts: Record<string, string> = {
      "ipam.move.task.l2_vlan": "Move the device to VLAN 30: set its switch port to VLAN 30 untagged, or join it to a wireless network that carries VLAN 30.",
      "ipam.move.task.l2_port": "On unifi-lab, give port 7 of sw-desk the port profile IoT (VLAN 30 untagged); writes through this connector are off.",
      "ipam.move.task.l2_client": "On unifi-lab, set the VLAN override of 00:00:5e:00:53:2b to the network IoT (VLAN 30); writes through this connector are off.",
      "ipam.move.task.l2_port_vlan": "Set port 7 of sw-desk to VLAN 30 untagged; no port profile on unifi-lab carries that VLAN untagged.",
      "ipam.move.task.l2_shared_port": "Move the device to VLAN 30 by hand: port 7 of sw-desk also serves 1 other device, and a profile change would move them too.",
      "ipam.move.task.l2_ssid": "Join the device to the wireless network iot.example.test, which carries VLAN 30; its access point sw-desk does not carry that VLAN.",
      "ipam.move.task.l2_network": "Create the network for VLAN 30 on unifi-lab (create the VLAN with its network in Tenko), then move the device to it.",
      "ipam.move.task.l2_refused": "Move the device to VLAN 30 by hand, if that is intended: Tenko never changes this path (connect.guardrail.uplink).",
    };
    for (const [instruction, text] of Object.entries(texts)) {
      expect(taskText({ instruction, args: { ...base, ...l2 } }), instruction).toBe(text);
      // As the step of a job: the head names the step and the task below says the rest.
      const step: StepRecord = {
        index: 1,
        kind: "ipam.move.l2",
        state: { state: "waiting_for_manual", data: { task: { instruction, args: { ...base, ...l2 } }, deadline: null } },
        attempts: 1,
      };
      expect(describeStep(step, { summary: instruction, args: { ...base, ...l2 } }), instruction).toBe(text);
      // A step that has not started carries no task: without the arguments the server always sends,
      // the name of the step stands in, never a key.
      const pending: StepRecord = { index: 1, kind: "ipam.move.l2", state: { state: "pending" }, attempts: 0 };
      expect(describeStep(pending, { summary: instruction, args: {} }), instruction).toBe("Move to the new network");
    }
    expect(taskText({ instruction: "ipam.move.task.l2_shared_port", args: { ...base, ...l2, count: "3" } })).toBe(
      "Move the device to VLAN 30 by hand: port 7 of sw-desk also serves 3 other devices, and a profile change would move them too.",
    );

    await setLocale("sv");
    expect(taskText({ instruction: "ipam.move.task.l2_port", args: { ...base, ...l2 } })).toBe(
      "I unifi-lab, ge port 7 på sw-desk portprofilen IoT (VLAN 30 otaggat); skrivningar via anslutningen är avstängda.",
    );
    expect(taskText({ instruction: "ipam.move.task.l2_shared_port", args: { ...base, ...l2, count: "3" } })).toContain("3 andra enheter");
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
    // The generic undo text names the step in words, not by its raw kind.
    expect(taskText({ instruction: "jobs.undo.step", args: { step: "3", kind: "dns.manual" } })).toBe(
      "Undo step 3 (Update DNS) by hand, then mark this done.",
    );
    expect(taskText({ instruction: "jobs.undo.step", args: { step: "2", kind: "vendor.unknown" } })).toBe(
      "Undo step 2 (vendor.unknown) by hand, then mark this done.",
    );
  });

  it("has a Swedish translation for the words", async () => {
    await setLocale("sv");
    expect(jobStateWord("waiting")).toBe("Väntar");
    expect(jobTitle({ title: "jobs.title.move" })).toBe("Flytta värd till ett annat nätverk");
    expect(stepSummary("l2.move", { host: "h1", vlan: "30" })).toBe("Flytta h1 till VLAN 30");
    expect(jobTitle({ title: "ipam.job.edit", kind: "ipam.move", targets: [] })).toBe("Flytta en värd till en ny adress");
    expect(jobTitle({ title: "ipam.job.edit", kind: "ipam.edit", targets: [{}, {}] })).toBe("Redigera 2 IPAM-objekt");
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
      "ipam.move.prepare",
      "ipam.move.intent",
      "ipam.move.dhcp",
      "ipam.move.dns",
      "ipam.move.device",
      "ipam.move.lease",
      "ipam.move.l2",
      "ipam.move.nudge",
      "ipam.move.observe",
      "ipam.move.cleanup",
    ]);
    expect(STEP_ORDER.map(kindRank)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(kindRank("vendor.step")).toBe(STEP_ORDER.length);
    // The kinds of earlier versions keep their place, and the preview kinds of the DHCP preparation theirs.
    expect(["ipam.intent", "dhcp.manual", "dns.manual", "device.manual", "l2.move", "observe", "cleanup"].map(kindRank)).toEqual([1, 2, 3, 4, 6, 8, 9]);
    expect(["dhcp.prepare", "dhcp.short_lease", "l2.nudge"].map(kindRank)).toEqual([0, 5, 7]);
    // The L2 change through the network controller takes the place of the manual L2 step.
    expect(kindRank("ipam.move.controller")).toBe(kindRank("ipam.move.l2"));
    expect(kindRank("l2.controller")).toBe(kindRank("ipam.move.l2"));
    expect(kindRank("ipam.move.controller")).toBeGreaterThan(kindRank("ipam.move.device"));
    expect(kindRank("ipam.move.controller")).toBeLessThan(kindRank("ipam.move.observe"));
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

describe("a cancelled job that its cancellation rolled back", () => {
  const step = (state: StepStateKind): StepRecord => ({ index: 0, kind: "ipam.move.intent", state: { state } }) as unknown as StepRecord;

  it("is told from the current step of a summary or the steps of a job", () => {
    expect(cancelRolledBack({ state: "cancelled", current_step_state: "compensated" })).toBe(true);
    expect(cancelRolledBack({ state: "cancelled", current_step_state: "pending" })).toBe(false);
    expect(cancelRolledBack({ state: "cancelled" })).toBe(false);
    expect(cancelRolledBack({ state: "rolled_back", current_step_state: "compensated" })).toBe(false);
    expect(cancelRolledBack({ state: "cancelled", steps: [step("compensated"), step("pending")] })).toBe(true);
    expect(cancelRolledBack({ state: "cancelled", steps: [step("pending")] })).toBe(false);
  });

  it("says so in words, and only for a cancelled job", () => {
    expect(jobStateText("cancelled", "cancel")).toBe("Rolled back (cancelled)");
    expect(jobStateText("cancelled")).toBe("Cancelled");
    expect(jobStateText("failed", "cancel")).toBe("Failed");
  });
});
