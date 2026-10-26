import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HOST_IDS, IPAM_IDS, findAddress, ADDRESS_IDS } from "../../api/mock/ipam/api";
import { jobStore } from "../../api/mock/job-store";
import { server } from "../../api/mock/node";
import { grantMockLease } from "../../api/mock/routes-dhcp-leases";
import { mockVlanController } from "../../api/mock/topology-store";
import { previewMove, type MoveItem, type MovePreview as Preview } from "../../api/moves";
import type { ObjectRef } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { paths } from "../../app/paths";
import MovePreview, { parseObjects } from "./MovePreview";

const TARGET = IPAM_IDS.prefix.iot;

function refs(hosts: string[]): ObjectRef[] {
  return hosts.map((h) => ({ kind: "host", id: HOST_IDS[h] as string }));
}

function url(...hosts: string[]): string {
  return paths.move(TARGET, refs(hosts));
}

async function open(...hosts: string[]) {
  const view = renderRoute(MovePreview, { url: url(...hosts), path: "/ipam/move", routes: { "/jobs": () => <div data-testid="jobs-page" /> } });
  const table = await screen.findByTestId("move-devices");
  await waitFor(() => expect(within(table).getAllByTestId("move-item")).toHaveLength(hosts.length));
  return { ...view, table };
}

function item(table: HTMLElement, name: string): HTMLElement {
  const found = within(table)
    .getAllByTestId("move-item")
    .find((el) => el.dataset.key?.startsWith(name));
  if (!found) throw new Error(`no move item ${name}`);
  return found;
}

/** The network cell of a device. */
const l2Cell = (table: HTMLElement, name: string) => within(item(table, name)).getByTestId("move-l2");
/** The first line of a network cell, and its muted second line. */
const headline = (cell: HTMLElement) => cell.querySelector(".l2h")?.textContent ?? null;
const detail = (cell: HTMLElement) => cell.querySelector(".l2s")?.textContent ?? null;

/** Opens the steps of one device and returns the list. */
async function openSteps(table: HTMLElement, name: string): Promise<HTMLElement> {
  const device = item(table, name);
  fireEvent.click(within(device).getByTestId("move-steps-toggle"));
  return within(device).findByTestId("move-steps");
}

/** The preview is not being read again. */
async function settled(table: HTMLElement) {
  await waitFor(() => expect(table.getAttribute("aria-busy")).toBeNull());
}

interface Sent {
  dryRun: boolean;
  key: string | null;
  body: Record<string, unknown>;
}

/** The requests the page sends to the moves API, in order. */
function capture(): Sent[] {
  const sent: Sent[] = [];
  server.events.on("request:start", ({ request }) => {
    const u = new URL(request.url);
    if (request.method !== "POST" || u.pathname !== "/api/v1/moves") return;
    const dryRun = u.searchParams.get("dry_run") === "true";
    const key = request.headers.get("idempotency-key");
    void request
      .clone()
      .json()
      .then((body: Record<string, unknown>) => sent.push({ dryRun, key, body }));
  });
  return sent;
}

/** The preview the mock computes for these hosts, changed by `edit`, served for every dry run; a start falls through to the mock. */
async function serveEdited(hosts: string[], edit: (preview: Preview) => void) {
  const preview = await previewMove({ objects: refs(hosts), target: TARGET, parallelism: 2 });
  edit(preview);
  server.use(
    http.post("/api/v1/moves", ({ request }) => {
      if (new URL(request.url).searchParams.get("dry_run") === "true") return HttpResponse.json(preview);
      return undefined;
    }),
  );
}

const problem = (code: string, status: number) =>
  HttpResponse.json({ code, status, title: code, detail: code, params: {} }, { status, headers: { "content-type": "application/problem+json" } });

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  server.events.removeAllListeners();
  // The controller of the mock is shared by the whole suite.
  mockVlanController.present = true;
  mockVlanController.enabled = true;
  mockVlanController.writes_enabled = true;
});

describe("move preview", () => {
  it("parses the objects of the link", () => {
    expect(parseObjects("host:a,address:b,bogus:c,host:")).toEqual([
      { kind: "host", id: "a" },
      { kind: "address", id: "b" },
    ]);
  });

  it("keeps the host part when it is free and explains when it is not", async () => {
    const { table } = await open("thermostat-1", "speaker-den");
    const thermo = item(table, "thermostat-1");
    expect(thermo.textContent).toContain("192.0.2.41");
    expect(thermo.textContent).toContain("198.51.100.41");
    expect(within(thermo).queryByText("other host part")).toBeNull();
    const speaker = item(table, "speaker-den");
    expect(within(speaker).getByText("other host part")).toBeTruthy();
    expect(speaker.textContent).toMatch(/taken in the target network/);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("198.51.100.0/24");
  });

  it("groups the manual tasks of the batch by step and explains the timeout from the lease", async () => {
    await open("thermostat-1", "speaker-den");
    const checklist = screen.getByTestId("move-checklist");
    const groups = within(checklist).getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
    expect(groups[0]).toMatch(/^DHCP reservations \(2\)/);
    expect(groups).toEqual(expect.arrayContaining([expect.stringMatching(/^DNS records/), expect.stringMatching(/^Network changes/)]));
    // No client of the batch holds a lease Tenko knows: the deadline comes from the pool's lease time.
    expect(screen.getByTestId("move-timeout-help").textContent).toMatch(/Pool lease 1 hr?, so the longest deadline is 61 min/);
  });

  it("shows the steps of one device with Enter and leaves a device out with Space", async () => {
    const { table } = await open("thermostat-1", "speaker-den");
    const row = within(item(table, "thermostat-1")).getAllByRole("row")[0] as HTMLElement;
    fireEvent.keyDown(row, { key: "Enter" });
    const steps = await within(item(table, "thermostat-1")).findByTestId("move-steps");
    // The controller makes the network change of the thermostat: an automatic step, not a task.
    expect(within(steps).getAllByRole("listitem").map((li) => li.dataset.kind)).toEqual([
      "ipam.intent",
      "dhcp.manual",
      "dns.manual",
      "l2.controller",
      "observe",
      "cleanup",
    ]);
    fireEvent.keyDown(row, { key: " " });
    await waitFor(() => expect(screen.getByTestId("move-start").textContent).toMatch(/^Start 1 move/));
  });

  it("starts one job per device in one group and hands over to the jobs of that group", async () => {
    const view = await open("thermostat-1", "speaker-den");
    const before = jobStore.jobs.length;
    fireEvent.click(screen.getByTestId("move-start"));
    // The group is named like the server names it: "ipam.move." and the 32 hex digits of an id.
    await waitFor(() => expect(view.location()).toMatch(/^\/jobs\?group=ipam\.move\.[0-9a-f]{32}$/));
    const created = jobStore.jobs.slice(0, jobStore.jobs.length - before).filter((r) => r.job.spec.kind === "ipam.move");
    expect(created).toHaveLength(2);
    expect(new Set(created.map((r) => r.job.spec.group)).size).toBe(1);
    // The jobs have the title, the steps and the tasks of the server's move job.
    for (const { job } of created) expect(job.spec.title).toBe("ipam.move.title");
    const jobOf = (host: string) => {
      const found = created.find((r) => r.job.spec.targets.some((target) => target.kind === "host" && target.id === HOST_IDS[host]));
      if (!found) throw new Error(`no job of ${host}`);
      return found.job.spec;
    };
    // The thermostat moves through the network controller, the speaker's port is shared: a person moves it.
    expect(jobOf("thermostat-1").steps.map((s) => s.kind)).toEqual([
      "ipam.move.intent",
      "ipam.move.dhcp",
      "ipam.move.dns",
      "ipam.move.controller",
      "ipam.move.observe",
      "ipam.move.cleanup",
    ]);
    expect(jobOf("thermostat-1").targets.map((t) => t.kind)).toEqual(["address", "host", "prefix", "connector"]);
    expect(jobOf("speaker-den").steps.map((s) => s.kind)).toEqual([
      "ipam.move.intent",
      "ipam.move.dhcp",
      "ipam.move.dns",
      "ipam.move.l2",
      "ipam.move.observe",
      "ipam.move.cleanup",
    ]);
    expect(jobOf("speaker-den").targets.map((t) => t.kind)).toEqual(["address", "host", "prefix"]);
    expect(findAddress(ADDRESS_IDS["192.0.2.41"] as string)?.ip).toBe("198.51.100.41");
  });

  it("refuses an unmanaged host with the reason", async () => {
    renderRoute(MovePreview, { url: url("legacy-ups"), path: "/ipam/move" });
    expect(await screen.findByText("Unmanaged hosts are never moved.")).toBeTruthy();
    expect((screen.getByTestId("move-start") as HTMLButtonElement).disabled).toBe(true);
  });

  it("passes axe", async () => {
    await open("thermostat-1");
    expect(await axeViolations(screen.getByTestId("page-move-preview"))).toEqual([]);
  });
});

/** The two times and the preparation of a device, as the timing column shows them. */
function timingOf(table: HTMLElement, name: string) {
  const cell = within(item(table, name)).getByTestId("move-timing");
  const text = (id: string) => within(cell).getByTestId(id).textContent ?? "";
  return { cell, next: text("move-next-activity"), deadline: text("move-deadline"), prepare: text("move-prepare") };
}

/** The kinds of the steps of a device, in order (the steps are opened first). */
async function stepKinds(table: HTMLElement, name: string): Promise<(string | undefined)[]> {
  const steps = await openSteps(table, name);
  return within(steps)
    .getAllByRole("listitem")
    .map((li) => li.dataset.kind);
}

describe("the two times of each device and the preparation", () => {
  it("shows the next DHCP activity and the migration deadline with their sources", async () => {
    // The thermostat holds a lease of an hour that Tenko serves; the speaker is not served.
    grantMockLease({ mac: "00:00:5e:00:53:29", addr: "192.0.2.41" });
    const { table } = await open("thermostat-1", "speaker-den");

    const thermo = timingOf(table, "thermostat-1");
    // Half of the hour: the renewal, relative and absolute, from the client's own lease.
    expect(thermo.next).toMatch(/in (29|30) minutes, .+from the lease$/);
    expect(within(thermo.cell).getByTestId("move-next-activity").querySelector("time")?.getAttribute("datetime")).toMatch(/^\d{4}-\d\d-\d\dT/);
    // The short lease plus the margin is below the floor of five minutes.
    expect(thermo.deadline).toBe("5 minshort lease");
    expect(thermo.prepare).toBe("Waits for the next renewal, which gets a short lease of 2 min.");
    expect(thermo.cell.dataset.prepare).toBe("short_lease");
    expect(thermo.cell.dataset.activitySource).toBe("lease");
    expect(thermo.cell.dataset.deadlineSource).toBe("short_lease");

    const speaker = timingOf(table, "speaker-den");
    // No lease: half the pool's lease time, and the pool's lease time plus the margin.
    expect(speaker.next).toMatch(/in (29|30) minutes, .+from the pool's lease time$/);
    expect(speaker.deadline).toBe("61 minthe pool's lease time");
    expect(speaker.prepare).toBe("Not served by Tenko DHCP: nothing to wait for.");
    expect(speaker.cell.dataset.prepare).toBe("not_served");

    // The move-level text names the longest deadline and how it was chosen.
    expect(screen.getByTestId("move-timeout-help").textContent).toMatch(/Pool lease 1 hr?, so the longest deadline is 61 min/);
    expect(screen.getByText(/Automatic: 61 min/)).toBeTruthy();
  });

  it("puts the preparation into the steps: the mark first, the wait for the short lease right before the network change", async () => {
    grantMockLease({ mac: "00:00:5e:00:53:29", addr: "192.0.2.41" });
    const { table } = await open("thermostat-1", "speaker-den");
    expect(await stepKinds(table, "thermostat-1")).toEqual([
      "dhcp.prepare",
      "ipam.intent",
      "dhcp.manual",
      "dns.manual",
      "dhcp.short_lease",
      "l2.controller",
      "observe",
      "cleanup",
    ]);
    const steps = within(item(table, "thermostat-1")).getByTestId("move-steps");
    const [prepare, , , , wait] = within(steps).getAllByRole("listitem");
    expect(prepare?.classList.contains("auto")).toBe(true);
    expect(prepare?.textContent).toMatch(/Mark thermostat-1 as moving in Tenko DHCP; its next renewal gets a short lease of 2 min\./);
    expect(wait?.classList.contains("manual")).toBe(true);
    expect(wait?.textContent).toMatch(/Wait until thermostat-1 renews 192\.0\.2\.41 with the short lease of 2 min/);
    // The client's lease on its old network is in the expanded row.
    expect(within(item(table, "thermostat-1")).getByTestId("move-lease-span").textContent).toMatch(/^Lease on the old network: .+ to .+/);
    // A client Tenko does not serve has no preparation.
    expect(await stepKinds(table, "speaker-den")).not.toContain("dhcp.prepare");
    // The wait is a manual task of the batch, before the network changes.
    const groups = within(screen.getByTestId("move-checklist")).getAllByTestId("move-checklist-group");
    const wait1 = groups.find((g) => g.dataset.key === "dhcp.short_lease");
    expect(wait1?.querySelector("h3")?.textContent).toBe("Wait for the short lease (1)");
    expect(groups.findIndex((g) => g.dataset.key === "dhcp.short_lease")).toBeLessThan(groups.findIndex((g) => g.dataset.key === "l2.move"));
  });

  it("shows each preparation, an unknown activity and a deadline from the request", async () => {
    await serveEdited(["thermostat-1", "speaker-den", "cam-door"], (preview) => {
      const [a, b, c] = preview.items;
      if (!a || !b || !c) throw new Error("three items");
      a.timing = { next_activity_source: "unknown", prepare: "no_mac", deadline_secs: 3600, deadline_source: "default" };
      b.timing = {
        next_activity: "2030-01-01T10:00:00Z",
        next_activity_source: "lease",
        lease_start: "2030-01-01T00:00:00Z",
        lease_end: "2030-01-02T00:00:00Z",
        prepare: "limit",
        short_lease_secs: 120,
        deadline_secs: 86_400,
        deadline_source: "lease",
      };
      c.timing = { next_activity_source: "unknown", prepare: "move_now", deadline_secs: 1800, deadline_source: "request" };
    });
    const { table } = await open("thermostat-1", "speaker-den", "cam-door");
    const no = timingOf(table, "thermostat-1");
    expect(no.next).toBe("Not knownunknown");
    expect(no.deadline).toBe("1 hrdefault");
    expect(no.prepare).toBe("No MAC address: nothing to prepare in DHCP.");
    const limit = timingOf(table, "speaker-den");
    expect(limit.next).toMatch(/2030.+from the lease$/);
    expect(limit.deadline).toBe("1 daythe client's lease");
    expect(limit.prepare).toBe("The renewal is expected after the preparation limit: the network changes at once.");
    const now = timingOf(table, "cam-door");
    expect(now.deadline).toBe("30 minas chosen");
    expect(now.prepare).toBe("Moves at once, as chosen.");
  });

  it("shows a server without timing as a dash", async () => {
    await serveEdited(["thermostat-1"], (preview) => {
      for (const i of preview.items) delete i.timing;
    });
    const { table } = await open("thermostat-1");
    expect(within(item(table, "thermostat-1")).getByTestId("move-timing").textContent).toBe("–");
  });
});

describe("move now", () => {
  const moveNowSwitch = () => screen.getByRole("switch", { name: "Move now" }) as HTMLInputElement;

  it("is off at first and explains itself in one line", async () => {
    const sent = capture();
    await open("thermostat-1");
    expect(moveNowSwitch().checked).toBe(false);
    expect(screen.getByTestId("move-now-help").textContent).toMatch(/at once instead of after the client's next renewal.+asks for a new lease when its link changes\.$/);
    await waitFor(() => expect(sent.filter((s) => s.dryRun).length).toBeGreaterThan(0));
    expect(sent.filter((s) => s.dryRun).every((s) => s.body.move_now === false)).toBe(true);
  });

  it("previews again with move_now, drops the wait for the short lease and sends the same choice with Start", async () => {
    grantMockLease({ mac: "00:00:5e:00:53:29", addr: "192.0.2.41" });
    const sent = capture();
    const view = await open("thermostat-1");
    const waiting = (await previewMove({ objects: refs(["thermostat-1"]), target: TARGET, parallelism: 2 })).fingerprint;
    expect(await stepKinds(screen.getByTestId("move-devices"), "thermostat-1")).toContain("dhcp.short_lease");

    fireEvent.click(moveNowSwitch());
    await waitFor(() => expect(sent.some((s) => s.dryRun && s.body.move_now === true)).toBe(true));
    const table = screen.getByTestId("move-devices");
    await settled(table);
    const timing = timingOf(table, "thermostat-1");
    expect(timing.prepare).toBe("Moves at once, as chosen.");
    // At once, the deadline is the end of the client's lease plus the margin.
    expect(timing.deadline).toBe("61 minthe client's lease");
    // The steps stay open over the new preview.
    const steps = within(item(table, "thermostat-1")).getByTestId("move-steps");
    const kinds = within(steps)
      .getAllByRole("listitem")
      .map((li) => li.dataset.kind);
    expect(kinds).toContain("dhcp.prepare");
    expect(kinds).not.toContain("dhcp.short_lease");
    expect(screen.queryByTestId("move-checklist")?.querySelector('[data-key="dhcp.short_lease"]') ?? null).toBeNull();

    // The confirmed plan is the one with the choice: its fingerprint differs from the one without it.
    const expected = (await previewMove({ objects: refs(["thermostat-1"]), target: TARGET, parallelism: 2, move_now: true })).fingerprint;
    expect(expected).not.toBe(waiting);
    const before = jobStore.jobs.length;
    fireEvent.click(screen.getByTestId("move-start"));
    await waitFor(() => expect(view.location()).toMatch(/^\/jobs\?group=/));
    const started = sent.filter((s) => !s.dryRun);
    expect(started).toHaveLength(1);
    expect(started[0]?.body.move_now).toBe(true);
    expect(started[0]?.body.expect_fingerprint).toBe(expected);
    // The job marks the client as moving and does not wait for a renewal.
    const created = jobStore.jobs.slice(0, jobStore.jobs.length - before).filter((r) => r.job.spec.kind === "ipam.move");
    expect(created.flatMap((r) => r.job.spec.steps.map((s) => s.kind))).toEqual([
      "ipam.move.prepare",
      "ipam.move.intent",
      "ipam.move.dhcp",
      "ipam.move.dns",
      "ipam.move.controller",
      "ipam.move.observe",
      "ipam.move.cleanup",
    ]);
  });

  it("starts a job that waits for the short lease when the choice is off", async () => {
    grantMockLease({ mac: "00:00:5e:00:53:29", addr: "192.0.2.41" });
    const sent = capture();
    const view = await open("thermostat-1");
    const before = jobStore.jobs.length;
    fireEvent.click(screen.getByTestId("move-start"));
    await waitFor(() => expect(view.location()).toMatch(/^\/jobs\?group=/));
    expect(sent.filter((s) => !s.dryRun)[0]?.body.move_now).toBe(false);
    const created = jobStore.jobs.slice(0, jobStore.jobs.length - before).filter((r) => r.job.spec.kind === "ipam.move");
    const record = created[0];
    const spec = record?.job.spec;
    expect(spec?.steps.map((s) => s.kind)).toEqual([
      "ipam.move.prepare",
      "ipam.move.intent",
      "ipam.move.dhcp",
      "ipam.move.dns",
      "ipam.move.lease",
      "ipam.move.controller",
      "ipam.move.observe",
      "ipam.move.cleanup",
    ]);
    // The wait is a task of a person with the arguments of the server's message.
    const task = record?.plan[spec?.steps.findIndex((s) => s.kind === "ipam.move.lease") ?? -1]?.manual;
    expect(task?.instruction).toBe("ipam.move.task.short_lease");
    expect(task?.args).toMatchObject({ short_secs: "120", mac: "00:00:5e:00:53:29", old_ip: "192.0.2.41" });
    expect(task?.args?.next_activity).toMatch(/^\d{4}-\d\d-\d\dT/);
  });

  it("passes axe with the timing column and the choice", async () => {
    grantMockLease({ mac: "00:00:5e:00:53:29", addr: "192.0.2.41" });
    const { table } = await open("thermostat-1", "speaker-den");
    await openSteps(table, "thermostat-1");
    expect(await axeViolations(table.closest("[data-testid='page-move-preview']") as HTMLElement)).toEqual([]);
  });
});

describe("the network change of each device", () => {
  it("says per device what happens, for a batch of the seed hosts", async () => {
    const { table } = await open(
      "thermostat-1",
      "plug-kitchen",
      "cam-door",
      "speaker-den",
      "printer-1",
      "tenko1",
      "laptop-ak",
      "doorbell",
      "tv-living",
    );
    const seen = Object.fromEntries(
      ["thermostat-1", "plug-kitchen", "cam-door", "speaker-den", "printer-1", "tenko1", "laptop-ak", "doorbell", "tv-living"].map((name) => {
        const cell = l2Cell(table, name);
        return [name, [cell.dataset.action, cell.dataset.reason ?? "", headline(cell), detail(cell)]];
      }),
    );
    expect(seen).toEqual({
      // Wireless: the VLAN override of the client, on the SSID it stays on.
      "thermostat-1": ["client_vlan", "", "VLAN override on ap-hall (SSID home.example.test)", "through unifi.example.test"],
      "plug-kitchen": ["client_vlan", "", "VLAN override on ap-garage (SSID home.example.test)", "through unifi.example.test"],
      // Wired on a port of its own: the port gets the profile.
      "cam-door": ["port_profile", "", "Port profile IoT on sw-desk port 7", "through unifi.example.test"],
      // By hand, with the reason under it.
      "speaker-den": ["manual", "ipam.move.l2.shared_port", "By hand", "1 other device is on the same switch port."],
      "printer-1": ["manual", "ipam.move.l2.refused", "By hand", "This switch port is an uplink; Tenko never changes it."],
      tenko1: ["manual", "ipam.move.l2.refused", "By hand", "This device is the network controller or Tenko's host; Tenko never moves it."],
      "laptop-ak": ["manual", "ipam.move.l2.join_ssid", "By hand", "Its access point does not carry VLAN 30: the device must join iot.example.test."],
      doorbell: ["manual", "ipam.move.l2.no_mac", "By hand", "The device has no MAC address in IPAM."],
      "tv-living": ["manual", "ipam.move.l2.not_seen", "By hand", "The network controller does not see the device."],
    });
    // Only a refusal carries the tag.
    expect(within(table).getAllByText("Refused")).toHaveLength(2);
    expect(within(l2Cell(table, "printer-1")).getByText("Refused")).toBeTruthy();
    expect(within(l2Cell(table, "cam-door")).queryByText("Refused")).toBeNull();
  });

  it("refuses an uplink with its guardrail and keeps Start blocked until the warning is acknowledged", async () => {
    const sent = capture();
    const { table, location } = await open("printer-1", "thermostat-1");
    const cell = l2Cell(table, "printer-1");
    expect(cell.dataset.reason).toBe("ipam.move.l2.refused");
    expect(within(cell).getByText("Refused").classList.contains("tag")).toBe(true);
    expect(cell.textContent).toContain("This switch port is an uplink; Tenko never changes it.");

    // The warning is translated with its own message and asks for an acknowledgement.
    const warnings = screen.getByTestId("move-warnings");
    expect(warnings.textContent).toContain(
      "A guardrail stops Tenko from changing the network of printer-1 (connect.guardrail.uplink); a person moves it, if that is intended.",
    );
    const start = screen.getByTestId("move-start") as HTMLButtonElement;
    expect(start.disabled).toBe(true);
    // The row does not repeat the warning that the network cell and the warnings above already say.
    expect(within(item(table, "printer-1")).queryByText(/A guardrail stops Tenko/)).toBeNull();

    const tick = within(warnings).getByRole("checkbox") as HTMLInputElement;
    fireEvent.click(tick);
    await waitFor(() => expect(tick.checked).toBe(true));
    await settled(table);
    await waitFor(() => expect(start.disabled).toBe(false));
    // The preview was read again with the acknowledgement.
    expect(sent.filter((s) => s.dryRun).at(-1)?.body.acknowledge).toEqual(["ipam.move.l2_refused"]);

    fireEvent.click(start);
    await waitFor(() => expect(location()).toMatch(/^\/jobs\?group=ipam\.move\./));
    const started = sent.filter((s) => !s.dryRun);
    expect(started).toHaveLength(1);
    expect(started[0]?.body.acknowledge).toEqual(["ipam.move.l2_refused"]);
  });

  it("gives a wireless device the SSID to join when its access point does not carry the VLAN", async () => {
    const { table } = await open("laptop-ak");
    const cell = l2Cell(table, "laptop-ak");
    expect(cell.dataset.action).toBe("manual");
    expect(detail(cell)).toBe("Its access point does not carry VLAN 30: the device must join iot.example.test.");
    const steps = await openSteps(table, "laptop-ak");
    const manual = within(steps).getAllByRole("listitem").find((li) => li.dataset.kind === "l2.move");
    expect(manual?.textContent).toContain(
      "Join the device to the wireless network iot.example.test, which carries VLAN 30; its access point ap-attic does not carry that VLAN.",
    );
    // The SSID is the instruction already: no second suggestion of it.
    expect(within(item(table, "laptop-ak")).queryByTestId("move-l2-details")).toBeNull();
  });

  it("says a device without a MAC address is moved by a person and offers the SSID", async () => {
    const { table } = await open("doorbell");
    expect(l2Cell(table, "doorbell").dataset.reason).toBe("ipam.move.l2.no_mac");
    await openSteps(table, "doorbell");
    const details = within(item(table, "doorbell")).getByTestId("move-l2-details");
    expect(details.textContent).toContain("Or join a wireless network that carries VLAN 30: iot.example.test.");
    expect(within(details).queryByTestId("move-l2-diff")).toBeNull();
  });

  it("shows a device that is in the VLAN already, one that moves with another address, and a server without decisions", async () => {
    await serveEdited(["thermostat-1", "plug-kitchen", "cam-door"], (preview) => {
      const [first, second, third] = preview.items as [MoveItem, MoveItem, MoveItem];
      const withoutNetwork = (i: MoveItem) => i.steps.filter((s) => !s.kind.startsWith("l2."));
      first.l2 = { action: "unchanged", reason: "ipam.move.l2.already_there", attachment: { medium: "wireless", device: "d", device_name: "ap-hall", vlan: 30 } };
      first.steps = withoutNetwork(first);
      second.l2 = { action: "shared", reason: "ipam.move.l2.same_interface", with: first.object.id };
      second.steps = withoutNetwork(second);
      // A server that does not know the network step yet: the old step stays and the old text with it.
      delete third.l2;
      third.steps = third.steps.map((s) => (s.kind === "l2.controller" ? { ...s, kind: "l2.move", automatic: false, params: { host: "cam-door" } } : s));
    });
    const { table } = await open("thermostat-1", "plug-kitchen", "cam-door");
    const unchanged = l2Cell(table, "thermostat-1");
    expect(unchanged.dataset.action).toBe("unchanged");
    expect(headline(unchanged)).toBe("In VLAN 30 already");
    const shared = l2Cell(table, "plug-kitchen");
    expect(shared.dataset.action).toBe("shared");
    expect(headline(shared)).toBe("Moves with 192.0.2.41");
    const old = l2Cell(table, "cam-door");
    expect(old.dataset.action).toBeUndefined();
    expect(old.textContent).toBe("Move cam-door to VLAN 30 (switch port or wireless network).");
    // Neither of the first two has a step for the network change.
    for (const name of ["thermostat-1", "plug-kitchen"]) {
      const steps = await openSteps(table, name);
      expect(within(steps).getAllByRole("listitem").map((li) => li.dataset.kind)).not.toContain("l2.move");
      expect(within(item(table, name)).queryByTestId("move-l2-details")).toBeNull();
    }
  });

  it("explains a port profile in the steps: the diff, the notes and the SSID alternative", async () => {
    const { table } = await open("cam-door", "thermostat-1");
    const steps = await openSteps(table, "cam-door");
    const step = within(steps).getAllByRole("listitem").find((li) => li.dataset.kind === "l2.controller");
    expect(step?.dataset.testid).toBe("move-step");
    expect(step?.textContent).toContain("Move cam-door to VLAN 30 through unifi.example.test: dry run, write, read back and compare.");

    const details = within(item(table, "cam-door")).getByTestId("move-l2-details");
    const diff = within(details).getByTestId("move-l2-diff");
    const rows = within(diff).getAllByRole("row");
    expect(rows).toHaveLength(1);
    expect(within(rows[0] as HTMLElement).getByRole("rowheader").textContent).toBe("devices/00:00:5e:00:53:03/ports/7/profile");
    expect(within(rows[0] as HTMLElement).getByRole("cell").textContent).toBe("LAN → IoT");
    expect(within(details).getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      "The device loses its link for a moment while the switch applies the profile.",
    ]);
    expect(details.textContent).toContain("Or join a wireless network that carries VLAN 30: iot.example.test.");

    // The VLAN override of a client has its own diff and note.
    await openSteps(table, "thermostat-1");
    const client = within(item(table, "thermostat-1")).getByTestId("move-l2-details");
    expect(within(client).getByRole("rowheader").textContent).toBe("clients/00:00:5e:00:53:29/network");
    expect(within(client).getByRole("cell").textContent).toBe("LAN → IoT");
    expect(within(client).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["The device moves when it reconnects."]);
  });

  it("says exactly what a person does when the shared port or the SSID decides, in the steps and in the checklist", async () => {
    const { table } = await open("speaker-den", "laptop-ak");
    const speaker = await openSteps(table, "speaker-den");
    const text = "Move the device to VLAN 30 by hand: port 8 of sw-desk also serves 1 other device, and a profile change would move them too.";
    expect(within(speaker).getAllByRole("listitem").find((li) => li.dataset.kind === "l2.move")?.textContent).toContain(text);
    const group = within(screen.getByTestId("move-checklist")).getAllByTestId("move-checklist-group").find((g) => g.dataset.key === "l2.move");
    const tasks = within(group as HTMLElement).getAllByTestId("move-task");
    expect(tasks.map((task) => task.textContent)).toEqual([
      `speaker-den ${text}`,
      "laptop-ak Join the device to the wireless network iot.example.test, which carries VLAN 30; its access point ap-attic does not carry that VLAN.",
    ]);
  });
});

describe("the network controller of a move", () => {
  const summary = () => screen.getByTestId("move-controllers");

  it("names the controller that was read", async () => {
    await open("thermostat-1");
    expect(summary().textContent).toBe("Network controller: unifi.example.test");
    expect(summary().querySelector(".ctl")?.getAttribute("data-writes")).toBe("on");
  });

  it("turns the automatic changes into exact tasks when writes through the controller are off", async () => {
    mockVlanController.writes_enabled = false;
    const { table } = await open("thermostat-1", "cam-door");
    expect(summary().textContent).toBe("Network controller: unifi.example.test (writes off)");
    expect(summary().querySelector(".ctl")?.getAttribute("data-writes")).toBe("off");
    for (const name of ["thermostat-1", "cam-door"]) {
      const cell = l2Cell(table, name);
      expect(cell.dataset.action).toBe("manual");
      expect(cell.dataset.reason).toBe("ipam.move.l2.read_only");
      expect(detail(cell)).toBe("Writes through unifi.example.test are off (TGL-20).");
    }
    const steps = await openSteps(table, "cam-door");
    expect(within(steps).getAllByRole("listitem").map((li) => li.dataset.kind)).toContain("l2.move");
    const group = within(screen.getByTestId("move-checklist")).getAllByTestId("move-checklist-group").find((g) => g.dataset.key === "l2.move");
    expect(within(group as HTMLElement).getAllByTestId("move-task").map((task) => task.textContent)).toEqual([
      "thermostat-1 On unifi.example.test, set the VLAN override of 00:00:5e:00:53:29 to the network IoT (VLAN 30); writes through this connector are off.",
      "cam-door On unifi.example.test, give port 7 of sw-desk the port profile IoT (VLAN 30 untagged); writes through this connector are off.",
    ]);
  });

  it("says so when there is no network controller, and every network change is a task", async () => {
    mockVlanController.present = false;
    const { table } = await open("thermostat-1", "doorbell");
    expect(summary().textContent).toBe("No network controller: every network change is a task for a person.");
    expect(l2Cell(table, "thermostat-1").dataset.reason).toBe("ipam.move.l2.no_controller");
    expect(detail(l2Cell(table, "thermostat-1"))).toBe("No network controller is configured.");
    const group = within(screen.getByTestId("move-checklist")).getAllByTestId("move-checklist-group").find((g) => g.dataset.key === "l2.move");
    expect(within(group as HTMLElement).getAllByTestId("move-task")[0]?.textContent).toBe(
      "thermostat-1 Move the device to VLAN 30: set its switch port to VLAN 30 untagged, or join it to a wireless network that carries VLAN 30.",
    );
  });
});

describe("starting a confirmed plan", () => {
  it("sends the fingerprint of the preview with Start and not with the previews", async () => {
    const sent = capture();
    const view = await open("thermostat-1", "speaker-den");
    const expected = (await previewMove({ objects: refs(["thermostat-1", "speaker-den"]), target: TARGET, parallelism: 2 })).fingerprint;
    expect(expected).toMatch(/^[0-9a-f]{32}$/);
    fireEvent.click(screen.getByTestId("move-start"));
    await waitFor(() => expect(view.location()).toMatch(/^\/jobs\?group=/));
    const started = sent.filter((s) => !s.dryRun);
    expect(started).toHaveLength(1);
    expect(started[0]?.body.expect_fingerprint).toBe(expected);
    const previews = sent.filter((s) => s.dryRun);
    expect(previews.length).toBeGreaterThan(0);
    expect(previews.every((s) => !("expect_fingerprint" in s.body))).toBe(true);
  });

  it("previews again at once when the plan changed before Start, and asks for a new confirmation", async () => {
    const sent = capture();
    const { table, location } = await open("thermostat-1", "cam-door");
    expect(l2Cell(table, "thermostat-1").dataset.action).toBe("client_vlan");
    const moveJobs = () => jobStore.jobs.filter((r) => r.job.spec.kind === "ipam.move").length;
    const jobs = moveJobs();
    // The controller turned read-only after the preview was made.
    mockVlanController.writes_enabled = false;
    const start = screen.getByTestId("move-start") as HTMLButtonElement;
    fireEvent.click(start);

    const notice = await screen.findByTestId("move-plan-changed");
    expect(notice.getAttribute("role")).toBe("status");
    expect(notice.textContent).toContain("The plan changed since this preview. Here is the new one: check it and start again.");
    // The new preview is what the controller allows now; nothing started.
    await waitFor(() => expect(l2Cell(table, "thermostat-1").dataset.action).toBe("manual"));
    await settled(table);
    expect(l2Cell(table, "cam-door").dataset.reason).toBe("ipam.move.l2.read_only");
    expect(screen.getByTestId("move-controllers").textContent).toContain("(writes off)");
    expect(screen.queryByTestId("error-notice")).toBeNull();
    expect(location()).not.toMatch(/^\/jobs/);
    expect(moveJobs()).toBe(jobs);
    await waitFor(() => expect(start.disabled).toBe(false));

    // The second Start confirms the new plan, with a new key.
    fireEvent.click(start);
    await waitFor(() => expect(location()).toMatch(/^\/jobs\?group=ipam\.move\./));
    const started = sent.filter((s) => !s.dryRun);
    expect(started).toHaveLength(2);
    expect(started[1]?.body.expect_fingerprint).toMatch(/^[0-9a-f]{32}$/);
    expect(started[1]?.body.expect_fingerprint).not.toBe(started[0]?.body.expect_fingerprint);
    expect(started[1]?.key).not.toBe(started[0]?.key);
    expect(moveJobs()).toBe(jobs + 2);
  });

  it("clears the notice when the person changes the plan", async () => {
    const { table } = await open("thermostat-1", "cam-door");
    mockVlanController.writes_enabled = false;
    fireEvent.click(screen.getByTestId("move-start"));
    await screen.findByTestId("move-plan-changed");
    await settled(table);
    fireEvent.click(within(item(table, "cam-door")).getByRole("checkbox", { name: "Include cam-door" }));
    await waitFor(() => expect(screen.queryByTestId("move-plan-changed")).toBeNull());
  });

  it("shows any other error of Start as before, without the notice", async () => {
    server.use(
      http.post("/api/v1/moves", ({ request }) => {
        if (new URL(request.url).searchParams.get("dry_run") === "true") return undefined;
        return problem("sys.unavailable", 503);
      }),
    );
    const { table, location } = await open("thermostat-1");
    const start = screen.getByTestId("move-start") as HTMLButtonElement;
    fireEvent.click(start);
    const error = await screen.findByTestId("error-notice");
    expect(error.dataset.code).toBe("sys.unavailable");
    expect(screen.queryByTestId("move-plan-changed")).toBeNull();
    expect(location()).not.toMatch(/^\/jobs/);
    await settled(table);
    expect(start.disabled).toBe(false);
  });
});

describe("the move preview in the steps view", () => {
  it("passes axe with the details of every network change open", async () => {
    const { table } = await open("thermostat-1", "cam-door", "speaker-den", "printer-1", "laptop-ak", "doorbell");
    fireEvent.click(screen.getByTestId("move-show-steps"));
    await waitFor(() => expect(within(table).getAllByTestId("move-steps")).toHaveLength(6));
    expect(within(table).getAllByTestId("move-l2-details").length).toBeGreaterThanOrEqual(3);
    expect(await axeViolations(screen.getByTestId("page-move-preview"))).toEqual([]);
  });

  it("passes axe with the controller off", async () => {
    mockVlanController.present = false;
    const { table } = await open("thermostat-1", "doorbell");
    fireEvent.click(screen.getByTestId("move-show-steps"));
    await waitFor(() => expect(within(table).getAllByTestId("move-steps")).toHaveLength(2));
    expect(await axeViolations(screen.getByTestId("page-move-preview"))).toEqual([]);
  });
});
