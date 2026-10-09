import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it } from "vitest";
import { HOST_IDS, IPAM_IDS, findAddress, ADDRESS_IDS } from "../../api/mock/ipam/api";
import { jobStore } from "../../api/mock/job-store";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { paths } from "../../app/paths";
import MovePreview, { parseObjects } from "./MovePreview";

function url(...hosts: string[]): string {
  return paths.move(
    IPAM_IDS.prefix.iot,
    hosts.map((h) => ({ kind: "host", id: HOST_IDS[h] as string })),
  );
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

beforeEach(async () => {
  await signInAlex();
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
    expect(screen.getByTestId("move-timeout-help").textContent).toMatch(/Lease 1 hr?, so the timeout is 30 min/);
  });

  it("shows the steps of one device with Enter and leaves a device out with Space", async () => {
    const { table } = await open("thermostat-1", "speaker-den");
    const row = within(item(table, "thermostat-1")).getAllByRole("row")[0] as HTMLElement;
    fireEvent.keyDown(row, { key: "Enter" });
    const steps = await within(item(table, "thermostat-1")).findByTestId("move-steps");
    expect(within(steps).getAllByRole("listitem").map((li) => li.dataset.kind)).toEqual([
      "ipam.intent",
      "dhcp.manual",
      "dns.manual",
      "l2.move",
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
    for (const { job } of created) {
      expect(job.spec.title).toBe("ipam.move.title");
      expect(job.spec.steps.map((s) => s.kind)).toEqual([
        "ipam.move.intent",
        "ipam.move.dhcp",
        "ipam.move.dns",
        "ipam.move.l2",
        "ipam.move.observe",
        "ipam.move.cleanup",
      ]);
      expect(job.spec.targets.map((t) => t.kind)).toEqual(["address", "host", "prefix"]);
    }
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
