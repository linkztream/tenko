import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { bridgeMockEvents } from "../audit/testkit";
import { CONNECTOR_IDS } from "../api/mock/connectors-store";
import { recordEvent } from "../api/mock/db";
import { RECONCILE_IDS, reconcileState } from "../api/mock/reconcile-store";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import ObservationsView from "./ObservationsView";
import { resetRefs } from "./refs";
import SubjectView from "./SubjectView";

const INVENTORY = `inventory:${CONNECTOR_IDS.inventory}`;
const CONTROLLER = `network_controller:${CONNECTOR_IDS.controller}`;
const PROBE = `probe:${RECONCILE_IDS.probeNode}`;

/** The id of a fact row: its source key and subject key. */
const MEDIA_PC = `${INVENTORY}|host:vm-104`;
const MEDIA_SERVICES = `${PROBE}:tcp_syn|services:192.0.2.150`;
const MEDIA_OS = `${PROBE}:os_fingerprint|os:192.0.2.150`;
const HALL_CLIENT = `${CONTROLLER}|attachment:00:00:5e:00:53:d2`;
const IOT_ADDRESS = `${PROBE}:icmp|address:0190d1c2-0000-7000-8000-000000020001/198.51.100.77`;
const THERMOSTAT_SEEN = `${PROBE}:arp|address:0190d1c2-0000-7000-8000-000000020001/192.0.2.49`;
const THERMOSTAT_ATTACHED = `${CONTROLLER}|attachment:00:00:5e:00:53:29`;
const OUTSIDE = `${PROBE}:arp|address:0190d1c2-0000-7000-8000-000000020001/203.0.113.230`;
const PRINTER_TAKEN = `${PROBE}:arp|address:0190d1c2-0000-7000-8000-000000020001/192.0.2.30`;
const GUEST_PHONE = `${CONTROLLER}|attachment:00:00:5e:00:53:c3`;
const OLD_TEST = `${INVENTORY}|host:vm-200`;
/** What a probe found for an address (reverse DNS), and the vendor of a MAC address (ARP). */
const SPEAKER_NAME = `${PROBE}:reverse_dns|name:192.0.2.44`;
const OUTSIDE_VENDOR = `${PROBE}:arp|vendor:00:00:5e:00:53:d5`;

/** The twelve facts that are current in the seed. */
const CURRENT = [
  MEDIA_PC,
  MEDIA_SERVICES,
  MEDIA_OS,
  HALL_CLIENT,
  IOT_ADDRESS,
  THERMOSTAT_SEEN,
  THERMOSTAT_ATTACHED,
  OUTSIDE,
  PRINTER_TAKEN,
  GUEST_PHONE,
  SPEAKER_NAME,
  OUTSIDE_VENDOR,
];

let stopBridge: (() => void) | undefined;

beforeEach(async () => {
  resetRefs();
  await signInAlex();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  setSessionForTest(null);
});

function renderObservations(url: string = paths.observations()) {
  return renderRoute(ObservationsView, {
    url,
    path: "/discovery/observations",
    routes: { "/discovery/observations/:subject": SubjectView },
  });
}

const rows = (): HTMLElement[] => screen.queryAllByTestId("row");
const rowIds = (): (string | undefined)[] => rows().map((r) => r.dataset.id);
const sortedIds = (): (string | undefined)[] => [...rowIds()].sort();

function rowOf(id: string): HTMLElement {
  const row = rows().find((r) => r.dataset.id === id);
  if (!row) throw new Error(`no row for fact ${id}`);
  return row;
}

function cell(row: HTMLElement, column: string): string {
  return row.querySelector(`[data-col='${column}']`)?.textContent ?? "";
}

async function listed(count: number) {
  await waitFor(() => expect(rows()).toHaveLength(count));
}

async function openObservations(url: string = paths.observations(), count = CURRENT.length) {
  const view = renderObservations(url);
  await listed(count);
  return view;
}

describe("the observations", () => {
  it("lists the current facts, newest sighting first, and leaves out the expired ones", async () => {
    await openObservations();
    expect(sortedIds()).toEqual([...CURRENT].sort());
    expect(rowIds()).not.toContain(OLD_TEST);
    expect(screen.getByTestId("page-discovery-observations")).toBeTruthy();
    expect(screen.getByTestId("grid-observations")).toBeTruthy();
    // The newest sightings come first; the oldest (40 minutes ago) come last.
    expect(rowIds().slice(0, 2).sort()).toEqual([HALL_CLIENT, THERMOSTAT_ATTACHED].sort());
    expect(rowIds().slice(-2).sort()).toEqual([MEDIA_OS, MEDIA_SERVICES].sort());
    for (const row of rows()) expect(cell(row, "state")).toBe("Current");
    // Current is the pressed chip.
    expect(screen.getByTestId("filter-current-current").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("filter-current-expired").getAttribute("aria-pressed")).toBe("false");
  });

  it("says in words what each source reported", async () => {
    await openObservations();
    const observed = (id: string) => cell(rowOf(id), "observed");
    expect(observed(MEDIA_PC)).toBe("media-pc · 00:00:5e:00:53:d1 · 192.0.2.150 · Debian 12 · qemu · on pve1");
    expect(observed(MEDIA_SERVICES)).toBe("192.0.2.150: TCP 22, 8096");
    expect(observed(MEDIA_OS)).toBe("192.0.2.150: Linux 6.x, 90 %");
    expect(observed(HALL_CLIENT)).toBe("00:00:5e:00:53:d2 at switch-hall, port 7, VLAN 10");
    expect(observed(THERMOSTAT_ATTACHED)).toBe("00:00:5e:00:53:29 at ap-garage, wireless network iot, VLAN 30");
    expect(observed(THERMOSTAT_SEEN)).toBe("192.0.2.49 from 00:00:5e:00:53:29");
    // An address without a MAC address is just the address.
    expect(observed(IOT_ADDRESS)).toBe("198.51.100.77");
    // A name a probe found for an address, and the vendor of a MAC address.
    expect(observed(SPEAKER_NAME)).toBe("192.0.2.44 is called speaker-den.example.test");
    expect(observed(OUTSIDE_VENDOR)).toBe("00:00:5e:00:53:d5 is made by ICANN, IANA Department");

    expect(cell(rowOf(MEDIA_PC), "type")).toBe("Host");
    expect(cell(rowOf(MEDIA_SERVICES), "type")).toBe("Open ports");
    expect(cell(rowOf(MEDIA_OS), "type")).toBe("Operating system");
    expect(cell(rowOf(HALL_CLIENT), "type")).toBe("Attachment");
    expect(cell(rowOf(IOT_ADDRESS), "type")).toBe("Address");
    expect(cell(rowOf(SPEAKER_NAME), "type")).toBe("Name");
    expect(cell(rowOf(OUTSIDE_VENDOR), "type")).toBe("Vendor");
    expect(cell(rowOf(MEDIA_PC), "sightings")).toBe("9");
    expect(cell(rowOf(THERMOSTAT_ATTACHED), "sightings")).toBe("40");
  });

  it("names the source of each fact by its connector or probe", async () => {
    await openObservations();
    await waitFor(() => expect(cell(rowOf(MEDIA_PC), "source")).toBe("Lab inventory (inventory)"));
    expect(cell(rowOf(HALL_CLIENT), "source")).toBe("Home network (network controller)");
    // The probe node of the seed is not in the node list, so its number stands in.
    expect(cell(rowOf(MEDIA_SERVICES), "source")).toBe("Probe 1, port scan");
    expect(cell(rowOf(MEDIA_OS), "source")).toBe("Probe 1, OS fingerprint");
    expect(cell(rowOf(THERMOSTAT_SEEN), "source")).toBe("Probe 1, ARP");
    expect(cell(rowOf(IOT_ADDRESS), "source")).toBe("Probe 1, ping");
    expect(cell(rowOf(SPEAKER_NAME), "source")).toBe("Probe 1, reverse DNS");
    expect(cell(rowOf(OUTSIDE_VENDOR), "source")).toBe("Probe 1, ARP");
  });

  it("filters by the type of the fact with chips that keep the URL up to date", async () => {
    const view = await openObservations();
    const chip = (type: string) => screen.getByTestId(`filter-type-${type}`);

    fireEvent.click(chip("attachment"));
    await waitFor(() => expect(sortedIds()).toEqual([HALL_CLIENT, THERMOSTAT_ATTACHED, GUEST_PHONE].sort()));
    expect(chip("attachment").getAttribute("aria-pressed")).toBe("true");
    expect(view.location()).toBe("/discovery/observations?type=attachment");

    // One type at a time: another chip replaces the first.
    fireEvent.click(chip("address"));
    await waitFor(() => expect(sortedIds()).toEqual([IOT_ADDRESS, THERMOSTAT_SEEN, OUTSIDE, PRINTER_TAKEN].sort()));
    expect(chip("attachment").getAttribute("aria-pressed")).toBe("false");

    fireEvent.click(chip("host"));
    await waitFor(() => expect(rowIds()).toEqual([MEDIA_PC]));
    fireEvent.click(chip("services"));
    await waitFor(() => expect(rowIds()).toEqual([MEDIA_SERVICES]));
    fireEvent.click(chip("os"));
    await waitFor(() => expect(rowIds()).toEqual([MEDIA_OS]));

    // A name and a vendor are facts of their own, not sightings of an address.
    fireEvent.click(chip("name"));
    await waitFor(() => expect(rowIds()).toEqual([SPEAKER_NAME]));
    expect(chip("name").getAttribute("aria-pressed")).toBe("true");
    expect(chip("os").getAttribute("aria-pressed")).toBe("false");
    expect(view.location()).toBe("/discovery/observations?type=name");
    fireEvent.click(chip("vendor"));
    await waitFor(() => expect(rowIds()).toEqual([OUTSIDE_VENDOR]));
    expect(chip("name").getAttribute("aria-pressed")).toBe("false");
    expect(view.location()).toBe("/discovery/observations?type=vendor");
    fireEvent.click(chip("os"));
    await waitFor(() => expect(rowIds()).toEqual([MEDIA_OS]));

    // No link is reported: the list says so, and says why only when nothing is narrowed.
    fireEvent.click(chip("link"));
    await waitFor(() => expect(screen.getByTestId("observations-empty")).toBeTruthy());
    expect(screen.getByTestId("observations-empty").textContent).toContain("No observation matches");
    expect(screen.getByTestId("observations-empty").textContent).not.toContain("Connectors and probes report what they see");

    // The same chip again takes the filter away.
    fireEvent.click(chip("link"));
    await listed(CURRENT.length);
    expect(view.location()).toBe("/discovery/observations");
  });

  it("takes the type from the URL", async () => {
    await openObservations("/discovery/observations?type=services", 1);
    expect(rowIds()).toEqual([MEDIA_SERVICES]);
    expect(screen.getByTestId("filter-type-services").getAttribute("aria-pressed")).toBe("true");
  });

  it("offers a chip for every type of fact, the name and the vendor among them", async () => {
    await openObservations();
    expect(screen.getAllByTestId(/^filter-type-/).map((chip) => [chip.dataset.testid, chip.textContent])).toEqual([
      ["filter-type-host", "Host"],
      ["filter-type-address", "Address"],
      ["filter-type-attachment", "Attachment"],
      ["filter-type-services", "Open ports"],
      ["filter-type-os", "Operating system"],
      ["filter-type-link", "Link"],
      ["filter-type-name", "Name"],
      ["filter-type-vendor", "Vendor"],
    ]);
  });

  it("takes the name and the vendor as the type from the URL", async () => {
    const view = await openObservations("/discovery/observations?type=name", 1);
    expect(rowIds()).toEqual([SPEAKER_NAME]);
    expect(screen.getByTestId("filter-type-name").getAttribute("aria-pressed")).toBe("true");
    view.history.set({ value: "/discovery/observations?type=vendor" });
    await waitFor(() => expect(rowIds()).toEqual([OUTSIDE_VENDOR]));
    expect(screen.getByTestId("filter-type-vendor").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("filter-type-name").getAttribute("aria-pressed")).toBe("false");
  });

  it("shows the expired facts, or all of them, on request", async () => {
    const view = await openObservations();
    fireEvent.click(screen.getByTestId("filter-current-expired"));
    await waitFor(() => expect(rowIds()).toEqual([OLD_TEST]));
    expect(view.location()).toBe("/discovery/observations?current=expired");
    expect(cell(rowOf(OLD_TEST), "state")).toBe("Expired");
    expect(cell(rowOf(OLD_TEST), "observed")).toBe("old-test · 00:00:5e:00:53:c4 · lxc");
    expect(screen.getByTestId("filter-current-expired").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("filter-current-current").getAttribute("aria-pressed")).toBe("false");

    fireEvent.click(screen.getByTestId("filter-current-all"));
    await listed(CURRENT.length + 1);
    expect(rowIds()).toContain(OLD_TEST);
    expect(view.location()).toBe("/discovery/observations?current=all");

    fireEvent.click(screen.getByTestId("filter-current-current"));
    await listed(CURRENT.length);
    expect(view.location()).toBe("/discovery/observations");
  });

  it("filters by text over the subject, the name, the operating system, the tags and the device", async () => {
    const view = await openObservations();
    const type = (value: string) => fireEvent.input(screen.getByTestId("filter-input"), { target: { value } });

    type("media");
    // Not at once: the field waits for the typing to pause.
    expect(rows()).toHaveLength(CURRENT.length);
    await waitFor(() => expect(rowIds()).toEqual([MEDIA_PC]));
    expect(view.location()).toBe("/discovery/observations?q=media");

    type("ap-garage");
    await waitFor(() => expect(rowIds()).toEqual([THERMOSTAT_ATTACHED]));
    type("linux");
    await waitFor(() => expect(rowIds()).toEqual([MEDIA_OS]));
    // The text of a name and of a vendor is searched too.
    type("example.test");
    await waitFor(() => expect(rowIds()).toEqual([SPEAKER_NAME]));
    type("icann");
    await waitFor(() => expect(rowIds()).toEqual([OUTSIDE_VENDOR]));
    type("no such text");
    await waitFor(() => expect(rows()).toHaveLength(0));
    expect(screen.getByTestId("observations-empty").textContent).toContain("No observation matches");

    fireEvent.keyDown(screen.getByTestId("filter-input"), { key: "Escape" });
    await listed(CURRENT.length);
    expect(view.location()).toBe("/discovery/observations");
  });

  it("starts from the text of the URL", async () => {
    await openObservations("/discovery/observations?q=ap-garage", 1);
    expect((screen.getByTestId("filter-input") as HTMLInputElement).value).toBe("ap-garage");
  });

  it("explains an empty list when no source has reported anything", async () => {
    reconcileState().facts.splice(0);
    renderObservations();
    const empty = await screen.findByTestId("observations-empty");
    expect(empty.textContent).toContain("No observation matches");
    expect(empty.textContent).toContain("Connectors and probes report what they see; their facts appear here.");
  });
});

describe("the filters of the URL", () => {
  it("shows the connector a link from its page names, and the chip removes the filter", async () => {
    const view = await openObservations(`/discovery/observations?source=${CONNECTOR_IDS.inventory}`, 1);
    expect(rowIds()).toEqual([MEDIA_PC]);
    // The name arrives with the list of connectors; the chip is drawn again when it does.
    await waitFor(() => expect(screen.getByTestId("filter-source").textContent).toContain("Lab inventory"));
    const chip = screen.getByTestId("filter-source");
    expect(chip.textContent).not.toContain(CONNECTOR_IDS.inventory);

    fireEvent.click(within(chip).getByRole("button", { name: "Remove the filter Lab inventory" }));
    await listed(CURRENT.length);
    expect(screen.queryByTestId("filter-source")).toBeNull();
    expect(view.location()).toBe("/discovery/observations");
  });

  it("matches a connector with both of its sources", async () => {
    await openObservations(`/discovery/observations?source=${CONNECTOR_IDS.controller}`, 3);
    expect(sortedIds()).toEqual([HALL_CLIENT, THERMOSTAT_ATTACHED, GUEST_PHONE].sort());
    await waitFor(() => expect(screen.getByTestId("filter-source").textContent).toContain("Home network"));
  });

  it("names a source key in words", async () => {
    await openObservations(`/discovery/observations?source=${encodeURIComponent(`${PROBE}:arp`)}`, 4);
    expect(sortedIds()).toEqual([THERMOSTAT_SEEN, OUTSIDE, PRINTER_TAKEN, OUTSIDE_VENDOR].sort());
    expect(screen.getByTestId("filter-source").textContent).toContain("Probe 1, ARP");
  });

  it("narrows to a MAC address, an address or a network and shows each as a chip", async () => {
    const view = await openObservations("/discovery/observations?mac=00:00:5e:00:53:29", 2);
    expect(sortedIds()).toEqual([THERMOSTAT_SEEN, THERMOSTAT_ATTACHED].sort());
    expect(screen.getByTestId("filter-mac").textContent).toContain("00:00:5e:00:53:29");

    view.history.set({ value: "/discovery/observations?ip=192.0.2.150" });
    await waitFor(() => expect(sortedIds()).toEqual([MEDIA_PC, MEDIA_SERVICES, MEDIA_OS].sort()));
    expect(screen.getByTestId("filter-ip").textContent).toContain("192.0.2.150");

    // A name names its address, and a vendor its MAC address.
    view.history.set({ value: "/discovery/observations?ip=192.0.2.44" });
    await waitFor(() => expect(rowIds()).toEqual([SPEAKER_NAME]));
    view.history.set({ value: "/discovery/observations?mac=00:00:5e:00:53:d5" });
    await waitFor(() => expect(sortedIds()).toEqual([OUTSIDE, OUTSIDE_VENDOR].sort()));

    view.history.set({ value: "/discovery/observations?within=203.0.113.0/24" });
    await waitFor(() => expect(rowIds()).toEqual([OUTSIDE]));
    fireEvent.click(within(screen.getByTestId("filter-within")).getByRole("button"));
    await listed(CURRENT.length);
  });
});

describe("opening a subject", () => {
  it("opens the picture of the device of a fact when its row is clicked", async () => {
    const view = await openObservations();
    fireEvent.click(rowOf(MEDIA_PC).querySelector("[data-col='type']") as HTMLElement);
    await waitFor(() => expect(view.location()).toBe("/discovery/observations/00:00:5e:00:53:d1"));
    const page = await screen.findByTestId("page-discovery-subject");
    expect(page.dataset.key).toBe("00:00:5e:00:53:d1");
  });

  it("opens the address of a fact that names no MAC address, and the MAC address of an attachment", async () => {
    const view = await openObservations();
    fireEvent.click(rowOf(IOT_ADDRESS).querySelector("[data-col='state']") as HTMLElement);
    await waitFor(() => expect(view.location()).toBe("/discovery/observations/198.51.100.77"));
    expect((await screen.findByTestId("page-discovery-subject")).dataset.key).toBe("198.51.100.77");

    view.history.set({ value: "/discovery/observations" });
    await listed(CURRENT.length);
    fireEvent.click(rowOf(HALL_CLIENT).querySelector("[data-col='sightings']") as HTMLElement);
    await waitFor(() => expect(view.location()).toBe("/discovery/observations/00:00:5e:00:53:d2"));
  });

  it("opens the address of a name and the MAC address of a vendor", async () => {
    const view = await openObservations();
    fireEvent.click(rowOf(SPEAKER_NAME).querySelector("[data-col='type']") as HTMLElement);
    await waitFor(() => expect(view.location()).toBe("/discovery/observations/192.0.2.44"));
    expect((await screen.findByTestId("page-discovery-subject")).dataset.key).toBe("192.0.2.44");
    expect((await screen.findByTestId("subject-names")).textContent).toBe("speaker-den.example.test");

    view.history.set({ value: "/discovery/observations" });
    await listed(CURRENT.length);
    fireEvent.click(rowOf(OUTSIDE_VENDOR).querySelector("[data-col='type']") as HTMLElement);
    await waitFor(() => expect(view.location()).toBe("/discovery/observations/00:00:5e:00:53:d5"));
    expect((await screen.findByTestId("subject-vendors")).textContent).toBe("ICANN, IANA Department");
  });

  it("opens the picture of the service of an address by that address", async () => {
    const view = await openObservations();
    fireEvent.click(rowOf(MEDIA_SERVICES).querySelector("[data-col='type']") as HTMLElement);
    await waitFor(() => expect(view.location()).toBe("/discovery/observations/192.0.2.150"));
  });

  it("opens the focused fact with Enter", async () => {
    const view = await openObservations();
    const grid = screen.getByRole("grid", { name: "Observations" });
    fireEvent.focus(grid);
    // The focus starts on the newest fact.
    const first = rows()[0]?.dataset.id;
    fireEvent.keyDown(grid, { key: "Enter" });
    const expected = first === HALL_CLIENT ? "00:00:5e:00:53:d2" : "00:00:5e:00:53:29";
    await waitFor(() => expect(view.location()).toBe(`/discovery/observations/${expected}`));
  });

  it("looks up any MAC address, address or name from the lookup field", async () => {
    const view = await openObservations();
    const form = screen.getByTestId("discovery-lookup");
    const field = within(form).getByTestId("field-subject") as HTMLInputElement;
    const submit = within(form).getByTestId("form-submit") as HTMLButtonElement;
    expect(field.value).toBe("");
    // Nothing to look up yet.
    expect(submit.disabled).toBe(true);
    fireEvent.submit(form);
    expect(view.location()).toBe("/discovery/observations");

    fireEvent.input(field, { target: { value: "   " } });
    expect(submit.disabled).toBe(true);

    fireEvent.input(field, { target: { value: "  00-00-5E-00-53-D1 " } });
    expect(submit.disabled).toBe(false);
    fireEvent.click(submit);
    await waitFor(() => expect(view.location()).toBe("/discovery/observations/00-00-5E-00-53-D1"));
    const page = await screen.findByTestId("page-discovery-subject");
    expect(page.dataset.key).toBe("00-00-5E-00-53-D1");
    expect((await screen.findByTestId("subject-names")).textContent).toBe("media-pc");
  });

  it("looks up a name", async () => {
    const view = await openObservations();
    fireEvent.input(screen.getByTestId("field-subject"), { target: { value: "media-pc" } });
    fireEvent.submit(screen.getByTestId("discovery-lookup"));
    await waitFor(() => expect(view.location()).toBe("/discovery/observations/media-pc"));
  });
});

describe("live updates", () => {
  it("drops a fact from the current list when it expires", async () => {
    stopBridge = bridgeMockEvents();
    await openObservations();
    // The services fact of media-pc expires; the server tells the discovery topic.
    const facts = reconcileState().facts;
    const index = facts.findIndex((f) => `${f.source_key}|${f.subject_key}` === MEDIA_SERVICES);
    const fact = facts[index];
    if (!fact) throw new Error("the seed has no services fact");
    facts[index] = { ...fact, expires_at: new Date(Date.now() - 1000).toISOString() };
    recordEvent("discovery", { tables: ["ipam.obs.facts"] });

    await waitFor(() => expect(rowIds()).not.toContain(MEDIA_SERVICES), { timeout: 4000 });
    expect(rows()).toHaveLength(CURRENT.length - 1);
  });
});

describe("accessibility", () => {
  it("has no violations", async () => {
    const view = await openObservations();
    await waitFor(() => expect(cell(rowOf(MEDIA_PC), "source")).toBe("Lab inventory (inventory)"));
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("has no violations with filters applied", async () => {
    const view = await openObservations(`/discovery/observations?source=${CONNECTOR_IDS.inventory}&current=all&type=host`, 2);
    await waitFor(() => expect(screen.getByTestId("filter-source").textContent).toContain("Lab inventory"));
    expect(await axeViolations(view.container)).toEqual([]);
  });
});
