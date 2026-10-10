import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { bridgeMockEvents } from "../audit/testkit";
import { CONNECTOR_IDS } from "../api/mock/connectors-store";
import { recordEvent } from "../api/mock/db";
import { HOST_IDS, INTERFACE_IDS } from "../api/mock/ipam/api";
import { server } from "../api/mock/node";
import { RECONCILE_IDS, reconcileState } from "../api/mock/reconcile-store";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { rejectProposal } from "./api";
import { resetRefs } from "./refs";
import SubjectView from "./SubjectView";

const P = RECONCILE_IDS.proposal;
const VRF = "0190d1c2-0000-7000-8000-000000020001";
const INVENTORY = `inventory:${CONNECTOR_IDS.inventory}`;
const CONTROLLER = `network_controller:${CONNECTOR_IDS.controller}`;
const PROBE = `probe:${RECONCILE_IDS.probeNode}`;

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

function renderSubject(subject: string) {
  return renderRoute(SubjectView, {
    url: paths.observation(subject),
    path: "/discovery/observations/:subject",
    routes: {
      "/discovery/observations": () => <div data-testid="observations-route" />,
      "/discovery/:id": () => <div data-testid="proposal-route" />,
      "/ipam/hosts/:fqdn": () => <div data-testid="host-route" />,
    },
  });
}

/** Renders the page of a subject and waits until its picture is there. */
async function openSubject(subject: string) {
  const view = renderSubject(subject);
  await screen.findByTestId("subject-summary");
  return view;
}

const text = (testid: string): string => screen.getByTestId(testid).textContent ?? "";
const facts = (): HTMLElement[] => screen.queryAllByTestId("fact");
const factKeys = (): (string | undefined)[] => facts().map((f) => f.dataset.key);

function card(testid: string): HTMLElement {
  return screen.getByTestId(testid);
}

describe("the picture of a device", () => {
  it("sums up what the sources report about a device by its MAC address", async () => {
    await openSubject("00-00-5E-00-53-D1");
    const page = screen.getByTestId("page-discovery-subject");
    expect(page.dataset.key).toBe("00-00-5E-00-53-D1");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("00-00-5E-00-53-D1");
    // What the subject is, and whether any source sees it now.
    expect(page.textContent).toContain("MAC address · seen now");
    expect(within(screen.getByTestId("discovery-nav")).getByRole("link", { name: "Observations" }).getAttribute("aria-current")).toBe("page");

    const summary = card("subject-summary");
    expect(summary.textContent).toContain("Across sources");
    expect(summary.textContent).toContain("seen now");
    expect(text("subject-names")).toBe("media-pc");
    expect(text("subject-macs")).toBe("00:00:5e:00:53:d1");
    expect(text("subject-ips")).toBe("192.0.2.150");
    expect(text("subject-os")).toBe("Debian 12");
    // The port scan names the address, not the MAC address, so a MAC address does not list ports.
    expect(within(summary).queryByTestId("subject-ports")).toBeNull();
    expect(summary.textContent).toContain("qemu");
    expect(summary.textContent).toContain("pve1");
    expect(summary.textContent).toContain("media");
    await waitFor(() => expect(text("subject-sources")).toBe("Lab inventory (inventory)"));
  });

  it("joins the open ports and the operating systems of every source for an address", async () => {
    await openSubject("192.0.2.150");
    expect(screen.getByTestId("page-discovery-subject").textContent).toContain("IP address · seen now");
    expect(text("subject-names")).toBe("media-pc");
    // The operating system the inventory says and the guess of the fingerprint.
    expect(card("subject-os").querySelectorAll("span")).toHaveLength(2);
    expect(text("subject-os")).toContain("Debian 12");
    expect(text("subject-os")).toContain("Linux 6.x");
    expect([...card("subject-ports").querySelectorAll("span")].map((s) => s.textContent)).toEqual(["22", "8096"]);
    await waitFor(() => expect(text("subject-sources")).toContain("Lab inventory (inventory)"));
    expect(text("subject-sources")).toContain("Probe 1, port scan");
    expect(text("subject-sources")).toContain("Probe 1, OS fingerprint");
    expect(card("subject-facts").textContent).toContain("3 facts");
    expect(factKeys().sort()).toEqual(
      [`${INVENTORY}|host:vm-104`, `${PROBE}:tcp_syn|services:192.0.2.150`, `${PROBE}:os_fingerprint|os:192.0.2.150`].sort(),
    );
  });

  it("looks a device up by name, without regard to case", async () => {
    await openSubject("Media-PC");
    expect(screen.getByTestId("page-discovery-subject").textContent).toContain("Name · seen now");
    expect(text("subject-macs")).toBe("00:00:5e:00:53:d1");
    expect(factKeys()).toEqual([`${INVENTORY}|host:vm-104`]);
  });

  it("says that IPAM knows nothing of a device that is not in it, and lists the open proposal about it", async () => {
    await openSubject("00-00-5E-00-53-D1");
    const intent = card("subject-intent");
    expect(intent.textContent).toContain("IPAM has no host, interface or address for it.");
    expect(within(intent).queryByRole("link")).toBeNull();
    expect(within(intent).queryByTestId("subject-sightings")).toBeNull();

    const proposals = card("subject-proposals");
    const entries = within(proposals).getAllByTestId("subject-proposal");
    expect(entries).toHaveLength(1);
    expect(entries[0]?.dataset.id).toBe(P.mediaPc);
    expect(entries[0]?.textContent).toContain("Discovered host");
    expect(entries[0]?.textContent).toContain("Open");
    const link = within(entries[0] as HTMLElement).getByRole("link", {
      name: "Unknown device 00:00:5e:00:53:d1 (media-pc) seen at 192.0.2.150 by one source; adopt it as host media-pc",
    });
    expect(link.getAttribute("href")).toBe(`/discovery/${P.mediaPc}`);
  });

  it("lists the facts, one row per source and subject, with when they were seen and whether they are current", async () => {
    await openSubject("00-00-5E-00-53-D1");
    const table = within(card("subject-facts")).getByRole("table", { name: "Facts per source" });
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
      "Source",
      "Type",
      "Observed",
      "First seen",
      "Last seen",
      "Sightings",
      "State",
    ]);
    const [fact] = facts();
    expect(facts()).toHaveLength(1);
    expect(fact?.dataset.key).toBe(`${INVENTORY}|host:vm-104`);
    expect(fact?.dataset.state).toBe("current");
    const cells = within(fact as HTMLElement).getAllByRole("cell");
    await waitFor(() => expect(cells[0]?.textContent).toBe("Lab inventory (inventory)"));
    expect(cells[1]?.textContent).toBe("Host");
    expect(cells[2]?.textContent).toBe("media-pc · 00:00:5e:00:53:d1 · 192.0.2.150 · Debian 12 · qemu · on pve1");
    expect(cells[3]?.textContent).toContain("3 days ago");
    expect(cells[4]?.textContent).toContain("10 minutes ago");
    expect(cells[5]?.textContent).toBe("9");
    expect(cells[6]?.textContent).toBe("Current");
    // On the page of the subject itself the facts do not link to it.
    expect(within(fact as HTMLElement).queryByRole("link")).toBeNull();
  });

  it("links the host and the interface that IPAM has for a device and shows when each was last seen", async () => {
    await openSubject("00:00:5e:00:53:29");
    expect(text("subject-macs")).toBe("00:00:5e:00:53:29");
    expect(text("subject-ips")).toBe("192.0.2.49");

    const intent = card("subject-intent");
    expect(intent.textContent).not.toContain("IPAM has no host");
    const host = await within(intent).findByRole("link", { name: "thermostat-1" });
    expect(host.getAttribute("href")).toBe("/ipam/hosts/thermostat-1");
    const sightings = within(intent).getByTestId("subject-sightings");
    const refs = [...intent.querySelectorAll<HTMLElement>(".obj-ref")].filter((r) => !sightings.contains(r));
    expect(refs.map((r) => r.dataset.kind)).toEqual(["host", "interface"]);
    expect(refs.map((r) => r.dataset.id)).toEqual([HOST_IDS["thermostat-1"], INTERFACE_IDS["thermostat-1"]]);
    // The interface is listed as intent and again with its last sighting; both link to its host.
    const interfaces = await within(intent).findAllByRole("link", { name: "thermostat-1 eth0" });
    expect(interfaces).toHaveLength(2);

    // The last sighting of the interface: the newest fact that names its MAC address.
    expect(within(intent).getByRole("heading", { name: "Last sightings of intent" })).toBeTruthy();
    expect(sightings.querySelector<HTMLElement>(".obj-ref")?.dataset.kind).toBe("interface");
    expect(sightings.querySelectorAll("li")).toHaveLength(1);
    expect(sightings.textContent).toContain("minutes ago");
    await waitFor(() => expect(sightings.textContent).toContain("Home network (network controller)"));
  });

  it("shows where a device is attached", async () => {
    await openSubject("00:00:5e:00:53:29");
    const attached = card("subject-attachments");
    expect(attached.textContent).toContain("00:00:5e:00:53:29");
    expect(attached.textContent).toContain("ap-garage, wireless network iot");
    expect(attached.textContent).toContain("VLAN 30");
    await waitFor(() => expect(attached.textContent).toContain("Home network (network controller)"));
    expect(card("subject-summary").textContent).toContain("Attached at");
  });

  it("has no list of attachments for a device that no controller reports", async () => {
    await openSubject("00-00-5E-00-53-D1");
    expect(screen.queryByTestId("subject-attachments")).toBeNull();
    expect(card("subject-summary").textContent).not.toContain("Attached at");
  });

  it("lists the proposal about a difference and links it to the inbox", async () => {
    await openSubject("00:00:5e:00:53:29");
    const entry = within(card("subject-proposals")).getByTestId("subject-proposal");
    expect(entry.dataset.id).toBe(P.thermostat);
    expect(entry.textContent).toContain("Address differs");
    expect(within(entry).getByRole("link", { name: "thermostat-1 is seen at 192.0.2.49, not at its intended 192.0.2.41" }).getAttribute("href")).toBe(`/discovery/${P.thermostat}`);

    // The facts of both sources are listed, the current ones first.
    expect(factKeys().sort()).toEqual([`${CONTROLLER}|attachment:00:00:5e:00:53:29`, `${PROBE}:arp|address:${VRF}/192.0.2.49`].sort());
    expect(card("subject-facts").textContent).toContain("2 facts");
  });

  it("follows the link of a proposal", async () => {
    const view = await openSubject("00:00:5e:00:53:29");
    fireEvent.click(within(card("subject-proposals")).getByRole("link"));
    await waitFor(() => expect(view.location()).toBe(`/discovery/${P.thermostat}`));
  });

  it("shows a device that nothing reports now as not seen recently, with its expired facts", async () => {
    await openSubject("00:00:5e:00:53:c4");
    expect(screen.getByTestId("page-discovery-subject").textContent).toContain("MAC address · not seen recently");
    expect(card("subject-summary").textContent).toContain("not seen recently");
    expect(text("subject-names")).toBe("old-test");
    const [fact] = facts();
    expect(fact?.dataset.state).toBe("expired");
    expect(within(fact as HTMLElement).getByText("Expired")).toBeTruthy();
    // The proposal that expired with it is still listed, in words.
    const entry = within(card("subject-proposals")).getByTestId("subject-proposal");
    expect(entry.dataset.id).toBe(P.oldTest);
    expect(entry.textContent).toContain("Expired");
  });
});

describe("a subject that no source reported", () => {
  it("says so and offers the way back to the observations", async () => {
    renderSubject("00:00:5e:00:53:ee");
    const notice = await screen.findByTestId("subject-unknown");
    expect(notice.textContent).toBe("No source has reported 00:00:5e:00:53:ee.");
    expect(screen.queryByTestId("subject-summary")).toBeNull();
    expect(screen.queryByTestId("subject-intent")).toBeNull();
    expect(screen.queryByTestId("subject-facts")).toBeNull();
    // Nothing is said about proposals when there is none to list.
    expect(screen.queryByTestId("subject-proposals")).toBeNull();
    const back = within(screen.getByRole("heading", { level: 1 }).closest(".page-head") as HTMLElement).getByRole("link", { name: "Observations" });
    expect(back.getAttribute("href")).toBe("/discovery/observations");
    expect(screen.getByTestId("page-discovery-subject").textContent).toContain("MAC address");
  });

  it("still lists a proposal about it, as one that is decided", async () => {
    // The speaker was adopted: its proposal has no evidence left and no source reports it now.
    renderSubject("00:00:5e:00:53:2c");
    expect(await screen.findByTestId("subject-unknown")).toBeTruthy();
    const entry = within(await screen.findByTestId("subject-proposals")).getByTestId("subject-proposal");
    expect(entry.dataset.id).toBe(P.speaker);
    expect(entry.textContent).toContain("Accepted");
  });

  it("reads an address and a name the same way", async () => {
    renderSubject("203.0.113.99");
    expect((await screen.findByTestId("subject-unknown")).textContent).toBe("No source has reported 203.0.113.99.");
    expect(screen.getByTestId("page-discovery-subject").textContent).toContain("IP address");
  });

  it("names a subject that is neither", async () => {
    renderSubject("no-such-device");
    expect((await screen.findByTestId("subject-unknown")).textContent).toBe("No source has reported no-such-device.");
    expect(screen.getByTestId("page-discovery-subject").textContent).toContain("Name");
  });
});

describe("a failed read", () => {
  it("shows the error and not a picture", async () => {
    server.use(
      http.get("/api/v1/observations/:subject", () =>
        HttpResponse.json(
          { type: "about:blank", title: "Internal error", status: 500, code: "sys.internal", detail: "", params: {} },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    renderSubject("00:00:5e:00:53:d1");
    expect(await screen.findByText("The server ran into an internal error. The details are in its log.")).toBeTruthy();
    expect(screen.queryByTestId("subject-summary")).toBeNull();
    expect(screen.queryByTestId("subject-unknown")).toBeNull();
    // The page still names what it is about.
    expect(screen.getByTestId("page-discovery-subject").dataset.key).toBe("00:00:5e:00:53:d1");
  });
});

describe("live updates", () => {
  it("follows a change of the facts", async () => {
    stopBridge = bridgeMockEvents();
    await openSubject("192.0.2.150");
    expect(text("subject-os")).toContain("Linux 6.x");

    const state = reconcileState();
    const index = state.facts.findIndex((f) => f.observed.type === "os");
    const fact = state.facts[index];
    if (!fact || fact.observed.type !== "os") throw new Error("the seed has no fingerprint");
    state.facts[index] = { ...fact, observed: { type: "os", data: { ...fact.observed.data, guess: "Linux 6.8" } } };
    recordEvent("discovery", { tables: ["ipam.obs.facts"] });

    await waitFor(() => expect(text("subject-os")).toContain("Linux 6.8"), { timeout: 4000 });
    expect(text("subject-os")).not.toContain("Linux 6.x");
  });

  it("follows the decision of a proposal about the subject", async () => {
    stopBridge = bridgeMockEvents();
    await openSubject("00-00-5E-00-53-D1");
    expect(within(card("subject-proposals")).getByTestId("subject-proposal").textContent).toContain("Open");

    await rejectProposal({ id: P.mediaPc }, "decided elsewhere");

    await waitFor(() => expect(within(card("subject-proposals")).getByTestId("subject-proposal").textContent).toContain("Rejected"), { timeout: 4000 });
  });
});

describe("accessibility", () => {
  it("has no violations for a device with intent, attachments and a proposal", async () => {
    const view = await openSubject("00:00:5e:00:53:29");
    await waitFor(() => expect(card("subject-sightings").textContent).toContain("Home network (network controller)"));
    await within(card("subject-intent")).findByRole("link", { name: "thermostat-1" });
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("has no violations for a device that IPAM does not know", async () => {
    const view = await openSubject("192.0.2.150");
    await waitFor(() => expect(text("subject-sources")).toContain("Lab inventory (inventory)"));
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("has no violations for a subject nobody reported", async () => {
    const view = renderSubject("00:00:5e:00:53:ee");
    await screen.findByTestId("subject-unknown");
    expect(await axeViolations(view.container)).toEqual([]);
  });
});
