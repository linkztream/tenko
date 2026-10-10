import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { bridgeMockEvents } from "../audit/testkit";
import { recordEvent } from "../api/mock/db";
import { server } from "../api/mock/node";
import { RECONCILE_IDS, reconcileState } from "../api/mock/reconcile-store";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import HostView from "../hosts/HostView";
import { approveProposal, rejectProposal } from "./api";
import { resetRefs } from "./refs";

const P = RECONCILE_IDS.proposal;

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

function renderHost(name: string) {
  return renderRoute(HostView, {
    url: paths.host(name),
    path: "/ipam/hosts/:fqdn",
    routes: {
      "/discovery/observations/:subject": () => <div data-testid="subject-route" />,
      "/discovery/:id": () => <div data-testid="proposal-route" />,
    },
  });
}

/** Renders the host page and waits until its observation section has answered. */
async function openHost(name: string) {
  const view = renderHost(name);
  await screen.findByTestId("host-modes");
  await within(section()).findByTestId("host-observations-body");
  await waitFor(() => expect(within(section()).queryByText("Loading…")).toBeNull());
  return view;
}

const section = (): HTMLElement => screen.getByTestId("host-observations");
const facts = (): HTMLElement[] => within(section()).queryAllByTestId("fact");
const links = (): HTMLElement[] => within(section()).queryAllByTestId("host-observation-link");

/** The host media-pc of the open proposal, as an approval makes it: with its MAC address and its address. */
async function adoptMediaPc() {
  await approveProposal({ id: P.mediaPc }, { dryRun: false, acknowledge: [] });
}

describe("the observations of a host", () => {
  it("lists what the sources report about the MAC address of the host", async () => {
    await openHost("thermostat-1");
    expect(within(section()).getByRole("heading", { level: 2, name: "Observations" })).toBeTruthy();
    // The host has the MAC address 00:00:5e:00:53:29 and the address 192.0.2.41. The sources
    // report the MAC address, seen at another address, and nothing about 192.0.2.41.
    await waitFor(() => expect(facts()).toHaveLength(2));
    expect(facts().map((f) => f.dataset.key).sort()).toEqual(
      [
        `network_controller:${RECONCILE_IDS.controller}|attachment:00:00:5e:00:53:29`,
        `probe:${RECONCILE_IDS.probeNode}:arp|address:0190d1c2-0000-7000-8000-000000020001/192.0.2.49`,
      ].sort(),
    );
    for (const fact of facts()) expect(fact.dataset.state).toBe("current");
    const observed = facts().map((f) => f.querySelector(".fact-observed")?.textContent);
    expect(observed).toContain("00:00:5e:00:53:29 at ap-garage, wireless network iot, VLAN 30");
    expect(observed).toContain("192.0.2.49 from 00:00:5e:00:53:29");
    await waitFor(() => expect(facts().map((f) => f.querySelector("td")?.textContent)).toContain("Home network (network controller)"));
  });

  it("sums up the newest sighting, the open ports and the operating system", async () => {
    await openHost("thermostat-1");
    const summary = await within(section()).findByTestId("host-observations-summary");
    // The newest fact is the attachment the network controller reports.
    await waitFor(() => expect(summary.textContent).toContain("Home network (network controller)"));
    expect(summary.textContent).toContain("5 minutes ago");
    expect(within(summary).getByTestId("host-open-ports").textContent).toBe("–");
    expect(within(summary).getByTestId("host-os").textContent).toBe("–");
  });

  it("links the facts, and the host, to the picture of each subject", async () => {
    await openHost("thermostat-1");
    await waitFor(() => expect(facts()).toHaveLength(2));
    // One link per subject that has facts: the MAC address, not the address or the name.
    expect(links().map((a) => a.dataset.key)).toEqual(["00:00:5e:00:53:29"]);
    expect(links()[0]?.getAttribute("href")).toBe("/discovery/observations/00:00:5e:00:53:29");
    expect(links()[0]?.textContent).toBe("00:00:5e:00:53:29");
    expect(section().textContent).toContain("Everything the sources report about");

    // Each fact links to the picture of its own subject.
    const attachment = facts().find((f) => f.dataset.key?.includes("attachment"));
    const fact = within(attachment as HTMLElement).getByRole("link");
    expect(fact.getAttribute("href")).toBe("/discovery/observations/00:00:5e:00:53:29");
    const address = facts().find((f) => f.dataset.key?.includes("address:"));
    expect(within(address as HTMLElement).getByRole("link").getAttribute("href")).toBe("/discovery/observations/00:00:5e:00:53:29");
  });

  it("opens the picture of a subject from its link", async () => {
    const view = await openHost("thermostat-1");
    fireEvent.click(await within(section()).findByTestId("host-observation-link"));
    await waitFor(() => expect(view.location()).toBe("/discovery/observations/00:00:5e:00:53:29"));
  });

  it("lists the open proposal about the host and links it to the inbox", async () => {
    await openHost("thermostat-1");
    const list = await within(section()).findByTestId("host-proposals");
    const entries = within(list).getAllByTestId("host-proposal");
    expect(entries).toHaveLength(1);
    expect(entries[0]?.dataset.id).toBe(P.thermostat);
    expect(entries[0]?.textContent).toContain("Address differs");
    const link = within(entries[0] as HTMLElement).getByRole("link", { name: "thermostat-1 is seen at 192.0.2.49, not at its intended 192.0.2.41" });
    expect(link.getAttribute("href")).toBe(`/discovery/${P.thermostat}`);
  });

  it("lists a conflict that names the host, with the facts of the other device", async () => {
    await openHost("printer-1");
    const entry = await within(section()).findByTestId("host-proposal");
    expect(entry.dataset.id).toBe(P.printerTaken);
    expect(entry.textContent).toContain("Conflict");
    expect(entry.textContent).toContain("192.0.2.30 is intended for printer-1 (00:00:5e:00:53:1e) but used by 00:00:5e:00:53:b0");
    // The address of the printer is reported with the MAC address of a different device.
    await waitFor(() => expect(facts()).toHaveLength(1));
    expect(facts()[0]?.querySelector(".fact-observed")?.textContent).toBe("192.0.2.30 from 00:00:5e:00:53:b0");
    expect(links().map((a) => a.dataset.key)).toEqual(["192.0.2.30"]);
  });

  it("shows the ports, the operating systems and every fact of a host that the sources know well", async () => {
    // Approving the proposal makes the host media-pc, with the MAC address and the address the sources report.
    await adoptMediaPc();
    await openHost("media-pc");
    await waitFor(() => expect(facts()).toHaveLength(3));
    const summary = within(section()).getByTestId("host-observations-summary");
    expect(within(summary).getByTestId("host-open-ports").textContent).toBe("22, 8096");
    expect(within(summary).getByTestId("host-os").textContent).toBe("Debian 12 and Linux 6.x (90 %)");
    // The host fact comes in by the MAC address and by the address, and is listed once.
    expect(facts().map((f) => f.querySelector("td:nth-child(2)")?.textContent).sort()).toEqual(["Host", "Open ports", "Operating system"]);
    // The subjects with facts: the MAC address, the address and the name of the host.
    expect(links().map((a) => a.dataset.key)).toEqual(["00:00:5e:00:53:d1", "192.0.2.150", "media-pc"]);
    // The proposal is accepted now, so none is listed.
    expect(within(section()).queryByTestId("host-proposals")).toBeNull();
    await waitFor(() => expect(summary.textContent).toContain("Lab inventory (inventory)"));
  });

  it("says that no source has reported a host nobody sees", async () => {
    await openHost("gw");
    expect(section().textContent).toContain("No source has reported this host yet.");
    expect(facts()).toHaveLength(0);
    expect(links()).toHaveLength(0);
    expect(within(section()).queryByTestId("host-proposals")).toBeNull();
    expect(within(section()).queryByTestId("host-observations-summary")).toBeNull();
  });

  it("leaves the proposals that are decided out", async () => {
    await rejectProposal({ id: P.thermostat }, "not now");
    await openHost("thermostat-1");
    expect(within(section()).queryByTestId("host-proposals")).toBeNull();
    // The facts are still there.
    await waitFor(() => expect(facts()).toHaveLength(2));
  });

  it("shows the error of a failed read and not a half picture", async () => {
    server.use(
      http.get("/api/v1/observations/:subject", () =>
        HttpResponse.json(
          { type: "about:blank", title: "Internal error", status: 500, code: "sys.internal", detail: "", params: {} },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    renderHost("thermostat-1");
    expect(await within(await screen.findByTestId("host-observations")).findByText("The server ran into an internal error. The details are in its log.")).toBeTruthy();
    expect(facts()).toHaveLength(0);
    expect(within(section()).queryByTestId("host-observations-summary")).toBeNull();
    // The rest of the page is there.
    expect(screen.getByTestId("host-modes")).toBeTruthy();
  });
});

describe("live updates", () => {
  it("drops the proposal from the host page when it is decided elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    await openHost("thermostat-1");
    await within(section()).findByTestId("host-proposal");

    await rejectProposal({ id: P.thermostat }, "decided on another screen");

    await waitFor(() => expect(within(section()).queryByTestId("host-proposal")).toBeNull(), { timeout: 4000 });
    expect(facts()).toHaveLength(2);
  });

  it("follows a change of the facts", async () => {
    stopBridge = bridgeMockEvents();
    await openHost("thermostat-1");
    await waitFor(() => expect(facts()).toHaveLength(2));

    // The address fact expires: the sources do not see the thermostat at 192.0.2.49 any more.
    const state = reconcileState();
    const index = state.facts.findIndex((f) => f.observed.type === "address" && f.observed.data.ip === "192.0.2.49");
    const fact = state.facts[index];
    if (!fact) throw new Error("the seed has no such fact");
    state.facts[index] = { ...fact, expires_at: new Date(Date.now() - 1000).toISOString() };
    recordEvent("discovery", { tables: ["ipam.obs.facts"] });

    await waitFor(() => expect(facts().find((f) => f.dataset.key?.includes("address:"))?.dataset.state).toBe("expired"), { timeout: 4000 });
    // The current fact comes first.
    expect(facts()[0]?.dataset.state).toBe("current");
    expect(facts()[1]?.dataset.state).toBe("expired");
  });
});

describe("accessibility", () => {
  it("has no violations with facts and a proposal", async () => {
    await openHost("thermostat-1");
    await waitFor(() => expect(facts()).toHaveLength(2));
    await within(section()).findByTestId("host-proposal");
    expect(await axeViolations(section())).toEqual([]);
  });

  it("has no violations without observations", async () => {
    await openHost("gw");
    expect(await axeViolations(section())).toEqual([]);
  });
});
