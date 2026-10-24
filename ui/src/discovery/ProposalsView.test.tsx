import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ANY_REVISION, api } from "../api/client";
import { bridgeMockEvents } from "../audit/testkit";
import { CONNECTOR_IDS } from "../api/mock/connectors-store";
import { ADDRESS_IDS, HOST_IDS, IPAM_IDS, ipamState } from "../api/mock/ipam/api";
import { server } from "../api/mock/node";
import { RECONCILE_IDS, REASON_GONE, reconcileState } from "../api/mock/reconcile-store";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { confirmPlan, recordWrites } from "../ipam/testkit";
import { rejectProposal } from "./api";
import ProposalsView from "./ProposalsView";
import { resetRefs } from "./refs";

const P = RECONCILE_IDS.proposal;

/** The open proposals of the seed, newest first (the order of `-created`). */
const OPEN_NEWEST_FIRST = [P.printerTaken, P.outside, P.thermostat, P.iotAddress, P.hallSwitchClient, P.mediaPc];

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

function renderInbox(url: string = paths.discovery()) {
  return renderRoute(ProposalsView, {
    url,
    path: "/discovery/:id?",
    routes: { "/discovery/observations/:subject": () => <div data-testid="subject-route" /> },
  });
}

const rows = (): HTMLElement[] => screen.queryAllByTestId("row");
const rowIds = (): (string | undefined)[] => rows().map((r) => r.dataset.id);

function rowOf(id: string): HTMLElement {
  const row = rows().find((r) => r.dataset.id === id);
  if (!row) throw new Error(`no row for proposal ${id}`);
  return row;
}

function cell(row: HTMLElement, column: string): string {
  return row.querySelector(`[data-col='${column}']`)?.textContent ?? "";
}

async function listed(count: number) {
  await waitFor(() => expect(rows()).toHaveLength(count));
}

/** Renders the inbox and waits until `count` proposals are listed. */
async function openInbox(url: string = paths.discovery(), count = 6) {
  const view = renderInbox(url);
  await listed(count);
  return view;
}

/** Renders the inbox with a proposal docked and waits until the panel shows it. */
async function openPanel(id: string, query = "") {
  const view = renderInbox(`${paths.proposal(id)}${query}`);
  await screen.findByTestId("proposal-summary");
  return view;
}

const stored = (id: string) => {
  const found = reconcileState().proposals.get(id);
  if (!found) throw new Error(`the mock has no proposal ${id}`);
  return found;
};

const panel = () => screen.getByTestId("proposal-panel");

async function signInAs(roles: ("admin" | "operator" | "viewer")[]) {
  await signInAlex({
    prepare: (user) => {
      user.roles = roles;
    },
  });
}

/** Makes the proposal about thermostat-1 stale: IPAM already has the address the proposal suggests. */
async function resolveThermostatInIpam() {
  await api.patch("/api/v1/addresses/{id}", { path: { id: ADDRESS_IDS["192.0.2.41"] as string }, body: { ip: "192.0.2.49" }, ifMatch: ANY_REVISION });
}

describe("the proposal list", () => {
  it("lists the open proposals, newest first, in the class of their kind", async () => {
    await openInbox();
    expect(rowIds()).toEqual(OPEN_NEWEST_FIRST);
    expect(screen.getByTestId("grid-proposals")).toBeTruthy();

    // Conflicts are red, differences amber, proposals magenta (design: color is for exceptions).
    expect(rowOf(P.printerTaken).classList.contains("conflict")).toBe(true);
    expect(rowOf(P.thermostat).classList.contains("differs")).toBe(true);
    for (const id of [P.outside, P.iotAddress, P.hallSwitchClient, P.mediaPc]) {
      expect(rowOf(id).classList.contains("proposal")).toBe(true);
      expect(rowOf(id).classList.contains("conflict")).toBe(false);
      expect(rowOf(id).classList.contains("differs")).toBe(false);
    }
    expect(rowOf(P.mediaPc).dataset.key).toBe("media-pc");

    // The proposals that are decided already are not in the open list.
    for (const id of [P.guestPhone, P.speaker, P.oldTest]) expect(rowIds()).not.toContain(id);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("6 open proposals");
    // Nothing is docked until a proposal is chosen.
    expect(screen.queryByTestId("proposal-panel")).toBeNull();
  });

  it("reads every rule in words, with the values of its parameters", async () => {
    await openInbox();
    expect(cell(rowOf(P.mediaPc), "summary")).toBe(
      "Unknown device 00:00:5e:00:53:d1 (media-pc) seen at 192.0.2.150 by one source; adopt it as host media-pc",
    );
    // No address known: the sentence has no "at".
    expect(cell(rowOf(P.hallSwitchClient), "summary")).toBe(
      "Unknown device 00:00:5e:00:53:d2 (host-00005e0053d2) seen by one source; adopt it as host host-00005e0053d2",
    );
    // No MAC address known: the device has none to name.
    expect(cell(rowOf(P.iotAddress), "summary")).toBe(
      "Unknown device (host-198-51-100-77) seen at 198.51.100.77 by one source; adopt it as host host-198-51-100-77",
    );
    expect(cell(rowOf(P.thermostat), "summary")).toBe("thermostat-1 is seen at 192.0.2.49, not at its intended 192.0.2.41");
    expect(cell(rowOf(P.outside), "summary")).toBe("1 address seen outside every known network; create the network 203.0.113.224/27");
    expect(cell(rowOf(P.printerTaken), "summary")).toBe("192.0.2.30 is intended for printer-1 (00:00:5e:00:53:1e) but used by 00:00:5e:00:53:b0");
  });

  it("shows severity, kind and state in words and the network and sources of each", async () => {
    await openInbox();
    const media = rowOf(P.mediaPc);
    expect(cell(media, "severity")).toContain("Info");
    expect(cell(media, "kind")).toContain("Discovered host");
    expect(cell(media, "state")).toBe("Open");
    expect(media.querySelector("[data-severity='info']")).not.toBeNull();
    expect(media.querySelector("[data-kind='discovered_host']")).not.toBeNull();
    expect(rowOf(P.printerTaken).querySelector("[data-severity='warning']")).not.toBeNull();
    expect(cell(rowOf(P.printerTaken), "kind")).toContain("Conflict");
    expect(cell(rowOf(P.thermostat), "kind")).toContain("Address differs");
    expect(cell(rowOf(P.outside), "kind")).toContain("Outside known networks");

    // What it is about: MAC address, address and the name a source gives.
    expect(cell(media, "subject")).toContain("00:00:5e:00:53:d1");
    expect(cell(media, "subject")).toContain("192.0.2.150");
    expect(cell(media, "subject")).toContain("media-pc");
    // The network by its CIDR, once it is read; a proposal outside every network has a dash.
    await waitFor(() => expect(cell(media, "prefix")).toBe("192.0.2.0/24"));
    expect(cell(rowOf(P.outside), "prefix")).toBe("–");

    // The sources by short word, with the full source (named by its connector) in the tooltip.
    const inventory = media.querySelector("[data-source^='inventory:']") as HTMLElement;
    expect(inventory.textContent).toBe("Inventory");
    await waitFor(() => expect(inventory.title).toBe("Lab inventory (inventory)"));
    expect(inventory.dataset.source).toBe(`inventory:${CONNECTOR_IDS.inventory}`);
    const controller = rowOf(P.hallSwitchClient).querySelector("[data-source^='network_controller:']") as HTMLElement;
    expect(controller.textContent).toBe("Network");
    await waitFor(() => expect(controller.title).toBe("Home network (network controller)"));
    // The probe node of the seed has no name in the node list, so its number stands in.
    const probe = rowOf(P.printerTaken).querySelector("[data-source^='probe:']") as HTMLElement;
    expect(probe.textContent).toBe("Probe");
    expect(probe.title).toBe("Probe 1, ARP");
  });

  it("filters by state", async () => {
    await openInbox();
    const select = screen.getByTestId("filter-state") as HTMLSelectElement;
    expect([...select.options].map((o) => o.textContent)).toEqual(["Open", "Accepted", "Rejected", "Expired", "Superseded", "All"]);
    expect(select.value).toBe("open");

    const choose = (value: string) => fireEvent.change(select, { target: { value } });
    choose("accepted");
    await waitFor(() => expect(rowIds()).toEqual([P.speaker]));
    expect(cell(rowOf(P.speaker), "state")).toBe("Accepted");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("1 proposal");

    choose("rejected");
    await waitFor(() => expect(rowIds()).toEqual([P.guestPhone]));
    expect(cell(rowOf(P.guestPhone), "state")).toBe("Rejected");

    choose("expired");
    await waitFor(() => expect(rowIds()).toEqual([P.oldTest]));
    expect(cell(rowOf(P.oldTest), "state")).toBe("Expired");

    choose("superseded");
    await waitFor(() => expect(screen.getByTestId("discovery-empty").textContent).toContain("No proposal matches the filter"));
    expect(rows()).toHaveLength(0);

    choose("all");
    await listed(9);
    expect(rowIds()).toEqual(expect.arrayContaining([...OPEN_NEWEST_FIRST, P.guestPhone, P.speaker, P.oldTest]));

    choose("open");
    await listed(6);
    expect(rowIds()).toEqual(OPEN_NEWEST_FIRST);
  });

  it("takes the state from the URL", async () => {
    await openInbox("/discovery?state=rejected", 1);
    expect(rowIds()).toEqual([P.guestPhone]);
    expect((screen.getByTestId("filter-state") as HTMLSelectElement).value).toBe("rejected");
  });

  it("takes the open proposals when the state of the URL is not one it knows", async () => {
    await openInbox("/discovery?state=nonsense");
    expect(rowIds()).toEqual(OPEN_NEWEST_FIRST);
    expect((screen.getByTestId("filter-state") as HTMLSelectElement).value).toBe("open");
  });

  it("filters by severity and by kind with chips that keep the URL up to date", async () => {
    const view = await openInbox();
    const chip = (testid: string) => screen.getByTestId(testid);
    expect(chip("filter-severity-warning").getAttribute("aria-pressed")).toBe("false");

    fireEvent.click(chip("filter-severity-warning"));
    await waitFor(() => expect(rowIds()).toEqual([P.printerTaken, P.outside, P.thermostat]));
    expect(chip("filter-severity-warning").getAttribute("aria-pressed")).toBe("true");
    expect(view.location()).toBe("/discovery?severity=warning");

    fireEvent.click(chip("filter-severity-warning"));
    await listed(6);
    expect(view.location()).toBe("/discovery");

    fireEvent.click(chip("filter-severity-critical"));
    await waitFor(() => expect(screen.getByTestId("discovery-empty")).toBeTruthy());
    fireEvent.click(chip("filter-severity-critical"));
    await listed(6);

    fireEvent.click(chip("filter-kind-discovered_host"));
    await waitFor(() => expect(rowIds()).toEqual([P.iotAddress, P.hallSwitchClient, P.mediaPc]));
    // A second kind adds to the first.
    fireEvent.click(chip("filter-kind-conflict"));
    await waitFor(() => expect(rowIds()).toEqual([P.printerTaken, P.iotAddress, P.hallSwitchClient, P.mediaPc]));
    expect(view.location()).toBe("/discovery?kind=discovered_host%2Cconflict");
    fireEvent.click(chip("filter-kind-discovered_host"));
    await waitFor(() => expect(rowIds()).toEqual([P.printerTaken]));

    // Kind and severity together.
    fireEvent.click(chip("filter-severity-info"));
    await waitFor(() => expect(screen.getByTestId("discovery-empty")).toBeTruthy());
    fireEvent.click(chip("filter-kind-address_mismatch"));
    fireEvent.click(chip("filter-severity-info"));
    await waitFor(() => expect(rowIds()).toEqual([P.printerTaken, P.thermostat]));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("2 proposals");
  });

  it("takes severity and kind from the URL and ignores values it does not know", async () => {
    await openInbox("/discovery?kind=outside_prefixes,nonsense&severity=warning", 1);
    expect(rowIds()).toEqual([P.outside]);
    expect(screen.getByTestId("filter-kind-outside_prefixes").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("filter-severity-warning").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("filter-kind-conflict").getAttribute("aria-pressed")).toBe("false");
  });

  it("narrows to the proposals about a network and shows the network as a chip that removes the filter", async () => {
    const view = await openInbox(`/discovery?prefix=${IPAM_IDS.prefix.iot}`, 1);
    expect(rowIds()).toEqual([P.iotAddress]);
    const chip = screen.getByTestId("filter-prefix");
    await waitFor(() => expect(chip.textContent).toContain("Network 198.51.100.0/24"));
    expect(screen.queryByTestId("discovery-empty")).toBeNull();

    fireEvent.click(within(chip).getByRole("button", { name: "Remove the network filter" }));
    await listed(6);
    expect(screen.queryByTestId("filter-prefix")).toBeNull();
    expect(view.location()).toBe("/discovery");
  });

  it("narrows to the proposals about a device by what is typed, after a short pause", async () => {
    const view = await openInbox();
    fireEvent.input(screen.getByTestId("filter-input"), { target: { value: "00:00:5e:00:53:29" } });
    // Not at once: the field waits for the typing to pause.
    expect(rows()).toHaveLength(6);
    await waitFor(() => expect(rowIds()).toEqual([P.thermostat]));
    expect(view.location()).toBe("/discovery?q=00%3A00%3A5e%3A00%3A53%3A29");

    fireEvent.input(screen.getByTestId("filter-input"), { target: { value: "192.0.2.150" } });
    await waitFor(() => expect(rowIds()).toEqual([P.mediaPc]));

    fireEvent.input(screen.getByTestId("filter-input"), { target: { value: "no-such-device" } });
    await waitFor(() => expect(rows()).toHaveLength(0));
    expect(screen.getByTestId("discovery-empty").textContent).toContain("No proposal matches the filter");
    // A narrowed list does not say that nothing is waiting.
    expect(screen.getByTestId("discovery-empty").textContent).not.toContain("The reconciler compares");

    fireEvent.keyDown(screen.getByTestId("filter-input"), { key: "Escape" });
    await listed(6);
    expect(view.location()).toBe("/discovery");
  });

  it("starts from the device filter of the URL", async () => {
    await openInbox("/discovery?q=media-pc", 1);
    expect(rowIds()).toEqual([P.mediaPc]);
    expect((screen.getByTestId("filter-input") as HTMLInputElement).value).toBe("media-pc");
  });

  it("says that nothing waits for a decision when no proposal is open", async () => {
    for (const proposal of reconcileState().proposals.values()) {
      if (proposal.state === "open") reconcileState().proposals.set(proposal.id, { ...proposal, state: "rejected" });
    }
    renderInbox();
    const empty = await screen.findByTestId("discovery-empty");
    expect(empty.textContent).toContain("Nothing to decide");
    expect(empty.textContent).toContain("The reconciler compares what connectors and probes see with IPAM.");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Nothing to decide");
  });

  it("sorts on the server when a sortable header is chosen", async () => {
    await openInbox();
    fireEvent.click(within(screen.getByTestId("grid-proposals")).getByRole("button", { name: /^Severity/ }));
    // Ascending: info before warning, and within a severity the order of the list is kept.
    await waitFor(() => expect(rows().map((r) => cell(r, "severity").trim().slice(0, 4))).toEqual(["Info", "Info", "Info", "Warn", "Warn", "Warn"]));
  });
});

describe("opening a proposal", () => {
  it("docks the proposal beside the list when its row is clicked, and keeps the filters", async () => {
    const view = await openInbox("/discovery?kind=discovered_host", 3);
    fireEvent.click(rowOf(P.mediaPc).querySelector("[data-col='severity']") as HTMLElement);
    await waitFor(() => expect(view.location()).toBe(`/discovery/${P.mediaPc}?kind=discovered_host`));
    const docked = await screen.findByTestId("proposal-panel");
    expect(docked.dataset.id).toBe(P.mediaPc);
    expect(await screen.findByTestId("proposal-summary")).toBeTruthy();
    // The list stays beside it, with the open one marked.
    expect(rows()).toHaveLength(3);
    expect(rowOf(P.mediaPc).classList.contains("current")).toBe(true);
    expect(rowOf(P.hallSwitchClient).classList.contains("current")).toBe(false);

    // Another row replaces the proposal in the panel.
    fireEvent.click(rowOf(P.hallSwitchClient).querySelector("[data-col='kind']") as HTMLElement);
    await waitFor(() => expect(screen.getByTestId("proposal-panel").dataset.id).toBe(P.hallSwitchClient));
    expect(view.location()).toBe(`/discovery/${P.hallSwitchClient}?kind=discovered_host`);
  });

  it("opens the focused proposal with Enter", async () => {
    const view = await openInbox();
    const grid = screen.getByRole("grid", { name: "Proposals" });
    fireEvent.focus(grid);
    // The focus starts on the first proposal; one key reaches the second.
    fireEvent.keyDown(grid, { key: "ArrowDown" });
    fireEvent.keyDown(grid, { key: "Enter" });
    await waitFor(() => expect(view.location()).toBe(`/discovery/${P.outside}`));
    expect((await screen.findByTestId("proposal-panel")).dataset.id).toBe(P.outside);
  });

  it("closes the panel with its button and with Esc, and keeps the filters", async () => {
    const view = await openPanel(P.mediaPc, "?severity=info");
    await listed(3);
    fireEvent.click(within(panel()).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByTestId("proposal-panel")).toBeNull());
    expect(view.location()).toBe("/discovery?severity=info");

    fireEvent.click(rowOf(P.iotAddress).querySelector("[data-col='state']") as HTMLElement);
    await screen.findByTestId("proposal-panel");
    fireEvent.keyDown(panel(), { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("proposal-panel")).toBeNull());
    expect(view.location()).toBe("/discovery?severity=info");
  });

  it("says so when the proposal does not exist", async () => {
    renderInbox(paths.proposal("0190d1c2-0000-7000-8000-00000dffffff"));
    expect(await within(await screen.findByTestId("proposal-panel")).findByText("The proposal does not exist.")).toBeTruthy();
  });
});

describe("the proposal panel", () => {
  it("names the rule, what it is about and the evidence", async () => {
    await openPanel(P.mediaPc);
    expect(screen.getByTestId("proposal-summary").textContent).toBe(
      "Unknown device 00:00:5e:00:53:d1 (media-pc) seen at 192.0.2.150 by one source; adopt it as host media-pc",
    );
    expect(panel().textContent).toContain("Rule ipam.reconcile.discovered_mac, opened");
    expect(within(panel()).getByText("Discovered host")).toBeTruthy();
    expect(within(panel()).getByText("Info")).toBeTruthy();
    expect(panel().querySelector("[data-state='open']")?.textContent).toBe("Open");

    // What it is about: the device links to its observations.
    const subject = within(panel()).getByRole("region", { name: "What it is about" });
    expect(subject.textContent).toContain("00:00:5e:00:53:d1");
    expect(subject.textContent).toContain("192.0.2.150");
    expect(subject.textContent).toContain("media-pc");
    expect(within(subject).getByTestId("proposal-subject-link").getAttribute("href")).toBe("/discovery/observations/00:00:5e:00:53:d1");
    expect(await within(subject).findByRole("link", { name: "192.0.2.0/24" })).toBeTruthy();

    // One line per observation behind it.
    const evidence = within(panel()).getAllByTestId("evidence");
    expect(evidence).toHaveLength(1);
    expect(panel().textContent).toContain("1 observation");
    await waitFor(() => expect(within(evidence[0] as HTMLElement).getByText("Lab inventory (inventory)")).toBeTruthy());
    expect(evidence[0]?.dataset.key).toBe(`inventory:${CONNECTOR_IDS.inventory}`);
    expect(evidence[0]?.textContent).toContain("00:00:5e:00:53:d1");
    expect(evidence[0]?.textContent).toContain("192.0.2.150");
    expect(evidence[0]?.textContent).toContain("media-pc");
    expect(evidence[0]?.textContent).toContain("first seen");
    expect(evidence[0]?.textContent).toContain("last seen");
    expect(evidence[0]?.textContent).toContain("9 sightings");
  });

  it("links the intent a difference is about", async () => {
    await openPanel(P.thermostat);
    expect(screen.getByTestId("proposal-summary").textContent).toBe("thermostat-1 is seen at 192.0.2.49, not at its intended 192.0.2.41");
    const subject = within(panel()).getByRole("region", { name: "What it is about" });
    const intent = subject.querySelectorAll<HTMLElement>(".obj-ref");
    expect([...intent].map((o) => o.dataset.kind)).toEqual(["host", "interface", "address"]);
    expect(await within(subject).findByRole("link", { name: "thermostat-1" })).toBeTruthy();
    expect(within(subject).getByRole("link", { name: "thermostat-1" }).getAttribute("href")).toBe("/ipam/hosts/thermostat-1");
    expect(await within(subject).findByRole("link", { name: "192.0.2.41" })).toBeTruthy();
    expect(within(panel()).getByText("Address differs")).toBeTruthy();
    expect(within(panel()).getByText("Warning")).toBeTruthy();
  });

  it("shows the suggested change as the plan the planner would run", async () => {
    await openPanel(P.mediaPc);
    const change = screen.getByTestId("proposal-change");
    const summary = await within(change).findByTestId("plan-summary");
    // The host brings its interface along; every kind says how many were created.
    expect(within(summary).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Address: 1 created", "Host: 1 created", "Interface: 1 created"]);
    expect(within(change).getAllByTestId("plan-change").map((row) => row.dataset.kind)).toEqual(["host", "interface", "address"]);
  });

  it("shows the change of a proposal that suggests none", async () => {
    await openPanel(P.printerTaken);
    expect(screen.getByTestId("proposal-change").textContent).toContain("None: a conflict is resolved at its cause.");
    expect(screen.queryByTestId("plan-summary")).toBeNull();
    expect(screen.queryByTestId("discovery-approve")).toBeNull();
  });

  it("says what an adoption policy that failed tried, and links the newer proposal that replaced this one", async () => {
    const current = stored(P.mediaPc);
    reconcileState().proposals.set(P.mediaPc, { ...current, adoption_error: "ipam.adoption.invalid" });
    reconcileState().proposals.set(P.oldTest, { ...stored(P.oldTest), state: "superseded", superseded_by: P.mediaPc });
    await openPanel(P.mediaPc);
    expect(screen.getByTestId("proposal-adoption-error").textContent).toContain("An adoption policy tried to apply it and failed:");
    expect(screen.getByTestId("proposal-adoption-error").textContent).toContain("A person decides it now.");

    renderInbox(paths.proposal(P.oldTest));
    const link = await screen.findByTestId("proposal-superseded-by");
    expect(link.getAttribute("href")).toBe(`/discovery/${P.mediaPc}`);
    expect(link.textContent).toBe("The newer proposal");
  });
});

describe("a decided proposal", () => {
  it("shows a rejection with who decided it and the reason, and offers no decision", async () => {
    await openPanel(P.guestPhone, "?state=rejected");
    const decision = await screen.findByTestId("proposal-decision");
    expect(decision.textContent).toContain("Rejected");
    expect(decision.textContent).toContain("Decided by");
    expect(decision.textContent).toContain("Alex Example (you)");
    expect(decision.textContent).toContain("Reason");
    expect(decision.querySelector(".proposal-reason")?.textContent).toBe("A guest phone on the guest network");
    expect(screen.queryByTestId("discovery-approve")).toBeNull();
    expect(screen.queryByTestId("discovery-reject")).toBeNull();
    // A proposal that is decided shows how many changes it had, not a plan.
    expect(screen.getByTestId("proposal-change").textContent).toContain("1 change of intent");
    expect(screen.queryByTestId("plan-summary")).toBeNull();
  });

  it("shows an adoption with the prefix whose policy adopted it and what it changed", async () => {
    await openPanel(P.speaker, "?state=accepted");
    const decision = await screen.findByTestId("proposal-decision");
    expect(decision.textContent).toContain("Accepted");
    expect(decision.textContent).toContain("Adopted by the policy of");
    expect(await within(decision).findByRole("link", { name: "192.0.2.0/24" })).toBeTruthy();
    expect(decision.textContent).toContain("Tenko (reconciler)");
    // The result: the host the adoption created.
    const result = decision.querySelector<HTMLElement>(".obj-ref[data-kind='host']");
    expect(result?.dataset.id).toBe(HOST_IDS["speaker-den"]);
    expect(await within(decision).findByRole("link", { name: "speaker-den" })).toBeTruthy();
    expect(screen.getByTestId("proposal-change").textContent).toContain("None");
  });

  it("shows why a proposal expired", async () => {
    await openPanel(P.oldTest, "?state=expired");
    const decision = await screen.findByTestId("proposal-decision");
    expect(decision.textContent).toContain("Expired");
    expect(decision.querySelector(".proposal-reason")?.textContent).toBe(REASON_GONE);
    expect(screen.queryByTestId("discovery-reject")).toBeNull();
  });

  it("does not show a decision section for an open proposal", async () => {
    await openPanel(P.mediaPc);
    expect(screen.queryByTestId("proposal-decision")).toBeNull();
  });
});

describe("approving", () => {
  it("applies the suggested change through the plan dialog and takes the proposal off the open list", async () => {
    const view = await openInbox(paths.proposal(P.mediaPc), 6);
    await screen.findByTestId("plan-summary");
    fireEvent.click(screen.getByTestId("discovery-approve"));

    const dialog = await screen.findByTestId("dialog-approve");
    expect(screen.getByRole("dialog", { name: "Approve proposal" })).toBeTruthy();
    expect(dialog.textContent).toContain("Unknown device 00:00:5e:00:53:d1 (media-pc) seen at 192.0.2.150 by one source; adopt it as host media-pc");
    const planned = await within(dialog).findByTestId("plan-summary");
    expect(planned.textContent).toContain("1 created");
    expect(within(dialog).getByTestId("plan-confirm").textContent).toBe("Approve and apply 2 changes");
    // The preview wrote nothing.
    expect(stored(P.mediaPc).state).toBe("open");

    await confirmPlan({ dialog: "dialog-approve" });
    await waitFor(() => expect(screen.queryByTestId("dialog-approve")).toBeNull());
    expect(stored(P.mediaPc).state).toBe("accepted");
    expect(stored(P.mediaPc).results?.some((r) => r.kind === "host")).toBe(true);
    // A toast names the result, and the proposal leaves the open list.
    expect(await screen.findByText("Proposal approved")).toBeTruthy();
    await listed(5);
    expect(rowIds()).not.toContain(P.mediaPc);
    expect(view.location()).toBe(`/discovery/${P.mediaPc}`);
    // The host exists now, with its interface and address.
    const host = [...ipamState().data.host.values()].find((h) => h.name === "media-pc");
    expect(host?.mode).toBe("dynamic");
    expect([...ipamState().data.address.values()].some((a) => a.ip === "192.0.2.150")).toBe(true);
  });

  it("approves from the A key and decides nothing while a field has the focus", async () => {
    await openPanel(P.mediaPc);
    await screen.findByTestId("plan-summary");
    // Typing an A in the filter field is typing, not a decision.
    const field = screen.getByTestId("filter-input");
    field.focus();
    fireEvent.keyDown(field, { key: "a" });
    expect(screen.queryByTestId("dialog-approve")).toBeNull();

    fireEvent.keyDown(document.body, { key: "a" });
    expect(await screen.findByTestId("dialog-approve")).toBeTruthy();
    // With a dialog open the keys belong to the dialog.
    fireEvent.keyDown(document.body, { key: "r" });
    expect(screen.queryByTestId("dialog-reject")).toBeNull();
    fireEvent.click(within(screen.getByTestId("dialog-approve")).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByTestId("dialog-approve")).toBeNull());
    expect(stored(P.mediaPc).state).toBe("open");
  });

  it("offers approval from the row actions menu and refuses it for a conflict", async () => {
    await openInbox();
    const grid = screen.getByRole("grid", { name: "Proposals" });
    fireEvent.focus(grid);
    fireEvent.keyDown(grid, { key: "ContextMenu" });
    const menu = await screen.findByRole("menu");
    // The first row is the conflict: it cannot be approved, but it can be dismissed.
    expect((within(menu).getByRole("menuitem", { name: "Approve" }) as HTMLButtonElement).getAttribute("aria-disabled")).toBe("true");
    expect(within(menu).getByRole("menuitem", { name: "Reject" }).getAttribute("aria-disabled")).not.toBe("true");
  });

  it("shows the error when the proposal changed after the preview", async () => {
    await openPanel(P.mediaPc);
    await screen.findByTestId("plan-summary");
    fireEvent.click(screen.getByTestId("discovery-approve"));
    const dialog = await screen.findByTestId("dialog-approve");
    await within(dialog).findByTestId("plan-summary");
    // Someone else touched the proposal: the revision the dialog holds is not the current one.
    const current = stored(P.mediaPc);
    reconcileState().proposals.set(P.mediaPc, { ...current, revision: (current.revision ?? 0) + 1000 });
    fireEvent.click(within(dialog).getByTestId("plan-confirm"));
    expect(await within(dialog).findByText("The proposal changed meanwhile. Look at it again before you decide.")).toBeTruthy();
    expect(stored(P.mediaPc).state).toBe("open");
  });
});

describe("rejecting", () => {
  it("rejects with a reason and takes the proposal off the open list", async () => {
    await openPanel(P.hallSwitchClient);
    await screen.findByTestId("plan-summary");
    fireEvent.click(screen.getByTestId("discovery-reject"));

    const dialog = await screen.findByTestId("dialog-reject");
    expect(screen.getByRole("dialog", { name: "Reject proposal" })).toBeTruthy();
    expect(dialog.textContent).toContain("The same evidence will not open it again.");
    expect(dialog.textContent).toContain("Recorded with the decision and in the audit log.");
    expect(within(dialog).getByTestId("form-submit").textContent).toBe("Reject proposal");
    fireEvent.input(within(dialog).getByTestId("field-reason"), { target: { value: "  A visitor's laptop  " } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(screen.queryByTestId("dialog-reject")).toBeNull());
    const rejected = stored(P.hallSwitchClient);
    expect(rejected.state).toBe("rejected");
    expect(rejected.reason).toBe("A visitor's laptop");
    expect(await screen.findByText("Proposal rejected")).toBeTruthy();
    await listed(5);
    expect(rowIds()).not.toContain(P.hallSwitchClient);
  });

  it("rejects without a reason", async () => {
    await openPanel(P.iotAddress);
    fireEvent.click(await screen.findByTestId("discovery-reject"));
    fireEvent.click(within(await screen.findByTestId("dialog-reject")).getByTestId("form-submit"));
    await waitFor(() => expect(stored(P.iotAddress).state).toBe("rejected"));
    expect(stored(P.iotAddress).reason ?? null).toBeNull();
  });

  it("opens from the R key and from the row actions, and cancel leaves the proposal open", async () => {
    await openPanel(P.outside);
    await screen.findByTestId("discovery-reject");
    fireEvent.keyDown(document.body, { key: "R" });
    const dialog = await screen.findByTestId("dialog-reject");
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByTestId("dialog-reject")).toBeNull());
    expect(stored(P.outside).state).toBe("open");

    // Esc closes the dialog, not the panel behind it.
    fireEvent.keyDown(document.body, { key: "r" });
    fireEvent.keyDown(await screen.findByTestId("field-reason"), { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-reject")).toBeNull());
    expect(screen.getByTestId("proposal-panel")).toBeTruthy();
  });

  it("refuses a reason of more than 1,024 bytes, counting bytes and not characters", async () => {
    await openPanel(P.mediaPc);
    fireEvent.click(await screen.findByTestId("discovery-reject"));
    const dialog = await screen.findByTestId("dialog-reject");
    const field = within(dialog).getByTestId("field-reason");
    const submit = within(dialog).getByTestId("form-submit") as HTMLButtonElement;
    const hint = () => dialog.querySelector("#reject-reason-help")?.textContent ?? "";

    // 1,024 bytes are fine.
    fireEvent.input(field, { target: { value: "a".repeat(1024) } });
    expect(submit.disabled).toBe(false);
    expect(field.getAttribute("aria-invalid")).toBeNull();
    expect(hint()).toContain("Recorded with the decision");

    // 513 two-byte letters are 513 characters but 1,026 bytes.
    fireEvent.input(field, { target: { value: "å".repeat(513) } });
    expect(submit.disabled).toBe(true);
    expect(field.getAttribute("aria-invalid")).toBe("true");
    expect(hint()).toContain("At most 1,024 bytes.");
    fireEvent.submit(dialog);
    expect(stored(P.mediaPc).state).toBe("open");

    fireEvent.input(field, { target: { value: "å".repeat(512) } });
    expect(submit.disabled).toBe(false);
    expect(hint()).toContain("Recorded with the decision");
  });

  it("shows the error when the proposal was decided elsewhere meanwhile", async () => {
    await openPanel(P.mediaPc);
    fireEvent.click(await screen.findByTestId("discovery-reject"));
    const dialog = await screen.findByTestId("dialog-reject");
    // Decided elsewhere, without a change the dialog could notice.
    reconcileState().proposals.set(P.mediaPc, { ...stored(P.mediaPc), state: "rejected", reason: "someone else was first" });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("The proposal was decided already (rejected).")).toBeTruthy();
    expect(stored(P.mediaPc).reason).toBe("someone else was first");
    // The dialog stays, so that the person can read the problem.
    expect(screen.getByTestId("dialog-reject")).toBeTruthy();
  });
});

describe("a conflict", () => {
  it("cannot be approved and is dismissed instead of rejected", async () => {
    await openPanel(P.printerTaken);
    const dismiss = await screen.findByTestId("discovery-reject");
    expect(dismiss.textContent).toContain("Dismiss");
    expect(screen.queryByTestId("discovery-approve")).toBeNull();
    expect(screen.getByTestId("proposal-panel").textContent).toContain("A conflict suggests no change. Resolve its cause, then dismiss it.");
    // The A key does nothing for it.
    fireEvent.keyDown(document.body, { key: "a" });
    expect(screen.queryByTestId("dialog-approve")).toBeNull();

    fireEvent.click(dismiss);
    const dialog = await screen.findByTestId("dialog-reject");
    expect(screen.getByRole("dialog", { name: "Dismiss conflict" })).toBeTruthy();
    expect(dialog.textContent).toContain("Dismiss it once its cause is resolved.");
    expect(within(dialog).getByTestId("form-submit").textContent).toBe("Dismiss conflict");
    fireEvent.input(within(dialog).getByTestId("field-reason"), { target: { value: "The printer got its address back" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(screen.queryByTestId("dialog-reject")).toBeNull());
    expect(stored(P.printerTaken).state).toBe("rejected");
    expect(stored(P.printerTaken).reason).toBe("The printer got its address back");
    expect(await screen.findByText("Conflict dismissed")).toBeTruthy();
    await listed(5);
    expect(rowIds()).not.toContain(P.printerTaken);
  });

  it("is told that a proposal without commands cannot be approved, when it is not a conflict", async () => {
    reconcileState().proposals.set(P.outside, { ...stored(P.outside), commands: [] });
    await openPanel(P.outside);
    await screen.findByTestId("discovery-reject");
    expect(screen.queryByTestId("discovery-approve")).toBeNull();
    expect(screen.getByTestId("proposal-panel").textContent).toContain("This proposal suggests no change. Resolve it by hand, then reject it.");
    expect(screen.getByTestId("proposal-change").textContent).toContain("None");
  });
});

describe("reconcile now", () => {
  it("runs the reconciler and reports what it did, expiring what no longer holds", async () => {
    await openInbox();
    await resolveThermostatInIpam();
    fireEvent.click(screen.getByTestId("discovery-reconcile"));

    const report = await screen.findByTestId("dialog-reconcile-report");
    expect(report.textContent).toContain("Reconciler run");
    const counts = () => Object.fromEntries(within(report).getAllByTestId("report-count").map((c) => [c.dataset.key, c.textContent]));
    expect(counts()).toEqual({
      opened: "0",
      refreshed: "0",
      unchanged: "5",
      superseded: "0",
      expired: "1",
      suppressed: "0",
      adopted: "0",
      adoption_failures: "0",
      sightings: "0",
      moves_confirmed: "0",
    });
    expect(within(report).getByText("No longer holding")).toBeTruthy();
    expect(report.textContent).not.toContain("Nothing changed.");
    expect(stored(P.thermostat).state).toBe("expired");
    expect(stored(P.thermostat).reason).toBe(REASON_GONE);

    // The expired proposal leaves the open list behind the report.
    await listed(5);
    expect(rowIds()).not.toContain(P.thermostat);

    fireEvent.click(within(report).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByTestId("dialog-reconcile-report")).toBeNull());
  });

  it("says when nothing changed", async () => {
    await openInbox();
    fireEvent.click(screen.getByTestId("discovery-reconcile"));
    const report = await screen.findByTestId("dialog-reconcile-report");
    expect(report.textContent).toContain("Nothing changed.");
    expect(within(report).getAllByTestId("report-count").find((c) => c.dataset.key === "unchanged")?.textContent).toBe("6");
    expect(within(report).getAllByTestId("report-count").find((c) => c.dataset.key === "expired")?.textContent).toBe("0");
    expect(rows()).toHaveLength(6);
  });

  it("tells a failed run in a toast", async () => {
    server.use(
      http.post("/api/v1/proposals/reconcile", () =>
        HttpResponse.json(
          { type: "about:blank", title: "Internal error", status: 500, code: "sys.internal", detail: "", params: {} },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    await openInbox();
    fireEvent.click(screen.getByTestId("discovery-reconcile"));
    expect(await screen.findByText("The reconciler did not run")).toBeTruthy();
    expect(screen.queryByTestId("dialog-reconcile-report")).toBeNull();
    // The button works again.
    await waitFor(() => expect((screen.getByTestId("discovery-reconcile") as HTMLButtonElement).disabled).toBe(false));
  });
});

describe("deciding many at once", () => {
  const box = (id: string) => within(rowOf(id)).getByRole("checkbox") as HTMLInputElement;
  const pick = (...ids: string[]) => ids.forEach((id) => fireEvent.click(box(id)));
  const bar = () => screen.queryByTestId("actionbar");
  const grid = () => screen.getByRole("grid", { name: "Proposals" });
  const buttons = () => Array.from(bar()?.querySelectorAll("button[data-testid^='action-']") ?? []).map((b) => b.textContent);

  it("offers the check box column and the select-all box to someone who may decide, and a bar for the selection", async () => {
    await openInbox();
    expect(bar()).toBeNull();
    pick(P.mediaPc, P.hallSwitchClient);
    expect(box(P.mediaPc).checked).toBe(true);
    expect(box(P.outside).checked).toBe(false);
    expect(bar()?.textContent).toContain("2");
    expect(buttons()).toEqual(["Approve 2", "Reject 2"]);

    // The header box selects the loaded rows, and a click on a box does not open the proposal.
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all rows in view" }));
    expect(buttons()).toEqual(["Approve 6", "Reject 6"]);
    expect(screen.queryByTestId("selection-loaded-only")).toBeNull();
    expect(screen.queryByTestId("proposal-panel")).toBeNull();

    fireEvent.click(within(bar() as HTMLElement).getByRole("button", { name: "Clear selection (Esc)" }));
    expect(bar()).toBeNull();
  });

  it("follows the keys of the grid: Space, Shift with the arrows, Ctrl+A and Esc", async () => {
    await openInbox();
    fireEvent.focus(grid());
    fireEvent.keyDown(grid(), { key: " " });
    fireEvent.keyDown(grid(), { key: "ArrowDown", shiftKey: true });
    expect(buttons()).toEqual(["Approve 2", "Reject 2"]);
    expect([box(P.printerTaken).checked, box(P.outside).checked, box(P.thermostat).checked]).toEqual([true, true, false]);
    fireEvent.keyDown(grid(), { key: "a", ctrlKey: true });
    expect(buttons()).toEqual(["Approve 6", "Reject 6"]);
    fireEvent.keyDown(grid(), { key: "Escape" });
    expect(bar()).toBeNull();
  });

  it("gives a viewer no check boxes and no bar", async () => {
    await signInAs(["viewer"]);
    await openInbox();
    expect(within(grid()).queryAllByRole("checkbox")).toHaveLength(0);
    expect(bar()).toBeNull();
  });

  it("does not offer a proposal that is decided already for selection", async () => {
    await openInbox(`${paths.discovery()}?state=all`, 9);
    expect(within(rowOf(P.speaker)).queryByRole("checkbox")).toBeNull();
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all rows in view" }));
    expect(buttons()).toEqual(["Approve 6", "Reject 6"]);
  });

  it("asks once, naming the count and the kinds, and approves them in one request", async () => {
    await openInbox();
    const writes = recordWrites();
    pick(P.mediaPc, P.hallSwitchClient, P.iotAddress);
    fireEvent.click(screen.getByTestId("action-approve"));

    const dialog = await screen.findByTestId("dialog-approve-many");
    expect(screen.getByRole("dialog", { name: "Approve 3 proposals" })).toBeTruthy();
    expect(within(dialog).getByTestId("approve-kinds").textContent).toContain("3 discovered hosts");
    expect(within(dialog).getByTestId("form-submit").textContent).toBe("Approve 3 proposals");
    // Cancel decides nothing.
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByTestId("dialog-approve-many")).toBeNull());
    expect(stored(P.mediaPc).state).toBe("open");
    expect(buttons()).toEqual(["Approve 3", "Reject 3"]);

    fireEvent.click(screen.getByTestId("action-approve"));
    fireEvent.click(within(await screen.findByTestId("dialog-approve-many")).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-approve-many")).toBeNull());

    const batches = writes().filter((w) => w.url.endsWith("/api/v1/proposals/approve"));
    expect(batches).toHaveLength(1);
    // The ids go in the order of the list.
    expect(batches[0]?.body?.ids).toEqual([P.iotAddress, P.hallSwitchClient, P.mediaPc]);
    expect([...((batches[0]?.body?.ids as string[]) ?? [])].sort()).toEqual([P.hallSwitchClient, P.iotAddress, P.mediaPc].sort());
    for (const id of [P.mediaPc, P.hallSwitchClient, P.iotAddress]) expect(stored(id).state).toBe("accepted");
    expect(await screen.findByText("3 proposals approved")).toBeTruthy();
    await listed(3);
    expect(rowIds()).toEqual([P.printerTaken, P.outside, P.thermostat]);
    // The selection is gone with the rows, and nothing was skipped.
    expect(bar()).toBeNull();
    expect(screen.queryByTestId("dialog-skipped")).toBeNull();
    expect([...ipamState().data.host.values()].some((h) => h.name === "media-pc")).toBe(true);
  });

  it("rejects the selection with one reason dialog and one request", async () => {
    await openInbox();
    const writes = recordWrites();
    pick(P.mediaPc, P.hallSwitchClient);
    fireEvent.click(screen.getByTestId("action-reject"));

    const dialog = await screen.findByTestId("dialog-reject");
    expect(screen.getByRole("dialog", { name: "Reject 2 proposals" })).toBeTruthy();
    expect(within(dialog).getByTestId("reject-kinds").textContent).toContain("2 discovered hosts are rejected with the same reason");
    expect(within(dialog).getByTestId("form-submit").textContent).toBe("Reject 2 proposals");
    fireEvent.input(within(dialog).getByTestId("field-reason"), { target: { value: "  Visitors' devices  " } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-reject")).toBeNull());

    const batches = writes().filter((w) => w.url.endsWith("/api/v1/proposals/reject"));
    expect(batches).toHaveLength(1);
    expect(batches[0]?.body?.reason).toBe("Visitors' devices");
    for (const id of [P.mediaPc, P.hallSwitchClient]) {
      expect(stored(id).state).toBe("rejected");
      expect(stored(id).reason).toBe("Visitors' devices");
    }
    expect(await screen.findByText("2 proposals rejected")).toBeTruthy();
    await listed(4);
    expect(bar()).toBeNull();
  });

  it("refuses a reason of more than 1,024 bytes for the selection too", async () => {
    await openInbox();
    pick(P.mediaPc, P.hallSwitchClient);
    fireEvent.click(screen.getByTestId("action-reject"));
    const dialog = await screen.findByTestId("dialog-reject");
    fireEvent.input(within(dialog).getByTestId("field-reason"), { target: { value: "å".repeat(513) } });
    expect((within(dialog).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(true);
    expect(stored(P.mediaPc).state).toBe("open");
  });

  it("reports what was skipped with the reasons, and can keep those rows selected", async () => {
    await openInbox();
    pick(P.printerTaken, P.mediaPc, P.hallSwitchClient);
    fireEvent.click(screen.getByTestId("action-approve"));
    const dialog = await screen.findByTestId("dialog-approve-many");
    expect(within(dialog).getByTestId("approve-kinds").textContent).toContain("2 discovered hosts and 1 conflict");
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    // One toast with the counts.
    expect(await screen.findByText("2 proposals approved")).toBeTruthy();
    expect(screen.getByText("1 skipped")).toBeTruthy();
    // The panel lists the skipped proposal with the reason of the single route.
    const skipped = await screen.findByTestId("dialog-skipped");
    expect(screen.getByRole("dialog", { name: "1 proposal was skipped" })).toBeTruthy();
    const items = within(skipped).getAllByTestId("skipped-item");
    expect(items).toHaveLength(1);
    expect(items[0]?.dataset.id).toBe(P.printerTaken);
    expect(items[0]?.dataset.code).toBe("ipam.proposal.nothing_to_apply");
    expect(items[0]?.textContent).toContain("192.0.2.30 is intended for printer-1");
    expect(items[0]?.textContent).toContain("The proposal suggests no change. Resolve its cause, then reject it.");
    expect(stored(P.printerTaken).state).toBe("open");
    // The selection was cleared by the batch.
    expect(bar()).toBeNull();

    fireEvent.click(within(skipped).getByTestId("skipped-keep"));
    await waitFor(() => expect(screen.queryByTestId("dialog-skipped")).toBeNull());
    await listed(4);
    expect(box(P.printerTaken).checked).toBe(true);
    expect(buttons()).toEqual(["Approve 1", "Reject 1"]);
  });

  it("closes the panel of the skipped without keeping the selection", async () => {
    await openInbox();
    pick(P.printerTaken, P.mediaPc);
    fireEvent.click(screen.getByTestId("action-approve"));
    fireEvent.click(within(await screen.findByTestId("dialog-approve-many")).getByTestId("form-submit"));
    const skipped = await screen.findByTestId("dialog-skipped");
    fireEvent.click(within(skipped).getByTestId("skipped-close"));
    await waitFor(() => expect(screen.queryByTestId("dialog-skipped")).toBeNull());
    await listed(5);
    expect(bar()).toBeNull();
  });

  it("names a proposal that was decided elsewhere meanwhile as skipped", async () => {
    await openInbox();
    pick(P.mediaPc, P.hallSwitchClient);
    await rejectProposal({ id: P.hallSwitchClient }, "decided on another screen");
    fireEvent.click(screen.getByTestId("action-reject"));
    fireEvent.click(within(await screen.findByTestId("dialog-reject")).getByTestId("form-submit"));
    expect(await screen.findByText("1 proposal rejected")).toBeTruthy();
    const skipped = await screen.findByTestId("dialog-skipped");
    const item = within(skipped).getByTestId("skipped-item");
    expect(item.dataset.code).toBe("ipam.proposal.not_open");
    expect(item.textContent).toContain("The proposal was decided already (rejected).");
    expect(stored(P.hallSwitchClient).reason).toBe("decided on another screen");
  });

  it("shows the error and keeps the dialog when the request fails", async () => {
    await openInbox();
    server.use(
      http.post("*/api/v1/proposals/approve", () =>
        HttpResponse.json({ type: "about:blank", status: 503, code: "ipam.unavailable", title: "Service unavailable", detail: "no ipam" }, { status: 503, headers: { "content-type": "application/problem+json" } }),
      ),
    );
    pick(P.mediaPc, P.hallSwitchClient);
    fireEvent.click(screen.getByTestId("action-approve"));
    const dialog = await screen.findByTestId("dialog-approve-many");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(dialog.querySelector("[role='alert']")).not.toBeNull());
    expect(screen.getByTestId("dialog-approve-many")).toBeTruthy();
    expect(stored(P.mediaPc).state).toBe("open");
    expect(buttons()).toEqual(["Approve 2", "Reject 2"]);
  });

  it("has no violations with the confirmation and with the skipped panel open", async () => {
    await openInbox();
    pick(P.printerTaken, P.mediaPc);
    fireEvent.click(screen.getByTestId("action-approve"));
    const dialog = await screen.findByTestId("dialog-approve-many");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await axeViolations(await screen.findByTestId("dialog-skipped"))).toEqual([]);
  });
});

describe("who may decide", () => {
  it("shows a viewer the proposals but no way to decide them or to run the reconciler", async () => {
    await signInAs(["viewer"]);
    await openPanel(P.mediaPc);
    await listed(6);
    expect(screen.queryByTestId("discovery-reconcile")).toBeNull();
    expect(screen.queryByTestId("discovery-approve")).toBeNull();
    expect(screen.queryByTestId("discovery-reject")).toBeNull();
    // Without the right to approve there is no plan to preview, only the count of changes.
    expect(screen.getByTestId("proposal-change").textContent).toContain("2 changes of intent");
    expect(screen.queryByTestId("plan-summary")).toBeNull();
    // The keys do nothing.
    fireEvent.keyDown(document.body, { key: "a" });
    fireEvent.keyDown(document.body, { key: "r" });
    expect(screen.queryByTestId("dialog-approve")).toBeNull();
    expect(screen.queryByTestId("dialog-reject")).toBeNull();
    // Evidence is for everyone.
    expect(within(panel()).getAllByTestId("evidence")).toHaveLength(1);
  });

  it("lets an operator decide and run the reconciler", async () => {
    await signInAs(["operator"]);
    await openPanel(P.mediaPc);
    await listed(6);
    expect(screen.getByTestId("discovery-reconcile")).toBeTruthy();
    await screen.findByTestId("plan-summary");
    expect(screen.getByTestId("discovery-approve")).toBeTruthy();
    expect(screen.getByTestId("discovery-reject")).toBeTruthy();
    fireEvent.click(screen.getByTestId("discovery-approve"));
    await confirmPlan({ dialog: "dialog-approve" });
    await waitFor(() => expect(stored(P.mediaPc).state).toBe("accepted"));
  });
});

describe("live updates", () => {
  it("follows a decision made elsewhere in the row and in the open panel", async () => {
    stopBridge = bridgeMockEvents();
    await openInbox(`${paths.proposal(P.mediaPc)}?state=all`, 9);
    await screen.findByTestId("plan-summary");
    expect(cell(rowOf(P.mediaPc), "state")).toBe("Open");
    expect(screen.getByTestId("discovery-approve")).toBeTruthy();
    expect(screen.queryByTestId("proposal-decision")).toBeNull();

    // Someone else rejects it through the API.
    await rejectProposal({ id: P.mediaPc }, "decided on another screen");

    await waitFor(() => expect(cell(rowOf(P.mediaPc), "state")).toBe("Rejected"), { timeout: 4000 });
    const decision = await screen.findByTestId("proposal-decision");
    expect(decision.querySelector(".proposal-reason")?.textContent).toBe("decided on another screen");
    expect(panel().querySelector("[data-state='rejected']")).not.toBeNull();
    expect(screen.queryByTestId("discovery-approve")).toBeNull();
    expect(screen.queryByTestId("discovery-reject")).toBeNull();
    // Another proposal is not touched.
    expect(cell(rowOf(P.outside), "state")).toBe("Open");
  });

  it("takes a proposal off the open list when the reconciler expires it", async () => {
    stopBridge = bridgeMockEvents();
    await openInbox();
    await resolveThermostatInIpam();
    // A run elsewhere (the server runs it on a schedule).
    await api.post("/api/v1/proposals/reconcile");
    await waitFor(() => expect(rowIds()).toEqual([P.printerTaken, P.outside, P.iotAddress, P.hallSwitchClient, P.mediaPc]), { timeout: 4000 });
  });
});

describe("accessibility", () => {
  it("has no violations with a proposal open", async () => {
    const view = await openPanel(P.mediaPc);
    await listed(6);
    await screen.findByTestId("plan-summary");
    await waitFor(() => expect(within(panel()).getByText("Lab inventory (inventory)")).toBeTruthy());
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("has no violations with a decided proposal open", async () => {
    const view = await openPanel(P.speaker, "?state=all");
    await listed(9);
    await screen.findByTestId("proposal-decision");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("has no violations with the reject dialog open", async () => {
    await openPanel(P.mediaPc);
    fireEvent.click(await screen.findByTestId("discovery-reject"));
    expect(await axeViolations(await screen.findByTestId("dialog-reject"))).toEqual([]);
  });

  it("has no violations with the report of a run open", async () => {
    await openInbox();
    fireEvent.click(screen.getByTestId("discovery-reconcile"));
    expect(await axeViolations(await screen.findByTestId("dialog-reconcile-report"))).toEqual([]);
  });
});
