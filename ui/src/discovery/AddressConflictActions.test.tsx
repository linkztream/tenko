// What a person can do about an address conflict in the proposal panel: decommission one of the
// hosts in the conflict, or keep both. The hosts come from the parameters of the proposal.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HOST_IDS, ipamState } from "../api/mock/ipam/api";
import { putAddressConflict, RECONCILE_IDS, reconcileState } from "../api/mock/reconcile-store";
import { bridgeMockEvents } from "../audit/testkit";
import { paths } from "../app/paths";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInWithRoles } from "../auth/scope-testkit";
import { setSessionForTest } from "../auth/session";
import { applied, confirmPlan, recordWrites } from "../ipam/testkit";
import ProposalsView from "./ProposalsView";
import { resetRefs } from "./refs";

const SHARED = "ipam.reconcile.conflict_shared_address" as const;
const TAKEN = "ipam.reconcile.conflict_address_taken" as const;
const id = (name: string) => HOST_IDS[name] as string;

beforeEach(async () => {
  resetRefs();
  await signInAlex();
});

let stopBridge: (() => void) | undefined;

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  setSessionForTest(null);
});

async function openPanel(proposalId: string) {
  renderRoute(ProposalsView, {
    url: paths.proposal(proposalId),
    path: "/discovery/:id?",
    routes: { "/discovery/observations/:subject": () => <div data-testid="subject-route" /> },
  });
  await screen.findByTestId("proposal-summary");
  return screen.getByTestId("proposal-panel");
}

const decommissionButtons = () => screen.queryAllByTestId("conflict-decommission");
const stored = (proposalId: string) => reconcileState().proposals.get(proposalId);
const gone = (testid: string) => waitFor(() => expect(screen.queryByTestId(testid)).toBeNull());

describe("the actions on an address conflict", () => {
  it("offers a Decommission button for each host in a shared address, beside Dismiss and Keep both", async () => {
    const conflict = putAddressConflict({ rule: SHARED, ip: "192.0.2.77", hosts: [id("ha"), id("tenko1")] });
    const panel = await openPanel(conflict.id);
    await waitFor(() => expect(decommissionButtons()).toHaveLength(2));
    expect(decommissionButtons().map((b) => b.textContent)).toEqual(["Decommission ha", "Decommission tenko1"]);
    expect(decommissionButtons().every((b) => b.dataset.dormant === "false")).toBe(true);
    expect(within(panel).queryByTestId("conflict-dormant")).toBeNull();
    expect(within(panel).getByTestId("discovery-reject").textContent).toContain("Dismiss");
    expect(within(panel).getByTestId("conflict-keep").textContent).toBe("Keep both");
  });

  it("puts the host that only has a dormant claim first, as the primary action, and says why", async () => {
    const conflict = putAddressConflict({ rule: TAKEN, ip: "192.0.2.77", hosts: [id("ha"), id("tenko1")], dormant: [id("tenko1")] });
    const panel = await openPanel(conflict.id);
    await waitFor(() => expect(decommissionButtons()).toHaveLength(2));
    expect(decommissionButtons().map((b) => b.dataset.host)).toEqual([id("tenko1"), id("ha")]);
    const [dormant, other] = decommissionButtons();
    expect(dormant?.dataset.dormant).toBe("true");
    expect(dormant?.classList.contains("primary")).toBe(true);
    expect(other?.classList.contains("primary")).toBe(false);
    expect(within(panel).getByTestId("conflict-dormant").textContent).toBe("only on a stopped guest");
  });

  it("is on the seeded taken-address conflict, for the intended host", async () => {
    const panel = await openPanel(RECONCILE_IDS.proposal.printerTaken);
    await waitFor(() => expect(decommissionButtons()).toHaveLength(1));
    expect(decommissionButtons()[0]?.textContent).toBe("Decommission printer-1");
    expect(within(panel).getByTestId("conflict-keep")).toBeTruthy();
  });

  it("is not there for other proposals, decided conflicts or someone who may not decide", async () => {
    let panel = await openPanel(RECONCILE_IDS.proposal.mediaPc);
    await screen.findByTestId("discovery-approve");
    expect(within(panel).queryByTestId("conflict-keep")).toBeNull();
    expect(decommissionButtons()).toHaveLength(0);

    // A conflict that is decided already.
    const conflict = putAddressConflict({ rule: SHARED, ip: "192.0.2.78", hosts: [id("ha"), id("tenko1")] });
    reconcileState().proposals.set(conflict.id, { ...conflict, state: "rejected" });
    document.body.innerHTML = "";
    panel = await openPanel(conflict.id);
    expect(within(panel).queryByTestId("conflict-keep")).toBeNull();
    expect(decommissionButtons()).toHaveLength(0);
  });

  it("is not there for a viewer", async () => {
    await signInWithRoles(["viewer"]);
    const conflict = putAddressConflict({ rule: SHARED, ip: "192.0.2.77", hosts: [id("ha"), id("tenko1")] });
    const panel = await openPanel(conflict.id);
    expect(within(panel).queryByTestId("discovery-reject")).toBeNull();
    expect(within(panel).queryByTestId("conflict-keep")).toBeNull();
    expect(decommissionButtons()).toHaveLength(0);
  });
});

describe("decommissioning a host of the conflict", () => {
  it("opens the decommission dialog, previews and decommissions the host", async () => {
    const writes = recordWrites();
    const conflict = putAddressConflict({ rule: SHARED, ip: "192.0.2.77", hosts: [id("ha"), id("tenko1")] });
    await openPanel(conflict.id);
    await waitFor(() => expect(decommissionButtons()).toHaveLength(2));
    fireEvent.click(decommissionButtons()[1] as HTMLElement);

    const form = await screen.findByTestId("dialog-decommission");
    expect(within(form).getByRole("heading", { name: "Decommission tenko1" })).toBeTruthy();
    fireEvent.input(within(form).getByTestId("decommission-reason"), { target: { value: "Cloned by mistake" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await confirmPlan({ dialog: "dialog-decommission-plan" });
    await gone("dialog-decommission-plan");

    const sent = applied(writes()).filter((w) => w.url.includes("/decommission"));
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toContain(`/hosts/${id("tenko1")}/decommission`);
    expect(sent[0]?.body).toEqual({ reason: "Cloned by mistake", keep_dns: false });
    expect(ipamState().data.host.get(id("tenko1"))?.decommissioned).toBeTruthy();
    // The host that is retired has no button any more; the other one has.
    await waitFor(() => expect(decommissionButtons().map((b) => b.dataset.host)).toEqual([id("ha")]));
  });
});

describe("keeping both claims", () => {
  it("asks for a reason and posts it at the revision of the proposal", async () => {
    stopBridge = bridgeMockEvents();
    const writes = recordWrites();
    const conflict = putAddressConflict({ rule: SHARED, ip: "192.0.2.77", hosts: [id("ha"), id("tenko1")] });
    await openPanel(conflict.id);
    fireEvent.click(await screen.findByTestId("conflict-keep"));
    const dialog = await screen.findByTestId("dialog-keep");
    expect(within(dialog).getByRole("heading", { name: "Keep both claims" })).toBeTruthy();
    expect(dialog.textContent).toContain("not raised again while the same devices share the address");
    fireEvent.input(within(dialog).getByTestId("keep-reason"), { target: { value: "  A cluster with a floating address  " } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await gone("dialog-keep");

    const sent = applied(writes()).filter((w) => w.url.includes("/keep"));
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toContain(`/proposals/${conflict.id}/keep`);
    expect(sent[0]?.body).toEqual({ reason: "A cluster with a floating address" });
    expect(sent[0]?.headers["If-Match"]).toBe(`"${conflict.revision}"`);
    expect(stored(conflict.id)).toMatchObject({ state: "rejected", reason: "A cluster with a floating address" });
    expect(await screen.findByText("Kept both claims")).toBeTruthy();
    // The panel follows the decision: nothing is left to decide.
    await waitFor(() => expect(screen.queryByTestId("conflict-keep")).toBeNull());
    expect(decommissionButtons()).toHaveLength(0);
  });

  it("sends no reason when none is given, and refuses a reason that is too long", async () => {
    const writes = recordWrites();
    const conflict = putAddressConflict({ rule: TAKEN, ip: "192.0.2.77", hosts: [id("ha"), id("tenko1")] });
    await openPanel(conflict.id);
    fireEvent.click(await screen.findByTestId("conflict-keep"));
    const dialog = await screen.findByTestId("dialog-keep");
    const submit = within(dialog).getByTestId("form-submit") as HTMLButtonElement;
    fireEvent.input(within(dialog).getByTestId("keep-reason"), { target: { value: "x".repeat(1025) } });
    expect(submit.disabled).toBe(true);
    fireEvent.input(within(dialog).getByTestId("keep-reason"), { target: { value: "" } });
    expect(submit.disabled).toBe(false);
    fireEvent.click(submit);
    await gone("dialog-keep");
    expect(applied(writes()).filter((w) => w.url.includes("/keep"))[0]?.body).toEqual({ reason: null });
    expect(stored(conflict.id)?.state).toBe("rejected");
  });

  it("leaves the conflict open when cancelled and shows what the server refuses", async () => {
    const writes = recordWrites();
    const conflict = putAddressConflict({ rule: SHARED, ip: "192.0.2.77", hosts: [id("ha"), id("tenko1")] });
    await openPanel(conflict.id);
    fireEvent.click(await screen.findByTestId("conflict-keep"));
    fireEvent.click(within(await screen.findByTestId("dialog-keep")).getByRole("button", { name: "Cancel" }));
    await gone("dialog-keep");
    expect(writes()).toHaveLength(0);
    expect(stored(conflict.id)?.state).toBe("open");

    // Somebody else decided it meanwhile: the answer is the server's.
    fireEvent.click(screen.getByTestId("conflict-keep"));
    const dialog = await screen.findByTestId("dialog-keep");
    reconcileState().proposals.set(conflict.id, { ...conflict, state: "rejected", revision: (conflict.revision ?? 0) + 1000 });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const notice = await within(dialog).findByTestId("error-notice");
    expect(notice.getAttribute("data-code")).toBe("ipam.proposal.revision_mismatch");
    expect(screen.getByTestId("dialog-keep")).toBeTruthy();
  });
});
