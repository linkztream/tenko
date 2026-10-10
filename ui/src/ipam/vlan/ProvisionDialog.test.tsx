import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { applyCommands, IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import { server } from "../../api/mock/node";
import { mockVlanController } from "../../api/mock/routes-vlans";
import type { Vlan } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import VlansView from "../tenancy/VlansView";
import type { VlanProvisionPreview, VlanProvisionSubmitted } from "./api";
import { ProvisionDialog } from "./ProvisionDialog";

/** A free network inside the documentation supernet of the seed. */
const FREE_NET = "203.0.113.208/28";
const CONTROLLER = "unifi.example.test";

beforeEach(async () => {
  await signInAlex();
});

const vlanOf = (vid: number): Vlan => {
  const found = [...ipamState().data.vlan.values()].find((v) => v.vid === vid);
  if (!found) throw new Error(`no VLAN ${vid} in the mock`);
  return found;
};
const hasVlan = (vid: number) => [...ipamState().data.vlan.values()].some((v) => v.vid === vid && !v.meta.deleted);

/** Renders the dialog on its own, for a new VLAN or an existing one. */
function open(vlan?: Vlan) {
  const done = vi.fn();
  const close = vi.fn();
  const view = renderRoute(() => <ProvisionDialog vlan={vlan} onDone={done} onClose={close} />, {
    routes: { "/jobs/:id": () => <div data-testid="job-page" /> },
  });
  return { done, close, view };
}

const dialog = () => screen.findByTestId("dialog-vlan-provision");
const field = (id: string) => within(screen.getByTestId("dialog-vlan-provision")).getByTestId(`field-${id}`);
const type = (id: string, value: string) => fireEvent.input(field(id), { target: { value } });
const choose = (id: string, value: string) => fireEvent.change(field(id), { target: { value } });
const click = (testid: string) => fireEvent.click(within(screen.getByTestId("dialog-vlan-provision")).getByTestId(testid));
const confirm = () => within(screen.getByTestId("dialog-vlan-provision")).getByTestId("vlan-provision-confirm") as HTMLButtonElement;

/** Fills the form of a new VLAN; a network when `cidr` is given. */
function fillNew(values: { vid?: string; name?: string; cidr?: string | null } = {}) {
  type("vid", values.vid ?? "60");
  type("name", values.name ?? "Guests");
  const cidr = values.cidr === undefined ? FREE_NET : values.cidr;
  if (cidr !== null) {
    click("field-with-prefix");
    type("cidr", cidr);
  }
}

/** Sends the form and waits for the preview. */
async function preview(): Promise<HTMLElement> {
  click("form-submit");
  return screen.findByTestId("vlan-provision-preview");
}

const stepKinds = (root: HTMLElement) => within(root).getAllByTestId("vlan-provision-step").map((s) => s.dataset.kind);
const ackCodes = (root: HTMLElement) => within(root).queryAllByTestId("plan-ack").map((a) => a.dataset.code);

describe("the form", () => {
  it("asks for a new VLAN and, on request, its network and how the network gets onto the switches", async () => {
    open();
    const dlg = await dialog();
    for (const id of ["vid", "name", "site", "vni", "description", "with-prefix", "controller-auto", "controller-manual", "network-name", "dhcp-relay"]) {
      expect(within(dlg).getByTestId(`field-${id}`), id).toBeTruthy();
    }
    expect((field("controller-auto") as HTMLInputElement).checked).toBe(true);
    expect(within(dlg).queryByTestId("field-cidr")).toBeNull();
    expect(within(dlg).queryByTestId("field-vrf")).toBeNull();
    expect(within(dlg).queryByTestId("field-connector")).toBeNull();
    click("field-with-prefix");
    expect(field("cidr")).toBeTruthy();
    // The VRF choice starts at the default VRF and lists the VRFs of the API.
    await waitFor(() => expect([...(field("vrf") as HTMLSelectElement).options].map((o) => o.textContent)).toEqual(["Default VRF", "default", "isolated"]));
    expect((field("vrf") as HTMLSelectElement).value).toBe("");
    // The sites come from the API too.
    await waitFor(() => expect([...(field("site") as HTMLSelectElement).options].map((o) => o.textContent)).toContain("Home"));
    expect(await axeViolations(dlg)).toEqual([]);
  });

  it("shows the network name placeholder as the VLAN name and hides the relays for a network made by hand", async () => {
    open();
    const dlg = await dialog();
    expect((field("network-name") as HTMLInputElement).placeholder).toBe("The VLAN name");
    type("name", "Guests");
    expect((field("network-name") as HTMLInputElement).placeholder).toBe("Guests");
    click("field-controller-manual");
    expect(within(dlg).queryByTestId("field-dhcp-relay")).toBeNull();
    click("field-controller-auto");
    expect(within(dlg).getByTestId("field-dhcp-relay")).toBeTruthy();
  });

  it("closes with Cancel", async () => {
    const { close } = open();
    const dlg = await dialog();
    fireEvent.click(within(dlg).getByRole("button", { name: "Cancel" }));
    expect(close).toHaveBeenCalledTimes(1);
  });
});

describe("local validation", () => {
  it("refuses a VLAN id, a name, a network and relays that cannot be right, with the messages under the fields", async () => {
    open();
    const dlg = await dialog();
    fillNew({ vid: "5000", name: "", cidr: "203.0.113.209/28" });
    type("dhcp-relay", "192.0.2.53 dhcp.example.test");
    click("form-submit");
    expect(await within(dlg).findByText("Enter a VLAN id from 1 to 4094.")).toBeTruthy();
    expect(within(dlg).getByText("Enter a name.")).toBeTruthy();
    expect(within(dlg).getByText(/Enter a network in CIDR form/)).toBeTruthy();
    expect(within(dlg).getByText("dhcp.example.test is not a valid IPv4 or IPv6 address.")).toBeTruthy();
    expect(field("vid").getAttribute("aria-invalid")).toBe("true");
    await waitFor(() => expect(document.activeElement).toBe(field("vid")));
    // Nothing was asked of the server.
    expect(screen.queryByTestId("vlan-provision-preview")).toBeNull();
    expect(hasVlan(5000)).toBe(false);
    expect(await axeViolations(dlg)).toEqual([]);

    // Fixing the values lets the preview through.
    type("vid", "60");
    type("name", "Guests");
    type("cidr", FREE_NET);
    type("dhcp-relay", "192.0.2.53, 2001:db8::53");
    await preview();
    expect(within(dlg).queryByText("Enter a name.")).toBeNull();
  });

  it("refuses more than eight relays and a network name that is too long", async () => {
    open();
    const dlg = await dialog();
    fillNew({ cidr: null });
    type("dhcp-relay", Array.from({ length: 9 }, (_, i) => `192.0.2.${50 + i}`).join(" "));
    type("network-name", "x".repeat(65));
    click("form-submit");
    expect(await within(dlg).findByText("Enter at most 8 relay addresses.")).toBeTruthy();
    expect(within(dlg).getByText("Use at most 64 characters.")).toBeTruthy();
    expect(screen.queryByTestId("vlan-provision-preview")).toBeNull();
  });

  it("refuses a VNI out of range and a network without a length", async () => {
    open();
    const dlg = await dialog();
    fillNew({ cidr: "203.0.113.208" });
    type("vni", "16777216");
    click("form-submit");
    expect(await within(dlg).findByText("Enter a VNI from 0 to 16777215.")).toBeTruthy();
    expect(within(dlg).getByText(/Enter a network in CIDR form/)).toBeTruthy();
  });
});

describe("the preview of a new VLAN with a network", () => {
  it("shows an automatic network step with two diff lines, the IPAM plan and the three steps of the job", async () => {
    open();
    const dlg = await dialog();
    fillNew();
    const prev = await preview();
    // Nothing is written by a preview.
    expect(hasVlan(60)).toBe(false);

    const controller = within(prev).getByTestId("vlan-provision-controller");
    expect(controller.dataset.mode).toBe("automatic");
    expect(within(controller).getByTestId("vlan-provision-mode").textContent).toBe("Automatic");
    expect(within(controller).getByTestId("vlan-provision-connector").textContent).toContain(CONTROLLER);
    expect(within(controller).getByTestId("vlan-provision-network").textContent).toBe("Guests");
    expect(within(controller).getByTestId("vlan-provision-relays").textContent).toMatch(/DHCP service of the controller stays off/);
    expect(within(controller).queryByTestId("vlan-provision-reason")).toBeNull();
    const lines = within(controller).getAllByTestId("diff-line");
    expect(lines.map((l) => l.dataset.key)).toEqual(["networks/vlan-60/name", "networks/vlan-60/vlan"]);
    expect(lines[0]?.textContent).toContain("absent");
    expect(lines[0]?.textContent).toContain("Guests");
    expect(lines[1]?.textContent).toContain("60");
    expect(within(controller).queryByTestId("vlan-provision-unchanged")).toBeNull();
    expect(within(controller).queryByTestId("vlan-provision-notes")).toBeNull();
    expect(controller.textContent).toContain("Read from the controller");

    // The VLAN and the network that will exist, and the IPAM plan.
    expect(within(prev).getByTestId("vlan-provision-vlan").textContent).toMatch(/60.*Guests.*Planned/);
    expect(within(prev).getByTestId("vlan-provision-prefix").dataset.key).toBe(FREE_NET);
    expect(within(prev).getAllByTestId("plan-change").map((c) => c.dataset.kind)).toEqual(["vlan", "prefix"]);

    // The steps of the job, in order, with their words.
    const steps = within(prev).getAllByTestId("vlan-provision-step");
    expect(stepKinds(prev)).toEqual(["ipam.intent", "l2.network", "activate"]);
    expect(steps.map((s) => s.dataset.mode)).toEqual(["automatic", "automatic", "automatic"]);
    expect(steps[0]?.textContent).toContain(`Create VLAN 60 (Guests) and the network ${FREE_NET} in IPAM as planned.`);
    expect(steps[1]?.textContent).toContain(`Create the network Guests on VLAN 60 through ${CONTROLLER}: dry run, write, read back and compare.`);
    expect(steps[2]?.textContent).toContain("Make VLAN 60 and its network active.");

    expect(ackCodes(prev)).toEqual([]);
    expect(confirm().disabled).toBe(false);
    // The keyboard lands on Start.
    await waitFor(() => expect(document.activeElement).toBe(confirm()));
    expect(within(dlg).queryByTestId("vlan-provision-error")).toBeNull();
    expect(await axeViolations(dlg)).toEqual([]);
  });

  it("names the network and the relays it asked for", async () => {
    open();
    await dialog();
    fillNew();
    type("network-name", "Visitors");
    type("dhcp-relay", "2001:DB8::53, 192.0.2.53");
    const prev = await preview();
    expect(within(prev).getByTestId("vlan-provision-network").textContent).toBe("Visitors");
    expect(within(prev).getByTestId("vlan-provision-relays").textContent).toBe("2001:db8::53, 192.0.2.53");
    expect(within(prev).getAllByTestId("diff-line")[0]?.textContent).toContain("Visitors");
    expect(within(prev).getAllByTestId("vlan-provision-step")[1]?.textContent).toContain("Create the network Visitors on VLAN 60");
  });

  it("starts the job: the answer reaches the page, the VLAN exists and the toast links to the job", async () => {
    const { done, view } = open();
    await dialog();
    fillNew();
    await preview();
    click("vlan-provision-confirm");
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const result = done.mock.calls[0]?.[0] as VlanProvisionSubmitted;
    expect(result.job_id).toBeTruthy();
    expect(result.preview.vlan).toMatchObject({ vid: 60, name: "Guests" });
    expect(hasVlan(60)).toBe(true);
    const toast = (await screen.findAllByTestId("toast"))[0] as HTMLElement;
    expect(toast.textContent).toContain("Started the network job for VLAN 60");
    fireEvent.click(within(toast).getByTestId("toast-action"));
    await waitFor(() => expect(view.location()).toBe(`/jobs/${result.job_id}`));
  });

  it("goes back to the form with its values and previews again", async () => {
    open();
    const dlg = await dialog();
    fillNew();
    type("vni", "5000");
    type("description", "Visitors");
    type("network-name", "Visitors");
    type("dhcp-relay", "192.0.2.53");
    await preview();
    click("vlan-provision-back");
    await within(dlg).findByTestId("vlan-provision-form");
    expect(screen.queryByTestId("vlan-provision-preview")).toBeNull();
    expect((field("vid") as HTMLInputElement).value).toBe("60");
    expect((field("name") as HTMLInputElement).value).toBe("Guests");
    expect((field("vni") as HTMLInputElement).value).toBe("5000");
    expect((field("description") as HTMLInputElement).value).toBe("Visitors");
    expect((field("with-prefix") as HTMLInputElement).checked).toBe(true);
    expect((field("cidr") as HTMLInputElement).value).toBe(FREE_NET);
    expect((field("network-name") as HTMLInputElement).value).toBe("Visitors");
    expect((field("dhcp-relay") as HTMLInputElement).value).toBe("192.0.2.53");
    expect((field("controller-auto") as HTMLInputElement).checked).toBe(true);
    // A single controller is not a choice.
    expect(within(dlg).queryByTestId("field-connector")).toBeNull();
    type("name", "Visitors");
    const again = await preview();
    expect(within(again).getByTestId("vlan-provision-vlan").textContent).toContain("Visitors");
    expect(hasVlan(60)).toBe(false);
  });

  it("closes with Cancel from the preview", async () => {
    const { close } = open();
    const dlg = await dialog();
    fillNew();
    await preview();
    fireEvent.click(within(dlg).getByRole("button", { name: "Cancel" }));
    expect(close).toHaveBeenCalledTimes(1);
    expect(hasVlan(60)).toBe(false);
  });
});

describe("a network made by hand", () => {
  it("previews a manual step with its reason and the steps of the job", async () => {
    const { done } = open();
    const dlg = await dialog();
    fillNew();
    click("field-controller-manual");
    const prev = await preview();
    const controller = within(prev).getByTestId("vlan-provision-controller");
    expect(controller.dataset.mode).toBe("manual");
    const reason = within(controller).getByTestId("vlan-provision-reason");
    expect(reason.dataset.code).toBe("ipam.vlan.manual_requested");
    expect(reason.textContent).toBe("You chose to create the network by hand.");
    expect(within(controller).getByTestId("vlan-provision-mode").textContent).toBe("By hand");
    expect(within(controller).getByTestId("vlan-provision-connector").textContent).toBe("No network controller");
    expect(within(controller).queryByTestId("vlan-provision-diff")).toBeNull();
    const steps = within(prev).getAllByTestId("vlan-provision-step");
    expect(steps.map((s) => [s.dataset.kind, s.dataset.mode])).toEqual([
      ["ipam.intent", "automatic"],
      ["l2.manual", "manual"],
      ["activate", "automatic"],
    ]);
    expect(steps[1]?.textContent).toContain("Create the network Guests on VLAN 60 on the switches and access points, then mark the step done.");
    expect(ackCodes(prev)).toEqual([]);
    expect(await axeViolations(dlg)).toEqual([]);
    click("vlan-provision-confirm");
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect((done.mock.calls[0]?.[0] as VlanProvisionSubmitted).preview.controller.mode).toBe("manual");
    // The controller was left alone.
    expect(mockVlanController.networks.some((n) => n.vlan === 60)).toBe(false);
  });

  it("explains that no network controller is configured", async () => {
    mockVlanController.present = false;
    open();
    await dialog();
    fillNew();
    const prev = await preview();
    const reason = within(prev).getByTestId("vlan-provision-reason");
    expect(reason.dataset.code).toBe("ipam.vlan.no_controller");
    expect(reason.textContent).toMatch(/No network controller is configured/);
    expect(within(prev).getByTestId("vlan-provision-controller").dataset.mode).toBe("manual");
    expect(stepKinds(prev)).toEqual(["ipam.intent", "l2.manual", "activate"]);
    expect(confirm().disabled).toBe(false);
  });
});

describe("a controller that does not allow writes", () => {
  beforeEach(() => {
    mockVlanController.writes_enabled = false;
  });

  it("shows the reason and the planned diff, and Start waits for the acknowledgement", async () => {
    const { done } = open();
    const dlg = await dialog();
    fillNew();
    const prev = await preview();
    const controller = within(prev).getByTestId("vlan-provision-controller");
    expect(controller.dataset.mode).toBe("manual");
    expect(within(controller).getByTestId("vlan-provision-reason").dataset.code).toBe("ipam.vlan.controller_read_only");
    expect(within(controller).getByTestId("vlan-provision-connector").textContent).toMatch(/Read only/);
    expect(within(controller).getAllByTestId("diff-line")).toHaveLength(2);
    expect(stepKinds(prev)).toEqual(["ipam.intent", "l2.manual", "activate"]);

    const warnings = within(prev).getByTestId("vlan-provision-warnings");
    expect(warnings.textContent).toContain(`Writes through ${CONTROLLER} are switched off.`);
    expect(ackCodes(prev)).toEqual(["ipam.vlan.controller_read_only"]);
    expect(confirm().disabled).toBe(true);
    // Start cannot take the keyboard: the acknowledgement does.
    await waitFor(() => expect(document.activeElement).toBe(within(prev).getByTestId("plan-ack")));
    expect(within(dlg).getByText("Acknowledge the marked warnings to continue.")).toBeTruthy();
    expect(await axeViolations(dlg)).toEqual([]);

    fireEvent.click(within(prev).getByTestId("plan-ack"));
    expect(confirm().disabled).toBe(false);
    // Unticking takes it away again.
    fireEvent.click(within(prev).getByTestId("plan-ack"));
    expect(confirm().disabled).toBe(true);
    fireEvent.click(within(prev).getByTestId("plan-ack"));
    click("vlan-provision-confirm");
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const submitted = done.mock.calls[0]?.[0] as VlanProvisionSubmitted;
    expect(submitted.preview.warnings?.[0]).toMatchObject({ code: "ipam.vlan.controller_read_only", acknowledged: true });
    expect(mockVlanController.networks.some((n) => n.vlan === 60)).toBe(false);
  });

  it("asks for the warnings of the IPAM plan and of the network step, each with its own acknowledgement", async () => {
    open();
    await dialog();
    fillNew({ vid: "62", name: "Six", cidr: "2001:db8:0:60::/62" });
    const prev = await preview();
    expect(ackCodes(prev).sort()).toEqual(["ipam.prefix.nibble_boundary", "ipam.vlan.controller_read_only"]);
    expect(within(within(prev).getByTestId("plan-blocking")).getByTestId("plan-ack").dataset.code).toBe("ipam.prefix.nibble_boundary");
    expect(confirm().disabled).toBe(true);
    fireEvent.click(within(within(prev).getByTestId("plan-blocking")).getByTestId("plan-ack"));
    expect(confirm().disabled).toBe(true);
    fireEvent.click(within(within(prev).getByTestId("vlan-provision-warnings")).getByTestId("plan-ack"));
    expect(confirm().disabled).toBe(false);
  });

  it("has nothing to acknowledge for a network the controller has already", async () => {
    open(vlanOf(30));
    await dialog();
    const prev = await preview();
    expect(within(prev).getByTestId("vlan-provision-controller").dataset.mode).toBe("unchanged");
    expect(ackCodes(prev)).toEqual([]);
    expect(confirm().disabled).toBe(false);
  });
});

describe("errors", () => {
  it("shows the guardrail of the management VLAN with the way out, and lets the person go on by hand", async () => {
    open();
    const dlg = await dialog();
    fillNew({ vid: "10", name: "Core", cidr: null });
    click("form-submit");
    const error = await within(dlg).findByTestId("vlan-provision-error");
    expect(error.dataset.code).toBe("connect.guardrail.protected_vlan");
    expect(error.textContent).toContain("This VLAN is protected: Tenko or the controller is managed through it.");
    expect(within(error).getByTestId("vlan-provision-hint").textContent).toMatch(/Choose By hand to create the VLAN in IPAM only/);
    expect(screen.queryByTestId("vlan-provision-preview")).toBeNull();
    expect(hasVlan(10)).toBe(true);
    expect(await axeViolations(dlg)).toEqual([]);

    // By hand, the VLAN is created in IPAM only.
    click("field-controller-manual");
    const prev = await preview();
    expect(within(dlg).queryByTestId("vlan-provision-error")).toBeNull();
    expect(within(prev).getByTestId("vlan-provision-controller").dataset.mode).toBe("manual");
    expect(stepKinds(prev)).toEqual(["ipam.intent", "l2.manual", "activate"]);
  });

  it("shows the error of a VLAN id that exists at the site", async () => {
    open();
    const dlg = await dialog();
    fillNew({ vid: "30", name: "More", cidr: null });
    await waitFor(() => expect([...(field("site") as HTMLSelectElement).options].map((o) => o.textContent)).toContain("Home"));
    choose("site", IPAM_IDS.site.home);
    click("form-submit");
    const error = await within(dlg).findByTestId("vlan-provision-error");
    expect(error.dataset.code).toBe("ipam.vlan.duplicate");
    expect(error.textContent).toContain("VLAN 30 already exists at this site.");
    // A duplicate has nothing to do with the controller.
    expect(within(error).queryByTestId("vlan-provision-hint")).toBeNull();
  });

  it("shows the error of a network that overlaps another", async () => {
    open();
    const dlg = await dialog();
    fillNew({ cidr: "198.51.100.0/24" });
    click("form-submit");
    const error = await within(dlg).findByTestId("vlan-provision-error");
    expect(error.dataset.code).toBe("ipam.prefix.overlap");
  });

  it("keeps the same Idempotency-Key when the start is retried after a failure", async () => {
    const keys: (string | null)[] = [];
    let failures = 1;
    server.use(
      http.post("/api/v1/vlans/provision", ({ request }) => {
        if (new URL(request.url).searchParams.get("dry_run") === "true") return undefined;
        keys.push(request.headers.get("idempotency-key"));
        if (failures-- > 0) {
          return HttpResponse.json(
            { code: "connect.unreachable", status: 502, title: "Bad Gateway", detail: "no answer", params: {} },
            { status: 502, headers: { "content-type": "application/problem+json" } },
          );
        }
        return undefined;
      }),
    );
    const { done } = open();
    const dlg = await dialog();
    fillNew();
    await preview();
    click("vlan-provision-confirm");
    const error = await within(dlg).findByTestId("vlan-provision-error");
    expect(error.dataset.code).toBe("connect.unreachable");
    expect(error.textContent).toContain("The remote system cannot be reached.");
    // The preview stays; the controller error offers the way by hand.
    expect(within(error).getByTestId("vlan-provision-hint")).toBeTruthy();
    expect(done).not.toHaveBeenCalled();
    await waitFor(() => expect(confirm().disabled).toBe(false));
    click("vlan-provision-confirm");
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBeTruthy();
    expect(keys[1]).toBe(keys[0]);
  });

  it("previews again, with a note, when the data changed since the preview", async () => {
    let refused = false;
    server.use(
      http.post("/api/v1/vlans/provision", ({ request }) => {
        if (new URL(request.url).searchParams.get("dry_run") === "true" || refused) return undefined;
        refused = true;
        return HttpResponse.json(
          { code: "ipam.plan.stale", status: 409, title: "Conflict", detail: "stale", params: {} },
          { status: 409, headers: { "content-type": "application/problem+json" } },
        );
      }),
    );
    const { done } = open();
    const dlg = await dialog();
    fillNew();
    await preview();
    click("vlan-provision-confirm");
    expect(await within(dlg).findByText("The data changed since the preview. This is a new preview.")).toBeTruthy();
    expect(done).not.toHaveBeenCalled();
    await waitFor(() => expect(confirm().disabled).toBe(false));
    click("vlan-provision-confirm");
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
  });
});

describe("several network controllers", () => {
  const first = "0190d1c2-0000-7000-8000-00000c000001";
  const second = "0190d1c2-0000-7000-8000-00000c000002";
  const infos = [
    { id: first, name: "unifi-a.example.test", plugin: "unifi", enabled: true, writes_enabled: true },
    { id: second, name: "unifi-b.example.test", plugin: "unifi", enabled: true, writes_enabled: true },
  ];
  const vlan = { id: "0190d1c2-0000-7000-8000-0000000400a1", vid: 60, name: "Guests", existing: false, status: "planned" as const };

  const answer = (connector: string | undefined): VlanProvisionPreview => {
    const chosen = infos.find((c) => c.id === connector);
    const network = { vid: 60, name: "Guests" };
    if (!chosen) {
      return {
        vlan,
        controller: { mode: "manual", reason: "ipam.vlan.controller_ambiguous", network, candidates: infos },
        steps: [{ kind: "l2.manual", step_kind: "ipam.vlan.manual", automatic: false, text: "By hand", params: { vid: "60", name: "Guests" } }],
        warnings: [
          { code: "ipam.vlan.controller_ambiguous", message: "Two controllers", params: { count: "2" }, requires_ack: true, acknowledged: false },
        ],
        unacknowledged: ["ipam.vlan.controller_ambiguous"],
        base_revision: 1,
      };
    }
    return {
      vlan,
      controller: {
        mode: "automatic",
        connector: chosen,
        network,
        diff: [{ path: "networks/vlan-60/name", after: "Guests" }],
        warnings: ["The controller note, in English."],
        candidates: infos,
      },
      steps: [{ kind: "l2.network", step_kind: "ipam.vlan.controller", automatic: true, text: "Network", params: { vid: "60", name: "Guests", connector: chosen.name } }],
      base_revision: 1,
    };
  };

  it("asks which controller to use when none is named, and previews again with the one chosen", async () => {
    const bodies: { connector?: string }[] = [];
    server.use(
      http.post("/api/v1/vlans/provision", async ({ request }) => {
        const body = (await request.clone().json()) as { connector?: string };
        bodies.push(body);
        return HttpResponse.json(answer(body.connector));
      }),
    );
    open();
    const dlg = await dialog();
    fillNew({ cidr: null });
    expect(within(dlg).queryByTestId("field-connector")).toBeNull();

    const prev = await preview();
    const controller = within(prev).getByTestId("vlan-provision-controller");
    expect(within(controller).getByTestId("vlan-provision-reason").dataset.code).toBe("ipam.vlan.controller_ambiguous");
    expect(ackCodes(prev)).toEqual(["ipam.vlan.controller_ambiguous"]);
    expect(within(prev).getByTestId("vlan-provision-warnings").textContent).toContain("Several network controllers are configured and none is chosen.");
    expect(confirm().disabled).toBe(true);

    // Back to the form: the controllers the preview listed are a choice now.
    click("vlan-provision-back");
    await within(dlg).findByTestId("vlan-provision-form");
    const select = field("connector") as HTMLSelectElement;
    expect([...select.options].map((o) => o.textContent)).toEqual(["Not chosen", "unifi-a.example.test", "unifi-b.example.test"]);
    choose("connector", second);
    const chosen = await preview();
    expect(bodies.map((b) => b.connector)).toEqual([undefined, second]);
    const controller2 = within(chosen).getByTestId("vlan-provision-controller");
    expect(controller2.dataset.mode).toBe("automatic");
    expect(within(controller2).getByTestId("vlan-provision-connector").textContent).toContain("unifi-b.example.test");
    expect(ackCodes(chosen)).toEqual([]);
    expect(confirm().disabled).toBe(false);
    // The notes of the controller are shown as they are.
    expect(within(controller2).getByTestId("vlan-provision-notes").textContent).toContain("The controller note, in English.");

    // By hand names no connector.
    click("vlan-provision-back");
    await within(dlg).findByTestId("vlan-provision-form");
    click("field-controller-manual");
    expect(within(dlg).queryByTestId("field-connector")).toBeNull();
    await preview();
    expect(bodies[2]).toMatchObject({ manual: true });
    expect(bodies[2]?.connector).toBeUndefined();
  });
});

describe("an existing VLAN", () => {
  it("has the network step only, with the id and the name read only", async () => {
    const { done } = open(vlanOf(20));
    const dlg = await dialog();
    expect(within(dlg).getByRole("heading", { name: "Put VLAN 20 onto the network" })).toBeTruthy();
    expect((field("vid") as HTMLInputElement).value).toBe("20");
    expect((field("vid") as HTMLInputElement).readOnly).toBe(true);
    expect((field("name") as HTMLInputElement).value).toBe("Lab");
    expect((field("name") as HTMLInputElement).readOnly).toBe(true);
    expect(within(dlg).queryByTestId("field-site")).toBeNull();
    expect(within(dlg).queryByTestId("field-vni")).toBeNull();
    expect((field("network-name") as HTMLInputElement).placeholder).toBe("Lab");
    expect(await axeViolations(dlg)).toEqual([]);

    const prev = await preview();
    expect(stepKinds(prev)).toEqual(["l2.network"]);
    expect(within(prev).queryByTestId("plan-preview")).toBeNull();
    expect(within(prev).queryByTestId("vlan-provision-prefix")).toBeNull();
    expect(within(prev).getByTestId("vlan-provision-vlan").textContent).toMatch(/20.*Lab.*Active/);
    const controller = within(prev).getByTestId("vlan-provision-controller");
    expect(controller.dataset.mode).toBe("automatic");
    expect(within(controller).getAllByTestId("diff-line")).toHaveLength(2);
    expect(await axeViolations(dlg)).toEqual([]);
    click("vlan-provision-confirm");
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect(mockVlanController.networks.find((n) => n.vlan === 20)?.name).toBe("Lab");
  });

  it("is unchanged when the controller has the network as asked", async () => {
    open(vlanOf(30));
    await dialog();
    const prev = await preview();
    const controller = within(prev).getByTestId("vlan-provision-controller");
    expect(controller.dataset.mode).toBe("unchanged");
    expect(within(controller).getByTestId("vlan-provision-unchanged").textContent).toBe("The controller already has the network as asked. Nothing is written.");
    expect(within(controller).queryByTestId("vlan-provision-diff")).toBeNull();
    expect(within(prev).getByTestId("vlan-provision-step").textContent).toContain(`Check that ${CONTROLLER} has the network IoT on VLAN 30.`);
    expect(confirm().disabled).toBe(false);
  });

  it("asks for an acknowledgement when the write changes a network the controller has", async () => {
    const { done } = open(vlanOf(30));
    const dlg = await dialog();
    type("network-name", "Things");
    const prev = await preview();
    const line = within(prev).getByTestId("diff-line");
    expect(line.dataset.key).toBe("networks/vlan-30/name");
    expect(line.textContent).toContain("IoT");
    expect(line.textContent).toContain("Things");
    expect(ackCodes(prev)).toEqual(["ipam.vlan.network_changes"]);
    expect(within(prev).getByTestId("vlan-provision-warnings").textContent).toContain("The controller already has a network on VLAN 30.");
    expect(confirm().disabled).toBe(true);
    expect(await axeViolations(dlg)).toEqual([]);
    fireEvent.click(within(prev).getByTestId("plan-ack"));
    click("vlan-provision-confirm");
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect(mockVlanController.networks.find((n) => n.vlan === 30)?.name).toBe("Things");
  });

  it("can also create a network for the VLAN in IPAM", async () => {
    open(vlanOf(20));
    await dialog();
    click("field-with-prefix");
    type("cidr", FREE_NET);
    const prev = await preview();
    expect(within(prev).getAllByTestId("plan-change").map((c) => c.dataset.kind)).toEqual(["prefix"]);
    expect(stepKinds(prev)).toEqual(["ipam.intent", "l2.network", "activate"]);
    expect(within(prev).getAllByTestId("vlan-provision-step")[0]?.textContent).toContain(`Create the network ${FREE_NET} for VLAN 20 (Lab) in IPAM as planned.`);
  });
});

describe("the VLAN page", () => {
  const rowsOf = (grid: HTMLElement) => within(grid).queryAllByTestId("row");
  const keysOf = (grid: HTMLElement) => rowsOf(grid).map((r) => r.dataset.key);

  async function loaded() {
    const view = renderRoute(VlansView, { url: "/ipam/vlans", routes: { "/jobs/:id": () => <div data-testid="job-page" /> } });
    const grid = await screen.findByTestId("grid-vlans");
    await waitFor(() => expect(rowsOf(grid)).toHaveLength(6));
    return { grid, view };
  }

  async function chooseRowAction(grid: HTMLElement, row: string, action: string) {
    const rowEl = rowsOf(grid).find((r) => r.dataset.key === row) as HTMLElement;
    fireEvent.click(within(rowEl).getByRole("button", { name: `Actions for ${row}` }));
    const menu = await screen.findByTestId("row-menu");
    const item = within(menu).getAllByTestId("menu-item").find((i) => i.dataset.key === action) as HTMLElement;
    return item;
  }

  it("creates a VLAN with its network from the page action and reloads the list", async () => {
    const { grid } = await loaded();
    fireEvent.click(screen.getByTestId("vlan-provision"));
    await dialog();
    fillNew();
    await preview();
    click("vlan-provision-confirm");
    await waitFor(() => expect(screen.queryByTestId("dialog-vlan-provision")).toBeNull());
    await waitFor(() => expect(keysOf(grid)).toContain("60 Guests"));
    const toast = (await screen.findAllByTestId("toast"))[0] as HTMLElement;
    expect(toast.textContent).toContain("Started the network job for VLAN 60");
    expect(within(toast).getByTestId("toast-action").textContent).toBe("Open job");
  });

  it("puts an existing VLAN onto the network from its row", async () => {
    const { grid } = await loaded();
    const item = await chooseRowAction(grid, "20 Lab", "provision");
    expect(item.getAttribute("aria-disabled")).toBeNull();
    fireEvent.click(item);
    const dlg = await dialog();
    expect(within(dlg).getByRole("heading", { name: "Put VLAN 20 onto the network" })).toBeTruthy();
    expect((field("vid") as HTMLInputElement).value).toBe("20");
    const prev = await preview();
    expect(stepKinds(prev)).toEqual(["l2.network"]);
    click("vlan-provision-confirm");
    await waitFor(() => expect(screen.queryByTestId("dialog-vlan-provision")).toBeNull());
    expect(mockVlanController.networks.some((n) => n.vlan === 20)).toBe(true);
  });

  it("does not offer to put a deleted VLAN onto the network", async () => {
    applyCommands([{ op: "delete", args: { object: { kind: "vlan", id: IPAM_IDS.vlan.v50 }, expected: null, cascade: false } }] as never);
    expect(hasVlan(50)).toBe(false);
    renderRoute(VlansView, { url: "/ipam/vlans" });
    const grid = await screen.findByTestId("grid-vlans");
    await waitFor(() => expect(rowsOf(grid)).toHaveLength(5));
    fireEvent.click(within(screen.getByRole("group", { name: "Deleted objects" })).getByRole("button", { name: "With deleted" }));
    await waitFor(() => expect(rowsOf(grid)).toHaveLength(6));
    const item = await chooseRowAction(grid, "50 Guest", "provision");
    expect(item.getAttribute("aria-disabled")).toBe("true");
  });

  it("has no accessibility violations with the new actions", async () => {
    const { grid } = await loaded();
    expect(screen.getByTestId("vlan-provision").textContent).toContain("Create with network");
    const item = await chooseRowAction(grid, "30 IoT", "prefixes");
    expect(item.textContent).toBe("Prefixes");
    expect(await axeViolations(screen.getByTestId("page-ipam-vlans"))).toEqual([]);
  });
});
