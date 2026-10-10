import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../../api/client";
import { bridgeMockEvents } from "../../audit/testkit";
import { IPAM_IDS } from "../../api/mock/ipam/api";
import { server } from "../../api/mock/node";
import { reconcileState } from "../../api/mock/reconcile-store";
import type { Prefix } from "../../api/types";
import { paths } from "../../app/paths";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { getAdoptionPolicy, setAdoptionPolicy } from "../../discovery/api";
import { resetRefs } from "../../discovery/refs";
import IpamView from "../IpamView";
import { chooseVrf } from "../scope";
import { applied, recordWrites } from "../testkit";
import { AdoptionPanel, checkPolicy, modeText, parseVendors } from "./AdoptionPanel";

const P = IPAM_IDS.prefix;

let stopBridge: (() => void) | undefined;

beforeEach(async () => {
  resetRefs();
  chooseVrf(null);
  await signInAlex();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  chooseVrf(null);
  setSessionForTest(null);
});

async function readPrefix(id: string): Promise<Prefix> {
  return (await api.get("/api/v1/prefixes/{id}", { path: { id } })) as Prefix;
}

/** Renders the panel of a prefix and waits until it shows the policy in force. */
async function openPanel(id: string = P.iot) {
  const prefix = await readPrefix(id);
  const view = renderRoute(() => <AdoptionPanel prefix={prefix} />, {
    url: "/adoption",
    path: "/adoption",
    routes: { "/discovery": () => <div data-testid="inbox-route" /> },
  });
  await screen.findByTestId("adoption-effective");
  return view;
}

const effective = (): HTMLElement => screen.getByTestId("adoption-effective");
const source = (): HTMLElement => screen.getByTestId("adoption-source");
const constraints = (): string[] => [...effective().querySelectorAll(".adoption-constraints li")].map((li) => li.textContent ?? "");
const policyOf = (id: string) => reconcileState().policies.get(id);

async function startEditing() {
  fireEvent.click(await screen.findByTestId("adoption-edit"));
  return screen.findByTestId("dialog-adoption-form");
}

const field = (testid: string) => screen.getByTestId(testid) as HTMLInputElement;
const fill = (testid: string, value: string) => fireEvent.input(screen.getByTestId(testid), { target: { value } });

/** The message under a field: the alert line of its `.field`. */
function fieldMessage(testid: string): string | undefined {
  return screen.getByTestId(testid).closest(".field")?.querySelector("[role='alert']")?.textContent?.trim();
}

async function signInAs(roles: ("admin" | "operator" | "viewer")[]) {
  await signInAlex({
    prepare: (user) => {
      user.roles = roles;
    },
  });
}

describe("the policy in force", () => {
  it("shows the own policy of a prefix with its constraints and who set it", async () => {
    await openPanel(P.iot);
    expect(effective().dataset.mode).toBe("adopt_hosts");
    expect(within(effective()).getByText("Adopt discovered hosts with a MAC address")).toBeTruthy();
    expect(source().dataset.source).toBe("own");
    expect(source().textContent).toContain("The own policy of this prefix");
    expect(source().textContent).toContain("set by Alex Example (you)");
    expect(source().textContent).toContain("last week");
    expect(constraints()).toEqual([
      "Only addresses inside a DHCP pool",
      "Only devices of 00:00:5e",
      "Only after 2 sightings by one source",
      "Adopted hosts get the mode dynamic",
    ]);
    // What a policy never adopts is said once, below the policy.
    expect(effective().textContent).toContain("Conflicts, outside networks, addresses not seen any more");
    expect(screen.getByTestId("prefix-adoption")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Adoption policy" })).toBeTruthy();
  });

  it("shows a policy that adopts everything, without the constraints it does not set", async () => {
    await openPanel(P.documentation);
    expect(effective().dataset.mode).toBe("adopt_all");
    expect(within(effective()).getByText("Adopt discovered hosts and address changes of dynamic hosts")).toBeTruthy();
    expect(source().dataset.source).toBe("own");
    expect(constraints()).toEqual(["Only after 3 sightings by one source", "Adopted hosts get the mode dynamic"]);
  });

  it("shows a manual policy without any constraint", async () => {
    await openPanel(P.lab);
    expect(effective().dataset.mode).toBe("manual");
    expect(within(effective()).getByText("Manual: every proposal waits for a person")).toBeTruthy();
    expect(source().dataset.source).toBe("own");
    expect(effective().querySelector(".adoption-constraints")).toBeNull();
  });

  it("shows the policy a prefix inherits and the prefix it comes from", async () => {
    await openPanel(P.dmz);
    expect(effective().dataset.mode).toBe("adopt_all");
    expect(source().dataset.source).toBe("inherited");
    expect(source().textContent).toContain("Inherited from");
    // The prefix above, by its CIDR, as a link to its page.
    const link = await within(source()).findByRole("link", { name: "203.0.113.0/24" });
    expect(link.getAttribute("href")).toMatch(/^\/ipam\/prefixes\/203\.0\.113\.0\/24(\?|$)/);
    expect(source().textContent).not.toContain("set by");
    expect(constraints()).toEqual(["Only after 3 sightings by one source", "Adopted hosts get the mode dynamic"]);
  });

  it("reads the nearest policy above, not the one further out", async () => {
    // 203.0.113.192/28 lies in 203.0.113.0/24 and in no other prefix with a policy.
    await openPanel(P.cameras);
    expect(source().dataset.source).toBe("inherited");
    await within(source()).findByRole("link", { name: "203.0.113.0/24" });
  });

  it("shows the default for a prefix with no policy above it", async () => {
    await openPanel(P.lan);
    expect(effective().dataset.mode).toBe("manual");
    expect(source().dataset.source).toBe("default");
    expect(source().textContent).toBe("The default: no prefix above sets a policy");
    expect(within(source()).queryByRole("link")).toBeNull();
    expect(effective().querySelector(".adoption-constraints")).toBeNull();
  });

  it("gives the same default to a network of an IPv6 supernet", async () => {
    await openPanel(P.lanV6);
    expect(source().dataset.source).toBe("default");
  });

  it("links to the proposals of the network", async () => {
    const view = await openPanel(P.iot);
    const link = screen.getByTestId("adoption-proposals");
    expect(link.textContent).toContain("Proposals in this network");
    expect(link.getAttribute("href")).toBe(`/discovery?prefix=${P.iot}`);
    fireEvent.click(link);
    await waitFor(() => expect(view.location()).toBe(`/discovery?prefix=${P.iot}`));
  });

  it("has a word for every mode", () => {
    expect(modeText("manual")).toBe("Manual: every proposal waits for a person");
    expect(modeText("adopt_hosts")).toBe("Adopt discovered hosts with a MAC address");
    expect(modeText("adopt_all")).toBe("Adopt discovered hosts and address changes of dynamic hosts");
  });
});

describe("setting a policy", () => {
  it("sets a policy for a prefix that inherits the default, and stores what was entered", async () => {
    const writes = recordWrites();
    await openPanel(P.lan);
    const form = await startEditing();
    expect(within(form).getByRole("group", { name: "What is adopted" })).toBeTruthy();
    // The form starts from the policy in force: here the default.
    expect(field("field-mode-manual").checked).toBe(true);
    expect(field("field-mode-adopt_hosts").checked).toBe(false);
    // Nothing else to set while nothing is adopted.
    expect(screen.queryByTestId("field-min_sightings")).toBeNull();
    expect(screen.queryByTestId("field-only_dhcp_pools")).toBeNull();

    fireEvent.click(field("field-mode-adopt_all"));
    expect(field("field-mode-adopt_all").checked).toBe(true);
    expect(field("field-min_sightings").value).toBe("1");
    expect((screen.getByTestId("field-host_mode") as HTMLSelectElement).value).toBe("dynamic");
    expect(field("field-only_dhcp_pools").checked).toBe(false);
    fireEvent.click(field("field-only_dhcp_pools"));
    fill("field-min_sightings", "3");
    fireEvent.change(screen.getByTestId("field-host_mode"), { target: { value: "reserved" } });
    fill("field-vendors", "00-00-5E\n  Example Networks, 00-00-5E,\n");
    fireEvent.click(screen.getByTestId("form-submit"));

    await waitFor(() => expect(screen.queryByTestId("dialog-adoption-form")).toBeNull());
    // The values are sent as the API wants them, at revision 0 (the prefix had no policy of its own).
    const [put] = applied(writes()).filter((call) => call.method === "PUT");
    expect(put?.url).toContain(`/api/v1/prefixes/${P.lan}/adoption`);
    expect(put?.headers["If-Match"]).toBe('"0"');
    expect(put?.body).toEqual({ mode: "adopt_all", only_dhcp_pools: true, vendors: ["00-00-5E", "Example Networks"], min_sightings: 3, host_mode: "reserved" });
    expect(policyOf(P.lan)?.policy).toEqual({ mode: "adopt_all", only_dhcp_pools: true, vendors: ["00-00-5E", "Example Networks"], min_sightings: 3, host_mode: "reserved" });

    expect(await screen.findByText("Saved the adoption policy of 192.0.2.0/24")).toBeTruthy();
    // The panel shows the policy as the prefix's own now.
    await waitFor(() => expect(source().dataset.source).toBe("own"));
    expect(effective().dataset.mode).toBe("adopt_all");
    expect(constraints()).toEqual([
      "Only addresses inside a DHCP pool",
      "Only devices of 00-00-5E and Example Networks",
      "Only after 3 sightings by one source",
      "Adopted hosts get the mode reserved",
    ]);
    expect(source().textContent).toContain("set by Alex Example (you)");
    expect(screen.getByTestId("adoption-edit").textContent).toContain("Change policy");
    expect(screen.getByTestId("adoption-clear")).toBeTruthy();
  });

  it("changes the own policy at the revision it was read at", async () => {
    const writes = recordWrites();
    await openPanel(P.iot);
    const before = policyOf(P.iot);
    await startEditing();
    // The form starts from the own policy.
    expect(field("field-mode-adopt_hosts").checked).toBe(true);
    expect(field("field-only_dhcp_pools").checked).toBe(true);
    expect(field("field-min_sightings").value).toBe("2");
    expect(field("field-vendors").value).toBe("00:00:5e");
    fireEvent.click(field("field-mode-manual"));
    // A manual policy has no other setting.
    expect(screen.queryByTestId("field-min_sightings")).toBeNull();
    fireEvent.click(screen.getByTestId("form-submit"));

    await waitFor(() => expect(screen.queryByTestId("dialog-adoption-form")).toBeNull());
    const [put] = applied(writes()).filter((call) => call.method === "PUT");
    expect(put?.headers["If-Match"]).toBe(`"${before?.revision}"`);
    expect(policyOf(P.iot)?.policy.mode).toBe("manual");
    expect(policyOf(P.iot)?.revision).toBeGreaterThan(before?.revision ?? 0);
    await waitFor(() => expect(effective().dataset.mode).toBe("manual"));
  });

  it("starts the form from the policy a prefix inherits and stores it as the prefix's own", async () => {
    await openPanel(P.dmz);
    expect((await screen.findByTestId("adoption-edit")).textContent).toContain("Set a policy for this prefix");
    await startEditing();
    expect(field("field-mode-adopt_all").checked).toBe(true);
    expect(field("field-min_sightings").value).toBe("3");
    expect(policyOf(P.dmz)).toBeUndefined();
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(policyOf(P.dmz)?.policy).toEqual({ mode: "adopt_all", only_dhcp_pools: false, vendors: [], min_sightings: 3, host_mode: "dynamic" }));
    await waitFor(() => expect(source().dataset.source).toBe("own"));
    expect(screen.getByTestId("adoption-edit").textContent).toContain("Change policy");
  });

  it("closes the form with Cancel and shows the policy in force again", async () => {
    const writes = recordWrites();
    await openPanel(P.iot);
    await startEditing();
    fireEvent.click(field("field-mode-adopt_all"));
    fill("field-min_sightings", "9");
    fireEvent.click(within(screen.getByTestId("dialog-adoption-form")).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByTestId("dialog-adoption-form")).toBeNull();
    expect(applied(writes()).filter((call) => call.method === "PUT")).toEqual([]);
    expect(effective().dataset.mode).toBe("adopt_hosts");
    // Editing again starts from the policy, not from what was typed before.
    await startEditing();
    expect(field("field-mode-adopt_hosts").checked).toBe(true);
    expect(field("field-min_sightings").value).toBe("2");
  });
});

describe("the checks before saving", () => {
  async function editedIot() {
    const writes = recordWrites();
    await openPanel(P.iot);
    await startEditing();
    return writes;
  }
  const puts = (writes: ReturnType<typeof recordWrites>) => writes().filter((call) => call.method === "PUT");

  it.each([["0"], ["-1"], ["1001"], ["1.5"], [""]])("refuses %j sightings at the field, and sends nothing", async (value) => {
    const writes = await editedIot();
    fill("field-min_sightings", value);
    fireEvent.click(screen.getByTestId("form-submit"));
    expect(fieldMessage("field-min_sightings")).toBe("A whole number from 1 to 1000.");
    expect(field("field-min_sightings").getAttribute("aria-invalid")).toBe("true");
    expect(puts(writes)).toEqual([]);
    // The form stays open with the other values.
    expect(screen.getByTestId("dialog-adoption-form")).toBeTruthy();
    expect(policyOf(P.iot)?.policy.min_sightings).toBe(2);
  });

  it("takes the border values", async () => {
    await editedIot();
    fill("field-min_sightings", "1000");
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(policyOf(P.iot)?.policy.min_sightings).toBe(1000));
  });

  it("takes the message away once the value is right", async () => {
    await editedIot();
    fill("field-min_sightings", "0");
    fireEvent.click(screen.getByTestId("form-submit"));
    expect(fieldMessage("field-min_sightings")).toBeTruthy();
    fill("field-min_sightings", "5");
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(policyOf(P.iot)?.policy.min_sightings).toBe(5));
  });

  it("refuses more than 32 vendors", async () => {
    const writes = await editedIot();
    fill("field-vendors", Array.from({ length: 33 }, (_, i) => `Vendor ${i}`).join("\n"));
    fireEvent.click(screen.getByTestId("form-submit"));
    expect(fieldMessage("field-vendors")).toBe("At most 32 vendors.");
    expect(puts(writes)).toEqual([]);
    // Duplicates count once, so 32 different ones are fine.
    fill("field-vendors", [...Array.from({ length: 32 }, (_, i) => `Vendor ${i}`), "Vendor 0"].join("\n"));
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(policyOf(P.iot)?.policy.vendors).toHaveLength(32));
  });

  it("refuses a vendor of more than 64 characters, counting characters and not bytes", async () => {
    const writes = await editedIot();
    fill("field-vendors", "x".repeat(65));
    fireEvent.click(screen.getByTestId("form-submit"));
    expect(fieldMessage("field-vendors")).toBe("A vendor has 1 to 64 characters.");
    expect(puts(writes)).toEqual([]);
    // 64 two-byte letters are 64 characters.
    fill("field-vendors", "å".repeat(64));
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(policyOf(P.iot)?.policy.vendors).toEqual(["å".repeat(64)]));
  });

  it("has the same checks as the function that makes them", () => {
    expect(checkPolicy({ mode: "adopt_all", min_sightings: 0 })).toEqual({ field: "min_sightings", message: "A whole number from 1 to 1000." });
    expect(checkPolicy({ mode: "adopt_all", min_sightings: 1001 })?.field).toBe("min_sightings");
    expect(checkPolicy({ mode: "adopt_all", min_sightings: 2.5 })?.field).toBe("min_sightings");
    expect(checkPolicy({ mode: "adopt_all", min_sightings: Number.NaN })?.field).toBe("min_sightings");
    expect(checkPolicy({ mode: "adopt_all", vendors: Array.from({ length: 33 }, (_, i) => `v${i}`) })?.field).toBe("vendors");
    expect(checkPolicy({ mode: "adopt_all", vendors: ["x".repeat(65)] })?.field).toBe("vendors");
    expect(checkPolicy({ mode: "adopt_all", vendors: ["x".repeat(64)], min_sightings: 1000 })).toBeNull();
    // A policy without the optional members is the default one.
    expect(checkPolicy({ mode: "manual" })).toBeNull();
  });

  it("reads the vendors of the text field: one per line or comma, trimmed, without duplicates", () => {
    expect(parseVendors("")).toEqual([]);
    expect(parseVendors(" \n , \n")).toEqual([]);
    expect(parseVendors("00-00-5E")).toEqual(["00-00-5E"]);
    expect(parseVendors("00-00-5E\nExample Networks")).toEqual(["00-00-5E", "Example Networks"]);
    expect(parseVendors("00-00-5E, Example Networks ,00-00-5E\n\n  Example Networks  ")).toEqual(["00-00-5E", "Example Networks"]);
  });
});

describe("a refusal by the server", () => {
  const problem = (status: number, code: string, params: Record<string, string> = {}) =>
    HttpResponse.json({ type: "about:blank", title: "Refused", status, code, detail: "", params }, { status, headers: { "content-type": "application/problem+json" } });

  it("shows the message of a value the server refused at its field", async () => {
    server.use(http.put("/api/v1/prefixes/:id/adoption", () => problem(400, "ipam.adoption.invalid", { field: "host_mode" })));
    await openPanel(P.iot);
    await startEditing();
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(fieldMessage("field-host_mode")).toBe("The value of host_mode is not valid for an adoption policy."));
    // It is a message of the field, not one above the buttons as well.
    expect(screen.getByTestId("dialog-adoption-form").querySelectorAll("[role='alert']")).toHaveLength(1);
    expect((screen.getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(false);
  });

  it("shows any other problem above the buttons and keeps the form", async () => {
    server.use(http.put("/api/v1/prefixes/:id/adoption", () => problem(500, "sys.internal")));
    await openPanel(P.iot);
    const form = await startEditing();
    fireEvent.click(screen.getByTestId("form-submit"));
    expect(await within(form).findByText("The server ran into an internal error. The details are in its log.")).toBeTruthy();
    expect(screen.getByTestId("dialog-adoption-form")).toBeTruthy();
    expect(policyOf(P.iot)?.policy.mode).toBe("adopt_hosts");
  });

  it("says that the policy changed meanwhile and saves at the new revision on a second try", async () => {
    await openPanel(P.iot);
    await startEditing();
    fireEvent.click(field("field-mode-adopt_all"));
    fill("field-min_sightings", "4");
    // Someone else sets the policy between the read and the save.
    const read = await getAdoptionPolicy(P.iot);
    await setAdoptionPolicy(P.iot, { mode: "manual", only_dhcp_pools: false, vendors: [], min_sightings: 1, host_mode: "dynamic" }, read.revision);
    const changedAt = policyOf(P.iot)?.revision;
    expect(changedAt).not.toBe(read.revision);

    fireEvent.click(screen.getByTestId("form-submit"));
    const form = screen.getByTestId("dialog-adoption-form");
    expect(
      await within(form).findByText("Someone changed the policy meanwhile; the summary above shows it as it is now. Save again to replace it with yours."),
    ).toBeTruthy();
    // Nothing was written by the refused save.
    expect(policyOf(P.iot)?.policy.mode).toBe("manual");
    // The policy in force, above the form, is the new one.
    await waitFor(() => expect(effective().dataset.mode).toBe("manual"));
    // The problem is told once, in its own words, and not as a second message.
    expect(form.querySelectorAll(".note")).toHaveLength(1);

    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-adoption-form")).toBeNull());
    expect(policyOf(P.iot)?.policy.mode).toBe("adopt_all");
    expect(policyOf(P.iot)?.policy.min_sightings).toBe(4);
  });

  it("shows the error when the policy cannot be read, and no form", async () => {
    server.use(http.get("/api/v1/prefixes/:id/adoption", () => problem(500, "sys.internal")));
    const prefix = await readPrefix(P.iot);
    renderRoute(() => <AdoptionPanel prefix={prefix} />, { url: "/adoption", path: "/adoption" });
    expect(await screen.findByText("The server ran into an internal error. The details are in its log.")).toBeTruthy();
    expect(screen.queryByTestId("adoption-effective")).toBeNull();
    expect(screen.queryByTestId("adoption-edit")).toBeNull();
    expect(screen.getByTestId("prefix-adoption")).toBeTruthy();
  });
});

describe("clearing a policy", () => {
  it("lets the prefix inherit again, from the prefix above", async () => {
    const writes = recordWrites();
    await openPanel(P.lab);
    expect(source().dataset.source).toBe("own");
    const before = policyOf(P.lab);
    fireEvent.click(screen.getByTestId("adoption-clear"));

    await waitFor(() => expect(policyOf(P.lab)).toBeUndefined());
    const [del] = applied(writes()).filter((call) => call.method === "DELETE");
    expect(del?.url).toContain(`/api/v1/prefixes/${P.lab}/adoption`);
    expect(del?.headers["If-Match"]).toBe(`"${before?.revision}"`);
    expect(await screen.findByText("203.0.113.0/25 inherits its adoption policy again")).toBeTruthy();
    // The documentation supernet above sets a policy, so that is what the prefix inherits now.
    await waitFor(() => expect(source().dataset.source).toBe("inherited"));
    expect(effective().dataset.mode).toBe("adopt_all");
    await within(source()).findByRole("link", { name: "203.0.113.0/24" });
    expect(screen.queryByTestId("adoption-clear")).toBeNull();
    expect(screen.getByTestId("adoption-edit").textContent).toContain("Set a policy for this prefix");
  });

  it("falls back to the default when nothing above sets a policy", async () => {
    await openPanel(P.iot);
    fireEvent.click(screen.getByTestId("adoption-clear"));
    await waitFor(() => expect(policyOf(P.iot)).toBeUndefined());
    await waitFor(() => expect(source().dataset.source).toBe("default"));
    expect(effective().dataset.mode).toBe("manual");
  });

  it("does not offer to clear a policy a prefix inherits", async () => {
    await openPanel(P.cameras);
    expect(screen.queryByTestId("adoption-clear")).toBeNull();
  });

  it("tells a person whose clear was refused why", async () => {
    server.use(
      http.delete("/api/v1/prefixes/:id/adoption", () =>
        HttpResponse.json(
          { type: "about:blank", title: "Refused", status: 500, code: "sys.internal", detail: "", params: {} },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    await openPanel(P.iot);
    fireEvent.click(screen.getByTestId("adoption-clear"));
    expect(await screen.findByText("The server ran into an internal error. The details are in its log.")).toBeTruthy();
    expect(policyOf(P.iot)).toBeDefined();
    expect(screen.queryByText("203.0.113.0/25 inherits its adoption policy again")).toBeNull();
  });

  it("clears nothing when the policy changed meanwhile, and shows the new policy", async () => {
    await openPanel(P.iot);
    const read = await getAdoptionPolicy(P.iot);
    await setAdoptionPolicy(P.iot, { mode: "adopt_all", only_dhcp_pools: false, vendors: [], min_sightings: 1, host_mode: "dynamic" }, read.revision);
    fireEvent.click(screen.getByTestId("adoption-clear"));
    // The panel reads the policy again, so the person sees what the other one set.
    await waitFor(() => expect(effective().dataset.mode).toBe("adopt_all"));
    expect(policyOf(P.iot)?.policy.mode).toBe("adopt_all");
    expect(screen.queryByText("198.51.100.0/24 inherits its adoption policy again")).toBeNull();
    expect(source().dataset.source).toBe("own");
  });
});

describe("who may change a policy", () => {
  it("shows a viewer the policy and no way to change it", async () => {
    await signInAs(["viewer"]);
    await openPanel(P.iot);
    expect(effective().dataset.mode).toBe("adopt_hosts");
    expect(screen.queryByTestId("adoption-edit")).toBeNull();
    expect(screen.queryByTestId("adoption-clear")).toBeNull();
    expect(screen.queryByTestId("dialog-adoption-form")).toBeNull();
    // The way to the proposals is for everyone.
    expect(screen.getByTestId("adoption-proposals")).toBeTruthy();
  });

  it("lets an operator change it", async () => {
    await signInAs(["operator"]);
    await openPanel(P.lan);
    await startEditing();
    fireEvent.click(field("field-mode-adopt_hosts"));
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(policyOf(P.lan)?.policy.mode).toBe("adopt_hosts"));
  });

  it("does not offer a change for a prefix that is deleted", async () => {
    const prefix = await readPrefix(P.iot);
    const deleted = { ...prefix, meta: { ...prefix.meta, deleted: { at: "2026-10-08T00:00:00Z", by: prefix.meta.created.by } } } as Prefix;
    renderRoute(() => <AdoptionPanel prefix={deleted} />, { url: "/adoption", path: "/adoption" });
    await screen.findByTestId("adoption-effective");
    expect(screen.queryByTestId("adoption-edit")).toBeNull();
    expect(screen.queryByTestId("adoption-clear")).toBeNull();
  });
});

describe("live updates", () => {
  it("follows a change of the own policy made elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    await openPanel(P.iot);
    expect(effective().dataset.mode).toBe("adopt_hosts");
    const read = await getAdoptionPolicy(P.iot);
    await setAdoptionPolicy(P.iot, { mode: "adopt_all", only_dhcp_pools: false, vendors: [], min_sightings: 5, host_mode: "static" }, read.revision);
    await waitFor(() => expect(effective().dataset.mode).toBe("adopt_all"), { timeout: 4000 });
    expect(constraints()).toEqual(["Only after 5 sightings by one source", "Adopted hosts get the mode static"]);
  });

  it("follows a change of the policy of the prefix above, for a prefix that inherits", async () => {
    stopBridge = bridgeMockEvents();
    await openPanel(P.dmz);
    expect(effective().dataset.mode).toBe("adopt_all");
    const read = await getAdoptionPolicy(P.documentation);
    await setAdoptionPolicy(P.documentation, { mode: "adopt_hosts", only_dhcp_pools: true, vendors: [], min_sightings: 1, host_mode: "dynamic" }, read.revision);
    await waitFor(() => expect(effective().dataset.mode).toBe("adopt_hosts"), { timeout: 4000 });
    expect(source().dataset.source).toBe("inherited");
    expect(constraints()).toContain("Only addresses inside a DHCP pool");
  });

  it("keeps what is typed while the policy changes elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    await openPanel(P.iot);
    await startEditing();
    fill("field-min_sightings", "7");
    const read = await getAdoptionPolicy(P.iot);
    await setAdoptionPolicy(P.iot, { mode: "adopt_hosts", only_dhcp_pools: true, vendors: [], min_sightings: 9, host_mode: "dynamic" }, read.revision);
    await waitFor(() => expect(constraints()).toContain("Only after 9 sightings by one source"), { timeout: 4000 });
    expect(field("field-min_sightings").value).toBe("7");
  });
});

describe("the adoption tab of a prefix", () => {
  function renderIpam(url: string) {
    return renderRoute(IpamView, {
      url,
      path: "/ipam",
      routes: {
        "/ipam/prefixes/:network/:length": IpamView,
        "/discovery": () => <div data-testid="inbox-route" />,
      },
    });
  }

  it("shows the policy of the prefix in its pane", async () => {
    renderIpam(paths.prefix("198.51.100.0/24"));
    await waitFor(() => expect(screen.getByTestId("prefix-pane").dataset.key).toBe("198.51.100.0/24"));
    const tab = await screen.findByTestId("prefix-tab-adoption");
    expect(tab.textContent).toBe("Adoption");
    expect(tab.getAttribute("aria-selected")).toBe("false");
    expect(screen.queryByTestId("prefix-adoption")).toBeNull();

    fireEvent.click(tab);
    expect(tab.getAttribute("aria-selected")).toBe("true");
    await screen.findByTestId("adoption-effective");
    expect(effective().dataset.mode).toBe("adopt_hosts");
    expect(source().dataset.source).toBe("own");
  });

  it("follows the prefix the pane shows", async () => {
    const view = renderIpam(paths.prefix("198.51.100.0/24"));
    await waitFor(() => expect(screen.getByTestId("prefix-pane").dataset.key).toBe("198.51.100.0/24"));
    fireEvent.click(await screen.findByTestId("prefix-tab-adoption"));
    await screen.findByTestId("adoption-effective");
    fireEvent.click(screen.getByTestId("adoption-proposals"));
    await waitFor(() => expect(view.location()).toBe(`/discovery?prefix=${P.iot}`));
  });
});

describe("accessibility", () => {
  it("has no violations when it shows a policy", async () => {
    const view = await openPanel(P.dmz);
    await within(source()).findByRole("link", { name: "203.0.113.0/24" });
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("has no violations with the form open", async () => {
    const view = await openPanel(P.iot);
    await startEditing();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("has no violations with the form open and a field in error", async () => {
    const view = await openPanel(P.iot);
    await startEditing();
    fill("field-min_sightings", "0");
    fireEvent.click(screen.getByTestId("form-submit"));
    expect(fieldMessage("field-min_sightings")).toBeTruthy();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("has no violations for a viewer", async () => {
    await signInAs(["viewer"]);
    const view = await openPanel(P.lan);
    expect(await axeViolations(view.container)).toEqual([]);
  });
});
