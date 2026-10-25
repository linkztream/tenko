// The page of one scope: the settings saved with the revision (only what changed is sent, a stale
// revision is refused, an authoritative setting cannot be taken back), the utilization figures, the
// pools with their DHCP settings, the exclusions with the local check of a range, the scope's
// options and the effective options of a client with the level of each; who sees what; Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DHCP_IDS } from "../api/mock/dhcp-model";
import { dhcpState } from "../api/mock/routes-dhcp";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInWithRoles } from "../auth/scope-testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import ScopePage from "./ScopePage";
import { dhcpSwitchedOff, recordIfMatch, row, rowAction, rowActions, rows } from "./testkit";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = (tab?: string) =>
  renderRoute(ScopePage, { url: `/dhcp/scopes/${DHCP_IDS.lan}${tab ? `/${tab}` : ""}`, path: "/dhcp/scopes/:prefix/:tab?" });
const loaded = async () => screen.findByTestId("scope-name");
const change = (id: string, value: string) => fireEvent.input(screen.getByTestId(id), { target: { value } });
const lan = () => dhcpState().scopes.find((s) => s.prefix === DHCP_IDS.lan)!;

describe("the settings tab", () => {
  it("shows the scope, its settings and the utilization", async () => {
    const view = open();
    expect((await loaded()).textContent).toBe("192.0.2.0/24");
    expect(screen.getByTestId("scope-state").dataset.key).toBe("on");
    expect((screen.getByTestId("field-enabled") as HTMLInputElement).checked).toBe(true);
    // Own lease times: 12 hours between 1 hour and 1 day.
    expect((screen.getByTestId("field-lease-inherit") as HTMLInputElement).checked).toBe(false);
    expect((screen.getByTestId("field-lease-default") as HTMLInputElement).value).toBe("12");
    expect((screen.getByTestId("field-lease-default-unit") as HTMLSelectElement).value).toBe("hours");
    expect((screen.getByTestId("field-lease-max") as HTMLInputElement).value).toBe("1");
    expect((screen.getByTestId("field-lease-max-unit") as HTMLSelectElement).value).toBe("days");
    expect(screen.getByTestId("scope-ddns").dataset.key).toBe("off");
    await waitFor(() => expect(screen.getByTestId("util-pool_size").dataset.value).toBe("90"));
    expect(screen.getByTestId("util-leased").dataset.value).toBe("12");
    expect(screen.getByTestId("util-free").dataset.value).toBe("78");
    expect(screen.getByTestId("util-percent").dataset.value).toBe("13");
    expect(screen.getByTestId("scope-ipam-link").getAttribute("href")).toBe("/ipam/prefixes/192.0.2.0/24");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("sends only what changed, with the revision read, and shows the saved scope", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    const revision = lan().revision;
    fireEvent.click(screen.getByTestId("field-enabled"));
    change("field-server_id", "192.0.2.254");
    change("field-description", "Changed");
    fireEvent.click(screen.getByTestId("scope-save"));
    await waitFor(() => expect(lan().description).toBe("Changed"));
    const sent = writes().find((w) => w.method === "PATCH");
    expect(sent?.body).toEqual({ enabled: false, server_id: "192.0.2.254", description: "Changed" });
    expect(sent?.ifMatch).toBe(`"${revision}"`);
    expect(lan().enabled).toBe(false);
    await waitFor(() => expect(screen.getByTestId("scope-state").dataset.key).toBe("off"));
    expect(await screen.findByText("Scope for 192.0.2.0/24 saved")).toBeTruthy();
  });

  it("takes back the own lease times with the server's, and says when nothing changed", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("scope-save"));
    expect(await screen.findByText("Nothing was changed.")).toBeTruthy();
    expect(writes()).toHaveLength(0);
    fireEvent.click(screen.getByTestId("field-lease-inherit"));
    fireEvent.click(screen.getByTestId("scope-save"));
    await waitFor(() => expect(lan().lease).toBeUndefined());
    expect(writes().find((w) => w.method === "PATCH")?.body).toEqual({ clear_lease: true });
  });

  it("checks the lease times, the server identifier and the shared network before it sends", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    change("field-lease-default", "3");
    fireEvent.change(screen.getByTestId("field-lease-default-unit"), { target: { value: "days" } });
    fireEvent.click(screen.getByTestId("scope-save"));
    await waitFor(() => expect(screen.getAllByTestId("field-error").map((e) => e.dataset.field)).toContain("lease-default"));
    change("field-lease-default", "12");
    fireEvent.change(screen.getByTestId("field-lease-default-unit"), { target: { value: "hours" } });
    change("field-server_id", "256.1.1.1");
    fireEvent.click(screen.getByTestId("scope-save"));
    await waitFor(() => expect(screen.getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["server_id"]));
    expect(writes()).toHaveLength(0);
  });

  it("joins a shared network and leaves it again", async () => {
    open();
    await loaded();
    await waitFor(() => expect((screen.getByTestId("field-shared_network") as HTMLSelectElement).options.length).toBe(2));
    fireEvent.change(screen.getByTestId("field-shared_network"), { target: { value: DHCP_IDS.sharedNetwork } });
    fireEvent.click(screen.getByTestId("scope-save"));
    await waitFor(() => expect(lan().shared_network).toBe(DHCP_IDS.sharedNetwork));
    fireEvent.change(screen.getByTestId("field-shared_network"), { target: { value: "" } });
    fireEvent.click(screen.getByTestId("scope-save"));
    await waitFor(() => expect(lan().shared_network).toBeUndefined());
  });

  it("admits classes", async () => {
    open();
    await loaded();
    const box = await screen.findByTestId("scope-class");
    expect(box.dataset.key).toBe("pxe-clients");
    fireEvent.click(box);
    fireEvent.click(screen.getByTestId("scope-save"));
    await waitFor(() => expect(lan().classes).toEqual([DHCP_IDS.class]));
  });

  it("does not offer to take back an authoritative setting", async () => {
    open();
    await loaded();
    const select = screen.getByTestId("field-authoritative") as HTMLSelectElement;
    expect(select.value).toBe("inherit");
    fireEvent.change(select, { target: { value: "true" } });
    fireEvent.click(screen.getByTestId("scope-save"));
    await waitFor(() => expect(lan().authoritative).toBe(true));
    await waitFor(() => expect((within(select).getByRole("option", { name: "Follow the server" }) as HTMLOptionElement).disabled).toBe(true));
  });

  it("refuses to save over a scope that changed meanwhile", async () => {
    open();
    await loaded();
    // Another session saves first: the revision the form holds is stale.
    lan().revision += 5;
    change("field-description", "Mine");
    fireEvent.click(screen.getByTestId("scope-save"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("sys.store.precondition_failed");
    expect(lan().description).toBe("House LAN");
  });

  it("leaves a viewer the figures and nothing to change", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("scope-save")).toBeNull();
    expect(screen.queryByTestId("dhcp-scope-delete")).toBeNull();
    expect((screen.getByTestId("field-description") as HTMLInputElement).disabled).toBe(true);
    await waitFor(() => expect(screen.getByTestId("util-pool_size")).toBeTruthy());
  });

  it("deletes the scope after the confirmation and leaves for the list", async () => {
    const view = renderRoute(ScopePage, { url: `/dhcp/scopes/${DHCP_IDS.lan}`, path: "/dhcp/scopes/:prefix/:tab?" });
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-scope-delete"));
    fireEvent.click(within(await screen.findByTestId("dialog-scope-delete")).getByTestId("confirm-ok"));
    // Only the DHCPv6 scopes of the seed are left.
    await waitFor(() => expect(dhcpState().scopes.map((s) => s.prefix)).toEqual([DHCP_IDS.lanV6, DHCP_IDS.pdV6]));
    await waitFor(() => expect(view.location()).toBe("/dhcp"));
  });
});

describe("the pools tab", () => {
  it("lists the pool with its size and lease time, and links to the prefix in IPAM", async () => {
    const view = open("pools");
    await loaded();
    await waitFor(() => expect(rows("dhcp-pools")).toHaveLength(1));
    const pool = row("dhcp-pools", "192.0.2.100-192.0.2.199");
    expect(within(pool).getByTestId("pool-size").dataset.value).toBe("90");
    expect(pool.textContent).toContain("from the range");
    expect(screen.getByTestId("pools-ipam-link").getAttribute("href")).toBe("/ipam/prefixes/192.0.2.0/24");
    expect(await rowActions(pool)).toEqual(["edit"]);
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("sets the classes and the lease times of a pool, and clears them", async () => {
    const writes = recordIfMatch();
    open("pools");
    await loaded();
    await waitFor(() => expect(rows("dhcp-pools")).toHaveLength(1));
    await rowAction(row("dhcp-pools", "192.0.2.100-192.0.2.199"), "edit");
    const dialog = await screen.findByTestId("dialog-pool-form");
    fireEvent.click(await within(dialog).findByTestId("pool-class"));
    fireEvent.click(within(dialog).getByTestId("field-lease-inherit"));
    fireEvent.input(within(dialog).getByTestId("field-lease-default"), { target: { value: "2" } });
    fireEvent.change(within(dialog).getByTestId("field-lease-default-unit"), { target: { value: "hours" } });
    fireEvent.input(within(dialog).getByTestId("field-lease-min"), { target: { value: "30" } });
    fireEvent.change(within(dialog).getByTestId("field-lease-min-unit"), { target: { value: "minutes" } });
    fireEvent.input(within(dialog).getByTestId("field-lease-max"), { target: { value: "4" } });
    fireEvent.change(within(dialog).getByTestId("field-lease-max-unit"), { target: { value: "hours" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-pool-form")).toBeNull());
    const sent = writes().find((w) => w.method === "PUT");
    expect(sent?.body).toEqual({ classes: [DHCP_IDS.class], lease: { default_secs: 7200, min_secs: 1800, max_secs: 14_400 } });
    expect(sent?.ifMatch).toBe('"0"');
    const pool = () => row("dhcp-pools", "192.0.2.100-192.0.2.199");
    await waitFor(() => expect(within(pool()).queryByText("pxe-clients")).toBeTruthy());
    expect(await rowActions(pool())).toEqual(["edit", "clear"]);

    await rowAction(pool(), "clear");
    fireEvent.click(within(await screen.findByTestId("dialog-pool-clear")).getByTestId("confirm-ok"));
    await waitFor(() => expect(dhcpState().pools).toHaveLength(0));
  });
});

describe("the exclusions tab", () => {
  it("lists the exclusion, checks a range locally, adds one and deletes it", async () => {
    const writes = recordIfMatch();
    open("exclusions");
    await loaded();
    await waitFor(() => expect(rows("dhcp-exclusions")).toHaveLength(1));
    expect(cellText(row("dhcp-exclusions", "192.0.2.150-192.0.2.159"), "size")).toBe("10");
    fireEvent.click(screen.getByTestId("exclusion-add"));
    const dialog = await screen.findByTestId("dialog-exclusion-form");
    fireEvent.input(within(dialog).getByTestId("field-first"), { target: { value: "192.0.2.10" } });
    fireEvent.input(within(dialog).getByTestId("field-last"), { target: { value: "198.51.100.19" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("field-error")).dataset.field).toBe("last");
    expect(writes()).toHaveLength(0);
    fireEvent.input(within(dialog).getByTestId("field-last"), { target: { value: "192.0.2.19" } });
    fireEvent.input(within(dialog).getByTestId("field-description"), { target: { value: "Servers" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dhcp-exclusions").map((r) => r.dataset.key)).toEqual(["192.0.2.10-192.0.2.19", "192.0.2.150-192.0.2.159"]));
    expect(writes().find((w) => w.method === "POST")?.body).toEqual({ first: "192.0.2.10", last: "192.0.2.19", description: "Servers" });

    await rowAction(row("dhcp-exclusions", "192.0.2.10-192.0.2.19"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-exclusion-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dhcp-exclusions")).toHaveLength(1));
  });

  it("shows an empty list and gives a viewer no add", async () => {
    await signInWithRoles(["viewer"]);
    dhcpState().exclusions.length = 0;
    open("exclusions");
    await loaded();
    expect(await screen.findByTestId("dhcp-exclusions-empty")).toBeTruthy();
    expect(screen.queryByTestId("exclusion-add")).toBeNull();
  });
});

function cellText(r: HTMLElement, col: string): string {
  return r.querySelector(`td[data-col="${col}"]`)?.textContent ?? "";
}

describe("the options tab", () => {
  it("shows the options of the scope, adds an option by type and saves the whole set with the revision", async () => {
    const writes = recordIfMatch();
    const view = open("options");
    await loaded();
    const editor = await screen.findByTestId("scope-optset");
    await waitFor(() => expect(within(editor).getAllByTestId("optset-row")).toHaveLength(1));
    const routers = within(editor).getByTestId("optset-row");
    expect(routers.dataset.key).toBe("dhcp4:3");
    expect((within(routers).getByTestId("optset-value") as HTMLTextAreaElement).value).toBe("192.0.2.1");
    expect(await axeViolations(view.container)).toEqual([]);

    const add = within(editor).getByTestId("optset-add") as HTMLSelectElement;
    expect(Array.from(add.options).some((o) => o.value === "dhcp4|3")).toBe(false);
    expect(Array.from(add.options).some((o) => o.value === "dhcp4|54")).toBe(false);
    fireEvent.change(add, { target: { value: "dhcp4|6" } });
    const dns = await waitFor(() => within(editor).getAllByTestId("optset-row").find((r) => r.dataset.key === "dhcp4:6") as HTMLElement);
    fireEvent.input(within(dns).getByTestId("optset-value"), { target: { value: "192.0.2.53, 192.0.2.54" } });
    fireEvent.change(add, { target: { value: "dhcp4|26" } });
    const mtu = await waitFor(() => within(editor).getAllByTestId("optset-row").find((r) => r.dataset.key === "dhcp4:26") as HTMLElement);
    fireEvent.input(within(mtu).getByTestId("optset-value"), { target: { value: "70000" } });
    fireEvent.click(within(editor).getByTestId("optset-save"));
    expect((await within(editor).findByTestId("optset-row-error")).dataset.key).toBe("dhcp4:26");
    expect(writes()).toHaveLength(0);
    fireEvent.input(within(mtu).getByTestId("optset-value"), { target: { value: "1500" } });
    fireEvent.click(within(editor).getByTestId("optset-save"));
    await waitFor(() => expect(dhcpState().optionSets.get(`scope:${DHCP_IDS.lan}`)?.values.map((v) => v.code)).toEqual([3, 6, 26]));
    const sent = writes().find((w) => w.method === "PUT");
    expect(sent?.body).toEqual({
      values: [
        { code: 3, typed: { ipv4: { values: ["192.0.2.1"] } } },
        { code: 6, typed: { ipv4: { values: ["192.0.2.53", "192.0.2.54"] } } },
        { code: 26, typed: { unsigned: [1500] } },
      ],
    });
    expect(sent?.ifMatch).toMatch(/^"\d+"$/);
    expect(await screen.findByText("Options saved")).toBeTruthy();
  });

  it("shows the refusal of the server under the row it names", async () => {
    open("options");
    await loaded();
    const editor = await screen.findByTestId("scope-optset");
    await waitFor(() => expect(within(editor).getAllByTestId("optset-row")).toHaveLength(1));
    // A code without a known type is edited as hexadecimal; the server has no definition for it.
    fireEvent.input(within(editor).getByTestId("optset-add-code"), { target: { value: "200" } });
    fireEvent.click(within(editor).getByTestId("optset-add-code-go"));
    const row200 = await waitFor(() => within(editor).getAllByTestId("optset-row").find((r) => r.dataset.key === "dhcp4:200") as HTMLElement);
    fireEvent.input(within(row200).getByTestId("optset-value"), { target: { value: "c0ff" } });
    fireEvent.click(within(editor).getByTestId("optset-save"));
    const error = await within(editor).findByTestId("optset-row-error");
    expect(error.dataset.key).toBe("dhcp4:200");
    expect(error.textContent).toBe("This code has no definition. Define the option first.");
  });

  it("will not add a code the server sets itself", async () => {
    open("options");
    await loaded();
    const editor = await screen.findByTestId("scope-optset");
    await waitFor(() => expect(within(editor).getAllByTestId("optset-row")).toHaveLength(1));
    fireEvent.input(within(editor).getByTestId("optset-add-code"), { target: { value: "54" } });
    fireEvent.click(within(editor).getByTestId("optset-add-code-go"));
    expect((await within(editor).findByTestId("optset-code-error")).textContent).toBe("The server sets this option itself.");
    expect(within(editor).getAllByTestId("optset-row")).toHaveLength(1);
  });

  it("shows the effective options of a client with the level of each", async () => {
    open("options");
    await loaded();
    fireEvent.input(screen.getByTestId("field-mac"), { target: { value: "not a mac" } });
    fireEvent.click(screen.getByTestId("effective-show"));
    expect((await screen.findAllByTestId("field-error")).map((e) => e.dataset.field)).toContain("mac");
    fireEvent.input(screen.getByTestId("field-mac"), { target: { value: "00:00:5E:00:53:01" } });
    fireEvent.click(screen.getByTestId("effective-show"));
    const table = await screen.findByTestId("effective-options");
    const options = within(table).getAllByTestId("effective-option");
    expect(options.map((o) => [o.dataset.code, o.dataset.level])).toEqual([
      ["6", "server"],
      ["15", "server"],
      ["3", "scope"],
    ]);
    expect(options[0]?.textContent).toContain("192.0.2.53");
    expect(within(options[2]!).getByTestId("effective-level").textContent).toBe("Scope");
    expect(within(table).queryByTestId("effective-reservation")).toBeNull();
  });

  it("shows the reservation of a client", async () => {
    open("options");
    await loaded();
    fireEvent.input(screen.getByTestId("field-mac"), { target: { value: "00:00:5e:00:53:04" } });
    fireEvent.click(screen.getByTestId("effective-show"));
    expect(await screen.findByTestId("effective-reservation")).toBeTruthy();
  });

  it("gives a viewer the options to read and nothing to change", async () => {
    await signInWithRoles(["viewer"]);
    open("options");
    await loaded();
    const editor = await screen.findByTestId("scope-optset");
    await waitFor(() => expect(within(editor).getAllByTestId("optset-row")).toHaveLength(1));
    expect(within(editor).queryByTestId("optset-save")).toBeNull();
    expect(within(editor).queryByTestId("optset-add")).toBeNull();
    expect(within(editor).queryByTestId("optset-remove")).toBeNull();
  });
});

describe("the page", () => {
  it("opens the tabs from the tab bar", async () => {
    const view = open();
    await loaded();
    fireEvent.click(screen.getByTestId("scope-tab-pools"));
    await waitFor(() => expect(view.location()).toBe(`/dhcp/scopes/${DHCP_IDS.lan}/pools`));
  });

  it("says the module is switched off", async () => {
    dhcpSwitchedOff();
    open();
    expect(await screen.findByTestId("dhcp-off")).toBeTruthy();
  });

  it("shows the refusal when the scope does not exist", async () => {
    renderRoute(ScopePage, { url: "/dhcp/scopes/0190d1c2-0000-7000-8000-0000000a00ff", path: "/dhcp/scopes/:prefix/:tab?" });
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dhcp.scope.not_found");
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open("pools");
    await loaded();
    expect(screen.getByTestId("scope-tab-exclusions").textContent).toBe("Undantag");
    await waitFor(() => expect(rows("dhcp-pools")).toHaveLength(1));
    expect(screen.getByTestId("pools-note").textContent).toContain("DHCP-pool");
  });
});
