// The scope page of a DHCPv6 scope (WP9.4): the DHCPv6 tab only a DHCPv6 scope has, the default of the
// preferred lifetime explained with its value, the local check against the valid lifetime, a save
// that sends the whole `v6` object, the defaults, the DHCPv4-only parts replaced by a line (also by
// an old link to the boot tab), the dhcp6 options of the scope, the utilization of a very large
// pool, and the DHCPv4 scope unchanged.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DHCP_IDS } from "../../api/mock/dhcp-model";
import { dhcpState } from "../../api/mock/routes-dhcp";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import ScopePage from "../ScopePage";
import { recordIfMatch, row, rowAction, rows } from "../testkit";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = (prefix: string, tab?: string) => renderRoute(ScopePage, { url: `/dhcp/scopes/${prefix}${tab ? `/${tab}` : ""}`, path: "/dhcp/scopes/:prefix/:tab?" });
const loaded = async () => screen.findByTestId("scope-name");
const change = (id: string, value: string) => fireEvent.input(screen.getByTestId(id), { target: { value } });
const lan6 = () => dhcpState().scopes.find((s) => s.prefix === DHCP_IDS.lanV6)!;
const tabs = () => screen.getAllByRole("tab").map((t) => (t as HTMLElement).dataset.testid);

describe("the tabs", () => {
  it("shows the family and a DHCPv6 tab after the settings, and no network boot tab, for a DHCPv6 scope", async () => {
    const view = open(DHCP_IDS.lanV6);
    expect((await loaded()).textContent).toBe("2001:db8:0:10::/64");
    expect(screen.getByTestId("scope-family").dataset.key).toBe("v6");
    expect(screen.getByTestId("scope-family").textContent).toBe("DHCPv6");
    expect(tabs()).toEqual(["scope-tab-settings", "scope-tab-v6", "scope-tab-pools", "scope-tab-exclusions", "scope-tab-options", "scope-tab-ddns"]);
    expect(screen.getByTestId("scope-tab-v6").textContent).toBe("DHCPv6");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("leaves a DHCPv4 scope as it was: the family DHCPv4, the network boot tab and no DHCPv6 tab", async () => {
    open(DHCP_IDS.lan);
    await loaded();
    expect(screen.getByTestId("scope-family").dataset.key).toBe("v4");
    expect(tabs()).toEqual(["scope-tab-settings", "scope-tab-pools", "scope-tab-exclusions", "scope-tab-options", "scope-tab-ddns", "scope-tab-boot"]);
    expect(screen.queryByTestId("scope-v6-lease-note")).toBeNull();
    expect(screen.getByTestId("field-server_id")).toBeTruthy();
    expect(screen.getByTestId("scope-classes")).toBeTruthy();
  });

  it("shows the settings for the DHCPv6 tab of a DHCPv4 scope", async () => {
    open(DHCP_IDS.lan, "v6");
    await loaded();
    expect(screen.getByTestId("scope-settings")).toBeTruthy();
    expect(screen.queryByTestId("scope-v6")).toBeNull();
  });

  it("says on the old link to the network boot tab of a DHCPv6 scope that boot is DHCPv4 only", async () => {
    open(DHCP_IDS.lanV6, "boot");
    await loaded();
    const note = await screen.findByTestId("scope-boot-v6");
    expect(within(note).getByTestId("v4-only").textContent).toBe("Classes, policies and network boot are DHCPv4 only; a DHCPv6 client is matched by its scope and its reservation.");
    expect(screen.queryByTestId("scope-boot")).toBeNull();
    expect(screen.queryByTestId("scope-tab-boot")).toBeNull();
  });
});

describe("the settings tab of a DHCPv6 scope", () => {
  it("has neither a server identifier nor admitted classes, and says why", async () => {
    open(DHCP_IDS.lanV6);
    await loaded();
    expect(screen.queryByTestId("field-server_id")).toBeNull();
    expect(screen.queryByTestId("scope-classes")).toBeNull();
    expect(screen.getAllByTestId("v4-only").map((n) => n.dataset.key)).toEqual(["server_id", "classes"]);
    expect(screen.getByTestId("scope-v6-link").getAttribute("href")).toBe(`/dhcp/scopes/${DHCP_IDS.lanV6}/v6`);
  });

  it("shows the utilization of the pool, the leases of the DHCPv6 table counted", async () => {
    open(DHCP_IDS.lanV6);
    await loaded();
    await waitFor(() => expect(screen.getByTestId("util-pool_size").dataset.value).toBe("256"));
    expect(screen.getByTestId("util-leased").dataset.value).toBe("3");
    expect(screen.getByTestId("util-free").dataset.value).toBe("253");
    expect(screen.getByTestId("util-pool_size").dataset.bits).toBeUndefined();
  });

  it("says the size of a pool of 2^32 addresses or more as a power of two", async () => {
    // A /64 pool: the figures stop at 2^64 - 1, `pool_bits` says the size.
    const ipam = (await import("../../api/mock/ipam/state")).ipamState().data;
    const range = ipam.range.get("0190d1c2-0000-7000-8000-000000050004");
    expect(range).toBeDefined();
    (range as NonNullable<typeof range>).first = "2001:db8:0:10::";
    (range as NonNullable<typeof range>).last = "2001:db8:0:10:ffff:ffff:ffff:ffff";
    open(DHCP_IDS.lanV6);
    await loaded();
    await waitFor(() => expect(screen.getByTestId("util-pool_size").dataset.bits).toBe("64"));
    expect(screen.getByTestId("util-pool_size").textContent).toBe("At least 2^64");
    expect(screen.getByTestId("util-free").textContent).toBe("At least 2^64");
    expect(screen.getByTestId("util-leased").textContent).toBe("3");
  });
});

describe("the DHCPv6 tab", () => {
  it("shows the settings, and explains the default of the preferred lifetime with its value", async () => {
    const view = open(DHCP_IDS.lanV6, "v6");
    await loaded();
    const form = await screen.findByTestId("scope-v6");
    expect((within(form).getByTestId("field-preferred") as HTMLInputElement).value).toBe("");
    expect((within(form).getByTestId("field-rapid_commit") as HTMLInputElement).checked).toBe(true);
    expect((within(form).getByTestId("field-interface_id") as HTMLInputElement).value).toBe("");
    // The server's lease time is 24 hours: five eighths of 86 400 s.
    await waitFor(() => expect(within(form).getByTestId("v6-preferred-default").dataset.value).toBe("54000"));
    expect(within(form).getByTestId("v6-preferred-default").textContent).toBe("Empty: five eighths of the valid lifetime, 54,000 s for this scope's default lease time of 1 day.");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("computes the default from the lease times of the scope when it has its own", async () => {
    updateLease(7200);
    open(DHCP_IDS.lanV6, "v6");
    await loaded();
    await waitFor(() => expect(screen.getByTestId("v6-preferred-default").dataset.value).toBe("4500"));
    expect(screen.getByTestId("v6-preferred-default").textContent).toContain("4,500 s");
    expect(screen.getByTestId("v6-preferred-default").textContent).toContain("2 h");
  });

  it("refuses a preferred lifetime above the valid lifetime and one that is no number, before anything is sent", async () => {
    const writes = recordIfMatch();
    open(DHCP_IDS.lanV6, "v6");
    await loaded();
    await screen.findByTestId("scope-v6");
    change("field-preferred", "86401");
    fireEvent.click(screen.getByTestId("v6-save"));
    const error = await screen.findByTestId("field-error");
    expect(error.dataset.field).toBe("preferred");
    expect(error.textContent).toBe("The preferred lifetime cannot be above the valid lifetime of 86,400 s.");
    change("field-preferred", "soon");
    fireEvent.click(screen.getByTestId("v6-save"));
    await waitFor(() => expect(screen.getByTestId("field-error").textContent).toBe("Enter a whole number of seconds, 1 or more, or leave the field empty."));
    change("field-interface_id", "x".repeat(65));
    change("field-preferred", "");
    fireEvent.click(screen.getByTestId("v6-save"));
    await waitFor(() => expect(screen.getByTestId("field-error").dataset.field).toBe("interface_id"));
    expect(writes()).toHaveLength(0);
  });

  it("sends the whole v6 object with the revision and keeps the values after a reload", async () => {
    const writes = recordIfMatch();
    const view = open(DHCP_IDS.lanV6, "v6");
    await loaded();
    await screen.findByTestId("scope-v6");
    const revision = lan6().revision;
    change("field-preferred", "3600");
    change("field-interface_id", "eth1");
    fireEvent.click(screen.getByTestId("field-rapid_commit"));
    fireEvent.click(screen.getByTestId("v6-save"));
    await waitFor(() => expect(lan6().v6).toEqual({ rapid_commit: false, preferred_secs: 3600, interface_id: "eth1" }));
    const sent = writes().find((w) => w.method === "PATCH");
    expect(sent?.body).toEqual({ v6: { rapid_commit: false, preferred_secs: 3600, interface_id: "eth1" } });
    expect(sent?.ifMatch).toBe(`"${revision}"`);
    expect(await screen.findByText(`DHCPv6 settings of 2001:db8:0:10::/64 saved`)).toBeTruthy();
    view.unmount();

    open(DHCP_IDS.lanV6, "v6");
    await loaded();
    await screen.findByTestId("scope-v6");
    expect((screen.getByTestId("field-preferred") as HTMLInputElement).value).toBe("3600");
    expect((screen.getByTestId("field-interface_id") as HTMLInputElement).value).toBe("eth1");
    expect((screen.getByTestId("field-rapid_commit") as HTMLInputElement).checked).toBe(false);
  });

  it("says nothing was changed when the form shows what the scope has", async () => {
    const writes = recordIfMatch();
    open(DHCP_IDS.lanV6, "v6");
    await loaded();
    await screen.findByTestId("scope-v6");
    fireEvent.click(screen.getByTestId("v6-save"));
    expect(await screen.findByText("Nothing was changed.")).toBeTruthy();
    expect(writes()).toHaveLength(0);
  });

  it("drops the settings with the defaults button, sending clear_v6", async () => {
    lan6().v6 = { preferred_secs: 3600, rapid_commit: false, interface_id: "eth1" };
    const writes = recordIfMatch();
    open(DHCP_IDS.lanV6, "v6");
    await loaded();
    await screen.findByTestId("scope-v6");
    expect((screen.getByTestId("field-preferred") as HTMLInputElement).value).toBe("3600");
    fireEvent.click(screen.getByTestId("v6-defaults"));
    await waitFor(() => expect(lan6().v6).toBeUndefined());
    expect(writes().find((w) => w.method === "PATCH")?.body).toEqual({ clear_v6: true });
    await waitFor(() => expect((screen.getByTestId("field-preferred") as HTMLInputElement).value).toBe(""));
    expect((screen.getByTestId("field-rapid_commit") as HTMLInputElement).checked).toBe(true);
    expect((screen.getByTestId("field-interface_id") as HTMLInputElement).value).toBe("");
    // With no settings left there is nothing to drop.
    await waitFor(() => expect(screen.queryByTestId("v6-defaults")).toBeNull());
  });

  it("shows the refusal of the server under the field it names", async () => {
    open(DHCP_IDS.lanV6, "v6");
    await loaded();
    await screen.findByTestId("scope-v6");
    // The valid lifetime shrank on another session after the form was read: the server refuses.
    change("field-preferred", "80000");
    updateLease(3600);
    fireEvent.click(screen.getByTestId("v6-save"));
    await waitFor(() => expect(screen.getByTestId("field-error").dataset.field).toBe("preferred"));
  });

  it("gives a viewer the values to read and no save", async () => {
    await signInWithRoles(["viewer"]);
    open(DHCP_IDS.lanV6, "v6");
    await loaded();
    await screen.findByTestId("scope-v6");
    expect(screen.queryByTestId("v6-save")).toBeNull();
    expect(screen.queryByTestId("v6-defaults")).toBeNull();
    expect((screen.getByTestId("field-preferred") as HTMLInputElement).disabled).toBe(true);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open(DHCP_IDS.lanV6, "v6");
    await loaded();
    await screen.findByTestId("scope-v6");
    expect(screen.getByTestId("scope-tab-v6").textContent).toBe("DHCPv6");
    expect(screen.getByRole("heading", { level: 2 }).textContent).toBe("DHCPv6-inställningar för 2001:db8:0:10::/64");
    expect(screen.getByTestId("v6-save").textContent).toBe("Spara DHCPv6-inställningar");
    expect(screen.getByTestId("v6-defaults").textContent).toBe("Använd standardvärdena");
    await waitFor(() => expect(screen.getByTestId("v6-preferred-default").textContent).toContain("fem åttondelar"));
  });
});

/** Sets the lease times the scope has (the default lease time is the valid lifetime). */
function updateLease(defaultSecs: number): void {
  lan6().lease = { default_secs: defaultSecs, min_secs: Math.min(600, defaultSecs), max_secs: Math.max(defaultSecs, 86_400) };
}

describe("the pools and exclusions of a DHCPv6 scope", () => {
  it("lists the pool, which admits no classes", async () => {
    open(DHCP_IDS.lanV6, "pools");
    await loaded();
    await waitFor(() => expect(rows("dhcp-pools")).toHaveLength(1));
    const pool = row("dhcp-pools", "2001:db8:0:10::100-2001:db8:0:10::1ff");
    expect(pool.querySelector('[data-testid="pool-size"]')?.textContent).toBe("256");
    await rowAction(pool, "edit");
    const dialog = await screen.findByTestId("dialog-pool-form");
    expect(within(dialog).queryByTestId("pool-class")).toBeNull();
    expect(within(dialog).getByTestId("v4-only").dataset.key).toBe("classes");
    // The lease times stay: they are the valid lifetime.
    expect(within(dialog).getByTestId("field-lease-inherit")).toBeTruthy();
  });

  it("checks an exclusion against the IPv6 network and adds one", async () => {
    const writes = recordIfMatch();
    open(DHCP_IDS.lanV6, "exclusions");
    await loaded();
    fireEvent.click(await screen.findByTestId("exclusion-add"));
    const dialog = await screen.findByTestId("dialog-exclusion-form");
    fireEvent.input(within(dialog).getByTestId("field-first"), { target: { value: "192.0.2.10" } });
    fireEvent.input(within(dialog).getByTestId("field-last"), { target: { value: "192.0.2.19" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("field-error")).dataset.field).toBe("first");
    expect(writes()).toHaveLength(0);
    fireEvent.input(within(dialog).getByTestId("field-first"), { target: { value: "2001:db8:0:10::1" } });
    fireEvent.input(within(dialog).getByTestId("field-last"), { target: { value: "2001:db8:0:10::ff" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dhcp-exclusions").map((r) => r.dataset.key)).toEqual(["2001:db8:0:10::1-2001:db8:0:10::ff"]));
    expect(writes().find((w) => w.method === "POST")?.body).toEqual({ first: "2001:db8:0:10::1", last: "2001:db8:0:10::ff" });
  });
});

describe("the options tab of a DHCPv6 scope", () => {
  it("edits the dhcp6 options with the DHCPv6 catalog, typed as the catalog says", async () => {
    const writes = recordIfMatch();
    const view = open(DHCP_IDS.lanV6, "options");
    await loaded();
    const editor = await screen.findByTestId("scope-optset");
    await waitFor(() => expect(within(editor).getAllByTestId("optset-row")).toHaveLength(2));
    const rowsNow = within(editor).getAllByTestId("optset-row");
    expect(rowsNow.map((r) => r.dataset.key)).toEqual(["dhcp6:23", "dhcp6:24"]);
    expect(rowsNow[0]?.textContent).toContain("dns-servers");
    expect(rowsNow[0]?.textContent).toContain("IPv6 address, list");
    expect((within(rowsNow[0] as HTMLElement).getByTestId("optset-value") as HTMLTextAreaElement).value).toBe("2001:db8:0:10::53");
    expect((within(rowsNow[1] as HTMLElement).getByTestId("optset-value") as HTMLTextAreaElement).value).toBe("example.net");
    expect(await axeViolations(view.container)).toEqual([]);

    const add = within(editor).getByTestId("optset-add") as HTMLSelectElement;
    const offered = Array.from(add.options).map((o) => o.value);
    // The DHCPv6 catalog without what is in the set and what the server writes itself; nothing of dhcp4.
    expect(offered).toContain("dhcp6|31");
    expect(offered).toContain("dhcp6|56");
    expect(offered).not.toContain("dhcp6|23");
    expect(offered).not.toContain("dhcp6|3");
    expect(offered).not.toContain("dhcp6|39");
    expect(offered.filter((v) => v !== "").every((v) => v.startsWith("dhcp6|"))).toBe(true);

    fireEvent.change(add, { target: { value: "dhcp6|31" } });
    const sntp = await waitFor(() => within(editor).getAllByTestId("optset-row").find((r) => r.dataset.key === "dhcp6:31") as HTMLElement);
    fireEvent.input(within(sntp).getByTestId("optset-value"), { target: { value: "2001:db8:0:10::123" } });
    fireEvent.change(add, { target: { value: "dhcp6|32" } });
    const refresh = await waitFor(() => within(editor).getAllByTestId("optset-row").find((r) => r.dataset.key === "dhcp6:32") as HTMLElement);
    fireEvent.input(within(refresh).getByTestId("optset-value"), { target: { value: "86400" } });
    fireEvent.click(within(editor).getByTestId("optset-save"));
    await waitFor(() => expect(dhcpState().optionSets.get(`scope:${DHCP_IDS.lanV6}`)?.values.map((v) => v.code)).toEqual([23, 24, 31, 32]));
    expect(writes().find((w) => w.method === "PUT")?.body).toEqual({
      values: [
        { space: "dhcp6", code: 23, typed: { ipv6: { values: ["2001:db8:0:10::53"] } } },
        { space: "dhcp6", code: 24, typed: { names: ["example.net"] } },
        { space: "dhcp6", code: 31, typed: { ipv6: { values: ["2001:db8:0:10::123"] } } },
        { space: "dhcp6", code: 32, typed: { unsigned: [86_400] } },
      ],
    });
  });

  it("refuses an address of the wrong family before it sends, and a typed code that the server writes itself", async () => {
    open(DHCP_IDS.lanV6, "options");
    await loaded();
    const editor = await screen.findByTestId("scope-optset");
    await waitFor(() => expect(within(editor).getAllByTestId("optset-row")).toHaveLength(2));
    fireEvent.input(within(editor).getByTestId("optset-add-code"), { target: { value: "70000" } });
    fireEvent.click(within(editor).getByTestId("optset-add-code-go"));
    expect((await within(editor).findByTestId("optset-code-error")).textContent).toBe("Enter a code from 1 to 65535.");
    fireEvent.input(within(editor).getByTestId("optset-add-code"), { target: { value: "3" } });
    fireEvent.click(within(editor).getByTestId("optset-add-code-go"));
    await waitFor(() => expect(within(editor).getByTestId("optset-code-error").textContent).not.toBe("Enter a code from 1 to 65535."));
    const first = within(editor).getAllByTestId("optset-row")[0] as HTMLElement;
    fireEvent.input(within(first).getByTestId("optset-value"), { target: { value: "192.0.2.53" } });
    fireEvent.click(within(editor).getByTestId("optset-save"));
    expect((await within(editor).findByTestId("optset-row-error")).dataset.key).toBe("dhcp6:23");
  });

  it("leaves the effective options of a client out for a DHCPv6 scope, with a line, and keeps them for DHCPv4", async () => {
    open(DHCP_IDS.lanV6, "options");
    await loaded();
    await screen.findByTestId("scope-optset");
    expect(screen.queryByTestId("effective-show")).toBeNull();
    expect(screen.getByTestId("v4-only").dataset.key).toBe("effective");
    expect(screen.getByTestId("v4-only").textContent).toContain("shown for DHCPv4 only");
  });

  it("offers the DHCPv4 catalog and not the DHCPv6 one to a DHCPv4 scope", async () => {
    open(DHCP_IDS.lan, "options");
    await loaded();
    const editor = await screen.findByTestId("scope-optset");
    await waitFor(() => expect(within(editor).getAllByTestId("optset-row")).toHaveLength(1));
    const offered = Array.from((within(editor).getByTestId("optset-add") as HTMLSelectElement).options).map((o) => o.value);
    expect(offered).toContain("dhcp4|6");
    expect(offered.some((v) => v.startsWith("dhcp6|"))).toBe(false);
    expect(screen.getByTestId("effective-show")).toBeTruthy();
  });
});
