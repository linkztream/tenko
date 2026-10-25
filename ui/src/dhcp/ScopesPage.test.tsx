// The DHCP scope list: the scopes of the seed (DHCPv4 and DHCPv6, each tagged with its family) with
// their pools, active leases and utilization, creating a scope for a network that has none, IPv4 or
// IPv6 (the local checks first, then the server's refusal), deleting
// one with the confirmation that says the prefix stays, who sees what, the module-off and
// not-available states, Swedish, and accessibility.
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
import ScopesPage from "./ScopesPage";
import { cell, dhcpNoService, dhcpNotBuilt, dhcpSwitchedOff, recordWrites, row, rowAction, rowActions, rows } from "./testkit";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

/** The IPAM prefix 2001:db8:0:30::/64 (IoT, IPv6): a network without a scope. */
const IOT_V6 = "0190d1c2-0000-7000-8000-0000000a0009";

const open = () => renderRoute(ScopesPage, { url: "/dhcp", path: "/dhcp" });
const loaded = () => waitFor(() => expect(rows("dhcp-scopes").length).toBeGreaterThan(0));

describe("the scope list", () => {
  it("shows the scope with its state, pools, active leases and utilization", async () => {
    const view = open();
    await loaded();
    const lan = row("dhcp-scopes", "192.0.2.0/24");
    expect(within(cell(lan, "network")).getByTestId("scope-link").getAttribute("href")).toBe(`/dhcp/scopes/${DHCP_IDS.lan}`);
    expect(within(cell(lan, "enabled")).getByTestId("scope-enabled").dataset.key).toBe("on");
    expect(cell(lan, "pools").textContent).toBe("1");
    expect(cell(lan, "leases").textContent).toBe("12");
    // 12 of the 90 addresses of the pool are leased.
    const util = await within(lan).findByTestId("scope-util");
    expect(util.dataset.key).toBe("13");
    expect(util.querySelector('[role="img"]')?.getAttribute("aria-label")).toBe("13 percent used");
    expect(cell(lan, "description").textContent).toBe("House LAN");
    expect(screen.getByTestId("dhcp-nav").querySelectorAll('[data-testid="dhcp-nav-link"]')).toHaveLength(8);
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("creating a scope", () => {
  it("lists the networks without a scope, checks the form, and creates the scope", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-scope-create"));
    const dialog = await screen.findByTestId("dialog-scope-form");
    const prefix = within(dialog).getByTestId("field-prefix") as HTMLSelectElement;
    await waitFor(() => expect(prefix.options.length).toBeGreaterThan(2));
    const labels = Array.from(prefix.options).map((o) => o.textContent ?? "");
    expect(labels.some((l) => l.startsWith("198.51.100.0/24"))).toBe(true);
    // The LAN has a scope; the same network of the other VRF (the workshop) has none.
    expect(Array.from(prefix.options).some((o) => o.value === DHCP_IDS.lan)).toBe(false);
    // WP9.4: the IPv6 networks are offered too, those that have a scope are not.
    expect(labels.some((l) => l.startsWith("2001:db8:0:30::/64"))).toBe(true);
    expect(Array.from(prefix.options).some((o) => o.value === DHCP_IDS.lanV6)).toBe(false);

    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("field-error")).dataset.field).toBe("prefix");
    expect(writes()).toHaveLength(0);

    fireEvent.change(prefix, { target: { value: DHCP_IDS.iot } });
    fireEvent.input(within(dialog).getByTestId("field-server_id"), { target: { value: "not an address" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").dataset.field).toBe("server_id"));
    fireEvent.input(within(dialog).getByTestId("field-server_id"), { target: { value: "198.51.100.1" } });

    // Own lease times: the shortest above the default is refused before anything is sent.
    fireEvent.click(within(dialog).getByTestId("field-lease-inherit"));
    fireEvent.input(await within(dialog).findByTestId("field-lease-min"), { target: { value: "2" } });
    fireEvent.change(within(dialog).getByTestId("field-lease-min-unit"), { target: { value: "days" } });
    fireEvent.input(within(dialog).getByTestId("field-lease-default"), { target: { value: "12" } });
    fireEvent.change(within(dialog).getByTestId("field-lease-default-unit"), { target: { value: "hours" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").dataset.field).toBe("lease-min"));
    expect(writes()).toHaveLength(0);
    fireEvent.input(within(dialog).getByTestId("field-lease-min"), { target: { value: "30" } });
    fireEvent.change(within(dialog).getByTestId("field-lease-min-unit"), { target: { value: "minutes" } });
    fireEvent.change(within(dialog).getByTestId("field-authoritative"), { target: { value: "false" } });
    fireEvent.click(within(dialog).getByTestId("field-restricted"));
    fireEvent.input(within(dialog).getByTestId("field-description"), { target: { value: "Things" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(rows("dhcp-scopes").map((r) => r.dataset.key)).toEqual(["192.0.2.0/24", "198.51.100.0/24", "2001:db8:0:10::/64"]));
    const sent = writes().find((w) => w.method === "POST" && w.url.endsWith("/api/v1/dhcp/scopes"));
    expect(sent?.body).toEqual({
      prefix: DHCP_IDS.iot,
      lease: { default_secs: 43_200, min_secs: 1800, max_secs: 604_800 },
      authoritative: false,
      server_id: "198.51.100.1",
      restricted: true,
      description: "Things",
    });
    expect(dhcpState().scopes.map((s) => s.prefix)).toContain(DHCP_IDS.iot);
    expect(await screen.findByText("Scope for 198.51.100.0/24 created")).toBeTruthy();
  });

  // WP9.4: a scope for an IPv6 network has no server identifier.
  it("creates a scope for an IPv6 network, without a server identifier", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-scope-create"));
    const dialog = await screen.findByTestId("dialog-scope-form");
    const prefix = within(dialog).getByTestId("field-prefix") as HTMLSelectElement;
    await waitFor(() => expect(prefix.options.length).toBeGreaterThan(2));
    expect(within(dialog).getByTestId("field-server_id")).toBeTruthy();
    fireEvent.input(within(dialog).getByTestId("field-server_id"), { target: { value: "not an address" } });
    fireEvent.change(prefix, { target: { value: IOT_V6 } });
    await waitFor(() => expect(within(dialog).queryByTestId("field-server_id")).toBeNull());
    fireEvent.input(within(dialog).getByTestId("field-description"), { target: { value: "IoT, IPv6" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dhcp-scopes").map((r) => r.dataset.key)).toEqual(["192.0.2.0/24", "2001:db8:0:10::/64", "2001:db8:0:30::/64"]));
    // The server identifier typed for the IPv4 network was not sent.
    expect(writes().find((w) => w.method === "POST" && w.url.endsWith("/api/v1/dhcp/scopes"))?.body).toEqual({ prefix: IOT_V6, description: "IoT, IPv6" });
    expect(dhcpState().scopes.find((s) => s.prefix === IOT_V6)?.family).toBe("v6");
    expect(within(cell(row("dhcp-scopes", "2001:db8:0:30::/64"), "family")).getByTestId("scope-family").dataset.key).toBe("v6");
    expect(await screen.findByText("Scope for 2001:db8:0:30::/64 created")).toBeTruthy();
  });

  it("shows the refusal of the server when the network got a scope meanwhile", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-scope-create"));
    const dialog = await screen.findByTestId("dialog-scope-form");
    const prefix = within(dialog).getByTestId("field-prefix") as HTMLSelectElement;
    await waitFor(() => expect(prefix.options.length).toBeGreaterThan(2));
    fireEvent.change(prefix, { target: { value: DHCP_IDS.iot } });
    // Another session creates the scope first.
    const lan = dhcpState().scopes[0];
    dhcpState().scopes.push({ ...(lan as NonNullable<typeof lan>), prefix: DHCP_IDS.iot });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const notice = await within(dialog).findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dhcp.scope.exists");
    expect(notice.textContent).toBe("This network has a scope already.");
  });
});

describe("deleting a scope", () => {
  it("says the prefix and its ranges stay, and deletes the scope", async () => {
    // The DHCPv6 scope of the seed would stay in the list; the empty list is what this checks.
    dhcpState().scopes = dhcpState().scopes.filter((s) => s.prefix !== DHCP_IDS.lanV6);
    open();
    await loaded();
    await rowAction(row("dhcp-scopes", "192.0.2.0/24"), "delete");
    const dialog = await screen.findByTestId("dialog-scope-delete");
    expect(dialog.textContent).toContain("The network and its ranges stay in IPAM.");
    expect(dialog.textContent).toContain("192.0.2.0/24");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dhcp-scopes")).toHaveLength(0));
    expect(dhcpState().scopes).toHaveLength(0);
    expect(await screen.findByTestId("dhcp-scopes-empty")).toBeTruthy();
  });
});

describe("who sees what", () => {
  it("offers a viewer no create and no delete", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dhcp-scope-create")).toBeNull();
    expect(await rowActions(row("dhcp-scopes", "192.0.2.0/24"))).toEqual(["open"]);
  });

  it("offers an operator both", async () => {
    await signInWithRoles(["operator"]);
    open();
    await loaded();
    expect(screen.getByTestId("dhcp-scope-create")).toBeTruthy();
    expect(await rowActions(row("dhcp-scopes", "192.0.2.0/24"))).toEqual(["open", "delete"]);
  });

  // WP9.4: the family of every scope, and the utilization of a DHCPv6 scope.
  it("tags every scope DHCPv4 or DHCPv6", async () => {
    open();
    await loaded();
    const lan = row("dhcp-scopes", "192.0.2.0/24");
    const lan6 = row("dhcp-scopes", "2001:db8:0:10::/64");
    expect(within(cell(lan, "family")).getByTestId("scope-family").dataset.key).toBe("v4");
    expect(within(cell(lan, "family")).getByTestId("scope-family").textContent).toBe("DHCPv4");
    expect(within(cell(lan6, "family")).getByTestId("scope-family").dataset.key).toBe("v6");
    expect(within(cell(lan6, "family")).getByTestId("scope-family").textContent).toBe("DHCPv6");
    expect(within(cell(lan6, "network")).getByTestId("scope-link").getAttribute("href")).toBe(`/dhcp/scopes/${DHCP_IDS.lanV6}`);
    expect(cell(lan6, "leases").textContent).toBe("3");
    // 3 of the 256 addresses of the pool are leased.
    const util = await within(lan6).findByTestId("scope-util");
    expect(util.dataset.key).toBe("1");
  });

  it("says the module is switched off and links to the settings", async () => {
    dhcpSwitchedOff();
    const view = open();
    const notice = await screen.findByTestId("dhcp-off");
    expect(within(notice).getByTestId("dhcp-modules-link").getAttribute("href")).toBe("/settings");
    expect(screen.queryByTestId("dhcp-scope-create")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows the same state when the server runs no configuration service", async () => {
    dhcpNoService();
    open();
    expect(await screen.findByTestId("dhcp-off")).toBeTruthy();
  });

  it("says the service is not available when the server answers 501", async () => {
    dhcpNotBuilt();
    const view = open();
    expect(await screen.findByTestId("dhcp-not-built")).toBeTruthy();
    expect(screen.queryByTestId("grid-dhcp-scopes")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("language", () => {
  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("DHCP-omfång");
    expect(screen.getByTestId("dhcp-scope-create").textContent).toBe("Nytt omfång");
    expect(within(row("dhcp-scopes", "192.0.2.0/24")).getByTestId("scope-enabled").textContent).toBe("Aktivt");
    expect(screen.getAllByTestId("dhcp-nav-link").map((l) => l.textContent)).toContain("Delade nätverk");
  });
});
