// The shared networks: the list with the scopes of each (linked), creating one with the local check
// of the name and the server's refusal under the field, editing with the revision, deleting (refused
// while a scope belongs to it, with the server's message), who sees what, Swedish.
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
import SharedNetworksPage from "./SharedNetworksPage";
import { cell, dhcpSwitchedOff, recordIfMatch, row, rowAction, rowActions, rows } from "./testkit";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(SharedNetworksPage, { url: "/dhcp/shared-networks", path: "/dhcp/shared-networks" });
const loaded = () => waitFor(() => expect(rows("dhcp-networks").length).toBeGreaterThan(0));

describe("the shared networks", () => {
  it("lists the shared network with its description", async () => {
    const view = open();
    await loaded();
    const network = row("dhcp-networks", "home-links");
    expect(cell(network, "description").textContent).toBe("The links of the house");
    expect(within(network).queryAllByTestId("network-scope")).toHaveLength(0);
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("links the scopes that belong to it", async () => {
    dhcpState().scopes[0]!.shared_network = DHCP_IDS.sharedNetwork;
    open();
    await loaded();
    const link = await waitFor(() => within(row("dhcp-networks", "home-links")).getByTestId("network-scope"));
    await waitFor(() => expect(link.dataset.key).toBe("192.0.2.0/24"));
    expect(link.getAttribute("href")).toBe(`/dhcp/scopes/${DHCP_IDS.lan}`);
  });

  it("creates one after the local check of the name and shows the refusal of the server under the field", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-network-create"));
    const dialog = await screen.findByTestId("dialog-network-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Bad Name" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("field-error")).dataset.field).toBe("name");
    expect(writes()).toHaveLength(0);
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "home-links" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").textContent).toBe("The shared network is not valid (name)."));
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "garage-links" } });
    fireEvent.input(within(dialog).getByTestId("field-interface"), { target: { value: "eth1" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dhcp-networks").map((r) => r.dataset.key)).toEqual(["garage-links", "home-links"]));
    // The first POST was refused (the name exists); the second is the one that created it.
    expect(writes().filter((w) => w.method === "POST").map((w) => w.body)).toEqual([{ name: "home-links" }, { name: "garage-links", interface: "eth1" }]);
    expect(cell(row("dhcp-networks", "garage-links"), "interface").textContent).toBe("eth1");
  });

  it("edits with the revision read and clears the interface with an empty text", async () => {
    dhcpState().sharedNetworks[0]!.interface = "eth0";
    const writes = recordIfMatch();
    open();
    await loaded();
    const revision = dhcpState().sharedNetworks[0]!.revision;
    await rowAction(row("dhcp-networks", "home-links"), "edit");
    const dialog = await screen.findByTestId("dialog-network-form");
    expect((within(dialog).getByTestId("field-interface") as HTMLInputElement).value).toBe("eth0");
    fireEvent.input(within(dialog).getByTestId("field-interface"), { target: { value: "" } });
    fireEvent.input(within(dialog).getByTestId("field-description"), { target: { value: "Changed" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(dhcpState().sharedNetworks[0]!.description).toBe("Changed"));
    expect(dhcpState().sharedNetworks[0]!.interface).toBeUndefined();
    const sent = writes().find((w) => w.method === "PATCH");
    expect(sent?.body).toEqual({ name: "home-links", interface: "", description: "Changed" });
    expect(sent?.ifMatch).toBe(`"${revision}"`);
  });

  it("deletes one that no scope belongs to", async () => {
    open();
    await loaded();
    await rowAction(row("dhcp-networks", "home-links"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-network-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dhcp-networks")).toHaveLength(0));
    expect(await screen.findByTestId("dhcp-networks-empty")).toBeTruthy();
  });

  it("shows the message of the server when a scope still belongs to it", async () => {
    dhcpState().scopes[0]!.shared_network = DHCP_IDS.sharedNetwork;
    open();
    await loaded();
    await rowAction(row("dhcp-networks", "home-links"), "delete");
    const dialog = await screen.findByTestId("dialog-network-delete");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    const notice = await within(dialog).findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dhcp.shared_network.in_use");
    expect(notice.textContent).toBe("1 scope still belongs to this shared network; move or delete them first.");
    expect(dhcpState().sharedNetworks).toHaveLength(1);
  });

  it("offers a viewer nothing to change", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dhcp-network-create")).toBeNull();
    expect(await rowActions(row("dhcp-networks", "home-links"))).toEqual([]);
  });

  it("says the module is switched off", async () => {
    dhcpSwitchedOff();
    open();
    expect(await screen.findByTestId("dhcp-off")).toBeTruthy();
    expect(screen.queryByTestId("dhcp-network-create")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Delade nätverk");
    expect(screen.getByTestId("dhcp-network-create").textContent).toBe("Nytt delat nätverk");
  });
});
