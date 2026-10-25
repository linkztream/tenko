// The DHCP options page: the option set of the server, the custom definitions (define one with the
// local checks and the server's refusals, delete one, a definition that is in use is refused with the
// server's message) and the read-only catalog with the codes the server sets itself.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { catalog } from "../../api/mock/dhcp-model";
import { dhcpState } from "../../api/mock/routes-dhcp";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { cell, dhcpSwitchedOff, recordIfMatch, row, rowAction, rowActions, rows } from "../testkit";
import OptionsPage from "./OptionsPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(OptionsPage, { url: "/dhcp/options", path: "/dhcp/options" });
const loaded = () => waitFor(() => expect(rows("dhcp-option-defs").length).toBeGreaterThan(0));

describe("the options page", () => {
  it("shows the options of the server, the definitions and the catalog", async () => {
    const view = open();
    await loaded();
    const server = await screen.findByTestId("server-optset");
    await waitFor(() => expect(within(server).getAllByTestId("optset-row")).toHaveLength(2));
    const site = row("dhcp-option-defs", "dhcp4:230");
    expect(cell(site, "name").textContent).toBe("site-code");
    expect(cell(site, "kind").textContent).toBe("Number (0 to 65535)");
    expect(cell(site, "used_by").textContent).toBe("0");
    await waitFor(() => expect(rows("dhcp-catalog").length).toBeGreaterThan(5));
    expect(within(row("dhcp-catalog", "dhcp4:54")).getByTestId("catalog-managed")).toBeTruthy();
    expect(within(row("dhcp-catalog", "dhcp4:6")).queryByTestId("catalog-managed")).toBeNull();
    expect(cell(row("dhcp-catalog", "dhcp4:6"), "kind").textContent).toBe("IPv4 address, list");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  // WP9.4: the catalog of both spaces, and the set of the server holds values of both.
  it("lists the DHCPv6 catalog after the DHCPv4 one and offers both spaces for the options of the server", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    // The grid shows the rows in view; its row count says both catalogs are in it (the header counts one).
    await waitFor(() => expect(screen.getByTestId("grid-dhcp-catalog").querySelector("[aria-rowcount]")?.getAttribute("aria-rowcount")).toBe(String(catalog().length + 1)));
    expect(catalog().some((c) => c.space === "dhcp6")).toBe(true);

    const server = await screen.findByTestId("server-optset");
    await waitFor(() => expect(within(server).getAllByTestId("optset-row")).toHaveLength(2));
    const add = within(server).getByTestId("optset-add") as HTMLSelectElement;
    expect(Array.from(add.querySelectorAll("optgroup")).map((g) => g.label)).toEqual(["DHCPv4", "DHCPv6"]);
    const offered = Array.from(add.options).map((o) => o.value);
    expect(offered).toContain("dhcp4|3");
    expect(offered).toContain("dhcp6|23");
    expect(offered).not.toContain("dhcp6|3");
    fireEvent.change(add, { target: { value: "dhcp6|23" } });
    const dns = await waitFor(() => within(server).getAllByTestId("optset-row").find((r) => r.dataset.key === "dhcp6:23") as HTMLElement);
    // A row of the other family says which one it is.
    expect(dns.textContent).toContain("DHCPv6");
    fireEvent.input(within(dns).getByTestId("optset-value"), { target: { value: "2001:db8::53" } });
    fireEvent.click(within(server).getByTestId("optset-save"));
    await waitFor(() => expect(dhcpState().optionSets.get("server")?.values.map((v) => `${v.space}:${v.code}`)).toEqual(["dhcp4:6", "dhcp4:15", "dhcp6:23"]));
    expect(writes().find((w) => w.method === "PUT")?.body).toEqual({
      values: [
        { code: 6, typed: { ipv4: { values: ["192.0.2.53"] } } },
        { code: 15, typed: { text: "example.test" } },
        { space: "dhcp6", code: 23, typed: { ipv6: { values: ["2001:db8::53"] } } },
      ],
    });
  });

  it("defines an option after the local checks and shows the refusals of the server under the field", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-def-create"));
    const dialog = await screen.findByTestId("dialog-def-form");
    fireEvent.input(within(dialog).getByTestId("field-code"), { target: { value: "300" } });
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Bad Name" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["code", "name"]));
    expect(writes()).toHaveLength(0);

    // A code of the catalog is refused by the server.
    fireEvent.input(within(dialog).getByTestId("field-code"), { target: { value: "6" } });
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "other-dns" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const notice = await within(dialog).findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dhcp.option.code_reserved");
    expect(notice.textContent).toBe("This code is defined by the catalog or set by the server itself.");

    fireEvent.input(within(dialog).getByTestId("field-code"), { target: { value: "240" } });
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "lab-servers" } });
    fireEvent.change(within(dialog).getByTestId("field-kind"), { target: { value: "ipv4_address" } });
    fireEvent.click(within(dialog).getByTestId("field-array"));
    fireEvent.input(within(dialog).getByTestId("field-description"), { target: { value: "Lab servers" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dhcp-option-defs").map((r) => r.dataset.key)).toEqual(["dhcp4:230", "dhcp4:240"]));
    expect(writes().filter((w) => w.method === "POST").pop()?.body).toEqual({ code: 240, name: "lab-servers", kind: "ipv4_address", array: true, description: "Lab servers" });
    expect(cell(row("dhcp-option-defs", "dhcp4:240"), "kind").textContent).toBe("IPv4 address, list");
    // The new code can be set in the server's option set.
    const server = screen.getByTestId("server-optset");
    await waitFor(() => expect(Array.from((within(server).getByTestId("optset-add") as HTMLSelectElement).options).some((o) => o.value === "dhcp4|240")).toBe(true));
  });

  it("cannot make a list of a type that does not repeat", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-def-create"));
    const dialog = await screen.findByTestId("dialog-def-form");
    expect((within(dialog).getByTestId("field-array") as HTMLInputElement).disabled).toBe(true);
    fireEvent.change(within(dialog).getByTestId("field-kind"), { target: { value: "u8" } });
    expect((within(dialog).getByTestId("field-array") as HTMLInputElement).disabled).toBe(false);
  });

  it("deletes a definition after the confirmation, and refuses one that an option set uses with the server's message", async () => {
    open();
    await loaded();
    await rowAction(row("dhcp-option-defs", "dhcp4:230"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-def-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dhcp-option-defs")).toHaveLength(0));
    expect(await screen.findByTestId("dhcp-defs-empty")).toBeTruthy();
  });

  it("refuses to delete a definition that an option set uses", async () => {
    dhcpState().optionSets.set("server", { ...dhcpState().optionSets.get("server")!, values: [{ space: "dhcp4", code: 230, data: "0004" }] });
    open();
    await loaded();
    await waitFor(() => expect(cell(row("dhcp-option-defs", "dhcp4:230"), "used_by").textContent).toBe("1"));
    await rowAction(row("dhcp-option-defs", "dhcp4:230"), "delete");
    const dialog = await screen.findByTestId("dialog-def-delete");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    const notice = await within(dialog).findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dhcp.option_def.in_use");
    expect(notice.textContent).toBe("Option sets use this definition: server.");
    expect(dhcpState().optionDefs).toHaveLength(1);
  });

  it("gives a viewer the lists and nothing to change", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dhcp-def-create")).toBeNull();
    expect(await rowActions(row("dhcp-option-defs", "dhcp4:230"))).toEqual([]);
    const server = await screen.findByTestId("server-optset");
    await waitFor(() => expect(within(server).getAllByTestId("optset-row")).toHaveLength(2));
    expect(within(server).queryByTestId("optset-save")).toBeNull();
  });

  it("says the module is switched off", async () => {
    dhcpSwitchedOff();
    open();
    expect(await screen.findByTestId("dhcp-off")).toBeTruthy();
    expect(screen.queryByTestId("grid-dhcp-catalog")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("DHCP-alternativ");
    expect(screen.getByTestId("dhcp-def-create").textContent).toBe("Definiera alternativ");
    await waitFor(() => expect(rows("dhcp-catalog").length).toBeGreaterThan(5));
    expect(within(row("dhcp-catalog", "dhcp4:54")).getByTestId("catalog-managed").textContent).toBe("Sätts av servern");
  });
});
