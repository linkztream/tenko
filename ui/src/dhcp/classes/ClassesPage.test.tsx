// The client classes and the match editor: the list with the matches in words and the scopes,
// pools and policies that name each class, creating a class with matches of every kind (with the
// local checks of each row), editing with the revision, deleting (refused while the class is named,
// with the server's message), who sees what, Swedish.
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
import { cell, dhcpSwitchedOff, recordIfMatch, row, rowAction, rowActions, rows } from "../testkit";
import ClassesPage from "./ClassesPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(ClassesPage, { url: "/dhcp/classes", path: "/dhcp/classes" });
const loaded = () => waitFor(() => expect(rows("dhcp-classes").length).toBeGreaterThan(0));
const matchRows = (dialog: HTMLElement) => within(dialog).getAllByTestId("match-row");

describe("the classes", () => {
  it("lists the class with its matches in words and where it is used", async () => {
    const view = open();
    await loaded();
    const pxe = row("dhcp-classes", "pxe-clients");
    expect(within(pxe).getByTestId("class-match").textContent).toBe('vendor class starting with "PXEClient"');
    expect(within(pxe).getByTestId("class-used-by").dataset.value).toBe("1");
    expect(cell(pxe, "description").textContent).toBe("Network boot");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("creates a class with a match of each kind and sends them in their stored form", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-class-create"));
    const dialog = await screen.findByTestId("dialog-class-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "lab-gear" } });

    const kinds: [string, string, boolean][] = [
      ["vendor_class", "MSFT", true],
      ["user_class", "lab", false],
      ["mac", "00:00:5E:00:53:*", false],
      ["client_id", "01:AA:BB", false],
      ["circuit_id", "0001", false],
      ["remote_id", "0a0b", false],
      ["architecture", "7", false],
      ["host_name", "printer", true],
    ];
    for (let i = 0; i < kinds.length; i += 1) {
      if (i > 0) fireEvent.click(within(dialog).getByTestId("match-add"));
      const [kind, value, prefix] = kinds[i]!;
      const line = matchRows(dialog)[i]!;
      fireEvent.change(within(line).getByTestId("match-kind"), { target: { value: kind } });
      // The architecture has a picker of the known codes; the other kinds a text input.
      if (kind === "architecture") fireEvent.change(within(line).getByTestId("match-arch"), { target: { value } });
      else fireEvent.input(within(line).getByTestId("match-value"), { target: { value } });
      if (prefix) fireEvent.click(within(line).getByTestId("match-prefix"));
    }
    expect(matchRows(dialog)).toHaveLength(8);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dhcp-classes").map((r) => r.dataset.key)).toEqual(["lab-gear", "pxe-clients"]));
    expect(writes().find((w) => w.method === "POST")?.body).toEqual({
      name: "lab-gear",
      matches: [
        { vendor_class: { value: "MSFT", prefix: true } },
        { user_class: { value: "lab" } },
        { mac: { pattern: "00:00:5e:00:53:*" } },
        { client_id: { value: "01aabb" } },
        { circuit_id: { value: "0001" } },
        { remote_id: { value: "0a0b" } },
        { architecture: { code: 7 } },
        { host_name: { value: "printer", prefix: true } },
      ],
    });
    expect(within(row("dhcp-classes", "lab-gear")).getAllByTestId("class-match")).toHaveLength(8);
  });

  it("picks an architecture by name, and takes any other number with the number input", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-class-create"));
    const dialog = await screen.findByTestId("dialog-class-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "boot-arch" } });
    const first = matchRows(dialog)[0]!;
    fireEvent.change(within(first).getByTestId("match-kind"), { target: { value: "architecture" } });
    const picker = within(first).getByTestId("match-arch") as HTMLSelectElement;
    // The known codes of RFC 4578 and the registry, named, and "another number"; no number input for a known code.
    expect([...picker.options].map((o) => o.value)).toEqual(["", "0", "6", "7", "9", "10", "11", "15", "16", "19", "other"]);
    expect(picker.options[3]?.textContent).toBe("7: UEFI x64");
    expect(within(first).queryByTestId("match-value")).toBeNull();
    fireEvent.change(picker, { target: { value: "16" } });
    expect(within(first).queryByTestId("match-value")).toBeNull();
    // Another number shows the number input; a number with a name typed there stays in it.
    fireEvent.click(within(dialog).getByTestId("match-add"));
    const second = matchRows(dialog)[1]!;
    fireEvent.change(within(second).getByTestId("match-kind"), { target: { value: "architecture" } });
    fireEvent.change(within(second).getByTestId("match-arch"), { target: { value: "other" } });
    const number = within(second).getByTestId("match-value") as HTMLInputElement;
    fireEvent.input(number, { target: { value: "33" } });
    expect((within(second).getByTestId("match-arch") as HTMLSelectElement).value).toBe("other");
    expect(within(second).getByTestId("match-value")).toBe(number);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dhcp-classes").map((r) => r.dataset.key)).toContain("boot-arch"));
    expect(writes().find((w) => w.method === "POST")?.body).toMatchObject({ matches: [{ architecture: { code: 16 } }, { architecture: { code: 33 } }] });
    const made = within(row("dhcp-classes", "boot-arch")).getAllByTestId("class-match");
    expect(made.map((m) => m.textContent)).toEqual(["client architecture UEFI HTTP x64 (16)", "client architecture 33"]);
  });

  it("checks an architecture that is not chosen", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-class-create"));
    const dialog = await screen.findByTestId("dialog-class-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "none-picked" } });
    fireEvent.change(within(matchRows(dialog)[0]!).getByTestId("match-kind"), { target: { value: "architecture" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").textContent).toBe("Enter a value."));
  });

  it("keeps the focus in a row while its value is typed", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-class-create"));
    const dialog = await screen.findByTestId("dialog-class-form");
    const input = within(matchRows(dialog)[0]!).getByTestId("match-value");
    fireEvent.input(input, { target: { value: "PXE" } });
    fireEvent.input(input, { target: { value: "PXEClient" } });
    expect(within(matchRows(dialog)[0]!).getByTestId("match-value")).toBe(input);
    expect((input as HTMLInputElement).value).toBe("PXEClient");
  });

  it("checks the name and each match before it sends, naming the row", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-class-create"));
    const dialog = await screen.findByTestId("dialog-class-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Bad Name" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["name", "match-0"]));
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "ok-name" } });
    fireEvent.change(within(matchRows(dialog)[0]!).getByTestId("match-kind"), { target: { value: "mac" } });
    fireEvent.input(within(matchRows(dialog)[0]!).getByTestId("match-value"), { target: { value: "00:00" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").textContent).toBe("Enter a MAC pattern such as 00:00:5e:*."));
    fireEvent.change(within(matchRows(dialog)[0]!).getByTestId("match-kind"), { target: { value: "client_id" } });
    fireEvent.input(within(matchRows(dialog)[0]!).getByTestId("match-value"), { target: { value: "xyz" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").textContent).toBe("Enter whole octets in hexadecimal, such as c0ff."));
    expect(writes()).toHaveLength(0);
  });

  it("shows the refusal of the server when the name exists", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-class-create"));
    const dialog = await screen.findByTestId("dialog-class-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "pxe-clients" } });
    fireEvent.input(within(matchRows(dialog)[0]!).getByTestId("match-value"), { target: { value: "x" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").textContent).toBe("The class is not valid (name)."));
  });

  it("removes a match row, but never the last", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-class-create"));
    const dialog = await screen.findByTestId("dialog-class-form");
    expect(within(dialog).queryByTestId("match-remove")).toBeNull();
    fireEvent.click(within(dialog).getByTestId("match-add"));
    expect(matchRows(dialog)).toHaveLength(2);
    fireEvent.click(within(matchRows(dialog)[0]!).getByTestId("match-remove"));
    expect(matchRows(dialog)).toHaveLength(1);
    expect(within(dialog).queryByTestId("match-remove")).toBeNull();
  });

  it("edits a class with the revision read", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    const revision = dhcpState().classes[0]!.revision;
    await rowAction(row("dhcp-classes", "pxe-clients"), "edit");
    const dialog = await screen.findByTestId("dialog-class-form");
    const line = matchRows(dialog)[0]!;
    expect((within(line).getByTestId("match-value") as HTMLInputElement).value).toBe("PXEClient");
    expect((within(line).getByTestId("match-prefix") as HTMLInputElement).checked).toBe(true);
    fireEvent.input(within(line).getByTestId("match-value"), { target: { value: "PXEClient:Arch:00007" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(dhcpState().classes[0]!.matches).toEqual([{ vendor_class: { value: "PXEClient:Arch:00007", prefix: true } }]));
    const sent = writes().find((w) => w.method === "PATCH");
    expect(sent?.ifMatch).toBe(`"${revision}"`);
    expect(sent?.body).toMatchObject({ name: "pxe-clients", description: "Network boot" });
  });

  it("deletes a class nobody names", async () => {
    dhcpState().policies.length = 0;
    open();
    await loaded();
    await rowAction(row("dhcp-classes", "pxe-clients"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-class-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dhcp-classes")).toHaveLength(0));
  });

  it("shows the message of the server when a policy names the class", async () => {
    open();
    await loaded();
    await rowAction(row("dhcp-classes", "pxe-clients"), "delete");
    const dialog = await screen.findByTestId("dialog-class-delete");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    const notice = await within(dialog).findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dhcp.class.in_use");
    expect(notice.textContent).toBe(`This class is named by policy:${DHCP_IDS.policy}.`);
    expect(dhcpState().classes).toHaveLength(1);
  });

  it("offers a viewer nothing to change", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dhcp-class-create")).toBeNull();
    expect(await rowActions(row("dhcp-classes", "pxe-clients"))).toEqual([]);
  });

  it("says the module is switched off", async () => {
    dhcpSwitchedOff();
    open();
    expect(await screen.findByTestId("dhcp-off")).toBeTruthy();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Klientklasser");
    expect(within(row("dhcp-classes", "pxe-clients")).getByTestId("class-match").textContent).toBe('tillverkarklass som börjar med "PXEClient"');
    fireEvent.click(screen.getByTestId("dhcp-class-create"));
    const dialog = await screen.findByTestId("dialog-class-form");
    expect(within(dialog).getByTestId("match-add").textContent).toBe("Lägg till matchning");
  });
});
