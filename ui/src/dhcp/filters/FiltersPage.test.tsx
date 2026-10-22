// The MAC filters: the list with allow and deny, adding an entry with the local check of the pattern
// (six hexadecimal octets, `*` for any octet, or a prefix ending in `*`), the server's refusal of a
// second entry for one pattern, editing with the revision, deleting, who sees what, Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { dhcpState } from "../../api/mock/routes-dhcp";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { cell, dhcpSwitchedOff, recordIfMatch, row, rowAction, rowActions, rows } from "../testkit";
import FiltersPage from "./FiltersPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(FiltersPage, { url: "/dhcp/filters", path: "/dhcp/filters" });
const loaded = () => waitFor(() => expect(rows("dhcp-filters").length).toBeGreaterThan(0));

describe("the MAC filters", () => {
  it("lists the entries with allow or deny and the note", async () => {
    const view = open();
    await loaded();
    const lab = row("dhcp-filters", "00:00:5e:00:53:*");
    expect(within(lab).getByTestId("filter-kind").dataset.key).toBe("allow");
    expect(within(lab).getByTestId("filter-kind").textContent).toBe("Allow");
    expect(cell(lab, "note").textContent).toBe("The lab");
    expect(screen.getByTestId("filters-note").textContent).toContain("Deny wins over allow.");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("checks the pattern before it sends and stores it the way the server does", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-filter-create"));
    const dialog = await screen.findByTestId("dialog-filter-form");
    for (const bad of ["00:00:5e", "00:00:5g:00:53:01", "", "00:00:5e:00:53:01:02"]) {
      fireEvent.input(within(dialog).getByTestId("field-mac"), { target: { value: bad } });
      fireEvent.click(within(dialog).getByTestId("form-submit"));
      await waitFor(() => expect(within(dialog).getByTestId("field-error").dataset.field).toBe("mac"));
    }
    expect(writes()).toHaveLength(0);
    fireEvent.input(within(dialog).getByTestId("field-mac"), { target: { value: "02-00-5E-*" } });
    fireEvent.click(within(dialog).getByTestId("field-kind-deny"));
    fireEvent.input(within(dialog).getByTestId("field-note"), { target: { value: "Guests" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dhcp-filters").map((r) => r.dataset.key)).toEqual(["00:00:5e:00:53:*", "02:00:5e:*:*:*"]));
    expect(writes().find((w) => w.method === "POST")?.body).toEqual({ mac: "02:00:5e:*:*:*", kind: "deny", note: "Guests" });
    expect(within(row("dhcp-filters", "02:00:5e:*:*:*")).getByTestId("filter-kind").dataset.key).toBe("deny");
  });

  it("shows the refusal of the server for a pattern that has an entry", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-filter-create"));
    const dialog = await screen.findByTestId("dialog-filter-form");
    fireEvent.input(within(dialog).getByTestId("field-mac"), { target: { value: "00:00:5E:00:53:*" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").textContent).toBe("An entry for this pattern exists already."));
    expect(rows("dhcp-filters")).toHaveLength(1);
  });

  it("edits an entry with the revision read and clears the note with an empty text", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    const revision = dhcpState().filters[0]!.revision;
    await rowAction(row("dhcp-filters", "00:00:5e:00:53:*"), "edit");
    const dialog = await screen.findByTestId("dialog-filter-form");
    expect((within(dialog).getByTestId("field-kind-allow") as HTMLInputElement).checked).toBe(true);
    fireEvent.click(within(dialog).getByTestId("field-kind-deny"));
    fireEvent.input(within(dialog).getByTestId("field-note"), { target: { value: "" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(dhcpState().filters[0]!.kind).toBe("deny"));
    expect(dhcpState().filters[0]!.note).toBeUndefined();
    const sent = writes().find((w) => w.method === "PATCH");
    expect(sent?.ifMatch).toBe(`"${revision}"`);
    expect(sent?.body).toEqual({ mac: "00:00:5e:00:53:*", kind: "deny", note: "" });
  });

  it("deletes an entry after the confirmation", async () => {
    open();
    await loaded();
    await rowAction(row("dhcp-filters", "00:00:5e:00:53:*"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-filter-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dhcp-filters")).toHaveLength(0));
    expect(await screen.findByTestId("dhcp-filters-empty")).toBeTruthy();
  });

  it("offers a viewer nothing to change", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dhcp-filter-create")).toBeNull();
    expect(await rowActions(row("dhcp-filters", "00:00:5e:00:53:*"))).toEqual([]);
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
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("MAC-filter");
    expect(within(row("dhcp-filters", "00:00:5e:00:53:*")).getByTestId("filter-kind").textContent).toBe("Tillåt");
  });
});
