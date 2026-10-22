// The DHCP server settings (/settings/dhcp): the lease times in human units, authoritative, conflict
// detection and the history retention with "follow the security profile" and the value in force,
// saved with the revision; the local checks; the server's refusal; the page for administrators
// only; the module-off state; Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { dhcpState } from "../../api/mock/routes-dhcp";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { dhcpSwitchedOff, recordIfMatch } from "../testkit";
import DhcpSettingsPage from "./DhcpSettingsPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(DhcpSettingsPage, { url: "/settings/dhcp", path: "/settings/dhcp" });
const loaded = () => screen.findByTestId("dhcp-settings-form");
const field = (id: string) => screen.getByTestId(id) as HTMLInputElement;

describe("the DHCP settings", () => {
  it("shows the lease times in human units and the values in force for what follows the profile", async () => {
    const view = open();
    await loaded();
    expect(screen.getByTestId("page-dhcp-settings")).toBeTruthy();
    expect([field("field-lease-default").value, (screen.getByTestId("field-lease-default-unit") as HTMLSelectElement).value]).toEqual(["1", "days"]);
    expect([field("field-lease-min").value, (screen.getByTestId("field-lease-min-unit") as HTMLSelectElement).value]).toEqual(["1", "hours"]);
    expect([field("field-lease-max").value, (screen.getByTestId("field-lease-max-unit") as HTMLSelectElement).value]).toEqual(["7", "days"]);
    expect(field("field-authoritative").checked).toBe(true);
    expect(field("field-conflict-follow").checked).toBe(true);
    expect(field("field-history-follow").checked).toBe(true);
    expect(screen.getByTestId("settings-effective-conflict").dataset.value).toBe("true");
    expect(screen.getByTestId("settings-effective-conflict").textContent).toBe("In force now: on.");
    expect(screen.getByTestId("settings-effective-history").textContent).toBe("In force now: 90 days.");
    expect(screen.queryByTestId("field-conflict")).toBeNull();
    expect(screen.getByTestId("settings-nav")).toBeTruthy();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("saves with the revision read, setting what no longer follows the profile", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    const revision = dhcpState().settings.revision;
    fireEvent.input(field("field-lease-default"), { target: { value: "12" } });
    fireEvent.change(screen.getByTestId("field-lease-default-unit"), { target: { value: "hours" } });
    fireEvent.click(field("field-authoritative"));
    fireEvent.click(field("field-conflict-follow"));
    fireEvent.click(await screen.findByTestId("field-conflict"));
    fireEvent.click(field("field-history-follow"));
    fireEvent.input(await screen.findByTestId("field-history_days"), { target: { value: "14" } });
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(dhcpState().settings.history_days).toBe(14));
    const sent = writes().find((w) => w.method === "PUT");
    expect(sent?.ifMatch).toBe(`"${revision}"`);
    expect(sent?.body).toEqual({
      authoritative: false,
      ddns: {},
      lease: { default_secs: 43_200, min_secs: 3600, max_secs: 604_800 },
      conflict_detection: false,
      history_days: 14,
    });
    expect(dhcpState().settings.conflict_detection).toBe(false);
    expect(await screen.findByText("DHCP settings saved")).toBeTruthy();
    // A second save uses the revision of the first.
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(writes().filter((w) => w.method === "PUT")).toHaveLength(2));
    expect(writes().filter((w) => w.method === "PUT")[1]?.ifMatch).toBe(`"${dhcpState().settings.revision}"`);
  });

  it("lets the profile decide again when the settings follow it", async () => {
    dhcpState().settings.history_days = 14;
    dhcpState().settings.conflict_detection = false;
    const writes = recordIfMatch();
    open();
    await loaded();
    expect(field("field-conflict-follow").checked).toBe(false);
    expect(field("field-history-follow").checked).toBe(false);
    fireEvent.click(field("field-conflict-follow"));
    fireEvent.click(field("field-history-follow"));
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(dhcpState().settings.history_days).toBeUndefined());
    expect(dhcpState().settings.conflict_detection).toBeUndefined();
    expect(writes().find((w) => w.method === "PUT")?.body).not.toHaveProperty("history_days");
  });

  it("checks the lease times and the days before it sends", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.input(field("field-lease-min"), { target: { value: "3" } });
    fireEvent.change(screen.getByTestId("field-lease-min-unit"), { target: { value: "days" } });
    fireEvent.click(field("field-history-follow"));
    fireEvent.input(await screen.findByTestId("field-history_days"), { target: { value: "0" } });
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(screen.getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["lease-min", "history_days"]));
    expect(screen.getAllByTestId("field-error")[0]?.textContent).toBe("The shortest time must not exceed the default, and the default must not exceed the longest.");
    expect(writes()).toHaveLength(0);
  });

  it("shows the refusal of a save over settings that changed meanwhile", async () => {
    open();
    await loaded();
    dhcpState().settings.revision += 4;
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("sys.store.precondition_failed");
  });

  it("says the module is switched off", async () => {
    dhcpSwitchedOff();
    open();
    expect(await screen.findByTestId("dhcp-off")).toBeTruthy();
    expect(screen.queryByTestId("dhcp-settings-form")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("DHCP-inställningar");
    expect(screen.getByTestId("settings-effective-history").textContent).toBe("Gäller nu: 90 dagar.");
    expect(within(screen.getByTestId("dhcp-settings-form")).getByTestId("dhcp-settings-save").textContent).toBe("Spara");
  });
});
