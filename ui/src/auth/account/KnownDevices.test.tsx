import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { db } from "../../api/mock/db";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import Account from "./Account";
import { signInAlex } from "./testkit";

const NO_SHELL = { disable: ["region"] } as const;

function show() {
  return renderRoute(Account, { url: "/account/sessions", path: "/account/:section?" });
}

/** The data rows of the table of known devices (the header row left out). */
function rows(): HTMLTableRowElement[] {
  const table = screen.getByTestId("known-devices");
  return within(table).getAllByRole("row").slice(1) as HTMLTableRowElement[];
}

describe("known devices", () => {
  it("lists this browser and the others under the sessions, with the dates", async () => {
    await signInAlex();
    show();
    await screen.findByRole("heading", { name: "Known devices" });
    await screen.findByTestId("known-devices");
    expect(rows()).toHaveLength(2);
    const columns = within(screen.getByTestId("known-devices"))
      .getAllByRole("columnheader")
      .map((c) => c.textContent);
    expect(columns).toEqual(expect.arrayContaining(["Last sign-in", "Known since", "Known until"]));
    // One badge, on the newest sign-in: this browser, signed in just now.
    expect(screen.getAllByText("This browser")).toHaveLength(1);
    const current = rows()[0];
    if (!current) throw new Error("no row");
    expect(within(current).getByText("This browser")).toBeTruthy();
    expect(within(current).getByText(/seconds? ago|now/i)).toBeTruthy();
    const other = rows()[1];
    if (!other) throw new Error("no row");
    expect(within(other).getByText(/3 days ago/)).toBeTruthy();
    const cells = within(other).getAllByRole("cell");
    expect(cells[1]?.textContent).not.toBe("");
    expect(cells[2]?.textContent).not.toBe("");
    expect(within(other).queryByText("This browser")).toBeNull();
  });

  it("explains in plain words what a known device is and when it is forgotten", async () => {
    await signInAlex();
    show();
    const lede = await screen.findByText(/becomes a known device/);
    expect(lede.textContent).toContain("does not sign you in by itself");
    expect(lede.textContent).toContain("30 days without a sign-in");
    expect(lede.textContent).toContain("when your password changes");
  });

  it("asks before forgetting one device, then takes it off the list", async () => {
    await signInAlex();
    show();
    await screen.findByTestId("known-devices");
    const other = rows()[1];
    if (!other) throw new Error("no row");
    fireEvent.click(within(other).getByRole("button", { name: /^Forget the device that last signed in / }));
    const dialog = await screen.findByRole("dialog", { name: "Forget this device?" });
    // Nothing has happened yet.
    expect(db.knownDevices).toHaveLength(3);
    fireEvent.click(within(dialog).getByRole("button", { name: "Forget device" }));
    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(screen.getByText("Device forgotten")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(within(rows()[0] as HTMLElement).getByText("This browser")).toBeTruthy();
  });

  it("leaves everything as it is when the confirmation is canceled", async () => {
    await signInAlex();
    show();
    await screen.findByTestId("known-devices");
    fireEvent.click(screen.getByRole("button", { name: "Forget all" }));
    const dialog = await screen.findByRole("dialog", { name: "Forget all known devices?" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(rows()).toHaveLength(2);
  });

  it("forgets all devices with the count on the button, and then shows the empty state", async () => {
    await signInAlex();
    show();
    await screen.findByTestId("known-devices");
    fireEvent.click(screen.getByRole("button", { name: "Forget all" }));
    const dialog = await screen.findByRole("dialog", { name: "Forget all known devices?" });
    expect(dialog.textContent).toContain("The 2 known devices of this account are forgotten.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Forget 2 devices" }));
    expect(await screen.findByText("2 devices forgotten")).toBeTruthy();
    expect(await screen.findByText(/No browser is known for your account yet/)).toBeTruthy();
    expect(screen.queryByTestId("known-devices")).toBeNull();
    expect(screen.getByRole("button", { name: "Forget all" }).hasAttribute("disabled")).toBe(true);
    // Sessions are untouched.
    expect(db.currentSessionId).not.toBeNull();
  });

  it("uses the singular for one device", async () => {
    await signInAlex();
    db.knownDevices = db.knownDevices.filter((d) => d.id === db.currentDeviceId);
    show();
    await screen.findByTestId("known-devices");
    fireEvent.click(screen.getByRole("button", { name: "Forget all" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toContain("The 1 known device of this account is forgotten.");
    expect(within(dialog).getByRole("button", { name: "Forget 1 device" })).toBeTruthy();
  });

  it("shows the empty state at once when no device is known", async () => {
    await signInAlex();
    db.knownDevices = [];
    show();
    expect(await screen.findByText(/No browser is known for your account yet/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Forget all" }).hasAttribute("disabled")).toBe(true);
  });

  it("has no accessibility violations on the section or in the confirmation", async () => {
    await signInAlex();
    const { container } = show();
    await screen.findByTestId("known-devices");
    expect(await axeViolations(container)).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Forget all" }));
    await screen.findByRole("dialog");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });
});
