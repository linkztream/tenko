import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { db } from "../api/mock/db";
import { MOCK_USER_IDS } from "../api/mock/fixtures";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { setSessionForTest } from "../auth/session";
import Settings from "./Settings";
import { SETTINGS_PATH, signInAs } from "./testkit";

afterEach(() => setSessionForTest(null));

async function openUsers() {
  const view = renderRoute(Settings, { url: "/settings/users", path: SETTINGS_PATH });
  const table = await screen.findByRole("table", { name: "Users" });
  await within(table).findByText("sam");
  return { ...view, table };
}

function rowOf(table: HTMLElement, name: string): HTMLElement {
  const cell = within(table).getByText(name);
  const row = cell.closest("tr");
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

async function openDetail(name: keyof typeof MOCK_USER_IDS) {
  const view = renderRoute(Settings, { url: `/settings/users/${MOCK_USER_IDS[name]}`, path: SETTINGS_PATH });
  await screen.findByRole("navigation", { name: "Breadcrumb" });
  return view;
}

describe("user administration", () => {
  it("lists the users with their roles, methods and status in words", async () => {
    await signInAs();
    const { table } = await openUsers();
    expect(within(rowOf(table, "alex")).getByText("You")).toBeTruthy();
    expect(within(rowOf(table, "alex")).getByText(/Administrator/)).toBeTruthy();
    expect(within(rowOf(table, "sam")).getByText(/Locked until/)).toBeTruthy();
    expect(within(rowOf(table, "robin")).getByText("Disabled")).toBeTruthy();
    expect(within(rowOf(table, "breakglass")).getAllByText("Break-glass account").length).toBeGreaterThan(0);
  });

  it("opens a user from the list", async () => {
    await signInAs();
    const view = await openUsers();
    fireEvent.click(within(rowOf(view.table, "sam")).getByRole("link", { name: /sam/ }));
    await waitFor(() => expect(view.location()).toBe(`/settings/users/${MOCK_USER_IDS.sam}`));
    expect(await screen.findByRole("button", { name: "Unlock" })).toBeTruthy();
  });

  it("unlocks a locked user and says so", async () => {
    await signInAs();
    await openDetail("sam");
    fireEvent.click(await screen.findByRole("button", { name: "Unlock" }));
    expect(await screen.findByText("Unlocked sam")).toBeTruthy();
    await waitFor(() => expect(screen.queryByRole("button", { name: "Unlock" })).toBeNull());
    expect(db.users.find((u) => u.name === "sam")?.lock ?? null).toBeNull();
  });

  it("shows a taken user name on the field when adding a user", async () => {
    await signInAs();
    await openUsers();
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
    const dialog = await screen.findByRole("dialog", { name: "Add user" });
    fireEvent.input(within(dialog).getByLabelText("User name"), { target: { value: "sam" } });
    // Viewer is preselected.
    expect((within(dialog).getByRole("checkbox", { name: /Viewer/ }) as HTMLInputElement).checked).toBe(true);
    fireEvent.click(within(dialog).getByRole("button", { name: "Add user" }));
    expect(await within(dialog).findByText("That user name is taken.")).toBeTruthy();
  });

  it("adds a user who then appears in the list", async () => {
    await signInAs();
    const { table } = await openUsers();
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
    const dialog = await screen.findByRole("dialog", { name: "Add user" });
    fireEvent.input(within(dialog).getByLabelText("User name"), { target: { value: "kim" } });
    fireEvent.input(within(dialog).getByLabelText("Display name"), { target: { value: "Kim Example" } });
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /Operator/ }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Add user" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Add user" })).toBeNull());
    expect(await within(table).findByText("kim")).toBeTruthy();
    expect(db.users.some((u) => u.name === "kim" && u.roles.includes("operator"))).toBe(true);
  });

  it("keeps the last administrator", async () => {
    await signInAs();
    await openDetail("alex");
    fireEvent.click(await screen.findByRole("button", { name: "Change roles" }));
    const dialog = await screen.findByRole("dialog", { name: "Change roles" });
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /Administrator/ }));
    const viewer = within(dialog).getByRole("checkbox", { name: /Viewer/ }) as HTMLInputElement;
    if (!viewer.checked) fireEvent.click(viewer);
    fireEvent.click(within(dialog).getByRole("button", { name: "Save roles" }));
    expect(await within(dialog).findByText("At least one active administrator must remain.")).toBeTruthy();
    expect(db.users.find((u) => u.name === "alex")?.roles).toContain("admin");
  });

  it("does not let you disable or delete your own account, and says why", async () => {
    await signInAs();
    await openDetail("alex");
    await screen.findByRole("button", { name: "Change roles" });
    expect((screen.getByRole("button", { name: "Disable" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Delete user" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/You cannot disable your own account here/)).toBeTruthy();
    expect(screen.getByText(/You cannot delete your own account/)).toBeTruthy();
  });

  it("asks before signing a user out everywhere, naming the user", async () => {
    await signInAs();
    await openDetail("sam");
    fireEvent.click(await screen.findByRole("button", { name: "Sign out everywhere" }));
    const dialog = await screen.findByRole("dialog", { name: "Sign sam out everywhere?" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Sign sam out everywhere" }));
    expect(await screen.findByText("Signed sam out everywhere")).toBeTruthy();
  });

  it("has no accessibility violations on the list, the detail and a dialog", async () => {
    await signInAs();
    const list = await openUsers();
    expect(await axeViolations(list.container)).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
    const dialog = await screen.findByRole("dialog", { name: "Add user" });
    expect(await axeViolations(dialog)).toEqual([]);
    list.unmount();
    const detail = await openDetail("sam");
    expect(await axeViolations(detail.container)).toEqual([]);
  });
});
