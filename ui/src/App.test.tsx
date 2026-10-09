import { createMemoryHistory, MemoryRouter } from "@solidjs/router";
import { fireEvent, render, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { resetMockDb, type MockScenario } from "./api/mock/db";
import { setTheme } from "./app/prefs";
import { axeViolations } from "./app/testing/axe";
import { buildRoutes, Root } from "./App";
import { loadSession, setSessionForTest } from "./auth/session";

async function renderApp(url: string, scenario: MockScenario) {
  resetMockDb(scenario);
  setSessionForTest(null, "loading");
  const history = createMemoryHistory();
  history.set({ value: url });
  const result = render(() => <MemoryRouter history={history} root={Root}>{buildRoutes()}</MemoryRouter>);
  await loadSession();
  return { ...result, location: () => history.get() };
}

afterEach(() => {
  setSessionForTest(null, "loading");
  setTheme("system");
});

describe("access", () => {
  it("sends a signed-out visitor to sign-in and keeps the deep link", async () => {
    const app = await renderApp("/ipam/hosts/nas.example.test", "signed-out");
    await waitFor(() => expect(app.location()).toBe("/signin?next=%2Fipam%2Fhosts%2Fnas.example.test"));
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeTruthy();
  });

  it("sends everyone to the wizard while setup is open", async () => {
    const app = await renderApp("/ipam", "setup");
    await waitFor(() => expect(app.location()).toBe("/setup"));
  });

  it("sends a signed-in user away from the sign-in page to where they wanted to go", async () => {
    const app = await renderApp("/signin?next=%2Fjobs", "signed-in");
    await waitFor(() => expect(app.location()).toBe("/jobs"));
  });
});

describe("shell", () => {
  it("shows the rail in the approved order with labels, and the placeholder for unbuilt areas", async () => {
    const app = await renderApp("/ipam/prefixes/192.0.2.0/24", "signed-in");
    const rail = await screen.findByRole("navigation", { name: "Main" });
    const labels = within(rail)
      .getAllByRole("link")
      .map((a) => a.textContent?.trim());
    expect(labels).toEqual(["Dashboard", "IPAM", "DNS", "DHCP", "Topology", "Jobs", "Settings"]);
    expect(within(rail).getByRole("link", { name: /IPAM/ }).classList.contains("active")).toBe(true);
    expect(await screen.findByText("IPAM arrives in a later build")).toBeTruthy();
    expect(app.location()).toBe("/ipam/prefixes/192.0.2.0/24");
  });

  it("opens the command palette with Ctrl+K and runs a navigation command", async () => {
    const app = await renderApp("/", "signed-in");
    await screen.findByRole("navigation", { name: "Main" });
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    const input = await screen.findByRole("combobox", { name: "Search" });
    fireEvent.input(input, { target: { value: ">jobs" } });
    const option = await screen.findByRole("option", { name: /Jobs/ });
    expect(option.getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(app.location()).toBe("/jobs"));
    expect(screen.queryByRole("dialog", { name: "Command palette" })).toBeNull();
  });

  it("finds addresses and hosts through the search API", async () => {
    await renderApp("/", "signed-in");
    await screen.findByRole("navigation", { name: "Main" });
    fireEvent.click(screen.getByRole("button", { name: "Open command palette" }));
    const input = await screen.findByRole("combobox", { name: "Search" });
    fireEvent.input(input, { target: { value: "nas" } });
    expect(await screen.findByRole("option", { name: /Search everything for/ })).toBeTruthy();
  });

  it("navigates with G chords and opens the shortcuts sheet with ?", async () => {
    const app = await renderApp("/", "signed-in");
    await screen.findByRole("navigation", { name: "Main" });
    fireEvent.keyDown(document, { key: "g" });
    fireEvent.keyDown(document, { key: "s" });
    await waitFor(() => expect(app.location()).toMatch(/^\/settings/));
    fireEvent.keyDown(document, { key: "?" });
    const sheet = await screen.findByRole("dialog", { name: "Keyboard shortcuts" });
    expect(within(sheet).getByText("Command palette and search")).toBeTruthy();
    fireEvent.keyDown(sheet, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Keyboard shortcuts" })).toBeNull());
  });

  it("ignores single-key shortcuts while typing", async () => {
    const app = await renderApp("/", "signed-in");
    await screen.findByRole("navigation", { name: "Main" });
    const field = document.createElement("input");
    document.body.appendChild(field);
    fireEvent.keyDown(field, { key: "g" });
    fireEvent.keyDown(field, { key: "j" });
    expect(app.location()).toBe("/");
    field.remove();
  });

  it("shows the Lab banner, which cannot be dismissed", async () => {
    await renderApp("/", "lab");
    const banner = await screen.findByRole("alert");
    expect(banner.textContent).toContain("Lab profile active.");
    expect(within(banner).queryByRole("button", { name: /dismiss|close/i })).toBeNull();
  });

  it("opens the account menu with theme, density and emphasis", async () => {
    await renderApp("/", "signed-in");
    const avatar = await screen.findByRole("button", { name: /Account menu for/ });
    fireEvent.click(avatar);
    const menu = await screen.findByRole("dialog", { name: "Account and preferences" });
    fireEvent.click(within(menu).getByRole("button", { name: "Dark" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
    fireEvent.click(within(menu).getByRole("button", { name: "Dense" }));
    expect(document.documentElement.dataset.density).toBe("dense");
    fireEvent.click(within(menu).getByRole("button", { name: "Compact" }));
    expect(document.documentElement.dataset.density).toBeUndefined();
    const emphasis = within(menu).getByRole("switch", { name: /Emphasize host part/ });
    fireEvent.click(emphasis);
    expect(document.documentElement.dataset.emphasize).toBe("host");
    fireEvent.click(emphasis);
    expect(document.documentElement.dataset.emphasize).toBeUndefined();
  });

  it("signs out from the account menu", async () => {
    const app = await renderApp("/", "signed-in");
    fireEvent.click(await screen.findByRole("button", { name: /Account menu for/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(app.location()).toBe("/signin"));
  });

  it("has no accessibility violations on the dashboard and in the palette", async () => {
    const app = await renderApp("/", "signed-in");
    await screen.findByRole("navigation", { name: "Main" });
    await screen.findByRole("heading", { name: /Dashboard/ });
    expect(await axeViolations(app.container)).toEqual([]);
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    const dialog = await screen.findByRole("dialog", { name: "Command palette" });
    expect(await axeViolations(dialog)).toEqual([]);
  });
});
