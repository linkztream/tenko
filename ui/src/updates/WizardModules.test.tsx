import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db, resetMockDb } from "../api/mock/db";
import { MOCK_SETUP_TOKEN } from "../api/mock/fixtures";
import { mockUpdates } from "../api/mock/routes-updates";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { authState, setSessionForTest } from "../auth/session";
import { dismissToast } from "../components/toast";
import { setLocale } from "../i18n";
import Wizard from "../setup/Wizard";
import { resetModules } from "./modules";

const GOOD_PASSWORD = "quiet-orchard-ember-17";

beforeEach(async () => {
  await setLocale("en");
  resetModules();
});

afterEach(() => {
  setSessionForTest(null, "loading");
  vi.unstubAllGlobals();
  for (let id = 1; id <= 50; id++) dismissToast(id);
});

async function start() {
  resetMockDb("setup");
  setSessionForTest(null, "setup");
  const view = renderRoute(Wizard, { url: "/setup", path: "/setup", routes: { "/": () => <div data-testid="dashboard" /> } });
  await screen.findByRole("heading", { name: "Welcome to Tenko DDI" });
  await screen.findByLabelText("Setup token");
  return view;
}

function next() {
  fireEvent.click(screen.getByRole("button", { name: /^(Continue|Finish setup)/ }));
}

function blocker(): string {
  return document.querySelector(".wz-blocker")?.textContent?.trim() ?? "";
}

async function heading(name: string | RegExp) {
  return screen.findByRole("heading", { level: 1, name });
}

function type(label: string | RegExp, value: string) {
  fireEvent.input(screen.getByLabelText(label), { target: { value } });
}

/** Through the steps up to the roles step. */
async function toRoles() {
  await start();
  type("Setup token", MOCK_SETUP_TOKEN);
  next();
  await heading("Security profile");
  fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
  next();
  await heading("Administrator");
  type("User name", "admin1");
  type("Display name", "Admin One");
  type(/^(Password|PIN|Passphrase)$/, GOOD_PASSWORD);
  await waitFor(() => expect(blocker()).toBe(""), { timeout: 3000 });
  next();
  await heading("Host name and TLS");
  type("Host name", "tenko1.example.test");
  next();
  await heading("Data directory");
  next();
  await heading("Roles for this node");
}

function module(name: string): HTMLInputElement {
  return document.querySelector<HTMLInputElement>(`[data-testid="setup-module"][data-key="${name}"]`) as HTMLInputElement;
}

async function finish() {
  next();
  // The DNS upstreams step (WP5.5) comes between the roles and the review.
  await heading("Where DNS asks next");
  next();
  await heading("Review and finish");
  next();
  await heading("Setup complete");
  await waitFor(() => expect(authState()).toBe("signed-in"));
}

describe("the module choice of the first-run wizard", () => {
  it("asks what the installation is for, with all four modules selected", async () => {
    await toRoles();
    const group = screen.getByRole("group", { name: "What is this installation for?" });
    const boxes = within(group).getAllByRole("checkbox");
    expect(boxes).toHaveLength(4);
    expect(boxes.map((b) => b.getAttribute("data-key"))).toEqual(["ipam", "dns", "dhcp", "discovery"]);
    expect(boxes.every((b) => (b as HTMLInputElement).checked)).toBe(true);
    for (const [name, label] of [
      ["ipam", "IPAM"],
      ["dns", "DNS"],
      ["dhcp", "DHCP"],
      ["discovery", "Discovery"],
    ] as const) {
      expect(within(group).getByRole("checkbox", { name: new RegExp(`^${label}`) })).toBe(module(name));
    }
    // One line of description each.
    expect(within(group).getByText("Plan and record networks, addresses, VLANs and hosts.")).toBeTruthy();
    expect(within(group).getByText("Serve and manage DNS zones.")).toBeTruthy();
    expect(within(group).getByText("Serve and manage DHCP scopes and leases.")).toBeTruthy();
    expect(within(group).getByText(/Find devices on the networks/)).toBeTruthy();
    // Only the modules without code yet say that they arrive later.
    const later = within(group).getAllByText("Arrives in a later version");
    expect(later).toHaveLength(3);
    expect(module("ipam").closest("label")?.textContent).not.toContain("later version");
    // The roles of the node are still there.
    expect(screen.getAllByTestId("setup-role")).toHaveLength(4);
    expect(await axeViolations(screen.getByTestId("page-setup"))).toEqual([]);
  });

  it("refuses to continue when no module is selected, and names the way out", async () => {
    await toRoles();
    for (const name of ["ipam", "dns", "dhcp", "discovery"]) fireEvent.click(module(name));
    expect(module("ipam").checked).toBe(false);
    next();
    expect(blocker()).toBe("Select at least one module.");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Roles for this node");
    expect(document.activeElement).toBe(module("ipam"));

    fireEvent.click(module("dns"));
    next();
    await heading("Where DNS asks next");
  });

  it("refuses to jump past the roles step with no module selected", async () => {
    await toRoles();
    for (const name of ["ipam", "dns", "dhcp", "discovery"]) fireEvent.click(module(name));
    const steps = screen.getByRole("navigation", { name: "Setup steps" });
    fireEvent.click(within(steps).getByRole("button", { name: /Done/ }));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Roles for this node");
    expect(blocker()).toBe("Select at least one module.");
  });

  it("sends nothing about the modules when all four stay selected", async () => {
    await toRoles();
    await finish();
    expect(db.setupOpen).toBe(false);
    expect(mockUpdates.modulesPuts).toBe(0);
    expect(mockUpdates.modules.configured).toEqual(["ipam", "dns", "dhcp", "discovery"]);
  });

  it("sends the choice after setup, with the new session, when it is not all four", async () => {
    await toRoles();
    fireEvent.click(module("dns"));
    fireEvent.click(module("dhcp"));
    await finish();
    await waitFor(() => expect(mockUpdates.modulesPuts).toBe(1));
    expect(mockUpdates.modules.configured).toEqual(["ipam", "discovery"]);
    // A restart is needed before the choice applies.
    expect(mockUpdates.modules.running).toEqual(["ipam", "dns", "dhcp", "discovery"]);
  });

  it("keeps a single module", async () => {
    await toRoles();
    for (const name of ["dns", "dhcp", "discovery"]) fireEvent.click(module(name));
    await finish();
    await waitFor(() => expect(mockUpdates.modules.configured).toEqual(["ipam"]));
  });

  it("ignores a refusal because tenko.toml pins the modules", async () => {
    await toRoles();
    mockUpdates.modules.pinned = true;
    fireEvent.click(module("dns"));
    await finish();
    await waitFor(() => expect(mockUpdates.modulesPuts).toBe(1));
    expect(mockUpdates.modules.configured).toEqual(["ipam", "dns", "dhcp", "discovery"]);
    expect(screen.queryByTestId("toast")).toBeNull();
    // The wizard went on to its result as usual.
    expect(screen.getByRole("heading", { level: 1, name: "Setup complete" })).toBeTruthy();
  });

  it("shows any other refusal", async () => {
    await toRoles();
    mockUpdates.modules.unavailable = true;
    fireEvent.click(module("dns"));
    await finish();
    const toast = await screen.findByTestId("toast");
    expect(toast.textContent).toContain("The module choice could not be saved");
    expect(toast.textContent).toContain("This installation does not manage its modules from the web interface.");
    expect(screen.getByRole("heading", { level: 1, name: "Setup complete" })).toBeTruthy();
  });
});
