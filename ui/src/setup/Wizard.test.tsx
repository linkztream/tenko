import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db, resetMockDb, type MockScenario } from "../api/mock/db";
import { MOCK_SETUP_TOKEN } from "../api/mock/fixtures";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { authState, setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import Wizard from "./Wizard";

const GOOD_PASSWORD = "quiet-orchard-ember-17";

beforeEach(async () => {
  await setLocale("en");
});

afterEach(() => {
  setSessionForTest(null, "loading");
  vi.unstubAllGlobals();
});

function bytes(...values: number[]): ArrayBuffer {
  return new Uint8Array(values).buffer;
}

/** A stand-in for navigator.credentials.create() returning an attestation-shaped object. */
function stubPasskeyCreation() {
  const create = vi.fn(async () => ({
    id: "bmV3LWtleQ",
    rawId: bytes(110, 101, 119),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: bytes(1, 2, 3),
      attestationObject: bytes(4, 5, 6),
      getTransports: () => ["internal"],
    },
  }));
  vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
  Object.defineProperty(navigator, "credentials", { value: { create, get: vi.fn() }, configurable: true });
  return create;
}

async function start(scenario: MockScenario = "setup") {
  resetMockDb(scenario);
  setSessionForTest(null, "setup");
  const view = renderRoute(Wizard, {
    url: "/setup",
    path: "/setup",
    routes: { "/": () => <div data-testid="dashboard" /> },
  });
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

// WP8.6: the DHCP step follows the DNS step; these tests set the first scope up later.
async function passDhcpLater() {
  await heading("The first DHCP scope");
  const later = document.querySelector<HTMLInputElement>('[data-testid="setup-dhcp-mode"][data-key="later"]');
  if (later) fireEvent.click(later);
  next();
  await heading("Review and finish");
}

function type(label: string | RegExp, value: string) {
  fireEvent.input(screen.getByLabelText(label), { target: { value } });
}

async function passWelcome(token = MOCK_SETUP_TOKEN) {
  type("Setup token", token);
  next();
  await heading("Security profile");
}

async function passAdmin(password = GOOD_PASSWORD) {
  type("User name", "admin1");
  type("Display name", "Admin One");
  type(/^(Password|PIN|Passphrase)$/, password);
  await waitFor(() => expect(blocker()).toBe(""), { timeout: 3000 });
  next();
  await heading("Host name and TLS");
}

async function passHost(name = "tenko1.example.test") {
  type("Host name", name);
  next();
  await heading("Data directory");
}

describe("first-run wizard", () => {
  it("needs the setup token before anything else", async () => {
    await start();
    next();
    expect(blocker()).toBe("Enter the setup token to continue.");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Welcome to Tenko DDI");
    await passWelcome();
  });

  it("makes Lab loud and blocks until the operator acknowledges it", async () => {
    await start();
    await passWelcome();
    fireEvent.click(screen.getByRole("radio", { name: /^Lab/ }));
    const banner = await screen.findByRole("alert");
    expect(banner.textContent).toContain("Lab profile selected.");
    const table = screen.getByRole("table", { name: "Key settings for the selected profile" });
    expect(within(table).getAllByText("Weaker than Home").length).toBeGreaterThan(0);
    next();
    expect(blocker()).toBe("Tick the confirmation to continue with Lab.");
    fireEvent.click(screen.getByRole("checkbox", { name: "I understand this node must not serve a production network" }));
    next();
    await heading("Administrator");
  });

  it("shows no weaker setting for Standard", async () => {
    await start();
    await passWelcome();
    fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
    const table = screen.getByRole("table", { name: "Key settings for the selected profile" });
    expect(within(table).queryByText("Weaker than Home")).toBeNull();
  });

  it("checks the administrator's password live against the profile and known breaches", async () => {
    await start();
    await passWelcome();
    fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
    next();
    await heading("Administrator");
    type("User name", "admin1");
    type("Display name", "Admin One");
    type("Password", "password1234");
    await waitFor(() => expect(blocker()).toBe("The password does not meet every item on the checklist yet."), {
      timeout: 3000,
    });
    expect(screen.getByText(/known breaches/i)).toBeTruthy();
    type("Password", GOOD_PASSWORD);
    await waitFor(() => expect(blocker()).toBe(""), { timeout: 3000 });
  });

  it("generates a password that meets the policy", async () => {
    await start();
    await passWelcome();
    fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
    next();
    await heading("Administrator");
    type("User name", "admin1");
    type("Display name", "Admin One");
    fireEvent.click(screen.getByRole("button", { name: "Generate" }));
    const field = screen.getByLabelText("Password") as HTMLInputElement;
    expect(field.value.length).toBe(16);
    await waitFor(() => expect(blocker()).toBe(""), { timeout: 3000 });
  });

  it("refuses an IP address as host name and needs trusted proxies in reverse-proxy mode", async () => {
    await start();
    await passWelcome();
    fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
    next();
    await heading("Administrator");
    await passAdmin();
    for (const bad of ["192.0.2.13", "2001:db8::1"]) {
      type("Host name", bad);
      next();
      expect(blocker()).toBe("Enter a valid DNS host name, not an IP address.");
    }
    type("Host name", "tenko1.example.test");
    fireEvent.click(screen.getByRole("radio", { name: /^TLS in a reverse proxy/ }));
    next();
    expect(blocker()).toBe("List at least one trusted proxy address or prefix.");
    type("Trusted proxies", "proxy.example.test");
    next();
    expect(blocker()).toBe("Fix the entries that are not IP addresses or prefixes.");
    type("Trusted proxies", "192.0.2.1\n198.51.100.0/24\n2001:db8::/32");
    next();
    await heading("Data directory");
  });

  it("offers plain HTTP only with Lab", async () => {
    await start();
    await passWelcome();
    fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
    next();
    await heading("Administrator");
    await passAdmin();
    expect((screen.getByRole("radio", { name: /^Plain HTTP/ }) as HTMLInputElement).disabled).toBe(true);
  });

  it("blocks a rotating disk until the override is ticked", async () => {
    await start("setup-slow-disk");
    await passWelcome();
    fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
    next();
    await heading("Administrator");
    await passAdmin();
    await passHost();
    expect(screen.getByText("This disk is not supported.")).toBeTruthy();
    next();
    expect(blocker()).toBe("Move the data directory to an SSD, or tick the override.");
    fireEvent.click(screen.getByRole("checkbox", { name: /Use it anyway for a short test/ }));
    next();
    await heading("Roles for this node");
  });

  it("completes setup, adds the first passkey, shows the recovery codes once and opens Tenko after they are saved", async () => {
    const create = stubPasskeyCreation();
    const view = await start();
    await passWelcome();
    fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
    next();
    await heading("Administrator");
    await passAdmin();
    await passHost();
    next();
    await heading("Roles for this node");
    next();
    await heading("Where DNS asks next");
    next();
    await passDhcpLater();
    next();
    await heading("Setup complete");
    await waitFor(() => expect(authState()).toBe("signed-in"));
    expect(db.setupOpen).toBe(false);
    // A password-only account has no recovery codes yet: they come with the first passkey.
    expect(await screen.findByText(/Recovery codes are created together with your first passkey/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Add a passkey" }));
    const codes = await screen.findByRole("list", { name: "Recovery codes" });
    expect(create).toHaveBeenCalledTimes(1);
    expect(within(codes).getAllByRole("listitem")).toHaveLength(10);
    const open = screen.getByRole("button", { name: /^Open Tenko/ });
    expect(open.getAttribute("aria-disabled")).toBe("true");
    fireEvent.click(open);
    expect(blocker()).toBe("Confirm that you have saved the recovery codes.");
    fireEvent.click(screen.getByRole("checkbox", { name: "I have saved the recovery codes" }));
    fireEvent.click(screen.getByRole("button", { name: /^Open Tenko/ }));
    await waitFor(() => expect(view.location()).toBe("/"));
  });

  it("returns to the first step with the reason when the setup token is wrong", async () => {
    await start();
    await passWelcome("0000-0000-0000-0000");
    fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
    next();
    await heading("Administrator");
    await passAdmin();
    await passHost();
    next();
    await heading("Roles for this node");
    next();
    await heading("Where DNS asks next");
    next();
    await passDhcpLater();
    next();
    await heading("Welcome to Tenko DDI");
    expect((await screen.findByRole("alert")).textContent).toContain("The setup token is wrong.");
    expect(db.setupOpen).toBe(true);
  });

  it("goes back with Alt+Left and from the step list", async () => {
    await start();
    await passWelcome();
    fireEvent.keyDown(document.activeElement ?? document.body, { key: "ArrowLeft", altKey: true });
    await heading("Welcome to Tenko DDI");
    next();
    await heading("Security profile");
    const steps = screen.getByRole("navigation", { name: "Setup steps" });
    fireEvent.click(within(steps).getByRole("button", { name: /Welcome/ }));
    await heading("Welcome to Tenko DDI");
  });

  it("has no accessibility violations on the steps", async () => {
    const { container } = await start();
    expect(await axeViolations(container)).toEqual([]);
    await passWelcome();
    fireEvent.click(screen.getByRole("radio", { name: /^Lab/ }));
    expect(await axeViolations(container)).toEqual([]);
    fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
    next();
    await heading("Administrator");
    expect(await axeViolations(container)).toEqual([]);
    await passAdmin();
    expect(await axeViolations(container)).toEqual([]);
    await passHost();
    expect(await axeViolations(container)).toEqual([]);
    next();
    await heading("Roles for this node");
    expect(await axeViolations(container)).toEqual([]);
    next();
    await heading("Where DNS asks next");
    expect(await axeViolations(container)).toEqual([]);
    next();
    await passDhcpLater();
    expect(await axeViolations(container)).toEqual([]);
    next();
    await heading("Setup complete");
    await screen.findByText(/Recovery codes are created together with your first passkey/);
    expect(await axeViolations(container)).toEqual([]);
  });
});
