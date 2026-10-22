// WP8.6: the DHCP step of the first-run wizard: the first scope from the node's network, the
// checks behind the step's gate, "later", the step that says it has nothing to set when DHCP is
// not part of the installation, the review row, and what finishing does (the IPAM network, the
// pool, the scope with its router and DNS servers, the [dhcp] section on the result step).
import { fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetMockDb } from "../api/mock/db";
import { MOCK_SETUP_TOKEN } from "../api/mock/fixtures";
import { server } from "../api/mock/node";
import { dhcpState } from "../api/mock/routes-dhcp";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { defaultPool, dhcpPlan, dhcpStepProblem, generateDhcpConfig, initialDhcp, leaseSecs, scopeLease, type DhcpStepState } from "./dhcp";
import Wizard from "./Wizard";

const PIN = "73920146";

beforeEach(async () => {
  await setLocale("en");
});

afterEach(() => {
  setSessionForTest(null, "loading");
  vi.unstubAllGlobals();
});

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

function field(testid: string): HTMLInputElement {
  return screen.getByTestId(testid) as HTMLInputElement;
}

function fill(testid: string, value: string) {
  fireEvent.input(field(testid), { target: { value } });
}

function control(testid: string, key: string): HTMLInputElement {
  const found = screen.getAllByTestId(testid).find((el) => el.dataset.key === key);
  if (!found) throw new Error(`no ${testid} ${key}`);
  return found as HTMLInputElement;
}

/** Walks to the roles step and, unless `stop` says otherwise, on to the DHCP step. */
async function toDhcp(options: { roles?: (container: HTMLElement) => void } = {}) {
  resetMockDb("setup");
  setSessionForTest(null, "setup");
  const view = renderRoute(Wizard, { url: "/setup", path: "/setup", routes: { "/": () => <div data-testid="dashboard" /> } });
  await screen.findByRole("heading", { name: "Welcome to Tenko DDI" });
  await screen.findByLabelText("Setup token");
  type("Setup token", MOCK_SETUP_TOKEN);
  next();
  await heading("Security profile");
  next();
  await heading("Administrator");
  type("User name", "admin1");
  type("Display name", "Admin One");
  type(/^(Password|PIN|Passphrase)$/, PIN);
  await waitFor(() => expect(blocker()).toBe(""), { timeout: 3000 });
  next();
  await heading("Host name and TLS");
  type("Host name", "tenko1.example.test");
  next();
  await heading("Data directory");
  next();
  await heading("Roles for this node");
  options.roles?.(view.container);
  next();
  await heading("Where DNS asks next");
  next();
  await heading("The first DHCP scope");
  return view;
}

/** Fills the router and confirms the other server is off: what the node's network leaves open. */
function completeScope() {
  fill("field-dhcp-router", "192.0.2.1");
  fireEvent.click(field("field-dhcp-others-off"));
}

const STATE: DhcpStepState = {
  mode: "now",
  network: "192.0.2.0/24",
  poolFirst: "192.0.2.128",
  poolLast: "192.0.2.254",
  router: "192.0.2.1",
  dns: "",
  lease: "24",
  leaseUnit: "hours",
  listen: "relay",
  address: "192.0.2.10",
  iface: "",
  othersOff: true,
};

describe("the DHCP step's rules", () => {
  it("proposes the upper half of a network as the pool and starts from the node's first IPv4 network", () => {
    expect(defaultPool("192.0.2.0/24")).toEqual({ first: "192.0.2.128", last: "192.0.2.254" });
    expect(defaultPool("198.51.100.64/26")).toEqual({ first: "198.51.100.96", last: "198.51.100.126" });
    expect(defaultPool("2001:db8::/64")).toBeNull();
    expect(defaultPool("192.0.2.0/30")).toBeNull();
    const state = initialDhcp([{ id: "lan", name: "LAN", prefix: "192.0.2.0/24", interface: "eth0", address: "192.0.2.13" }]);
    expect(state).toMatchObject({ mode: "now", network: "192.0.2.0/24", poolFirst: "192.0.2.128", address: "192.0.2.13", iface: "eth0", othersOff: false });
    expect(initialDhcp([]).mode).toBe("later");
  });

  it("checks every field in order and nothing while the step is not wanted or set up later", () => {
    expect(dhcpStepProblem(STATE, true)).toBeNull();
    expect(dhcpStepProblem({ ...STATE, network: "192.0.2.0" }, true)).toBe("network");
    expect(dhcpStepProblem({ ...STATE, network: "2001:db8::/64" }, true)).toBe("network");
    expect(dhcpStepProblem({ ...STATE, poolFirst: "198.51.100.5" }, true)).toBe("pool_first");
    expect(dhcpStepProblem({ ...STATE, poolLast: "192.0.2.255" }, true)).toBe("pool_last");
    expect(dhcpStepProblem({ ...STATE, poolFirst: "192.0.2.200", poolLast: "192.0.2.150" }, true)).toBe("pool_order");
    expect(dhcpStepProblem({ ...STATE, router: "" }, true)).toBe("router");
    expect(dhcpStepProblem({ ...STATE, router: "192.0.2.130" }, true)).toBe("router_in_pool");
    expect(dhcpStepProblem({ ...STATE, dns: "192.0.2.53, dns.example.test" }, true)).toBe("dns");
    expect(dhcpStepProblem({ ...STATE, dns: "", address: "" }, true)).toBe("dns");
    expect(dhcpStepProblem({ ...STATE, lease: "0" }, true)).toBe("lease");
    expect(dhcpStepProblem({ ...STATE, lease: "400", leaseUnit: "days" }, true)).toBe("lease");
    expect(dhcpStepProblem({ ...STATE, dns: "192.0.2.53", address: "" }, true)).toBe("address");
    expect(dhcpStepProblem({ ...STATE, listen: "direct", iface: "" }, true)).toBe("iface");
    expect(dhcpStepProblem({ ...STATE, othersOff: false }, true)).toBe("others_off");
    expect(dhcpStepProblem({ ...STATE, router: "" }, false)).toBeNull();
    expect(dhcpStepProblem({ ...STATE, mode: "later", router: "" }, true)).toBeNull();
  });

  it("plans the scope with this server's address as the DNS server and writes the [dhcp] section", () => {
    const plan = dhcpPlan({ ...STATE, network: "192.0.2.77/24" }, true);
    expect(plan).toEqual({
      network: "192.0.2.0/24",
      poolFirst: "192.0.2.128",
      poolLast: "192.0.2.254",
      router: "192.0.2.1",
      dns: ["192.0.2.10"],
      leaseSecs: 86_400,
      listen: "relay",
      address: "192.0.2.10",
      iface: null,
    });
    expect(generateDhcpConfig(plan)).toContain('listen = [{ address = "192.0.2.10", mode = "relay" }]');
    const direct = dhcpPlan({ ...STATE, listen: "direct", iface: "eth0", dns: "192.0.2.53 198.51.100.53" }, true);
    expect(direct?.dns).toEqual(["192.0.2.53", "198.51.100.53"]);
    expect(generateDhcpConfig(direct)).toContain('listen = [{ address = "192.0.2.10", mode = "direct", interface = "eth0" }]');
    expect(generateDhcpConfig(null)).toContain("listen = []");
    expect(leaseSecs({ lease: "2", leaseUnit: "days" })).toBe(172_800);
    expect(scopeLease(86_400)).toEqual({ default_secs: 86_400, min_secs: 3600, max_secs: 604_800 });
    expect(scopeLease(1_209_600)).toEqual({ default_secs: 1_209_600, min_secs: 3600, max_secs: 1_209_600 });
  });
});

describe("the DHCP step of the wizard", () => {
  it("starts from the node's first network and asks for the router and the confirmation", async () => {
    await toDhcp();
    const step = screen.getByTestId("setup-dhcp");
    expect(step.dataset.state).toBe("wanted");
    expect(control("setup-dhcp-mode", "now").checked).toBe(true);
    expect(field("field-dhcp-network").value).toBe("192.0.2.0/24");
    expect(field("field-dhcp-pool-first").value).toBe("192.0.2.128");
    expect(field("field-dhcp-pool-last").value).toBe("192.0.2.254");
    expect(field("field-dhcp-address").value).toBe("192.0.2.13");
    expect(field("field-dhcp-dns").placeholder).toBe("192.0.2.13");
    expect(control("setup-dhcp-listen", "relay").checked).toBe(true);
    expect(screen.getByTestId("setup-dhcp-safety").textContent).toContain("Switch off any other DHCP server on the same network first");
    expect(screen.getByTestId("setup-dhcp-privacy").textContent).toContain("30 days");
    next();
    await heading("The first DHCP scope");
    expect(blocker()).toBe("Enter the router's address in this network.");
    fill("field-dhcp-router", "192.0.2.200");
    next();
    expect(blocker()).toBe("The router's address must lie outside the pool.");
    fill("field-dhcp-router", "192.0.2.1");
    next();
    expect(blocker()).toBe("Confirm that no other DHCP server answers on this network.");
    fireEvent.click(field("field-dhcp-others-off"));
    expect(screen.getByTestId("setup-dhcp-summary").textContent).toBe(
      "Clients in 192.0.2.0/24 get an address from 192.0.2.128 to 192.0.2.254, the router 192.0.2.1 and the DNS servers 192.0.2.13.",
    );
    // Another of the node's networks proposes its own pool while the pool is still the proposal.
    fireEvent.click(control("setup-dhcp-network-choice", "198.51.100.0/24"));
    expect(field("field-dhcp-pool-first").value).toBe("198.51.100.128");
    expect(field("field-dhcp-address").value).not.toBe("192.0.2.13");
    // Direct mode needs the interface.
    fireEvent.click(control("setup-dhcp-listen", "direct"));
    expect(screen.getByTestId("field-dhcp-iface")).toBeTruthy();
  });

  it("creates the network, the pool and the scope with its router and DNS servers when setup finishes", async () => {
    await toDhcp();
    const before = new Set(dhcpState().scopes.map((s) => s.prefix));
    completeScope();
    fill("field-dhcp-lease", "2");
    fireEvent.change(field("field-dhcp-lease-unit"), { target: { value: "days" } });
    next();
    await heading("Review and finish");
    const review = screen.getByTestId("setup-review-dhcp");
    expect(review.dataset.state).toBe("now");
    expect(review.textContent).toContain("192.0.2.0/24");
    next();
    await heading("Setup complete");
    await waitFor(() => expect(screen.getByTestId("setup-result-dhcp").dataset.state).toBe("saved"));
    expect(screen.getByTestId("setup-dhcp-saved").textContent).toContain("The scope for 192.0.2.0/24 was created");
    expect(screen.getByTestId("setup-dhcp-config").textContent).toContain('listen = [{ address = "192.0.2.13", mode = "relay" }]');

    const state = dhcpState();
    const added = state.scopes.filter((s) => !before.has(s.prefix));
    expect(added).toHaveLength(1);
    const scope = added[0]!;
    expect(scope.lease).toMatchObject({ default_secs: 172_800, min_secs: 3600, max_secs: 604_800 });
    const options = state.optionSets.get(`scope:${scope.prefix}`)?.values ?? [];
    expect(options.map((o) => o.code)).toEqual([3, 6]);
    expect(screen.getByTestId("setup-dhcp-scope-link").getAttribute("href")).toContain(`/dhcp/scopes/${scope.prefix}`);
  });

  it("creates nothing when the scope is set up later, and still shows the section to fill in", async () => {
    await toDhcp();
    const before = dhcpState().scopes.length;
    fireEvent.click(control("setup-dhcp-mode", "later"));
    expect(screen.queryByTestId("field-dhcp-network")).toBeNull();
    next();
    await heading("Review and finish");
    expect(screen.getByTestId("setup-review-dhcp").dataset.state).toBe("later");
    next();
    await heading("Setup complete");
    expect((await screen.findByTestId("setup-result-dhcp")).dataset.state).toBe("none");
    expect(screen.getByTestId("setup-dhcp-config").textContent).toContain("listen = []");
    expect(dhcpState().scopes).toHaveLength(before);
  });

  it("says where it stopped when the scope is refused", async () => {
    server.use(
      http.post("/api/v1/dhcp/scopes", () =>
        HttpResponse.json(
          { type: "about:blank", status: 409, code: "dhcp.module.disabled", title: "Conflict", detail: "the DHCP module is off", params: {} },
          { status: 409, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    await toDhcp();
    completeScope();
    next();
    await heading("Review and finish");
    next();
    await heading("Setup complete");
    const failed = await screen.findByTestId("setup-dhcp-failed");
    expect(failed.textContent).toContain("The network and its pool exist, but the scope could not be created");
    expect(screen.getByTestId("setup-result-dhcp").dataset.state).toBe("failed");
  });

  it("says it has nothing to set when the node does not take the dhcp role", async () => {
    await toDhcp({
      roles: (container) => {
        const box = container.querySelector<HTMLInputElement>('[data-testid="setup-role"][data-key="dhcp"]');
        if (box) fireEvent.click(box);
      },
    });
    expect(screen.getByTestId("setup-dhcp").dataset.state).toBe("skipped");
    expect(screen.getByTestId("setup-dhcp").textContent).toContain("DHCP is not part of this installation");
    next();
    await heading("Review and finish");
    expect(screen.queryByTestId("setup-review-dhcp")).toBeNull();
  });

  it("has no accessibility violations on the DHCP step", async () => {
    const { container } = await toDhcp();
    expect(await axeViolations(container)).toEqual([]);
    fireEvent.click(control("setup-dhcp-listen", "direct"));
    expect(await axeViolations(container)).toEqual([]);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    await toDhcpSwedish();
    expect(screen.getByTestId("setup-dhcp-safety").textContent).toContain("Stäng först av alla andra DHCP-servrar");
  });
});

/** The same walk in Swedish, by test ids and the button's role. */
async function toDhcpSwedish() {
  resetMockDb("setup");
  setSessionForTest(null, "setup");
  renderRoute(Wizard, { url: "/setup", path: "/setup", routes: { "/": () => <div data-testid="dashboard" /> } });
  const go = () => fireEvent.click(screen.getByRole("button", { name: /^(Fortsätt|Slutför installationen)/ }));
  await waitFor(() => expect(document.getElementById("wz-token")).toBeTruthy());
  fireEvent.input(document.getElementById("wz-token")!, { target: { value: MOCK_SETUP_TOKEN } });
  go();
  await waitFor(() => expect(screen.getByTestId("setup-card").dataset.key).toBe("profile"));
  go();
  await waitFor(() => expect(screen.getByTestId("setup-card").dataset.key).toBe("admin"));
  fireEvent.input(document.getElementById("wz-user")!, { target: { value: "admin1" } });
  fireEvent.input(document.getElementById("wz-name")!, { target: { value: "Admin One" } });
  fireEvent.input(document.getElementById("wz-pw")!, { target: { value: PIN } });
  await waitFor(() => expect(blocker()).toBe(""), { timeout: 3000 });
  go();
  await waitFor(() => expect(screen.getByTestId("setup-card").dataset.key).toBe("host"));
  fireEvent.input(document.getElementById("wz-host")!, { target: { value: "tenko1.example.test" } });
  go();
  await waitFor(() => expect(screen.getByTestId("setup-card").dataset.key).toBe("disk"));
  go();
  await waitFor(() => expect(screen.getByTestId("setup-card").dataset.key).toBe("roles"));
  go();
  await waitFor(() => expect(screen.getByTestId("setup-card").dataset.key).toBe("dns"));
  go();
  await waitFor(() => expect(screen.getByTestId("setup-card").dataset.key).toBe("dhcp"));
}
