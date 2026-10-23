// The DNS step of the first-run wizard (P2-Q5): the choice between resolving names itself
// (the default) and forwarding them, the upstreams, the well-known resolver that offers DNS over
// TLS, the Home preset, the step that says it has nothing to set when DNS is not part of the
// installation, the review row, and what finishing does with the upstreams (the root forwarding
// rule and the [dns] section on the result step; recursion writes no rule).
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetMockDb } from "../api/mock/db";
import { MOCK_SETUP_TOKEN } from "../api/mock/fixtures";
import { server } from "../api/mock/node";
import { dnsResolverState } from "../api/mock/routes-dns";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import Wizard from "./Wizard";

const PASSWORD = "quiet-orchard-ember-17";
const PIN = "73920146";

beforeEach(async () => {
  await setLocale("en");
});

afterEach(() => {
  setSessionForTest(null, "loading");
  vi.unstubAllGlobals();
});

async function start() {
  resetMockDb("setup");
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

function field(testid: string): HTMLInputElement | HTMLTextAreaElement {
  return screen.getByTestId(testid) as HTMLInputElement | HTMLTextAreaElement;
}

function upstreams(text: string) {
  fireEvent.input(field("field-dns-upstreams"), { target: { value: text } });
}

function control(testid: string, key: string): HTMLInputElement {
  const found = screen.getAllByTestId(testid).find((el) => el.dataset.key === key);
  if (!found) throw new Error(`no ${testid} ${key}`);
  return found as HTMLInputElement;
}

function switchFor(key: string): HTMLInputElement {
  return control("setup-dns-switch", key);
}

function checks(): string[] {
  return screen.queryAllByTestId("setup-dns-check").map((el) => el.dataset.key ?? "");
}

/** Walks to the roles step: the profile, an administrator, a host name, the data directory. */
async function toRoles(profile: "home" | "standard" = "home") {
  await start();
  type("Setup token", MOCK_SETUP_TOKEN);
  next();
  await heading("Security profile");
  if (profile === "standard") fireEvent.click(screen.getByRole("radio", { name: /^Standard/ }));
  next();
  await heading("Administrator");
  type("User name", "admin1");
  type("Display name", "Admin One");
  type(/^(Password|PIN|Passphrase)$/, profile === "home" ? PIN : PASSWORD);
  await waitFor(() => expect(blocker()).toBe(""), { timeout: 3000 });
  next();
  await heading("Host name and TLS");
  type("Host name", "tenko1.example.test");
  next();
  await heading("Data directory");
  next();
  await heading("Roles for this node");
}

async function toDns(profile: "home" | "standard" = "home") {
  await toRoles(profile);
  next();
  await heading("Where DNS asks next");
}

/** Chooses to forward names to resolvers; the upstream fields appear. */
function forward() {
  fireEvent.click(control("setup-dns-resolve", "forward"));
}

async function toDnsForward(profile: "home" | "standard" = "home") {
  await toDns(profile);
  forward();
}

/** Chooses to forward, types the Quad9 addresses and chooses DNS over TLS with the offered name. */
async function chooseQuad9Dot() {
  forward();
  upstreams("9.9.9.9\n149.112.112.112");
  fireEvent.click(await screen.findByTestId("setup-dns-use-dot"));
}

describe("the DNS step of the wizard", () => {
  it("starts with the node resolving names itself, the privacy sentence and no upstream field", async () => {
    await toDns();
    expect(screen.getByTestId("setup-dns").dataset.state).toBe("wanted");
    expect(control("setup-dns-resolve", "recurse").checked).toBe(true);
    expect(control("setup-dns-resolve", "forward").checked).toBe(false);
    expect(screen.getByTestId("setup-dns-privacy").textContent).toContain("Resolving yourself sends each name to the authorities of its zone");
    expect(screen.queryByTestId("field-dns-upstreams")).toBeNull();
    expect(screen.queryByTestId("setup-dns-transport")).toBeNull();
    expect(screen.queryByTestId("field-dns-tls-name")).toBeNull();
    expect(screen.queryByTestId("setup-dns-known")).toBeNull();
    // The step can be left without a word about upstreams.
    next();
    await passDhcpLater();
    const row = screen.getByTestId("setup-review-dns");
    expect(row.dataset.count).toBe("0");
    expect(row.dataset.resolve).toBe("recurse");
    expect(row.textContent).toContain("Resolved by Tenko itself");
  });

  it("shows the upstream fields for forwarding, plain DNS first, and hides them again for recursion", async () => {
    await toDnsForward();
    expect(control("setup-dns-resolve", "forward").checked).toBe(true);
    expect(field("field-dns-upstreams").value).toBe("");
    expect(control("setup-dns-transport", "plain").checked).toBe(true);
    expect(control("setup-dns-transport", "dot").checked).toBe(false);
    expect(screen.queryByTestId("setup-dns-known")).toBeNull();
    expect(screen.queryByTestId("field-dns-tls-name")).toBeNull();
    // The privacy sentence stays under both choices.
    expect(screen.getByTestId("setup-dns-privacy")).toBeTruthy();
    fireEvent.click(control("setup-dns-resolve", "recurse"));
    expect(screen.queryByTestId("field-dns-upstreams")).toBeNull();
    expect(screen.queryAllByTestId("setup-dns-transport")).toHaveLength(0);
  });

  it("blocks forwarding without an upstream and lets the step go once one is typed", async () => {
    await toDnsForward();
    next();
    expect(blocker()).toBe("Fix the upstreams: each is an IP address with an optional port.");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Where DNS asks next");
    expect(document.activeElement).toBe(field("field-dns-upstreams"));
    upstreams("192.0.2.1");
    expect(blocker()).toBe("");
    next();
    await passDhcpLater();
    expect(screen.getByTestId("setup-review-dns").dataset.resolve).toBe("forward");
    expect(screen.getByTestId("setup-review-dns").dataset.count).toBe("1");
  });

  it("lets recursion pass with upstreams typed earlier and ignores them", async () => {
    const before = dnsResolverState().forwarders.length;
    await toDnsForward();
    upstreams("192.0.2.1");
    fireEvent.click(control("setup-dns-resolve", "recurse"));
    next();
    await passDhcpLater();
    expect(screen.getByTestId("setup-review-dns").dataset.count).toBe("0");
    expect(screen.getByTestId("setup-review-dns").dataset.resolve).toBe("recurse");
    next();
    await heading("Setup complete");
    expect((await screen.findByTestId("setup-dns-none")).dataset.resolve).toBe("recurse");
    expect(dnsResolverState().forwarders).toHaveLength(before);
    expect(screen.getByTestId("setup-dns-config").textContent).toContain("forwarders = []");
  });

  it("offers DNS over TLS for the addresses of a well-known resolver and fills its TLS name", async () => {
    await toDnsForward();
    upstreams("9.9.9.9\n149.112.112.112");
    const known = await screen.findByTestId("setup-dns-known");
    expect(known.dataset.key).toBe("dns.quad9.net");
    expect(known.textContent).toContain("These are addresses of Quad9, which also answers over DNS over TLS as dns.quad9.net.");
    fireEvent.click(within(known).getByTestId("setup-dns-use-dot"));
    expect(control("setup-dns-transport", "dot").checked).toBe(true);
    expect(control("setup-dns-transport", "plain").checked).toBe(false);
    expect(field("field-dns-tls-name").value).toBe("dns.quad9.net");
    expect(screen.queryByTestId("setup-dns-known")).toBeNull();
  });

  it("offers nothing for addresses that are not all those of one well-known resolver", async () => {
    await toDnsForward();
    upstreams("9.9.9.9\n192.0.2.1");
    await waitFor(() => expect(field("field-dns-upstreams").value).toBe("9.9.9.9\n192.0.2.1"));
    expect(screen.queryByTestId("setup-dns-known")).toBeNull();
    upstreams("9.9.9.9\n1.1.1.1");
    expect(screen.queryByTestId("setup-dns-known")).toBeNull();
    upstreams("1.1.1.1");
    expect((await screen.findByTestId("setup-dns-known")).dataset.key).toBe("cloudflare-dns.com");
  });

  it("asks for the TLS name when the transport needs one", async () => {
    await toDnsForward();
    upstreams("192.0.2.1");
    fireEvent.click(control("setup-dns-transport", "dot"));
    expect(field("field-dns-tls-name")).toBeTruthy();
    next();
    expect(blocker()).toBe("Give the TLS name of the resolvers for DNS over TLS or HTTPS.");
    expect(document.activeElement).toBe(field("field-dns-tls-name"));
    fireEvent.input(field("field-dns-tls-name"), { target: { value: "dns.example.test" } });
    expect(blocker()).toBe("");
    next();
    await passDhcpLater();
  });

  it("blocks a bad upstream and stays on the step", async () => {
    await toDnsForward();
    upstreams("192.0.2.1\nnot-an-address");
    next();
    expect(blocker()).toBe("Fix the upstreams: each is an IP address with an optional port.");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Where DNS asks next");
    expect(document.activeElement).toBe(field("field-dns-upstreams"));
    upstreams("192.0.2.1\n198.51.100.7:5353");
    expect(blocker()).toBe("");
    next();
    await passDhcpLater();
  });

  it("blocks a cache bound out of range", async () => {
    await toDns();
    fireEvent.input(field("field-dns-entries"), { target: { value: "0" } });
    next();
    expect(blocker()).toBe("The cache takes 1 to 10000000 entries.");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Where DNS asks next");
    fireEvent.input(field("field-dns-entries"), { target: { value: "20000" } });
    next();
    await passDhcpLater();
  });

  it("presets the switches of the Home profile and the preset button restores them", async () => {
    await toDns();
    expect(switchFor("cache").checked).toBe(true);
    expect(switchFor("dot").checked).toBe(false);
    expect(switchFor("doh").checked).toBe(false);
    expect(switchFor("log").checked).toBe(false);
    expect(field("field-dns-entries").value).toBe("10000");
    const preset = screen.getByTestId("setup-dns-preset") as HTMLButtonElement;
    expect(preset.disabled).toBe(true);
    expect(screen.getByText("Home preset")).toBeTruthy();

    fireEvent.click(switchFor("log"));
    fireEvent.click(switchFor("dot"));
    expect(switchFor("log").checked).toBe(true);
    expect(preset.disabled).toBe(false);
    expect(screen.queryByText("Home preset")).toBeNull();

    fireEvent.click(preset);
    expect(switchFor("log").checked).toBe(false);
    expect(switchFor("dot").checked).toBe(false);
    expect(preset.disabled).toBe(true);
    expect(screen.getByText("Home preset")).toBeTruthy();
  });

  it("hides the cache bound while the cache is off", async () => {
    await toDns();
    fireEvent.click(switchFor("cache"));
    expect(screen.queryByTestId("field-dns-entries")).toBeNull();
    // A bound that would be out of range does not matter then.
    fireEvent.click(switchFor("cache"));
    fireEvent.input(field("field-dns-entries"), { target: { value: "0" } });
    fireEvent.click(switchFor("cache"));
    next();
    await passDhcpLater();
  });

  it("lists the ports to open, and adds the TLS ports when DoT or DoH is served", async () => {
    await toDns();
    expect(checks()).toEqual(["role", "port", "capability", "firewall"]);
    fireEvent.click(switchFor("doh"));
    expect(checks()).toEqual(["role", "port", "capability", "firewall", "tls_ports"]);
    fireEvent.click(switchFor("doh"));
    expect(checks()).toEqual(["role", "port", "capability", "firewall"]);
    fireEvent.click(switchFor("dot"));
    expect(checks()).toContain("tls_ports");
  });

  it("turns the query log on and takes 100,000 entries when the profile is Standard", async () => {
    await toDns("standard");
    expect(switchFor("log").checked).toBe(true);
    expect(field("field-dns-entries").value).toBe("100000");
    expect(switchFor("dot").checked).toBe(false);
    expect((screen.getByTestId("setup-dns-preset") as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByTestId("setup-dns-preset"));
    expect(switchFor("log").checked).toBe(false);
    expect(field("field-dns-entries").value).toBe("10000");
  });

  it("says it has nothing to set when the DNS module is not chosen", async () => {
    await toRoles();
    fireEvent.click(control("setup-module", "dns"));
    expect(control("setup-module", "dns").checked).toBe(false);
    next();
    await heading("Where DNS asks next");
    const step = screen.getByTestId("setup-dns");
    expect(step.dataset.state).toBe("skipped");
    expect(step.textContent).toContain("DNS is not part of this installation");
    expect(screen.queryByTestId("field-dns-upstreams")).toBeNull();
    next();
    await passDhcpLater();
    expect(screen.queryByTestId("setup-review-dns")).toBeNull();
  });

  it("says it has nothing to set when the node does not take the dns role", async () => {
    await toRoles();
    fireEvent.click(control("setup-role", "dns"));
    next();
    await heading("Where DNS asks next");
    expect(screen.getByTestId("setup-dns").dataset.state).toBe("skipped");
    next();
    await passDhcpLater();
    expect(screen.queryByTestId("setup-review-dns")).toBeNull();
  });

  it("shows the upstreams on the review step with the transport and the TLS name", async () => {
    await toDns();
    await chooseQuad9Dot();
    next();
    await passDhcpLater();
    const row = screen.getByTestId("setup-review-dns");
    expect(row.dataset.count).toBe("2");
    expect(row.textContent).toBe("9.9.9.9, 149.112.112.112");
    expect(row.closest("div")?.textContent).toContain("DNS over TLS");
    expect(row.closest("div")?.textContent).toContain("dns.quad9.net");
  });

  it("stores the upstreams as the root rule, and shows the [dns] section with the TLS name", async () => {
    const before = dnsResolverState().forwarders.length;
    await toDns();
    await chooseQuad9Dot();
    fireEvent.click(switchFor("dot"));
    next();
    await passDhcpLater();
    next();
    await heading("Setup complete");
    await waitFor(() => expect(screen.getByTestId("setup-result-dns").dataset.state).toBe("saved"));

    const rules = dnsResolverState().forwarders;
    expect(rules).toHaveLength(before + 1);
    const root = rules.find((r) => r.suffix === ".");
    expect(root).toMatchObject({
      suffix: ".",
      transport: "dot",
      tls_name: "dns.quad9.net",
      upstreams: [{ address: "9.9.9.9" }, { address: "149.112.112.112" }],
    });

    expect(screen.getByTestId("setup-dns-saved")).toBeTruthy();
    expect(screen.queryByTestId("setup-dns-failed")).toBeNull();
    const config = screen.getByTestId("setup-dns-config").textContent ?? "";
    expect(config).toContain('{ address = "9.9.9.9", transport = "dot", tls_name = "dns.quad9.net" },');
    expect(config).toContain('{ address = "149.112.112.112", transport = "dot", tls_name = "dns.quad9.net" },');
    expect(config).toContain("[dns.cache]\nenabled = true\n");
    expect(config).toContain("[dns.tls]\ndot = true\ndoh = false\n");
    expect(config).toContain("[dns.log]\nenabled = false\n");
    const list = screen.getByTestId("setup-dns-checklist");
    expect(within(list).getAllByTestId("setup-dns-check").map((el) => el.dataset.key)).toEqual(["role", "port", "capability", "firewall", "tls_ports"]);
  });

  it("creates no rule when the node resolves names itself and says so on the result step", async () => {
    const before = dnsResolverState().forwarders.length;
    await toDns();
    next();
    await passDhcpLater();
    next();
    await heading("Setup complete");
    const result = await screen.findByTestId("setup-result-dns");
    expect(result.dataset.state).toBe("none");
    const none = screen.getByTestId("setup-dns-none");
    expect(none.dataset.resolve).toBe("recurse");
    expect(none.textContent).toContain("Tenko resolves names itself; no forwarding rule was written.");
    expect(dnsResolverState().forwarders).toHaveLength(before);
    expect(screen.getByTestId("setup-dns-config").textContent).toContain("forwarders = []");
    expect(screen.queryByTestId("setup-dns-saved")).toBeNull();
  });

  it("says so, and keeps the section to copy, when the root rule is refused", async () => {
    server.use(
      http.post("/api/v1/dns/forwarders", () =>
        HttpResponse.json(
          { type: "about:blank", status: 404, code: "sys.route_not_found", title: "Not Found", detail: "no such route", params: {} },
          { status: 404, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    const before = dnsResolverState().forwarders.length;
    await toDns();
    await chooseQuad9Dot();
    next();
    await passDhcpLater();
    next();
    await heading("Setup complete");
    const failed = await screen.findByTestId("setup-dns-failed");
    expect(failed.textContent).toContain("The upstreams were not stored as the default forwarder");
    expect(screen.getByTestId("setup-result-dns").dataset.state).toBe("failed");
    expect(screen.queryByTestId("setup-dns-saved")).toBeNull();
    expect(dnsResolverState().forwarders).toHaveLength(before);
    expect(screen.getByTestId("setup-dns-config").textContent).toContain('tls_name = "dns.quad9.net"');
  });

  it("has no accessibility violations on the DNS step", async () => {
    const { container } = await start();
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
    next();
    await heading("Where DNS asks next");
    expect(await axeViolations(container)).toEqual([]);
    await chooseQuad9Dot();
    expect(await axeViolations(container)).toEqual([]);
  });
});
