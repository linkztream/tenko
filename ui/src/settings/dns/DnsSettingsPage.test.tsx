// The DNS settings page: the node's DNS role read-only, grouped as tenko.toml groups it, with the
// listeners and the key behind each figure; the notices for a log that is off, problems the node
// reports, a node without the role, a switched-off module and a server without the service.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { server } from "../../api/mock/node";
import { dnsLogState, dnsResolverState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { dnsNotBuilt } from "../../dns/testkit";
import { setLocale } from "../../i18n";
import DnsSettingsPage from "./DnsSettingsPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

function open() {
  return renderRoute(DnsSettingsPage, { url: "/settings/dns", path: "/settings/dns" });
}

async function loaded() {
  await screen.findByTestId("dns-settings-tls");
}

function setting(key: string): HTMLElement {
  const found = screen.getAllByTestId("dns-setting").find((el) => el.dataset.key === key);
  if (!found) throw new Error(`no setting ${key}`);
  return found;
}

function problem(status: number, code: string, title: string, params: Record<string, string> = {}) {
  return HttpResponse.json(
    { type: "about:blank", status, code, title, detail: title, params },
    { status, headers: { "content-type": "application/problem+json" } },
  );
}

/** A node status with DoT and DoH served and no cache figure beyond the entries. */
function tlsStatus() {
  return HttpResponse.json({
    node: 1,
    serving: true,
    revision: 7,
    lag: 0,
    zones: 1,
    rrsets: 2,
    listeners: [
      { address: "192.0.2.53:53", transport: "udp", workers: 2 },
      { address: "192.0.2.53:53", transport: "tcp", workers: 0 },
      { address: "192.0.2.53:853", transport: "dot", workers: 0 },
      { address: "[2001:db8::53]:443", transport: "doh", workers: 0 },
    ],
    cache_entries: 5,
    problems: [],
  });
}

describe("the DNS settings page", () => {
  it("shows the listeners of the node with their transport and the key that sets them", async () => {
    open();
    await loaded();
    expect(screen.getByTestId("page-dns-settings")).toBeTruthy();
    const listeners = screen.getAllByTestId("dns-settings-listener");
    expect(listeners.map((l) => l.dataset.kind)).toEqual(["udp", "tcp"]);
    expect(listeners[0]?.dataset.key).toBe("192.0.2.53:53");
    expect(listeners[0]?.textContent).toContain("[dns] listen");
    expect(within(listeners[0]!).getAllByRole("cell")[2]?.textContent).toBe("2");
    expect(within(listeners[1]!).getAllByRole("cell")[2]?.textContent).toBe("");
    const tls = screen.getByTestId("dns-settings-tls");
    expect(tls.dataset.dot).toBe("false");
    expect(tls.dataset.doh).toBe("false");
    expect(tls.textContent).toBe("DNS over TLS not served, DNS over HTTPS not served ([dns.tls] dot and doh).");
  });

  it("shows the cache figures with the percent of the hit ratio and the key behind a setting", async () => {
    open();
    await loaded();
    const entries = setting("cache_entries");
    expect(entries.dataset.value).toBe("1234");
    expect(entries.textContent).toContain("1,234");
    expect(within(entries).getByTestId("dns-setting-key").textContent).toBe("[dns.cache] entries");
    const ratio = setting("cache_hit_ratio");
    expect(ratio.dataset.value).toBe("0.84");
    expect(ratio.textContent).toContain("84%");
    expect(within(ratio).queryByTestId("dns-setting-key")).toBeNull();
    expect(setting("cache_bytes").dataset.value).toBe("2097152");
    expect(setting("serving").textContent).toContain("Yes");
    expect(setting("workers").textContent).toContain("[dns] workers");
    expect(setting("socket_mode").textContent).toContain("shared");
  });

  it("names the document of each group", async () => {
    open();
    await loaded();
    const docs = screen.getAllByTestId("dns-setting-doc").map((el) => el.textContent);
    expect(docs).toContain("docs/dns-resolver.md section 3");
    expect(docs).toContain("docs/dns.md section 8");
    expect(within(screen.getByTestId("dns-settings-cache")).getByTestId("dns-setting-doc").textContent).toBe("docs/dns-resolver.md section 3");
  });

  it("shows the query log group while the log is on, and says so when it is off", async () => {
    const first = open();
    await loaded();
    expect(screen.getByTestId("dns-settings-log")).toBeTruthy();
    expect(setting("log_state").dataset.value).toBe("on");
    expect(setting("log_written").dataset.value).toBe("60");
    expect(screen.queryByTestId("dns-settings-log-off")).toBeNull();
    first.unmount();
    dnsLogState().mode = "off";
    open();
    const off = await screen.findByTestId("dns-settings-log-off");
    expect(off.textContent).toContain("The query log is off");
    expect(screen.queryByTestId("dns-settings-log")).toBeNull();
  });

  it("links to the forwarders and from the other settings pages", async () => {
    open();
    await loaded();
    expect(screen.getByTestId("dns-settings-forwarders").getAttribute("href")).toBe("/dns/forwarders");
    const link = screen.getAllByTestId("settings-nav-link").find((l) => l.dataset.key === "dns");
    expect(link?.getAttribute("href")).toBe("/settings/dns");
  });

  it("shows the DoT and DoH listeners when they are served", async () => {
    server.use(http.get("/api/v1/nodes/:id/dns", () => tlsStatus()));
    open();
    await loaded();
    const listeners = screen.getAllByTestId("dns-settings-listener");
    expect(listeners.map((l) => l.dataset.kind)).toEqual(["udp", "tcp", "dot", "doh"]);
    expect(listeners[2]?.textContent).toContain("[dns.tls] dot_listen");
    expect(listeners[3]?.textContent).toContain("[dns.tls] doh_listen");
    const tls = screen.getByTestId("dns-settings-tls");
    expect(tls.dataset.dot).toBe("true");
    expect(tls.dataset.doh).toBe("true");
    expect(tls.textContent).toContain("DNS over TLS served, DNS over HTTPS served");
  });

  it("shows a figure the node does not report as not reported", async () => {
    server.use(http.get("/api/v1/nodes/:id/dns", () => tlsStatus()));
    open();
    await loaded();
    const ratio = setting("cache_hit_ratio");
    expect(ratio.dataset.value).toBeUndefined();
    expect(ratio.textContent).toContain("Not reported");
  });

  it("lists the problems the node reports", async () => {
    dnsResolverState().problems.push("stub zone lab.example.test: no name server could be learnt");
    open();
    await loaded();
    const notice = screen.getByTestId("dns-settings-problems");
    expect(notice.textContent).toContain("The node reports problems:");
    expect(within(notice).getAllByTestId("dns-settings-problem").map((p) => p.textContent)).toEqual([
      "stub zone lab.example.test: no name server could be learnt",
    ]);
  });

  it("shows no problem notice for a node without problems", async () => {
    open();
    await loaded();
    expect(screen.queryByTestId("dns-settings-problems")).toBeNull();
  });

  it("reads the node again", async () => {
    open();
    await loaded();
    expect(setting("cache_entries").dataset.value).toBe("1234");
    dnsResolverState().cache.entries = 4321;
    fireEvent.click(await screen.findByTestId("dns-settings-refresh"));
    await waitFor(() => expect(setting("cache_entries").dataset.value).toBe("4321"));
  });

  it("says when the node does not run the DNS role", async () => {
    server.use(http.get("/api/v1/nodes/:id/dns", () => problem(409, "dns.node.not_dns", "Not a DNS node", { node: "1" })));
    open();
    const notice = await screen.findByTestId("dns-settings-no-role");
    expect(notice.textContent).toContain("This node does not run the dns role.");
    expect(notice.textContent).toContain('roles = "controller,dns"');
    expect(screen.queryByTestId("dns-settings-listeners")).toBeNull();
  });

  it("says so when the server reports the node without the dns role and the read fails", async () => {
    server.use(
      http.get("/api/v1/system/status", () => HttpResponse.json({ node: { id: 1, roles: ["controller"] } })),
      http.get("/api/v1/nodes/:id/dns", () => problem(500, "sys.internal", "Internal error")),
    );
    open();
    expect(await screen.findByTestId("dns-settings-no-role")).toBeTruthy();
  });

  it("says when the server has no node id yet", async () => {
    server.use(http.get("/api/v1/system/status", () => HttpResponse.json({ node: { id: null, roles: ["controller"] } })));
    open();
    expect(await screen.findByTestId("dns-settings-no-node")).toBeTruthy();
    expect(screen.queryByTestId("dns-settings-listeners")).toBeNull();
  });

  it("says when the DNS module is switched off", async () => {
    server.use(http.get("/api/v1/nodes/:id/dns", () => problem(404, "sys.route_not_found", "Not Found")));
    open();
    const notice = await screen.findByTestId("dns-settings-off");
    expect(notice.textContent).toContain("The DNS module is switched off");
    expect(within(notice).getByTestId("dns-modules-link").getAttribute("href")).toBe("/settings");
  });

  it("says when the server has no DNS service", async () => {
    dnsNotBuilt();
    open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    expect(screen.queryByTestId("dns-settings-listeners")).toBeNull();
  });

  it("shows another error as it is", async () => {
    server.use(http.get("/api/v1/nodes/:id/dns", () => problem(500, "sys.internal", "Internal error")));
    open();
    await screen.findByRole("alert");
    expect(screen.queryByTestId("dns-settings-no-role")).toBeNull();
    expect(screen.queryByTestId("dns-settings-off")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await screen.findByTestId("dns-settings-tls");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("DNS-inställningar");
  });

  it("has no accessibility violations", async () => {
    dnsResolverState().problems.push("stub zone lab.example.test: no name server could be learnt");
    const { container } = open();
    await loaded();
    expect(await axeViolations(container)).toEqual([]);
  });
});
