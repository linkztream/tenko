// OPS-20, OPS-05: the start page of U3 (docs/plans/ui-plan.md section 5.1): every block in both of
// its states, the profiles, one node and several, the Hidden line and Show all.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { components } from "../api/generated/schema";
import { setMockHealthFindings } from "../api/mock/findings-store";
import { IPAM_IDS } from "../api/mock/ipam/api";
import { mockMetricsSnapshot, type MockMetricsOptions, type MockMetricsSnapshot } from "../api/mock/metrics-model";
import { server } from "../api/mock/node";
import type { AuditRecord, SystemStatus } from "../api/types";
import { si } from "../app/format/si";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { db, signInAlex } from "../auth/account/testkit";
import { writeQuery } from "../ipam/plan/describe";
import Dashboard, { humanDuration } from "./Dashboard";

type FindingCounts = components["schemas"]["FindingCounts"];

let stopBridge: (() => void) | undefined;

/** Signs alex in under `profile` (the mock's default is Standard). */
async function signIn(profile?: "lab" | "home" | "standard" | "hardened", roles?: string[]) {
  await signInAlex({
    prepare: (user) => {
      if (profile) db.settings.profile = profile;
      if (roles) user.roles = roles as never;
    },
  });
}

beforeEach(async () => {
  sessionStorage.clear();
  await signIn();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  vi.unstubAllGlobals();
});

/**
 * A stand-in for EventSource whose `metrics` stream sends `snapshots` (one each 10 ms) and nothing
 * else; the page's other streams stay quiet.
 */
function fakeMetrics(snapshots: MockMetricsSnapshot[]) {
  class Samples {
    onopen: ((e: Event) => void) | null = null;
    onerror: ((e: Event) => void) | null = null;
    private listeners = new Map<string, ((e: Event) => void)[]>();
    constructor(readonly url: string) {
      setTimeout(() => {
        this.onopen?.(new Event("open"));
        if (!url.includes("topics=metrics")) return;
        snapshots.forEach((snapshot, i) =>
          setTimeout(() => {
            const event = new MessageEvent("metrics", { data: JSON.stringify({ topic: "metrics", kind: "metrics.snapshot", metrics: snapshot }) });
            for (const fn of this.listeners.get("metrics") ?? []) fn(event);
          }, i * 10),
        );
      }, 10);
    }
    addEventListener(type: string, fn: (e: Event) => void) {
      this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
    }
    close() {}
  }
  vi.stubGlobal("EventSource", Samples);
}

/** `count` snapshots one second apart ending now, with `change` applied to each. */
function snapshots(count: number, options: MockMetricsOptions, change?: (s: MockMetricsSnapshot) => void): MockMetricsSnapshot[] {
  const now = Date.now();
  return Array.from({ length: count }, (_, i) => {
    const s = mockMetricsSnapshot(1000 + i, options, new Date(now - (count - 1 - i) * 1000));
    change?.(s);
    return s;
  });
}

/** Answers the findings and their counts with nothing at all: the all-clear state. */
function noFindings() {
  const empty: FindingCounts = {
    areas: Object.fromEntries(["ipam", "dns", "dhcp", "discovery", "topology", "jobs", "connectors", "nodes", "settings"].map((a) => [a, { act: 0, review: 0, info: 0 }])) as FindingCounts["areas"],
    problems: 0,
    revision: 1,
    sources: { alarm: 0, health: 0, job: 0, proposal: 0, reconcile: 0 },
    total: { act: 0, review: 0, info: 0 },
  };
  server.use(
    http.get("/api/v1/findings/counts", () => HttpResponse.json(empty)),
    http.get("/api/v1/findings", () => HttpResponse.json({ items: [], next_cursor: null, revision: 1 })),
  );
}

/** The status with `change` applied. */
async function status(change: (s: SystemStatus) => void) {
  const base = await api.get("/api/v1/system/status");
  change(base);
  server.use(http.get("/api/v1/system/status", () => HttpResponse.json(base)));
}

/** Fills the cameras network (203.0.113.192/28, thresholds 70 and 90 percent) to critical. */
async function fillCameras() {
  const used = new Set((await api.get("/api/v1/addresses", { query: { vrf: IPAM_IDS.vrf.default, limit: 500 } })).items.map((a) => a.ip));
  for (let i = 193; i <= 206; i++) {
    const ip = `203.0.113.${i}`;
    if (used.has(ip)) continue;
    await api.post("/api/v1/addresses", { query: writeQuery(false, ["*"]), body: { ip, vrf: IPAM_IDS.vrf.default, status: "active" } as never });
  }
}

/** The order of the page's blocks, by their test ids. */
function blockOrder(): string[] {
  const ids = ["dashboard-attention", "dashboard-health", "dashboard-dns", "dashboard-dhcp", "dashboard-system", "dashboard-utilization", "dashboard-audit", "hidden-line"];
  return [...screen.getByTestId("page-dashboard").querySelectorAll("[data-testid]")]
    .map((e) => (e as HTMLElement).dataset.testid!)
    .filter((id) => ids.includes(id));
}

describe("the header", () => {
  it("says the node, its uptime as people say it, the free disk of its total, the store and the version", async () => {
    renderRoute(Dashboard, { url: "/" });
    const facts = await screen.findByTestId("dashboard-facts");
    await waitFor(() => expect(facts.textContent).toMatch(/^tenko1 · up 3 h \d+ min · 180 of 512 GiB free · store 12\.6 MB · \d/));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Dashboard");
  });

  it("names durations as people say them", () => {
    expect(humanDuration(40)).toBe("40 s");
    expect(humanDuration(5 * 60 + 9)).toBe("5 min");
    expect(humanDuration(17 * 3600 + 17 * 60)).toBe("17 h 17 min");
    expect(humanDuration(3 * 86400 + 4 * 3600 + 59)).toBe("3 d 4 h");
  });

  it("starts the quick actions: claim an address asks for the network first, N does the same, new prefix opens the form, import links to the wizard", async () => {
    renderRoute(Dashboard, { url: "/" });
    const claim = (await screen.findByTestId("dashboard-claim")) as HTMLButtonElement;
    await waitFor(() => expect(claim.disabled).toBe(false));
    expect(claim.classList.contains("primary")).toBe(true);
    expect(screen.getByTestId("dashboard-import").getAttribute("href")).toBe(paths.imports());
    fireEvent.click(claim);
    const picker = await screen.findByRole("dialog");
    await waitFor(() => expect(picker.textContent).toContain("192.0.2.0/24"));
    fireEvent.keyDown(picker, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    fireEvent.keyDown(document.body, { key: "n" });
    expect(await screen.findByRole("dialog")).toBeTruthy();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    fireEvent.click(screen.getByTestId("dashboard-new-prefix"));
    expect(await screen.findByRole("dialog")).toBeTruthy();
  });
});

describe("the needs-attention strip", () => {
  it("is the first block, with a row per finding to act on, the conflict with its MACs and its action, and one line for those to review", async () => {
    renderRoute(Dashboard, { url: "/" });
    const strip = await screen.findByTestId("dashboard-attention");
    await waitFor(() => expect(strip.dataset.state).toBe("attention"));
    expect(blockOrder()[0]).toBe("dashboard-attention");
    const counts = await api.get("/api/v1/findings/counts");
    const acts = (await api.get("/api/v1/findings", { query: { severity: "act", limit: 50 } })).items;
    const rows = within(strip).getAllByTestId("dashboard-finding");
    expect(rows.length).toBe(Math.min(5, acts.length));
    const conflict = rows.find((r) => r.dataset.kind === "conflict")!;
    expect(conflict).toBeTruthy();
    const finding = acts.find((f) => f.id === conflict.dataset.id)!;
    expect(conflict.textContent).toContain("Conflict");
    expect(conflict.textContent).toContain(finding.subject.label);
    expect(within(conflict).getByTestId("dashboard-finding-action").textContent).toBe("Resolve conflict");
    expect(within(conflict).getByTestId("dashboard-finding-action").getAttribute("href")).toBe(paths.proposal(finding.evidence.id));
    if (finding.params?.macs) expect(conflict.textContent).toContain(finding.params.macs.split(/,\s*/).join(" · "));
    const review = within(strip).getByTestId("dashboard-proposals");
    expect(review.dataset.count).toBe(String(counts.total.review));
    expect(within(review).getByTestId("dashboard-proposals-link").getAttribute("href")).toBe(paths.discovery({ severity: "review" }));
    expect(within(strip).queryByTestId("dashboard-clear")).toBeNull();
    expect(await axeViolations(screen.getByTestId("page-dashboard"))).toEqual([]);
  });

  it("is one All clear line when nothing is to act on, never two empty cards", async () => {
    noFindings();
    renderRoute(Dashboard, { url: "/" });
    const strip = await screen.findByTestId("dashboard-attention");
    await waitFor(() => expect(strip.dataset.state).toBe("clear"));
    expect(within(strip).getByTestId("dashboard-clear").textContent).toContain("All clear");
    expect(within(strip).getByTestId("dashboard-clear").textContent).toContain("no job waits for a person");
    expect(within(strip).queryAllByTestId("dashboard-finding")).toHaveLength(0);
    expect(within(strip).queryByTestId("dashboard-proposals")).toBeNull();
  });

  it("shows low disk as a finding to act on with the room left and Open Nodes", async () => {
    setMockHealthFindings([
      {
        code: "node.disk.low",
        severity: "act",
        area: "nodes",
        summary: "the file system of the data directory has 0.5 GiB of 20 GiB available",
        params: { available: String(500_000_000), total: String(20_000_000_000) },
      },
    ]);
    renderRoute(Dashboard, { url: "/" });
    const strip = await screen.findByTestId("dashboard-attention");
    const row = await waitFor(() => {
      const found = within(strip).getAllByTestId("dashboard-finding").find((r) => r.dataset.kind === "health");
      expect(found).toBeTruthy();
      return found!;
    });
    expect(row.textContent).toContain("The data directory has 500 MB of 20 GB free");
    expect(within(row).getByTestId("dashboard-finding-action").getAttribute("href")).toBe(paths.nodes());
    expect(within(row).getByTestId("dashboard-finding-action").textContent).toBe("Open Nodes");
  });

  it("lists a network that crosses its critical threshold as soon as the alarm event arrives", async () => {
    stopBridge = bridgeMockEvents();
    renderRoute(Dashboard, { url: "/" });
    const strip = await screen.findByTestId("dashboard-attention");
    await waitFor(() => expect(strip.dataset.state).toBe("attention"));
    await fillCameras();
    await waitFor(
      async () => {
        const acts = (await api.get("/api/v1/findings", { query: { severity: "act", limit: 50 } })).items;
        expect(acts.some((f) => f.subject.label === "203.0.113.192/28")).toBe(true);
        expect(screen.getByTestId("dashboard-health-alarms").dataset.value).not.toBe("0");
      },
      { timeout: 3000 },
    );
  });
});

describe("the health row", () => {
  it("has a metric block per figure, each a link, with the counts of the one findings store", async () => {
    renderRoute(Dashboard, { url: "/" });
    const row = await screen.findByTestId("dashboard-health");
    const counts = await api.get("/api/v1/findings/counts");
    await waitFor(() => expect(within(row).getByTestId("dashboard-health-findings").dataset.value).toBe(String(counts.total.act)));
    expect(within(row).getByTestId("dashboard-health-findings").textContent).toContain(`${counts.total.review} to review · ${counts.total.info} info`);
    await waitFor(() => expect(within(row).getByTestId("dashboard-health-v4").dataset.value).toMatch(/^[1-9]/));
    expect(within(row).getByTestId("dashboard-health-v4").textContent).toMatch(/prefixes · fullest [\d.]+ %/);
    expect(within(row).getByTestId("dashboard-health-v6").textContent).toMatch(/prefix/);
    await waitFor(() => expect(within(row).getByTestId("dashboard-connectors-hint").dataset.total).toBeDefined());
    expect(within(row).getByTestId("dashboard-health-jobs")).toBeTruthy();
    for (const block of within(row).getAllByRole("link")) expect(block.classList.contains("metric")).toBe(true);
    expect(within(row).getAllByRole("link").length).toBe(6);
  });

  it("leaves the jobs and connectors out under Home and names them in the Hidden line", async () => {
    await signIn("home");
    renderRoute(Dashboard, { url: "/" });
    const row = await screen.findByTestId("dashboard-health");
    await waitFor(() => expect(within(row).getByTestId("dashboard-health-findings")).toBeTruthy());
    expect(within(row).queryByTestId("dashboard-health-jobs")).toBeNull();
    expect(within(row).queryByTestId("dashboard-connectors")).toBeNull();
    const line = await screen.findByTestId("hidden-line");
    expect(within(line).getAllByTestId("hidden-line-item").map((i) => i.dataset.item)).toContain("operations");
    expect(line.textContent).toContain("jobs and connectors (not in the Home set)");
  });
});

describe("the service panels", () => {
  it("draw DNS with the rate, the five-minute chart with its window and scale, the response codes and the figures", async () => {
    fakeMetrics(snapshots(12, { dns: true, dhcp: true, host: true }));
    renderRoute(Dashboard, { url: "/" });
    const dns = await screen.findByTestId("dashboard-dns", undefined, { timeout: 3000 });
    expect(dns.dataset.status).toBe("healthy");
    expect(dns.textContent).toContain("Healthy");
    expect(within(dns).getByTestId("dashboard-dns-open").getAttribute("href")).toBe(paths.dns());
    const chart = within(dns).getByTestId("dashboard-dns-chart");
    await waitFor(() => expect(Number(chart.dataset.bars)).toBeGreaterThan(0));
    const max = Number(chart.dataset.max);
    expect(within(dns).getByTestId("dashboard-dns-scale").textContent).toBe(`${max >= 1000 ? si(max, "en") : String(max)}/s`);
    expect(chart.getAttribute("aria-label")).toBe(`DNS queries per second over the last 5 minutes in 5-second bars, from 0 to ${max >= 1000 ? si(max, "en") : String(max)}`);
    expect(chart.textContent).toContain("−5 min");
    expect(chart.textContent).toContain("now");
    expect(within(dns).getAllByTestId("dashboard-dns-rcode").map((r) => r.dataset.rcode)).toEqual(["noerror", "nxdomain", "servfail", "refused"]);
    expect(within(dns).getByTestId("dashboard-dns-encrypted").textContent).not.toContain("Not served");
    expect(within(dns).getByTestId("dashboard-dns-validation")).toBeTruthy();
  });

  it("draw DHCP's figures while a scope has a pool", async () => {
    fakeMetrics(snapshots(4, { dns: true, dhcp: true, host: true }));
    renderRoute(Dashboard, { url: "/" });
    const dhcp = await screen.findByTestId("dashboard-dhcp", undefined, { timeout: 3000 });
    await waitFor(() => expect(within(dhcp).getByTestId("dashboard-dhcp-active").dataset.value).toMatch(/^\d+$/));
    expect(within(dhcp).getByTestId("dashboard-dhcp-leases")).toBeTruthy();
    expect(within(dhcp).getByTestId("dashboard-dhcp-naks")).toBeTruthy();
    expect(within(dhcp).getByTestId("dashboard-dhcp-ddns")).toBeTruthy();
    expect(within(dhcp).queryByTestId("dashboard-dhcp-empty")).toBeNull();
  });

  it("draw DHCP as one empty state while no scope has a pool, instead of zeros", async () => {
    fakeMetrics(
      snapshots(3, { dns: true, dhcp: true, host: true }, (s) => {
        s.cluster.dhcp!.scopes = 0;
        s.cluster.dhcp!.fullest = [];
      }),
    );
    renderRoute(Dashboard, { url: "/" });
    const dhcp = await screen.findByTestId("dashboard-dhcp", undefined, { timeout: 3000 });
    const empty = within(dhcp).getByTestId("dashboard-dhcp-empty");
    expect(empty.textContent).toContain("No scope has a pool yet, so Tenko answers no DHCP requests.");
    expect(within(empty).getByTestId("dashboard-dhcp-create").getAttribute("href")).toBe(paths.dhcp());
    expect(within(dhcp).queryByTestId("dashboard-dhcp-leases")).toBeNull();
  });

  it("say Not served without DoT and DoH, and leave a role that does not run to the Hidden line", async () => {
    fakeMetrics(
      snapshots(3, { dns: true, dhcp: false, host: true }, (s) => {
        s.cluster.dns!.connections = null;
      }),
    );
    renderRoute(Dashboard, { url: "/" });
    const dns = await screen.findByTestId("dashboard-dns", undefined, { timeout: 3000 });
    expect(within(dns).getByTestId("dashboard-dns-encrypted").textContent).toContain("Not served");
    expect(screen.queryByTestId("dashboard-dhcp")).toBeNull();
    await waitFor(() => expect(within(screen.getByTestId("hidden-line")).getAllByTestId("hidden-line-item").map((i) => i.dataset.item)).toContain("dhcp"));
  });

  it("are not drawn for a viewer, and the Hidden line says the metrics are for administrators", async () => {
    await signIn(undefined, ["viewer"]);
    renderRoute(Dashboard, { url: "/" });
    const line = await screen.findByTestId("hidden-line");
    expect(within(line).getAllByTestId("hidden-line-item").map((i) => i.dataset.item)).toContain("admin");
    expect(screen.queryByTestId("dashboard-dns")).toBeNull();
    expect(screen.queryByTestId("dashboard-dhcp")).toBeNull();
    expect(screen.queryByTestId("dashboard-system")).toBeNull();
  });
});

describe("one node and several", () => {
  it("with one node leaves the controller's metrics to the Cluster page and names them in the Hidden line", async () => {
    fakeMetrics(
      snapshots(3, { dns: true, dhcp: true, host: true }, (s) => {
        s.cluster.host = { ...s.cluster.host!, cpu_percent: null, memory_total: null, memory_available: null };
      }),
    );
    await status((s) => {
      s.cluster = { connected: 0, listening: [], majors: [1], mismatched: 0, nodes: 0, versions: {} };
    });
    renderRoute(Dashboard, { url: "/" });
    await screen.findByTestId("dashboard-dns", undefined, { timeout: 3000 });
    const line = screen.getByTestId("hidden-line");
    await waitFor(() => expect(within(line).getAllByTestId("hidden-line-item").map((i) => i.dataset.item)).toEqual(["host", "controller"]));
    expect(line.textContent).toContain("host CPU and memory (not read on this host)");
    expect(line.textContent).toContain("(1 node, see Cluster)");
    expect(screen.queryByTestId("dashboard-system")).toBeNull();
    expect(screen.queryByTestId("dashboard-commit")).toBeNull();
  });

  it("with an enrolled node draws the nodes connected and the controller's metrics, and the Hidden line no longer names them", async () => {
    fakeMetrics(snapshots(3, { dns: true, dhcp: true, host: true }));
    await status((s) => {
      s.cluster = { connected: 1, listening: ["198.51.100.10:7443"], majors: [1], mismatched: 0, nodes: 2, versions: {} };
    });
    renderRoute(Dashboard, { url: "/" });
    const system = await screen.findByTestId("dashboard-system", undefined, { timeout: 3000 });
    await waitFor(() => expect(within(system).getByTestId("dashboard-commit")).toBeTruthy());
    expect(within(system).getByTestId("dashboard-replication")).toBeTruthy();
    expect(within(system).getByTestId("dashboard-buffers")).toBeTruthy();
    expect(within(system).getByTestId("dashboard-clients")).toBeTruthy();
    expect(within(system).getByTestId("dashboard-host-cpu")).toBeTruthy();
    const nodes = within(system).getByTestId("dashboard-nodes");
    await waitFor(() => expect(nodes.dataset.value).toBeDefined());
    expect(nodes.getAttribute("href")).toBe(paths.nodes());
    expect(within(nodes).getByTestId("dashboard-nodes-hint").dataset.total).toBeDefined();
    expect(screen.queryAllByTestId("hidden-line-item").map((i) => i.dataset.item)).not.toContain("controller");
  });
});

describe("the profiles", () => {
  it("Lab draws the controller's metrics with one node", async () => {
    await signIn("lab");
    fakeMetrics(snapshots(3, { dns: true, dhcp: true, host: true }));
    await status((s) => {
      s.cluster = { connected: 0, listening: [], majors: [1], mismatched: 0, nodes: 0, versions: {} };
    });
    renderRoute(Dashboard, { url: "/" });
    const system = await screen.findByTestId("dashboard-system", undefined, { timeout: 3000 });
    await waitFor(() => expect(within(system).getByTestId("dashboard-commit")).toBeTruthy());
    expect(within(system).queryByTestId("dashboard-nodes")).toBeNull();
  });

  it("Hardened adds the security events and the audit summary", async () => {
    await signIn("hardened");
    renderRoute(Dashboard, { url: "/" });
    const security = await screen.findByTestId("dashboard-security", undefined, { timeout: 3000 });
    expect(Number(security.dataset.records)).toBeGreaterThan(0);
    expect(within(security).getByTestId("dashboard-security-records").textContent).toMatch(/by people · \d+ by Tenko/);
    expect(within(security).getByTestId("dashboard-security-audit").getAttribute("href")).toBe(paths.audit());
  });

  it("Standard has no security panel and shows people's changes by default", async () => {
    renderRoute(Dashboard, { url: "/" });
    await screen.findByTestId("dashboard-audit");
    expect(screen.queryByTestId("dashboard-security")).toBeNull();
    expect((screen.getByTestId("dashboard-system-activity") as HTMLInputElement).checked).toBe(false);
  });

  it("Home shows Tenko's own activity by default", async () => {
    await signIn("home");
    renderRoute(Dashboard, { url: "/" });
    await screen.findByTestId("dashboard-audit");
    expect((screen.getByTestId("dashboard-system-activity") as HTMLInputElement).checked).toBe(true);
  });
});

describe("the Hidden line", () => {
  it("Show all metrics draws every block and the tiles of every metric for the session, and Show fewer hides them again", async () => {
    await signIn("home");
    fakeMetrics(snapshots(3, { dns: true, dhcp: true, host: true }));
    const view = renderRoute(Dashboard, { url: "/" });
    const toggle = await screen.findByTestId("hidden-line-toggle");
    expect(toggle.textContent).toBe("Show all metrics");
    expect(toggle.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-pressed")).toBe("true");
    expect(toggle.textContent).toBe("Show fewer metrics");
    await waitFor(() => expect(screen.getByTestId("dashboard-health-jobs")).toBeTruthy());
    expect(await screen.findByTestId("metrics-tiles", undefined, { timeout: 3000 })).toBeTruthy();
    await waitFor(() => expect(screen.getByTestId("dashboard-commit")).toBeTruthy());
    expect(sessionStorage.getItem("tenko.dashboard.show-all")).toBe("1");
    // The session keeps the choice across a new mount of the page.
    view.unmount();
    renderRoute(Dashboard, { url: "/" });
    expect((await screen.findByTestId("hidden-line-toggle")).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(screen.getByTestId("hidden-line-toggle"));
    await waitFor(() => expect(screen.queryByTestId("metrics-tiles")).toBeNull());
    expect(screen.queryByTestId("dashboard-health-jobs")).toBeNull();
  });
});

describe("the fullest prefixes", () => {
  it("show per tenant and VRF the totals and the fullest networks as links with their alarm line, and narrow to one VRF", async () => {
    renderRoute(Dashboard, { url: "/" });
    const panel = await screen.findByTestId("dashboard-utilization");
    await waitFor(() => expect(within(panel).getAllByTestId("dashboard-vrf").length).toBe(2));
    const vrf = within(panel).getAllByTestId("dashboard-vrf").find((v) => v.dataset.vrf === IPAM_IDS.vrf.default)!;
    expect(vrf.textContent).toMatch(/IPv4 .+ in use · \d+ prefix(es)? · IPv6 .+ in use/);
    const rows = within(vrf).getAllByTestId("dashboard-prefix");
    expect(rows.length).toBeLessThanOrEqual(6);
    const percents = rows.map((r) => Number(r.dataset.percent));
    expect([...percents].sort((a, b) => b - a)).toEqual(percents);
    expect(rows[0]!.getAttribute("href")).toBe(paths.prefix(rows[0]!.dataset.key!, IPAM_IDS.vrf.default));
    expect(within(panel).getByTestId("dashboard-prefixes-all").getAttribute("href")).toBe(paths.ipam());
    fireEvent.change(within(panel).getByTestId("dashboard-vrf-select"), { target: { value: IPAM_IDS.vrf.default } });
    await waitFor(() => expect(within(panel).getAllByTestId("dashboard-vrf").map((v) => v.dataset.vrf)).toEqual([IPAM_IDS.vrf.default]));
  });
});

describe("recent changes", () => {
  /** Audit records built from the mock's newest one: `spec` is the action and principal of each, newest first. */
  async function records(spec: [string, AuditRecord["principal"]][]) {
    const base = (await api.get("/api/v1/audit", { query: { order: "desc", limit: 1 } })).items[0]!;
    const items: AuditRecord[] = spec.map(([action, principal], i) => ({
      ...base,
      seq: 500 - i,
      at: new Date(Date.now() - i * 1000).toISOString(),
      principal,
      draft: { ...base.draft, action },
    }));
    server.use(http.get("/api/v1/audit", () => HttpResponse.json({ items, next_cursor: null, revision: 1 })));
  }

  const reconciler = { kind: "system", component: "reconciler" } as AuditRecord["principal"];

  it("group repeats with a count, read through the catalog with the code below, and the switch leaves out Tenko's own activity", async () => {
    await signIn("home");
    const me = { kind: "user", id: "0190d1c2-0000-7000-8000-000000000001", session: "0190d1c2-0000-7000-8000-000000000002", strength: "passkey" } as AuditRecord["principal"];
    await records([
      ["ipam.reconcile.run", reconciler],
      ["ipam.observation.ingest", reconciler],
      ["ipam.observation.ingest", reconciler],
      ["ipam.prefix.create", me],
      ["ipam.reconcile.run", reconciler],
    ]);
    renderRoute(Dashboard, { url: "/" });
    const panel = await screen.findByTestId("dashboard-audit");
    await waitFor(() => expect(within(panel).getAllByTestId("dashboard-change").length).toBe(4));
    const rows = within(panel).getAllByTestId("dashboard-change");
    expect(rows.map((r) => r.dataset.count)).toEqual(["1", "2", "1", "1"]);
    expect(rows[1]!.textContent).toContain("×2");
    expect(rows[1]!.querySelector(".audit-action-code")?.textContent).toBe("ipam.observation.ingest");
    expect(rows[1]!.textContent).toContain("Tenko (reconciler)");
    expect(rows[0]!.getAttribute("href")).toBe(paths.auditRecord(500));
    const system = within(panel).getByTestId("dashboard-system-activity") as HTMLInputElement;
    expect(system.closest("label")?.textContent).toContain("System activity");
    fireEvent.click(system);
    await waitFor(() => expect(within(panel).getAllByTestId("dashboard-change").length).toBe(1));
    expect(within(panel).getByTestId("dashboard-change").dataset.seq).toBe("497");
    expect(within(panel).getByTestId("dashboard-audit-all").getAttribute("href")).toBe(paths.audit());
  });

  it("say so when the recent changes are all Tenko's own and the switch is off", async () => {
    await records([["ipam.reconcile.run", reconciler]]);
    renderRoute(Dashboard, { url: "/" });
    const panel = await screen.findByTestId("dashboard-audit");
    await waitFor(() => expect(panel.textContent).toContain("No change by a person among the recent ones."));
  });
});

describe("the page's layout", () => {
  it("draws the blocks in reading order and passes axe", async () => {
    fakeMetrics(snapshots(3, { dns: true, dhcp: true, host: true }));
    await status((s) => {
      s.cluster = { connected: 1, listening: [], majors: [1], mismatched: 0, nodes: 1, versions: {} };
    });
    renderRoute(Dashboard, { url: "/" });
    await screen.findByTestId("dashboard-system", undefined, { timeout: 3000 });
    await screen.findByTestId("dashboard-dhcp", undefined, { timeout: 3000 });
    await screen.findByTestId("dashboard-utilization");
    expect(blockOrder()).toEqual([
      "dashboard-attention",
      "dashboard-health",
      "dashboard-dns",
      "dashboard-dhcp",
      "dashboard-system",
      "dashboard-utilization",
      "dashboard-audit",
    ]);
    expect(await axeViolations(screen.getByTestId("page-dashboard"))).toEqual([]);
  });
});
