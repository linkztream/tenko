// The blocking page: the tiles, the hours, the lists, the top tables, the clients and the newest
// blocked queries from the mock, the 7-day window, the short log, pause 15 minutes and resume,
// a timed pause that ends, allow from the log, the failures of a write, the notice of a log that
// is off, what the log keeps of the client, a viewer, the states of the service, Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BLOCKING_IDS } from "../../api/mock/dns-blocking-model";
import { server } from "../../api/mock/node";
import { dnsBlockingState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { dnsNotBuilt, dnsSwitchedOff, recordWrites } from "../testkit";
import BlockingPage from "./BlockingPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

function open(url = "/dns/blocking") {
  return renderRoute(BlockingPage, { url, path: "/dns/blocking" });
}

const tile = (name: string) => screen.getByTestId(`blocking-tile-${name}`);
const hours = () => screen.queryAllByTestId("blocking-hour");
const recent = () => screen.queryAllByTestId("blocking-recent-row");
const status = () => screen.getByTestId("blocking-pause-status");

async function loaded() {
  await screen.findByTestId("blocking-pause");
}

function problem(status: number, code: string) {
  return HttpResponse.json(
    { type: "about:blank", status, code, title: "", detail: code, params: {} },
    { status, headers: { "content-type": "application/problem+json" } },
  );
}

describe("the figures", () => {
  it("shows the four tiles, the hours, the lists, the top tables, the clients and the newest blocked queries", async () => {
    const view = open();
    await loaded();
    expect(screen.getByTestId("page-dns-blocking")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Blocking/);

    // 24 hours of bars; the tiles are the sums of the hours.
    expect(hours()).toHaveLength(24);
    const queries = hours().reduce((sum, h) => sum + Number(h.dataset.queries), 0);
    const blocked = hours().reduce((sum, h) => sum + Number(h.dataset.blocked), 0);
    expect(Number(tile("queries").dataset.value)).toBe(queries);
    expect(Number(tile("blocked").dataset.value)).toBe(blocked);
    expect(Number(tile("cached").dataset.value)).toBeGreaterThan(0);
    expect(tile("clients").dataset.value).toBe("4");
    const share = within(tile("blocked")).getByTestId("blocking-share");
    expect(Number(share.dataset.share)).toBeCloseTo(blocked / queries, 6);
    expect(share.textContent).toMatch(/^\d+(\.\d)?%$/);
    expect(hours()[0]!.getAttribute("aria-label")).toMatch(/quer(y|ies), \d+ blocked$/);
    expect(screen.getByTestId("blocking-hours").getAttribute("role")).toBe("group");

    // The blocked queries per list: the list's name, and the id of a list deleted since.
    const lists = screen.getAllByTestId("blocking-list");
    expect(lists.map((l) => l.dataset.list)).toEqual([BLOCKING_IDS.ads, BLOCKING_IDS.gone]);
    expect(lists[0]!.textContent).toContain("Ads");
    expect(lists[1]!.textContent).toContain(BLOCKING_IDS.gone);
    expect(lists[1]!.textContent).toContain("deleted list");
    expect(lists.reduce((sum, l) => sum + Number(l.dataset.blocked), 0)).toBe(blocked);
    expect(screen.getByTestId("blocking-lists-link").getAttribute("href")).toBe("/dns/lists");

    // The two tables of names.
    const topBlocked = within(screen.getByTestId("blocking-top-blocked")).getAllByTestId("blocking-name");
    expect(topBlocked[0]!.dataset.key).toBe("ads.example.test");
    const topNames = within(screen.getByTestId("blocking-top-names")).getAllByTestId("blocking-name");
    expect(topNames[0]!.dataset.key).toBe("www.example.test");

    // The clients: pseudonyms, with the note that says a client counts once per day.
    const clients = within(screen.getByTestId("blocking-clients")).getAllByTestId("blocking-client");
    expect(clients).toHaveLength(4);
    expect(clients[0]!.dataset.kind).toBe("pseudonym");
    expect(clients[0]!.textContent).toMatch(/p:[0-9a-f]{16}/);
    expect(screen.getByTestId("blocking-clients-note").dataset.client).toBe("pseudonym");
    expect(screen.getByTestId("blocking-clients-note").textContent).toContain("once per day");

    // The newest blocked queries, newest first.
    expect(recent()).toHaveLength(12);
    expect(recent()[0]!.dataset.key).toBe("ads.example.test");
    expect(recent()[0]!.textContent).toContain("Ads");
    expect(recent().some((r) => r.textContent?.includes("deleted list"))).toBe(true);

    expect(screen.getByTestId("blocking-next").textContent).toContain("next step");
    expect(screen.queryByTestId("blocking-truncated")).toBeNull();
    expect(screen.queryByTestId("blocking-short-log")).toBeNull();
    expect(status().textContent).toContain("Blocking is on");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows the DNS tab of the blocking view in the sub-navigation", async () => {
    open();
    await loaded();
    const link = screen.getByTestId("dns-nav").querySelector<HTMLElement>('[data-key="blocking"]');
    expect(link?.getAttribute("href")).toBe("/dns/blocking");
  });

  it("switches to 7 days and says so when the log keeps fewer days", async () => {
    dnsBlockingState().logDays = 3;
    const view = open();
    await loaded();
    expect(screen.getByTestId("blocking-window-24h").getAttribute("aria-pressed")).toBe("true");
    const day = Number(tile("queries").dataset.value);
    expect(screen.queryByTestId("blocking-short-log")).toBeNull();

    fireEvent.click(screen.getByTestId("blocking-window-7d"));
    await waitFor(() => expect(hours()).toHaveLength(168));
    expect(view.location()).toContain("window=7d");
    expect(screen.getByTestId("blocking-window-7d").getAttribute("aria-pressed")).toBe("true");
    expect(Number(tile("queries").dataset.value)).toBeGreaterThan(day);
    expect(tile("clients").dataset.value).toBe("11");
    expect(screen.getByTestId("blocking-short-log").textContent).toContain("3 days");

    fireEvent.click(screen.getByTestId("blocking-window-24h"));
    await waitFor(() => expect(hours()).toHaveLength(24));
    expect(screen.queryByTestId("blocking-short-log")).toBeNull();
    expect(view.location()).not.toContain("window");
  });

  it("opens on the 7-day window from the address and does not warn about a log that keeps 7 days", async () => {
    open("/dns/blocking?window=7d");
    await waitFor(() => expect(hours()).toHaveLength(168));
    expect(screen.queryByTestId("blocking-short-log")).toBeNull();
  });

  it("says the figures cover the newest part of a log that held more than one read looks at", async () => {
    dnsBlockingState().truncated = true;
    dnsBlockingState().logSample = 4;
    open();
    await loaded();
    expect(screen.getByTestId("blocking-truncated").textContent).toContain("newest part");
    expect(screen.getByTestId("blocking-sample").dataset.sample).toBe("4");
  });
});

describe("the pause", () => {
  it("pauses for 15 minutes, counts down and resumes", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    expect(status().dataset.state).toBe("on");
    expect(screen.queryByTestId("blocking-resume")).toBeNull();

    fireEvent.click(screen.getByTestId("blocking-pause-15"));
    await waitFor(() => expect(status().dataset.state).toBe("timed"));
    expect(status().textContent).toContain("Paused until");
    expect(screen.getByTestId("blocking-pause").dataset.state).toBe("timed");
    const left = Number(screen.getByTestId("blocking-pause-left").dataset.seconds);
    expect(left).toBeGreaterThan(14 * 60);
    expect(left).toBeLessThanOrEqual(15 * 60);
    expect(screen.getByTestId("blocking-pause-left").textContent).toMatch(/left$/);
    expect(dnsBlockingState().paused?.until).toBeTruthy();
    const pause = writes().find((w) => w.method === "POST" && w.url.endsWith("/dns/blocking/pause"));
    expect(pause?.body).toEqual({ minutes: 15 });

    fireEvent.click(screen.getByTestId("blocking-resume"));
    await waitFor(() => expect(status().dataset.state).toBe("on"));
    expect(status().textContent).toContain("Blocking is on");
    expect(dnsBlockingState().paused).toBeNull();
    expect(writes().some((w) => w.method === "DELETE" && w.url.endsWith("/dns/blocking/pause"))).toBe(true);
    expect(screen.queryByTestId("blocking-resume")).toBeNull();
  });

  it("pauses until resumed, for 5 minutes and for an hour", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("blocking-pause-open"));
    await waitFor(() => expect(status().dataset.state).toBe("open"));
    expect(status().textContent).toContain("Paused until resumed");
    expect(screen.queryByTestId("blocking-pause-left")).toBeNull();
    fireEvent.click(screen.getByTestId("blocking-pause-5"));
    await waitFor(() => expect(status().dataset.state).toBe("timed"));
    fireEvent.click(screen.getByTestId("blocking-pause-60"));
    await waitFor(() => expect(Number(screen.getByTestId("blocking-pause-left").dataset.seconds)).toBeGreaterThan(30 * 60));
    const bodies = writes()
      .filter((w) => w.method === "POST")
      .map((w) => w.body);
    expect(bodies).toEqual([{}, { minutes: 5 }, { minutes: 60 }]);
  });

  it("shows a pause that is already in force when the page opens", async () => {
    dnsBlockingState().paused = { since: new Date().toISOString() };
    open();
    await loaded();
    expect(status().dataset.state).toBe("open");
    expect(screen.getByTestId("blocking-resume")).toBeTruthy();
  });

  it("reads the figures again when a timed pause ends", async () => {
    const now = Date.now();
    dnsBlockingState().paused = { since: new Date(now - 1000).toISOString(), until: new Date(now + 1500).toISOString() };
    open();
    await loaded();
    expect(status().dataset.state).toBe("timed");
    await waitFor(() => expect(status().dataset.state).toBe("on"), { timeout: 5000 });
    expect(screen.queryByTestId("blocking-pause-left")).toBeNull();
    // The node ended the pause by itself; the page read its figures again to learn it.
    await waitFor(() => expect(dnsBlockingState().paused).toBeNull());
  }, 10_000);

  it("shows the notice of a pause that failed", async () => {
    server.use(http.post("/api/v1/dns/blocking/pause", () => problem(409, "dns.node.not_dns")));
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("blocking-pause-5"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dns.node.not_dns");
    expect(status().dataset.state).toBe("on");
  });
});

describe("allow from the log", () => {
  it("adds a blocked name to the list allowed and follows the compile job", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const row = recent()[0]!;
    fireEvent.click(within(row).getByTestId("blocking-allow"));
    const result = await within(row).findByTestId("blocking-allow-result");
    expect(result.dataset.state).toBe("added");
    expect(result.textContent).toContain("Added to the list allowed; the list is compiled now");
    expect(within(row).getByTestId("blocking-allow-job").getAttribute("href")).toMatch(/^\/jobs\/[0-9a-f-]{36}$/);
    expect(dnsBlockingState().allowed).toEqual(["ads.example.test"]);
    const sent = writes().find((w) => w.url.endsWith("/dns/blocking/allow"));
    expect(sent?.body).toEqual({ name: "ads.example.test" });
    // Every row of the name shows the outcome; another name still has its button.
    const same = recent().filter((r) => r.dataset.key === "ads.example.test");
    expect(same.length).toBeGreaterThan(1);
    for (const r of same) expect(within(r).getByTestId("blocking-allow-result")).toBeTruthy();
    const other = recent().find((r) => r.dataset.key === "track.example.test")!;
    expect(within(other).getByTestId("blocking-allow")).toBeTruthy();
  });

  it("says a name is allowed already when the list covers it", async () => {
    dnsBlockingState().allowed = ["example.test"];
    dnsBlockingState().allowListExists = true;
    open();
    await loaded();
    const row = recent()[0]!;
    fireEvent.click(within(row).getByTestId("blocking-allow"));
    const result = await within(row).findByTestId("blocking-allow-result");
    expect(result.dataset.state).toBe("already");
    expect(result.textContent).toContain("Already allowed");
    expect(within(row).queryByTestId("blocking-allow-job")).toBeNull();
    expect(dnsBlockingState().allowed).toEqual(["example.test"]);
  });

  it("shows the refusal of the server and keeps the button", async () => {
    server.use(http.post("/api/v1/dns/blocking/allow", () => problem(409, "dns.list.invalid")));
    open();
    await loaded();
    const row = recent()[0]!;
    fireEvent.click(within(row).getByTestId("blocking-allow"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dns.list.invalid");
    expect(within(row).getByTestId("blocking-allow")).toBeTruthy();
  });
});

describe("what the log keeps of the client", () => {
  it("shows addresses and the IPAM names to a principal that may update the node", async () => {
    dnsBlockingState().logClient = "address";
    open();
    await loaded();
    const clients = within(screen.getByTestId("blocking-clients")).getAllByTestId("blocking-client");
    expect(clients[0]!.dataset.kind).toBe("address");
    expect(clients[0]!.dataset.key).toBe("192.0.2.10");
    expect(clients[0]!.textContent).toContain("laptop.example.test");
    expect(screen.queryByTestId("blocking-clients-note")).toBeNull();
    expect(tile("clients").textContent).toContain("Distinct addresses");
  });

  it("says a client is withheld from a viewer when the log keeps addresses", async () => {
    await signInWithRoles(["viewer"]);
    dnsBlockingState().logClient = "address";
    open();
    await loaded();
    const clients = within(screen.getByTestId("blocking-clients")).getAllByTestId("blocking-client");
    expect(clients.every((c) => c.dataset.kind === "withheld")).toBe(true);
    expect(clients[0]!.textContent).toContain("Withheld");
    expect(recent()[0]!.textContent).toContain("Withheld");
  });

  it("says the log keeps no client", async () => {
    dnsBlockingState().logClient = "hidden";
    open();
    await loaded();
    expect(screen.getByTestId("blocking-clients-note").dataset.client).toBe("hidden");
    expect(screen.getByTestId("blocking-clients-note").textContent).toContain("keeps no client");
    expect(screen.queryByTestId("blocking-client")).toBeNull();
    expect(screen.getByTestId("blocking-clients-empty")).toBeTruthy();
    expect(recent()[0]!.textContent).toContain("Withheld");
  });
});

describe("what a viewer sees", () => {
  it("reads the figures and the pause but changes nothing", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(recent()).toHaveLength(12);
    expect(status().dataset.state).toBe("on");
    expect(screen.queryByTestId("blocking-pause-5")).toBeNull();
    expect(screen.queryByTestId("blocking-pause-open")).toBeNull();
    expect(screen.queryByTestId("blocking-resume")).toBeNull();
    expect(screen.queryByTestId("blocking-allow")).toBeNull();
  });
});

describe("the states of the service", () => {
  it("says the query log is off and where it is turned on", async () => {
    dnsBlockingState().logOff = true;
    const view = open();
    const off = await screen.findByTestId("blocking-log-off");
    expect(off.textContent).toContain("[dns.log]");
    expect(off.textContent).toContain("enabled = true");
    expect(off.textContent).toContain("tenko.toml");
    expect(screen.getByTestId("blocking-settings-link").getAttribute("href")).toBe("/settings/dns");
    expect(screen.queryByTestId("blocking-pause")).toBeNull();
    expect(screen.queryByTestId("blocking-tile-queries")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("says the node does not run the DNS role", async () => {
    server.use(http.get("/api/v1/dns/blocking/stats", () => problem(409, "dns.node.not_dns")));
    open();
    expect(await screen.findByTestId("blocking-not-dns")).toBeTruthy();
    expect(screen.queryByTestId("blocking-pause")).toBeNull();
  });

  it("says the service is not built yet", async () => {
    dnsNotBuilt();
    open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    expect(screen.queryByTestId("blocking-pause")).toBeNull();
  });

  it("says the module is switched off", async () => {
    dnsSwitchedOff();
    open();
    expect(await screen.findByTestId("dns-off")).toBeTruthy();
    expect(screen.queryByTestId("blocking-pause")).toBeNull();
  });
});

describe("language", () => {
  it("speaks Swedish without a missing key", async () => {
    await setLocale("sv");
    const view = open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Blockering/);
    expect(status().textContent).toContain("Blockering är på");
    expect(screen.getByTestId("blocking-pause-5").textContent).toBe("5 minuter");
    fireEvent.click(screen.getByTestId("blocking-pause-15"));
    await waitFor(() => expect(status().dataset.state).toBe("timed"));
    expect(status().textContent).toContain("Pausad till");
    expect(screen.getByTestId("blocking-pause-left").textContent).toMatch(/kvar$/);
    // A message that is missing renders as its key.
    const text = view.container.textContent ?? "";
    const labels = [...view.container.querySelectorAll("[aria-label],[title]")].map((el) => `${el.getAttribute("aria-label")} ${el.getAttribute("title")}`).join(" ");
    expect(`${text} ${labels}`).not.toMatch(/\bdns\.(blocking|nav)\.[a-z_.0-9]+/);
  });

  it("speaks Swedish when the log is off", async () => {
    await setLocale("sv");
    dnsBlockingState().logOff = true;
    const view = open();
    await screen.findByTestId("blocking-log-off");
    expect(view.container.textContent).toContain("Frågeloggen är av");
    expect(view.container.textContent).not.toMatch(/\bdns\.blocking\./);
  });
});
