// The one store of the findings counts (ui-plan section 2.5), the rail badges and the status bar
// that read it: the rail's three groups and every badge state (none at zero, review, act, a dot,
// the weakened-setting dot of Settings), the status bar's counts and their links, one number on
// the rail and the status bar after events and answers that arrive out of order, and a reload
// when the event stream connects again. The counts come from the mock's `GET /findings/counts`
// or from answers a test hands out one by one.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { createSignal, Show } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ApiEvent, ConnectionState, EventStream, Topic } from "../api/events";
import { setMockFindingsExtra } from "../api/mock/findings-store";
import { server } from "../api/mock/node";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { session, setSessionForTest, updateBanner } from "../auth/session";
import { resetModules, setModulesForTest } from "../updates/modules";
import { AREAS } from "./areas";
import { useFindingCounts, type FindingCounts, type LevelCounts } from "./findings";
import { Rail } from "./Rail";
import * as badges from "./railBadge";
import { railBadge } from "./railBadge";
import FindingsStatus from "./FindingsStatus";

type Areas = FindingCounts["areas"];

const ZERO: LevelCounts = { act: 0, review: 0, info: 0 };

/** Counts with the given areas, everything else zero, totals summed. */
function countsOf(revision: number, areas: Partial<Areas>): FindingCounts {
  const all = {} as Areas;
  for (const key of ["ipam", "dns", "dhcp", "discovery", "topology", "jobs", "connectors", "nodes", "settings"] as const) {
    all[key] = { ...ZERO, ...areas[key] };
  }
  const total = { ...ZERO };
  for (const level of Object.values(all)) {
    total.act += level.act;
    total.review += level.review;
    total.info += level.info;
  }
  return { areas: all, revision, problems: total.act + total.review, total, sources: { alarm: 0, health: 0, job: 0, proposal: 0, reconcile: 0 } };
}

/** An event stream the test drives: events of a topic, resets and the connection state. */
function fakeStream() {
  const handlers = new Map<Topic, Set<(e: ApiEvent) => void>>();
  const resets = new Set<() => void>();
  const [state, setState] = createSignal<ConnectionState>("live");
  const stream = {
    state,
    subscribe(topic: Topic, handler: (e: ApiEvent) => void) {
      const set = handlers.get(topic) ?? new Set();
      handlers.set(topic, set);
      set.add(handler);
      return () => set.delete(handler);
    },
    onReset(_topic: Topic, handler: () => void) {
      resets.add(handler);
      return () => resets.delete(handler);
    },
  };
  return {
    stream: stream as unknown as EventStream,
    setState,
    emit(revision: number) {
      const event: ApiEvent = { topic: "findings", type: "findings", objects: [], deleted: [], revision: undefined, data: { kind: "findings.changed", params: { revision: String(revision) } } };
      for (const h of [...(handlers.get("findings") ?? [])]) h(event);
    },
    reset() {
      for (const h of [...resets]) h();
    },
    listeners: () => handlers.get("findings")?.size ?? 0,
  };
}

/** Answers `GET /findings/counts` from a queue; each answer waits for its own release. */
function queuedAnswers() {
  const waiting: { counts: FindingCounts; release: Promise<void> }[] = [];
  let reads = 0;
  server.use(
    http.get("*/api/v1/findings/counts", async () => {
      reads += 1;
      const next = waiting.shift();
      if (!next) return HttpResponse.json(countsOf(0, {}));
      await next.release;
      return HttpResponse.json(next.counts);
    }),
  );
  return {
    /** Queues an answer; returns the function that lets it through. */
    answer(counts: FindingCounts): () => void {
      let release!: () => void;
      waiting.push({ counts, release: new Promise<void>((resolve) => (release = resolve)) });
      return release;
    },
    reads: () => reads,
  };
}

/** The rail and the status bar on one store, as the shell renders them. */
function Surfaces(props: { stream: EventStream }) {
  // eslint-disable-next-line solid/reactivity -- the stream of a test is fixed for the life of the component
  const counts = useFindingCounts(props.stream);
  return (
    <>
      <Rail badges={badges} counts={counts()} />
      <footer class="statusbar">
        <FindingsStatus counts={counts()} />
      </footer>
    </>
  );
}

const badge = (area: string) => document.querySelector(`.rail a[data-area="${area}"] [data-testid="rail-badge"]`);
const dot = (area: string) => document.querySelector(`.rail a[data-area="${area}"] [data-testid="rail-dot"]`);

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  setMockFindingsExtra({});
  resetModules();
  setSessionForTest(null);
});

describe("the badge of a rail item", () => {
  const area = (id: string) => AREAS.find((a) => a.id === id) as (typeof AREAS)[number];

  it("is none at zero and for info alone, a review count, an act count, and a dot for connectors and nodes", () => {
    expect(railBadge(area("ipam"), countsOf(1, {}), false)).toBeNull();
    expect(railBadge(area("ipam"), countsOf(1, { ipam: { act: 0, review: 0, info: 23 } }), false)).toBeNull();
    expect(railBadge(area("ipam"), null, false)).toBeNull();
    expect(railBadge(area("dns"), countsOf(1, { dns: { act: 0, review: 2, info: 1 } }), false)).toEqual({
      kind: "count",
      count: 2,
      level: "review",
      label: "DNS: 2 findings to review",
    });
    expect(railBadge(area("ipam"), countsOf(1, { ipam: { act: 1, review: 3, info: 0 } }), false)).toEqual({
      kind: "count",
      count: 4,
      level: "act",
      label: "IPAM: 4 findings, 1 to act on now",
    });
    expect(railBadge(area("jobs"), countsOf(1, { jobs: { act: 2, review: 0, info: 0 } }), false)).toMatchObject({ kind: "count", count: 2, level: "act", label: "Jobs: 2 jobs wait for a person" });
    // A connector or node with a finding to review raises no dot; one to act on does.
    expect(railBadge(area("connectors"), countsOf(1, { connectors: { act: 0, review: 4, info: 0 } }), false)).toBeNull();
    expect(railBadge(area("connectors"), countsOf(1, { connectors: { act: 1, review: 0, info: 0 } }), false)).toEqual({ kind: "dot", label: "Connectors: 1 finding to act on now" });
    expect(railBadge(area("nodes"), countsOf(1, { nodes: { act: 2, review: 0, info: 0 } }), false)).toEqual({ kind: "dot", label: "Nodes: 2 findings to act on now" });
    // The areas the counts have no member for carry nothing.
    for (const id of ["dashboard", "audit", "cluster"]) expect(railBadge(area(id), countsOf(1, {}), true)).toBeNull();
  });

  it("is a dot on Settings while a setting is weaker than the profile, or a finding of the settings is to act on", () => {
    expect(railBadge(area("settings"), countsOf(1, {}), false)).toBeNull();
    expect(railBadge(area("settings"), countsOf(1, {}), true)).toEqual({ kind: "dot", label: "Settings: a security setting is weaker than the Home profile" });
    expect(railBadge(area("settings"), countsOf(1, { settings: { act: 1, review: 0, info: 0 } }), false)).toMatchObject({ kind: "dot" });
    expect(railBadge(area("settings"), countsOf(1, { settings: { act: 0, review: 5, info: 0 } }), false)).toBeNull();
  });
});

describe("the rail", () => {
  it("shows the twelve areas in three groups with Settings at the bottom, and keeps aria-current", async () => {
    renderRoute(() => <Rail badges={badges} counts={null} />, { url: "/ipam", path: "/ipam" });
    const nav = screen.getByRole("navigation", { name: "Main" });
    const items = [...nav.querySelectorAll<HTMLElement>("a, [data-testid='rail-sep']")].map((el) => (el.tagName === "A" ? el.dataset.area : "|"));
    expect(items).toEqual(["dashboard", "ipam", "dns", "dhcp", "discovery", "topology", "|", "jobs", "audit", "|", "connectors", "nodes", "cluster", "settings"]);
    expect(nav.querySelector("a.bottom")?.getAttribute("data-area")).toBe("settings");
    expect(within(nav).getByRole("link", { name: "IPAM" }).getAttribute("aria-current")).toBe("page");
    expect(nav.querySelectorAll("[data-testid='rail-badge'], [data-testid='rail-dot']")).toHaveLength(0);
    expect(await axeViolations(nav)).toEqual([]);
  });

  it("drops a group's hairline with its areas when the modules hide them", () => {
    setModulesForTest(["ipam"]);
    renderRoute(() => <Rail badges={badges} counts={null} />, { url: "/", path: "/" });
    const shown = [...document.querySelectorAll<HTMLElement>(".rail a, .rail [data-testid='rail-sep']")].map((el) => (el.tagName === "A" ? el.dataset.area : "|"));
    // No two hairlines in a row and none at either end.
    expect(shown.join(",")).not.toMatch(/\|,\|/);
    expect(shown[0]).not.toBe("|");
    expect(shown.at(-1)).toBe("settings");
  });

  it("draws each badge in the fill of its worst severity, labelled with the count and the area", async () => {
    const counts = countsOf(7, {
      ipam: { act: 1, review: 2, info: 9 },
      dns: { act: 0, review: 3, info: 0 },
      discovery: { act: 0, review: 0, info: 4 },
      jobs: { act: 1, review: 0, info: 0 },
      connectors: { act: 1, review: 0, info: 0 },
      nodes: { act: 0, review: 1, info: 0 },
    });
    renderRoute(() => <Rail badges={badges} counts={counts} />, { url: "/", path: "/" });
    expect(badge("ipam")?.textContent).toBe("3");
    expect(badge("ipam")?.getAttribute("data-level")).toBe("act");
    expect(badge("ipam")?.classList.contains("act")).toBe(true);
    expect(badge("dns")?.getAttribute("data-level")).toBe("review");
    expect(badge("discovery")).toBeNull();
    expect(badge("jobs")?.textContent).toBe("1");
    expect(dot("connectors")).not.toBeNull();
    expect(dot("nodes")).toBeNull();
    // The link is named by its badge, so a screen reader hears the count with the area.
    expect(screen.getByRole("link", { name: "IPAM: 3 findings, 1 to act on now" }).getAttribute("href")).toBe("/ipam");
    expect(badge("dns")?.getAttribute("aria-label")).toBe("DNS: 3 findings to review");
    expect(screen.getByRole("link", { name: "Connectors: 1 finding to act on now" })).toBeTruthy();
    expect(await axeViolations(screen.getByRole("navigation"))).toEqual([]);
  });

  it("shows more than 99 as 99+", () => {
    renderRoute(() => <Rail badges={badges} counts={countsOf(1, { discovery: { act: 0, review: 250, info: 0 } })} />, { url: "/", path: "/" });
    expect(badge("discovery")?.textContent).toBe("99+");
    expect(badge("discovery")?.getAttribute("aria-label")).toBe("Discovery: 250 findings to review");
  });

  it("puts the dot on Settings from the session's banner, and not under Lab", async () => {
    renderRoute(() => <Rail badges={badges} counts={countsOf(1, {})} />, { url: "/", path: "/" });
    expect(dot("settings")).toBeNull();
    const banner = session()?.banner;
    if (!banner) throw new Error("no session");
    updateBanner({ ...banner, weaker_than_home: true, lab: false });
    await waitFor(() => expect(dot("settings")).not.toBeNull());
    expect(dot("settings")?.getAttribute("aria-label")).toBe("Settings: a security setting is weaker than the Home profile");
    updateBanner({ ...banner, weaker_than_home: true, lab: true });
    await waitFor(() => expect(dot("settings")).toBeNull());
  });
});

describe("the findings in the status bar", () => {
  it("shows one count per severity, each as a link to the filtered Discovery list, info in plain ink", async () => {
    renderRoute(() => <FindingsStatus counts={countsOf(3, { ipam: { act: 1, review: 2, info: 20 }, discovery: { act: 0, review: 3, info: 3 } })} />, { url: "/", path: "/" });
    const act = screen.getByTestId("status-findings-act");
    expect(act.tagName).toBe("A");
    expect(act.textContent).toBe("1 act now");
    expect(act.getAttribute("href")).toBe("/discovery?severity=act");
    const review = screen.getByTestId("status-findings-review");
    expect(review.textContent).toBe("5 to review");
    expect(review.getAttribute("href")).toBe("/discovery?severity=review");
    const info = screen.getByTestId("status-findings-info");
    expect(info.tagName).toBe("A");
    expect(info.getAttribute("href")).toBe("/discovery?severity=info");
    expect(info.textContent).toBe("23 info");
    expect(info.classList.contains("info")).toBe(true);
    expect(await axeViolations(screen.getByTestId("status-findings"))).toEqual([]);
  });

  it("shows nothing for a severity without findings, and nothing at all before the counts", () => {
    const view = renderRoute(() => <FindingsStatus counts={countsOf(3, { dns: { act: 0, review: 1, info: 0 } })} />, { url: "/", path: "/" });
    expect(screen.queryByTestId("status-findings-act")).toBeNull();
    expect(screen.getByTestId("status-findings-review").textContent).toBe("1 to review");
    expect(screen.queryByTestId("status-findings-info")).toBeNull();
    view.unmount();
    renderRoute(() => <FindingsStatus counts={null} />, { url: "/", path: "/" });
    expect(screen.queryByTestId("status-findings")).toBeNull();
  });

  it("opens the Discovery list filtered by the severity", async () => {
    const view = renderRoute(() => <FindingsStatus counts={countsOf(3, { discovery: { act: 2, review: 0, info: 0 } })} />, {
      url: "/",
      path: "/",
      routes: { "/discovery": () => <div data-testid="discovery" /> },
    });
    fireEvent.click(screen.getByTestId("status-findings-act"));
    await screen.findByTestId("discovery");
    expect(view.location()).toBe("/discovery?severity=act");
  });
});

describe("the findings store", () => {
  it("reads the mock's counts, follows a change after an event and gives one number to the rail and the status bar", async () => {
    const fake = fakeStream();
    renderRoute(() => <Surfaces stream={fake.stream} />, { url: "/", path: "/" });
    // The seed of the mock has open proposals: Discovery has a badge and the status bar the same total.
    await waitFor(() => expect(badge("discovery")).not.toBeNull());
    const ipamBefore = Number(badge("ipam")?.textContent ?? 0);
    const actBefore = Number.parseInt(screen.queryByTestId("status-findings-act")?.textContent ?? "0", 10);
    setMockFindingsExtra({ ipam: { act: 2 } });
    fake.emit(1_000_000);
    await waitFor(() => expect(Number(badge("ipam")?.textContent)).toBe(ipamBefore + 2));
    expect(badge("ipam")?.getAttribute("data-level")).toBe("act");
    // The status bar moved by the same two.
    expect(Number.parseInt(screen.getByTestId("status-findings-act").textContent ?? "", 10)).toBe(actBefore + 2);
  });

  it("never sets a number back when an older answer arrives after a newer one", async () => {
    const answers = queuedAnswers();
    const fake = fakeStream();
    const first = answers.answer(countsOf(10, { ipam: { act: 1, review: 0, info: 0 } }));
    renderRoute(() => <Surfaces stream={fake.stream} />, { url: "/", path: "/" });
    first();
    await waitFor(() => expect(badge("ipam")?.textContent).toBe("1"));

    // Two events arrive out of order (12, then 11); the newer answer comes back first.
    const newer = answers.answer(countsOf(12, { ipam: { act: 3, review: 0, info: 0 } }));
    fake.emit(12);
    fake.emit(11);
    await waitFor(() => expect(answers.reads()).toBe(2));
    newer();
    await waitFor(() => expect(badge("ipam")?.textContent).toBe("3"));
    expect(screen.getByTestId("status-findings-act").textContent).toBe("3 act now");

    // A late answer of an older revision is dropped: rail and status bar keep 3.
    const stale = answers.answer(countsOf(11, { ipam: { act: 2, review: 0, info: 0 } }));
    fake.emit(11);
    await waitFor(() => expect(answers.reads()).toBe(3));
    stale();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(badge("ipam")?.textContent).toBe("3");
    expect(screen.getByTestId("status-findings-act").textContent).toBe("3 act now");
  });

  it("reads again when the stream connects again and on a reset, and once for two components", async () => {
    const answers = queuedAnswers();
    const fake = fakeStream();
    const [second, setSecond] = createSignal(false);
    function Two() {
      return (
        <>
          <Surfaces stream={fake.stream} />
          <Show when={second()}>
            <Surfaces stream={fake.stream} />
          </Show>
        </>
      );
    }
    renderRoute(Two, { url: "/", path: "/" });
    await waitFor(() => expect(answers.reads()).toBe(1));
    setSecond(true);
    await new Promise((resolve) => setTimeout(resolve, 20));
    // One store: a second reader neither reads nor subscribes again.
    expect(answers.reads()).toBe(1);
    expect(fake.listeners()).toBe(1);

    fake.setState("reconnecting");
    fake.setState("live");
    await waitFor(() => expect(answers.reads()).toBe(2));
    fake.reset();
    await waitFor(() => expect(answers.reads()).toBe(3));
  });

  it("stops listening and forgets the counts when the last reader goes", async () => {
    queuedAnswers();
    const fake = fakeStream();
    const view = renderRoute(() => <Surfaces stream={fake.stream} />, { url: "/", path: "/" });
    await waitFor(() => expect(fake.listeners()).toBe(1));
    view.unmount();
    expect(fake.listeners()).toBe(0);
  });

  it("clears the counts when the server refuses them, and nothing is drawn", async () => {
    server.use(http.get("*/api/v1/findings/counts", () => HttpResponse.json({ code: "findings.unavailable", status: 503, title: "Unavailable", detail: "" }, { status: 503, headers: { "content-type": "application/problem+json" } })));
    const fake = fakeStream();
    renderRoute(() => <Surfaces stream={fake.stream} />, { url: "/", path: "/" });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByTestId("status-findings")).toBeNull();
    expect(document.querySelectorAll("[data-testid='rail-badge']")).toHaveLength(0);
  });
});
