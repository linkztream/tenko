// The mirror views (WP14.1): the card's states, a mirror created with its token shown once, the
// diff of a scope, the losses acknowledged, the settings with the commands and the deletion, in
// English and Swedish, without accessibility violations.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { components } from "../api/generated/schema";
import { server } from "../api/mock/node";
import { seedMirror } from "../api/mock/routes-migrate";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { formatDateTime, setLocale } from "../i18n";
import { sourceList } from "./api";
import { MirrorCards, REFRESH_MS } from "./MirrorCards";
import MirrorPage from "./MirrorPage";
import { mirrorState } from "./model";
import { migratePaths } from "./paths";

type S = components["schemas"];

const MIRROR = "0190d1c2-0000-7000-8000-00000000a001";
const PARTNER = "0190d1c2-0000-7000-8000-00000000b001";
const SCOPE = "192.0.2.0/24";

/** The diff of a paired mirror: one row against Tenko, one against the partner. */
const PAIRED_DIFF: S["ScopeDiff"] = {
  mirror: MIRROR,
  scope: SCOPE,
  sequence: 42,
  source_active: true,
  tenko_enabled: false,
  losses_open: 0,
  partner: PARTNER,
  partner_sequence: 41,
  rows: [
    { kind: "pool", item: "192.0.2.100-192.0.2.199", mirror: "192.0.2.100-192.0.2.199", action: "create" },
    { kind: "partner", item: "scope:42", mirror: "192.0.2.5", partner: "192.0.2.6", action: "decide", reason: "the partners differ" },
  ],
};

function item(change: Partial<S["MirrorItem"]> = {}): S["MirrorItem"] {
  return {
    id: MIRROR,
    name: "dc1",
    kind: "windows-dhcp",
    enabled: true,
    token: "0190d1c2-0000-7000-8000-00000000a002",
    account: "0190d1c2-0000-7000-8000-00000000a003",
    interval_secs: 60,
    last_sequence: 42,
    created: { at: "2026-11-01T08:00:00Z", by: { kind: "system", component: "api" } } as unknown as S["Stamp"],
    updated: { at: "2026-11-01T08:00:00Z", by: { kind: "system", component: "api" } } as unknown as S["Stamp"],
    age_secs: 30,
    stale: false,
    counts: { scopes: 1, reservations: 30, leases: 60, losses: 2 },
    source: { kind: "windows-dhcp", server: "dc1.corp.example.test", adapter: "Tenko-DhcpMirror.ps1", adapter_version: "0.1.0" },
    losses_open: 2,
    scopes: [{ cidr: SCOPE, name: "Office", active: true }],
    ca_fingerprint: "ab".repeat(32),
    ...change,
  };
}

function seed(change: Partial<S["MirrorItem"]> = {}) {
  seedMirror({
    item: item(change),
    losses: [
      {
        key: "Get-DhcpServerv4Policy, column Name=Printers|migrate.loss.policy",
        entry: { location: { sheet: "Get-DhcpServerv4Policy", column: "Name=Printers" }, code: "migrate.loss.policy", detail: "the policy <b>Printers</b> is not carried" },
      },
      {
        key: "Get-DhcpServerv4Lease, column IPAddress=192.0.2.198|migrate.loss.lease_state",
        entry: { location: { sheet: "Get-DhcpServerv4Lease", column: "IPAddress=192.0.2.198" }, code: "migrate.loss.lease_state", detail: "a lease in the state Offered" },
        scope: SCOPE,
      },
    ],
    diffs: {
      [SCOPE]: {
        mirror: MIRROR,
        scope: SCOPE,
        sequence: 42,
        source_active: true,
        tenko_enabled: false,
        losses_open: 2,
        rows: [
          { kind: "pool", item: "192.0.2.100-192.0.2.199", mirror: "192.0.2.100-192.0.2.199", action: "create" },
          { kind: "reservation", item: "192.0.2.10", mirror: "mac 00:00:5e:00:53:0a", tenko: "host printer01 (mac 00:00:5e:00:53:0b)", action: "decide", reason: "the address and the client's identity are on two hosts" },
        ],
      },
    },
  });
}

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = (tab = "") => renderRoute(MirrorPage, { url: `/connectors/mirrors/${MIRROR}${tab ? `/${tab}` : ""}`, path: "/connectors/mirrors/:id/:tab?" });

describe("the mirror model", () => {
  it("names the card's state", () => {
    expect(mirrorState({ enabled: false, age_secs: 1, stale: false })).toBe("disabled");
    expect(mirrorState({ enabled: true, age_secs: null, stale: false })).toBe("waiting");
    expect(mirrorState({ enabled: true, age_secs: 200, stale: true })).toBe("stale");
    expect(mirrorState({ enabled: true, age_secs: 20, stale: false })).toBe("fresh");
  });
});

describe("the mirror cards", () => {
  it("show each mirror's freshness and create one whose token is shown once", async () => {
    seed({ stale: true, age_secs: 200 });
    const view = renderRoute(MirrorCards, { url: "/connectors", path: "/connectors" });
    const card = await screen.findByTestId("mirror-card");
    expect(card.dataset.state).toBe("stale");
    expect(within(card).getByTestId("mirror-state").textContent).toBe("Stale");
    expect(within(card).getByTestId("mirror-losses-open").textContent).toBe("2");
    // Names are not unique: the card tells two mirrors apart by the end of the id.
    expect(within(card).getByTestId("mirror-short-id").textContent).toBe(MIRROR.slice(-8));
    expect(card.textContent).toContain("dc1.corp.example.test");
    expect(await axeViolations(view.container)).toEqual([]);

    fireEvent.click(screen.getByTestId("mirror-create"));
    fireEvent.input(await screen.findByTestId("mirror-name"), { target: { value: "Office DHCP 2" } });
    fireEvent.input(screen.getByTestId("mirror-sources"), { target: { value: "192.0.2.10, 198.51.100.0/24" } });
    fireEvent.click(screen.getByTestId("mirror-create-submit"));
    const token = await screen.findByTestId("mirror-token");
    // Bound to its sources, the token has the constrained form.
    expect(token.textContent).toMatch(/^tnkc_mock-mirror-/);
    // Esc does not lose a token that is shown once; the box does.
    fireEvent.keyDown(screen.getByTestId("dialog-mirror-token"), { key: "Escape" });
    expect(screen.getByTestId("mirror-token")).toBeTruthy();
    expect((screen.getByTestId("mirror-token-done") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId("mirror-token-stored"));
    fireEvent.click(screen.getByTestId("mirror-token-done"));
    await waitFor(() => expect(screen.getAllByTestId("mirror-card")).toHaveLength(2));
    expect(screen.queryByTestId("mirror-token")).toBeNull();
  });

  it("show the changes left and when a held change is stored, in English and Swedish", async () => {
    const due = "2026-11-20T08:10:00Z";
    seed({ changes_left: 0, change_reserve: 30, change_held: true, held_change_due: due });
    renderRoute(MirrorCards, { url: "/connectors", path: "/connectors" });
    const card = await screen.findByTestId("mirror-card");
    expect(within(card).getByTestId("mirror-changes-left").textContent).toBe("0 of 30");
    expect(within(card).getByTestId("mirror-held-change").textContent).toBe(`A newer configuration has arrived. It is stored with the first push after ${formatDateTime(due)}.`);
    await setLocale("sv");
    expect(within(card).getByTestId("mirror-changes-left").textContent).toBe("0 av 30");
    expect(within(card).getByTestId("mirror-held-change").textContent).toBe(`En nyare konfiguration har kommit. Den sparas vid första sändningen efter ${formatDateTime(due)}.`);
  });

  it("show the full count and no notice when no change is held", async () => {
    seed({ changes_left: 30, change_reserve: 30, change_held: false });
    renderRoute(MirrorCards, { url: "/connectors", path: "/connectors" });
    const card = await screen.findByTestId("mirror-card");
    expect(within(card).getByTestId("mirror-changes-left").textContent).toBe("30 of 30");
    expect(within(card).queryByTestId("mirror-held-change")).toBeNull();
  });

  it("show a held change without a time while the clock is held, with the server's total", async () => {
    seed({ changes_left: 4, change_reserve: 40, change_held: true });
    renderRoute(MirrorCards, { url: "/connectors", path: "/connectors" });
    const card = await screen.findByTestId("mirror-card");
    expect(within(card).getByTestId("mirror-changes-left").textContent).toBe("4 of 40");
    expect(within(card).getByTestId("mirror-held-change").textContent).toBe("A newer configuration has arrived. It is stored when Tenko trusts this controller's clock again.");
  });
});

describe("the poll of the mirror cards", () => {
  /** Renders the cards and returns the function the 5-second timer runs. */
  async function openCards() {
    const ticks: Array<() => void> = [];
    const real = globalThis.setInterval;
    vi.spyOn(globalThis, "setInterval").mockImplementation(((fn: () => void, ms?: number) => {
      if (ms === REFRESH_MS) ticks.push(fn);
      return real(fn, ms);
    }) as typeof setInterval);
    renderRoute(MirrorCards, { url: "/connectors", path: "/connectors" });
    await screen.findByTestId("mirror-card");
    return ticks.at(-1)!;
  }
  afterEach(() => {
    vi.restoreAllMocks();
    Object.defineProperty(document, "hidden", { configurable: true, value: false });
  });

  it("keeps the cards when one poll fails, instead of saying there are no mirrors", async () => {
    seed();
    const tick = await openCards();
    server.use(http.get("/api/v1/migrate/mirrors", () => HttpResponse.json({ status: 503, code: "x", title: "Down", params: {} }, { status: 503 })));
    tick();
    await screen.findByTestId("error-notice");
    expect(screen.getAllByTestId("mirror-card")).toHaveLength(1);
    expect(screen.queryByText(/No mirrored source yet/)).toBeNull();
  });

  it("does not poll while the tab is hidden", async () => {
    seed();
    const tick = await openCards();
    let reads = 0;
    server.use(http.get("/api/v1/migrate/mirrors", () => (reads++, HttpResponse.json({ items: [], next: null }))));
    Object.defineProperty(document, "hidden", { configurable: true, value: true });
    tick();
    Object.defineProperty(document, "hidden", { configurable: true, value: false });
    tick();
    // The visible tick alone read the list (now empty); the hidden one read nothing.
    await screen.findByText(/No mirrored source yet/);
    expect(reads).toBe(1);
  });
});

describe("the mirror page", () => {
  it("shows the card and the diff of the first scope", async () => {
    seed();
    const view = open();
    const diff = await screen.findByTestId("mirror-diff");
    expect(within(diff).getAllByRole("row")).toHaveLength(3);
    expect(diff.querySelector("[data-action='decide']")?.textContent).toContain("wait for your decision");
    expect(screen.getByTestId("mirror-diff-summary").textContent).toContain("2 open losses");
    expect(screen.getByTestId("mirror-tab-scopes").getAttribute("aria-selected")).toBe("true");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("acknowledges the chosen losses and shows a source's text as text", async () => {
    seed();
    open("losses");
    const rows = await screen.findAllByTestId("mirror-loss");
    expect(rows[0]?.textContent).toContain("<b>Printers</b>");
    expect(rows[1]?.textContent).toContain(SCOPE);
    expect(rows[0]?.textContent).toContain("every scope");
    const box = within(rows[0] as HTMLElement).getByRole("checkbox");
    fireEvent.click(box);
    fireEvent.click(screen.getByTestId("mirror-ack"));
    await waitFor(() => expect(screen.getAllByTestId("mirror-loss")[0]?.dataset.acked).toBe("true"));
  });

  it("shows the diff's partner column for a paired mirror", async () => {
    seedMirror({ item: item({ partner: PARTNER }), diffs: { [SCOPE]: PAIRED_DIFF } });
    open();
    const diff = await screen.findByTestId("mirror-diff");
    const row = diff.querySelector("[data-kind='partner']");
    expect(row?.textContent).toContain("192.0.2.6");
    expect(row?.textContent).toContain("Partner differs");
    expect(within(diff).getAllByRole("columnheader").map((cell) => cell.textContent)).toContain("Partner");
  });

  it("shows the values as text without a command, pairs the mirror, replaces the token and deletes it", async () => {
    seed();
    seedMirror({ item: item({ id: PARTNER, name: "dc2" }) });
    const view = open("settings");
    expect((await screen.findByTestId("mirror-value-id")).textContent).toBe(MIRROR);
    expect(screen.getByTestId("mirror-value-fingerprint").textContent).toBe("ab".repeat(32));
    expect(screen.getByTestId("mirror-value-url").textContent).toBe(window.location.origin);
    expect(screen.getByTestId("mirror-values-hint").getAttribute("aria-describedby")).toBeTruthy();
    expect(screen.getByTestId("mirror-settings").textContent).not.toContain("Install-TenkoDhcpMirror");
    const partner = screen.getByTestId("mirror-partner") as HTMLSelectElement;
    await waitFor(() => expect(partner.options).toHaveLength(2));
    fireEvent.change(partner, { target: { value: PARTNER } });
    await waitFor(() => expect((screen.getByTestId("mirror-partner") as HTMLSelectElement).value).toBe(PARTNER));
    expect(await axeViolations(view.container)).toEqual([]);
    fireEvent.click(screen.getByTestId("mirror-token-replace"));
    expect((await screen.findByTestId("mirror-token")).textContent).toMatch(/^tnk_/);
    expect(sourceList(" 192.0.2.10,198.51.100.0/24  2001:db8::1 ")).toEqual(["192.0.2.10", "198.51.100.0/24", "2001:db8::1"]);
    fireEvent.click(screen.getByTestId("mirror-token-stored"));
    fireEvent.click(screen.getByTestId("mirror-token-done"));
    fireEvent.click(screen.getByTestId("mirror-delete"));
    fireEvent.click(await screen.findByTestId("confirm-ok"));
    await waitFor(() => expect(view.location()).toBe("/connectors"));
    expect(migratePaths.mirror(MIRROR, "scopes")).toBe(`/connectors/mirrors/${MIRROR}`);
  });

  it("speaks Swedish", async () => {
    seed();
    await setLocale("sv");
    open();
    expect(await screen.findByText("Aktuell")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Speglad källa/);
  });
});
