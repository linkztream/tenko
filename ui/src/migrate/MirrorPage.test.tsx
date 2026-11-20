// The mirror views (WP14.1): the card's states, a mirror created with its token shown once, the
// diff of a scope, the losses acknowledged, the settings with the commands and the deletion, in
// English and Swedish, without accessibility violations.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { components } from "../api/generated/schema";
import { seedMirror } from "../api/mock/routes-migrate";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { MirrorCards } from "./MirrorCards";
import MirrorPage from "./MirrorPage";
import { installCommands, mirrorState } from "./model";
import { migratePaths } from "./paths";

type S = components["schemas"];

const MIRROR = "0190d1c2-0000-7000-8000-00000000a001";
const SCOPE = "192.0.2.0/24";

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
  it("names the card's state and writes the two commands", () => {
    expect(mirrorState({ enabled: false, age_secs: 1, stale: false })).toBe("disabled");
    expect(mirrorState({ enabled: true, age_secs: null, stale: false })).toBe("waiting");
    expect(mirrorState({ enabled: true, age_secs: 200, stale: true })).toBe("stale");
    expect(mirrorState({ enabled: true, age_secs: 20, stale: false })).toBe("fresh");
    const [hash, install] = installCommands({ id: MIRROR, ca_fingerprint: "ab" }, "https://tenko.example.test:8443");
    expect(hash).toContain("Get-FileHash");
    expect(install).toBe(
      `.\\Install-TenkoDhcpMirror.ps1 -Url 'https://tenko.example.test:8443' -MirrorId '${MIRROR}' -Fingerprint 'ab' -Account 'DOMAIN\\account' -PromptToken`,
    );
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
    expect(card.textContent).toContain("dc1.corp.example.test");
    expect(await axeViolations(view.container)).toEqual([]);

    fireEvent.click(screen.getByTestId("mirror-create"));
    fireEvent.input(await screen.findByTestId("mirror-name"), { target: { value: "dc2" } });
    fireEvent.click(screen.getByTestId("mirror-create-submit"));
    const token = await screen.findByTestId("mirror-token");
    expect(token.textContent).toMatch(/^tnk_mock-mirror-/);
    fireEvent.click(screen.getByTestId("mirror-token-done"));
    await waitFor(() => expect(screen.getAllByTestId("mirror-card")).toHaveLength(2));
    expect(screen.queryByTestId("mirror-token")).toBeNull();
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

  it("shows the commands, replaces the token and deletes the mirror", async () => {
    seed();
    const view = open("settings");
    const commands = await screen.findAllByTestId("mirror-command");
    expect(commands[1]?.textContent).toContain(`-MirrorId '${MIRROR}'`);
    expect(commands[1]?.textContent).toContain(`-Fingerprint '${"ab".repeat(32)}'`);
    fireEvent.click(screen.getByTestId("mirror-token-replace"));
    expect((await screen.findByTestId("mirror-token")).textContent).toMatch(/^tnk_/);
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
