// The node and profile chips of the top bar: the node chip reads this controller's role and the
// size of the cluster (`${storeRoleLabel("leader")} · 1 node`, `${storeRoleLabel("follower")} · 3 nodes, 1 behind`), a single controller
// needs no read of the members, the cluster card behind the chip lists the controllers, the
// profile card lists what the profile sets with the toggles this installation changed marked,
// an administrator is offered the security settings, one card is open at a time, and Esc closes
// a card and returns the focus to its chip.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import type { components } from "../api/generated/schema";
import { server } from "../api/mock/node";
import type { SystemStatus } from "../api/types";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { session, setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { PROFILE_DEFAULTS, valueOf } from "../settings/profileMatrix";
import { formatToggle, TOGGLES } from "../settings/toggles";
import { signInAdmin, viewerOnly } from "../updates/testkit";
import { storeRoleLabel, TopBar } from "./TopBar";

type MemberView = components["schemas"]["MemberView"];
type Quorum = components["schemas"]["QuorumKind"];

/** Every request to the members route: a single controller must make none. */
let memberReads = 0;
const onRequest = ({ request }: { request: Request }) => {
  if (request.method === "GET" && new URL(request.url).pathname.endsWith("/cluster/members")) memberReads += 1;
};

beforeEach(() => {
  memberReads = 0;
  server.events.on("request:start", onRequest);
});

afterEach(async () => {
  server.events.removeListener("request:start", onRequest);
  setSessionForTest(null);
  await setLocale("en");
});

/** The mock's status with the store's role and quorum set; no quorum for a server of before the cluster. */
async function status(role: string, quorum?: Quorum): Promise<SystemStatus> {
  const system = await api.get("/api/v1/system/status");
  system.store.role = role;
  if (quorum) system.store.quorum = { state: quorum };
  else delete system.store.quorum;
  return system;
}

function member(node: number, extra: Partial<MemberView> = {}): MemberView {
  return {
    node,
    name: `ctl-${node}.example.test`,
    address: `192.0.2.${10 + node}:8444`,
    role: "voter",
    leader: false,
    lag_entries: 0,
    last_contact_ms: 200,
    ...extra,
  };
}

/** Answers the members route with a leader and two followers, the last of them as given. */
function answerMembers(lagging: Partial<MemberView>): void {
  server.use(
    http.get("*/api/v1/cluster/members", () =>
      HttpResponse.json({
        node: 2,
        term: 7,
        leader: 1,
        changing: false,
        quorum: { state: "healthy" },
        members: [
          member(1, { leader: true, lag_entries: null, last_contact_ms: null }),
          member(2),
          member(3, lagging),
        ],
      }),
    ),
  );
}

async function show(system: SystemStatus | null, accountOpen = false) {
  return renderRoute(
    () => (
      <TopBar
        system={system}
        systemError={false}
        onPalette={() => {}}
        onShortcuts={() => {}}
        onAccount={() => {}}
        accountOpen={accountOpen}
      />
    ),
    { url: "/", path: "/" },
  );
}

function nodeChip(): HTMLElement {
  return screen.getByTestId("node-chip");
}

function profileChip(): HTMLElement {
  return screen.getByTestId("profile-chip");
}

/** The chip's text without the status dot. */
function chipText(): string {
  return (nodeChip().textContent ?? "").replace(/\s+/g, " ").trim();
}

/**
 * Collects the errors a handler throws (jsdom reports them on the window) so a test can assert on
 * them instead of the run failing on an unhandled error. Returns the list and a function to stop.
 */
function trapErrors(): { errors: unknown[]; stop: () => void } {
  const errors: unknown[] = [];
  const trap = (e: ErrorEvent) => {
    errors.push(e.error);
    e.preventDefault();
  };
  window.addEventListener("error", trap);
  return { errors, stop: () => window.removeEventListener("error", trap) };
}

describe("the node chip", () => {
  beforeEach(async () => {
    await signInAlex();
  });

  it("reads one node for a single controller and makes no read of the members", async () => {
    await show(await status("leader", "single"));
    expect(chipText()).toBe(`${storeRoleLabel("leader")} · 1 node`);
    // Give a stray read the time to arrive before asserting there was none.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(memberReads).toBe(0);
    expect(chipText()).toBe(`${storeRoleLabel("leader")} · 1 node`);
  });

  it("reads one node from a server that predates the cluster, with no read of the members", async () => {
    await show(await status("leader"));
    expect(chipText()).toBe(`${storeRoleLabel("leader")} · 1 node`);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(memberReads).toBe(0);
  });

  it("reads the size of a cluster and how many controllers lag, by log entries", async () => {
    answerMembers({ lag_entries: 500 });
    await show(await status("follower", "healthy"));
    await waitFor(() => expect(chipText()).toBe(`${storeRoleLabel("follower")} · 3 nodes, 1 behind`));
    expect(memberReads).toBeGreaterThan(0);
  });

  it("counts a controller out of contact as behind", async () => {
    answerMembers({ last_contact_ms: 20_000 });
    await show(await status("follower", "healthy"));
    await waitFor(() => expect(chipText()).toBe(`${storeRoleLabel("follower")} · 3 nodes, 1 behind`));
  });

  it("reads no controller behind when all are caught up", async () => {
    answerMembers({});
    await show(await status("follower", "healthy"));
    await waitFor(() => expect(chipText()).toBe(`${storeRoleLabel("follower")} · 3 nodes`));
  });

  it("shows the role alone while the status is unknown", async () => {
    await show(null);
    expect(chipText()).toBe("–");
  });
});

describe("the cluster card", () => {
  beforeEach(async () => {
    await signInAlex();
  });

  it("opens from the node chip and lists the controllers with a way to the cluster page", async () => {
    answerMembers({ lag_entries: 500 });
    await show(await status("follower", "healthy"));
    await waitFor(() => expect(chipText()).toBe(`${storeRoleLabel("follower")} · 3 nodes, 1 behind`));

    expect(nodeChip().getAttribute("aria-haspopup")).toBe("dialog");
    expect(nodeChip().getAttribute("aria-expanded")).toBe("false");
    expect(nodeChip().hasAttribute("aria-controls")).toBe(false);

    fireEvent.click(nodeChip());
    const card = await screen.findByTestId("cluster-card");
    expect(nodeChip().getAttribute("aria-expanded")).toBe("true");
    expect(nodeChip().getAttribute("aria-controls")).toBe(card.id);
    expect(card.getAttribute("role")).toBe("dialog");
    expect(card.getAttribute("aria-label")).toBe("Cluster");
    expect(within(card).getByTestId("cluster-card-role").textContent).toBe(storeRoleLabel("follower"));

    const members = within(card).getAllByTestId("cluster-card-member");
    expect(members.length).toBe(3);
    expect(members.map((m) => m.dataset.state)).toEqual(["leader", "caught_up", "catching_up"]);
    expect(members[0]?.textContent).toContain("ctl-1.example.test");

    const open = within(card).getByTestId("cluster-card-open");
    expect(open.getAttribute("href")).toBe("/cluster");
    expect(open.textContent).toBe("Open the cluster page");
  });

  it("closes with a second click on the chip", async () => {
    await show(await status("leader", "single"));
    fireEvent.click(nodeChip());
    await screen.findByTestId("cluster-card");
    fireEvent.click(nodeChip());
    expect(screen.queryByTestId("cluster-card")).toBeNull();
    expect(nodeChip().getAttribute("aria-expanded")).toBe("false");
  });

  it("lists no controllers for a single one", async () => {
    await show(await status("leader", "single"));
    fireEvent.click(nodeChip());
    const card = await screen.findByTestId("cluster-card");
    expect(within(card).queryByTestId("cluster-card-members")).toBeNull();
    expect(within(card).getByTestId("cluster-card-role").textContent).toBe(storeRoleLabel("leader"));
    expect(within(card).getByTestId("cluster-card-open").getAttribute("href")).toBe("/cluster");
  });

  // Defect in Popover: its Esc handler reads `props.anchor` after `onClose()`. The top bar passes
  // the anchor as the accessor of a <Show> that the close has just unmounted, so the read throws
  // ("stale value from <Show>") and the focus is not returned to the chip.
  it("closes on Esc and returns the focus to the chip", async () => {
    const { errors, stop } = trapErrors();
    try {
      await show(await status("leader", "single"));
      nodeChip().focus();
      fireEvent.click(nodeChip());
      const card = await screen.findByTestId("cluster-card");
      await waitFor(() => expect(document.activeElement).toBe(card));
      fireEvent.keyDown(card, { key: "Escape" });
      expect(screen.queryByTestId("cluster-card")).toBeNull();
      expect(nodeChip().getAttribute("aria-expanded")).toBe("false");
      expect(errors).toEqual([]);
      expect(document.activeElement).toBe(nodeChip());
    } finally {
      stop();
    }
  });

  it("has no axe violations with the card open", async () => {
    answerMembers({});
    await show(await status("follower", "healthy"));
    await waitFor(() => expect(chipText()).toBe(`${storeRoleLabel("follower")} · 3 nodes`));
    fireEvent.click(nodeChip());
    await screen.findByTestId("cluster-card");
    expect(await axeViolations(document.body, { disable: ["region", "landmark-one-main", "page-has-heading-one"] })).toEqual([]);
  });
});

describe("the profile card", () => {
  it("opens from the profile chip and lists every toggle with the value of the active profile", async () => {
    await signInAdmin();
    await show(await status("leader", "single"));

    expect(profileChip().getAttribute("aria-haspopup")).toBe("dialog");
    expect(profileChip().getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(profileChip());
    const card = await screen.findByTestId("profile-card");
    expect(profileChip().getAttribute("aria-expanded")).toBe("true");
    expect(profileChip().getAttribute("aria-controls")).toBe(card.id);
    expect(card.getAttribute("role")).toBe("dialog");

    const rows = within(card).getAllByTestId("profile-card-toggle");
    expect(rows.length).toBe(10);
    expect(rows.map((r) => r.dataset.toggle)).toEqual(TOGGLES.map((def) => def.id));
    const profile = session()?.profile ?? "standard";
    for (const [index, def] of TOGGLES.entries()) {
      const value = formatToggle(def.setting, valueOf(PROFILE_DEFAULTS[profile], def.setting));
      expect(rows[index]?.querySelector("td")?.textContent?.trim()).toBe(value);
      expect(rows[index]?.hasAttribute("data-changed")).toBe(false);
    }
    expect(within(card).queryByText("Changed here")).toBeNull();
    expect(within(card).getByTestId("profile-card-summary").textContent).toBe("Every setting follows the profile.");
  });

  it("marks a toggle the installation changed as changed here", async () => {
    await signInAdmin();
    const signedIn = session();
    if (!signedIn) throw new Error("no session");
    setSessionForTest({ ...signedIn, banner: { ...signedIn.banner, deviations: ["TGL-04"] } });
    await show(await status("leader", "single"));
    fireEvent.click(profileChip());
    const card = await screen.findByTestId("profile-card");

    const rows = within(card).getAllByTestId("profile-card-toggle");
    const changed = rows.filter((r) => r.dataset.changed === "true");
    expect(changed.map((r) => r.dataset.toggle)).toEqual(["TGL-04"]);
    expect(within(changed[0] as HTMLElement).getByText("Changed here")).toBeTruthy();
    expect(within(card).getAllByText("Changed here").length).toBe(1);
    expect(within(card).getByTestId("profile-card-summary").textContent).toBe("1 setting is changed from the profile.");
  });

  it("offers an administrator the security settings", async () => {
    await signInAdmin();
    await show(await status("leader", "single"));
    fireEvent.click(profileChip());
    const card = await screen.findByTestId("profile-card");
    const open = within(card).getByTestId("profile-card-open");
    expect(open.getAttribute("href")).toBe("/settings/security");
    expect(open.textContent).toBe("Open the security settings");
  });

  it("does not offer a viewer the security settings", async () => {
    await signInAdmin(viewerOnly);
    await show(await status("leader", "single"));
    fireEvent.click(profileChip());
    const card = await screen.findByTestId("profile-card");
    expect(within(card).getAllByTestId("profile-card-toggle").length).toBe(10);
    expect(within(card).queryByTestId("profile-card-open")).toBeNull();
  });

  // Defect in Popover: its Esc handler reads `props.anchor` after `onClose()`. The top bar passes
  // the anchor as the accessor of a <Show> that the close has just unmounted, so the read throws
  // ("stale value from <Show>") and the focus is not returned to the chip.
  it("closes on Esc and returns the focus to the chip", async () => {
    const { errors, stop } = trapErrors();
    try {
      await signInAdmin();
      await show(await status("leader", "single"));
      profileChip().focus();
      fireEvent.click(profileChip());
      const card = await screen.findByTestId("profile-card");
      await waitFor(() => expect(document.activeElement).toBe(card));
      fireEvent.keyDown(card, { key: "Escape" });
      expect(screen.queryByTestId("profile-card")).toBeNull();
      expect(profileChip().getAttribute("aria-expanded")).toBe("false");
      expect(errors).toEqual([]);
      expect(document.activeElement).toBe(profileChip());
    } finally {
      stop();
    }
  });

  it("has no axe violations with the card open", async () => {
    await signInAdmin();
    await show(await status("leader", "single"));
    fireEvent.click(profileChip());
    await screen.findByTestId("profile-card");
    expect(await axeViolations(document.body, { disable: ["region", "landmark-one-main", "page-has-heading-one"] })).toEqual([]);
  });
});

describe("one card at a time", () => {
  beforeEach(async () => {
    await signInAdmin();
  });

  it("closes the cluster card when the profile card opens", async () => {
    await show(await status("leader", "single"));
    fireEvent.click(nodeChip());
    await screen.findByTestId("cluster-card");

    fireEvent.mouseDown(profileChip());
    fireEvent.click(profileChip());
    await screen.findByTestId("profile-card");
    expect(screen.queryByTestId("cluster-card")).toBeNull();
    expect(nodeChip().getAttribute("aria-expanded")).toBe("false");
    expect(profileChip().getAttribute("aria-expanded")).toBe("true");
  });

  it("closes the profile card when the cluster card opens", async () => {
    await show(await status("leader", "single"));
    fireEvent.click(profileChip());
    await screen.findByTestId("profile-card");

    fireEvent.mouseDown(nodeChip());
    fireEvent.click(nodeChip());
    await screen.findByTestId("cluster-card");
    expect(screen.queryByTestId("profile-card")).toBeNull();
    expect(profileChip().getAttribute("aria-expanded")).toBe("false");
    expect(nodeChip().getAttribute("aria-expanded")).toBe("true");
  });

  it("swaps the card on a click alone, with no press before it", async () => {
    await show(await status("leader", "single"));
    fireEvent.click(nodeChip());
    await screen.findByTestId("cluster-card");
    fireEvent.click(profileChip());
    await screen.findByTestId("profile-card");
    expect(screen.queryByTestId("cluster-card")).toBeNull();
    expect(document.querySelectorAll("[data-testid='cluster-card'], [data-testid='profile-card']").length).toBe(1);
  });
});
