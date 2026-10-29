import { cleanup, fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { server } from "../api/mock/node";
import { mockTopologyDecisions } from "../api/mock/topology-decisions";
import { TOPOLOGY_IDS, topologyState } from "../api/mock/topology-store";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { RootNotice } from "./RootNotice";

const T = TOPOLOGY_IDS;
const PROBLEM = { "content-type": "application/problem+json" };

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  setSessionForTest(null);
  server.events.removeAllListeners();
});

/** The default route points at the NAS while the controller names the gateway: two roots. */
function disagree(): void {
  const nas = topologyState().nodes.find((n) => n.id === T.nas);
  const ip = nas?.ips?.[0];
  if (ip === undefined) throw new Error("the NAS has no address");
  topologyState().nextHops = [ip];
}

/** Renders the notice and waits until the server answered the first read of the root. */
async function renderNotice(overrides: { readOnly?: boolean } = {}) {
  let answered = 0;
  server.events.on("response:mocked", ({ request }) => {
    if (request.method === "GET" && new URL(request.url).pathname === "/api/v1/topology/root") answered += 1;
  });
  const onChosen = vi.fn<() => void>();
  const view = renderRoute(() => <RootNotice readOnly={overrides.readOnly ?? false} onChosen={onChosen} />, {
    url: "/topology",
    path: "/topology",
  });
  await waitFor(() => expect(answered).toBeGreaterThan(0));
  // Let the answer reach the page.
  await new Promise((resolve) => setTimeout(resolve, 30));
  return { ...view, onChosen };
}

const candidates = (): HTMLElement[] => screen.queryAllByTestId("topology-root-candidate");

describe("the notice", () => {
  it("is not there when the sources agree on the root", async () => {
    await renderNotice();
    expect(screen.queryByTestId("topology-root-notice")).toBeNull();
    expect(screen.queryByTestId("topology-root-use")).toBeNull();
    // The server agrees: one root, no open disagreement.
    const decision = await api.get("/api/v1/topology/root");
    expect(decision.disagree).toBe(false);
    expect(decision.open).toBe(false);
  });

  it("lists both candidates with their source when the sources disagree", async () => {
    disagree();
    await renderNotice();
    const notice = await screen.findByTestId("topology-root-notice");
    expect(notice.textContent).toContain("Topology root: sources disagree");
    expect(notice.textContent).toContain("The map is drawn from the ranked source until you choose; the choice is remembered.");
    expect(candidates().map((c) => [c.dataset.source, c.querySelector("span")?.textContent])).toEqual([
      ["controller", "gw (controller)"],
      ["default_route", "nas (default route)"],
    ]);
    expect(screen.getAllByTestId("topology-root-use").map((b) => b.textContent)).toEqual(["Use this", "Use this"]);
  });

  it("stores the chosen source, tells the map and goes away", async () => {
    disagree();
    const { onChosen } = await renderNotice();
    await screen.findByTestId("topology-root-notice");
    const route = candidates().find((c) => c.dataset.source === "default_route") as HTMLElement;
    fireEvent.click(within(route).getByTestId("topology-root-use"));
    await waitFor(() => expect(screen.queryByTestId("topology-root-notice")).toBeNull());
    expect(onChosen).toHaveBeenCalledTimes(1);
    expect(mockTopologyDecisions.root?.source).toBe("default_route");
    const decision = await api.get("/api/v1/topology/root");
    expect(decision.root).toEqual({ source: "default_route", chosen: true, node: T.nas });
    expect(decision.open).toBe(false);
  });

  it("stays away after a new render, until the candidates change", async () => {
    disagree();
    await renderNotice();
    await screen.findByTestId("topology-root-notice");
    fireEvent.click(candidates()[0]?.querySelector("button") as HTMLElement);
    await waitFor(() => expect(screen.queryByTestId("topology-root-notice")).toBeNull());
    cleanup();

    await renderNotice();
    expect(screen.queryByTestId("topology-root-notice")).toBeNull();
    cleanup();

    // A different default route is a new disagreement, which is asked again.
    const ha = topologyState().nodes.find((n) => n.id === T.ha)?.ips?.[0] as string;
    topologyState().nextHops = [ha];
    await renderNotice();
    expect((await screen.findByTestId("topology-root-notice")).textContent).toContain("ha (default route)");
  });

  it("shows why the choice failed and keeps the notice", async () => {
    disagree();
    server.use(
      http.put(
        "/api/v1/topology/root",
        () =>
          HttpResponse.json(
            { code: "ipam.topology.no_candidate", status: 409, title: "Conflict", detail: "gone", params: { source: "controller" } },
            { status: 409, headers: PROBLEM },
          ),
        { once: true },
      ),
    );
    const { onChosen } = await renderNotice();
    await screen.findByTestId("topology-root-notice");
    fireEvent.click(screen.getAllByTestId("topology-root-use")[0] as HTMLElement);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("That source names no root of the map now.");
    expect(screen.getByTestId("topology-root-notice")).toBeTruthy();
    expect(candidates()).toHaveLength(2);
    expect(onChosen).not.toHaveBeenCalled();
    // The buttons work again.
    expect((screen.getAllByTestId("topology-root-use")[0] as HTMLButtonElement).disabled).toBe(false);
    // And a second try succeeds and clears the message.
    fireEvent.click(screen.getAllByTestId("topology-root-use")[0] as HTMLElement);
    await waitFor(() => expect(screen.queryByTestId("topology-root-notice")).toBeNull());
    expect(onChosen).toHaveBeenCalledTimes(1);
  });

  it("names the candidates but offers no choice when the view is read-only", async () => {
    disagree();
    await renderNotice({ readOnly: true });
    await screen.findByTestId("topology-root-notice");
    expect(candidates()).toHaveLength(2);
    expect(screen.queryAllByTestId("topology-root-use")).toHaveLength(0);
    expect(within(screen.getByTestId("topology-root-notice")).queryAllByRole("button")).toHaveLength(0);
  });

  it("offers no choice to someone who cannot write", async () => {
    await signInAlex({
      prepare: (user) => {
        user.roles = ["viewer"];
      },
    });
    disagree();
    await renderNotice();
    await screen.findByTestId("topology-root-notice");
    expect(candidates()).toHaveLength(2);
    expect(screen.queryAllByTestId("topology-root-use")).toHaveLength(0);
  });

  it("has no axe violations and speaks Swedish", async () => {
    disagree();
    await setLocale("sv");
    try {
      await renderNotice();
      const notice = await screen.findByTestId("topology-root-notice");
      expect(notice.textContent).toContain("Topologins rot: källorna är oense");
      expect(screen.getAllByTestId("topology-root-use")[0]?.textContent).toBe("Använd den här");
      expect(await axeViolations(notice)).toEqual([]);
    } finally {
      await setLocale("en");
    }
  });
});
