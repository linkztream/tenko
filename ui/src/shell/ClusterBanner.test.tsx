// The partition banner and the dialog of a write refused for want of a quorum (OPS-26).
import { fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import { server } from "../api/mock/node";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { partition } from "../cluster/partition";
import { ClusterBanner } from "./ClusterBanner";

const SINCE = "2026-10-11T08:00:00Z";

function refuse(queueable: boolean) {
  server.use(
    http.patch("/api/v1/addresses/:id", () =>
      HttpResponse.json(
        { status: 503, code: "cluster.no_quorum", title: "", detail: "", params: { since: SINCE, queueable: String(queueable) } },
        { status: 503, headers: { "Retry-After": "5" } },
      ),
    ),
  );
}

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  partition.reset();
  setSessionForTest(null);
});

describe("ClusterBanner", () => {
  it("shows nothing while the cluster is healthy", () => {
    renderRoute(() => <ClusterBanner system={null} />);
    partition.setQuorum({ state: "healthy" });
    expect(screen.queryByTestId("cluster-banner")).toBeNull();
  });

  it("says how long the controller has been isolated and links to the queue", async () => {
    renderRoute(() => <ClusterBanner system={null} />);
    partition.setQuorum({ state: "isolated", since: new Date(Date.now() - 4.5 * 60_000).toISOString(), applied: 9 });
    const banner = await screen.findByTestId("cluster-banner");
    expect(banner.dataset.state).toBe("isolated");
    expect(banner.getAttribute("role")).toBe("alert");
    expect(banner.textContent).toContain("4 min");
    expect(banner.querySelector("a")?.getAttribute("href")).toBe("/cluster/queue");
    expect(await axeViolations()).toEqual([]);
  });

  it("follows store.quorum of the system status", async () => {
    renderRoute(() => <ClusterBanner system={{ store: { quorum: { state: "electing", since: SINCE } } } as never} />);
    expect((await screen.findByTestId("cluster-banner")).dataset.state).toBe("electing");
  });

  it("forgets the staleness and loads the decisions when the quorum is back", async () => {
    server.use(
      http.get("/api/v1/queue/conflicts", () =>
        HttpResponse.json({
          items: [{ id: "c1", state: "conflict", queued_at: SINCE, queued_on: 1, summary: { action: "update", kind: "address" }, revision: 3 }],
          revision: 3,
        }),
      ),
    );
    renderRoute(() => <ClusterBanner system={null} />);
    partition.setQuorum({ state: "isolated", since: SINCE });
    partition.setStaleness(`since=${SINCE}; revision=9`);
    await screen.findByTestId("cluster-banner");
    partition.setQuorum({ state: "healthy" });
    await waitFor(() => expect(screen.getByTestId("cluster-banner").dataset.state).toBe("conflicts"));
    expect(partition.staleness()).toBeNull();
    expect(partition.conflicts()).toBe(1);
  });

  it("counts the queued changes that wait for a decision after a heal", async () => {
    renderRoute(() => <ClusterBanner system={null} />);
    partition.setConflicts(2);
    const banner = await screen.findByTestId("cluster-banner");
    expect(banner.dataset.state).toBe("conflicts");
    expect(banner.textContent).toContain("2 queued changes need your decision");
  });

  it("offers to queue a refused IPAM write and posts it to the queue", async () => {
    let posted: unknown;
    server.use(
      http.post("/api/v1/queue", async ({ request }) => {
        posted = await request.json();
        return HttpResponse.json(
          {
            id: "0190d1c2-0000-7000-8000-0000000000q1",
            queued_at: SINCE,
            queued_on: 1,
            method: "PATCH",
            path: "/addresses/a1",
            expires_at: "2026-10-18T08:00:00Z",
            state: "queued",
          },
          { status: 201 },
        );
      }),
    );
    refuse(true);
    renderRoute(() => <ClusterBanner system={null} />);
    await expect(
      api.patch("/api/v1/addresses/{id}", { path: { id: "a1" }, body: { hostname: "web.example.test" } as never, ifMatch: 41 }),
    ).rejects.toThrow();
    const dialog = await screen.findByTestId("dialog-no-quorum");
    expect(screen.getByTestId("cluster-banner").dataset.state).toBe("isolated");
    expect(await axeViolations()).toEqual([]);
    fireEvent.click(screen.getByTestId("no-quorum-queue"));
    await screen.findByTestId("no-quorum-queued");
    expect(posted).toEqual({ method: "PATCH", path: "/addresses/a1", query: null, body: { hostname: "web.example.test" }, if_match: "41" });
    fireEvent.click(screen.getByTestId("no-quorum-close"));
    await waitFor(() => expect(dialog.isConnected).toBe(false));
    expect(partition.refused()).toBeNull();
  });

  it("explains that a write outside IPAM cannot be queued", async () => {
    refuse(false);
    renderRoute(() => <ClusterBanner system={null} />);
    await expect(api.patch("/api/v1/addresses/{id}", { path: { id: "a1" }, body: {} as never })).rejects.toThrow();
    await screen.findByTestId("dialog-no-quorum");
    expect(screen.queryByTestId("no-quorum-queue")).toBeNull();
    expect(screen.getByTestId("no-quorum-hint").textContent).toContain("cannot be queued");
  });
});
