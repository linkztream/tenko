// The areas of discovery, connectors and nodes in the whole application: their routes resolve
// to the right page (a static path wins over the proposal id of /discovery/:id), the G chords
// reach them, and the discovery area follows the discovery module.
import { createMemoryHistory, MemoryRouter } from "@solidjs/router";
import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { resetMockDb } from "../api/mock/db";
import { RECONCILE_IDS } from "../api/mock/reconcile-store";
import { buildRoutes, Root } from "../App";
import { loadSession, setSessionForTest } from "../auth/session";
import { setModulesForTest } from "../updates/modules";
import { AREAS } from "./areas";

async function renderApp(url: string) {
  resetMockDb("signed-in");
  setSessionForTest(null, "loading");
  const history = createMemoryHistory();
  history.set({ value: url });
  const result = render(() => <MemoryRouter history={history} root={Root}>{buildRoutes()}</MemoryRouter>);
  await loadSession();
  return { ...result, location: () => history.get() };
}

afterEach(() => {
  setModulesForTest(null);
  setSessionForTest(null, "loading");
});

describe("the WP2.9 areas", () => {
  it("have free chords of their own", () => {
    const chords = AREAS.map((a) => a.chord);
    expect(new Set(chords).size).toBe(chords.length);
    expect(AREAS.filter((a) => ["discovery", "connectors", "nodes"].includes(a.id)).map((a) => [a.id, a.path, a.chord])).toEqual([
      ["discovery", "/discovery", "O"],
      ["connectors", "/connectors", "C"],
      ["nodes", "/nodes", "N"],
    ]);
  });

  it("route the observations before a proposal id", async () => {
    await renderApp("/discovery/observations");
    expect(await screen.findByTestId("page-discovery-observations", {}, { timeout: 5000 })).toBeTruthy();
  });

  it("route a subject and a proposal", async () => {
    const app = await renderApp("/discovery/observations/00-00-5E-00-53-D1");
    expect(await screen.findByTestId("page-discovery-subject", {}, { timeout: 5000 })).toBeTruthy();
    app.unmount();
    await renderApp(`/discovery/${RECONCILE_IDS.proposal.mediaPc}`);
    const panel = await screen.findByTestId("proposal-panel", {}, { timeout: 5000 });
    expect(panel.dataset.id).toBe(RECONCILE_IDS.proposal.mediaPc);
  });

  it("reach connectors and nodes with G chords", async () => {
    const app = await renderApp("/jobs");
    await screen.findByTestId("page-jobs", {}, { timeout: 5000 });
    fireEvent.keyDown(document, { key: "g" });
    fireEvent.keyDown(document, { key: "c" });
    await waitFor(() => expect(app.location()).toBe("/connectors"));
    expect(await screen.findByTestId("page-connectors", {}, { timeout: 5000 })).toBeTruthy();
    fireEvent.keyDown(document, { key: "g" });
    fireEvent.keyDown(document, { key: "n" });
    await waitFor(() => expect(app.location()).toBe("/nodes"));
    expect(await screen.findByTestId("page-nodes", {}, { timeout: 5000 })).toBeTruthy();
    fireEvent.keyDown(document, { key: "g" });
    fireEvent.keyDown(document, { key: "o" });
    await waitFor(() => expect(app.location()).toBe("/discovery"));
    expect(await screen.findByTestId("page-discovery", {}, { timeout: 5000 })).toBeTruthy();
  });

  it("keep discovery out of reach while its module is off", async () => {
    await renderApp("/discovery");
    setModulesForTest(["ipam", "dns", "dhcp"]);
    await waitFor(() => expect(screen.queryByTestId("page-discovery")).toBeNull());
    const rail = screen.getByRole("navigation", { name: "Main" });
    expect(rail.textContent).not.toContain("Discovery");
    expect(rail.textContent).toContain("Connectors");
    expect(rail.textContent).toContain("Nodes");
  });
});
