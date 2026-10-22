// The settings sub-pages WP3.0 registers up front (access, audit export, vault, backup and
// languages): each has a route of its own that ranks above the generic /settings/:section?/:id?
// route, is for administrators and shows the settings navigation. The generic route keeps
// serving security and users.
import { createMemoryHistory, MemoryRouter } from "@solidjs/router";
import { fireEvent, render, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { resetMockDb } from "../api/mock/db";
import { axeViolations } from "../app/testing/axe";
import { buildRoutes, Root } from "../App";
import { alex } from "../auth/account/testkit";
import { loadSession, setSessionForTest } from "../auth/session";
import { collectRoutes } from "../app/router";

async function renderApp(url: string, roles?: string[]) {
  resetMockDb("signed-in");
  if (roles) alex().roles = roles as never;
  setSessionForTest(null, "loading");
  const history = createMemoryHistory();
  history.set({ value: url });
  const result = render(() => (
    <MemoryRouter history={history} root={Root}>
      {buildRoutes()}
    </MemoryRouter>
  ));
  await loadSession();
  return { ...result, location: () => history.get() };
}

afterEach(() => setSessionForTest(null, "loading"));

// WP7.4: the DHCP tab.
const TABS = ["security", "users", "updates", "secrets", "access", "audit-export", "vault", "backup", "reconciler", "guardrails", "dns", "dhcp", "languages"];
const TAB_NAMES = ["Security", "Users", "Updates", "Secrets", "Access", "Audit export", "Vault", "Backup", "Reconciler", "Guardrails", "DNS", "DHCP", "Languages"];

/** The sub-pages of WP3.11b, each with a part only the page itself shows. */
const PAGES = [
  { key: "access", url: "/settings/access", title: "Access", marker: "access-roles" },
  { key: "audit-export", url: "/settings/audit-export", title: "Audit export", marker: "audit-export-sinks" },
  { key: "vault", url: "/settings/vault", title: "Vault", marker: "vault-key" },
  { key: "backup", url: "/settings/backup", title: "Backup", marker: "backup-status" },
] as const;

describe("the route table", () => {
  it("lists the static settings pages before the generic section route, for administrators", () => {
    const settings = collectRoutes().filter((r) => r.path.startsWith("/settings"));
    const generic = settings.findIndex((r) => r.path === "/settings/:section?/:id?");
    expect(generic).toBeGreaterThanOrEqual(0);
    for (const page of PAGES) {
      const index = settings.findIndex((r) => r.path === page.url);
      expect(index, page.url).toBeGreaterThanOrEqual(0);
      expect(index, page.url).toBeLessThan(generic);
      expect(settings[index]?.access, page.url).toBe("admin");
    }
  });
});

describe("the settings sub-pages", () => {
  for (const page of PAGES) {
    it(`opens ${page.url} on its own page, not on the generic settings route`, async () => {
      const app = await renderApp(page.url);
      const root = await screen.findByTestId(`page-${page.key}`, {}, { timeout: 5000 });
      // The generic route would have redirected to the security section.
      expect(app.location()).toBe(page.url);
      expect(within(root).getByRole("heading", { level: 1 }).textContent).toBe(page.title);
      expect(await within(root).findByTestId(page.marker)).toBeTruthy();
      expect(screen.queryByTestId("deviation-count")).toBeNull();
      expect(document.title).toBe(`${page.title} - Tenko DDI`);

      const nav = within(root).getByTestId("settings-nav");
      expect(within(nav).getAllByTestId("settings-nav-link").map((a) => a.dataset.key)).toEqual(TABS);
      expect(within(nav).getAllByRole("link").map((a) => a.textContent)).toEqual(TAB_NAMES);
      const current = within(nav).getByRole("link", { name: page.title });
      expect(current.getAttribute("aria-current")).toBe("page");
      expect(current.getAttribute("href")).toBe(page.url);
      expect(within(nav).getAllByRole("link").filter((a) => a.getAttribute("aria-current") === "page")).toHaveLength(1);

      const rail = screen.getByRole("navigation", { name: "Main" });
      expect(within(rail).getByRole("link", { name: /Settings/ }).classList.contains("active")).toBe(true);
    });
  }

  it("is accessible", async () => {
    await renderApp("/settings/vault");
    const root = await screen.findByTestId("page-vault", {}, { timeout: 5000 });
    expect(await axeViolations(root, { disable: ["region"] })).toEqual([]);
  });

  it("is reached through the tabs, and the tabs lead back to the generic pages", async () => {
    const app = await renderApp("/settings/security");
    const nav = await screen.findByTestId("settings-nav", {}, { timeout: 5000 });
    for (const page of PAGES) {
      fireEvent.click(within(screen.getByTestId("settings-nav")).getByRole("link", { name: page.title }));
      await waitFor(() => expect(app.location()).toBe(page.url));
      expect(await screen.findByTestId(`page-${page.key}`)).toBeTruthy();
    }
    fireEvent.click(within(screen.getByTestId("settings-nav")).getByRole("link", { name: "Users" }));
    await waitFor(() => expect(app.location()).toBe("/settings/users"));
    expect(await screen.findByRole("table", { name: "Users" })).toBeTruthy();
    expect(screen.queryByTestId("page-languages")).toBeNull();
    expect(nav.isConnected).toBe(false);
  });

  it("leaves the generic settings route to security and users", async () => {
    const app = await renderApp("/settings");
    await waitFor(() => expect(app.location()).toBe("/settings/security"));
    expect(await screen.findByRole("table", { name: "Security settings and their values" }, { timeout: 5000 })).toBeTruthy();
    for (const page of PAGES) expect(screen.queryByTestId(`page-${page.key}`)).toBeNull();
    app.unmount();

    const users = await renderApp("/settings/users");
    expect(await screen.findByRole("table", { name: "Users" }, { timeout: 5000 })).toBeTruthy();
    expect(users.location()).toBe("/settings/users");
  });

  for (const role of ["operator", "viewer", "auditor"]) {
    it(`keeps the pages closed to ${role}`, async () => {
      await renderApp("/settings/backup", [role]);
      expect(await screen.findByText("Administrators only", {}, { timeout: 5000 })).toBeTruthy();
      expect(screen.queryByTestId("page-backup")).toBeNull();
      expect(screen.queryByTestId("settings-nav")).toBeNull();
    });
  }
});
