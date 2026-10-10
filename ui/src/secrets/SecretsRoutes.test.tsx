// The secrets page as a sub-page of Settings, in the whole application: its routes beat the
// generic settings route, the old /secrets address redirects (with the query and fragment), and
// operators, who have no other settings page, still reach it.
import { createMemoryHistory, MemoryRouter } from "@solidjs/router";
import { fireEvent, render, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { resetMockDb } from "../api/mock/db";
import { SEED_SECRET_IDS } from "../api/mock/secrets-store";
import { buildRoutes, Root } from "../App";
import { alex } from "../auth/account/testkit";
import { loadSession, setSessionForTest } from "../auth/session";
import { SECRETS_PATH, migratedSecretsPath, secretsPath } from "./paths";

const NAS = SEED_SECRET_IDS.nasAdmin;

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

const rail = () => screen.findByRole("navigation", { name: "Main" });

describe("the paths", () => {
  it("put the page under Settings", () => {
    expect(SECRETS_PATH).toBe("/settings/secrets");
    expect(secretsPath()).toBe("/settings/secrets");
    expect(secretsPath(NAS)).toBe(`/settings/secrets/${NAS}`);
    expect(secretsPath("a b")).toBe("/settings/secrets/a%20b");
  });

  it("move only what is under the old address", () => {
    expect(migratedSecretsPath("/secrets")).toBe("/settings/secrets");
    expect(migratedSecretsPath("/secrets/")).toBe("/settings/secrets/");
    expect(migratedSecretsPath(`/secrets/${NAS}`)).toBe(`/settings/secrets/${NAS}`);
    expect(migratedSecretsPath("/secrets/a%20b/more")).toBe("/settings/secrets/a%20b/more");
    expect(migratedSecretsPath("/secretsfoo")).toBe("/secretsfoo");
    expect(migratedSecretsPath("/settings/secrets")).toBe("/settings/secrets");
  });
});

describe("the secrets page under Settings", () => {
  it("is reached at /settings/secrets, ahead of the generic settings route, with Settings in the rail", async () => {
    const app = await renderApp("/settings/secrets");
    expect(await screen.findByTestId("page-secrets", {}, { timeout: 5000 })).toBeTruthy();
    await screen.findAllByTestId("secret");
    expect(app.location()).toBe("/settings/secrets");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Secrets");
    expect(within(await rail()).getByRole("link", { name: /Settings/ }).classList.contains("active")).toBe(true);
    expect(within(screen.getByTestId("settings-nav")).getByRole("link", { name: "Secrets" }).getAttribute("aria-current")).toBe("page");
    expect(document.title).toBe("Secrets - Tenko DDI");
  });

  it("has no entry of its own in the rail", async () => {
    await renderApp("/settings/secrets");
    const labels = within(await rail())
      .getAllByRole("link")
      .map((a) => a.textContent?.trim());
    expect(labels).not.toContain("Secrets");
  });

  it("opens one secret at /settings/secrets/:id", async () => {
    const app = await renderApp(`/settings/secrets/${NAS}`);
    const detail = await screen.findByTestId("secret-detail", {}, { timeout: 5000 });
    expect(detail.dataset.id).toBe(NAS);
    expect(app.location()).toBe(`/settings/secrets/${NAS}`);
    expect(screen.getByTestId("page-secrets")).toBeTruthy();
  });

  it("is reached from the settings navigation, and leads back to the other settings pages", async () => {
    const app = await renderApp("/settings/security");
    const nav = await screen.findByTestId("settings-nav", {}, { timeout: 5000 });
    expect(within(nav).getAllByTestId("settings-nav-link").map((a) => a.dataset.key)).toEqual([
      "security",
      "users",
      "updates",
      "secrets",
      "access",
      "audit-export",
      "vault",
      "backup",
      "languages",
    ]);
    fireEvent.click(within(nav).getByRole("link", { name: "Secrets" }));
    await waitFor(() => expect(app.location()).toBe("/settings/secrets"));
    expect(await screen.findByTestId("page-secrets")).toBeTruthy();

    fireEvent.click(within(screen.getByTestId("settings-nav")).getByRole("link", { name: "Users" }));
    await waitFor(() => expect(app.location()).toBe("/settings/users"));
    expect(await screen.findByRole("table", { name: "Users" })).toBeTruthy();
    expect(screen.queryByTestId("page-secrets")).toBeNull();
  });

  it("stays out of the way of the other settings pages", async () => {
    const app = await renderApp("/settings");
    await waitFor(() => expect(app.location()).toBe("/settings/security"));
    expect(screen.queryByTestId("page-secrets")).toBeNull();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Settings");
  });

  it("lets an operator in, without the settings navigation, while the other settings pages stay closed", async () => {
    await renderApp(`/settings/secrets/${NAS}`, ["operator"]);
    expect(await screen.findByTestId("secret-detail", {}, { timeout: 5000 })).toBeTruthy();
    expect(screen.queryByTestId("settings-nav")).toBeNull();
    expect(screen.queryByText("Administrators only")).toBeNull();
  });

  it("does not open the other settings pages to an operator", async () => {
    await renderApp("/settings/security", ["operator"]);
    expect(await screen.findByText("Administrators only", {}, { timeout: 5000 })).toBeTruthy();
    expect(screen.queryByTestId("page-secrets")).toBeNull();
  });
});

describe("the old /secrets address", () => {
  it("redirects the list", async () => {
    const app = await renderApp("/secrets");
    await waitFor(() => expect(app.location()).toBe("/settings/secrets"));
    expect(await screen.findByTestId("page-secrets", {}, { timeout: 5000 })).toBeTruthy();
    await screen.findAllByTestId("secret");
  });

  it("redirects one secret, keeping the query and the fragment", async () => {
    const app = await renderApp(`/secrets/${NAS}?tab=refs#details`);
    await waitFor(() => expect(app.location()).toBe(`/settings/secrets/${NAS}?tab=refs#details`));
    const detail = await screen.findByTestId("secret-detail", {}, { timeout: 5000 });
    expect(detail.dataset.id).toBe(NAS);
  });

  it("redirects a path with more segments and a trailing slash", async () => {
    const app = await renderApp(`/secrets/${NAS}/`);
    await waitFor(() => expect(app.location()).toBe(`/settings/secrets/${NAS}/`));
    expect(await screen.findByTestId("page-secrets", {}, { timeout: 5000 })).toBeTruthy();
  });

  it("redirects for an operator too", async () => {
    const app = await renderApp("/secrets", ["operator"]);
    await waitFor(() => expect(app.location()).toBe("/settings/secrets"));
    expect(await screen.findByTestId("page-secrets", {}, { timeout: 5000 })).toBeTruthy();
  });

  it("is followed after a sign-in that asked for it", async () => {
    resetMockDb("signed-out");
    setSessionForTest(null, "loading");
    const history = createMemoryHistory();
    history.set({ value: "/secrets/abc" });
    render(() => (
      <MemoryRouter history={history} root={Root}>
        {buildRoutes()}
      </MemoryRouter>
    ));
    await loadSession();
    await waitFor(() => expect(history.get()).toBe("/signin?next=%2Fsecrets%2Fabc"));
  });
});
