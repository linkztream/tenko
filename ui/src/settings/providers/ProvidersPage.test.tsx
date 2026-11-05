// The sign-in providers page (WP13.0): the title, the settings navigation with its tab, the
// notice that the provider forms come with later packages, in English and Swedish, without
// accessibility violations.
import { screen } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { PROVIDERS_PATH } from "./paths";
import ProvidersPage from "./ProvidersPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(ProvidersPage, { url: PROVIDERS_PATH, path: PROVIDERS_PATH });

describe("the sign-in providers page", () => {
  it("shows the title, the tab and the notice", async () => {
    const view = open();
    expect(screen.getByTestId("page-providers")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Sign-in providers");
    const tab = screen.getAllByTestId("settings-nav-link").find((link) => link.dataset.key === "providers");
    expect(tab?.getAttribute("href")).toBe("/settings/providers");
    expect(screen.getByTestId("providers-coming").textContent).toContain("Coming in a later package");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Inloggningsleverantörer");
  });
});
