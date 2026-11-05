// The directory mappings page (WP13.0): the title, the settings navigation, the notice that
// the table and the form come with a later package, the way back to access, in English and
// Swedish, without accessibility violations.
import { screen } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import MappingsPage from "./MappingsPage";
import { MAPPINGS_PATH } from "./mappingsPath";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(MappingsPage, { url: MAPPINGS_PATH, path: MAPPINGS_PATH });

describe("the directory mappings page", () => {
  it("shows the title, the navigation and the notice, and leads back to access", async () => {
    const view = open();
    expect(screen.getByTestId("page-access-mappings")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Directory mappings");
    expect(screen.getByTestId("settings-nav")).toBeTruthy();
    expect(screen.getByTestId("access-mappings-coming").textContent).toContain("Coming in a later package");
    expect(screen.getByTestId("access-mappings-back").getAttribute("href")).toBe("/settings/access");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Katalogmappningar");
  });
});
