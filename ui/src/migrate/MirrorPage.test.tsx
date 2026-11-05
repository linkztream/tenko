// The stub of a mirror's page (WP14.0): the title, the three tabs with the one of the URL
// selected, the notice that the content comes with a later package and the way back to the
// connectors, in English and Swedish, without accessibility violations.
import { fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import MirrorPage from "./MirrorPage";
import { migratePaths } from "./paths";

const MIRROR = "0190d1c2-0000-7000-8000-00000000a001";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = (tab = "") => renderRoute(MirrorPage, { url: `/connectors/mirrors/${MIRROR}${tab ? `/${tab}` : ""}`, path: "/connectors/mirrors/:id/:tab?" });

describe("the mirror page stub", () => {
  it("shows the title, the tabs and the notice, and leads back to the connectors", async () => {
    const view = open();
    expect(screen.getByTestId("page-migrate-mirror").dataset.id).toBe(MIRROR);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Mirrored source/);
    expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["Scopes", "Losses", "Settings"]);
    expect(screen.getByTestId("mirror-tab-scopes").getAttribute("aria-selected")).toBe("true");
    expect(screen.getByTestId("migrate-coming").textContent).toContain("Coming in a later package");
    expect(screen.getByTestId("migrate-coming-back").getAttribute("href")).toBe("/connectors");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("selects the tab of the URL and moves between tabs", async () => {
    const view = open("losses");
    expect(screen.getByTestId("mirror-tab-losses").getAttribute("aria-selected")).toBe("true");
    expect(screen.getByTestId("migrate-coming").dataset.tab).toBe("losses");
    fireEvent.click(screen.getByTestId("mirror-tab-settings"));
    await waitFor(() => expect(view.location()).toBe(migratePaths.mirror(MIRROR, "settings")));
    expect(migratePaths.mirror(MIRROR, "scopes")).toBe(`/connectors/mirrors/${MIRROR}`);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    expect(screen.getByText("Kommer i ett senare paket")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Speglad källa/);
  });
});
