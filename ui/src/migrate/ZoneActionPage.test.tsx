// The stubs of the zone actions (WP14.0): the flip and the release pages name the zone, say
// what comes with WP14.2 and lead back to the zone, in English and Swedish, without
// accessibility violations.
import { screen } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { migratePaths } from "./paths";
import ZoneFlipPage from "./ZoneFlipPage";
import ZoneReleasePage from "./ZoneReleasePage";

const ZONE = "0190d1c2-0000-7000-8000-00000000d001";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

describe("the zone action stubs", () => {
  it("the flip page names the zone and leads back to it", async () => {
    const view = renderRoute(ZoneFlipPage, { url: migratePaths.zoneFlip(ZONE), path: "/dns/zones/:id/flip" });
    expect(screen.getByTestId("page-migrate-zone-flip").dataset.id).toBe(ZONE);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Flip zone/);
    expect(screen.getByTestId("migrate-coming").textContent).toContain("secondary zone");
    expect(screen.getByTestId("migrate-coming-back").getAttribute("href")).toBe(`/dns/zones/${ZONE}`);
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("the release page names the zone and speaks Swedish", async () => {
    const view = renderRoute(ZoneReleasePage, { url: migratePaths.zoneRelease(ZONE), path: "/dns/zones/:id/release" });
    expect(screen.getByTestId("page-migrate-zone-release").dataset.id).toBe(ZONE);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Release frozen names/);
    expect(await axeViolations(view.container)).toEqual([]);
    view.unmount();
    await setLocale("sv");
    renderRoute(ZoneReleasePage, { url: migratePaths.zoneRelease(ZONE), path: "/dns/zones/:id/release" });
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Släpp frusna namn/);
  });
});
