// The DHCP page of WP7.0 that stays for the parts that come with later packages: the leases, the
// history and any other DHCP path say so, show the sub-navigation of the area and lead back to the
// scopes, in English and Swedish, without accessibility violations.
import { screen } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import DhcpPage from "./DhcpPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const TITLES: readonly (readonly [string, string])[] = [
  ["/dhcp/leases", "Leases"],
  ["/dhcp/history", "Lease history"],
  ["/dhcp/unknown/path", "DHCP"],
];

describe("the DHCP placeholder page", () => {
  it("shows the title of each path and says the part comes with a later package", async () => {
    for (const [url, title] of TITLES) {
      const view = renderRoute(DhcpPage, { url, path: "/dhcp/*rest" });
      expect(screen.getByTestId("page-dhcp")).toBeTruthy();
      expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(title);
      expect(screen.getByTestId("dhcp-coming").textContent).toContain("Coming with a later package");
      expect(screen.getByTestId("dhcp-coming-scopes").getAttribute("href")).toBe("/dhcp");
      expect(await axeViolations(view.container)).toEqual([]);
      view.unmount();
    }
  });

  it("shows the navigation of the area with the current part marked", () => {
    renderRoute(DhcpPage, { url: "/dhcp/leases", path: "/dhcp/*rest" });
    const links = screen.getAllByTestId("dhcp-nav-link");
    expect(links.map((l) => l.dataset.key)).toEqual(["scopes", "shared-networks", "options", "classes", "policies", "filters", "leases", "history"]);
    expect(links.find((l) => l.getAttribute("aria-current") === "page")?.dataset.key).toBe("leases");
    expect(links.find((l) => l.dataset.key === "classes")?.getAttribute("href")).toBe("/dhcp/classes");
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    renderRoute(DhcpPage, { url: "/dhcp/leases", path: "/dhcp/*rest" });
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Lån");
    expect(screen.getByText("Kommer med ett senare paket")).toBeTruthy();
  });
});
