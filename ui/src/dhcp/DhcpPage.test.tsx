// The DHCP page of WP7.0: every DHCP path shows its title and that this part of the module comes
// with a later package, leads back to the scopes, in English and Swedish, without accessibility
// violations.
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
  ["/dhcp", "DHCP scopes"],
  ["/dhcp/scopes/192.0.2.0", "DHCP scope"],
  ["/dhcp/scopes/192.0.2.0/leases", "DHCP scope"],
  ["/dhcp/shared-networks", "Shared networks"],
  ["/dhcp/options", "DHCP options"],
  ["/dhcp/classes", "Client classes"],
  ["/dhcp/policies", "DHCP policies"],
  ["/dhcp/filters", "MAC filters"],
  ["/dhcp/leases", "Leases"],
  ["/dhcp/history", "Lease history"],
  ["/dhcp/unknown/path", "DHCP"],
];

describe("the DHCP page", () => {
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

  it("speaks Swedish", async () => {
    await setLocale("sv");
    renderRoute(DhcpPage, { url: "/dhcp/leases", path: "/dhcp/*rest" });
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Lån");
    expect(screen.getByText("Kommer med ett senare paket")).toBeTruthy();
  });
});
