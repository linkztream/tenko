// The DNS page of WP4.0: every DNS path shows that the module is coming, in English and
// Swedish, with the page test id and no accessibility violations.
import { screen } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { setLocale } from "../i18n";
import DnsPage from "./DnsPage";

afterEach(async () => {
  await setLocale("en");
});

describe("the DNS page", () => {
  it("says the module is coming on every DNS path", async () => {
    for (const url of ["/dns", "/dns/zones/example.test"]) {
      const view = renderRoute(DnsPage, { url, path: "/dns/*rest" });
      expect(screen.getByTestId("page-dns")).toBeTruthy();
      expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("DNS");
      expect(screen.getByTestId("dns-coming").textContent).toContain("The DNS module is coming");
      expect(await axeViolations(view.container)).toEqual([]);
      view.unmount();
    }
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    renderRoute(DnsPage, { url: "/dns", path: "/dns/*rest" });
    expect(screen.getByText("DNS-modulen kommer snart")).toBeTruthy();
  });
});
