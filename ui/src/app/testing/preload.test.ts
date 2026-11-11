import { describe, expect, it } from "vitest";
import { routeMatches } from "./preload";

describe("the route matcher of the page preload", () => {
  it("matches literal segments, parameters, optional parameters and a rest", () => {
    expect(routeMatches("/", "/")).toBe(true);
    expect(routeMatches("/signin", "/signin?next=%2Fjobs")).toBe(true);
    expect(routeMatches("/dhcp/scopes/:prefix/:tab?", "/dhcp/scopes/abc")).toBe(true);
    expect(routeMatches("/dhcp/scopes/:prefix/:tab?", "/dhcp/scopes/abc/options")).toBe(true);
    expect(routeMatches("/settings/:section?/:id?", "/settings")).toBe(true);
    expect(routeMatches("/files/*rest", "/files/a/b/c")).toBe(true);
  });

  it("refuses a different literal, a missing parameter and a longer path", () => {
    expect(routeMatches("/signin", "/setup")).toBe(false);
    expect(routeMatches("/dhcp/scopes/:prefix", "/dhcp/scopes")).toBe(false);
    expect(routeMatches("/dhcp", "/dhcp/leases")).toBe(false);
  });
});
