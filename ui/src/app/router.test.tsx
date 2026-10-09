import { createMemoryHistory, MemoryRouter, Route, useParams } from "@solidjs/router";
import { cleanup, render } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { decodeSegment, paths, safeNext, seg } from "./paths";
import { collectRoutes, topSegment } from "./router";

describe("paths", () => {
  it("keeps FQDNs, addresses and MACs readable in the path", () => {
    expect(paths.host("nas.example.test")).toBe("/ipam/hosts/nas.example.test");
    expect(paths.address("192.0.2.41")).toBe("/ipam/addresses/192.0.2.41");
    expect(paths.address("2001:db8::1")).toBe("/ipam/addresses/2001:db8::1");
    expect(paths.mac("00-00-5E-00-53-2B")).toBe("/ipam/macs/00-00-5E-00-53-2B");
    expect(paths.zone("example.test.")).toBe("/dns/zones/example.test.");
  });

  it("puts a prefix into two segments, network and length", () => {
    expect(paths.prefix("192.0.2.0/24")).toBe("/ipam/prefixes/192.0.2.0/24");
    expect(paths.prefix("2001:db8::/32")).toBe("/ipam/prefixes/2001:db8::/32");
  });

  it("escapes what cannot be in a segment", () => {
    expect(seg("a/b")).toBe("a%2Fb");
    expect(seg("x y")).toBe("x%20y");
    expect(seg("user@example.test")).toBe("user@example.test");
  });

  it("builds sign-in links that come back, and only to this application", () => {
    expect(paths.signIn("/ipam/hosts/nas.example.test")).toBe("/signin?next=%2Fipam%2Fhosts%2Fnas.example.test");
    expect(paths.signIn("/")).toBe("/signin");
    expect(safeNext("/settings/users")).toBe("/settings/users");
    expect(safeNext("https://example.test/")).toBe("/");
    expect(safeNext("//example.test/")).toBe("/");
    expect(safeNext("/\\example.test")).toBe("/");
    expect(safeNext(null)).toBe("/");
  });
});

function ShowParams() {
  const params = useParams();
  return <pre data-testid="params">{JSON.stringify({ ...params })}</pre>;
}

function renderAt(url: string, pattern: string) {
  const history = createMemoryHistory();
  history.set({ value: url });
  const { getByTestId } = render(() => (
    <MemoryRouter history={history}>
      <Route path={pattern} component={ShowParams} />
    </MemoryRouter>
  ));
  const params = JSON.parse(getByTestId("params").textContent ?? "{}") as Record<string, string>;
  cleanup();
  return params;
}

describe("deep links with dots and colons", () => {
  it("route an FQDN, never treating the dot as a file", () => {
    expect(renderAt(paths.host("nas.example.test"), "/ipam/hosts/:fqdn")).toEqual({ fqdn: "nas.example.test" });
  });

  it("route IPv4 and IPv6 addresses", () => {
    expect(renderAt(paths.address("192.0.2.41"), "/ipam/addresses/:ip")).toEqual({ ip: "192.0.2.41" });
    expect(renderAt(paths.address("2001:db8::1"), "/ipam/addresses/:ip")).toEqual({ ip: "2001:db8::1" });
  });

  it("route prefixes of both families", () => {
    expect(renderAt(paths.prefix("198.51.100.0/24"), "/ipam/prefixes/:network/:length")).toEqual({ network: "198.51.100.0", length: "24" });
    expect(renderAt(paths.prefix("2001:db8::/32"), "/ipam/prefixes/:network/:length")).toEqual({ network: "2001:db8::", length: "32" });
  });

  it("arrive as written in the URL; views decode them", () => {
    const params = renderAt(`/ipam/hosts/${seg("odd name.example.test")}`, "/ipam/hosts/:fqdn");
    expect(params.fqdn).toBe("odd%20name.example.test");
    expect(decodeSegment(params.fqdn)).toBe("odd name.example.test");
    expect(decodeSegment("100%")).toBe("100%");
    expect(decodeSegment(undefined)).toBe("");
  });
});

describe("route discovery", () => {
  it("finds every area's routes.ts", () => {
    const all = collectRoutes();
    const paths_ = all.map((r) => r.path);
    expect(paths_).toContain("/");
    expect(paths_).toContain("/signin");
    expect(paths_).toContain("/setup");
    expect(paths_.some((p) => p.startsWith("/settings"))).toBe(true);
    expect(paths_.some((p) => p.startsWith("/account"))).toBe(true);
  });

  it("orders modules by folder and reads their routes", () => {
    const fake = () => null;
    const all = collectRoutes({
      "../zeta/routes.ts": { routes: [{ path: "/zeta", component: fake }] },
      "../alpha/routes.ts": { routes: [{ path: "/alpha", component: fake }] },
      "../empty/routes.ts": {},
    });
    expect(all.map((r) => r.path)).toEqual(["/alpha", "/zeta"]);
  });

  it("names the area a path belongs to", () => {
    expect(topSegment("/ipam/prefixes/:network/:length")).toBe("ipam");
    expect(topSegment("/")).toBe("");
  });
});
