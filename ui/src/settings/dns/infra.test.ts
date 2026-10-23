// The pure parts of the infrastructure cache section (WP10.4): what an address can do, shown as
// capabilities, and the addresses of a zone cut with the name of their server.
import { describe, expect, it } from "vitest";
import { addressesOf, capabilities, type InfraAddress, type InfraCut } from "./infra";

function address(extra: Partial<InfraAddress> = {}): InfraAddress {
  return {
    address: "192.0.2.53",
    origin: "glue",
    ttl: 3_600,
    srtt_ms: 21.5,
    p50_ms: 20,
    p99_ms: 64,
    failures: 0,
    down: false,
    edns: null,
    tcp_only: false,
    lame: false,
    lower_case: false,
    unwanted: 0,
    ...extra,
  };
}

describe("capabilities", () => {
  it("names nothing for an address that is not known to be able or unable to anything", () => {
    expect(capabilities(address())).toEqual([]);
    expect(capabilities(address({ edns: undefined }))).toEqual([]);
  });

  it("tells EDNS support from its absence, and does not mix up not known with absent", () => {
    expect(capabilities(address({ edns: true }))).toEqual(["edns"]);
    expect(capabilities(address({ edns: false }))).toEqual(["no_edns"]);
  });

  it("lists every flag that is set, in a fixed order", () => {
    expect(capabilities(address({ edns: false, tcp_only: true, lower_case: true, lame: true, down: true }))).toEqual([
      "no_edns",
      "tcp_only",
      "lower_case",
      "lame",
      "down",
    ]);
    expect(capabilities(address({ down: true, lame: true }))).toEqual(["lame", "down"]);
    expect(capabilities(address({ edns: true, lower_case: true }))).toEqual(["edns", "lower_case"]);
  });
});

describe("addressesOf", () => {
  const cut = (servers: InfraCut["servers"]): InfraCut => ({ zone: "example.test", ds: "unknown", ttl: 3_600, servers });

  it("lists the addresses of each server in the order the cut lists them, with the server's name", () => {
    const rows = addressesOf(
      cut([
        { name: "ns1.example.test", addresses: [address({ address: "192.0.2.10" }), address({ address: "2001:db8::10" })] },
        { name: "ns2.example.test", addresses: [address({ address: "192.0.2.11" })] },
      ]),
    );
    expect(rows.map((r) => [r.server, r.address.address])).toEqual([
      ["ns1.example.test", "192.0.2.10"],
      ["ns1.example.test", "2001:db8::10"],
      ["ns2.example.test", "192.0.2.11"],
    ]);
  });

  it("skips a server with no address and gives nothing for a cut without any", () => {
    const rows = addressesOf(cut([{ name: "ns1.example.test", addresses: [] }, { name: "ns2.example.test", addresses: [address()] }]));
    expect(rows.map((r) => r.server)).toEqual(["ns2.example.test"]);
    expect(addressesOf(cut([{ name: "ns1.example.test", addresses: [] }]))).toEqual([]);
    expect(addressesOf(cut([]))).toEqual([]);
  });
});
