// The reserve routes of the mock API: the rows written together with one audit record, the
// refusals that write nothing (no scope, no identity, another reserved host), the dry run, the
// value route, who may write, and the lease that becomes its client's reservation.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../client";
import { ApiError } from "../problem";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { audit } from "./audit-store";
import { ADDRESS_IDS, HOST_IDS, ipamState } from "./ipam/api";
import { dhcpLeaseState, grantMockLease } from "./routes-dhcp-leases";

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  setSessionForTest(null);
});

async function refusal(run: () => Promise<unknown>): Promise<ApiError> {
  try {
    await run();
  } catch (err) {
    if (err instanceof ApiError) return err;
    throw err;
  }
  throw new Error("the request was not refused");
}

const reserve = (id: string, body: Record<string, unknown>, dryRun = false) =>
  api.post("/api/v1/addresses/{id}/reserve", { path: { id }, query: dryRun ? { dry_run: true } : undefined, body: body as never });

describe("reserving an address", () => {
  it("writes the host, the interface and the address with one audit record", async () => {
    const before = audit.records.length;
    const result = await reserve(ADDRESS_IDS["192.0.2.30"] as string, { mac: "02:00:5e:10:00:30" });
    expect(result.host?.mode).toBe("reserved");
    expect(result.interface?.mac).toBe("02:00:5e:10:00:30");
    expect(result.unchanged).toBe(false);
    expect(audit.records.slice(before).map((r) => r.draft.action)).toEqual(["ipam.address.reserve"]);
    const again = await reserve(ADDRESS_IDS["192.0.2.30"] as string, { mac: "02:00:5e:10:00:30" });
    expect(again.unchanged).toBe(true);
  });

  it("writes nothing on a dry run", async () => {
    const result = await reserve(ADDRESS_IDS["192.0.2.30"] as string, { mac: "02:00:5e:10:00:30" }, true);
    expect(result.dry_run).toBe(true);
    expect(result.host?.mode).toBe("reserved");
    expect(ipamState().data.host.get(HOST_IDS["printer-1"] as string)?.mode).toBe("static");
  });

  it("refuses a network without a scope, an interface without identity and another host's client", async () => {
    expect((await refusal(() => reserve(ADDRESS_IDS["198.51.100.44"] as string, {}))).code).toBe("dhcp.scope.not_found");
    const created = await api.post("/api/v1/addresses", { body: { ip: "192.0.2.78" } as never });
    const id = created.item?.id as string;
    expect((await refusal(() => reserve(id, { new_host: "nomac" }))).code).toBe("dhcp.reservation.no_identity");
    expect((await refusal(() => reserve(id, { new_host: "twin", mac: "00:00:5e:00:53:29" }))).code).toBe("dhcp.reservation.conflict");
    expect([...ipamState().data.host.values()].some((h) => h.name === "nomac" || h.name === "twin")).toBe(false);
  });

  it("refuses an address another reserved host holds", async () => {
    const err = await refusal(() => reserve(ADDRESS_IDS["192.0.2.41"] as string, { new_host: "other", mac: "02:00:5e:10:00:41" }));
    expect(err.code).toBe("dhcp.reservation.conflict");
    expect(err.params.address).toBe("192.0.2.41");
  });

  it("creates the address of the value route and refuses a viewer", async () => {
    const result = await api.post("/api/v1/addresses/reserve", { body: { ip: "192.0.2.79", new_host: "laptop2", mac: "02:00:5e:10:00:79" } as never });
    expect(result.address?.ip).toBe("192.0.2.79");
    expect(result.address?.interface).toBe(result.interface?.id);
    await signInWithRoles(["viewer"]);
    expect((await refusal(() => reserve(ADDRESS_IDS["192.0.2.30"] as string, { mac: "02:00:5e:10:00:30" }))).status).toBe(403);
  });

  it("marks the lease of a reserved client as its reservation, with the host", async () => {
    grantMockLease({ mac: "00:00:5e:00:53:29", addr: "192.0.2.41" });
    const page = await api.get("/api/v1/dhcp/leases", { query: { addr: "192.0.2.41" } });
    expect(page.items[0]?.reserved).toBe(true);
    expect(page.items[0]?.host).toBe(HOST_IDS["thermostat-1"]);
    expect(dhcpLeaseState().leases.find((l) => l.addr === "192.0.2.41")?.reserved).toBe(false);
  });
});
