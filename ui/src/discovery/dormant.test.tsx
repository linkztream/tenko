// Dormant claims: an address configured on a stopped guest is said so on the host page and on the
// address page, and nowhere when the guest runs, the fact has expired or the sources cannot be read.
import { screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { server } from "../api/mock/node";
import { putGuest } from "../api/mock/reconcile-store";
import { paths } from "../app/paths";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import HostView from "../hosts/HostView";
import AddressView from "../ipam/address/AddressView";
import type { ObservedFact } from "./api";
import { dormantClaims } from "./dormant";
import { resetRefs } from "./refs";

beforeEach(async () => {
  resetRefs();
  await signInAlex();
});

async function openHost(name: string) {
  renderRoute(HostView, { url: paths.host(name), path: "/ipam/hosts/:fqdn", routes: { "/discovery/observations/:subject": () => <div /> } });
  await screen.findByTestId("host-modes");
  const section = screen.getByTestId("host-observations");
  await within(section).findByTestId("host-observations-body");
  await waitFor(() => expect(within(section).queryByText("Loading…")).toBeNull());
  return section;
}

/** Gives the reads of a page the time to answer. */
const settled = () => new Promise((resolve) => setTimeout(resolve, 150));

async function openAddress(ip: string) {
  renderRoute(AddressView, { url: paths.address(ip), path: "/ipam/addresses/:ip", routes: { "/ipam/hosts/:fqdn": () => <div /> } });
  const page = await screen.findByTestId("page-ipam-address");
  await waitFor(() => expect(within(page).getByRole("heading", { level: 1 }).textContent).toContain(ip));
  return page;
}

describe("dormantClaims", () => {
  const fact = (power: "running" | "stopped" | undefined, options: { expired?: boolean; ips?: string[] } = {}): ObservedFact => {
    const now = Date.now();
    return {
      source: { type: "inventory", connector: "0190d1c2-0000-7000-8000-00000c000001" },
      source_key: "inventory:0190d1c2-0000-7000-8000-00000c000001",
      subject: { type: "host", data: { external_id: "vm-1" } },
      subject_key: "host:vm-1",
      observed: { type: "host", data: { external_id: "vm-1", name: "vm-laptop", ips: options.ips ?? ["192.0.2.20"], ...(power ? { power } : {}) } },
      observation: "0190d1c2-0000-7000-8000-0000a0000001",
      first_seen: new Date(now - 86_400_000).toISOString(),
      last_seen: new Date(now - 300_000).toISOString(),
      received_at: new Date(now - 300_000).toISOString(),
      expires_at: new Date(now + (options.expired ? -60_000 : 3_600_000)).toISOString(),
      sightings: 1,
      counted_at: new Date(now - 300_000).toISOString(),
      revision: 1,
    };
  };

  it("lists the addresses of stopped guests whose facts are current, once", () => {
    expect(dormantClaims([fact("stopped"), fact("stopped")])).toEqual([{ ip: "192.0.2.20", name: "vm-laptop" }]);
    expect(dormantClaims([fact("stopped", { ips: ["192.0.2.20", "2001:db8::20"] })])).toEqual([
      { ip: "192.0.2.20", name: "vm-laptop" },
      { ip: "2001:db8::20", name: "vm-laptop" },
    ]);
  });

  it("leaves out running guests, guests without a power state and facts that expired", () => {
    expect(dormantClaims([fact("running"), fact(undefined), fact("stopped", { expired: true })])).toEqual([]);
  });
});

describe("on the host page", () => {
  it("says which addresses are configured on a stopped guest", async () => {
    putGuest("192.0.2.20", "vm-laptop");
    const section = await openHost("laptop-ak");
    const claims = await within(section).findByTestId("host-dormant");
    expect(claims.textContent).toBe("192.0.2.20 is configured on the stopped guest vm-laptop");
  });

  it("is quiet for a guest that runs and for a fact that expired", async () => {
    putGuest("192.0.2.20", "vm-laptop", { power: "running" });
    putGuest("192.0.2.20", "vm-old", { expired: true });
    const section = await openHost("laptop-ak");
    await waitFor(() => expect(within(section).queryAllByTestId("fact").length).toBeGreaterThan(0));
    expect(within(section).queryByTestId("host-dormant")).toBeNull();
  });
});

describe("on the address page", () => {
  it("says the address is configured on a stopped guest", async () => {
    putGuest("192.0.2.20", "vm-laptop");
    const page = await openAddress("192.0.2.20");
    const note = await within(page).findByTestId("address-dormant");
    expect(note.textContent).toBe("Configured on the stopped guest vm-laptop");
  });

  it("is quiet when the guest runs", async () => {
    putGuest("192.0.2.20", "vm-laptop", { power: "running" });
    const page = await openAddress("192.0.2.20");
    await settled();
    expect(within(page).queryByTestId("address-dormant")).toBeNull();
  });

  it("is quiet when the observations cannot be read", async () => {
    putGuest("192.0.2.20", "vm-laptop");
    server.use(
      http.get("/api/v1/observations/:subject", () =>
        HttpResponse.json(
          { type: "about:blank", title: "Forbidden", status: 403, code: "auth.forbidden", detail: "", params: {} },
          { status: 403, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    const page = await openAddress("192.0.2.20");
    await settled();
    expect(within(page).queryByTestId("address-dormant")).toBeNull();
    expect(within(page).queryByTestId("error-notice")).toBeNull();
  });
});
