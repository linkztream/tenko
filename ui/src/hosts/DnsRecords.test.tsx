// The DNS records block of the host and address pages: the A, AAAA and PTR records of each
// address from the zones that hold its name and its reverse name, "no zone in Tenko" where none
// does, and nothing at all while the module is off or the server has no DNS service.
import { render, screen, waitFor, within } from "@solidjs/testing-library";
import { MemoryRouter, createMemoryHistory } from "@solidjs/router";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { dnsStubs } from "../api/mock/routes-dns";
import { server } from "../api/mock/node";
import { axeViolations } from "../app/testing/axe";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { resetModules, setModulesForTest } from "../updates/modules";
import { DnsRecords, type DnsAddress } from "./DnsRecords";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  resetModules();
  await setLocale("en");
});

function show(addresses: DnsAddress[]) {
  const history = createMemoryHistory();
  history.set({ value: "/ipam/hosts/nas.example.test" });
  return render(() => (
    <MemoryRouter history={history}>{[{ path: "*rest", component: () => <DnsRecords addresses={addresses} /> }]}</MemoryRouter>
  ));
}

const records = (ip: string, kind: string) =>
  within(screen.getAllByTestId("host-dns-row").find((r) => r.dataset.key === ip) as HTMLElement)
    .queryAllByTestId("host-dns-record")
    .filter((r) => r.dataset.kind === kind)
    .map((r) => r.dataset.key);

describe("the DNS records of a host", () => {
  it("shows the name and reverse records of each address", async () => {
    const view = show([
      { ip: "192.0.2.1", dns_name: "gw.example.test" },
      { ip: "2001:db8:0:10::1", dns_name: "gw.example.test" },
    ]);
    await screen.findByTestId("host-dns");
    expect(records("192.0.2.1", "forward")).toEqual(["A 192.0.2.1"]);
    expect(records("2001:db8:0:10::1", "forward")).toEqual(["AAAA 2001:db8:0:10::1"]);
    expect(records("192.0.2.1", "reverse")).toEqual(["PTR gw.example.test"]);
    const v6 = screen.getAllByTestId("host-dns-row").find((r) => r.dataset.key === "2001:db8:0:10::1") as HTMLElement;
    expect(within(v6).getByTestId("host-dns-none").dataset.kind).toBe("reverse");
    expect(within(v6).getAllByTestId("host-dns-zone")[0]?.textContent).toBe("example.test");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("finds the zone by the longest suffix and says when it has no records yet", async () => {
    show([{ ip: "203.0.113.200", dns_name: "cam-1.lab.example.test" }]);
    await screen.findByTestId("host-dns");
    const r = screen.getByTestId("host-dns-row");
    expect(within(r).getByTestId("host-dns-empty").textContent).toBe("None in lab.example.test yet");
    expect(within(r).getByTestId("host-dns-none").dataset.kind).toBe("reverse");
  });

  it("says no zone in Tenko for a name outside every zone", async () => {
    show([{ ip: "198.51.100.7", dns_name: "printer.other.test" }]);
    await screen.findByTestId("host-dns");
    expect(screen.getAllByTestId("host-dns-none").map((n) => [n.dataset.kind, n.textContent])).toEqual([
      ["forward", "No zone in Tenko"],
      ["reverse", "No zone in Tenko"],
    ]);
  });

  it("shows nothing while the DNS module is off", async () => {
    setModulesForTest(["ipam"]);
    show([{ ip: "192.0.2.11", dns_name: "nas.example.test" }]);
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByTestId("host-dns")).toBeNull();
  });

  it("shows nothing while the server has no DNS service", async () => {
    server.use(...dnsStubs);
    show([{ ip: "192.0.2.11", dns_name: "nas.example.test" }]);
    await waitFor(() => expect(screen.queryByTestId("host-dns")).toBeNull());
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByTestId("host-dns")).toBeNull();
  });
});
