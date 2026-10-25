// The router advertisement panel and the status strip around it (DHCP-10): the three states of the
// check, the links with and without flags, each finding of the report as a note, Swedish, the panel
// hidden on a node without DHCPv6, and the server DUID in the strip. The panel gets its node status as
// a prop; the strip reads two handlers of its own, not the seed of the dev mock.
import { render, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { server } from "../../api/mock/node";
import { axeViolations } from "../../app/testing/axe";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import type { NodeStatus } from "../leases/model";
import { NodeStrip } from "../leases/NodeStrip";
import { RaPanel } from "./RaPanel";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const SEEN = "2026-10-25T10:00:00Z";
const DUID = "000400000000000000000000000000000001";

/** A node that serves DHCPv6 on one link with a router advertisement report; the tests override what they check. */
function status(over: Partial<NodeStatus> = {}): NodeStatus {
  return {
    node: 1,
    serving: true,
    accepting: true,
    probe: true,
    revision: 7,
    scopes: 1,
    scopes6: 2,
    listeners: [],
    listeners6: [
      {
        address: "2001:db8:0:10::1",
        interface: "eth0",
        mode: "relay",
        port: 547,
      },
    ],
    leases: [],
    leases6: [],
    ...over,
  } as NodeStatus;
}

const ETH0 = {
  interface: "eth0",
  routers: ["fe80::1"],
  managed: true,
  other: true,
  prefixes: ["2001:db8:0:10::/64"],
  scopes: ["2001:db8:0:10::/64"],
  seen: SEEN,
};
const ETH1 = {
  interface: "eth1",
  routers: ["fe80::2", "fe80::3"],
  managed: false,
  other: false,
  prefixes: ["2001:db8:0:30::/64"],
  scopes: ["2001:db8:0:30::/64"],
  seen: SEEN,
};
const FLAGS_OFF = {
  code: "dhcp.ra.flags_off",
  interface: "eth1",
  detail: "the routers set neither M nor O",
  params: {
    interface: "eth1",
    routers: "fe80::2, fe80::3",
    scopes: "2001:db8:0:30::/64",
  },
};

const panel = (node: NodeStatus) => render(() => <RaPanel node={node} />);

describe("the three states of the check", () => {
  it("says a node without a probe role is not checked, in one muted line", () => {
    panel(status({ ra: { check: "off", links: [], findings: [] } }));
    const state = screen.getByTestId("ra-state");
    expect(state.dataset.key).toBe("off");
    expect(state.textContent).toBe("Not checked: no probe role runs on this node");
    expect(state.className).toContain("muted");
    expect(screen.queryByTestId("ra-link")).toBeNull();
    expect(screen.queryByTestId("ra-finding")).toBeNull();
  });

  it("gives the reason as an information note when the check is unavailable", () => {
    panel(
      status({
        ra: {
          check: "unavailable",
          reason: "the raw socket needs CAP_NET_RAW",
          links: [],
          findings: [],
        },
      }),
    );
    const state = screen.getByTestId("ra-state");
    expect(state.classList.contains("info")).toBe(true);
    expect(state.textContent).toBe("Unavailable: the raw socket needs CAP_NET_RAW");
    expect(screen.queryByTestId("ra-link")).toBeNull();
  });

  it("does not repeat the unchecked finding next to the reason", () => {
    panel(
      status({
        ra: {
          check: "unavailable",
          reason: "the raw socket needs CAP_NET_RAW",
          links: [],
          findings: [
            {
              code: "dhcp.ra.unchecked",
              interface: "",
              detail: "cannot run",
              params: { reason: "the raw socket needs CAP_NET_RAW" },
            },
          ],
        },
      }),
    );
    expect(screen.queryByTestId("ra-finding")).toBeNull();
  });

  it("says it is watching and that nothing was heard when there is no link", () => {
    panel(status({ ra: { check: "watching", links: [], findings: [] } }));
    expect(screen.getByTestId("ra-state").dataset.key).toBe("watching");
    expect(screen.getByTestId("ra-state").textContent).toBe("Watching");
    expect(screen.getByTestId("ra-none").textContent).toBe("No router advertisement heard in the last hour");
    expect(screen.queryByRole("table")).toBeNull();
  });
});

describe("the links", () => {
  it("lists each link with its routers, its flags, its prefixes, its scopes and when it was heard", async () => {
    const view = panel(status({ ra: { check: "watching", links: [ETH0, ETH1], findings: [] } }));
    const headers = within(screen.getByRole("table"))
      .getAllByRole("columnheader")
      .map((h) => h.textContent);
    expect(headers).toEqual(["Interface", "Routers", "M", "O", "Advertised prefixes", "Scopes", "Last heard"]);
    const links = screen.getAllByTestId("ra-link");
    expect(links.map((l) => l.dataset.key)).toEqual(["eth0", "eth1"]);
    const eth0 = within(links[0]!);
    expect(eth0.getByTestId("ra-flag-m").dataset.key).toBe("yes");
    expect(eth0.getByTestId("ra-flag-m").textContent).toBe("Yes");
    expect(eth0.getByTestId("ra-flag-o").dataset.key).toBe("yes");
    expect(links[0]!.textContent).toContain("fe80::1");
    expect(links[0]!.textContent).toContain("2001:db8:0:10::/64");
    expect(links[0]!.querySelector("time")?.getAttribute("datetime")).toBe(SEEN);
    const eth1 = within(links[1]!);
    expect(eth1.getByTestId("ra-flag-m").dataset.key).toBe("no");
    expect(eth1.getByTestId("ra-flag-o").textContent).toBe("No");
    expect(links[1]!.textContent).toContain("fe80::2, fe80::3");
    expect(screen.getByTestId("ra-default-route").textContent).toBe("DHCPv6 never sets a default route: hosts take it from the router advertisements.");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows a dash where a link has no scope", () => {
    panel(
      status({
        ra: {
          check: "watching",
          links: [{ ...ETH0, scopes: [] }],
          findings: [],
        },
      }),
    );
    const cells = screen.getByTestId("ra-link").querySelectorAll("td");
    expect(cells[5]!.textContent).toBe("–");
  });
});

describe("the findings", () => {
  const NODE_PARAMS = { node: "1" };
  const cases = [
    {
      finding: FLAGS_OFF,
      kind: "warn",
      text: "The routers fe80::2, fe80::3 on eth1 of node 1 set neither the M nor the O flag, so the hosts on that link do not ask DHCPv6 and the scopes 2001:db8:0:30::/64 serve nobody. Turn on M (addresses) or O (options only) in the router advertisements.",
    },
    {
      finding: {
        code: "dhcp.ra.other_only",
        interface: "eth0",
        detail: "O only",
        params: {
          interface: "eth0",
          routers: "fe80::1",
          scopes: "2001:db8:0:10::/64",
        },
      },
      kind: "info",
      text: "The routers fe80::1 on eth0 of node 1 set the O flag without M, so the hosts on that link ask DHCPv6 for options only. That is right for stateless DHCPv6; turn on M if the hosts should get addresses from 2001:db8:0:10::/64.",
    },
    {
      finding: {
        code: "dhcp.ra.managed_without_scope",
        interface: "eth2",
        detail: "M without a scope",
        params: {
          interface: "eth2",
          routers: "fe80::9",
          prefixes: "2001:db8:0:50::/64",
        },
      },
      kind: "warn",
      text: "The routers fe80::9 on eth2 of node 1 set the M flag for 2001:db8:0:50::/64, but no enabled DHCPv6 scope covers that link, so the hosts ask a server that does not answer. Add a scope for the link or turn M off.",
    },
  ];

  for (const { finding, kind, text } of cases) {
    it(`shows ${finding.code} as a ${kind} note with its words and the node`, () => {
      panel(
        status({
          ra: { check: "watching", links: [ETH0], findings: [finding] },
        }),
      );
      const note = screen.getByTestId("ra-finding");
      expect(note.dataset.code).toBe(finding.code);
      expect(note.classList.contains(kind)).toBe(true);
      expect(note.textContent).toBe(text);
    });
  }

  it("keeps the node a finding of the server already names", () => {
    panel(
      status({
        ra: {
          check: "watching",
          links: [ETH1],
          findings: [
            {
              ...FLAGS_OFF,
              params: { ...FLAGS_OFF.params, ...NODE_PARAMS, node: "edge" },
            },
          ],
        },
      }),
    );
    expect(screen.getByTestId("ra-finding").textContent).toContain("of node edge");
  });

  it("shows the unchecked finding of a watching node with the reason", () => {
    panel(
      status({
        ra: {
          check: "watching",
          links: [],
          findings: [
            {
              code: "dhcp.ra.unchecked",
              interface: "",
              detail: "cannot run",
              params: { reason: "no CAP_NET_RAW" },
            },
          ],
        },
      }),
    );
    const note = screen.getByTestId("ra-finding");
    expect(note.classList.contains("info")).toBe(true);
    expect(note.textContent).toBe(
      "The router advertisement check cannot run on node 1: no CAP_NET_RAW. It needs the CAP_NET_RAW capability of the probe role on Linux.",
    );
  });

  it("falls back to the English detail for a code it has no words for", () => {
    panel(
      status({
        ra: {
          check: "watching",
          links: [ETH0],
          findings: [
            {
              code: "dhcp.ra.future",
              interface: "eth0",
              detail: "a finding of a newer server",
              params: {},
            },
          ],
        },
      }),
    );
    const note = screen.getByTestId("ra-finding");
    expect(note.dataset.code).toBe("dhcp.ra.future");
    expect(note.textContent).toBe("a finding of a newer server");
    expect(note.classList.contains("info")).toBe(true);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    panel(
      status({
        ra: { check: "watching", links: [ETH1], findings: [FLAGS_OFF] },
      }),
    );
    expect(screen.getByTestId("ra-state").textContent).toBe("Bevakar");
    expect(screen.getByTestId("ra-finding").textContent).toContain("sätter varken M- eller O-flaggan");
    expect(within(screen.getByTestId("ra-link")).getByTestId("ra-flag-m").textContent).toBe("Nej");
    expect(screen.getByTestId("ra-summary").textContent).toContain("Routerannonseringar");
    expect(screen.getByTestId("ra-finding-count").textContent).toBe("1 anmärkning");
  });
});

describe("when the panel is hidden", () => {
  it("shows nothing on a node without DHCPv6 whose check is off", () => {
    panel(
      status({
        scopes6: 0,
        listeners6: [],
        leases6: [],
        ra: { check: "off", links: [], findings: [] },
      }),
    );
    expect(screen.queryByTestId("ra-panel")).toBeNull();
  });

  it("shows nothing for a server that does not report the check", () => {
    panel(status());
    expect(screen.queryByTestId("ra-panel")).toBeNull();
  });

  it("shows the line of the off state on a node that serves DHCPv6", () => {
    panel(status({ ra: { check: "off", links: [], findings: [] } }));
    expect(screen.getByTestId("ra-panel").dataset.check).toBe("off");
  });
});

describe("in the status strip", () => {
  function serve(node: NodeStatus) {
    server.use(
      http.get("/api/v1/system/status", () => HttpResponse.json({ node: { id: 1 } })),
      http.get("/api/v1/nodes/:id/dhcp", () => HttpResponse.json(node)),
    );
  }

  it("shows the panel below the strip", async () => {
    serve(
      status({
        ra: { check: "watching", links: [ETH1], findings: [FLAGS_OFF] },
      }),
    );
    render(() => <NodeStrip version={() => 0} />);
    expect(await screen.findByTestId("dhcp-strip")).toBeTruthy();
    expect(await screen.findByTestId("ra-panel")).toBeTruthy();
    expect(screen.getByTestId("ra-link").dataset.key).toBe("eth1");
    expect(screen.getAllByTestId("ra-finding")).toHaveLength(1);
  });

  it("shows the server DUID in pairs with colons, the whole value in the title", async () => {
    serve(status({ server_duid: DUID }));
    render(() => <NodeStrip version={() => 0} />);
    const fact = await screen.findByTestId("strip-server-duid");
    expect(fact.textContent).toBe("Server DUID 00:04:00:00:00:00…00:00:00:01");
    expect(fact.title).toBe("The DUID this DHCPv6 server names itself with: 00:04:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01");
  });

  it("shows a short DUID in full and none when the server has none", async () => {
    serve(status({ server_duid: "00030001000000000001" }));
    const view = render(() => <NodeStrip version={() => 0} />);
    expect((await screen.findByTestId("strip-server-duid")).textContent).toBe("Server DUID 00:03:00:01:00:00:00:00:00:01");
    view.unmount();
    serve(status());
    render(() => <NodeStrip version={() => 0} />);
    await screen.findByTestId("dhcp-strip");
    await waitFor(() => expect(screen.queryByTestId("strip-server-duid")).toBeNull());
  });
});

describe("the closed panel", () => {
  it("is one line with the state and the number of findings until it is opened", () => {
    panel(
      status({
        ra: { check: "watching", links: [ETH1], findings: [FLAGS_OFF] },
      }),
    );
    const details = screen.getByTestId("ra-panel");
    expect(details.tagName).toBe("DETAILS");
    expect((details as HTMLDetailsElement).open).toBe(false);
    const count = screen.getByTestId("ra-finding-count");
    expect(count.textContent).toBe("1 finding");
    expect(count.dataset.count).toBe("1");
    expect(count.classList.contains("conflict")).toBe(true);
  });

  it("has no count without findings", () => {
    panel(
      status({
        ra: { check: "watching", links: [ETH1], findings: [] },
      }),
    );
    expect(screen.queryByTestId("ra-finding-count")).toBeNull();
  });
});
