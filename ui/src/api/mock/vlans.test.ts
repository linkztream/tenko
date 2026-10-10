// VLAN provisioning and the prefixes of a VLAN in the mock API through `fetch` against the msw
// server: the preview in each mode, the guardrail, duplicates and validation, the
// acknowledgements, the submit with its job, the IPAM objects and the controller network it
// creates, the manual task, idempotency, and the prefix list.
import { beforeEach, describe, expect, it } from "vitest";
import { apiOperations } from "../generated/operations";
import type { components } from "../generated/schema";
import { db, resetMockDb } from "./db";
import { IPAM_IDS, applyCommands, ipamState } from "./ipam/api";
import { jobStore } from "./job-store";
import { mockVlanController } from "./routes-vlans";
import { TOPOLOGY_IDS } from "./topology-store";

type S = components["schemas"];
type Preview = S["VlanProvisionPreview"];
type Submitted = S["VlanProvisionSubmitted"];
type JobDetail = S["JobDetail"];

interface Problem {
  type: string;
  status: number;
  code: string;
  title: string;
  detail: string;
  params: Record<string, string>;
  errors?: { field: string; code: string }[];
}
interface Answer<T> {
  res: Response;
  status: number;
  body: T;
}

async function call<T>(method: string, path: string, json?: unknown, headers: Record<string, string> = {}): Promise<Answer<T>> {
  const init: RequestInit = { method, headers: { accept: "application/json", ...headers } };
  if (json !== undefined) {
    init.headers = { ...init.headers, "content-type": "application/json" };
    init.body = JSON.stringify(json);
  }
  const res = await fetch(path, init);
  const text = await res.text();
  return { res, status: res.status, body: (text ? JSON.parse(text) : undefined) as T };
}
const get = <T>(path: string) => call<T>("GET", path);
const post = <T>(path: string, json?: unknown, headers?: Record<string, string>) => call<T>("POST", path, json, headers);

function expectProblem(answer: Answer<unknown>, status: number, code: string): Problem {
  expect(answer.status, JSON.stringify(answer.body)).toBe(status);
  expect(answer.res.headers.get("content-type")).toContain("application/problem+json");
  const body = answer.body as Problem;
  expect(body.type).toBe("about:blank");
  expect(body.code).toBe(code);
  expect(body.params).toBeTypeOf("object");
  return body;
}

const V = "/api/v1";
const PROVISION = `${V}/vlans/provision`;
const DRY = `${PROVISION}?dry_run=true`;
const CONTROLLER_NAME = "unifi.example.test";
/** A free network inside the documentation supernet of the seed (203.0.113.0/24). */
const FREE_NET = "203.0.113.208/28";

/** A new VLAN with a network, free in the seed. */
const guests = (extra: Record<string, unknown> = {}) => ({
  create: { vid: 60, name: "Guests" },
  prefix: { cidr: FREE_NET },
  ...extra,
});

async function preview(body: unknown): Promise<Preview> {
  const answer = await post<Preview>(DRY, body);
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  return answer.body;
}

async function submit(body: unknown, headers?: Record<string, string>): Promise<Submitted> {
  const answer = await post<Submitted>(PROVISION, body, headers);
  expect(answer.status, JSON.stringify(answer.body)).toBe(202);
  return answer.body;
}

const job = async (id: string): Promise<JobDetail> => (await get<JobDetail>(`${V}/jobs/${id}`)).body;
const vlanOf = (id: string) => ipamState().data.vlan.get(id);
const prefixOf = (id: string) => ipamState().data.prefix.get(id);
const liveVlans = () => [...ipamState().data.vlan.values()].filter((v) => !v.meta.deleted).length;
/** The VLANs of the seed: LAN, Lab, IoT, DMZ, Management and the planned Guest. */
const SEEDED_VLANS = 6;
const network = (vid: number) => mockVlanController.networks.find((n) => n.vlan === vid);

beforeEach(() => {
  resetMockDb("signed-in");
});

describe("the VLAN operations of the document", () => {
  it("are answered, each after the session check", async () => {
    const operations = apiOperations.filter((o) => o.path === "/api/v1/vlans/provision" || o.path === "/api/v1/vlans/{id}/prefixes");
    expect(operations).toHaveLength(2);
    for (const operation of operations) {
      const path = operation.path.replace("{id}", IPAM_IDS.vlan.v10);
      const json = operation.method === "post" ? {} : undefined;
      resetMockDb("signed-in");
      expect((await call(operation.method.toUpperCase(), path, json)).status, path).not.toBe(501);
      resetMockDb("signed-out");
      expectProblem(await call(operation.method.toUpperCase(), path, json), 401, "auth.unauthenticated");
    }
  });
});

describe("GET /vlans/{id}/prefixes", () => {
  const list = async (id: string, query = "") => get<{ items: S["Prefix"][]; next_cursor: string | null; revision: number }>(`${V}/vlans/${id}/prefixes${query}`);

  it("lists the live prefixes linked to the VLAN as a page, ordered by VRF and network", async () => {
    const answer = await list(IPAM_IDS.vlan.v10);
    expect(answer.status).toBe(200);
    expect(answer.body.next_cursor).toBeNull();
    expect(answer.body.revision).toBe(db.revision);
    // IPv4 before IPv6 within the VRF.
    expect(answer.body.items.map((p) => [p.id, p.cidr])).toEqual([
      [IPAM_IDS.prefix.lan, "192.0.2.0/24"],
      [IPAM_IDS.prefix.lanV6, "2001:db8:0:10::/64"],
    ]);
    expect((await list(IPAM_IDS.vlan.v30)).body.items.map((p) => p.id)).toEqual([IPAM_IDS.prefix.iot, IPAM_IDS.prefix.iotV6]);
    expect((await list(IPAM_IDS.vlan.v20)).body.items.map((p) => p.id)).toEqual([IPAM_IDS.prefix.lab]);
    // A VLAN without a prefix has an empty page, not a 404.
    expect((await list(IPAM_IDS.vlan.v50)).body).toMatchObject({ items: [], next_cursor: null });
  });

  it("orders by VRF first and follows a prefix that is linked to another VLAN", async () => {
    applyCommands([
      { op: "update_prefix", args: { id: IPAM_IDS.prefix.workshop, expected: null, patch: { vlan: IPAM_IDS.vlan.v10 } } },
    ] as never);
    const items = (await list(IPAM_IDS.vlan.v10)).body.items;
    expect(items.map((p) => p.id)).toEqual([IPAM_IDS.prefix.lan, IPAM_IDS.prefix.lanV6, IPAM_IDS.prefix.workshop]);
    expect(items.map((p) => p.vrf)).toEqual([IPAM_IDS.vrf.default, IPAM_IDS.vrf.default, IPAM_IDS.vrf.isolated]);
    applyCommands([
      { op: "update_prefix", args: { id: IPAM_IDS.prefix.lanV6, expected: null, patch: { vlan: IPAM_IDS.vlan.v20 } } },
    ] as never);
    expect((await list(IPAM_IDS.vlan.v10)).body.items.map((p) => p.id)).not.toContain(IPAM_IDS.prefix.lanV6);
    expect((await list(IPAM_IDS.vlan.v20)).body.items.map((p) => p.id)).toContain(IPAM_IDS.prefix.lanV6);
  });

  it("hides the deleted prefixes unless asked to include them", async () => {
    // 2001:db8:0:99::/64 of the Management VLAN was deleted two days ago in the seed.
    expect((await list(IPAM_IDS.vlan.v99)).body.items).toEqual([]);
    expect((await list(IPAM_IDS.vlan.v99, "?deleted=exclude")).body.items).toEqual([]);
    const included = (await list(IPAM_IDS.vlan.v99, "?deleted=include")).body.items;
    expect(included.map((p) => p.id)).toEqual([IPAM_IDS.prefix.managementV6]);
    expect(included[0]?.meta.deleted).not.toBeNull();
    expect((await list(IPAM_IDS.vlan.v10, "?deleted=include")).body.items).toHaveLength(2);
    expectProblem(await list(IPAM_IDS.vlan.v99, "?deleted=only"), 400, "sys.invalid_query");
    expectProblem(await list(IPAM_IDS.vlan.v99, "?deleted=yes"), 400, "sys.invalid_query");
    expectProblem(await list(IPAM_IDS.vlan.v99, "?deleted=include&deleted=exclude"), 400, "sys.invalid_query");
  });

  it("answers 404 for an unknown VLAN and 400 for a bad identifier or parameter", async () => {
    const missing = expectProblem(await list("0190d1c2-0000-7000-8000-0000000400ff"), 404, "ipam.not_found");
    expect(missing.params).toMatchObject({ kind: "vlan" });
    expectProblem(await list("nope"), 400, "sys.invalid_request");
    expectProblem(await list(IPAM_IDS.vlan.v10, "?colour=blue"), 400, "sys.invalid_query");
    expectProblem(await list(IPAM_IDS.vlan.v10, "?limit=0"), 400, "sys.invalid_query");
    expectProblem(await list(IPAM_IDS.vlan.v10, "?at_least=soon"), 400, "sys.invalid_query");
    expect((await list(IPAM_IDS.vlan.v10, "?limit=1000&at_least=1")).status).toBe(200);
  });
});

describe("the preview of a new VLAN with a network", () => {
  it("plans the intent, asks the controller for a network and lists the steps", async () => {
    const before = { vlans: liveVlans(), networks: mockVlanController.networks.length, jobs: jobStore.jobs.length, revision: db.revision };
    const p = await preview(guests());
    expect(p.vlan).toMatchObject({ vid: 60, name: "Guests", existing: false, status: "planned" });
    expect(p.vlan.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(p.vlan.site).toBeUndefined();
    expect(p.prefix).toMatchObject({ cidr: FREE_NET });
    expect(p.prefix?.vrf).toBeUndefined();
    expect(p.base_revision).toBe(db.revision);
    // The IPAM plan: the VLAN and the prefix, created as planned, the prefix linked to the VLAN.
    expect(p.plan?.changes.map((c) => [c.object.kind, c.action])).toEqual([
      ["vlan", "create"],
      ["prefix", "create"],
    ]);
    expect(p.plan?.changes.map((c) => (c.after?.data as { status?: string }).status)).toEqual(["planned", "planned"]);
    expect((p.plan?.changes[1]?.after?.data as { vlan?: string }).vlan).toBe(p.vlan.id);
    expect(p.plan?.results).toEqual([
      { kind: "vlan", id: p.vlan.id },
      { kind: "prefix", id: p.prefix?.id },
    ]);
    expect(p.plan?.summary.lines).toEqual(["1 prefix created", "1 VLAN created"]);
    // The controller: a write, with two diff lines for a network it does not have.
    expect(p.controller).toMatchObject({
      mode: "automatic",
      connector: { id: TOPOLOGY_IDS.controller, name: CONTROLLER_NAME, plugin: "unifi", enabled: true, writes_enabled: true },
      network: { vid: 60, name: "Guests" },
      diff: [
        { path: "networks/vlan-60/name", after: "Guests" },
        { path: "networks/vlan-60/vlan", after: "60" },
      ],
      candidates: [{ id: TOPOLOGY_IDS.controller }],
    });
    expect(p.controller.reason).toBeUndefined();
    expect(p.controller.diff?.every((line) => line.before === undefined)).toBe(true);
    expect(Date.parse(p.controller.read_at ?? "")).toBeLessThanOrEqual(Date.now());
    expect(p.controller.network.dhcp_relay).toBeUndefined();
    // The steps of the job, in order.
    expect(p.steps.map((s) => [s.kind, s.step_kind, s.automatic])).toEqual([
      ["ipam.intent", "ipam.vlan.intent", true],
      ["l2.network", "ipam.vlan.controller", true],
      ["activate", "ipam.vlan.activate", true],
    ]);
    expect(p.steps[0]?.text).toBe(`Create VLAN 60 (Guests) and the network ${FREE_NET} in IPAM as planned`);
    expect(p.steps[1]?.text).toContain(`Create the network Guests on VLAN 60 through ${CONTROLLER_NAME}`);
    expect(p.steps[1]?.params).toEqual({ vid: "60", name: "Guests", cidr: FREE_NET, connector: CONTROLLER_NAME });
    expect(p.warnings ?? []).toEqual([]);
    expect(p.unacknowledged ?? []).toEqual([]);
    // Nothing was written.
    expect({ vlans: liveVlans(), networks: mockVlanController.networks.length, jobs: jobStore.jobs.length, revision: db.revision }).toEqual(before);
  });

  it("uses the network name and the DHCP relays of the request, and the site of the VLAN for the prefix", async () => {
    const p = await preview(
      guests({
        create: { vid: 60, name: "Guests", site: IPAM_IDS.site.garage, description: "Visitors" },
        network_name: " Visitors ",
        dhcp_relay: ["192.0.2.53", "2001:db8::53"],
      }),
    );
    expect(p.vlan).toMatchObject({ name: "Guests", site: IPAM_IDS.site.garage });
    expect(p.controller.network).toEqual({ vid: 60, name: "Visitors", dhcp_relay: ["192.0.2.53", "2001:db8::53"] });
    expect(p.controller.diff?.[0]).toMatchObject({ path: "networks/vlan-60/name", after: "Visitors" });
    expect((p.plan?.changes[1]?.after?.data as { site?: string }).site).toBe(IPAM_IDS.site.garage);
    expect(p.steps[1]?.params.name).toBe("Visitors");
  });

  it("has only the intent and the network without a prefix", async () => {
    const p = await preview({ create: { vid: 61, name: "Spare" } });
    expect(p.prefix).toBeUndefined();
    expect(p.plan?.changes.map((c) => c.object.kind)).toEqual(["vlan"]);
    expect(p.steps.map((s) => s.kind)).toEqual(["ipam.intent", "l2.network", "activate"]);
    expect(p.steps[0]?.text).toBe("Create VLAN 61 (Spare) in IPAM as planned");
    expect(p.steps[1]?.params.cidr).toBeUndefined();
  });

  it("accepts the same VLAN id at another site and counts only live VLANs", async () => {
    // VLAN 30 exists at the site Home; a global VLAN 30 is another VLAN.
    expect((await post(DRY, { create: { vid: 30, name: "IoT" } })).status).toBe(200);
    // VLAN 50 (Guest, planned) is deleted: the id is free again.
    applyCommands([{ op: "delete", args: { object: { kind: "vlan", id: IPAM_IDS.vlan.v50 }, expected: null, cascade: false } }] as never);
    expect((await post(DRY, { create: { vid: 50, name: "Guests", site: IPAM_IDS.site.home } })).status).toBe(200);
  });
});

describe("the preview of an existing VLAN", () => {
  it("has the network step only: no IPAM change", async () => {
    const p = await preview({ vlan: IPAM_IDS.vlan.v20 });
    expect(p.vlan).toMatchObject({ id: IPAM_IDS.vlan.v20, vid: 20, name: "Lab", existing: true, status: "active", site: IPAM_IDS.site.lab });
    expect(p.plan).toBeUndefined();
    expect(p.prefix).toBeUndefined();
    expect(p.controller.mode).toBe("automatic");
    expect(p.controller.network).toEqual({ vid: 20, name: "Lab" });
    expect(p.steps.map((s) => s.kind)).toEqual(["l2.network"]);
  });

  it("is unchanged when the controller has the network under the same name", async () => {
    const p = await preview({ vlan: IPAM_IDS.vlan.v30 });
    expect(p.vlan).toMatchObject({ vid: 30, name: "IoT", existing: true });
    expect(p.controller).toMatchObject({ mode: "unchanged", connector: { name: CONTROLLER_NAME } });
    expect(p.controller.diff).toBeUndefined();
    expect(p.controller.reason).toBeUndefined();
    expect(p.warnings ?? []).toEqual([]);
    expect(p.steps.map((s) => [s.kind, s.automatic])).toEqual([["l2.network", true]]);
  });

  it("changes a network the controller has under another name, which needs an acknowledgement", async () => {
    const body = { vlan: IPAM_IDS.vlan.v30, network_name: "Things" };
    const p = await preview(body);
    expect(p.controller.mode).toBe("automatic");
    expect(p.controller.diff).toEqual([{ path: "networks/vlan-30/name", before: "IoT", after: "Things" }]);
    expect(p.warnings).toEqual([
      {
        code: "ipam.vlan.network_changes",
        message: expect.stringContaining("VLAN 30") as string,
        object: { kind: "vlan", id: IPAM_IDS.vlan.v30 },
        params: { vid: "30" },
        requires_ack: true,
        acknowledged: false,
      },
    ]);
    expect(p.unacknowledged).toEqual(["ipam.vlan.network_changes"]);
    // Acknowledged: the warning stays, the list of what is missing is empty.
    const acknowledged = await preview({ ...body, acknowledge: ["ipam.vlan.network_changes"] });
    expect(acknowledged.warnings?.[0]).toMatchObject({ code: "ipam.vlan.network_changes", acknowledged: true });
    expect(acknowledged.unacknowledged ?? []).toEqual([]);
  });

  it("links an existing VLAN to a new prefix: the intent creates the prefix only", async () => {
    const p = await preview({ vlan: IPAM_IDS.vlan.v20, prefix: { cidr: FREE_NET } });
    expect(p.plan?.changes.map((c) => [c.object.kind, c.action])).toEqual([["prefix", "create"]]);
    expect((p.plan?.changes[0]?.after?.data as { vlan?: string; site?: string }).vlan).toBe(IPAM_IDS.vlan.v20);
    // The prefix has the site of the VLAN.
    expect((p.plan?.changes[0]?.after?.data as { site?: string }).site).toBe(IPAM_IDS.site.lab);
    expect(p.steps.map((s) => s.kind)).toEqual(["ipam.intent", "l2.network", "activate"]);
    expect(p.steps[0]?.text).toBe(`Create the link to VLAN 20 (Lab) and the network ${FREE_NET} in IPAM as planned`);
  });
});

describe("the guardrail and the manual network step", () => {
  it("refuses the management VLAN of the controller, for a new and for an existing VLAN", async () => {
    for (const body of [{ create: { vid: 10, name: "Core" } }, { vlan: IPAM_IDS.vlan.v10 }]) {
      const problem = expectProblem(await post(DRY, body), 409, "connect.guardrail.protected_vlan");
      expect(problem.detail).toContain("10");
      expectProblem(await post(PROVISION, body), 409, "connect.guardrail.protected_vlan");
    }
    // The refusal writes nothing, not even the intent.
    expect(liveVlans()).toBe(SEEDED_VLANS);
    expect(jobStore.jobs.some((j) => j.job.spec.kind === "ipam.vlan.provision")).toBe(false);
    // Read-only does not lift it.
    mockVlanController.writes_enabled = false;
    expectProblem(await post(DRY, { vlan: IPAM_IDS.vlan.v10 }), 409, "connect.guardrail.protected_vlan");
  });

  it("leaves the network to a person when the request says `manual`, and then VLAN 10 is allowed", async () => {
    const p = await preview(guests({ manual: true }));
    expect(p.controller).toMatchObject({ mode: "manual", reason: "ipam.vlan.manual_requested", network: { vid: 60, name: "Guests" } });
    expect(p.controller.connector).toBeUndefined();
    expect(p.controller.diff).toBeUndefined();
    expect(p.controller.candidates).toEqual([expect.objectContaining({ id: TOPOLOGY_IDS.controller })]);
    expect(p.steps.map((s) => [s.kind, s.step_kind, s.automatic])).toEqual([
      ["ipam.intent", "ipam.vlan.intent", true],
      ["l2.manual", "ipam.vlan.manual", false],
      ["activate", "ipam.vlan.activate", true],
    ]);
    expect(p.steps[1]?.text).toBe("Create the network Guests on VLAN 60 on the switches and access points");
    expect(p.steps[1]?.params).toEqual({ vid: "60", name: "Guests", cidr: FREE_NET });
    expect(p.warnings ?? []).toEqual([]);
    // The management VLAN only in IPAM.
    const management = await preview({ create: { vid: 10, name: "Core" }, manual: true });
    expect(management.controller.mode).toBe("manual");
    expect(management.steps.map((s) => s.kind)).toEqual(["ipam.intent", "l2.manual", "activate"]);
  });

  it("asks a person when the controller does not allow writes, shows the plan and needs an acknowledgement", async () => {
    mockVlanController.writes_enabled = false;
    const p = await preview(guests());
    expect(p.controller).toMatchObject({
      mode: "manual",
      reason: "ipam.vlan.controller_read_only",
      connector: { name: CONTROLLER_NAME, writes_enabled: false },
      diff: [{ path: "networks/vlan-60/name" }, { path: "networks/vlan-60/vlan" }],
    });
    expect(p.warnings).toEqual([
      expect.objectContaining({
        code: "ipam.vlan.controller_read_only",
        requires_ack: true,
        acknowledged: false,
        params: { connector: CONTROLLER_NAME },
        object: { kind: "vlan", id: p.vlan.id },
      }),
    ]);
    expect(p.unacknowledged).toEqual(["ipam.vlan.controller_read_only"]);
    expect(p.steps.map((s) => s.kind)).toEqual(["ipam.intent", "l2.manual", "activate"]);
    // The manual task names the controller.
    expect(p.steps[1]?.params).toEqual({ vid: "60", name: "Guests", cidr: FREE_NET, connector: CONTROLLER_NAME });
    // A rename on a read-only controller asks for the one acknowledgement only.
    const rename = await preview({ vlan: IPAM_IDS.vlan.v30, network_name: "Things" });
    expect(rename.controller.mode).toBe("manual");
    expect(rename.warnings?.map((w) => w.code)).toEqual(["ipam.vlan.controller_read_only"]);
    // A network the controller has already needs no write.
    const same = await preview({ vlan: IPAM_IDS.vlan.v30 });
    expect(same.controller.mode).toBe("unchanged");
    expect(same.warnings ?? []).toEqual([]);
  });

  it("falls back to a manual step without a controller, and refuses a connector that is not one", async () => {
    mockVlanController.present = false;
    const p = await preview(guests());
    expect(p.controller).toMatchObject({ mode: "manual", reason: "ipam.vlan.no_controller" });
    expect(p.controller.connector).toBeUndefined();
    expect(p.controller.candidates).toBeUndefined();
    expect(p.steps[1]).toMatchObject({ kind: "l2.manual", automatic: false, params: { vid: "60", name: "Guests", cidr: FREE_NET } });
    expect(p.steps[1]?.params.connector).toBeUndefined();
    expect(p.warnings ?? []).toEqual([]);
    // Naming one is a 404; so is `manual` with the reason of the request.
    expectProblem(await post(DRY, guests({ connector: TOPOLOGY_IDS.controller })), 404, "ipam.vlan.controller_unknown");
    expect((await preview(guests({ manual: true }))).controller.reason).toBe("ipam.vlan.manual_requested");
  });

  it("treats a disabled controller as none, and refuses to be named", async () => {
    mockVlanController.enabled = false;
    expect((await preview(guests())).controller).toMatchObject({ mode: "manual", reason: "ipam.vlan.no_controller" });
    const disabled = expectProblem(await post(DRY, guests({ connector: TOPOLOGY_IDS.controller })), 409, "ipam.vlan.controller_disabled");
    expect(disabled.params).toEqual({ connector: TOPOLOGY_IDS.controller });
  });

  it("knows the connector it is named: 404 `ipam.vlan.controller_unknown` for another one", async () => {
    const named = await preview(guests({ connector: TOPOLOGY_IDS.controller }));
    expect(named.controller).toMatchObject({ mode: "automatic", connector: { id: TOPOLOGY_IDS.controller } });
    const other = "0190d1c2-0000-7000-8000-00000c0000ff";
    const unknown = expectProblem(await post(DRY, guests({ connector: other })), 404, "ipam.vlan.controller_unknown");
    expect(unknown.params).toEqual({ connector: other });
    expect(unknown.errors).toEqual([{ field: "connector", code: "ipam.vlan.controller_unknown" }]);
    expectProblem(await post(PROVISION, guests({ connector: other })), 404, "ipam.vlan.controller_unknown");
  });
});

describe("validation", () => {
  it("refuses a body with unknown or mistyped members: 400 `sys.invalid_request`", async () => {
    for (const body of [
      { create: { vid: 60, name: "Guests" }, colour: "blue" },
      { create: { vid: 60, name: "Guests", colour: "blue" } },
      { create: { vid: 60, name: "Guests" }, prefix: { cidr: FREE_NET, vlan: "x" } },
      { create: { vid: "60", name: "Guests" } },
      { create: { vid: 60 } },
      { create: { vid: 70_000, name: "Guests" } },
      { create: { vid: -1, name: "Guests" } },
      { create: { vid: 60.5, name: "Guests" } },
      { create: "VLAN 60" },
      { vlan: "lab" },
      { vlan: IPAM_IDS.vlan.v20, manual: "yes" },
      { vlan: IPAM_IDS.vlan.v20, connector: "unifi" },
      { vlan: IPAM_IDS.vlan.v20, dhcp_relay: ["dhcp"] },
      { vlan: IPAM_IDS.vlan.v20, dhcp_relay: "192.0.2.53" },
      { vlan: IPAM_IDS.vlan.v20, acknowledge: [1] },
      { vlan: IPAM_IDS.vlan.v20, network_name: 5 },
      { create: { vid: 60, name: "Guests" }, prefix: { cidr: "203.0.113.208" } },
      { create: { vid: 60, name: "Guests" }, prefix: { cidr: "lan" } },
      { create: { vid: 60, name: "Guests" }, prefix: {} },
    ]) {
      expectProblem(await post(DRY, body), 400, "sys.invalid_request");
      expectProblem(await post(PROVISION, body), 400, "sys.invalid_request");
    }
    expectProblem(await post(DRY, [1]), 400, "sys.invalid_request");
    expectProblem(await post(DRY), 400, "sys.invalid_request");
    const answer = await fetch(DRY, { method: "POST", headers: { "content-type": "application/json" }, body: "{" });
    expect(answer.status).toBe(400);
  });

  it("wants exactly one of `vlan` and `create`: 400 `ipam.vlan.invalid_request`", async () => {
    const neither = expectProblem(await post(DRY, {}), 400, "ipam.vlan.invalid_request");
    expect(neither.params).toEqual({ field: "create" });
    expect(neither.errors).toEqual([{ field: "create", code: "ipam.vlan.invalid_request" }]);
    const both = expectProblem(await post(DRY, { vlan: IPAM_IDS.vlan.v20, create: { vid: 60, name: "Guests" } }), 400, "ipam.vlan.invalid_request");
    expect(both.params).toEqual({ field: "vlan" });
    expectProblem(await post(PROVISION, { prefix: { cidr: FREE_NET } }), 400, "ipam.vlan.invalid_request");
    // Nulls are absent members.
    expectProblem(await post(DRY, { vlan: null, create: null }), 400, "ipam.vlan.invalid_request");
    expect((await post(DRY, { vlan: IPAM_IDS.vlan.v20, create: null, prefix: null, connector: null, network_name: null })).status).toBe(200);
  });

  it("limits the network name to 1 to 64 characters and the relays to 8", async () => {
    const name = (text: string) => post(DRY, { vlan: IPAM_IDS.vlan.v20, network_name: text });
    expect(expectProblem(await name("x".repeat(65)), 400, "ipam.vlan.invalid_request").params).toEqual({ field: "network_name" });
    expectProblem(await name(""), 400, "ipam.vlan.invalid_request");
    expectProblem(await name("   "), 400, "ipam.vlan.invalid_request");
    expect((await name("x".repeat(64))).status).toBe(200);
    expect((await name("é".repeat(64))).status).toBe(200);
    expectProblem(await name("é".repeat(65)), 400, "ipam.vlan.invalid_request");
    const relays = (count: number) =>
      post(DRY, { vlan: IPAM_IDS.vlan.v20, dhcp_relay: Array.from({ length: count }, (_, i) => `192.0.2.${50 + i}`) });
    expect((await relays(8)).status).toBe(200);
    expect(expectProblem(await relays(9), 400, "ipam.vlan.invalid_request").params).toEqual({ field: "dhcp_relay" });
    expect(expectProblem(await post(DRY, { vlan: IPAM_IDS.vlan.v20, manual: true, connector: TOPOLOGY_IDS.controller }), 400, "ipam.vlan.invalid_request").params).toEqual({
      field: "connector",
    });
  });

  it("checks the VLAN id: 1 to 4094 (`ipam.validation`), unique per site among the live VLANs (`ipam.vlan.duplicate`)", async () => {
    for (const vid of [0, 4095, 65_535]) {
      const problem = expectProblem(await post(DRY, { create: { vid, name: "Odd" } }), 400, "ipam.validation");
      expect(problem.errors?.[0]).toMatchObject({ field: "vid" });
    }
    expect((await post(DRY, { create: { vid: 1, name: "One" } })).status).toBe(200);
    expect((await post(DRY, { create: { vid: 4094, name: "Last" } })).status).toBe(200);
    const duplicate = expectProblem(await post(DRY, { create: { vid: 30, name: "More", site: IPAM_IDS.site.home } }), 409, "ipam.vlan.duplicate");
    expect(duplicate.params).toEqual({ vid: "30" });
    expectProblem(await post(PROVISION, { create: { vid: 30, name: "More", site: IPAM_IDS.site.home } }), 409, "ipam.vlan.duplicate");
    expectProblem(await post(DRY, { create: { vid: 60, name: "" } }), 400, "ipam.validation");
    expectProblem(await post(DRY, { create: { vid: 60, name: "Guests", site: IPAM_IDS.vlan.v10 } }), 409, "ipam.reference_missing");
  });

  it("checks the prefix with the IPAM rules", async () => {
    expectProblem(await post(DRY, guests({ prefix: { cidr: "198.51.100.0/24" } })), 409, "ipam.prefix.overlap");
    expectProblem(await post(DRY, guests({ prefix: { cidr: "203.0.113.209/28" } })), 400, "ipam.prefix.host_bits");
    expectProblem(await post(DRY, guests({ prefix: { cidr: FREE_NET, vrf: "0190d1c2-0000-7000-8000-0000000200ff" } })), 409, "ipam.reference_missing");
    // The same network in the other VRF is no overlap.
    expect((await post(DRY, guests({ prefix: { cidr: "198.51.100.0/24", vrf: IPAM_IDS.vrf.isolated } }))).status).toBe(200);
  });

  it("looks the existing VLAN up: 404 `ipam.not_found`, 409 `ipam.object_deleted`", async () => {
    const missing = expectProblem(await post(DRY, { vlan: "0190d1c2-0000-7000-8000-0000000400ff" }), 404, "ipam.not_found");
    expect(missing.params).toMatchObject({ kind: "vlan" });
    applyCommands([{ op: "delete", args: { object: { kind: "vlan", id: IPAM_IDS.vlan.v50 }, expected: null, cascade: false } }] as never);
    expectProblem(await post(DRY, { vlan: IPAM_IDS.vlan.v50 }), 409, "ipam.object_deleted");
    expectProblem(await post(PROVISION, { vlan: IPAM_IDS.vlan.v50 }), 409, "ipam.object_deleted");
  });

  it("refuses unknown query parameters and values", async () => {
    expectProblem(await post(`${PROVISION}?dry_run=maybe`, guests()), 400, "sys.invalid_query");
    expectProblem(await post(`${PROVISION}?colour=blue`, guests()), 400, "sys.invalid_query");
    expectProblem(await post(`${PROVISION}?dry_run=true&dry_run=false`, guests()), 400, "sys.invalid_query");
    for (const value of ["true", "1", "yes"]) expect((await post(`${PROVISION}?dry_run=${value}`, guests())).status, value).toBe(200);
    expect((await post(`${PROVISION}?dry_run=true&at_least=1`, guests())).status).toBe(200);
    // `dry_run=false` submits.
    expect((await post(`${PROVISION}?dry_run=false`, guests())).status).toBe(202);
  });
});

describe("submitting a provision", () => {
  it("refuses while a warning that needs an acknowledgement is not acknowledged, and writes nothing", async () => {
    const body = { vlan: IPAM_IDS.vlan.v30, network_name: "Things" };
    const problem = expectProblem(await post(PROVISION, body), 409, "ipam.plan.unacknowledged");
    expect(problem.params).toEqual({ codes: "ipam.vlan.network_changes" });
    expect(network(30)?.name).toBe("IoT");
    expect(jobStore.jobs.some((j) => j.job.spec.kind === "ipam.vlan.provision")).toBe(false);
    // Another code is no acknowledgement.
    expectProblem(await post(PROVISION, { ...body, acknowledge: ["ipam.vlan.controller_read_only"] }), 409, "ipam.plan.unacknowledged");
    // The warnings of the IPAM plan count as well, and several codes are listed sorted.
    mockVlanController.writes_enabled = false;
    const both = expectProblem(
      await post(PROVISION, { create: { vid: 62, name: "Six" }, prefix: { cidr: "2001:db8:0:60::/62" } }),
      409,
      "ipam.plan.unacknowledged",
    );
    expect(both.params.codes).toBe("ipam.prefix.nibble_boundary,ipam.vlan.controller_read_only");
    expect(vlanOf(IPAM_IDS.vlan.v10)).toBeDefined();
    expect(liveVlans()).toBe(SEEDED_VLANS);
  });

  it("creates the VLAN and the prefix, adds the network to the controller and starts a job that succeeds", async () => {
    const dry = await preview(guests());
    const answer = await post<Submitted>(PROVISION, guests());
    expect(answer.status).toBe(202);
    const s = answer.body;
    expect(s).toMatchObject({ replayed: false, vlan: s.preview.vlan.id, prefix: s.preview.prefix?.id });
    expect(s.job_id).toMatch(/^[0-9a-f-]{36}$/);
    // The preview as computed at submit has the shape of the dry run.
    expect(s.preview.steps).toEqual(dry.steps);
    expect(s.preview.controller.diff).toEqual(dry.controller.diff);
    expect(s.preview.vlan).toMatchObject({ vid: 60, name: "Guests", existing: false, status: "planned" });

    // IPAM: the VLAN and the prefix exist and the job activated them.
    const vlan = vlanOf(s.vlan);
    expect(vlan).toMatchObject({ vid: 60, name: "Guests", status: "active", site: null });
    const prefix = prefixOf(s.prefix ?? "");
    expect(prefix).toMatchObject({ cidr: FREE_NET, vlan: s.vlan, status: "active", role: "network", vrf: IPAM_IDS.vrf.default });
    expect(ipamState().history.get(s.vlan)?.map((e) => e.action)).toEqual(["create", "update"]);
    expect(ipamState().history.get(s.prefix ?? "")?.map((e) => e.action)).toEqual(["create", "update"]);
    expect((await get<{ items: S["Prefix"][] }>(`${V}/vlans/${s.vlan}/prefixes`)).body.items.map((p) => p.id)).toEqual([s.prefix]);
    expect(((await get(`${V}/vlans/${s.vlan}`)).body as S["Vlan"]).name).toBe("Guests");

    // The controller has the network now, and the map lists it.
    expect(network(60)).toMatchObject({ name: "Guests", vlan: 60, management: false });
    const map = (await get<S["TopologyGraph"]>(`${V}/topology`)).body;
    expect(map.summary.networks.map((n) => [n.vlan, n.name])).toEqual([
      [10, "Management"],
      [30, "IoT"],
      [60, "Guests"],
    ]);
    // A new provision of the same network finds nothing to do.
    expect((await preview({ vlan: s.vlan })).controller.mode).toBe("unchanged");

    // The job: kind, title, targets, the steps with their kinds, all done.
    const detail = await job(s.job_id);
    expect(detail.job.spec).toMatchObject({ kind: "ipam.vlan.provision", title: "ipam.vlan.job.title" });
    expect(detail.job.spec.targets).toEqual([
      { kind: "vlan", id: s.vlan },
      { kind: "prefix", id: s.prefix },
      { kind: "connector", id: TOPOLOGY_IDS.controller },
    ]);
    expect(detail.job.spec.group).toBe(`ipam.vlan.provision.${TOPOLOGY_IDS.controller}`);
    expect(detail.job.spec.group_limit).toBe(4);
    expect(detail.job.spec.timeout).toBe(3600);
    expect(detail.job.state).toBe("succeeded");
    expect(detail.job.steps.map((st) => [st.kind, st.state.state])).toEqual([
      ["ipam.vlan.intent", "done"],
      ["ipam.vlan.controller", "done"],
      ["ipam.vlan.activate", "done"],
    ]);
    expect(detail.preview?.steps.map((st) => st.summary)).toEqual(["ipam.vlan.step.intent", "ipam.vlan.step.controller", "ipam.vlan.step.activate"]);
    expect(detail.preview?.steps[0]?.args).toEqual({ vid: "60", name: "Guests", cidr: FREE_NET });
    expect(detail.preview?.steps[0]?.changes).toEqual([
      { kind: "vlan", id: s.vlan },
      { kind: "prefix", id: s.prefix },
    ]);
    const listed = (await get<{ items: { id: string }[] }>(`${V}/jobs?kind=ipam.vlan.provision`)).body.items;
    expect(listed.map((j) => j.id)).toEqual([s.job_id]);
  });

  it("puts an existing VLAN onto the controller without changing IPAM", async () => {
    const revision = db.revision;
    const historyOfVlan = ipamState().history.get(IPAM_IDS.vlan.v20)?.length;
    const s = await submit({ vlan: IPAM_IDS.vlan.v20 });
    expect(s).toMatchObject({ vlan: IPAM_IDS.vlan.v20, replayed: false });
    expect(s.prefix).toBeUndefined();
    expect(network(20)).toMatchObject({ name: "Lab", vlan: 20 });
    expect(ipamState().history.get(IPAM_IDS.vlan.v20)?.length).toBe(historyOfVlan);
    expect(liveVlans()).toBe(SEEDED_VLANS);
    const detail = await job(s.job_id);
    expect(detail.job.state).toBe("succeeded");
    expect(detail.job.steps.map((st) => st.kind)).toEqual(["ipam.vlan.controller"]);
    expect(detail.job.spec.targets).toEqual([
      { kind: "vlan", id: IPAM_IDS.vlan.v20 },
      { kind: "connector", id: TOPOLOGY_IDS.controller },
    ]);
    // Only the job moved the revision: the IPAM objects did not change.
    expect(db.revision).toBeGreaterThan(revision);
    expect(vlanOf(IPAM_IDS.vlan.v20)?.meta.revision).toBeLessThanOrEqual(revision);
  });

  it("does nothing on the controller when it has the network, and renames it after an acknowledgement", async () => {
    const same = await submit({ vlan: IPAM_IDS.vlan.v30 });
    expect((await job(same.job_id)).job.state).toBe("succeeded");
    expect(network(30)?.name).toBe("IoT");
    const renamed = await submit({ vlan: IPAM_IDS.vlan.v30, network_name: "Things", acknowledge: ["ipam.vlan.network_changes"] });
    expect(renamed.preview.warnings?.[0]).toMatchObject({ code: "ipam.vlan.network_changes", acknowledged: true });
    expect(network(30)).toMatchObject({ name: "Things", id: "net-iot" });
    expect(mockVlanController.networks).toHaveLength(2);
    expect((await job(renamed.job_id)).job.state).toBe("succeeded");
  });

  it("links an existing VLAN to a new prefix and activates only what the job created", async () => {
    // VLAN 50 (Guest) is planned in the seed and stays as it is; the new prefix becomes active.
    const s = await submit({ vlan: IPAM_IDS.vlan.v50, prefix: { cidr: FREE_NET, description: "Guests" } });
    expect(prefixOf(s.prefix ?? "")).toMatchObject({ vlan: IPAM_IDS.vlan.v50, status: "active", site: IPAM_IDS.site.home });
    expect(prefixOf(s.prefix ?? "")?.meta.description).toBe("Guests");
    expect(vlanOf(IPAM_IDS.vlan.v50)?.status).toBe("planned");
    const detail = await job(s.job_id);
    expect(detail.job.steps.map((st) => st.kind)).toEqual(["ipam.vlan.intent", "ipam.vlan.controller", "ipam.vlan.activate"]);
    expect(network(50)).toMatchObject({ name: "Guest" });
    expect((await get<{ items: S["Prefix"][] }>(`${V}/vlans/${IPAM_IDS.vlan.v50}/prefixes`)).body.items.map((p) => p.id)).toEqual([s.prefix]);
  });

  it("applies the optional members of the request to the VLAN and the prefix", async () => {
    const s = await submit({
      create: { vid: 63, name: "Printers", site: IPAM_IDS.site.garage, vni: 10_063, description: "Print servers", tags: ["print"] },
      prefix: { cidr: "203.0.113.208/28", vrf: IPAM_IDS.vrf.default, description: "Printers" },
      dhcp_relay: ["192.0.2.53"],
    });
    expect(vlanOf(s.vlan)).toMatchObject({ vid: 63, vni: 10_063, site: IPAM_IDS.site.garage, status: "active" });
    expect(vlanOf(s.vlan)?.meta).toMatchObject({ description: "Print servers", tags: ["print"] });
    expect(prefixOf(s.prefix ?? "")).toMatchObject({ site: IPAM_IDS.site.garage, vrf: IPAM_IDS.vrf.default });
    expect(s.preview.controller.network).toEqual({ vid: 63, name: "Printers", dhcp_relay: ["192.0.2.53"] });
  });

  it("waits for a person at the manual network step and activates the VLAN when the task is done", async () => {
    mockVlanController.writes_enabled = false;
    const s = await submit(guests({ acknowledge: ["ipam.vlan.controller_read_only"] }));
    // Read-only: the controller is untouched, the VLAN and the prefix are planned.
    expect(network(60)).toBeUndefined();
    expect(vlanOf(s.vlan)?.status).toBe("planned");
    expect(prefixOf(s.prefix ?? "")?.status).toBe("planned");
    const waiting = await job(s.job_id);
    expect(waiting.job.state).toBe("waiting");
    expect(waiting.job.spec.timeout).toBe(30 * 24 * 3600);
    // The controller of a manual step is no target and no group.
    expect(waiting.job.spec.targets).toEqual([
      { kind: "vlan", id: s.vlan },
      { kind: "prefix", id: s.prefix },
    ]);
    expect(waiting.job.spec.group).toBeUndefined();
    expect(waiting.job.steps.map((st) => [st.kind, st.state.state])).toEqual([
      ["ipam.vlan.intent", "done"],
      ["ipam.vlan.manual", "waiting_for_manual"],
      ["ipam.vlan.activate", "pending"],
    ]);
    const task = {
      instruction: "ipam.vlan.task.network",
      args: { vid: "60", name: "Guests", cidr: FREE_NET, connector: CONTROLLER_NAME },
    };
    expect(waiting.job.steps[1]?.state).toMatchObject({ state: "waiting_for_manual", data: { task } });
    expect(waiting.preview?.steps[1]).toMatchObject({ summary: "ipam.vlan.task.network", manual: task });

    // A person creates the network and completes the task: the job goes on and activates.
    const done = await post<S["JobSummary"]>(`${V}/jobs/${s.job_id}/steps/1/complete`, { note: "created in the controller" });
    expect(done.status).toBe(200);
    expect((await job(s.job_id)).job.state).toBe("succeeded");
    expect(vlanOf(s.vlan)?.status).toBe("active");
    expect(prefixOf(s.prefix ?? "")?.status).toBe("active");
  });

  it("carries only the VLAN id and name in the manual task of a VLAN without a prefix or a controller", async () => {
    mockVlanController.present = false;
    const s = await submit({ create: { vid: 64, name: "Quiet" } });
    const waiting = await job(s.job_id);
    expect(waiting.job.state).toBe("waiting");
    expect(waiting.preview?.steps[1]?.manual).toEqual({ instruction: "ipam.vlan.task.network", args: { vid: "64", name: "Quiet" } });
    expect(s.preview.controller.reason).toBe("ipam.vlan.no_controller");
    // An existing VLAN has only the manual task.
    const existing = await submit({ vlan: IPAM_IDS.vlan.v20, manual: true });
    const only = await job(existing.job_id);
    expect(only.job.steps.map((st) => st.kind)).toEqual(["ipam.vlan.manual"]);
    expect(only.job.state).toBe("waiting");
    expect(only.preview?.steps[0]?.manual?.args).toEqual({ vid: "20", name: "Lab" });
  });

  it("soft-deletes what the job created when the job is cancelled", async () => {
    const s = await submit(guests({ manual: true }));
    expect(vlanOf(s.vlan)?.status).toBe("planned");
    const cancelled = await post(`${V}/jobs/${s.job_id}/cancel`);
    expect(cancelled.status).toBe(202);
    expect((await job(s.job_id)).job.state).toBe("cancelled");
    expect(vlanOf(s.vlan)?.meta.deleted).not.toBeNull();
    expect(prefixOf(s.prefix ?? "")?.meta.deleted).not.toBeNull();
    expect((await get<{ items: S["Prefix"][] }>(`${V}/vlans/${s.vlan}/prefixes`)).body.items).toEqual([]);
    expect((await get<{ items: S["Prefix"][] }>(`${V}/vlans/${s.vlan}/prefixes?deleted=include`)).body.items).toHaveLength(1);
    // The VLAN id is free again.
    expect((await post(DRY, { create: { vid: 60, name: "Guests" } })).status).toBe(200);
    // An existing VLAN is never deleted by the job that only linked it.
    const linked = await submit({ vlan: IPAM_IDS.vlan.v20, manual: true, prefix: { cidr: FREE_NET } });
    await post(`${V}/jobs/${linked.job_id}/cancel`);
    expect(vlanOf(IPAM_IDS.vlan.v20)?.meta.deleted).toBeNull();
    expect(prefixOf(linked.prefix ?? "")?.meta.deleted).not.toBeNull();
  });

  it("starts independent jobs for independent requests", async () => {
    const first = await submit(guests());
    const second = await submit({ create: { vid: 61, name: "Spare" } });
    expect(first.job_id).not.toBe(second.job_id);
    expect(network(61)?.name).toBe("Spare");
    expect(jobStore.jobs.filter((j) => j.job.spec.kind === "ipam.vlan.provision")).toHaveLength(2);
  });
});

describe("idempotency", () => {
  const KEY = "Idempotency-Key";

  it("answers the first result with `replayed: true` for the same body under the same key", async () => {
    const first = await submit(guests(), { [KEY]: "provision-60" });
    const jobs = jobStore.jobs.length;
    const vlans = liveVlans();
    const again = await post<Submitted>(PROVISION, guests(), { [KEY]: "provision-60" });
    expect(again.status).toBe(202);
    expect(again.body).toEqual({ ...first, replayed: true });
    // Nothing happened twice, and the answer is still the first one when the world has changed.
    expect(jobStore.jobs.length).toBe(jobs);
    expect(liveVlans()).toBe(vlans);
    expect((await post<Submitted>(PROVISION, guests(), { [KEY]: "provision-60" })).body.job_id).toBe(first.job_id);
  });

  it("does not tell members in another order or default members apart", async () => {
    const first = await submit({ create: { vid: 61, name: "Spare" }, manual: false, dhcp_relay: [] }, { [KEY]: "spare" });
    const again = await post<Submitted>(PROVISION, { dhcp_relay: [], create: { name: "Spare", vid: 61 } }, { [KEY]: "spare" });
    expect(again.status).toBe(202);
    expect(again.body.replayed).toBe(true);
    expect(again.body.job_id).toBe(first.job_id);
  });

  it("refuses another body under the same key: 422 `ipam.idempotency_mismatch`", async () => {
    await submit(guests(), { [KEY]: "provision-60" });
    expectProblem(await post(PROVISION, { create: { vid: 61, name: "Spare" } }, { [KEY]: "provision-60" }), 422, "ipam.idempotency_mismatch");
    expectProblem(await post(PROVISION, guests({ network_name: "Visitors" }), { [KEY]: "provision-60" }), 422, "ipam.idempotency_mismatch");
    expectProblem(await post(PROVISION, guests({ manual: true }), { [KEY]: "provision-60" }), 422, "ipam.idempotency_mismatch");
  });

  it("keeps keys apart, ignores them for a dry run and does not remember a refusal", async () => {
    const one = await submit(guests(), { [KEY]: "a" });
    const two = await submit({ create: { vid: 61, name: "Spare" } }, { [KEY]: "b" });
    expect(one.job_id).not.toBe(two.job_id);
    // A dry run neither stores nor replays.
    const dry = await post<Preview>(DRY, { create: { vid: 66, name: "Other" } }, { [KEY]: "a" });
    expect(dry.status).toBe(200);
    expect(dry.body.vlan).toMatchObject({ vid: 66, existing: false });
    expect((await post<Preview>(DRY, { create: { vid: 67, name: "More" } }, { [KEY]: "a" })).body.vlan.vid).toBe(67);
    // A refused request is no first result: it can be sent again after the cause is gone.
    mockVlanController.writes_enabled = false;
    const refused = { create: { vid: 65, name: "Later" } };
    expectProblem(await post(PROVISION, refused, { [KEY]: "later" }), 409, "ipam.plan.unacknowledged");
    mockVlanController.writes_enabled = true;
    expect((await post(PROVISION, refused, { [KEY]: "later" })).status).toBe(202);
  });

  it("forgets the keys when the db resets", async () => {
    await submit(guests(), { [KEY]: "provision-60" });
    resetMockDb("signed-in");
    const again = await post<Submitted>(PROVISION, guests(), { [KEY]: "provision-60" });
    expect(again.status).toBe(202);
    expect(again.body.replayed).toBe(false);
  });
});
