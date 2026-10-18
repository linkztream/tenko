// The pure resolver side of the mock DNS service without msw: the seed, forwarding rules
// (create, update, delete with the refusals of docs/dns-contracts.md section 5), block lists
// (create, update, delete, the compiled names of a file, fetch now, upload) and the resolver
// figures of the node status. A fixed clock, a revision counter and a counter-based id stand in
// for the msw caller.
import { beforeEach, describe, expect, it } from "vitest";
import { DnsFailure, type DnsContext } from "./dns-model";
import {
  LIST_URLS,
  RESOLVER_IDS,
  compileNames,
  createForwarder,
  createList,
  deleteForwarder,
  deleteList,
  fetchList,
  findForwarder,
  findList,
  listForwarders,
  listLists,
  resolverStatus,
  seedResolver,
  updateForwarder,
  updateList,
  uploadList,
  type ResolverState,
} from "./dns-resolver-model";

const NOW = Date.UTC(2026, 9, 17, 12);
const CORP = RESOLVER_IDS.forwarder.corp;
const ADS = RESOLVER_IDS.list.ads;
const LOCAL = RESOLVER_IDS.list.local;

let rev = 0;
let ids = 0;
let state: ResolverState;
let ctx: DnsContext;

beforeEach(() => {
  rev = 0;
  ids = 0;
  ctx = {
    now: () => NOW,
    nextRevision: () => ++rev,
    principal: () => ({ kind: "system", component: "api" }) as ReturnType<DnsContext["principal"]>,
    newId: () => `0190d1c2-0000-7000-8000-${String(++ids).padStart(12, "0")}`,
    newSecret: () => "c2VjcmV0",
  };
  state = seedResolver(ctx);
});

/** Runs `fn`, expects it to fail with a DnsFailure and returns the failure. */
function failure(fn: () => unknown): DnsFailure {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(DnsFailure);
    return error as DnsFailure;
  }
  throw new Error("expected a DnsFailure");
}

const ruleBody = (over: Record<string, unknown> = {}) => ({ suffix: "lab.example.test", upstreams: [{ address: "192.0.2.53" }], ...over });
const listBody = (over: Record<string, unknown> = {}) => ({
  name: "Trackers",
  source: { kind: "url", url: LIST_URLS.trackers },
  format: "domains",
  action: { kind: "nxdomain" },
  ...over,
});
const adsOf = () => findList(state, ADS);
const localOf = () => findList(state, LOCAL);

describe("seedResolver", () => {
  it("makes one forwarding rule for the domain controllers", () => {
    expect(state.forwarders).toHaveLength(1);
    expect(state.forwarders[0]).toMatchObject({ id: CORP, suffix: "corp.example.test", transport: "plain", view: null, tls_name: null });
    expect(state.forwarders[0]?.upstreams).toEqual([{ address: "192.0.2.10" }, { address: "192.0.2.11" }]);
  });

  it("makes the fetched list Ads and the uploaded list Local", () => {
    const ads = adsOf();
    expect(ads).toMatchObject({ name: "Ads", source: { kind: "url", url: LIST_URLS.ads }, format: "domains", enabled: true, interval_hours: 24, last_error: null });
    expect(ads.version).toMatchObject({ revision: 3, entries: 4, etag: '"a1b2c3"' });
    expect(localOf()).toMatchObject({ name: "Local", source: { kind: "upload" }, format: "hosts", enabled: false, interval_hours: 0, version: null });
    expect(localOf().action).toEqual({ kind: "redirect", address: "192.0.2.80" });
  });

  it("knows what a fetch of each seeded URL finds", () => {
    expect([...state.sources.keys()]).toEqual([LIST_URLS.ads, LIST_URLS.trackers]);
  });
});

describe("forwarding rules", () => {
  it("lists the rules with the root first and the rest by reversed labels", () => {
    createForwarder(state, ctx, ruleBody({ suffix: "." }));
    createForwarder(state, ctx, ruleBody({ suffix: "a.example.test" }));
    createForwarder(state, ctx, ruleBody({ suffix: "b.test" }));
    expect(listForwarders(state).map((r) => r.suffix)).toEqual([".", "b.test", "a.example.test", "corp.example.test"]);
  });

  it("creates a rule with the canonical suffix and a new revision", () => {
    const rule = createForwarder(state, ctx, ruleBody({ suffix: "Lab.Example.Test.", description: "  The lab  ", tls_name: "  " }));
    expect(rule).toMatchObject({ suffix: "lab.example.test", transport: "plain", tls_name: null, view: null, description: "The lab", revision: rev });
    expect(rule.id).toMatch(/^0190d1c2-/);
    expect(findForwarder(state, rule.id)).toBe(rule);
  });

  it("creates a DoT and a DoH rule with a port and a path", () => {
    const dot = createForwarder(
      state,
      ctx,
      ruleBody({ suffix: "dot.example.test", transport: "dot", tls_name: "dns.example.test", upstreams: [{ address: "2001:db8::53", port: 853 }] }),
    );
    expect(dot.upstreams).toEqual([{ address: "2001:db8::53", port: 853 }]);
    const doh = createForwarder(
      state,
      ctx,
      ruleBody({ suffix: "doh.example.test", transport: "doh", tls_name: "dns.example.test", upstreams: [{ address: "192.0.2.53", path: "/dns-query" }] }),
    );
    expect(doh.upstreams).toEqual([{ address: "192.0.2.53", path: "/dns-query" }]);
  });

  it("refuses a rule that breaks a rule, naming the field and the reason", () => {
    const refused = (body: Record<string, unknown>) => {
      const f = failure(() => createForwarder(state, ctx, body));
      expect(f.status).toBe(400);
      expect(f.code).toBe("dns.forwarder.invalid");
      return f.params;
    };
    expect(refused(ruleBody({ upstreams: [] }))).toEqual({ field: "upstreams", reason: "at least one upstream" });
    expect(refused({ suffix: "lab.example.test" })).toMatchObject({ field: "upstreams" });
    expect(refused(ruleBody({ upstreams: Array.from({ length: 17 }, (_, i) => ({ address: `192.0.2.${i + 1}` })) }))).toEqual({
      field: "upstreams",
      reason: "at most 16 upstreams",
    });
    expect(refused(ruleBody({ upstreams: [{ address: "ns.example.test" }] }))).toMatchObject({ field: "upstreams" });
    expect(refused(ruleBody({ upstreams: [{ address: "192.0.2.1", port: 0 }] }))).toMatchObject({ field: "upstreams" });
    expect(refused(ruleBody({ transport: "dot", upstreams: [{ address: "192.0.2.1" }] }))).toEqual({ field: "tls_name", reason: "DoT and DoH need tls_name" });
    expect(refused(ruleBody({ transport: "doh", upstreams: [{ address: "192.0.2.1" }] }))).toMatchObject({ field: "tls_name" });
    expect(refused(ruleBody({ upstreams: [{ address: "192.0.2.1", path: "/dns-query" }] }))).toEqual({ field: "upstreams", reason: "a path needs DoH" });
    expect(
      refused(ruleBody({ transport: "doh", tls_name: "dns.example.test", upstreams: [{ address: "192.0.2.1", path: "dns-query" }] })),
    ).toMatchObject({ field: "upstreams" });
    expect(refused(ruleBody({ transport: "quic" }))).toEqual({ field: "transport", reason: "unknown transport" });
    expect(refused(ruleBody({ suffix: "bad name.example.test" }))).toEqual({ field: "suffix", reason: "not a DNS name" });
    expect(refused(ruleBody({ suffix: "*.example.test" }))).toMatchObject({ field: "suffix" });
    expect(refused(ruleBody({ view: "internal" }))).toEqual({ field: "view", reason: "no such view" });
    expect(state.forwarders).toHaveLength(1);
  });

  it("refuses the same suffix twice", () => {
    const f = failure(() => createForwarder(state, ctx, ruleBody({ suffix: "CORP.example.test." })));
    expect(f.code).toBe("dns.forwarder.invalid");
    expect(f.params).toEqual({ field: "suffix", reason: "a rule for this suffix exists in this view" });
    expect(state.forwarders).toHaveLength(1);
  });

  it("updates the fields that are sent and keeps the others", () => {
    const before = findForwarder(state, CORP).revision;
    const next = updateForwarder(state, ctx, CORP, { description: "Moved", upstreams: [{ address: "192.0.2.20" }] }, before);
    expect(next).toMatchObject({ id: CORP, suffix: "corp.example.test", transport: "plain", description: "Moved", revision: rev });
    expect(next.upstreams).toEqual([{ address: "192.0.2.20" }]);
    expect(next.revision).toBeGreaterThan(before);
    expect(findForwarder(state, CORP)).toBe(next);
    expect(updateForwarder(state, ctx, CORP, { description: "" }, "*").description).toBeNull();
    expect(updateForwarder(state, ctx, CORP, { suffix: "Corp2.Example.Test." }, null).suffix).toBe("corp2.example.test");
  });

  it("checks an update the way a create is checked", () => {
    createForwarder(state, ctx, ruleBody());
    expect(failure(() => updateForwarder(state, ctx, CORP, { suffix: "lab.example.test" }, null)).params).toMatchObject({ field: "suffix" });
    expect(failure(() => updateForwarder(state, ctx, CORP, { transport: "dot" }, null)).params).toMatchObject({ field: "tls_name" });
    expect(failure(() => updateForwarder(state, ctx, CORP, { upstreams: [] }, null)).params).toMatchObject({ field: "upstreams" });
    expect(findForwarder(state, CORP).transport).toBe("plain");
  });

  it("answers all_views by clearing the view and refuses a view that does not exist", () => {
    // A rule bound to a view cannot be made through the service (no views exist); arrange one.
    findForwarder(state, CORP).view = "internal";
    expect(failure(() => updateForwarder(state, ctx, CORP, { view: "other" }, null)).params).toEqual({ field: "view", reason: "no such view" });
    expect(updateForwarder(state, ctx, CORP, { all_views: true }, null).view).toBeNull();
  });

  it("refuses a stale revision with 412 and a missing rule with 404", () => {
    const stale = failure(() => updateForwarder(state, ctx, CORP, { description: "x" }, findForwarder(state, CORP).revision + 1));
    expect(stale.status).toBe(412);
    expect(stale.code).toBe("sys.store.precondition_failed");
    expect(failure(() => deleteForwarder(state, CORP, 999)).status).toBe(412);
    expect(state.forwarders).toHaveLength(1);
    const missing = failure(() => updateForwarder(state, ctx, "nope", {}, null));
    expect(missing).toMatchObject({ status: 404, code: "dns.forwarder.not_found", params: { id: "nope" } });
    expect(failure(() => findForwarder(state, "nope")).status).toBe(404);
    expect(failure(() => deleteForwarder(state, "nope", null)).status).toBe(404);
  });

  it("deletes a rule with the right revision", () => {
    const gone = deleteForwarder(state, CORP, findForwarder(state, CORP).revision);
    expect(gone.id).toBe(CORP);
    expect(state.forwarders).toEqual([]);
  });
});

describe("block lists", () => {
  it("lists the lists by name", () => {
    createList(state, ctx, listBody({ name: "Zed" }));
    createList(state, ctx, listBody({ name: "Beta" }));
    expect(listLists(state).map((l) => l.name)).toEqual(["Ads", "Beta", "Local", "Zed"]);
  });

  it("creates a URL list with the default interval and no version", () => {
    const list = createList(state, ctx, listBody({ name: "  Trackers  ", description: " Tracking hosts " }));
    expect(list).toMatchObject({
      name: "Trackers",
      source: { kind: "url", url: LIST_URLS.trackers },
      format: "domains",
      action: { kind: "nxdomain" },
      enabled: true,
      interval_hours: 24,
      description: "Tracking hosts",
      last_error: null,
      version: null,
      revision: rev,
    });
    expect(findList(state, list.id)).toBe(list);
  });

  it("creates an uploaded list with the interval 0, disabled, with a redirect", () => {
    const list = createList(
      state,
      ctx,
      listBody({ name: "Mine", source: { kind: "upload" }, interval_hours: 12, enabled: false, format: "hosts", action: { kind: "redirect", address: "2001:db8::80" } }),
    );
    expect(list).toMatchObject({ source: { kind: "upload" }, interval_hours: 0, enabled: false, format: "hosts", action: { kind: "redirect", address: "2001:db8::80" } });
    expect(createList(state, ctx, listBody({ name: "Hours", interval_hours: 168 })).interval_hours).toBe(168);
  });

  it("refuses a list that breaks a rule, naming the field", () => {
    const refused = (body: Record<string, unknown>) => {
      const f = failure(() => createList(state, ctx, body));
      expect(f.status).toBe(400);
      expect(f.code).toBe("dns.list.invalid");
      return f.params.field;
    };
    expect(refused(listBody({ name: "" }))).toBe("name");
    expect(refused(listBody({ name: "x".repeat(65) }))).toBe("name");
    expect(refused(listBody({ name: "ads" }))).toBe("name");
    expect(refused(listBody({ source: { kind: "url", url: "ftp://lists.example.test/x" } }))).toBe("source");
    expect(refused(listBody({ source: { kind: "url" } }))).toBe("source");
    expect(refused(listBody({ source: { kind: "file" } }))).toBe("source");
    expect(refused({ ...listBody(), source: undefined })).toBe("source");
    expect(refused(listBody({ interval_hours: 0 }))).toBe("interval_hours");
    expect(refused(listBody({ interval_hours: 169 }))).toBe("interval_hours");
    expect(refused(listBody({ interval_hours: 1.5 }))).toBe("interval_hours");
    expect(refused(listBody({ interval_hours: "24" }))).toBe("interval_hours");
    expect(refused(listBody({ action: { kind: "redirect", address: "example.test" } }))).toBe("action");
    expect(refused(listBody({ action: { kind: "sinkhole" } }))).toBe("action");
    expect(refused(listBody({ format: "csv" }))).toBe("format");
    expect(state.lists).toHaveLength(2);
  });

  it("gives the reason with the field", () => {
    expect(failure(() => createList(state, ctx, listBody({ name: "Ads" }))).params).toEqual({ field: "name", reason: "a list of this name exists" });
  });

  it("updates the fields that are sent and bumps the revision", () => {
    const before = adsOf().revision;
    const next = updateList(state, ctx, ADS, { name: "Ads 2", enabled: false, interval_hours: 12, action: { kind: "nodata" }, description: " Ads and trackers " }, before);
    expect(next).toMatchObject({ id: ADS, name: "Ads 2", enabled: false, interval_hours: 12, action: { kind: "nodata" }, description: "Ads and trackers" });
    expect(next.revision).toBeGreaterThan(before);
    expect(next.source).toEqual({ kind: "url", url: LIST_URLS.ads });
    expect(next.version?.entries).toBe(4);
    expect(updateList(state, ctx, ADS, { description: "" }, "*").description).toBeNull();
    expect(updateList(state, ctx, ADS, { source: { kind: "url", url: LIST_URLS.trackers } }, null).source).toEqual({ kind: "url", url: LIST_URLS.trackers });
    expect(updateList(state, ctx, LOCAL, { interval_hours: 12 }, null).interval_hours).toBe(0);
  });

  it("lets a list keep its own name and refuses one that another list has", () => {
    expect(updateList(state, ctx, ADS, { name: "ADS" }, null).name).toBe("ADS");
    expect(failure(() => updateList(state, ctx, ADS, { name: "local" }, null)).params.field).toBe("name");
  });

  it("refuses to change the kind of the source", () => {
    for (const [id, source] of [
      [ADS, { kind: "upload" }],
      [LOCAL, { kind: "url", url: LIST_URLS.ads }],
    ] as const) {
      const f = failure(() => updateList(state, ctx, id, { source }, null));
      expect(f).toMatchObject({ status: 400, code: "dns.list.invalid", params: { field: "source" } });
    }
    expect(adsOf().source.kind).toBe("url");
    expect(localOf().source.kind).toBe("upload");
  });

  it("checks an update the way a create is checked", () => {
    expect(failure(() => updateList(state, ctx, ADS, { interval_hours: 500 }, null)).params.field).toBe("interval_hours");
    expect(failure(() => updateList(state, ctx, ADS, { action: { kind: "redirect", address: "x" } }, null)).params.field).toBe("action");
    expect(failure(() => updateList(state, ctx, ADS, { source: { kind: "url", url: "nope" } }, null)).params.field).toBe("source");
    expect(failure(() => updateList(state, ctx, ADS, { format: "csv" }, null)).params.field).toBe("format");
    expect(adsOf().interval_hours).toBe(24);
  });

  it("refuses a stale revision with 412 and a missing list with 404", () => {
    const stale = failure(() => updateList(state, ctx, ADS, { enabled: false }, adsOf().revision + 1));
    expect(stale).toMatchObject({ status: 412, code: "sys.store.precondition_failed" });
    expect(failure(() => deleteList(state, ADS, 999)).status).toBe(412);
    expect(state.lists).toHaveLength(2);
    expect(failure(() => updateList(state, ctx, "nope", {}, null))).toMatchObject({ status: 404, code: "dns.list.not_found", params: { id: "nope" } });
    expect(failure(() => deleteList(state, "nope", null)).status).toBe(404);
    expect(failure(() => findList(state, "nope")).status).toBe(404);
  });

  it("deletes a list with the right revision", () => {
    expect(deleteList(state, LOCAL, localOf().revision).name).toBe("Local");
    expect(state.lists.map((l) => l.name)).toEqual(["Ads"]);
  });
});

describe("compileNames", () => {
  it("reads the first word of each line of a domains file, without comments", () => {
    const text = ["# a header", "ads.example.test", "  Track.Example.Test.  # a comment", "", "ads.example.test", "x.example.test and more words", "localhost", "bad!name.test", ""].join("\r\n");
    expect(compileNames(text, "domains")).toEqual(["ads.example.test", "track.example.test", "x.example.test"]);
  });

  it("reads every name after the address of a hosts line", () => {
    const text = ["# hosts", "127.0.0.1 localhost", "0.0.0.0 a.example.test b.example.test", "192.0.2.1\tA.example.test # again", "0.0.0.0", "0.0.0.0 c.example.test"].join("\n");
    expect(compileNames(text, "hosts")).toEqual(["a.example.test", "b.example.test", "c.example.test"]);
  });

  it("treats the same text differently by format", () => {
    expect(compileNames("a.example.test", "hosts")).toEqual([]);
    expect(compileNames("", "domains")).toEqual([]);
  });
});

describe("fetchList", () => {
  it("compiles the file of the URL into a new version with the entries and an ETag", () => {
    const text = state.sources.get(LIST_URLS.ads) as string;
    const list = fetchList(state, ctx, ADS);
    expect(list.version).toEqual({ revision: 4, entries: 5, fetched: new Date(NOW).toISOString(), etag: `"${text.length.toString(16)}"` });
    expect(list.last_error).toBeNull();
    expect(list.revision).toBe(rev);
    expect(adsOf()).toBe(list);
  });

  it("numbers the first version of a new list 1", () => {
    const list = createList(state, ctx, listBody());
    const fetched = fetchList(state, ctx, list.id);
    expect(fetched.version).toMatchObject({ revision: 1, entries: 2 });
  });

  it("sets last_error for a URL the mock cannot reach and keeps the version", () => {
    updateList(state, ctx, ADS, { source: { kind: "url", url: "https://nowhere.example.test/x.txt" } }, null);
    const before = adsOf().version;
    const list = fetchList(state, ctx, ADS);
    expect(list.last_error).toBe("dns.list.fetch_failed");
    expect(list.version).toEqual(before);
  });

  it("clears the last error after a good fetch", () => {
    adsOf().last_error = "dns.list.fetch_failed";
    expect(fetchList(state, ctx, ADS).last_error).toBeNull();
  });

  it("answers 409 for an uploaded list and 404 for a missing one", () => {
    expect(failure(() => fetchList(state, ctx, LOCAL))).toMatchObject({ status: 409, code: "dns.list.invalid", params: { field: "source" } });
    expect(failure(() => fetchList(state, ctx, "nope")).status).toBe(404);
  });
});

describe("uploadList", () => {
  const FILE = "# mine\n0.0.0.0 a.example.test b.example.test\n127.0.0.1 localhost\n0.0.0.0 c.example.test\n";

  it("compiles the text into the next version without an ETag", () => {
    const list = uploadList(state, ctx, LOCAL, FILE, localOf().revision);
    expect(list.version).toEqual({ revision: 1, entries: 3, fetched: new Date(NOW).toISOString(), etag: null });
    expect(list.revision).toBe(rev);
    const again = uploadList(state, ctx, LOCAL, "0.0.0.0 d.example.test\n", "*");
    expect(again.version).toMatchObject({ revision: 2, entries: 1 });
  });

  it("answers 409 for a URL list, 412 for a stale If-Match and 404 for a missing list", () => {
    expect(failure(() => uploadList(state, ctx, ADS, FILE, null))).toMatchObject({ status: 409, code: "dns.list.invalid", params: { field: "source" } });
    expect(failure(() => uploadList(state, ctx, LOCAL, FILE, localOf().revision + 1))).toMatchObject({ status: 412, code: "sys.store.precondition_failed" });
    expect(failure(() => uploadList(state, ctx, "nope", FILE, null)).status).toBe(404);
    expect(localOf().version).toBeNull();
  });
});

describe("resolverStatus", () => {
  it("gives the cache figures and the hit ratio", () => {
    const status = resolverStatus(state);
    expect(status).toMatchObject({ cache_entries: 1_234, cache_bytes: 2_097_152, cache_hits: 8_400, cache_misses: 1_600, cache_stale: 12, problems: [] });
    expect(status.cache_hit_ratio).toBeCloseTo(0.84, 10);
  });

  it("leaves the ratio out before any query was asked and copies the problems", () => {
    state.cache.hits = 0;
    state.cache.misses = 0;
    state.problems = ["dns.resolver.upstream_down"];
    const status = resolverStatus(state);
    expect(status).not.toHaveProperty("cache_hit_ratio");
    expect(status.problems).toEqual(["dns.resolver.upstream_down"]);
    expect(status.problems).not.toBe(state.problems);
  });
});
