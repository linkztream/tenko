// The resolution of a view in the mock (WP10.4): `resolution` on create and patch,
// `default_resolution` clearing it, and `profile_resolution` on every item. Pure model code.
import { beforeEach, describe, expect, it } from "vitest";
import { DnsFailure, seedDns, type DnsContext, type DnsState } from "./dns-model";
import { createView, findView, listViews, seedViews, updateView, VIEW_IDS, type ViewsState } from "./dns-views-model";

const NOW = Date.UTC(2026, 9, 17, 12);

let rev = 0;
let ids = 0;
let ctx: DnsContext;
let dns: DnsState;
let views: ViewsState;

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
  dns = seedDns(ctx);
  views = seedViews(ctx, dns);
});

function failure(fn: () => unknown): DnsFailure {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(DnsFailure);
    return error as DnsFailure;
  }
  throw new Error("expected a DnsFailure");
}

const body = (over: Record<string, unknown> = {}) => ({ name: "guests", order: 3, ...over });

describe("the resolution of a view", () => {
  it("is absent in the seed and every item carries the profile's default", () => {
    for (const view of listViews(views)) {
      expect(view.resolution ?? null).toBeNull();
      expect(view.profile_resolution).toBe("recurse");
    }
  });

  it("is set on create, and a view without one follows the profile", () => {
    expect(createView(views, ctx, dns, body({ resolution: "refuse" }))).toMatchObject({ resolution: "refuse", profile_resolution: "recurse" });
    const plain = createView(views, ctx, dns, body({ name: "plain", order: 4 }));
    expect(plain.resolution ?? null).toBeNull();
    expect(plain.profile_resolution).toBe("recurse");
  });

  it("is set and changed on patch, and kept by a patch that leaves it out", () => {
    const office = VIEW_IDS.office;
    expect(updateView(views, ctx, dns, office, { resolution: "forward" }, null).resolution).toBe("forward");
    expect(updateView(views, ctx, dns, office, { description: "Offices" }, null).resolution).toBe("forward");
    expect(updateView(views, ctx, dns, office, { resolution: "recurse" }, null)).toMatchObject({ resolution: "recurse", profile_resolution: "recurse" });
  });

  it("is cleared by default_resolution", () => {
    const office = VIEW_IDS.office;
    updateView(views, ctx, dns, office, { resolution: "refuse" }, null);
    const cleared = updateView(views, ctx, dns, office, { default_resolution: true }, null);
    expect(cleared.resolution ?? null).toBeNull();
    expect(cleared.profile_resolution).toBe("recurse");
    expect(findView(views, office).resolution ?? null).toBeNull();
  });

  it("refuses a resolution that is not recurse, forward or refuse", () => {
    const f = failure(() => createView(views, ctx, dns, body({ resolution: "iterate" })));
    expect(f).toMatchObject({ status: 400, code: "dns.view.invalid" });
    expect(f.params).toMatchObject({ field: "resolution" });
    expect(failure(() => updateView(views, ctx, dns, VIEW_IDS.tls, { resolution: "nope" }, null)).params).toMatchObject({ field: "resolution" });
    expect(listViews(views)).toHaveLength(2);
  });
});
