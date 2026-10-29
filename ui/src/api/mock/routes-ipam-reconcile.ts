// The reconciliation view of the mock API (GET /api/v1/ipam/reconcile, WP8.2): the four truths per
// address and the finding, seeded rather than derived. The rows use the IPAM seed (192.0.2.0/24,
// hosts such as ap-garage and laptop-ak, MAC addresses 00:00:5e:00:53:xx, names under
// example.test) and cover every kind and every rule. The answer filters by `kind`, `prefix` and
// `host` and pages with `limit` and `cursor`; with `host` it carries the truths of the host,
// among them the OS field of its DHCP fingerprint.
//
// Simplifications: the rows do not follow the IPAM writes of a scenario, and a prefix filter
// matches the prefix a row names, not the prefixes inside it. The rows themselves are in
// ipam-reconcile-model.ts, which the end-to-end tests use too.
import type { HttpHandler } from "msw";
import { requireSession } from "./auth";
import { db } from "./db";
import { filterRows, hostTruths, KINDS } from "./ipam-reconcile-model";
import { ipamState } from "./ipam/api";
import { notFound } from "./ipam/problems";
import { mockViewRows } from "./reconcile-view";
import { Problem, ok } from "./reply";
import { paginate, route } from "./route";
import { isUuid } from "./util";

const KIND_PARAMS = new Set<string>(KINDS);

function invalidQuery(name: string, detail: string): Problem {
  return new Problem("sys.invalid_query", { status: 400, detail: `query parameter \`${name}\`: ${detail}`, params: { parameter: name } });
}

const reconcileView = route("get", "/api/v1/ipam/reconcile", (ctx) => {
  requireSession();
  const url = ctx.url;
  for (const name of url.searchParams.keys()) {
    if (!["kind", "prefix", "host", "limit", "cursor", "at_least"].includes(name)) throw invalidQuery(name, "unknown parameter");
  }
  const kind = url.searchParams.get("kind");
  if (kind !== null && !KIND_PARAMS.has(kind)) throw invalidQuery("kind", `\`${kind}\` is not one of ${KINDS.join(", ")}`);
  const prefix = url.searchParams.get("prefix");
  if (prefix !== null && !isUuid(prefix)) throw invalidQuery("prefix", "is not a prefix identifier");
  const host = url.searchParams.get("host");
  if (host !== null && !isUuid(host)) throw invalidQuery("host", "is not a host identifier");

  const data = ipamState().data;
  const rows = mockViewRows();
  const page = paginate(filterRows(rows, { kind, prefix, host }), url, db.revision);
  const found = host === null ? undefined : data.host.get(host);
  if (host === null) return ok(page);
  if (!found) {
    throw notFound("host", host);
  }
  const interfaces = [...data.interface.values()].filter((i) => i.host === host && !i.meta.deleted);
  const ids = new Set(interfaces.map((i) => i.id));
  const macs = interfaces.flatMap((i) => (i.mac ? [i.mac] : []));
  const ips = [...data.address.values()].filter((a) => a.interface && ids.has(a.interface) && !a.meta.deleted).map((a) => a.ip);
  return ok({ ...page, host: hostTruths({ id: found.id, name: found.name, mode: found.mode }, macs, ips) });
});

export const ipamReconcileRoutes: HttpHandler[] = [reconcileView];
