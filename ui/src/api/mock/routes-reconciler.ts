// Mock routes of the reconciler settings (WP3.12a, docs/reconciliation.md, section 3.1.1): one
// settings record with a revision that answers as `ETag`, `PUT` with `If-Match` (a stale
// revision is 409 `sys.store.precondition_failed`) and the limits of the server (422
// `ipam.reconciler.settings.invalid` with the field). Administrators only.
import type { components } from "../generated/schema";
import { requireAdmin } from "./auth";
import { commit, db, onMockReset } from "./db";
import { ok, Problem } from "./reply";
import { route } from "./route";

type Settings = components["schemas"]["ReconcilerSettings"];

const DAY = 86_400;
const YEAR = 365 * DAY;

/** The limits in seconds, as the server enforces them. */
const LIMITS: readonly { key: Exclude<keyof Settings, "adopt" | "dns_actuator" | "dns_orphans">; min: number; max: number }[] = [
  { key: "interval_secs", min: 30, max: DAY },
  { key: "debounce_secs", min: 0, max: 300 },
  { key: "orphan_after_secs", min: 3_600, max: YEAR },
  { key: "retention_secs", min: DAY, max: YEAR },
  { key: "refresh_secs", min: 60, max: DAY },
  { key: "purge_interval_secs", min: 300, max: DAY },
];

interface ReconcilerState {
  settings: Settings;
  revision: number | null;
}

function fresh(): ReconcilerState {
  return {
    settings: {
      adopt: true,
      dns_actuator: true,
      dns_orphans: "remove",
      debounce_secs: 2,
      interval_secs: 300,
      orphan_after_secs: 604_800,
      purge_interval_secs: 3_600,
      refresh_secs: 900,
      retention_secs: 2_592_000,
    },
    revision: db.revision,
  };
}

/** The state of the mock; tests change it. */
export const reconcilerState: ReconcilerState = fresh();

onMockReset(() => {
  Object.assign(reconcilerState, fresh());
});

function etag(revision: number | null): Record<string, string> {
  return revision === null ? {} : { ETag: `"${revision}"` };
}

function invalid(field: string, detail: string): never {
  throw new Problem("ipam.reconciler.settings.invalid", { status: 422, detail, params: { field } });
}

export const reconcilerRoutes = [
  route("get", "/api/v1/settings/reconciler", () => {
    requireAdmin();
    return ok({ ...reconcilerState.settings }, etag(reconcilerState.revision));
  }),

  route("put", "/api/v1/settings/reconciler", async (ctx) => {
    requireAdmin();
    const expected = ctx.ifMatch();
    const input = (await ctx.body()) as Record<string, unknown>;
    if (expected !== null && expected !== "*" && expected !== reconcilerState.revision) {
      throw new Problem("sys.store.precondition_failed", { status: 409 });
    }
    if (typeof input["adopt"] !== "boolean") throw new Problem("sys.invalid_request", { detail: "adopt must be true or false" });
    const next: Settings = { ...reconcilerState.settings, adopt: input["adopt"] };
    for (const { key, min, max } of LIMITS) {
      const value = input[key];
      if (typeof value !== "number" || !Number.isInteger(value)) {
        throw new Problem("sys.invalid_request", { detail: `${key} must be a whole number` });
      }
      if (value < min || value > max) invalid(key, `${key} must be ${min} to ${max}`);
      next[key] = value;
    }
    if (next.refresh_secs >= next.retention_secs) invalid("refresh_secs", "refresh_secs must be shorter than retention_secs");
    commit("system", { tables: ["ipam.reconciler_settings"] });
    reconcilerState.settings = next;
    reconcilerState.revision = db.revision;
    return ok({ ...next }, etag(db.revision));
  }),
];
