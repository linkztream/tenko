// Mock routes of the guardrails (WP3.12a; docs/connectors-unifi.md, section 6): one settings record
// with a revision that answers as `ETag`, `PUT` with `If-Match` (a stale revision is 409
// `sys.store.precondition_failed`) and the limits of the server (422 `connect.guardrails.invalid`
// with the field): `max_parallel` 1 to 64, at most 256 paths, VLAN ids 1 to 4094, references of 1 to
// 128 characters and no duplicates. Administrators only.
import type { components } from "../generated/schema";
import { requireAdmin } from "./auth";
import { commit, db, onMockReset } from "./db";
import { ok, Problem } from "./reply";
import { route } from "./route";

type Guardrails = components["schemas"]["Guardrails"];
type ProtectedPath = components["schemas"]["ProtectedPath"];

interface GuardrailsState {
  guardrails: Guardrails;
  revision: number | null;
}

function fresh(): GuardrailsState {
  return { guardrails: { max_parallel: 10, protected: [] }, revision: db.revision };
}

/** The state of the mock; tests change it. */
export const guardrailsState: GuardrailsState = fresh();

onMockReset(() => {
  Object.assign(guardrailsState, fresh());
});

const MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

function etag(revision: number | null): Record<string, string> {
  return revision === null ? {} : { ETag: `"${revision}"` };
}

function invalid(field: string, detail: string): never {
  throw new Problem("connect.guardrails.invalid", { status: 422, detail, params: { field } });
}

function reference(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 128) invalid(field, "a reference has 1 to 128 characters");
  return value;
}

function key(path: ProtectedPath): string {
  switch (path.type) {
    case "port":
      return `port:${path.device}/${path.port}`;
    case "network":
      return `network:${path.network}`;
    case "vlan":
      return `vlan:${path.vid}`;
    case "client":
      return `client:${path.mac}`;
  }
}

function pathOf(raw: unknown, field: string): ProtectedPath {
  const input = (raw ?? {}) as Record<string, unknown>;
  switch (input["type"]) {
    case "port": {
      const port = input["port"];
      if (typeof port !== "number" || !Number.isInteger(port) || port < 0) invalid(`${field}.port`, "a port is a whole number");
      return { type: "port", device: reference(input["device"], `${field}.device`), port };
    }
    case "network":
      return { type: "network", network: reference(input["network"], `${field}.network`) };
    case "vlan": {
      const vid = input["vid"];
      if (typeof vid !== "number" || !Number.isInteger(vid) || vid < 1 || vid > 4094) invalid(`${field}.vid`, "a VLAN id is 1 to 4094");
      return { type: "vlan", vid };
    }
    case "client": {
      const mac = input["mac"];
      if (typeof mac !== "string" || !MAC.test(mac)) invalid(`${field}.mac`, "a MAC is six pairs, lowercase and colon-separated");
      return { type: "client", mac };
    }
    default:
      throw new Problem("sys.invalid_request", { detail: `${field}.type is not known` });
  }
}

export const guardrailsRoutes = [
  route("get", "/api/v1/settings/guardrails", () => {
    requireAdmin();
    return ok({ ...guardrailsState.guardrails, protected: [...guardrailsState.guardrails.protected] }, etag(guardrailsState.revision));
  }),

  route("put", "/api/v1/settings/guardrails", async (ctx) => {
    requireAdmin();
    const expected = ctx.ifMatch();
    const input = (await ctx.body()) as Record<string, unknown>;
    if (expected !== null && expected !== "*" && expected !== guardrailsState.revision) {
      throw new Problem("sys.store.precondition_failed", { status: 409 });
    }
    const parallel = input["max_parallel"];
    if (typeof parallel !== "number" || !Number.isInteger(parallel)) {
      throw new Problem("sys.invalid_request", { detail: "max_parallel must be a whole number" });
    }
    if (parallel < 1 || parallel > 64) invalid("max_parallel", "max_parallel must be 1 to 64");
    const list = input["protected"];
    if (!Array.isArray(list)) throw new Problem("sys.invalid_request", { detail: "protected must be a list" });
    if (list.length > 256) invalid("protected", "at most 256 paths");
    const paths = list.map((raw, index) => pathOf(raw, `protected[${index}]`));
    const seen = new Set<string>();
    paths.forEach((path, index) => {
      if (seen.has(key(path))) invalid(`protected[${index}]`, "a path is listed twice");
      seen.add(key(path));
    });
    commit("system", { tables: ["connect.guardrails"] });
    guardrailsState.guardrails = { max_parallel: parallel, protected: paths };
    guardrailsState.revision = db.revision;
    return ok({ ...guardrailsState.guardrails }, etag(db.revision));
  }),
];
