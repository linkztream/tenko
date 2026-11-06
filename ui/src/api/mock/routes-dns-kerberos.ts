// The Kerberos account of the mock API (`/api/v1/dns/kerberos`, scope `dns.keys`, identity plan
// section 3.18; the server's routes are crates/tenko-api/src/routes/dns/kerberos.rs). A small
// stand-in for a directory: the adopt takes the realm `CORP.EXAMPLE.TEST`, refuses the one-time
// password `wrong` with `dns.krb.password.refused`, answers `dns.krb.kdc.unreachable` when a KDC
// listed is `192.0.2.1`, and makes the account Tenko's at key version 2; the import takes a
// keytab whose first two octets are 0x05 0x02 and keeps versions 2 and 3. An SPN whose host
// starts with `missing` is reported by the self-test as `dns.gss.spn_missing`. Never a key or a
// password in an answer, as on the server. The one-time password is not kept.
import type { HttpHandler } from "msw";
import type { components } from "../generated/schema";
import { requireAdmin } from "./auth";
import { onMockReset } from "./db";
import { created, noContent, ok, Problem, Reply } from "./reply";
import { route } from "./route";
import { isRecord } from "./validate";

type S = components["schemas"];
type Account = S["KerberosAccountItem"];
type Finding = S["KerberosFinding"];

interface State {
  account: Account | null;
  findings: Finding[];
}

const state: State = { account: null, findings: [] };

onMockReset(() => {
  state.account = null;
  state.findings = [];
});

/** Sets the account and its findings directly (the tests of the status page). */
export function setMockKerberos(account: Account | null, findings: Finding[] = []): void {
  state.account = account;
  state.findings = findings;
}

function status(): S["KerberosStatus"] {
  return { account: state.account, findings: state.findings };
}

function problem(code: string, status: number, detail: string, params: Record<string, string> = {}): never {
  throw new Problem(code, { status, detail, params });
}

function strings(value: unknown, field: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    return problem("sys.invalid_request", 400, `${field} must be a list of strings`);
  }
  return value.map((v) => v.trim()).filter((v) => v !== "");
}

function common(body: Record<string, unknown>): {
  realm: string;
  spns: string[];
  kdcs: string[];
} {
  const realm = typeof body.realm === "string" ? body.realm.trim().toUpperCase() : "";
  if (!/^[A-Z0-9.-]+$/.test(realm)) return problem("sys.invalid_request", 400, "realm: not a realm");
  const spns = strings(body.spns, "spns");
  if (spns.length === 0 || !spns.every((s) => /^[A-Za-z]+\/[A-Za-z0-9.-]+$/.test(s))) {
    return problem("dns.krb.account.invalid", 400, "spns: a service principal name is `service/host`", {
      field: "spns",
      reason: "a service principal name is `service/host`",
    });
  }
  return { realm, spns, kdcs: strings(body.kdcs, "kdcs") };
}

function exists(realm: string): void {
  if (state.account) {
    problem("dns.krb.account.exists", 409, "a Kerberos account is set up already: delete it before adopting or importing another", {
      realm,
    });
  }
}

const now = () => new Date().toISOString();
const etypes: S["EncryptionType"][] = ["aes128-cts-hmac-sha1", "aes256-cts-hmac-sha1"];

function selfTest(account: Account): Finding[] {
  return account.spns
    .filter((spn) => /^[^/]+\/missing/.test(spn))
    .map((spn) => ({
      code: "dns.gss.spn_missing",
      detail: `the KDC knows no account with the SPN ${spn}`,
      params: { spn, kdc_error: "7" },
      at: now(),
    }));
}

function settle(account: Account): void {
  account.last_check = now();
  state.account = account;
  state.findings = selfTest(account);
}

const getStatus = route("get", "/api/v1/dns/kerberos", () => {
  requireAdmin();
  return ok(status());
});

const adopt = route("post", "/api/v1/dns/kerberos/adopt", async (ctx) => {
  requireAdmin();
  const body = await ctx.body();
  if (!isRecord(body)) return problem("sys.invalid_request", 400, "the body is an object");
  const { realm, spns, kdcs } = common(body);
  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (!name.endsWith("$"))
    return problem("dns.krb.account.invalid", 400, "name: a computer account's name ends in `$`", {
      field: "name",
      reason: "a computer account's name ends in `$`",
    });
  if (typeof body.password !== "string" || body.password === "") return problem("sys.invalid_request", 400, "password: missing");
  exists(realm);
  if (kdcs.includes("192.0.2.1"))
    return problem("dns.krb.kdc.unreachable", 503, `no KDC of ${realm} answered`, { realm, reason: "timeout" });
  if (realm !== "CORP.EXAMPLE.TEST" || body.password === "wrong") {
    return problem("dns.krb.password.refused", 422, `the KDC of ${realm} refused: error 24 (Preauthentication failed)`, {
      realm,
      reason: "error 24",
    });
  }
  const days = typeof body.rotation_days === "number" ? body.rotation_days : 30;
  const at = now();
  settle({
    realm,
    name,
    principal: `${name}@${realm}`,
    spns,
    kdcs,
    owned: true,
    rotation_days: days,
    versions: [{ kvno: 2, etypes, state: "current", created: at }],
    last_rotation: at,
    next_rotation: new Date(Date.now() + days * 86_400_000).toISOString(),
  });
  return created(status());
});

const importKeytab = route("post", "/api/v1/dns/kerberos/import", async (ctx) => {
  requireAdmin();
  const body = await ctx.body();
  if (!isRecord(body)) return problem("sys.invalid_request", 400, "the body is an object");
  const { realm, spns, kdcs } = common(body);
  const keytab = typeof body.keytab === "string" ? body.keytab : "";
  let head: string;
  try {
    head = atob(keytab.replace(/-/g, "+").replace(/_/g, "/").slice(0, 4));
  } catch {
    head = "";
  }
  if (head.charCodeAt(0) !== 5 || head.charCodeAt(1) !== 2) {
    return problem("dns.krb.keytab.invalid", 422, "keytab at offset 0: not a keytab: the file does not start with 0x0502", {
      reason: "not a keytab",
    });
  }
  exists(realm);
  const name = typeof body.name === "string" && body.name.trim() !== "" ? body.name.trim() : "TENKO-DNS$";
  const at = now();
  settle({
    realm,
    name,
    principal: `${name}@${realm}`,
    spns,
    kdcs,
    owned: false,
    rotation_days: 0,
    versions: [
      { kvno: 2, etypes, state: "previous", created: at },
      { kvno: 3, etypes, state: "current", created: at },
    ],
  });
  return created(status());
});

function account(): Account {
  requireAdmin();
  if (!state.account) return problem("dns.krb.account.not_found", 404, "no Kerberos account is set up");
  return state.account;
}

const check = route("post", "/api/v1/dns/kerberos/check", () => {
  settle(account());
  return ok(status());
});

const rotate = route("post", "/api/v1/dns/kerberos/rotate", () => {
  const current = account();
  if (!current.owned) {
    return problem("dns.krb.account.not_owned", 409, "the account was imported from a keytab: Tenko does not rotate it", {
      realm: current.realm,
    });
  }
  const top = Math.max(...current.versions.map((v) => v.kvno));
  const at = now();
  current.versions = [
    ...current.versions.filter((v) => v.state === "current").map((v) => ({ ...v, state: "previous" as const })),
    { kvno: top + 1, etypes, state: "current", created: at },
  ];
  current.last_rotation = at;
  return new Reply(202, { job_id: "0190d1c2-0000-7000-8000-000000000101" });
});

const remove = route("delete", "/api/v1/dns/kerberos", () => {
  account();
  state.account = null;
  state.findings = [];
  return noContent();
});

export const dnsKerberosRoutes: HttpHandler[] = [getStatus, adopt, importKeytab, check, rotate, remove];
