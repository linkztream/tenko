// Integration certificates of the mock API (ADR 0035): the certificate records with
// revocation of a lineage, and the enrollment codes (created once with their text, listed
// without it, withdrawn). The public enrollment, the renewal and the root answer 501 from the
// stubs: they need the integration listener and a real certificate authority.
//
// Seed: the service account "dns-sync" holds one active lineage, the host "dns-sync-host".
// Simplifications: no enrollment changes the records; a code expires by its own time only.
import type { HttpHandler } from "msw";
import type { components } from "../generated/schema";
import { ACCESS_IDS, removeBoundTokens } from "./access-store";
import { appendAudit } from "./audit-store";
import { requireAdmin } from "./auth";
import { db, onMockReset, recordEvent } from "./db";
import { MOCK_CA_FINGERPRINT } from "./fixtures";
import { Problem, created, noContent, ok } from "./reply";
import { route } from "./route";
import { iso, isUuid, randomHex, randomId } from "./util";

type S = components["schemas"];
type CertRecord = S["ClientCertRecord"];
type CodeView = S["EnrollmentCodeView"];

const DAY = 86_400_000;

interface State {
  certs: Map<string, CertRecord>;
  codes: Map<string, CodeView>;
}

let state: State | null = null;
onMockReset(() => {
  state = null;
});

/** A current certificate of `account` for the host `label`, issued `ageDays` ago for 30 days. */
export function mockCertificate(account: string, label: string, ageDays: number): CertRecord {
  const issued = Date.now() - ageDays * DAY;
  return {
    serial: randomHex(16),
    account,
    generation: 0,
    lineage: randomId(),
    label,
    key_sha256: randomHex(32),
    not_before: iso(issued - 3_600_000),
    not_after: iso(issued + 30 * DAY),
    issued_at: iso(issued),
    state: "current",
  };
}

/** The records and codes, built from the seed on first use after a reset. */
export function integrationsState(): State {
  if (!state) {
    const seed = db.scenario === "setup" ? [] : [mockCertificate(ACCESS_IDS.serviceAccount, "dns-sync-host", 5)];
    state = { certs: new Map(seed.map((c) => [c.serial, c])), codes: new Map() };
  }
  return state;
}

/** Whether `lineage` of `account` has a certificate in use or waiting to be (a token may bind to it). */
export function activeLineage(account: string, lineage: string): boolean {
  const now = Date.now();
  return [...integrationsState().certs.values()].some(
    (c) => c.account === account && c.lineage === lineage && (c.state === "current" || c.state === "pending") && Date.parse(c.not_after) > now,
  );
}

/** Records a change of the `auth` tables the integration routes write. */
function changed(tables: string[]): void {
  recordEvent("admin", { tables });
}

const listCertificates = route("get", "/api/v1/integrations/certificates", (ctx) => {
  requireAdmin();
  const account = ctx.url.searchParams.get("account");
  const items = [...integrationsState().certs.values()].filter((c) => !account || c.account === account);
  return ok({ items: items.sort((a, b) => a.serial.localeCompare(b.serial)) });
});

const revokeCertificate = route("delete", "/api/v1/integrations/certificates/{serial}", (ctx) => {
  requireAdmin();
  const st = integrationsState();
  const target = st.certs.get(ctx.params.serial);
  if (!target) throw new Problem("integration.not_found", { status: 404, detail: "no such certificate", params: { kind: "certificate" } });
  const now = iso(Date.now());
  for (const cert of st.certs.values()) {
    if (cert.lineage === target.lineage && cert.state !== "revoked" && cert.state !== "withdrawn") {
      Object.assign(cert, { state: "revoked", ended_at: now, reason: "revoked by an administrator" });
    }
  }
  const tokens = removeBoundTokens(target.lineage);
  changed(["auth.client_certs", "auth.scoped_tokens"]);
  appendAudit({
    action: "auth.client_cert.revoke",
    objects: [{ kind: "user", id: target.account }],
    context: { lineage: target.lineage, reason: "revoked by an administrator", tokens: String(tokens) },
  });
  return noContent();
});

const listCodes = route("get", "/api/v1/integrations/enrollments", () => {
  requireAdmin();
  const now = Date.now();
  const items = [...integrationsState().codes.values()]
    .map((code) => ({ ...code, expired: code.state.state === "pending" && Date.parse(code.expires_at) <= now }))
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
  return ok({ items });
});

const createCode = route("post", "/api/v1/integrations/enrollments", async (ctx) => {
  const { user } = requireAdmin();
  const body = await ctx.body();
  const account = typeof body.account === "string" ? body.account : "";
  const holder = db.users.find((u) => u.id === account);
  if (!isUuid(account) || !holder || holder.disabled) {
    throw new Problem("integration.account", { status: 403, detail: "the account cannot hold integration certificates" });
  }
  const lifetime = body.lifetime_secs ?? 3600;
  if (typeof lifetime !== "number" || lifetime < 60 || lifetime > 3600) {
    throw new Problem("integration.code.lifetime", { status: 422, detail: "an enrollment code lives 60 to 3600 seconds" });
  }
  const now = Date.now();
  const view: CodeView = {
    id: randomId(),
    account,
    created_by: user.id,
    created_at: iso(now),
    expires_at: iso(now + lifetime * 1000),
    source: typeof body.source === "string" ? body.source : null,
    state: { state: "pending" },
    expired: false,
  };
  integrationsState().codes.set(view.id, view);
  changed(["auth.integration_codes"]);
  appendAudit({ action: "auth.client_cert.code_create", objects: [{ kind: "user", id: account }], context: { code: view.id } });
  return created(
    {
      enrollment: view,
      code: `tnki.${view.id}.${account}.${randomHex(32)}.${MOCK_CA_FINGERPRINT}`,
      server_root_sha256: MOCK_CA_FINGERPRINT,
      listen: ["0.0.0.0:8445"],
    },
    { "Cache-Control": "no-store" },
  );
});

const withdrawCode = route("delete", "/api/v1/integrations/enrollments/{id}", (ctx) => {
  requireAdmin();
  const code = integrationsState().codes.get(ctx.params.id);
  if (!code) throw new Problem("integration.not_found", { status: 404, detail: "no such enrollment code", params: { kind: "enrollment code" } });
  if (code.state.state === "pending") code.state = { state: "withdrawn" };
  changed(["auth.integration_codes"]);
  appendAudit({ action: "auth.client_cert.code_withdraw", objects: [{ kind: "user", id: code.account }], context: { code: code.id } });
  return noContent();
});

export const integrationsRoutes: HttpHandler[] = [listCertificates, revokeCertificate, listCodes, createCode, withdrawCode];
