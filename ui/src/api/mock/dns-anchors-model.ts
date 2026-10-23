// The trust anchors and the negative trust anchors of the mock's recursive resolver (WP10.4):
// what `GET /dns/trust-anchors` lists (the root with its shipped keys and what RFC 5011 made of
// them, the anchors an operator added for private zones), the add of a key as a DS or a DNSKEY in
// presentation form, the protection of the root outside the Lab profile, the removal, the
// refresh, and the negative trust anchors (RFC 7646) with their bounds (at most seven days, the
// root never, an expiry required under Hardened) and their expiry. Pure code without msw and
// without the mock database, so the browser fakes of the end-to-end tests run the same code; the
// caller passes the clock, the revision, new ids and the profile. Failures are `RecursionFailure`
// with the codes of the server's `dns.trust_anchor.*` and `dns.nta.*`. Documentation values
// only.
import type { components } from "../generated/schema";
import type { Profile } from "../types";
import { canonical, validName } from "../../dns/model";
import { RecursionFailure } from "./dns-recursion-model";

type S = components["schemas"];
export type TrustAnchorItem = S["TrustAnchorItem"];
export type AnchorKey = S["AnchorKey"];
export type NtaItem = S["NtaItem"];

export interface AnchorsState {
  /** One row per zone. */
  anchors: TrustAnchorItem[];
  ntas: NtaItem[];
}

/** What the model needs of its caller. */
export interface AnchorsContext {
  now(): number;
  /** Raises the store revision and returns it. */
  nextRevision(): number;
  newId(): string;
  principal(): S["Principal"];
}

const HOUR = 3_600_000;
const DAY = 86_400_000;
/** RFC 5011 section 2.4.1: a new key is trusted after this long. */
const ADD_HOLD_DOWN = 30 * DAY;
/** The longest a negative trust anchor lives. */
export const NTA_MAX_MS = 7 * DAY;
/** The most keys one anchor holds. */
export const MAX_KEYS = 16;
/** The release the shipped keys name. */
export const SHIPPED_RELEASE = "0.0.4";
/** The most characters of a negative trust anchor's reason. */
export const NTA_REASON_MAX = 500;

/** The target of the audit records and events of the anchors: the singleton of the keys. */
export const ANCHORS_TARGET: S["ObjectRef"] = { kind: "dns_key", id: "00000000-0000-0000-0000-000000000000" };

/** The DS records of the root's two shipped keys (the IANA root anchors). */
const ROOT_20326 = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
const ROOT_38696 = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";
/** The digest of the key that is pending: made up. */
const ROOT_47000 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
const CORP_3613 = "3AA5AB37EFCE57F737FC1627013FEE07BDF241BD10F3B1964AB55C78E79A304B";

function fail(status: number, code: string, params: Record<string, string> = {}, detail?: string): never {
  throw new RecursionFailure(code, status, detail ?? code, params);
}

function invalidAnchor(field: string, reason: string): never {
  return fail(400, "dns.trust_anchor.invalid", { field, reason }, `${field}: ${reason}`);
}

function invalidNta(field: string, reason: string): never {
  return fail(400, "dns.nta.invalid", { field, reason }, `${field}: ${reason}`);
}

const iso = (at: number): string => new Date(at).toISOString();

function dsKey(tag: number, algorithm: number, digest: string, state: AnchorKey["state"], source: AnchorKey["source"], since: number, seen: number | null): AnchorKey {
  return {
    key_tag: tag,
    algorithm,
    digest_type: 2,
    data: { kind: "ds", rdata: `${tag} ${algorithm} 2 ${digest}` },
    state,
    state_since: iso(since),
    source,
    added_at: iso(since),
    last_seen: seen === null ? null : iso(seen),
  };
}

/** The seed: the root with its two shipped keys and a third one pending, and one operator anchor. */
export function seedAnchors(ctx: AnchorsContext): AnchorsState {
  const revision = ctx.nextRevision();
  const now = ctx.now();
  const shipped: AnchorKey["source"] = { kind: "shipped", release: SHIPPED_RELEASE };
  return {
    anchors: [
      {
        zone: ".",
        keys: [
          dsKey(20326, 8, ROOT_20326, "valid", shipped, now - 90 * DAY, now - 2 * HOUR),
          dsKey(38696, 8, ROOT_38696, "valid", shipped, now - 90 * DAY, now - 2 * HOUR),
          dsKey(47000, 8, ROOT_47000, "add_pend", { kind: "rfc5011" }, now - 12 * DAY, now - 2 * HOUR),
        ],
        last_query: iso(now - 2 * HOUR),
        next_query: iso(now + 22 * HOUR),
        revision,
      },
      {
        zone: "corp.example.test",
        keys: [dsKey(3613, 15, CORP_3613, "valid", { kind: "operator" }, now - 20 * DAY, now - HOUR)],
        last_query: iso(now - HOUR),
        next_query: iso(now + 23 * HOUR),
        revision,
      },
    ],
    ntas: [],
  };
}

// ---------------------------------------------------------------------------------
// Names

/** The zone of a path segment: `root` is the root, `root.` a zone named `root`; a trailing dot goes. */
export function zoneFromPath(segment: string): string {
  const text = segment.trim().toLowerCase();
  if (text === "root" || text === ".") return ".";
  return canonical(text);
}

/** The path segment of a zone. */
export function pathOfZone(zone: string): string {
  return zone === "." ? "root" : zone === "root" ? "root." : zone;
}

function rank(zone: string): string {
  return zone === "." ? "" : zone.split(".").reverse().join(".");
}

/** The anchors with the root first and the rest by reversed labels. */
export function listAnchors(state: AnchorsState): TrustAnchorItem[] {
  return [...state.anchors].sort((a, b) => (rank(a.zone) < rank(b.zone) ? -1 : rank(a.zone) > rank(b.zone) ? 1 : 0));
}

/** The anchor of a zone, by its path spelling. */
export function getAnchor(state: AnchorsState, segment: string): TrustAnchorItem {
  const zone = zoneFromPath(segment);
  return state.anchors.find((a) => a.zone === zone) ?? fail(404, "dns.trust_anchor.not_found", { zone }, `no trust anchor for ${zone}`);
}

// ---------------------------------------------------------------------------------
// Keys in presentation form

interface ParsedKey {
  key_tag: number;
  algorithm: number;
  digest_type: number | null;
  data: S["AnchorData"];
}

function wholeNumber(text: string | undefined, max: number): number | null {
  if (text === undefined || !/^\d{1,5}$/.test(text)) return null;
  const n = Number(text);
  return n <= max ? n : null;
}

function parseDs(text: string): ParsedKey {
  const parts = text.trim().split(/\s+/);
  const tag = wholeNumber(parts[0], 65_535);
  const algorithm = wholeNumber(parts[1], 255);
  const digestType = wholeNumber(parts[2], 255);
  const digest = parts.slice(3).join("");
  if (parts.length < 4 || tag === null || algorithm === null || digestType === null) {
    return invalidAnchor("ds", "expected `<key tag> <algorithm> <digest type> <digest>`");
  }
  if (digest === "" || digest.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(digest)) return invalidAnchor("ds", "the digest is not hexadecimal");
  return {
    key_tag: tag,
    algorithm,
    digest_type: digestType,
    data: { kind: "ds", rdata: `${tag} ${algorithm} ${digestType} ${digest.toUpperCase()}` },
  };
}

/** The key tag of RFC 4034 appendix B over the record data. */
export function keyTag(rdata: Uint8Array): number {
  let acc = 0;
  rdata.forEach((byte, i) => {
    acc += i % 2 === 0 ? byte << 8 : byte;
  });
  acc += (acc >>> 16) & 0xffff;
  return acc & 0xffff;
}

function parseDnskey(text: string): ParsedKey {
  const parts = text.trim().split(/\s+/);
  const flags = wholeNumber(parts[0], 65_535);
  const protocol = wholeNumber(parts[1], 255);
  const algorithm = wholeNumber(parts[2], 255);
  const key = parts.slice(3).join("");
  if (parts.length < 4 || flags === null || protocol === null || algorithm === null) {
    return invalidAnchor("dnskey", "expected `<flags> <protocol> <algorithm> <key>`");
  }
  if (protocol !== 3) return invalidAnchor("dnskey", "the protocol is 3");
  let raw: string;
  try {
    raw = atob(key);
  } catch {
    return invalidAnchor("dnskey", "the key is not base64");
  }
  if (raw === "") return invalidAnchor("dnskey", "the key is empty");
  const bytes = Uint8Array.from([flags >> 8, flags & 0xff, protocol, algorithm, ...[...raw].map((c) => c.charCodeAt(0))]);
  return {
    key_tag: keyTag(bytes),
    algorithm,
    digest_type: null,
    data: { kind: "dnskey", rdata: `${flags} ${protocol} ${algorithm} ${key}` },
  };
}

// ---------------------------------------------------------------------------------
// Trust anchors

/**
 * `POST /dns/trust-anchors`: adds a key to the zone's anchor (creating it). The key is valid at
 * once and its source is the operator. The root is touched only with `replace_root` under the
 * Lab profile, and then its keys are replaced by this one.
 */
export function addAnchor(state: AnchorsState, ctx: AnchorsContext, body: Record<string, unknown>, profile: Profile): TrustAnchorItem {
  const ds = typeof body.ds === "string" && body.ds.trim() !== "" ? body.ds : null;
  const dnskey = typeof body.dnskey === "string" && body.dnskey.trim() !== "" ? body.dnskey : null;
  if ((ds === null) === (dnskey === null)) return invalidAnchor(ds === null ? "ds" : "dnskey", "exactly one of ds and dnskey is given");
  const raw = typeof body.zone === "string" ? body.zone : "";
  const zone = canonical(raw);
  if (zone === "" || !validName(zone) || zone.includes("*")) return invalidAnchor("zone", "not a DNS name");
  const replace = body.replace_root === true;
  if (replace && zone !== ".") return invalidAnchor("replace_root", "only the root is replaced");
  if (zone === "." && !(replace && profile === "lab")) {
    return fail(409, "dns.trust_anchor.root_protected", { zone }, "the root's trust anchor changes only under the Lab profile, with replace_root");
  }
  const parsed = ds !== null ? parseDs(ds) : parseDnskey(dnskey ?? "");
  const now = ctx.now();
  const key: AnchorKey = {
    key_tag: parsed.key_tag,
    algorithm: parsed.algorithm,
    ...(parsed.digest_type !== null ? { digest_type: parsed.digest_type } : {}),
    data: parsed.data,
    state: "valid",
    state_since: iso(now),
    source: { kind: "operator" },
    added_at: iso(now),
    last_seen: null,
  };
  const current = state.anchors.find((a) => a.zone === zone);
  const kept = zone === "." ? [] : (current?.keys ?? []);
  if (kept.some((k) => k.data.kind === key.data.kind && k.data.rdata === key.data.rdata)) {
    return invalidAnchor(ds !== null ? "ds" : "dnskey", "the key is already in the anchor");
  }
  if (kept.length >= MAX_KEYS) return invalidAnchor(ds !== null ? "ds" : "dnskey", `an anchor holds at most ${MAX_KEYS} keys`);
  const row: TrustAnchorItem = {
    zone,
    keys: [...kept, key],
    last_query: current?.last_query ?? null,
    next_query: iso(now + HOUR),
    revision: ctx.nextRevision(),
  };
  state.anchors = current ? state.anchors.map((a) => (a.zone === zone ? row : a)) : [...state.anchors, row];
  return row;
}

/** `DELETE /dns/trust-anchors/{zone}`: the root's anchor goes only under the Lab profile. */
export function removeAnchor(state: AnchorsState, segment: string, profile: Profile): TrustAnchorItem {
  const zone = zoneFromPath(segment);
  if (zone === "." && profile !== "lab") {
    return fail(409, "dns.trust_anchor.root_protected", { zone }, "the root's trust anchor is removed only under the Lab profile");
  }
  const anchor = getAnchor(state, segment);
  state.anchors = state.anchors.filter((a) => a.zone !== anchor.zone);
  return anchor;
}

/**
 * `POST /dns/trust-anchors/{zone}/refresh`: RFC 5011 runs now. The last query is now, the next
 * one an hour on, and a key that was pending longer than the add hold-down is valid. Returns the
 * command id.
 */
export function refreshAnchor(state: AnchorsState, ctx: AnchorsContext, segment: string): string {
  const anchor = getAnchor(state, segment);
  const now = ctx.now();
  const row: TrustAnchorItem = {
    ...anchor,
    keys: anchor.keys.map((k) => {
      const seen = { ...k, last_seen: iso(now) };
      if (k.state === "add_pend" && now - Date.parse(k.state_since) >= ADD_HOLD_DOWN) return { ...seen, state: "valid" as const, state_since: iso(now) };
      return seen;
    }),
    last_query: iso(now),
    next_query: iso(now + HOUR),
    revision: ctx.nextRevision(),
  };
  state.anchors = state.anchors.map((a) => (a.zone === anchor.zone ? row : a));
  return ctx.newId();
}

// ---------------------------------------------------------------------------------
// Negative trust anchors

/** The negative trust anchors by zone, then by creation. */
export function listNtas(state: AnchorsState): NtaItem[] {
  return [...state.ntas].sort((a, b) => {
    const ra = rank(a.zone);
    const rb = rank(b.zone);
    return ra < rb ? -1 : ra > rb ? 1 : a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : 0;
  });
}

/**
 * `POST /dns/ntas`: refuses the root, a reason that is empty or over 500 characters, an expiry in
 * the past or more than seven days ahead, and no expiry under Hardened; without one the anchor
 * lives seven days.
 */
export function createNta(state: AnchorsState, ctx: AnchorsContext, body: Record<string, unknown>, profile: Profile): NtaItem {
  const raw = typeof body.zone === "string" ? body.zone : "";
  const zone = canonical(raw);
  if (zone === ".") return invalidNta("zone", "never the root");
  if (zone === "" || !validName(zone) || zone.includes("*")) return invalidNta("zone", "not a DNS name");
  const reason = typeof body.reason === "string" ? body.reason.trim() : "";
  if (reason === "") return invalidNta("reason", "a reason is required");
  if ([...reason].length > NTA_REASON_MAX) return invalidNta("reason", `at most ${NTA_REASON_MAX} characters`);
  const now = ctx.now();
  let expires = now + NTA_MAX_MS;
  if (body.expires_at !== undefined && body.expires_at !== null) {
    const at = typeof body.expires_at === "string" ? Date.parse(body.expires_at) : Number.NaN;
    if (Number.isNaN(at)) return invalidNta("expires_at", "not a timestamp");
    if (at <= now) return invalidNta("expires_at", "in the past");
    if (at > now + NTA_MAX_MS) return invalidNta("expires_at", "more than seven days ahead");
    expires = at;
  } else if (profile === "hardened") {
    return invalidNta("expires_at", "required under the Hardened profile");
  }
  const nta: NtaItem = {
    id: ctx.newId(),
    zone,
    reason,
    created_at: iso(now),
    created_by: ctx.principal(),
    expires_at: iso(expires),
    revision: ctx.nextRevision(),
  };
  state.ntas = [...state.ntas, nta];
  return nta;
}

/** `DELETE /dns/ntas/{id}`. */
export function deleteNta(state: AnchorsState, id: string): NtaItem {
  const nta = state.ntas.find((n) => n.id === id) ?? fail(404, "dns.nta.not_found", { id }, `no negative trust anchor ${id}`);
  state.ntas = state.ntas.filter((n) => n.id !== id);
  return nta;
}

/** Removes the negative trust anchors whose expiry has passed and returns them. */
export function expireNtas(state: AnchorsState, now: number): NtaItem[] {
  const gone = state.ntas.filter((n) => Date.parse(n.expires_at) <= now);
  if (gone.length > 0) state.ntas = state.ntas.filter((n) => Date.parse(n.expires_at) > now);
  return gone;
}
