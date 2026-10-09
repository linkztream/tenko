// Names and small facts about audit records shared by the log and the record page: the
// kinds of objects the log can name, the subject string of a principal (the form the
// `principal` filter of GET /audit takes) and the words for outcomes and failures.
import type { AuditOutcome, ObjectKind, Principal } from "../api/types";
import { tDynamic } from "../i18n";

/** Every kind of object of the API document; the record forces this table to stay complete. */
const KINDS: Record<ObjectKind, true> = {
  tenant: true,
  vrf: true,
  site: true,
  vlan: true,
  prefix: true,
  range: true,
  address: true,
  host: true,
  interface: true,
  custom_field: true,
  user: true,
  session: true,
  api_token: true,
  job: true,
  observation: true,
  proposal: true,
  import: true,
  connector: true,
  secret: true,
  node: true,
  settings: true,
  system: true,
};

export const OBJECT_KINDS = Object.keys(KINDS) as ObjectKind[];

export function isObjectKind(value: string): value is ObjectKind {
  return Object.prototype.hasOwnProperty.call(KINDS, value);
}

export type SystemComponent = Extract<Principal, { kind: "system" }>["component"];

const COMPONENTS: Record<SystemComponent, true> = {
  setup: true,
  api: true,
  auth: true,
  vault: true,
  store: true,
  ipam: true,
  import: true,
  jobs: true,
  reconciler: true,
  connector: true,
  scan: true,
  cluster: true,
};

export const SYSTEM_COMPONENTS = Object.keys(COMPONENTS) as SystemComponent[];

/** The kind of an object in words ("Host", "API token"); the raw kind for one the UI does not know. */
export function kindWord(kind: string): string {
  return tDynamic(`audit.kind.${kind}`) ?? kind;
}

/**
 * The subject of a principal as the API filters it: `user:<id>`, `token:<id>`,
 * `system:<component>` or `node:<id>`.
 */
export function principalSubject(principal: Principal): string {
  switch (principal.kind) {
    case "user":
      return `user:${principal.id}`;
    case "token":
      return `token:${principal.id}`;
    case "system":
      return `system:${principal.component}`;
    case "node":
      return `node:${principal.id}`;
  }
}

export type OutcomeKind = AuditOutcome["kind"];

/** A short form of a digest for display: the first twelve hexadecimal digits. */
export function shortHash(hash: string): string {
  return hash.slice(0, 12);
}

/** The all-zero digest that the first record carries as its predecessor. */
export function isZeroHash(hash: string): boolean {
  return /^0+$/.test(hash);
}
