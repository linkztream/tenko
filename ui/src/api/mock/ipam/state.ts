// The state of the IPAM mock: one module-level store with every object kind, the history of
// each object and the alarm level each prefix had at the last write. The planner works on a
// copy of `store.data` and swaps it in when a write applies, so a failing write changes
// nothing. Objects are kept in the shape the API shows them.
import type {
  Address,
  AlarmLevel,
  CustomFieldDef,
  HistoryEntry,
  Host,
  Interface,
  IpamObject,
  ObjectRef,
  Prefix,
  Range,
  Site,
  Tenant,
  Vlan,
  Vrf,
} from "../../types";

export interface KindTypes {
  tenant: Tenant;
  vrf: Vrf;
  site: Site;
  vlan: Vlan;
  prefix: Prefix;
  range: Range;
  address: Address;
  host: Host;
  interface: Interface;
  custom_field: CustomFieldDef;
}

/** Every kind of IPAM object, including custom field definitions. */
export type Kind = keyof KindTypes;
/** The kinds that carry `meta` (tags, custom values and soft delete). */
export type MetaKind = Exclude<Kind, "custom_field">;

export const META_KINDS: readonly MetaKind[] = [
  "tenant",
  "vrf",
  "site",
  "vlan",
  "prefix",
  "range",
  "address",
  "host",
  "interface",
];

export type IpamData = { [K in Kind]: Map<string, KindTypes[K]> } & {
  /** The revision of each custom field definition (definitions have no `meta`). */
  fieldRevisions: Map<string, number>;
};

export interface IpamStore {
  data: IpamData;
  /** The history of each object by id, oldest entry first. */
  history: Map<string, HistoryEntry[]>;
  /** The alarm level each prefix had after the last write. */
  levels: Map<string, AlarmLevel>;
}

export function emptyData(): IpamData {
  return {
    tenant: new Map(),
    vrf: new Map(),
    site: new Map(),
    vlan: new Map(),
    prefix: new Map(),
    range: new Map(),
    address: new Map(),
    host: new Map(),
    interface: new Map(),
    custom_field: new Map(),
    fieldRevisions: new Map(),
  };
}

/** A deep copy, for the planner to work on. */
export function cloneData(data: IpamData): IpamData {
  return structuredClone(data);
}

/** The state. One object for the life of the module: a reset replaces its members. */
export const store: IpamStore = { data: emptyData(), history: new Map(), levels: new Map() };

/** Replaces the state (used by the reset). */
export function installStore(next: IpamStore): void {
  store.data = next.data;
  store.history = next.history;
  store.levels = next.levels;
}

/**
 * The state for other mock modules: every object by kind and id, the history of each
 * object (oldest first) and the alarm level of each prefix. Read it, never change it; apply
 * changes with `applyCommands`.
 */
export function ipamState(): Readonly<IpamStore> {
  return store;
}

/** A prefix by id, deleted ones included. */
export function findPrefix(id: string): Prefix | undefined {
  return store.data.prefix.get(id);
}

/** An address by id, deleted ones included. */
export function findAddress(id: string): Address | undefined {
  return store.data.address.get(id);
}

/** The live objects of a kind with `meta`. */
export function liveOf<K extends MetaKind>(data: IpamData, kind: K): KindTypes[K][] {
  const out: KindTypes[K][] = [];
  for (const object of data[kind].values()) if (!object.meta.deleted) out.push(object as KindTypes[K]);
  return out;
}

/** The tagged union the API uses for any object. */
export function objectOf<K extends Kind>(kind: K, value: KindTypes[K]): IpamObject {
  return { kind, data: value } as unknown as IpamObject;
}

/** An object by reference, in the tagged form. */
export function lookup(data: IpamData, ref: ObjectRef): IpamObject | undefined {
  const kind = ref.kind as Kind;
  const found = (data[kind] as Map<string, KindTypes[Kind]> | undefined)?.get(ref.id);
  return found ? objectOf(kind, found as never) : undefined;
}
