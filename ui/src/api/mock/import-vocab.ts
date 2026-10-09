// The import vocabulary of the mock (crates/tenko-ipam/src/import/vocab.rs and codes.rs): the
// targets a column can map to, the header words in English and Swedish that suggest them, and
// the severity of every loss report code. Swedish words are written without diacritics and a
// header is folded the same way before the lookup, so this file stays plain ASCII.

export const CUSTOM_PREFIX = "custom.";
const FIELD_KEY = /^[a-z][a-z0-9_]{0,63}$/;

/** Every target except custom fields, in the order the mapping step lists them. */
export const FIXED_TARGETS = [
  "ignore",
  "address",
  "prefix",
  "mask",
  "host",
  "dns_name",
  "description",
  "status",
  "mode",
  "lock",
  "mac",
  "duid",
  "client_id",
  "interface",
  "interfaces",
  "vlan",
  "vlan_name",
  "site",
  "vrf",
  "tenant",
  "role",
  "alloc",
  "alarm_warn",
  "alarm_crit",
  "tags",
  "login",
  "password",
] as const;

export type FixedTarget = (typeof FIXED_TARGETS)[number];

const LABELS: Readonly<Record<FixedTarget, string>> = {
  ignore: "Do not import",
  address: "Address",
  prefix: "Network (CIDR)",
  mask: "Subnet mask or prefix length",
  host: "Host name",
  dns_name: "DNS name",
  description: "Description",
  status: "Status",
  mode: "Assignment mode",
  lock: "Lock",
  mac: "MAC address",
  duid: "DUID",
  client_id: "DHCP client identifier",
  interface: "Interface name",
  interfaces: "Interfaces of the host",
  vlan: "VLAN id",
  vlan_name: "VLAN name",
  site: "Site",
  vrf: "VRF",
  tenant: "Tenant",
  role: "Prefix role",
  alloc: "Next-free policy",
  alarm_warn: "Utilization warning (%)",
  alarm_crit: "Utilization critical (%)",
  tags: "Tags",
  login: "Login (stored in the vault)",
  password: "Password (stored in the vault)",
};

/** The English label of a target (the UI translates by the target name). */
export function targetLabel(target: string): string {
  if (target.startsWith(CUSTOM_PREFIX)) return `Custom field ${target.slice(CUSTOM_PREFIX.length)}`;
  return LABELS[target as FixedTarget] ?? target;
}

export function isCredential(target: string): boolean {
  return target === "login" || target === "password";
}

/** Whether `text` names a target: a fixed one, or `custom.<key>` with a valid key. */
export function isTarget(text: string): boolean {
  if (text.startsWith(CUSTOM_PREFIX)) return FIELD_KEY.test(text.slice(CUSTOM_PREFIX.length));
  return (FIXED_TARGETS as readonly string[]).includes(text);
}

/** Lowercase text without accents (`a` for a ring or a diaeresis, `o` for a slashed o). */
export function fold(text: string): string {
  const slashedO = new RegExp(String.fromCharCode(0xf8), "g");
  return text
    .toLowerCase()
    .replace(slashedO, "o")
    .normalize("NFD")
    .replace(/\p{M}/gu, "");
}

/** A header for the synonym lookup: lowercase, accents folded, letters and digits only. */
export function normalizeHeader(header: string): string {
  return fold(header.trim()).replace(/[^\p{L}\p{N}]/gu, "");
}

const SYNONYMS: ReadonlyMap<string, FixedTarget> = new Map<string, FixedTarget>([
  // Addresses.
  ...(
    [
      "ip",
      "ipadress",
      "ipaddress",
      "ipaddr",
      "address",
      "adress",
      "ipv4",
      "ipv6",
      "ipv4adress",
      "ipv4address",
      "ipv6adress",
      "ipv6address",
    ] as const
  ).map((word) => [word, "address"] as const),
  // Networks.
  ...(["prefix", "cidr", "network", "net", "nat", "natverk", "subnet", "subnat", "prefixcidr"] as const).map(
    (word) => [word, "prefix"] as const,
  ),
  // Masks.
  ...(
    ["mask", "netmask", "natmask", "subnetmask", "subnatmask", "prefixlength", "prefixlen", "prefixlangd"] as const
  ).map((word) => [word, "mask"] as const),
  // Names.
  ...(
    [
      "host",
      "hostname",
      "name",
      "namn",
      "vardnamn",
      "vard",
      "device",
      "enhet",
      "beteckning",
      "dator",
      "server",
    ] as const
  ).map((word) => [word, "host"] as const),
  // DNS names.
  ...(["dnsname", "dns", "dnsnamn", "fqdn"] as const).map((word) => [word, "dns_name"] as const),
  // Descriptions.
  ...(
    [
      "description",
      "beskrivning",
      "comment",
      "comments",
      "kommentar",
      "kommentarer",
      "notes",
      "note",
      "anteckning",
      "anteckningar",
      "info",
      "remark",
      "ovrigt",
    ] as const
  ).map((word) => [word, "description"] as const),
  // Lifecycle and assignment.
  ...(["status", "state"] as const).map((word) => [word, "status"] as const),
  ...(["mode", "assignment", "assignmentmode", "tilldelning"] as const).map((word) => [word, "mode"] as const),
  ...(["lock", "locked", "last"] as const).map((word) => [word, "lock"] as const),
  // Interfaces.
  ...(["mac", "macaddress", "macadress", "macaddr", "hwaddr", "hardwareaddress"] as const).map(
    (word) => [word, "mac"] as const,
  ),
  ["duid", "duid"],
  ["clientid", "client_id"],
  ["klientid", "client_id"],
  ["interface", "interface"],
  ["iface", "interface"],
  ["natverkskort", "interface"],
  ["interfaces", "interfaces"],
  // VLANs, sites and tenancy.
  ["vlan", "vlan"],
  ["vlanid", "vlan"],
  ["vid", "vlan"],
  ["vlanname", "vlan_name"],
  ["vlannamn", "vlan_name"],
  ["site", "site"],
  ["plats", "site"],
  ["location", "site"],
  ["placering", "site"],
  ["vrf", "vrf"],
  ["tenant", "tenant"],
  ["kund", "tenant"],
  // Prefix settings.
  ["role", "role"],
  ["roll", "role"],
  ["alloc", "alloc"],
  ["alarmwarn", "alarm_warn"],
  ["alarmcrit", "alarm_crit"],
  // Tags.
  ["tags", "tags"],
  ["tag", "tags"],
  ["taggar", "tags"],
  // Credentials: never IPAM fields.
  ["login", "login"],
  ["user", "login"],
  ["username", "login"],
  ["anvandare", "login"],
  ["anvandarnamn", "login"],
  ["anv", "login"],
  ["pass", "password"],
  ["password", "password"],
  ["passwd", "password"],
  ["pwd", "password"],
  ["losen", "password"],
  ["losenord", "password"],
]);

/** Header stems that, followed by a number, name one of several address columns. */
const NUMBERED_ADDRESS_STEMS: readonly string[] = ["nic", "ip", "eth", "if", "port", "natverkskort"];

/** The interface name a numbered address header implies (`Nic1` is `nic1`, `IP 2` is `ip2`). */
export function numberedInterface(header: string): string | null {
  const normalized = normalizeHeader(header);
  const digit = normalized.search(/[0-9]/);
  if (digit < 0) return null;
  const stem = normalized.slice(0, digit);
  const number = normalized.slice(digit);
  return NUMBERED_ADDRESS_STEMS.includes(stem) && /^[0-9]+$/.test(number) ? normalized : null;
}

/** The name of the interface created for the `n`-th address (1-based) of a host. */
export function defaultInterface(n: number): string {
  return `nic${n}`;
}

/** The target a header suggests, or null. `custom.<key>` headers suggest the custom field. */
export function targetForHeader(header: string): string | null {
  const trimmed = header.trim();
  if (trimmed.startsWith(CUSTOM_PREFIX)) return FIELD_KEY.test(trimmed.slice(CUSTOM_PREFIX.length)) ? trimmed : null;
  const normalized = normalizeHeader(trimmed);
  if (normalized === "") return null;
  const found = SYNONYMS.get(normalized);
  if (found) return found;
  return numberedInterface(normalized) !== null ? "address" : null;
}

// ---------------------------------------------------------------------------------
// Loss report codes (crates/tenko-ipam/src/import/codes.rs)

export const LOSS = {
  addressUnparsable: "import.address.unparsable",
  columnUnmapped: "import.column.unmapped",
  credentialSuspicious: "import.credential.suspicious",
  addressIsNetwork: "import.address.is_network",
  addressIsBroadcast: "import.address.is_broadcast",
  credentialNumeric: "import.credential.numeric",
  prefixUnlisted: "import.prefix.unlisted",
  sheetEmpty: "import.sheet.empty",
  sheetSkipped: "import.sheet.skipped",
  nameNormalized: "import.name.normalized",
  nameInvalid: "import.name.invalid",
  nameMissing: "import.name.missing",
  prefixProposed: "import.prefix.proposed",
  addressNoPrefix: "import.address.no_prefix",
  prefixHostBits: "import.prefix.host_bits",
  prefixUnparsable: "import.prefix.unparsable",
  addressDuplicate: "import.address.duplicate",
  rangeTooLarge: "import.address.range_too_large",
  valueInvalid: "import.value.invalid",
  hostConflict: "import.host.conflict",
  credentialNoHost: "import.credential.no_host",
  credentialDuplicate: "import.credential.duplicate",
  credentialSkipped: "import.credential.skipped",
  addressMissing: "import.address.missing",
  customUndefined: "import.custom.undefined",
  conflictKept: "import.conflict.kept",
  hostLocked: "import.host.locked",
} as const;

export type Severity = "info" | "warning" | "error";

const ERRORS: ReadonlySet<string> = new Set([
  LOSS.addressUnparsable,
  LOSS.nameInvalid,
  LOSS.nameMissing,
  LOSS.addressNoPrefix,
  LOSS.prefixUnparsable,
  LOSS.addressDuplicate,
  LOSS.rangeTooLarge,
  LOSS.credentialNoHost,
  LOSS.addressMissing,
  LOSS.customUndefined,
]);
const INFOS: ReadonlySet<string> = new Set([
  LOSS.prefixUnlisted,
  LOSS.sheetEmpty,
  LOSS.nameNormalized,
  LOSS.prefixProposed,
  LOSS.prefixHostBits,
]);

/** The severity of a loss code. */
export function severityOf(code: string): Severity {
  if (ERRORS.has(code)) return "error";
  if (INFOS.has(code)) return "info";
  return "warning";
}

/** The problem codes of the import endpoints. */
export const PROBLEM = {
  notFound: "import.not_found",
  expired: "import.expired",
  uploadEmpty: "import.upload.empty",
  uploadTooLarge: "import.upload.too_large",
  uploadUnsupported: "import.upload.unsupported",
  uploadUnreadable: "import.upload.unreadable",
  uploadMalformed: "import.upload.malformed",
  mappingInvalid: "import.mapping.invalid",
  stateConflict: "import.state.conflict",
  vaultRequired: "import.credentials.vault_required",
  planBlocked: "import.plan.blocked",
  previewStale: "import.preview.stale",
} as const;
