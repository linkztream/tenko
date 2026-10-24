// The words and small rules of the discovery views, as pure functions over `t`: proposal
// kinds, severities and states, the translated text of a rule (built from its `rule` code and
// `params`, with the English `summary` of the server as the fallback), sources, facts and
// subjects. The host page and the dashboard reuse them.
import type { ApiEvent } from "../api/events";
import type { IconName } from "../components/Icon";
import { formatDateTime, formatList, t, tDynamic } from "../i18n";
import { parseIp } from "../ipam/ip";
import {
  PROPOSAL_KINDS,
  type ObservationSource,
  type Observed,
  type ObservedFact,
  type Proposal,
  type ProposalKind,
  type ProposalSeverity,
  type ProposalState,
} from "./api";

// ---------------------------------------------------------------------------------
// Kinds, severities and states

export function kindWord(kind: ProposalKind): string {
  return t(`discovery.kind.${kind}`);
}

/** The glyph of a kind; the word always comes with it. */
export function kindIcon(kind: ProposalKind): IconName {
  switch (kind) {
    case "discovered_host":
      return "proposal";
    case "conflict":
      return "conflict";
    case "address_mismatch":
      return "alert";
    case "outside_prefixes":
      return "layers";
    case "orphaned_intent":
      return "clock";
  }
}

/** The kinds of some proposals with how many of each, as one phrase: "60 discovered hosts and 3 conflicts". */
export function kindSummary(list: readonly Pick<Proposal, "kind">[]): string {
  const counts = new Map<ProposalKind, number>();
  for (const p of list) counts.set(p.kind, (counts.get(p.kind) ?? 0) + 1);
  return formatList(PROPOSAL_KINDS.filter((k) => counts.has(k)).map((k) => t(`discovery.batch.kind.${k}`, { count: counts.get(k) ?? 0 })));
}

/** The design's exception class of a kind: magenta for proposals, red for conflicts, amber for differences. */
export function kindClass(kind: ProposalKind): "proposal" | "conflict" | "discrepancy" {
  if (kind === "conflict") return "conflict";
  if (kind === "address_mismatch" || kind === "orphaned_intent") return "discrepancy";
  return "proposal";
}

export function severityWord(severity: ProposalSeverity): string {
  return t(`discovery.severity.${severity}`);
}

export function severityIcon(severity: ProposalSeverity): IconName {
  return severity === "critical" ? "conflict" : severity === "warning" ? "alert" : "info";
}

export function stateWord(state: ProposalState): string {
  return t(`discovery.state.${state}`);
}

/** Whether a proposal can be decided at all (only open ones can). */
export function isOpen(p: Pick<Proposal, "state">): boolean {
  return p.state === "open";
}

/** Whether approving makes sense: open, with commands, and not a conflict. */
export function canApprove(p: Pick<Proposal, "state" | "kind" | "commands">): boolean {
  return isOpen(p) && p.kind !== "conflict" && (p.commands?.length ?? 0) > 0;
}

/** Whether an event of the `ipam` topic concerns proposals. */
export function isProposalEvent(e: ApiEvent): boolean {
  if ([...e.objects, ...e.deleted].some((o) => o.kind === "proposal")) return true;
  const tables = e.data.tables;
  return Array.isArray(tables) && tables.includes("ipam.proposals");
}

// ---------------------------------------------------------------------------------
// The text of a rule

/** `ipam.reconcile.discovered_mac` becomes `discovered_mac`. */
export function ruleName(rule: string): string {
  const dot = rule.lastIndexOf(".");
  return dot < 0 ? rule : rule.slice(dot + 1);
}

/** Message arguments from the string parameters of a proposal; absent optional ones say `none`. */
function ruleArgs(params: Readonly<Record<string, string>>): Record<string, string | number> {
  const out: Record<string, string | number> = { mac: "none", ips: "none", host: "none" };
  for (const [key, value] of Object.entries(params)) {
    if (value === "") continue;
    if (key === "last_seen") {
      const at = Date.parse(value);
      out[key] = Number.isNaN(at) ? value : formatDateTime(at);
    } else out[key] = /^\d+$/.test(value) ? Number(value) : value;
  }
  return out;
}

/**
 * The translated text of a proposal's rule. A rule this UI does not know, or parameters its
 * message does not fit, fall back to the server's English summary.
 */
export function ruleText(p: Pick<Proposal, "rule" | "params" | "summary">): string {
  const key = `discovery.rule.${ruleName(p.rule)}`;
  const text = tDynamic(key, ruleArgs(p.params ?? {}));
  return text === undefined || text === key ? p.summary : text;
}

/** The short label of what a proposal is about: its name, MAC, address or network. */
export function subjectLabel(p: Pick<Proposal, "subject">): string {
  const s = p.subject;
  return s.name ?? s.mac ?? s.ip ?? s.cidr ?? "–";
}

/** The newest last sighting among the evidence, or null without evidence. */
export function lastSeenOf(p: Pick<Proposal, "evidence">): string | null {
  let best: string | null = null;
  for (const e of p.evidence) if (best === null || e.last_seen > best) best = e.last_seen;
  return best;
}

// ---------------------------------------------------------------------------------
// Sources

/** Names to show for connector instances and nodes, by id; ids stand in where a name is missing. */
export interface SourceNames {
  connector: (id: string) => string | undefined;
  node: (id: number) => string | undefined;
}

export const NO_NAMES: SourceNames = { connector: () => undefined, node: () => undefined };

export function probeMethodWord(method: string): string {
  return tDynamic(`discovery.method.${method}`) ?? method;
}

/** The source of an observation in words: "Lab inventory (inventory)", "Probe probe-dmz, ARP". */
export function sourceText(source: ObservationSource, names: SourceNames = NO_NAMES): string {
  switch (source.type) {
    case "inventory":
      return t("discovery.source.inventory", { name: names.connector(source.connector) ?? source.connector.slice(0, 8) });
    case "network_controller":
      return t("discovery.source.network_controller", { name: names.connector(source.connector) ?? source.connector.slice(0, 8) });
    case "probe":
      return t("discovery.source.probe", { node: names.node(source.node) ?? String(source.node), method: probeMethodWord(source.method) });
    case "dns_record":
      return t("discovery.source.dns", { zone: source.zone });
    case "dhcp_lease":
      return t("discovery.source.dhcp", { node: names.node(source.node) ?? String(source.node) });
    default:
      // A source kind of a newer server: its type is still readable.
      return String((source as { type?: unknown }).type ?? "");
  }
}

/**
 * A source key (`inventory:<id>`, `probe:<node>:<method>`, ...) in words, for the sources of
 * a summary, which carry keys only. A key of an unknown form stays as it is.
 */
export function sourceKeyText(key: string, names: SourceNames = NO_NAMES): string {
  const [type, a, b] = key.split(":");
  if ((type === "inventory" || type === "network_controller") && a) return sourceText({ type, connector: a } as ObservationSource, names);
  if (type === "probe" && a && b && /^\d+$/.test(a)) return sourceText({ type: "probe", node: Number(a), method: b } as ObservationSource, names);
  if (type === "dhcp" && a && /^\d+$/.test(a)) return sourceText({ type: "dhcp_lease", node: Number(a) }, names);
  if (type === "dns" && a) return sourceText({ type: "dns_record", zone: key.slice(4) }, names);
  return key;
}

// ---------------------------------------------------------------------------------
// Facts

export function factTypeWord(type: string): string {
  return tDynamic(`discovery.fact_type.${type}`) ?? type;
}

/** Whether a fact is current: no expiry, or one in the future. */
export function isCurrent(fact: Pick<ObservedFact, "expires_at">, now = Date.now()): boolean {
  return !fact.expires_at || Date.parse(fact.expires_at) > now;
}

/** What a fact reports, in one line of words and identifiers. */
export function observedText(observed: Observed): string {
  switch (observed.type) {
    case "host": {
      const d = observed.data;
      const parts = [d.name ?? d.external_id];
      if (d.macs?.length) parts.push(formatList(d.macs));
      if (d.ips?.length) parts.push(formatList(d.ips));
      if (d.os) parts.push(d.os);
      if (d.platform) parts.push(d.platform);
      if (d.parent) parts.push(t("discovery.fact.parent", { parent: d.parent }));
      return parts.join(" · ");
    }
    case "address":
      return observed.data.mac ? t("discovery.fact.address_mac", { ip: observed.data.ip, mac: observed.data.mac }) : observed.data.ip;
    case "services": {
      const ports = observed.data.open_tcp.length
        ? t("discovery.fact.ports", { ip: observed.data.ip, ports: observed.data.open_tcp.join(", ") })
        : t("discovery.fact.no_ports", { ip: observed.data.ip });
      // Ports that answered a TLS handshake, from servers that report them.
      const tls = observed.data.tls_tcp;
      return Array.isArray(tls) && tls.length > 0 ? `${ports} · ${t("discovery.fact.tls", { ports: tls.join(", ") })}` : ports;
    }
    case "os":
      return t("discovery.fact.os", { ip: observed.data.ip, guess: observed.data.guess, confidence: observed.data.confidence });
    case "attachment": {
      const d = observed.data;
      const where = [d.device, d.port ? t("discovery.fact.port", { port: d.port }) : null, d.ssid ? t("discovery.fact.ssid", { ssid: d.ssid }) : null]
        .filter((x): x is string => !!x)
        .join(", ");
      return d.vlan != null ? t("discovery.fact.attachment_vlan", { mac: d.mac, where, vlan: d.vlan }) : t("discovery.fact.attachment", { mac: d.mac, where });
    }
    case "link": {
      const end = (e: { device: string; port?: string | null }) => (e.port ? `${e.device} ${e.port}` : e.device);
      return t("discovery.fact.link", { a: end(observed.data.a), b: end(observed.data.b), kind: observed.data.kind });
    }
    case "name":
      // What a probe found for an address; it is no sighting of the address.
      return observed.data.ip && observed.data.name ? t("discovery.fact.name", { ip: observed.data.ip, name: observed.data.name }) : otherObservedText(observed);
    case "vendor":
      return observed.data.mac && observed.data.vendor ? t("discovery.fact.vendor", { mac: observed.data.mac, vendor: observed.data.vendor }) : otherObservedText(observed);
    default:
      // A kind of fact that a newer server adds.
      return otherObservedText(observed);
  }
}

/** The `data` of an observation as members by name; nothing for a `data` that is not an object. */
function dataOf(o: { data?: unknown }): Record<string, unknown> {
  return typeof o.data === "object" && o.data !== null ? (o.data as Record<string, unknown>) : {};
}

/**
 * What an observation of a kind this build does not know reports: its members, as
 * `name value` in one line. Also the way out for a `name` or a `vendor` without its text.
 */
function otherObservedText(o: { type: string; data?: unknown }): string {
  const text = (v: unknown) => (typeof v === "string" || typeof v === "number" ? String(v) : "");
  return Object.entries(dataOf(o))
    .map(([k, v]) => `${k} ${Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : text(v)}`)
    .join(" · ");
}

/** The subject of a fact to look up across sources: its MAC, IP address or host name. */
export function lookupSubject(fact: ObservedFact): string | null {
  const o = fact.observed;
  switch (o.type) {
    case "host":
      return o.data.macs?.[0] ?? o.data.ips?.[0] ?? o.data.name ?? null;
    case "address":
      return o.data.mac ?? o.data.ip;
    case "services":
    case "os":
      return o.data.ip;
    case "attachment":
      return o.data.mac;
    case "link":
      return null;
    case "name":
      // The address the name was found for.
      return o.data.ip;
    case "vendor":
      // The MAC address whose vendor it is.
      return o.data.mac;
    default: {
      // A kind of fact that a newer server adds: whatever it names, MAC address first.
      const d = dataOf(o);
      const subject = d.mac ?? d.ip ?? d.name;
      return typeof subject === "string" ? subject : null;
    }
  }
}

// ---------------------------------------------------------------------------------
// Subjects

const MAC = /^[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$/i;

/** What a subject text is: a MAC address, an IP address or a name. */
export function subjectKind(text: string): "mac" | "ip" | "name" {
  const s = text.trim();
  if (MAC.test(s)) return "mac";
  if (parseIp(s)) return "ip";
  return "name";
}

/** A subject as the API spells it (`mac:<mac>`, `ip:<ip>`, `name:<name>`) without its prefix. */
export function subjectValue(subject: string): string {
  const colon = subject.indexOf(":");
  const kind = subject.slice(0, colon);
  return colon > 0 && (kind === "mac" || kind === "ip" || kind === "name") ? subject.slice(colon + 1) : subject;
}
