// The words and rules of the nodes views (docs/cluster.md): roles, the connection state of a
// node in one word, the certificate with its days left and whether a renewal is due, token
// states and lifetimes, and the command that enrols a node.
import type { IconName } from "../components/Icon";
import { formatDuration, t, tDynamic } from "../i18n";
import type { CertificateRef, CreatedEnrolment, EnrolmentView, NodeView } from "../api/nodes";

const DAY_MS = 86_400_000;

/** The job title and step summary the server sends for node edits; the jobs views translate them. */
export const CLUSTER_JOB_KEYS = ["cluster.job.edit", "cluster.job.write_preview"] as const;

export function roleWord(role: string): string {
  return tDynamic(`node.role.${role}`) ?? role;
}

/** How a node is: connected, refused for want of a common protocol major, or not connected. */
export type LinkState = "connected" | "mismatch" | "disconnected";

export function linkState(node: Pick<NodeView, "connected" | "protocol">): LinkState {
  if (node.connected) return "connected";
  return node.protocol.mismatch ? "mismatch" : "disconnected";
}

export function linkWord(state: LinkState): string {
  return t(`nodes.link.${state}`);
}

export function linkIcon(state: LinkState): IconName {
  return state === "connected" ? "check" : state === "mismatch" ? "conflict" : "pause";
}

export interface CertificateState {
  daysLeft: number;
  /** Renewal is due: less than a third of the lifetime or fewer than 30 days remain. */
  renewalDue: boolean;
  expired: boolean;
}

export function certificateState(cert: Pick<CertificateRef, "not_before" | "not_after">, now = Date.now()): CertificateState {
  const start = Date.parse(cert.not_before);
  const end = Date.parse(cert.not_after);
  const left = end - now;
  const lifetime = end - start;
  return {
    daysLeft: Math.floor(left / DAY_MS),
    renewalDue: left < lifetime / 3 || left < 30 * DAY_MS,
    expired: left <= 0,
  };
}

export function tokenStateWord(state: EnrolmentView["state"]): string {
  return t(`nodes.token.state.${state}`);
}

/** Token lifetimes the form offers, in seconds (60 to 604,800 are allowed). */
export const LIFETIMES: readonly number[] = [900, 3_600, 86_400, 604_800];
export const DEFAULT_LIFETIME = 3_600;

export function lifetimeWord(secs: number): string {
  return tDynamic(`nodes.lifetime.s${secs}`) ?? formatDuration(secs);
}

/**
 * The command to run on the node, as the server printed it. When the server could not tell
 * the address it was reached at, the command names a placeholder controller; this page knows
 * the address the browser uses, so it fills it in.
 */
export function enrolCommand(created: Pick<CreatedEnrolment, "command" | "token" | "ca_fingerprint">, origin: string): string {
  const command = created.command?.trim();
  if (command) return command.replace(/https:\/\/<controller>:\d+/, origin);
  return `tenko node enrol --controller ${origin} --token ${created.token} --ca-fingerprint ${created.ca_fingerprint}`;
}

/** A SHA-256 fingerprint in pairs of hexadecimal digits, for reading it aloud. */
export function fingerprintPairs(hex: string): string {
  return (hex.toUpperCase().match(/.{1,2}/g) ?? []).join(":");
}
