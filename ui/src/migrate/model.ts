// What the mirror views compute from a mirror: its state on the card and the two PowerShell
// commands of its Settings tab (deploy/windows/mirror/README.md). Pure functions, no API.
import type { MirrorItem } from "./api";

/** A mirror's state on its card: disabled, waiting for its first push, fresh or stale. */
export type MirrorState = "disabled" | "waiting" | "fresh" | "stale";

export function mirrorState(mirror: Pick<MirrorItem, "enabled" | "age_secs" | "stale">): MirrorState {
  if (mirror.enabled === false) return "disabled";
  if (mirror.age_secs === undefined || mirror.age_secs === null) return "waiting";
  return mirror.stale ? "stale" : "fresh";
}

/**
 * The short form of a mirror's id shown beside its name, which is not unique: its last eight
 * hexadecimal digits, as the server's findings and `Mirror::short_id` write it.
 */
export function shortId(id: string): string {
  return id.slice(-8);
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/i;
const ORIGIN = /^https?:\/\/[A-Za-z0-9.\-[\]:]+$/;

/**
 * The digest check and the install command an administrator runs on the DHCP server. Only
 * values of a checked shape go into the command (a UUID, 64 hexadecimal digits, a scheme with
 * a host and a port); anything else shows as a placeholder for the operator to fill in.
 */
export function installCommands(mirror: Pick<MirrorItem, "id" | "ca_fingerprint">, origin: string): [string, string] {
  const checked = (value: string | null | undefined, shape: RegExp, placeholder: string) =>
    value && shape.test(value) ? value : placeholder;
  const url = checked(origin, ORIGIN, "<https://tenko:8443>");
  const id = checked(mirror.id, UUID, "<mirror id>");
  const fingerprint = checked(mirror.ca_fingerprint, SHA256, "<fingerprint>");
  return [
    "Get-FileHash .\\Tenko-DhcpMirror.ps1, .\\Install-TenkoDhcpMirror.ps1 -Algorithm SHA256",
    `.\\Install-TenkoDhcpMirror.ps1 -Url '${url}' -MirrorId '${id}' -Fingerprint '${fingerprint}' -Account 'DOMAIN\\account' -PromptToken`,
  ];
}
