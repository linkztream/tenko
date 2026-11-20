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

/** The digest check and the install command an administrator runs on the DHCP server. */
export function installCommands(mirror: Pick<MirrorItem, "id" | "ca_fingerprint">, origin: string): [string, string] {
  const fingerprint = mirror.ca_fingerprint ?? "<fingerprint>";
  return [
    "Get-FileHash .\\Tenko-DhcpMirror.ps1, .\\Install-TenkoDhcpMirror.ps1 -Algorithm SHA256",
    `.\\Install-TenkoDhcpMirror.ps1 -Url '${origin}' -MirrorId '${mirror.id}' -Fingerprint '${fingerprint}' -Account 'DOMAIN\\account' -PromptToken`,
  ];
}
