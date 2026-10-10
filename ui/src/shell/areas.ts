// The areas of the navigation rail, in the approved order (decision 13: Dashboard first,
// icons with labels), with their "G then <key>" chords. Discovery (proposals and
// observations) sits next to Topology, both of the discovery module; Connectors and Nodes,
// which are configured rather than visited daily, sit above Settings (WP2.9).
import type { IconName } from "../components/Icon";
import type { MessageKey } from "../i18n";

export interface Area {
  id: "dashboard" | "ipam" | "dns" | "dhcp" | "discovery" | "topology" | "jobs" | "audit" | "connectors" | "nodes" | "settings";
  path: string;
  icon: IconName;
  label: MessageKey;
  /** The second key of the G chord. */
  chord: string;
}

export const AREAS: readonly Area[] = [
  { id: "dashboard", path: "/", icon: "dashboard", label: "shell.nav.dashboard", chord: "B" },
  { id: "ipam", path: "/ipam", icon: "ipam", label: "shell.nav.ipam", chord: "I" },
  { id: "dns", path: "/dns", icon: "dns", label: "shell.nav.dns", chord: "D" },
  { id: "dhcp", path: "/dhcp", icon: "dhcp", label: "shell.nav.dhcp", chord: "H" },
  { id: "discovery", path: "/discovery", icon: "proposal", label: "shell.nav.discovery", chord: "O" },
  { id: "topology", path: "/topology", icon: "topology", label: "shell.nav.topology", chord: "T" },
  { id: "jobs", path: "/jobs", icon: "jobs", label: "shell.nav.jobs", chord: "J" },
  { id: "audit", path: "/audit", icon: "audit", label: "shell.nav.audit", chord: "A" },
  { id: "connectors", path: "/connectors", icon: "cable", label: "shell.nav.connectors", chord: "C" },
  { id: "nodes", path: "/nodes", icon: "server", label: "shell.nav.nodes", chord: "N" },
  { id: "settings", path: "/settings", icon: "settings", label: "shell.nav.settings", chord: "S" },
];
