// The areas of the navigation rail, in the approved order (decision 13: Dashboard first,
// icons with labels), with their "G then <key>" chords. Discovery (proposals and
// observations) sits next to Topology, both of the discovery module; Connectors, Nodes and
// Cluster, which are configured rather than visited daily, sit above Settings (WP2.9, WP3.0).
// A hairline separates three groups (design decision 17): Operate, Work and System, with
// Settings at the bottom.
import type { IconName } from "../components/Icon";
import type { MessageKey } from "../i18n";

export type AreaGroup = "operate" | "work" | "system" | "bottom";

export interface Area {
  id: "dashboard" | "ipam" | "dns" | "dhcp" | "discovery" | "topology" | "jobs" | "audit" | "connectors" | "nodes" | "cluster" | "settings";
  path: string;
  icon: IconName;
  label: MessageKey;
  /** The second key of the G chord. */
  chord: string;
  /** The group of the rail it sits in. */
  group: AreaGroup;
}

export const AREAS: readonly Area[] = [
  { id: "dashboard", path: "/", icon: "dashboard", label: "shell.nav.dashboard", chord: "B", group: "operate" },
  { id: "ipam", path: "/ipam", icon: "ipam", label: "shell.nav.ipam", chord: "I", group: "operate" },
  { id: "dns", path: "/dns", icon: "dns", label: "shell.nav.dns", chord: "D", group: "operate" },
  { id: "dhcp", path: "/dhcp", icon: "dhcp", label: "shell.nav.dhcp", chord: "H", group: "operate" },
  { id: "discovery", path: "/discovery", icon: "proposal", label: "shell.nav.discovery", chord: "O", group: "operate" },
  { id: "topology", path: "/topology", icon: "topology", label: "shell.nav.topology", chord: "T", group: "operate" },
  { id: "jobs", path: "/jobs", icon: "jobs", label: "shell.nav.jobs", chord: "J", group: "work" },
  { id: "audit", path: "/audit", icon: "audit", label: "shell.nav.audit", chord: "A", group: "work" },
  { id: "connectors", path: "/connectors", icon: "cable", label: "shell.nav.connectors", chord: "C", group: "system" },
  { id: "nodes", path: "/nodes", icon: "server", label: "shell.nav.nodes", chord: "N", group: "system" },
  { id: "cluster", path: "/cluster", icon: "layers", label: "shell.nav.cluster", chord: "K", group: "system" },
  { id: "settings", path: "/settings", icon: "settings", label: "shell.nav.settings", chord: "S", group: "bottom" },
];
