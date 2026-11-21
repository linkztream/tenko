// Utilization alarms (IPAM-10): the server writes level changes as `system` events
// (`ipam.alarms`); the dashboard reads the prefix tree again when one arrives.

/** Whether an event may change the alarms. */
export function isAlarmEvent(e: { topic: string; data: Record<string, unknown>; objects: { kind: string }[] }): boolean {
  if (e.topic === "system") {
    const tables = Array.isArray(e.data.tables) ? (e.data.tables as unknown[]) : [];
    return e.data.kind === "ipam.prefix.alarm" || tables.includes("ipam.alarms");
  }
  return e.objects.some((o) => o.kind === "vrf");
}
