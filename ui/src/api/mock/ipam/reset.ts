// Rebuilds the IPAM state when the mock db resets: seeded for every scenario except the
// first-run setup ones, which start empty. Importing this module seeds the state once.
import { db, onMockReset } from "../db";
import { buildSeed } from "./seed";
import { emptyData, installStore } from "./state";

/** Replaces the state for the current scenario. */
export function reloadIpamState(): void {
  const empty = db.scenario === "setup" || db.scenario === "setup-slow-disk";
  installStore(empty ? { data: emptyData(), history: new Map(), levels: new Map() } : buildSeed(Date.now()));
}

reloadIpamState();
onMockReset(() => reloadIpamState());
