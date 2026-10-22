// The requests of the blocking page: the figures of the node's query log for 24 hours or 7
// days, the pause of the block lists (set and resumed) and "allow" from the log, which adds a
// name to an allow list and starts the compile job of its next version.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";

type S = components["schemas"];
export type BlockingStats = S["BlockingStats"];
export type BlockingPause = S["BlockingPause"];
export type BlockingPauseState = S["BlockingPauseState"];
export type BlockingAllowed = S["BlockingAllowed"];
export type BlockingWindow = S["BlockingWindow"];
export type QueryLogLine = S["QueryLogLine"];

/** Entries of each top list. */
export const TOP = 10;

export function blockingStats(window: BlockingWindow, signal?: AbortSignal): Promise<BlockingStats> {
  return api.get("/api/v1/dns/blocking/stats", { query: { window, top: TOP }, signal });
}

/** Pauses the block lists for `minutes`, or until they are resumed when absent. */
export function pauseBlocking(minutes?: number): Promise<BlockingPauseState> {
  return api.post("/api/v1/dns/blocking/pause", { body: minutes === undefined ? {} : { minutes } });
}

export function resumeBlocking(): Promise<BlockingPauseState> {
  return api.delete("/api/v1/dns/blocking/pause");
}

/** Allows `name` (and the names under it): the list `allowed` gets it, or `list` when given. */
export function allowName(name: string, list?: string): Promise<BlockingAllowed> {
  return api.post("/api/v1/dns/blocking/allow", { body: list === undefined ? { name } : { name, list } });
}
