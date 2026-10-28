// The one client store of the findings counts (docs/plans/ui-plan.md section 2.5): the rail
// badges, the status bar and every other surface read `GET /findings/counts` through it, so two
// screens can never show two numbers for one thing.
//
// The store loads while at least one component uses it. Every event of the `findings` topic
// schedules a reload (debounced), and so does every (re)connect of the event stream: the topic's
// events carry no SSE id and are never replayed, so a client that was away reloads instead. Only
// the answer of the newest request is taken, and never one older than the counts it would
// replace (`revision`), so an event or an answer that arrives out of order cannot set a number
// back. A read that fails keeps the last counts; one the server refuses (an account that may
// not read them, a server without the index) clears them, and nothing is drawn.
import { createEffect, createRoot, createSignal, on, onCleanup, onMount, type Accessor } from "solid-js";
import { api } from "../api/client";
import { events, type ApiEvent, type EventStream } from "../api/events";
import type { components } from "../api/generated/schema";
import { ApiError } from "../api/problem";

export type FindingCounts = components["schemas"]["FindingCounts"];
export type FindingLevel = components["schemas"]["FindingLevel"];
export type FindingArea = keyof FindingCounts["areas"];
export type LevelCounts = components["schemas"]["LevelCounts"];

/** Pause that lets a burst of events become one read. */
const DEBOUNCE_MS = 150;
/** Answers that mean "not for this account or not on this server", as opposed to a hiccup. */
const REFUSED: ReadonlySet<number> = new Set([401, 403, 404, 501, 503]);

const [counts, setCounts] = createSignal<FindingCounts | null>(null);

let users = 0;
let stop: (() => void) | undefined;
let timer: ReturnType<typeof setTimeout> | undefined;
let request = 0;
let controller: AbortController | undefined;

/** The newest revision an event announced. */
let announced = 0;

async function load(): Promise<void> {
  const mine = (request += 1);
  controller?.abort();
  controller = new AbortController();
  try {
    const next = await api.get("/api/v1/findings/counts", { signal: controller.signal });
    if (mine !== request || users === 0) return;
    const current = counts();
    if (current && next.revision < current.revision) return;
    setCounts(next);
    // An event announced a revision the answer has not reached yet: read once more.
    if (next.revision < announced) schedule();
  } catch (err) {
    if (mine !== request) return;
    if (err instanceof ApiError && REFUSED.has(err.status)) setCounts(null);
  }
}

function schedule(delay = DEBOUNCE_MS): void {
  clearTimeout(timer);
  timer = setTimeout(() => void load(), delay);
}

function onEvent(event: ApiEvent): void {
  const params = event.data.params as Record<string, unknown> | undefined;
  const revision = Number(params?.revision ?? event.revision);
  if (Number.isFinite(revision)) announced = Math.max(announced, revision);
  schedule();
}

function start(stream: EventStream): () => void {
  return createRoot((dispose) => {
    const offEvent = stream.subscribe("findings", onEvent);
    const offReset = stream.onReset("findings", () => schedule(0));
    // A (re)connect: what happened while the stream was away is not replayed for this topic.
    createEffect(
      on(
        () => stream.state() === "live",
        (live, before) => {
          if (live && before === false) schedule(0);
        },
        { defer: true },
      ),
    );
    void load();
    return () => {
      offEvent();
      offReset();
      dispose();
    };
  });
}

/**
 * The findings counts, loaded and kept current while the calling component is mounted; null
 * before the first answer and when the server does not give them to this account.
 */
export function useFindingCounts(stream: EventStream = events): Accessor<FindingCounts | null> {
  onMount(() => {
    users += 1;
    if (users === 1) stop = start(stream);
  });
  onCleanup(() => {
    users -= 1;
    if (users > 0) return;
    stop?.();
    stop = undefined;
    clearTimeout(timer);
    controller?.abort();
    request += 1;
    announced = 0;
    // A later sign-in starts afresh.
    setCounts(null);
  });
  return counts;
}

/** The counts of one area; zero for every severity while none are known. */
export function areaCounts(all: FindingCounts | null, area: FindingArea): LevelCounts {
  return all?.areas[area] ?? { act: 0, review: 0, info: 0 };
}

/** The worst severity that is counted (act, then review), or null when nothing is. */
export function worst(level: LevelCounts): "act" | "review" | null {
  return level.act > 0 ? "act" : level.review > 0 ? "review" : null;
}
