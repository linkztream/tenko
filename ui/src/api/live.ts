// Keeps a fetched value current with server-sent events: the pattern every live view
// uses. Subscribe first, then fetch; an event of a subscribed topic that is newer than
// the fetched revision (and relevant, if a filter is given) schedules a refetch, which is
// dropped if a read in the meantime reached that revision (a view that refetches after its
// own write already has the event's change, and a second load would rebuild its rows under
// the user's hands); a reset refetches at once. Rows never jump under the cursor because
// the view decides how to apply the new value (see design/README.md, "Live updates via SSE").
import { createResource, onCleanup, type Resource } from "solid-js";
import { events as defaultStream, type ApiEvent, type EventStream, type Topic } from "./events";

export interface LiveQueryOptions<T> {
  topics: readonly Topic[];
  /** Loads the value; return the list revision when there is one. */
  fetch: (signal: AbortSignal) => Promise<{ value: T; revision?: number | undefined }>;
  /** Only events this accepts trigger a refetch (default: every event of the topics). */
  relevant?: (event: ApiEvent) => boolean;
  /** Waits this long after an event to coalesce bursts (default 150 ms). */
  debounceMs?: number;
  stream?: EventStream;
}

export interface LiveQuery<T> {
  value: Resource<T>;
  refetch: () => void;
  /** The revision the current value was read at. */
  revision: () => number | undefined;
  /**
   * The value last read, or undefined while nothing is loaded yet or the last read failed. Use
   * it where `value.latest` was read: that getter throws the error of a failed read, so a view
   * has to look at `value.error` first, and a view that forgets crashes instead of showing
   * its error notice. This one never throws; the error stays on `value.error`.
   */
  latest: () => T | undefined;
}

/**
 * The guard for the pattern "`latest` rethrows the error of a failed read": the latest value of a
 * live query (or of any resource), or undefined while nothing is loaded or the last read failed.
 * Reactive like the resource itself.
 */
export function latest<T>(query: LiveQuery<T> | Resource<T>): T | undefined {
  const resource = typeof query === "function" ? query : query.value;
  return resource.error ? undefined : resource.latest;
}

/** Must be called inside a component or another reactive owner. */
export function createLiveQuery<T>(options: LiveQueryOptions<T>): LiveQuery<T> {
  const stream = options.stream ?? defaultStream;
  let revision: number | undefined;
  let controller: AbortController | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const [value, { refetch }] = createResource<T>(async () => {
    controller?.abort();
    controller = new AbortController();
    const result = await options.fetch(controller.signal);
    revision = result.revision;
    if (revision !== undefined) stream.resumeFrom(revision);
    return result.value;
  });

  // `refetch(false)` skips Solid's guard that drops a second load in the same microtask
  // (a source that changes twice in one tick would keep the first answer); the newest load
  // aborts the older one and only its answer is applied.
  const reload = () => void refetch(false);

  // The newest revision among the events behind the scheduled reload; null once one of them
  // had no revision (a system event), which no read satisfies.
  let behind: number | null | undefined;

  const schedule = (eventRevision: number | undefined) => {
    if (eventRevision === undefined) behind = null;
    else if (behind !== null) behind = behind === undefined ? eventRevision : Math.max(behind, eventRevision);
    clearTimeout(timer);
    timer = setTimeout(() => {
      const wanted = behind;
      behind = undefined;
      // A read since the events (the view's own refetch after its write) reached their revision.
      if (typeof wanted === "number" && revision !== undefined && wanted <= revision) return;
      reload();
    }, options.debounceMs ?? 150);
  };

  const offs = options.topics.flatMap((topic) => [
    stream.subscribe(topic, (event) => {
      if (event.revision !== undefined && revision !== undefined && event.revision <= revision) return;
      if (options.relevant && !options.relevant(event)) return;
      schedule(event.revision);
    }),
    stream.onReset(topic, reload),
  ]);

  onCleanup(() => {
    clearTimeout(timer);
    controller?.abort();
    for (const off of offs) off();
  });

  return { value, refetch: reload, revision: () => revision, latest: () => latest(value) };
}
