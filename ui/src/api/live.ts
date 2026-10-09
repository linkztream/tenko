// Keeps a fetched value current with server-sent events: the pattern every live view
// uses. Subscribe first, then fetch; an event of a subscribed topic that is newer than
// the fetched revision (and relevant, if a filter is given) schedules a refetch; a reset
// refetches at once. Rows never jump under the cursor because the view decides how to
// apply the new value (see design/README.md, "Live updates via SSE").
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

  const schedule = () => {
    clearTimeout(timer);
    timer = setTimeout(reload, options.debounceMs ?? 150);
  };

  const offs = options.topics.flatMap((topic) => [
    stream.subscribe(topic, (event) => {
      if (event.revision !== undefined && revision !== undefined && event.revision <= revision) return;
      if (options.relevant && !options.relevant(event)) return;
      schedule();
    }),
    stream.onReset(topic, reload),
  ]);

  onCleanup(() => {
    clearTimeout(timer);
    controller?.abort();
    for (const off of offs) off();
  });

  return { value, refetch: reload, revision: () => revision };
}
