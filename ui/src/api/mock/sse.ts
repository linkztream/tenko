// The event stream: GET /api/v1/events?topics=a,b&from=<revision> (API-05).
//
// Data events carry the topic as SSE event name, the revision as id and an `EventData`
// document as data. `from` (or `Last-Event-ID`) replays the mock journal after that
// revision; a position the journal cannot serve (older than the 256 retained events, in
// the future, or malformed) gets a `reset` event with reason `gap` and the stream goes on.
// `reset` and `shutdown` reach every stream whatever its topic filter.
//
// `msw/sse` is not used: its handler needs an `EventSource` to exist when it is built, and
// the test environment has none. A plain GET answering a `ReadableStream` works in the
// browser (service worker) and in Node alike.
import type { HttpHandler } from "msw";
import type { Topic } from "../events";
import { requireSession } from "./auth";
import {
  db,
  onMockReset,
  recordAlarm,
  recordEvent,
  subscribeEvents,
  type MockEvent,
  type MockEventData,
} from "./db";
import { advanceMockJobs } from "./job-store";
import { fail } from "./reply";
import { route } from "./route";

const TOPICS: readonly Topic[] = ["ipam", "jobs", "audit", "import", "system", "admin"];

interface OpenStream {
  controller: ReadableStreamDefaultController<Uint8Array>;
  topics: ReadonlySet<Topic>;
}

/** The start of every stream: the reconnection delay in milliseconds, then a comment. */
const HELLO = "retry: 3000\n: connected\n\n";

const streams = new Set<OpenStream>();
const encoder = new TextEncoder();

function frame(event: string, data: unknown, id?: number | null): string {
  const lines = [];
  if (id !== undefined && id !== null) lines.push(`id: ${id}`);
  lines.push(`event: ${event}`, `data: ${JSON.stringify(data)}`);
  return `${lines.join("\n")}\n\n`;
}

function eventFrame(event: MockEvent): string {
  return frame(event.topic, event.data, event.id);
}

function resetFrame(reason: "lagged" | "gap" | "journal", revision: number = db.revision): string {
  return frame("reset", { reason, revision }, revision);
}

function write(stream: OpenStream, text: string): void {
  try {
    stream.controller.enqueue(encoder.encode(text));
  } catch {
    // The reader went away.
    streams.delete(stream);
  }
}

function parseTopics(raw: string | null): ReadonlySet<Topic> {
  const names = (raw ?? "")
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t !== "");
  if (names.length === 0) return new Set(TOPICS);
  const set = new Set<Topic>();
  for (const name of names) {
    if (!(TOPICS as readonly string[]).includes(name)) {
      return fail("sys.events.unknown_topic", { params: { topic: name } });
    }
    set.add(name as Topic);
  }
  return set;
}

/** The frames a new stream starts with: the replay after `from`, or a reset. */
function replay(from: number | null, topics: ReadonlySet<Topic>): string[] {
  if (from === null || from === db.revision) return [];
  if (from > db.revision) return [resetFrame("gap")];
  const oldest = db.journal[0]?.id ?? null;
  // Everything after `from` must still be in the journal.
  if (oldest === null || oldest > from + 1) return [resetFrame("gap")];
  return db.journal.filter((e) => (e.id ?? 0) > from && topics.has(e.topic)).map(eventFrame);
}

function parseRevision(raw: string): number | null {
  return /^\d+$/.test(raw.trim()) ? Number(raw.trim()) : null;
}

const events = route("get", "/api/v1/events", (ctx) => {
  requireSession();
  const topics = parseTopics(ctx.query("topics"));

  let from: number | null = null;
  const fromParam = ctx.query("from");
  if (fromParam !== null) {
    from = parseRevision(fromParam);
    if (from === null) return fail("sys.invalid_query", { params: { name: "from", value: fromParam } });
  }
  // `Last-Event-ID` wins on reconnects; a malformed one cannot be served (the far future).
  const lastEventId = ctx.header("last-event-id");
  if (lastEventId !== null) from = parseRevision(lastEventId) ?? Number.MAX_SAFE_INTEGER;

  // The first chunk carries the retry hint and the replay, like the server's. It must not
  // be empty: msw answers a request in Node only once the body has produced a chunk.
  const first = `${HELLO}${replay(from, topics).join("")}`;
  let open: OpenStream | undefined;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      open = { controller, topics };
      controller.enqueue(encoder.encode(first));
      streams.add(open);
    },
    cancel() {
      if (open) streams.delete(open);
    },
  });
  ctx.request.signal.addEventListener(
    "abort",
    () => {
      if (!open) return;
      streams.delete(open);
      try {
        open.controller.close();
      } catch {
        // Already closed.
      }
    },
    { once: true },
  );
  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/event-stream", "cache-control": "no-cache", "x-accel-buffering": "no" },
  });
});

// Live events and resets reach every open stream.
subscribeEvents((event) => {
  const text = eventFrame(event);
  for (const stream of [...streams]) if (stream.topics.has(event.topic)) write(stream, text);
});

onMockReset((revision) => {
  const text = resetFrame("journal", revision);
  for (const stream of [...streams]) write(stream, text);
});

// ---------------------------------------------------------------------------------
// For tests and the dev console

export type EmitData = Partial<Omit<MockEventData, "topic" | "revision">>;

/**
 * Emits an event as a store change would: the revision rises, the journal keeps it (so a
 * later `from=` replays it) and every stream that follows the topic receives it.
 */
export function emitMockEvent(topic: Topic, data: EmitData = {}): MockEvent {
  if (!(TOPICS as readonly string[]).includes(topic)) throw new Error(`unknown topic ${String(topic)}`);
  return recordEvent(topic, data);
}

/** Emits an alarm: no revision, no id, not replayed. */
export function emitMockAlarm(topic: Topic, data: EmitData = {}): MockEvent {
  return recordAlarm(topic, data);
}

/** Sends a `reset` or `shutdown` control event to every open stream. */
export function emitMockControl(kind: "reset" | "shutdown", reason: "lagged" | "gap" | "journal" = "lagged"): void {
  const text = kind === "reset" ? resetFrame(reason) : frame("shutdown", {});
  for (const stream of [...streams]) write(stream, text);
}

/** The number of open streams. */
export function openStreamCount(): number {
  return streams.size;
}

/** Advances the running job every `intervalMs` (15 s by default) and tells the streams. */
export function startJobTicker(intervalMs = 15_000): () => void {
  const timer = setInterval(() => {
    advanceMockJobs();
  }, intervalMs);
  return () => clearInterval(timer);
}

export const eventRoutes: HttpHandler[] = [events];
