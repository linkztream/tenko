// Live updates over server-sent events (ADR 0008, API-05).
//
// One stream per tab, filtered by topic. Event ids are store revisions; the stream
// resumes from the last id it saw. Events carry references, not bodies: a view refetches
// what it shows (see live.ts). A `reset` event means the server could not replay what this
// client missed (it lagged or fell out of the replay ring): every subscriber of the
// affected topics reloads its state.
//
// Reconnects use jittered exponential backoff so that a restarted controller is not hit
// by every browser at the same instant. The browser's own EventSource retry is not used:
// the stream is closed on error and reopened with `from=<id>` in the query (EventSource
// cannot set the Last-Event-ID header on a new connection; the server treats both alike).
//
// A view reads its list at a revision R and follows the stream (see `resumeFrom`): it is told
// of every change after R. A page subscribes and reads at once, and the server may take the
// subscription after the read; a connection opened without a position, or at a later one than R,
// is therefore opened again from R (or from the last id seen, if older), and the server replays
// what came after it or sends `reset` when it no longer can.
//
// A stream lasts as long as the session that opened it. The server ends it with an `end`
// event: `access_changed` (what the session may read changed) reopens it after the first
// backoff step; `access_ended` also asks the server whether the session still acts, as a
// request would: a 401 takes the user to the sign-in page (the unauthorized handler of the
// API client) and the stream stops instead of reconnecting. A connection that fails before it opens asks the same
// question, since EventSource does not tell a 401 from a network failure.
import { createSignal, type Accessor } from "solid-js";
import { api } from "./client";
import { isApiError } from "./problem";

/**
 * Topics of GET /events; `admin` covers users, sessions, tokens and security settings,
 * `secrets` the metadata, reveal stamps and host bindings of operator secrets (never values),
 * `cluster` the enrolled nodes and enrollment tokens (never a token's text), `connectors` the
 * connector instances and plugins, `discovery` the observed facts and last sightings (table-level
 * events that name no object), `metrics` one snapshot of the controllers' metrics per second
 * (only for a stream that names it; the start page opens a stream of its own for it), `dns` the
 * zones, records, views, forwarders, access lists, keys and block lists of the DNS module, `dhcp` the
 * scopes, leases and policies of the DHCP module, `findings` the changes of the findings index (U1).
 */
export type Topic =
  | "ipam"
  | "jobs"
  | "audit"
  | "import"
  | "system"
  | "admin"
  | "connectors"
  | "discovery"
  | "secrets"
  | "cluster"
  | "metrics"
  | "dns"
  | "dhcp"
  | "findings";
export const TOPICS: readonly Topic[] = ["ipam", "jobs", "audit", "import", "system", "admin", "connectors", "discovery", "secrets", "cluster", "metrics", "dns", "dhcp", "findings"];

export interface ObjectRef {
  kind: string;
  id: string;
}

export interface ApiEvent {
  topic: Topic;
  /** The SSE event name: the topic, or a kind such as `reset`. */
  type: string;
  /** Objects created or changed. */
  objects: ObjectRef[];
  /** Objects removed from the store. */
  deleted: ObjectRef[];
  /** The store revision (the SSE id); absent for alarms that are not store changes. */
  revision: number | undefined;
  data: Record<string, unknown>;
}

export type ConnectionState = "idle" | "connecting" | "live" | "reconnecting" | "offline";

export interface BackoffOptions {
  /** First retry delay cap in milliseconds. */
  baseMs: number;
  /** Largest delay cap in milliseconds. */
  maxMs: number;
}

/** Delay before reconnect attempt `attempt` (0-based): uniform in [cap/2, cap]. */
export function backoffDelay(attempt: number, options: BackoffOptions, random: () => number = Math.random): number {
  const cap = Math.min(options.maxMs, options.baseMs * 2 ** Math.min(attempt, 30));
  return Math.round(cap / 2 + random() * (cap / 2));
}

export interface EventStreamOptions {
  url?: string;
  /**
   * Topics the stream always names besides those with a subscriber; default `system`, so the
   * tab's stream is never opened without topics (which would mean every topic). A stream for
   * one topic passes an empty list.
   */
  baseTopics?: readonly Topic[];
  backoff?: BackoffOptions;
  random?: () => number;
  /** Injected for tests. */
  createEventSource?: (url: string) => EventSource;
  /**
   * Whether the session still acts; `false` stops the stream. By default a request for the
   * session, whose 401 also sends the user to the sign-in page.
   */
  sessionActs?: () => Promise<boolean>;
}

/** Asks the server for the session, as any request would: a 401 says it ended. */
async function sessionActs(): Promise<boolean> {
  try {
    // A session that must change its password may make no other request: its stream neither.
    const session = await api.get("/api/v1/auth/session");
    return !session.flags.password_change_required;
  } catch (err) {
    return !(isApiError(err) && err.status === 401);
  }
}

type Handler = (event: ApiEvent) => void;

const RESET = "reset";
const SHUTDOWN = "shutdown";
const END = "end";

export class EventStream {
  readonly state: Accessor<ConnectionState>;
  /** Time of the last event (ms since the epoch), for the status bar. */
  readonly lastEventAt: Accessor<number | null>;
  private readonly setState: (s: ConnectionState) => void;
  private readonly setLastEventAt: (t: number | null) => void;

  private readonly url: string;
  private readonly baseTopics: readonly Topic[];
  private readonly backoff: BackoffOptions;
  private readonly random: () => number;
  private readonly create: (url: string) => EventSource;
  private readonly sessionActs: () => Promise<boolean>;

  private readonly supported: boolean;
  private source: EventSource | undefined;
  private connectedTopics = "";
  private attempt = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private topicTimer: ReturnType<typeof setTimeout> | undefined;
  private running = false;
  /** Counts the stops, so that an answer that arrives after one is not taken for this run. */
  private run = 0;
  private lastId: string | null = null;
  /**
   * The revision after which the connections of this run have delivered every change: the
   * position the first of them opened at, kept while each reconnect resumes from the last id.
   * `null` after a connection opened without a position.
   */
  private complete: number | null = null;
  private readonly handlers = new Map<Topic, Set<Handler>>();
  private readonly resetHandlers = new Map<Topic, Set<() => void>>();
  private readonly onOnline = () => this.reconnectNow();
  private readonly onOffline = () => {
    this.close();
    this.setState("offline");
  };

  constructor(options: EventStreamOptions = {}) {
    this.url = options.url ?? "/api/v1/events";
    this.baseTopics = options.baseTopics ?? ["system"];
    this.backoff = options.backoff ?? { baseMs: 1000, maxMs: 30_000 };
    this.random = options.random ?? Math.random;
    this.create = options.createEventSource ?? ((u) => new EventSource(u, { withCredentials: true }));
    this.sessionActs = options.sessionActs ?? sessionActs;
    this.supported = options.createEventSource !== undefined || typeof EventSource !== "undefined";
    const [state, setState] = createSignal<ConnectionState>("idle");
    const [lastEventAt, setLastEventAt] = createSignal<number | null>(null);
    this.state = state;
    this.setState = setState;
    this.lastEventAt = lastEventAt;
    this.setLastEventAt = setLastEventAt;
  }

  /** The id of the last event seen (a revision), or null. */
  get lastEventId(): string | null {
    return this.lastId;
  }

  /**
   * Makes the stream tell of every change after `revision`, the revision a list was read at.
   * A stream whose connections have delivered every change since a revision at or before this
   * one keeps them. Otherwise (not started yet, opened without a position, or after this
   * revision) it starts or opens again from the oldest of this revision and the last id seen:
   * the frames after that id may still be on their way to other views.
   */
  resumeFrom(revision: number): void {
    if (!Number.isFinite(revision)) return;
    if (this.complete !== null && revision >= this.complete) return;
    const last = this.lastId === null ? Number.NaN : Number(this.lastId);
    this.lastId = String(Number.isNaN(last) ? revision : Math.min(revision, last));
    // A connection that is waiting to reconnect takes the new position when it does.
    if (this.running && this.source !== undefined) this.reconnectNow();
  }

  /** Calls `handler` for every event of `topic`. Returns the unsubscribe function. */
  subscribe(topic: Topic, handler: Handler): () => void {
    return this.add(this.handlers, topic, handler);
  }

  /** Calls `handler` when the server asks every client to reload (a `reset` event). */
  onReset(topic: Topic, handler: () => void): () => void {
    return this.add(this.resetHandlers, topic, handler);
  }

  start(): void {
    // Without an EventSource (tests, very old browsers) the UI works without live updates.
    if (this.running || !this.supported) return;
    this.running = true;
    if (typeof window !== "undefined") {
      window.addEventListener("online", this.onOnline);
      window.addEventListener("offline", this.onOffline);
    }
    this.connect();
  }

  stop(): void {
    this.running = false;
    this.run += 1;
    // The views of the next run read their lists again and position it.
    this.complete = null;
    this.lastId = null;
    this.connectedTopics = "";
    clearTimeout(this.timer);
    clearTimeout(this.topicTimer);
    this.timer = undefined;
    this.close();
    if (typeof window !== "undefined") {
      window.removeEventListener("online", this.onOnline);
      window.removeEventListener("offline", this.onOffline);
    }
    this.setState("idle");
  }

  private add<T>(map: Map<Topic, Set<T>>, topic: Topic, fn: T): () => void {
    let set = map.get(topic);
    if (!set) map.set(topic, (set = new Set()));
    set.add(fn);
    this.topicsChanged();
    return () => {
      set.delete(fn);
      if (set.size === 0) map.delete(topic);
      this.topicsChanged();
    };
  }

  /** The topics with a subscriber, sorted, with the base topics (by default `system`, for resets). */
  topics(): Topic[] {
    const all = new Set<Topic>([...this.baseTopics, ...this.handlers.keys(), ...this.resetHandlers.keys()]);
    return TOPICS.filter((t) => all.has(t));
  }

  private topicsChanged(): void {
    if (!this.running) return;
    clearTimeout(this.topicTimer);
    // Coalesce the subscriptions of one render into one reconnect.
    this.topicTimer = setTimeout(() => {
      if (this.running && this.topics().join(",") !== this.connectedTopics) this.reconnectNow();
    }, 0);
  }

  private reconnectNow(): void {
    if (!this.running) return;
    clearTimeout(this.timer);
    this.timer = undefined;
    this.attempt = 0;
    this.close();
    this.connect();
  }

  private connect(): void {
    if (typeof navigator !== "undefined" && navigator.onLine === false) {
      this.setState("offline");
      return;
    }
    const topics = this.topics();
    const before = this.connectedTopics.split(",");
    this.connectedTopics = topics.join(",");
    const params = new URLSearchParams({ topics: this.connectedTopics });
    if (this.lastId !== null) params.set("from", this.lastId);
    // A topic this connection adds is delivered from its position only.
    const from = this.lastId === null ? Number.NaN : Number(this.lastId);
    const added = topics.some((topic) => !before.includes(topic));
    this.complete = Number.isNaN(from) ? null : added ? from : Math.min(this.complete ?? from, from);
    this.setState(this.attempt === 0 ? "connecting" : "reconnecting");
    const es = this.create(`${this.url}?${params.toString()}`);
    this.source = es;
    let opened = false;
    es.onopen = () => {
      if (this.source !== es) return;
      opened = true;
      this.attempt = 0;
      this.setState("live");
    };
    es.onerror = () => {
      if (this.source !== es) return;
      this.close();
      this.scheduleReconnect();
      // Refused before it opened: perhaps a 401, which EventSource does not report.
      if (!opened) this.stopUnlessSessionActs();
    };
    const listener = (e: Event) => this.dispatch(e as MessageEvent<string>);
    es.addEventListener("message", listener);
    es.addEventListener(RESET, listener);
    es.addEventListener(SHUTDOWN, listener);
    es.addEventListener(END, listener);
    for (const topic of topics) es.addEventListener(topic, listener);
  }

  private scheduleReconnect(): void {
    if (!this.running) return;
    const delay = backoffDelay(this.attempt, this.backoff, this.random);
    this.attempt += 1;
    this.setState("reconnecting");
    clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.connect();
    }, delay);
  }

  private close(): void {
    const es = this.source;
    this.source = undefined;
    if (es) {
      es.onopen = null;
      es.onerror = null;
      es.close();
    }
  }

  private dispatch(e: MessageEvent<string>): void {
    if (e.lastEventId) this.lastId = e.lastEventId;
    this.setLastEventAt(Date.now());
    let data: Record<string, unknown> = {};
    if (typeof e.data === "string" && e.data !== "") {
      try {
        const parsed: unknown = JSON.parse(e.data);
        if (parsed && typeof parsed === "object") data = parsed as Record<string, unknown>;
      } catch {
        data = {};
      }
    }
    const kind = typeof data.kind === "string" ? data.kind : typeof data.type === "string" ? data.type : undefined;
    if (e.type === RESET || kind === RESET) {
      // `{ reason, revision }`: reload at that revision or later.
      this.reset();
      return;
    }
    if (e.type === SHUTDOWN || kind === SHUTDOWN) {
      // The controller is going away: reconnect with backoff to whichever comes back.
      this.close();
      this.scheduleReconnect();
      return;
    }
    if (e.type === END) {
      // `{ reason }`: what the session reads changed (reopen and read what it may), or the
      // session no longer acts (stop, unless the server says otherwise). The reopening waits
      // the first backoff step, so the streams a change ended do not all return at once.
      this.close();
      this.attempt = 0;
      this.scheduleReconnect();
      if (data.reason !== "access_changed") this.stopUnlessSessionActs();
      return;
    }
    const topic = isTopic(data.topic) ? data.topic : isTopic(e.type) ? e.type : undefined;
    if (!topic) return;
    // A store event names its revision in its data. An event whose data names a topic but no
    // revision is a system event (a plugin process that started, a new cluster summary): it
    // has no revision, even though EventSource keeps reporting the id of the event before
    // it in `lastEventId`. Taking that id would make the views drop it as already seen.
    const revision =
      typeof data.revision === "number" ? data.revision : isTopic(data.topic) ? undefined : e.lastEventId ? Number(e.lastEventId) : undefined;
    const event: ApiEvent = {
      topic,
      type: e.type,
      objects: refs(data.objects),
      deleted: refs(data.deleted),
      revision: Number.isFinite(revision) ? revision : undefined,
      data,
    };
    for (const h of [...(this.handlers.get(topic) ?? [])]) h(event);
  }

  /** Stops the stream when the session no longer acts; an answer for an earlier run is ignored. */
  private stopUnlessSessionActs(): void {
    const run = this.run;
    void this.sessionActs().then((acts) => {
      if (!acts && this.running && run === this.run) this.stop();
    });
  }

  private reset(): void {
    for (const set of [...this.resetHandlers.values()]) for (const h of [...set]) h();
  }
}

function isTopic(v: unknown): v is Topic {
  return typeof v === "string" && (TOPICS as readonly string[]).includes(v);
}

function refs(v: unknown): ObjectRef[] {
  return Array.isArray(v) ? v.filter(isObjectRef) : [];
}

function isObjectRef(v: unknown): v is ObjectRef {
  return !!v && typeof v === "object" && typeof (v as ObjectRef).kind === "string" && typeof (v as ObjectRef).id === "string";
}

/** The stream of this tab. The shell starts it after sign-in and stops it on sign-out. */
export const events = new EventStream();
