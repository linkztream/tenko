// An EventSource that reads the stream with `fetch`. The mock uses it only in the browser's
// fallback mode (no service worker): interception there works on `fetch` and XMLHttpRequest,
// and the native EventSource would bypass it. Like the native one it dispatches `open`,
// `error` and the named events; unlike it, it does not reconnect on its own (the UI's
// EventStream closes on error and reconnects itself, with `from=<last id>`).

type Listener = ((this: FetchEventSource, event: Event) => unknown) | null;

export class FetchEventSource extends EventTarget {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;
  readonly CONNECTING = 0;
  readonly OPEN = 1;
  readonly CLOSED = 2;

  readonly url: string;
  readonly withCredentials: boolean;
  readyState = 0;
  onopen: Listener = null;
  onmessage: Listener = null;
  onerror: Listener = null;

  private readonly abort = new AbortController();
  private lastEventId = "";

  constructor(url: string | URL, init?: EventSourceInit) {
    super();
    this.url = new URL(String(url), window.location.href).href;
    this.withCredentials = init?.withCredentials ?? false;
    for (const type of ["open", "message", "error"] as const) {
      this.addEventListener(type, (event) => {
        const handler = type === "open" ? this.onopen : type === "message" ? this.onmessage : this.onerror;
        handler?.call(this, event);
      });
    }
    void this.connect();
  }

  close(): void {
    this.readyState = FetchEventSource.CLOSED;
    this.abort.abort();
  }

  private fail(): void {
    if (this.readyState === FetchEventSource.CLOSED) return;
    this.readyState = FetchEventSource.CLOSED;
    this.dispatchEvent(new Event("error"));
  }

  private async connect(): Promise<void> {
    try {
      const response = await fetch(this.url, {
        headers: { accept: "text/event-stream" },
        credentials: this.withCredentials ? "include" : "same-origin",
        signal: this.abort.signal,
      });
      const type = response.headers.get("content-type") ?? "";
      if (response.status !== 200 || !type.startsWith("text/event-stream") || !response.body) {
        this.fail();
        return;
      }
      if (this.readyState === FetchEventSource.CLOSED) return;
      this.readyState = FetchEventSource.OPEN;
      this.dispatchEvent(new Event("open"));
      await this.read(response.body);
      this.fail();
    } catch {
      this.fail();
    }
  }

  private async read(body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let event = "";
    let data: string[] = [];
    const flush = () => {
      if (data.length > 0) {
        this.dispatchEvent(
          new MessageEvent(event || "message", {
            data: data.join("\n"),
            lastEventId: this.lastEventId,
            origin: new URL(this.url).origin,
          }),
        );
      }
      event = "";
      data = [];
    };
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      let newline = buffer.indexOf("\n");
      while (newline >= 0) {
        const line = buffer.slice(0, newline).replace(/\r$/, "");
        buffer = buffer.slice(newline + 1);
        newline = buffer.indexOf("\n");
        if (line === "") {
          flush();
          continue;
        }
        if (line.startsWith(":")) continue;
        const colon = line.indexOf(":");
        const field = colon < 0 ? line : line.slice(0, colon);
        let text = colon < 0 ? "" : line.slice(colon + 1);
        if (text.startsWith(" ")) text = text.slice(1);
        if (field === "data") data.push(text);
        else if (field === "event") event = text;
        else if (field === "id" && !text.includes("\0")) this.lastEventId = text;
      }
    }
  }
}
