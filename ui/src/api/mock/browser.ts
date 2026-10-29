// The mock API in the browser (npm run dev:mock): the same handlers as the tests, answered
// by a service worker, with an artificial latency so loading states show up.
//
// Pick a scenario with `?mock-scenario=signed-in` in the URL, or with
// `localStorage["tenko-mock-scenario"]`; `window.tenkoMock.reset("lab")` switches at run time
// and remembers the choice. The state lives in the page: a reload starts the scenario again.
//
// Fallback mode: a service worker cannot always be registered (an insecure origin such as
// http://<LAN address>, or a browser that refuses the script). Then `fetch` and
// XMLHttpRequest are intercepted in the page instead, and the event stream is read with
// `fetch` as well (see event-source.ts).
import { delay, http } from "msw";
import { setupWorker } from "msw/browser";
import { defineNetwork, InterceptorSource } from "msw/experimental";
import { FetchInterceptor } from "@mswjs/interceptors/fetch";
import { XMLHttpRequestInterceptor } from "@mswjs/interceptors/XMLHttpRequest";
import type { Topic } from "../events";
import { DEFAULT_SCENARIO, MOCK_SCENARIOS, isMockScenario, resetMockDb, type MockScenario } from "./db";
import { FetchEventSource } from "./event-source";
import { handlers } from "./handlers";
import { setMockViewFindingsDefault } from "./reconcile-view";
import { emitMockControl, emitMockEvent, setMockHostMetrics, startJobTicker, startMetricsSampler, type EmitData } from "./sse";

const QUERY_KEY = "mock-scenario";
const STORAGE_KEY = "tenko-mock-scenario";

/** What the dev console offers as `window.tenkoMock`. */
export interface TenkoMock {
  /** Starts over in a scenario (default `signed-out`) and remembers it for the next reload. */
  reset(scenario?: MockScenario): void;
  /** Emits an event as a store change would, for example `emit("jobs", { objects: [] })`. */
  emit(topic: Topic, data?: EmitData): void;
  /** Sends `reset` or `shutdown` to every open event stream. */
  control(kind: "reset" | "shutdown"): void;
  readonly scenarios: readonly MockScenario[];
}

declare global {
  interface Window {
    tenkoMock?: TenkoMock;
  }
}

function storedScenario(): MockScenario | null {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return isMockScenario(stored) ? stored : null;
  } catch {
    return null;
  }
}

function remember(scenario: MockScenario): void {
  try {
    localStorage.setItem(STORAGE_KEY, scenario);
  } catch {
    // Storage is blocked: the choice only lasts until the reload.
  }
}

/** The URL parameter wins over the stored choice. */
function chosenScenario(): MockScenario {
  const fromUrl = new URLSearchParams(window.location.search).get(QUERY_KEY);
  if (isMockScenario(fromUrl)) return fromUrl;
  return storedScenario() ?? DEFAULT_SCENARIO;
}

/** Slows every API request down by 120 to 300 ms, except the event stream. */
const latency = http.all("/api/*", async ({ request }) => {
  if (new URL(request.url).pathname.endsWith("/events")) return;
  await delay(120 + Math.round(Math.random() * 180));
});

/** Intercepts fetch and XMLHttpRequest in the page, for when no service worker can run. */
async function startInPage(): Promise<void> {
  const network = defineNetwork({
    sources: [new InterceptorSource({ interceptors: [new XMLHttpRequestInterceptor(), new FetchInterceptor()] })],
    handlers: [latency, ...handlers],
    onUnhandledFrame: "bypass",
    context: { quiet: true },
  });
  await network.enable();
  // The native EventSource does not go through fetch, so the mock cannot answer it.
  window.EventSource = FetchEventSource as unknown as typeof EventSource;
}

export async function startMockWorker(): Promise<void> {
  // The rows of the reconciliation view are findings here, as on a server (reconcile-view.ts).
  setMockViewFindingsDefault(true);
  resetMockDb(chosenScenario());
  const worker = setupWorker(latency, ...handlers);
  try {
    await worker.start({
      onUnhandledFrame: "bypass",
      quiet: true,
      serviceWorker: { url: "/mockServiceWorker.js" },
    });
  } catch (error) {
    console.warn(
      "[tenko mock] The service worker could not start, so the mock API runs in fallback mode: " +
        "fetch and XMLHttpRequest are intercepted in the page.",
      error,
    );
    await startInPage();
  }
  startJobTicker();
  setMockHostMetrics(true);
  startMetricsSampler();
  window.tenkoMock = {
    reset(scenario: MockScenario = DEFAULT_SCENARIO): void {
      if (!isMockScenario(scenario)) {
        throw new Error(`unknown scenario ${String(scenario)}; use one of ${MOCK_SCENARIOS.join(", ")}`);
      }
      resetMockDb(scenario);
      remember(scenario);
    },
    emit(topic: Topic, data?: EmitData): void {
      emitMockEvent(topic, data);
    },
    control(kind: "reset" | "shutdown"): void {
      emitMockControl(kind);
    },
    scenarios: MOCK_SCENARIOS,
  };
}
