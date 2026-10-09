// Helpers of the audit tests: the mock API's events delivered to the views, and a list that
// is scrolled away from the top.
import { fireEvent } from "@solidjs/testing-library";
import { vi } from "vitest";
import { events, type ApiEvent, type Topic } from "../api/events";
import { subscribeEvents } from "../api/mock/db";

interface Subscription {
  topic: Topic;
  handler: (event: ApiEvent) => void;
}

/**
 * Delivers the events the mock API raises (appendAudit and every other write) to the
 * handlers views registered on the tab's stream. The stream itself needs an EventSource,
 * which the test environment lacks. Returns the function that stops the delivery.
 */
export function bridgeMockEvents(): () => void {
  const live = new Set<Subscription>();
  vi.spyOn(events, "subscribe").mockImplementation((topic, handler) => {
    const entry: Subscription = { topic, handler };
    live.add(entry);
    return () => {
      live.delete(entry);
    };
  });
  const stop = subscribeEvents((mock) => {
    const event: ApiEvent = {
      topic: mock.topic,
      type: mock.topic,
      objects: mock.data.objects,
      deleted: mock.data.deleted,
      revision: mock.id ?? undefined,
      data: mock.data as unknown as Record<string, unknown>,
    };
    for (const entry of [...live]) if (entry.topic === mock.topic) entry.handler(event);
  });
  return () => {
    stop();
    live.clear();
  };
}

/** Scrolls the scroll container of a grid, which jsdom does not lay out, and tells the grid. */
export function scrollGridTo(grid: HTMLElement, top: number): HTMLElement {
  const wrap = grid.querySelector<HTMLElement>(".grid-wrap");
  if (!wrap) throw new Error("the grid has no scroll container");
  Object.defineProperty(wrap, "scrollTop", { value: top, configurable: true, writable: true });
  fireEvent.scroll(wrap);
  return wrap;
}
