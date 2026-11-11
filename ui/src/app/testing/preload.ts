// Loads the lazy pages a test file opens before its tests run. A page of the route table is a lazy
// chunk (with its message packs, `withPacks`), which the test environment transforms and compiles
// the first time it is shown: on a loaded machine that takes seconds, longer than a `findBy` waits,
// so the first test that opened a page failed while the same test passed alone. Loaded here, in a
// `beforeAll` with a limit of its own, every test waits only for what it tests.
import type { Component } from "solid-js";
import { collectRoutes } from "../router";

/** A component made by Solid's `lazy`, which can load its chunk ahead of the first render. */
type Preloadable = Component & { preload?: () => Promise<unknown> };

/** Whether the route pattern `path` (`:param`, `:param?`, `*rest`) matches the path of `url`. */
export function routeMatches(path: string, url: string): boolean {
  const pattern = path.split("/").filter(Boolean);
  const parts = (url.split(/[?#]/)[0] ?? "").split("/").filter(Boolean);
  let at = 0;
  for (const segment of pattern) {
    if (segment.startsWith("*")) return true;
    if (segment.startsWith(":")) {
      if (at < parts.length) at += 1;
      else if (!segment.endsWith("?")) return false;
      continue;
    }
    if (parts[at] !== segment) return false;
    at += 1;
  }
  return at === parts.length;
}

/**
 * Loads the component of every route of the application that matches one of `urls`, and the
 * `extra` modules (the lazy parts a page loads itself, such as the dashboard's update card).
 */
export async function preloadPages(urls: readonly string[], extra: readonly (() => Promise<unknown>)[] = []): Promise<void> {
  const pages = collectRoutes()
    .filter((route) => urls.some((url) => routeMatches(route.path, url)))
    .map((route) => (route.component as Preloadable).preload?.());
  await Promise.all([...pages, ...extra.map((load) => load())]);
}
