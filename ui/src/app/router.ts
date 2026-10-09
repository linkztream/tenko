// Route registration. Each area folder owns a `routes.ts` that exports `routes: AppRoute[]`;
// the application finds them with import.meta.glob, so adding an area never edits a
// shared file:
//
//   // src/ipam/routes.ts
//   import { lazy } from "solid-js";
//   import type { AppRoute } from "../app/router";
//   export const routes: AppRoute[] = [
//     { path: "/ipam", component: lazy(() => import("./IpamView")), title: "shell.nav.ipam" },
//     { path: "/ipam/prefixes/:network/:length", component: lazy(() => import("./PrefixView")) },
//   ];
//
// Use `lazy()` so every area is its own chunk. Build links with app/paths.ts. A rail area
// without a registered route shows a placeholder.
import type { RouteSectionProps } from "@solidjs/router";
import type { Component } from "solid-js";
import type { MessageKey } from "../i18n";

/**
 * Who may open a route: `public` (signed out only, e.g. sign-in), `setup` (only while
 * first-run setup is open), `session` (any signed-in account, the default) or `admin`.
 */
export type Access = "public" | "setup" | "session" | "admin";

export interface AppRoute {
  /** A @solidjs/router path pattern; `:param`, `:param?` and `*rest` are allowed. */
  path: string;
  component: Component<RouteSectionProps>;
  /** `shell` (rail, top bar and status bar; the default) or `focus` (a page of its own). */
  layout?: "shell" | "focus";
  access?: Access;
  /** The page title, followed by the product name in the browser tab. */
  title?: MessageKey;
}

type RouteModule = { routes?: readonly AppRoute[] };

/** Every route of every area, in a stable order (by folder name). */
export function collectRoutes(
  modules: Record<string, RouteModule> = import.meta.glob<RouteModule>("../*/routes.ts", { eager: true }),
): AppRoute[] {
  return Object.keys(modules)
    .sort()
    .flatMap((k) => modules[k]?.routes ?? []);
}

/** The first path segment a route claims, for example "ipam" for "/ipam/prefixes/:n/:l". */
export function topSegment(path: string): string {
  return path.split("/").filter(Boolean)[0] ?? "";
}
