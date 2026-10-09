// Rendering helpers for component tests: a view inside a memory router at a given URL,
// with the icon sprite and the toast host, as in the application.
import { createMemoryHistory, MemoryRouter, type RouteDefinition, type RouteSectionProps } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import type { Component, JSX } from "solid-js";
import { IconSprite } from "../../components/Icon";
import { Toasts } from "../../components/toast";

export interface RouteRenderOptions {
  /** The URL to start at, for example "/settings/users". */
  url?: string;
  /** The route pattern the view is mounted at (default: the URL's path). */
  path?: string;
  /** Extra routes, for asserting navigation (path to a component). */
  routes?: Record<string, Component<RouteSectionProps>>;
}

function Root(props: RouteSectionProps): JSX.Element {
  return (
    <>
      <IconSprite />
      {props.children}
      <Toasts />
    </>
  );
}

/** Renders `view` at `url` inside a memory router; returns the testing-library result and the history. */
export function renderRoute(view: Component<RouteSectionProps>, options: RouteRenderOptions = {}) {
  const url = options.url ?? "/";
  const history = createMemoryHistory();
  history.set({ value: url });
  const path = options.path ?? url.split("?")[0] ?? "/";
  const routes: RouteDefinition[] = [
    { path, component: view },
    ...Object.entries(options.routes ?? {}).map(([p, c]) => ({ path: p, component: c })),
    { path: "*rest", component: () => <div data-testid="unmatched" /> },
  ];
  const result = render(() => (
    <MemoryRouter history={history} root={Root}>
      {routes}
    </MemoryRouter>
  ));
  return { ...result, history, location: () => history.get() };
}
