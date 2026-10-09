import { Navigate, Router, useLocation, useNavigate, useSearchParams, type RouteDefinition, type RouteSectionProps } from "@solidjs/router";
import { createEffect, lazy, Match, onMount, Switch, type Component, type JSX } from "solid-js";
import { collectRoutes, topSegment, type AppRoute } from "./app/router";
import { paths, safeNext } from "./app/paths";
import { authState, isAdmin, onSessionExpired } from "./auth/session";
import { IconSprite } from "./components/Icon";
import { Toasts } from "./components/toast";
import { t } from "./i18n";
import { AREAS } from "./shell/areas";
import Forbidden from "./shell/pages/Forbidden";
import Splash from "./shell/pages/Splash";
import { Shell } from "./shell/Shell";

const Placeholder = lazy(() => import("./shell/pages/Placeholder"));
const NotFound = lazy(() => import("./shell/pages/NotFound"));

const PRODUCT = "Tenko DDI";

/** Root of the router: the icon sprite, the toasts and session expiry handling. */
export function Root(props: RouteSectionProps) {
  const navigate = useNavigate();
  const location = useLocation();
  onMount(() =>
    onSessionExpired(() => navigate(paths.signIn(location.pathname + location.search), { replace: true })),
  );
  return (
    <>
      <IconSprite />
      {props.children}
      <Toasts />
    </>
  );
}

/** The shell for signed-in users; everyone else goes where they belong. */
function ShellGate(props: RouteSectionProps) {
  const location = useLocation();
  return (
    <Switch>
      <Match when={authState() === "loading"}>
        <Splash />
      </Match>
      <Match when={authState() === "setup"}>
        <Navigate href={paths.setup()} />
      </Match>
      <Match when={authState() === "signed-out"}>
        <Navigate href={paths.signIn(location.pathname + location.search)} />
      </Match>
      <Match when={authState() === "signed-in"}>
        <Shell>{props.children}</Shell>
      </Match>
    </Switch>
  );
}

/** A focused page (sign-in, setup) for the state it belongs to. */
function FocusGate(props: { access: "public" | "setup" | "session" | "admin"; children: JSX.Element }) {
  const [params] = useSearchParams();
  const next = () => safeNext(typeof params.next === "string" ? params.next : undefined);
  return (
    <Switch>
      <Match when={authState() === "loading"}>
        <Splash />
      </Match>
      <Match when={props.access === "public"}>
        <Switch fallback={props.children}>
          <Match when={authState() === "signed-in"}>
            <Navigate href={next()} />
          </Match>
          <Match when={authState() === "setup"}>
            <Navigate href={paths.setup()} />
          </Match>
        </Switch>
      </Match>
      <Match when={props.access === "setup"}>
        <Switch fallback={props.children}>
          <Match when={authState() === "signed-out"}>
            <Navigate href={paths.signIn()} />
          </Match>
        </Switch>
      </Match>
      <Match when={authState() === "signed-in"}>{props.children}</Match>
      <Match when={true}>
        <Navigate href={paths.signIn()} />
      </Match>
    </Switch>
  );
}

function decorate(route: AppRoute): Component<RouteSectionProps> {
  const Inner = route.component;
  const titled: Component<RouteSectionProps> = (props) => {
    createEffect(() => {
      document.title = route.title ? `${t(route.title)} - ${PRODUCT}` : PRODUCT;
    });
    return route.access === "admin" && !isAdmin() ? <Forbidden /> : <Inner {...props} />;
  };
  if ((route.layout ?? "shell") === "shell") return titled;
  const access = route.access ?? "session";
  const Titled = titled;
  return (props) => (
    <FocusGate access={access}>
      <Titled {...props} />
    </FocusGate>
  );
}

/** The route tree: focused pages, then the shell with every area inside it. */
export function buildRoutes(all: AppRoute[] = collectRoutes()): RouteDefinition[] {
  const shell = all.filter((r) => (r.layout ?? "shell") === "shell");
  const focus = all.filter((r) => r.layout === "focus");
  const claimed = new Set(shell.map((r) => topSegment(r.path)));
  const placeholders: RouteDefinition[] = AREAS.filter((a) => a.path !== "/" && !claimed.has(topSegment(a.path))).map(
    (a) => ({ path: `${a.path}/*rest`, component: Placeholder }),
  );
  return [
    ...focus.map((r) => ({ path: r.path, component: decorate(r) })),
    {
      path: "/",
      component: ShellGate,
      children: [
        ...shell.map((r) => ({ path: r.path, component: decorate(r) })),
        ...placeholders,
        { path: "*404", component: NotFound },
      ],
    },
  ];
}

export default function App() {
  return <Router root={Root}>{buildRoutes()}</Router>;
}
