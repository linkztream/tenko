// Keeps the router out of the areas of modules this installation does not run: a path that
// belongs to a switched-off module shows a short page instead of the area. Everything else
// passes through. The page itself loads lazily, so the gate costs the first load nothing.
import { useLocation } from "@solidjs/router";
import { createMemo, lazy, Show, type JSX } from "solid-js";
import { withPacks } from "../i18n";
import { moduleRunning, pathModule } from "./modules";

const ModuleDisabled = lazy(withPacks(["updates"], () => import("./ModuleDisabled")));

export function ModuleGate(props: { children?: JSX.Element }) {
  const location = useLocation();
  const off = createMemo(() => {
    const name = pathModule(location.pathname);
    return name !== null && !moduleRunning(name) ? name : null;
  });
  return (
    <Show when={off()} fallback={props.children}>
      {(name) => <ModuleDisabled module={name()} />}
    </Show>
  );
}
