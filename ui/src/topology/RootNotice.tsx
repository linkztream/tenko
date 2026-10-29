// The root of the map when its sources disagree (UI-Q10): the controller's gateway and the next
// hop of this node's default route are different devices. One note to review above the map with
// "Use this" per candidate; the choice is remembered on the server, so the same disagreement does
// not come back. Under Hardened with no controller allowing writes the note offers no action.
import { createSignal, For, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { errorMessage } from "../api/problem";
import { writesAll } from "../auth/gate";
import { Notice } from "../components/Notice";
import { t } from "../i18n";
import { chooseRoot, getRoot, type RootCandidate, type RootDecision } from "./api";

/** A candidate in words: its label and the source that names it. */
function candidateText(candidate: RootCandidate): string {
  return t(candidate.source === "controller" ? "topology.root.from_controller" : "topology.root.from_route", { label: candidate.label });
}

export function RootNotice(props: { readOnly: boolean; onChosen: () => void }) {
  const live = createLiveQuery<RootDecision>({
    topics: ["discovery", "ipam"],
    fetch: async (signal) => {
      const decision = await getRoot(signal);
      return { value: decision, revision: decision.revision };
    },
  });
  const [busy, setBusy] = createSignal(false);
  const [failure, setFailure] = createSignal<string | null>(null);
  const choose = async (candidate: RootCandidate) => {
    setBusy(true);
    setFailure(null);
    try {
      await chooseRoot(candidate.source);
      live.refetch();
      props.onChosen();
    } catch (err) {
      setFailure(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const mayChoose = () => !props.readOnly && writesAll();
  return (
    <Show when={live.latest()?.open ? live.latest() : undefined}>
      {(decision) => (
        <Notice kind="info" testid="topology-root-notice" title={t("topology.root.disagree")}>
          <span class="muted">{t("topology.root.disagree_hint")}</span>
          <ul class="topology-root-candidates">
            <For each={decision().candidates}>
              {(candidate) => (
                <li data-testid="topology-root-candidate" data-source={candidate.source}>
                  <span>{candidateText(candidate)}</span>
                  <Show when={mayChoose()}>
                    <button type="button" class="btn sm" data-testid="topology-root-use" disabled={busy()} onClick={() => void choose(candidate)}>
                      {t("topology.root.use")}
                    </button>
                  </Show>
                </li>
              )}
            </For>
          </ul>
          <Show when={failure()}>
            {(text) => (
              <span class="topology-root-failure" role="alert">
                {text()}
              </span>
            )}
          </Show>
        </Notice>
      )}
    </Show>
  );
}
