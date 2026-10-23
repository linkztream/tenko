// The default resolution of the forwarders page (WP10.4, recursion plan section 2.7, REC-Q2): how
// each view gets the names that no zone and no forwarding rule covers. Recurse (resolve them from
// the root servers), forward (to the default forwarder of the configuration file, `[dns]
// forwarders`) or refuse; "default" follows the profile, whose value is shown beside it (recurse
// under every profile). The implicit default view is no row, so it shows the profile's value
// only. A root rule covers every name of the views it applies in, so the block says when the
// default resolution is not reached. Those who may write DNS change a view's resolution here; the
// change goes to the view with its revision.
import { createSignal, For, Show } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { errorMessage } from "../../api/problem";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { mayWriteDns } from "../access";
import { listViews, updateView, type ViewItem } from "../views/api";

export type ResolutionChoice = "recurse" | "forward" | "refuse" | "default";

const CHOICES: readonly ResolutionChoice[] = ["default", "recurse", "forward", "refuse"];

/** The words of a choice; "default" names the profile's value. */
function choiceText(choice: ResolutionChoice, profile: "recurse" | "forward" | "refuse"): string {
  return choice === "default" ? t("dns.fwd.resolution.choice.default", { profile: t(`dns.fwd.resolution.mode.${profile}`) }) : t(`dns.resolution.${choice}`);
}

/** What a view's select shows: its own resolution, or `default`. */
export function choiceOf(view: Pick<ViewItem, "resolution">): ResolutionChoice {
  return view.resolution ?? "default";
}

/** The resolution in force for a view: its own, else the profile's. */
export function effectiveResolution(view: Pick<ViewItem, "resolution" | "profile_resolution">): "recurse" | "forward" | "refuse" {
  return view.resolution ?? view.profile_resolution;
}

function ViewRow(props: { view: ViewItem; onChanged: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const change = async (choice: ResolutionChoice) => {
    if (busy() || choice === choiceOf(props.view)) return;
    setBusy(true);
    try {
      await updateView(props.view, choice === "default" ? { default_resolution: true } : { resolution: choice });
      toast({ kind: "ok", title: t("dns.fwd.resolution.saved", { view: props.view.name }) });
      props.onChanged();
    } catch (err) {
      toast({ kind: "bad", title: t("dns.fwd.resolution.failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <tr data-testid="fwd-resolution-view" data-key={props.view.name} data-choice={choiceOf(props.view)} data-effective={effectiveResolution(props.view)}>
      <td>{props.view.name}</td>
      <td>
        <Show
          when={mayWriteDns()}
          fallback={<span>{choiceText(choiceOf(props.view), props.view.profile_resolution)}</span>}
        >
          <select
            class="select"
            aria-label={t("dns.fwd.resolution.of", { view: props.view.name })}
            value={choiceOf(props.view)}
            disabled={busy()}
            data-testid="fwd-resolution-select"
            onChange={(event) => void change(event.currentTarget.value as ResolutionChoice)}
          >
            <For each={CHOICES}>
              {(choice) => <option value={choice}>{choiceText(choice, props.view.profile_resolution)}</option>}
            </For>
          </select>
        </Show>
      </td>
    </tr>
  );
}

export function DefaultResolution(props: { hasRootRule: boolean }) {
  const query = createLiveQuery({ topics: ["dns"], fetch: (signal) => listViews(signal).then((page) => ({ value: page.items, revision: page.revision })) });
  const views = () => latest(query) ?? [];
  // The profile's value as the views report it; recurse under every profile when there is none.
  const profile = () => views()[0]?.profile_resolution ?? "recurse";
  return (
    <section class="page-section dns-fwd-side" aria-labelledby="dns-fwd-resolution-title" data-testid="fwd-resolution">
      <h2 id="dns-fwd-resolution-title">{t("dns.fwd.resolution.title")}</h2>
      <p>{t("dns.fwd.resolution.lede")}</p>
      <Show when={props.hasRootRule}>
        <p class="muted" data-testid="fwd-resolution-root">
          {t("dns.fwd.resolution.root_rule")}
        </p>
      </Show>
      <div class="table-wrap">
        <table class="plain">
          <caption class="sr-only">{t("dns.fwd.resolution.title")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("dns.fwd.resolution.col.view")}</th>
              <th scope="col">{t("dns.fwd.resolution.col.resolution")}</th>
            </tr>
          </thead>
          <tbody>
            <tr data-testid="fwd-resolution-default" data-effective={profile()}>
              <td>{t("dns.fwd.resolution.default_view")}</td>
              <td>{t("dns.fwd.resolution.choice.default", { profile: t(`dns.fwd.resolution.mode.${profile()}`) })}</td>
            </tr>
            <For each={views()}>{(view) => <ViewRow view={view} onChanged={() => query.refetch()} />}</For>
          </tbody>
        </table>
      </div>
    </section>
  );
}
