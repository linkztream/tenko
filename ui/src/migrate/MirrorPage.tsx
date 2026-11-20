// A mirrored source (/connectors/mirrors/:id/:tab?): the three tabs of plan section 3.3. Scopes
// lists each mirrored scope and shows the diff of the one chosen against Tenko's scope of the
// same network (the Prepare, Take over and Revert actions arrive with WP14.2); Losses lists the
// loss report and acknowledges entries; Settings changes the name, the interval and whether
// pushes are accepted, replaces the token, shows the PowerShell commands and deletes the mirror.
import { A, useNavigate, useParams } from "@solidjs/router";
import { createResource, For, Match, Show, Switch } from "solid-js";
import { decodeSegment, paths } from "../app/paths";
import { ErrorNotice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";
import { getMirror } from "./api";
import { MirrorCard } from "./MirrorCards";
import { LossesTab, ScopesTab, SettingsTab } from "./MirrorTabs";
import { MIRROR_TABS, migratePaths, type MirrorTab } from "./paths";

export default function MirrorPage() {
  const params = useParams<{ id: string; tab?: string }>();
  const navigate = useNavigate();
  const id = () => decodeSegment(params.id);
  const tab = (): MirrorTab => (MIRROR_TABS.includes(params.tab as MirrorTab) ? (params.tab as MirrorTab) : "scopes");
  const [mirror, { refetch }] = createResource(id, (key) => getMirror(key));
  return (
    <div class="page" data-testid="page-migrate-mirror" data-id={id()}>
      <PageHead crumbs={<A href={paths.connectors()}>{t("shell.nav.connectors")}</A>} title={t("migrate.mirror.title")} sub={<span class="mono">{mirror.latest?.name ?? id()}</span>} />
      <ErrorNotice error={mirror.error} />
      <div class="tabs" role="tablist" aria-label={t("migrate.mirror.tabs")}>
        <For each={MIRROR_TABS}>
          {(name) => (
            <button type="button" role="tab" aria-selected={tab() === name} data-testid={`mirror-tab-${name}`} onClick={() => navigate(migratePaths.mirror(id(), name))}>
              {t(`migrate.mirror.tab.${name}`)}
            </button>
          )}
        </For>
      </div>
      <div role="tabpanel" data-testid="mirror-panel" data-tab={tab()}>
        <Show when={mirror.latest}>
          {(m) => (
            <Switch>
              <Match when={tab() === "scopes"}>
                <MirrorCard mirror={m()} />
                <ScopesTab mirror={m()} />
              </Match>
              <Match when={tab() === "losses"}>
                <LossesTab mirror={m()} onChange={() => void refetch()} />
              </Match>
              <Match when={tab() === "settings"}>
                <SettingsTab mirror={m()} onChange={() => void refetch()} onDeleted={() => navigate(paths.connectors())} />
              </Match>
            </Switch>
          )}
        </Show>
      </div>
    </div>
  );
}
