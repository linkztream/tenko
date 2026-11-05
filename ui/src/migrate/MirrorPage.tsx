// A mirrored source (/connectors/mirrors/:id/:tab?): the three tabs of plan section 3.3, Scopes
// (each mirrored scope with its Tenko counterpart, the diff and the Prepare, Take over and
// Revert actions), Losses (the entries with their acknowledgment) and Settings (name, token,
// fingerprint, the PowerShell commands, deletion). WP14.0 stubs the route and the tabs; WP14.1
// and WP14.2 fill them.
import { A, useNavigate, useParams } from "@solidjs/router";
import { For } from "solid-js";
import { decodeSegment, paths } from "../app/paths";
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";
import { MIRROR_TABS, migratePaths, type MirrorTab } from "./paths";

export default function MirrorPage() {
  const params = useParams<{ id: string; tab?: string }>();
  const navigate = useNavigate();
  const id = () => decodeSegment(params.id);
  const tab = (): MirrorTab => (MIRROR_TABS.includes(params.tab as MirrorTab) ? (params.tab as MirrorTab) : "scopes");
  return (
    <div class="page" data-testid="page-migrate-mirror" data-id={id()}>
      <PageHead crumbs={<A href={paths.connectors()}>{t("shell.nav.connectors")}</A>} title={t("migrate.mirror.title")} sub={<span class="mono">{id()}</span>} />
      <div class="tabs" role="tablist" aria-label={t("migrate.mirror.tabs")}>
        <For each={MIRROR_TABS}>
          {(name) => (
            <button type="button" role="tab" aria-selected={tab() === name} data-testid={`mirror-tab-${name}`} onClick={() => navigate(migratePaths.mirror(id(), name))}>
              {t(`migrate.mirror.tab.${name}`)}
            </button>
          )}
        </For>
      </div>
      <div class="empty" role="tabpanel" data-testid="migrate-coming" data-tab={tab()}>
        <h2>{t("migrate.coming.title")}</h2>
        <p>{t("migrate.coming.body")}</p>
        <A class="btn" href={paths.connectors()} data-testid="migrate-coming-back">
          {t("migrate.coming.connectors")}
        </A>
      </div>
    </div>
  );
}
