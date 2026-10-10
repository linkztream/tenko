// The connectors (/connectors): the configured instances with their health and last run, and
// the plugins of this node from their manifests (name, version, capabilities, platforms,
// description). Administrators and operators create instances from a usable plugin with a
// form built from its settings schema, run and check them now, enable, disable and delete
// them. Live on the `connectors` topic.
import { A, useNavigate } from "@solidjs/router";
import { createResource, createSignal, For, Show } from "solid-js";
import { paths } from "../app/paths";
import { ConfirmDialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { DataGrid } from "../grid/DataGrid";
import { createColumnState } from "../grid/prefs";
import { createListSource } from "../grid/source";
import type { Column, RowAction } from "../grid/types";
import { formatList, t } from "../i18n";
import { useCommands } from "../shell/commands";
import { listPlugins, type ConnectorView, type PluginInfo } from "./api";
import { ConnectorForm } from "./ConnectorForm";
import { capabilityWord, connectorHealth, healthWord, pluginOf } from "./model";
import { HealthBadge, isConnectorEditor, LastRunText, ProcessText, secondsText, useConnectorActions } from "./Parts";
import "./connectors.css";

function columns(plugins: () => readonly PluginInfo[] | undefined): Column<ConnectorView>[] {
  return [
    {
      id: "name",
      header: () => t("connectors.col.name"),
      width: 200,
      fixed: true,
      text: (c) => c.name,
      render: (c) => (
        <A href={paths.connector(c.id)} class="conn-link" tabIndex={-1}>
          {c.name}
        </A>
      ),
    },
    {
      id: "plugin",
      header: () => t("connectors.col.plugin"),
      width: 190,
      text: (c) => c.plugin,
      render: (c) => (
        <span>
          <span class="mono">{c.plugin}</span> <span class="muted">{pluginOf(plugins(), c.plugin)?.manifest?.version ?? ""}</span>
        </span>
      ),
    },
    {
      id: "health",
      header: () => t("connectors.col.health"),
      width: 130,
      text: (c) => healthWord(connectorHealth(c)),
      render: (c) => <HealthBadge connector={c} />,
    },
    {
      id: "process",
      header: () => t("connectors.col.process"),
      width: 200,
      render: (c) => <ProcessText process={c.health.process} />,
    },
    {
      id: "last_run",
      header: () => t("connectors.col.last_run"),
      width: 240,
      render: (c) => <LastRunText run={c.last_run} />,
    },
    {
      id: "capabilities",
      header: () => t("connectors.col.capabilities"),
      width: 200,
      hidden: true,
      render: (c) => formatList((c.capabilities ?? []).map(capabilityWord)),
    },
    {
      id: "poll",
      header: () => t("connectors.col.poll"),
      width: 130,
      render: (c) => secondsText(c.poll_interval_secs, pluginOf(plugins(), c.plugin)?.manifest?.defaults?.poll_interval_secs ?? 300),
    },
    {
      id: "writes",
      header: () => t("connectors.col.writes"),
      width: 110,
      render: (c) => (
        <Show when={c.writes_enabled} fallback={<span class="muted">{t("connectors.writes.off")}</span>}>
          <span class="flag discrepancy">
            <Icon name="shield" size="xs" />
            {t("connectors.writes.on")}
          </span>
        </Show>
      ),
    },
  ];
}

export default function ConnectorsView() {
  const navigate = useNavigate();
  // Reading a failed resource throws its error at the reader (and breaks the page), so a failed
  // read is kept apart: no plugins, and the error is shown with the plugin cards.
  const [pluginsError, setPluginsError] = createSignal<unknown>(null);
  const [plugins, { refetch: refetchPlugins }] = createResource(async () => {
    try {
      const list = await listPlugins();
      setPluginsError(null);
      return list;
    } catch (err) {
      setPluginsError(err);
      return undefined;
    }
  });
  const source = createListSource<ConnectorView>({
    path: "/api/v1/connectors",
    query: () => ({}),
    rowId: (c) => c.id,
    topics: ["connectors"],
  });
  const actions = useConnectorActions(() => source.reload());
  const [form, setForm] = createSignal<{ connector?: ConnectorView } | null>(null);
  const [deleting, setDeleting] = createSignal<ConnectorView | null>(null);

  const cols = columns(() => plugins());
  const columnState = createColumnState("connectors", () => cols);
  const open = (c: ConnectorView) => navigate(paths.connector(c.id));
  const editor = () => isConnectorEditor();

  useCommands(() => [
    {
      id: "connectors.create",
      group: "actions",
      icon: "plus",
      label: () => t("connectors.action.create"),
      when: editor,
      run: () => setForm({}),
    },
  ]);

  const rowActions: RowAction<ConnectorView>[] = [
    { id: "open", label: () => t("connectors.action.open"), run: open },
    { id: "run", label: () => t("connectors.action.run"), disabled: (c) => !editor() || !c.enabled, run: (c) => void actions.run(c) },
    { id: "check", label: () => t("connectors.action.check"), disabled: (c) => !editor() || !c.enabled, run: (c) => void actions.check(c) },
    {
      id: "toggle",
      label: () => t("connectors.action.toggle"),
      disabled: () => !editor(),
      run: (c) => void actions.setEnabled(c, !c.enabled),
    },
    { id: "edit", label: () => t("connectors.action.edit"), disabled: () => !editor(), run: (c) => setForm({ connector: c }) },
    { id: "delete", label: () => t("connectors.action.delete"), danger: true, disabled: () => !editor(), run: (c) => setDeleting(c) },
  ];

  const onGridClick = (e: MouseEvent) => {
    const el = e.target as HTMLElement;
    if (el.closest("a, button, input, select, textarea")) return;
    const id = el.closest<HTMLElement>("tr[data-id]")?.dataset.id;
    if (id) navigate(paths.connector(id));
  };

  return (
    <div class="page connectors-page" data-testid="page-connectors">
      <PageHead
        title={t("shell.nav.connectors")}
        sub={t("connectors.sub")}
        actions={
          <Show when={editor()}>
            <button type="button" class="btn primary" data-testid="connectors-create" onClick={() => setForm({})} disabled={!plugins()}>
              <Icon name="plus" />
              {t("connectors.action.create")}
            </button>
          </Show>
        }
      />
      <div class="connectors-body">
        <section class="connectors-instances" aria-labelledby="conn-instances">
          <h2 id="conn-instances" class="section-title">
            {t("connectors.instances")}
          </h2>
          <div class="connectors-grid" onClick={onGridClick}>
            <DataGrid
              id="connectors"
              label={t("connectors.instances")}
              columns={cols}
              columnState={columnState}
              rows={source.rows()}
              rowId={(c) => c.id}
              rowKey={(c) => c.name}
              rowLabel={(c) => c.name}
              rowClass={(c) => `health-${connectorHealth(c)}`}
              noSelection
              loading={source.loading()}
              initial={source.initial()}
              hasMore={source.hasMore()}
              onLoadMore={source.loadMore}
              error={source.error()}
              onRetry={source.reload}
              flashed={source.flashed}
              onOpen={open}
              onOpenPage={open}
              rowActions={rowActions}
              empty={
                <div class="empty" data-testid="connectors-empty">
                  <h3>{t("connectors.empty.title")}</h3>
                  <p>{t("connectors.empty.body")}</p>
                </div>
              }
            />
          </div>
        </section>

        <section class="connectors-plugins page-section" aria-labelledby="conn-plugins" data-testid="connectors-plugins">
          <h2 id="conn-plugins">
            {t("connectors.plugins.title")}
            <button type="button" class="btn sm aside-btn" onClick={() => refetchPlugins()}>
              <Icon name="refresh" size="sm" />
              {t("connectors.plugins.reload")}
            </button>
          </h2>
          <ErrorNotice error={pluginsError()} />
          <Show when={plugins()} fallback={<Show when={!pluginsError()}><p class="muted" role="status">{t("common.loading")}</p></Show>}>
            {(list) => (
              <Show when={list().length > 0} fallback={<p class="muted">{t("connectors.plugins.none")}</p>}>
                <div class="plugin-cards">
                  <For each={list()}>{(p) => <PluginCard plugin={p} />}</For>
                </div>
              </Show>
            )}
          </Show>
        </section>
      </div>

      <Show when={form()} keyed>
        {(f) => (
          <ConnectorForm
            plugins={plugins() ?? []}
            connector={f.connector}
            onClose={() => setForm(null)}
            onDone={(view) => {
              setForm(null);
              source.reload();
              if (!f.connector) navigate(paths.connector(view.id));
            }}
          />
        )}
      </Show>
      <Show when={deleting()} keyed>
        {(c) => (
          <ConfirmDialog
            title={t("connectors.delete.title", { name: c.name })}
            body={<p>{t("connectors.delete.body")}</p>}
            confirmLabel={t("connectors.delete.confirm")}
            cancelLabel={t("common.action.cancel")}
            danger
            onClose={() => setDeleting(null)}
            onConfirm={() => {
              setDeleting(null);
              void actions.remove(c);
            }}
          />
        )}
      </Show>
    </div>
  );
}

/** One plugin as its manifest describes it. */
export function PluginCard(props: { plugin: PluginInfo }) {
  const m = () => props.plugin.manifest;
  return (
    <article class="card plugin-card" data-testid="plugin" data-key={props.plugin.name} data-usable={props.plugin.usable ? "true" : "false"}>
      <header>
        <h3>
          <span class="mono">{props.plugin.name}</span> <span class="muted">{m()?.version ?? ""}</span>
        </h3>
        <span class="tag">{t(`connectors.plugins.source.${props.plugin.source}`)}</span>
        <Show when={!props.plugin.usable}>
          <span class="tag discrepancy" data-testid="plugin-unusable">
            {t("connectors.plugins.unusable")}
          </span>
        </Show>
      </header>
      <Show when={m()}>
        {(manifest) => (
          <>
            <p>{manifest().description}</p>
            <dl class="kv">
              <dt>{t("connectors.plugins.capabilities")}</dt>
              <dd>{formatList(manifest().capabilities.map(capabilityWord))}</dd>
              <dt>{t("connectors.plugins.platforms")}</dt>
              <dd class="mono">{manifest().platforms.join(", ")}</dd>
              <Show when={(manifest().secrets ?? []).length > 0}>
                <dt>{t("connectors.plugins.secrets")}</dt>
                <dd class="mono">{(manifest().secrets ?? []).map((s) => s.purpose).join(", ")}</dd>
              </Show>
              <Show when={manifest().license}>
                <dt>{t("connectors.plugins.license")}</dt>
                <dd class="mono">{manifest().license}</dd>
              </Show>
              <Show when={manifest().homepage}>
                {(href) => (
                  <>
                    <dt>{t("connectors.plugins.homepage")}</dt>
                    <dd>
                      <a href={href()} target="_blank" rel="noopener noreferrer">
                        {href()}
                      </a>
                    </dd>
                  </>
                )}
              </Show>
            </dl>
          </>
        )}
      </Show>
      <Show when={(props.plugin.problems ?? []).length > 0}>
        <ul class="plugin-problems">
          <For each={props.plugin.problems ?? []}>
            {(p) => (
              <li>
                <span class="mono">{p.path || "/"}</span> {p.message}
              </li>
            )}
          </For>
        </ul>
      </Show>
    </article>
  );
}
