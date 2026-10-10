// One connector instance (/connectors/<id>): its health (the supervised process with its
// restarts and last error, the last check of the remote system, the last run), its recent
// runs as jobs, its settings with the titles of the plugin's schema, its secret references by
// purpose (names only), its schedule, guardrail and network targets. Run now, check now,
// enable, disable, change and delete. Live on the `connectors` and `jobs` topics.
import { A, useNavigate, useParams } from "@solidjs/router";
import { createMemo, createResource, createSignal, For, Show } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import type { JobSummary } from "../api/types";
import { decodeSegment, paths } from "../app/paths";
import { ConfirmDialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { TimeAgo } from "../grid/cells";
import { formatDateTime, formatList, formatNumber, t, tDynamic } from "../i18n";
import { JobStateChip } from "../jobs/StateChip";
import { jobTitle } from "../jobs/words";
import { listSecrets } from "../secrets/api";
import { secretsPath } from "../secrets/paths";
import { getConnector, listPlugins, type ConnectorView } from "./api";
import { ConnectorForm } from "./ConnectorForm";
import { capabilityWord, pluginOf } from "./model";
import { HealthBadge, isConnectorEditor, LastRunText, ProcessText, secondsText, useConnectorActions } from "./Parts";
import { settingsForm, type JsonSchema, type SettingField } from "./schema";
import "./connectors.css";

/** A setting's value in words: lists joined, booleans as yes or no, a dash for none. */
function valueText(value: unknown): string {
  if (value === undefined || value === null || value === "") return "–";
  if (typeof value === "boolean") return value ? t("connectors.detail.yes") : t("connectors.detail.no");
  if (Array.isArray(value)) return value.length ? value.map(String).join(", ") : "–";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function errorText(e: { code: string; detail: string; params?: Record<string, string> } | null | undefined): string {
  if (!e) return "";
  return tDynamic(`errors.${e.code}`, { ...e.params }) ?? e.detail;
}

export default function ConnectorDetail() {
  const params = useParams<{ id: string }>();
  const navigate = useNavigate();
  const id = () => decodeSegment(params.id);

  const live = createLiveQuery<ConnectorView>({
    topics: ["connectors"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => o.id === id()),
    fetch: async (signal) => {
      const c = await getConnector(id(), signal);
      return { value: c, revision: c.revision };
    },
  });
  // Reading a failed resource throws its error at the reader (and nothing is shown at all), so
  // a failed read reads as no value; the page shows the error of the connector instead.
  const connector = () => (live.value.error ? undefined : live.value.latest);
  const [pluginsRead] = createResource(() => listPlugins());
  const plugins = () => (pluginsRead.error ? undefined : pluginsRead());
  const plugin = () => (connector() ? pluginOf(plugins(), connector()!.plugin) : undefined);
  const form = createMemo(() => settingsForm(plugin()?.manifest?.settings as JsonSchema | undefined));

  const runs = createLiveQuery<JobSummary[]>({
    topics: ["jobs"],
    fetch: async (signal) => {
      const page = await api.get("/api/v1/jobs", { query: { target: `connector/${id()}`, limit: 10 }, signal });
      return { value: page.items, revision: page.revision };
    },
  });
  const recentRuns = () => (runs.value.error ? [] : (runs.value.latest ?? []));
  const [secrets] = createResource(async () => {
    try {
      return await listSecrets();
    } catch {
      return [];
    }
  });
  const secretName = (secretId: string) => secrets()?.find((s) => s.id === secretId)?.name;

  const actions = useConnectorActions(() => {
    live.refetch();
    runs.refetch();
  });
  const [editing, setEditing] = createSignal(false);
  const [deleting, setDeleting] = createSignal(false);
  const editor = () => isConnectorEditor();

  const settingRows = (fields: readonly SettingField[], values: Record<string, unknown>, prefix = ""): { label: string; value: string; name: string }[] =>
    fields.flatMap((f) =>
      f.type === "object"
        ? settingRows(f.fields, (values[f.name] as Record<string, unknown>) ?? {}, `${f.title ?? f.name} · `)
        : [{ label: `${prefix}${f.title ?? f.name}`, value: valueText(values[f.name]), name: f.name }],
    );

  return (
    <div class="page connector-page" data-testid="page-connector" data-id={id()}>
      <Show
        when={connector()}
        fallback={
          <div class="page-body">
            <Show when={live.value.error} fallback={<p class="muted" role="status">{t("common.loading")}</p>}>
              <ErrorNotice error={live.value.error} />
              <A href={paths.connectors()}>{t("connectors.detail.back")}</A>
            </Show>
          </div>
        }
      >
        {(c) => (
          <>
            <PageHead
              crumbs={<A href={paths.connectors()}>{t("shell.nav.connectors")}</A>}
              title={c().name}
              sub={
                <>
                  <span class="mono">{c().plugin}</span> {plugin()?.manifest?.version ?? ""} <HealthBadge connector={c()} />
                </>
              }
              actions={
                <Show when={editor()}>
                  <button type="button" class="btn" data-testid="connector-run" disabled={!c().enabled} onClick={() => void actions.run(c())}>
                    <Icon name="play" />
                    {t("connectors.action.run")}
                  </button>
                  <button type="button" class="btn" data-testid="connector-check" disabled={!c().enabled} onClick={() => void actions.check(c())}>
                    <Icon name="refresh" />
                    {t("connectors.action.check")}
                  </button>
                  <button
                    type="button"
                    class="btn"
                    data-testid="connector-toggle"
                    aria-pressed={c().enabled}
                    onClick={() => void actions.setEnabled(c(), !c().enabled)}
                  >
                    <Icon name={c().enabled ? "pause" : "play"} />
                    {c().enabled ? t("connectors.action.disable") : t("connectors.action.enable")}
                  </button>
                  <button type="button" class="btn" data-testid="connector-edit" disabled={!plugins()} onClick={() => setEditing(true)}>
                    <Icon name="settings" />
                    {t("connectors.action.edit")}
                  </button>
                  <button type="button" class="btn danger" data-testid="connector-delete" onClick={() => setDeleting(true)}>
                    <Icon name="trash" />
                    {t("connectors.action.delete")}
                  </button>
                </Show>
              }
            />
            <div class="page-body wide connector-body">
              <Show when={!c().enabled}>
                <Notice kind="info" testid="connector-disabled">
                  {t("connectors.detail.disabled")}
                </Notice>
              </Show>
              <div class="connector-cards">
                <section class="card connector-card" aria-labelledby="cd-process" data-testid="connector-process">
                  <h2 id="cd-process">{t("connectors.detail.process")}</h2>
                  <dl class="kv">
                    <dt>{t("connectors.detail.state")}</dt>
                    <dd>
                      <ProcessText process={c().health.process} />
                    </dd>
                    <Show when={c().health.process.state === "running" && (c().health.process as { version?: string }).version}>
                      {(v) => (
                        <>
                          <dt>{t("connectors.detail.version")}</dt>
                          <dd class="mono">{v()}</dd>
                        </>
                      )}
                    </Show>
                    <dt>{t("connectors.detail.changed")}</dt>
                    <dd>
                      <TimeAgo at={c().health.process.changed_at} />
                    </dd>
                    <dt>{t("connectors.detail.restarts")}</dt>
                    <dd class="num" data-testid="connector-restarts">
                      {formatNumber(c().health.process.restarts)}
                    </dd>
                    <dt>{t("connectors.detail.failures")}</dt>
                    <dd class="num" data-testid="connector-failures">
                      {formatNumber(c().health.process.consecutive_failures)}
                    </dd>
                    <Show when={c().health.process.last_error}>
                      {(e) => (
                        <>
                          <dt>{t("connectors.detail.last_error")}</dt>
                          <dd data-testid="connector-last-error" data-code={e().code}>
                            {errorText(e())} <span class="mono muted">{e().code}</span>
                          </dd>
                        </>
                      )}
                    </Show>
                  </dl>
                </section>

                <section class="card connector-card" aria-labelledby="cd-remote" data-testid="connector-remote">
                  <h2 id="cd-remote">{t("connectors.detail.remote")}</h2>
                  <Show when={c().health.remote} fallback={<p class="muted">{t("connectors.detail.no_check")}</p>}>
                    {(r) => (
                      <dl class="kv">
                        <dt>{t("connectors.detail.health")}</dt>
                        <dd data-health={r().health}>{t(`connectors.remote.${r().health}`)}</dd>
                        <dt>{t("connectors.detail.checked")}</dt>
                        <dd>
                          <TimeAgo at={r().checked_at} />
                        </dd>
                        <Show when={r().latency_ms != null}>
                          <dt>{t("connectors.detail.latency")}</dt>
                          <dd class="num">{t("connectors.detail.ms", { ms: r().latency_ms ?? 0 })}</dd>
                        </Show>
                        <Show when={r().remote_version}>
                          <dt>{t("connectors.detail.remote_version")}</dt>
                          <dd class="mono">{r().remote_version}</dd>
                        </Show>
                        <Show when={r().detail}>
                          <dt>{t("connectors.detail.detail")}</dt>
                          <dd>{r().detail}</dd>
                        </Show>
                      </dl>
                    )}
                  </Show>
                  <Show when={c().health.remote_error}>
                    {(e) => (
                      <Notice kind="warn" testid="connector-remote-error">
                        {t("connectors.detail.check_failed", { error: errorText(e()) })}
                      </Notice>
                    )}
                  </Show>
                </section>

                <section class="card connector-card" aria-labelledby="cd-run" data-testid="connector-last-run">
                  <h2 id="cd-run">{t("connectors.detail.last_run")}</h2>
                  <Show when={c().last_run} fallback={<p class="muted">{t("connectors.run.never")}</p>}>
                    {(r) => (
                      <dl class="kv">
                        <dt>{t("connectors.detail.outcome")}</dt>
                        <dd>
                          <LastRunText run={r()} />
                        </dd>
                        <dt>{t("connectors.detail.trigger")}</dt>
                        <dd>{t(`connectors.trigger.${r().trigger}`)}</dd>
                        <dt>{t("connectors.detail.started")}</dt>
                        <dd>{formatDateTime(r().started_at)}</dd>
                        <dt>{t("connectors.detail.observations")}</dt>
                        <dd class="num">{t("connectors.detail.pages", { observations: r().observations, pages: r().pages })}</dd>
                        <Show when={(r().consecutive_failures ?? 0) > 0}>
                          <dt>{t("connectors.detail.failed_runs")}</dt>
                          <dd class="num">{formatNumber(r().consecutive_failures ?? 0)}</dd>
                        </Show>
                        <Show when={r().last_success_at}>
                          <dt>{t("connectors.detail.last_success")}</dt>
                          <dd>
                            <TimeAgo at={r().last_success_at} />
                          </dd>
                        </Show>
                        <Show when={r().error}>
                          {(e) => (
                            <>
                              <dt>{t("connectors.detail.error")}</dt>
                              <dd data-code={e().code}>{errorText(e())}</dd>
                            </>
                          )}
                        </Show>
                        <Show when={(r().warnings ?? []).length > 0}>
                          <dt>{t("connectors.detail.warnings")}</dt>
                          <dd>{(r().warnings ?? []).join("; ")}</dd>
                        </Show>
                        <Show when={r().job}>
                          {(job) => (
                            <>
                              <dt>{t("connectors.detail.job")}</dt>
                              <dd>
                                <A href={paths.job(job())}>{t("connectors.toast.open_job")}</A>
                              </dd>
                            </>
                          )}
                        </Show>
                      </dl>
                    )}
                  </Show>
                  <p>
                    <A href={paths.observations({ source: c().id })} data-testid="connector-observations">
                      {t("connectors.detail.observations_link")}
                    </A>
                  </p>
                </section>
              </div>

              <section class="page-section" aria-labelledby="cd-runs" data-testid="connector-runs">
                <h2 id="cd-runs">
                  {t("connectors.detail.runs")}
                  <A class="aside" href={paths.jobs({ target: `connector/${c().id}` })}>
                    {t("connectors.detail.all_jobs")}
                  </A>
                </h2>
                <Show when={recentRuns().length > 0} fallback={<p class="muted">{t("connectors.detail.no_runs")}</p>}>
                  <ul class="plain-list run-list">
                    <For each={recentRuns()}>
                      {(job) => (
                        <li data-testid="connector-run-job" data-id={job.id}>
                          <JobStateChip state={job.state} done={job.steps_done} total={job.step_count} />
                          <A href={paths.job(job.id)}>{jobTitle(job)}</A>
                          <TimeAgo at={job.created.at} />
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </section>

              <div class="connector-cards">
                <section class="card connector-card" aria-labelledby="cd-settings" data-testid="connector-settings-view">
                  <h2 id="cd-settings">{t("connectors.form.settings")}</h2>
                  <Show when={form().fields.length > 0} fallback={<p class="muted">{t("connectors.form.no_settings")}</p>}>
                    <dl class="kv">
                      <For each={settingRows(form().fields, c().settings as Record<string, unknown>)}>
                        {(row) => (
                          <>
                            <dt>{row.label}</dt>
                            <dd class="mono" data-setting={row.name}>
                              {row.value}
                            </dd>
                          </>
                        )}
                      </For>
                    </dl>
                  </Show>
                </section>

                <section class="card connector-card" aria-labelledby="cd-config" data-testid="connector-config">
                  <h2 id="cd-config">{t("connectors.detail.config")}</h2>
                  <dl class="kv">
                    <dt>{t("connectors.form.poll")}</dt>
                    <dd>{secondsText(c().poll_interval_secs, plugin()?.manifest?.defaults?.poll_interval_secs ?? 300)}</dd>
                    <dt>{t("connectors.form.timeout")}</dt>
                    <dd>{secondsText(c().call_timeout_secs, plugin()?.manifest?.defaults?.call_timeout_secs ?? 30)}</dd>
                    <dt>{t("connectors.form.writes")}</dt>
                    <dd data-testid="connector-writes">{c().writes_enabled ? t("connectors.writes.on") : t("connectors.writes.off")}</dd>
                    <dt>{t("connectors.plugins.capabilities")}</dt>
                    <dd>{formatList((c().capabilities ?? []).map(capabilityWord))}</dd>
                    <For each={Object.entries(c().secrets ?? {})}>
                      {([purpose, ref]) => (
                        <>
                          <dt>{t("connectors.form.secret_purpose", { purpose })}</dt>
                          <dd data-testid="connector-secret" data-key={purpose}>
                            <A href={secretsPath(ref.secret)}>{secretName(ref.secret) ?? t("connectors.form.secret_unlisted")}</A>
                          </dd>
                        </>
                      )}
                    </For>
                    <dt>{t("connectors.detail.created")}</dt>
                    <dd>
                      <TimeAgo at={c().created.at} />
                    </dd>
                    <dt>{t("connectors.detail.updated")}</dt>
                    <dd>
                      <TimeAgo at={c().updated.at} />
                    </dd>
                  </dl>
                  <Show when={(plugin()?.manifest?.network ?? []).length > 0}>
                    <h3 class="sub-h">{t("connectors.form.targets")}</h3>
                    <ul class="plain-list">
                      <For each={plugin()?.manifest?.network ?? []}>
                        {(n) => (
                          <li>
                            <span class="mono">
                              {n.host ?? (n.setting ? valueText((c().settings as Record<string, unknown>)[n.setting.replace(/^\//, "")]) : "")}
                              {(n.ports?.length ?? 0) > 0 ? ` (${(n.ports ?? []).join(", ")})` : ""}
                            </span>{" "}
                            <span class="muted">{n.description}</span>
                          </li>
                        )}
                      </For>
                    </ul>
                  </Show>
                </section>
              </div>
            </div>

            <Show when={editing()}>
              <ConnectorForm
                plugins={plugins() ?? []}
                connector={c()}
                onClose={() => setEditing(false)}
                onDone={() => {
                  setEditing(false);
                  live.refetch();
                }}
              />
            </Show>
            <Show when={deleting()}>
              <ConfirmDialog
                title={t("connectors.delete.title", { name: c().name })}
                body={<p>{t("connectors.delete.body")}</p>}
                confirmLabel={t("connectors.delete.confirm")}
                cancelLabel={t("common.action.cancel")}
                danger
                onClose={() => setDeleting(false)}
                onConfirm={() => {
                  setDeleting(false);
                  const target = c();
                  void actions.remove(target).then((gone) => gone && navigate(paths.connectors()));
                }}
              />
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}
