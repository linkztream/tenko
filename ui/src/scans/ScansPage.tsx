// The scans page (/scans; SCAN-09): the scan jobs of the discovery module, newest first, with
// their progress and what they found, and the probes with the scope each applies and its kill
// switch. Live on the `discovery` topic and read again every two seconds while a scan is not
// terminal. Administrators stop every scan with an optional reason and resume them again.
import { A } from "@solidjs/router";
import { createSignal, For, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { errorMessage } from "../api/problem";
import { isAdmin } from "../auth/session";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { toast } from "../components/toast";
import { TimeAgo } from "../grid/cells";
import { formatList, formatNumber, t } from "../i18n";
import { listProbes, listScans, resumeAllScans } from "./api";
import { StopDialog } from "./dialogs";
import { diffTotals, isTerminal, type KillSwitchResult, type ProbeSummary, type ScanView, nodeScanPath, scanPath } from "./model";
import { pollWhile } from "./poll";
import { ProgressBar, StateTag } from "./ProgressBar";
import { Requester } from "./Requester";
import { kindWord, stateGlyph, stateWord, targetKindWord, targetText } from "./text";
import "./scans.css";

/** The summary of what a scan found, or a dash while it has no result. */
function Changes(props: { scan: ScanView }) {
  const totals = () => diffTotals(props.scan.diff);
  return (
    <Show when={props.scan.diff} fallback={<span class="muted">–</span>}>
      <span class="num" data-testid="scan-changes">
        {t("scans.diff.summary", { new: totals().new, changed: totals().changed, gone: totals().gone })}
      </span>
    </Show>
  );
}

function SwitchCell(props: { probe: ProbeSummary }) {
  const sw = () => props.probe.kill_switch;
  const word = () => (sw().stopped ? t("scans.switch.stopped") : t("scans.switch.active"));
  return (
    <>
      <span class={`tag scan-switch ${sw().stopped ? "stopped" : "active"}`} data-testid="probe-switch" data-state={sw().stopped ? "stopped" : "active"}>
        <Icon name={sw().stopped ? "pause" : "play"} size="xs" />
        {sw().confirmed ? word() : t("scans.switch.unconfirmed", { state: word() })}
      </span>
      <Show when={sw().stopped && sw().reason}>
        {(reason) => <div class="muted scan-reason">{t("scans.switch.reason", { reason: reason() })}</div>}
      </Show>
    </>
  );
}

function ScopeCell(props: { probe: ProbeSummary }) {
  return (
    <Show when={props.probe.applied} fallback={<span class="muted">{t("scans.probe.scope_none")}</span>}>
      {(scope) => (
        <span data-testid="probe-scope">
          {t("scans.probe.scope", {
            count: scope().prefixes.length,
            methods: scope().methods.length > 0 ? formatList(scope().methods) : t("scans.probe.methods_none"),
          })}
        </span>
      )}
    </Show>
  );
}

export default function ScansPage() {
  const scans = createLiveQuery<ScanView[]>({
    topics: ["discovery"],
    fetch: async (signal) => {
      const all = await listScans(signal);
      return { value: all.items, revision: all.revision };
    },
  });
  const probes = createLiveQuery<ProbeSummary[]>({
    topics: ["discovery"],
    fetch: async (signal) => ({ value: (await listProbes(signal)).items }),
  });
  pollWhile(
    () => (scans.latest() ?? []).some((s) => !isTerminal(s.state)),
    scans.refetch,
  );

  const rows = () => [...(scans.latest() ?? [])].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const anyStopped = () => (probes.latest() ?? []).some((p) => p.kill_switch.stopped);
  const allStopped = () => (probes.latest() ?? []).every((p) => p.kill_switch.stopped);

  const [stopping, setStopping] = createSignal(false);
  const [resuming, setResuming] = createSignal(false);

  const stopped = (result: KillSwitchResult) => {
    setStopping(false);
    toast({ kind: "ok", title: t("scans.toast.stopped", { count: result.commands.length }) });
    probes.refetch();
    scans.refetch();
  };

  const resume = async () => {
    if (resuming()) return;
    setResuming(true);
    try {
      const result = await resumeAllScans();
      toast({ kind: "ok", title: t("scans.toast.resumed", { count: result.commands.length }) });
      probes.refetch();
      scans.refetch();
    } catch (err) {
      toast({ kind: "bad", title: t("scans.action.resume_all"), body: errorMessage(err) });
    } finally {
      setResuming(false);
    }
  };

  return (
    <div class="page" data-testid="page-scans">
      <PageHead
        title={t("scans.title")}
        sub={scans.latest() ? t("scans.count", { count: rows().length }) : undefined}
        actions={
          <Show when={isAdmin()}>
            <Show when={anyStopped()}>
              <button type="button" class="btn" data-testid="scans-resume-all" disabled={resuming()} onClick={() => void resume()}>
                <Icon name="play" />
                {t("scans.action.resume_all")}
              </button>
            </Show>
            <button type="button" class="btn danger" data-testid="scans-stop-all" disabled={!probes.latest() || allStopped()} onClick={() => setStopping(true)}>
              <Icon name="pause" />
              {t("scans.action.stop_all")}
            </button>
          </Show>
        }
      />
      <div class="page-body">
        <section class="scans-section" aria-labelledby="scans-jobs-heading">
          <h2 id="scans-jobs-heading" class="scans-heading">
            {t("scans.section.jobs")}
          </h2>
          <ErrorNotice error={scans.value.error} />
          <Show when={scans.latest()} fallback={<Show when={!scans.value.error}><p class="muted" role="status">{t("common.loading")}</p></Show>}>
            <Show
              when={rows().length > 0}
              fallback={
                <div class="empty" data-testid="scans-empty">
                  <h3>{t("scans.empty.title")}</h3>
                  <p>{t("scans.empty.body")}</p>
                </div>
              }
            >
              <div class="table-wrap">
                <table class="plain scans-table" aria-label={t("scans.list.label")} data-testid="scans-list">
                  <thead>
                    <tr>
                      <th scope="col">{t("scans.col.target")}</th>
                      <th scope="col">{t("scans.col.kinds")}</th>
                      <th scope="col">{t("scans.col.state")}</th>
                      <th scope="col">{t("scans.col.progress")}</th>
                      <th scope="col">{t("scans.col.changes")}</th>
                      <th scope="col">{t("scans.col.requested_by")}</th>
                      <th scope="col">{t("scans.col.created")}</th>
                      <th scope="col">{t("scans.col.finished")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={rows()}>
                      {(scan) => (
                        <tr data-testid={`scan-row-${scan.id}`} data-state={scan.state}>
                          <td>
                            <A href={scanPath(scan.id)} class="mono scan-target" title={scan.target.value}>
                              {targetText(scan)}
                            </A>
                            <span class="tag scan-target-kind">{targetKindWord(scan.target.kind)}</span>
                          </td>
                          <td>{scan.kinds.map(kindWord).join(", ")}</td>
                          <td>
                            <StateTag glyph={stateGlyph(scan.state)} state={scan.state} word={stateWord(scan.state)} progress={scan.progress} />
                          </td>
                          <td>
                            <ProgressBar value={scan.progress} label={t("scans.progress.label", { target: targetText(scan) })} />
                          </td>
                          <td>
                            <Changes scan={scan} />
                          </td>
                          <td>
                            <Show when={scan.requested_by} fallback={<span class="muted">–</span>}>
                              {(id) => <Requester id={id()} />}
                            </Show>
                          </td>
                          <td>
                            <TimeAgo at={scan.created_at} />
                          </td>
                          <td>
                            <TimeAgo at={scan.finished_at} />
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </Show>
        </section>

        <section class="scans-section" aria-labelledby="scans-probes-heading">
          <h2 id="scans-probes-heading" class="scans-heading">
            {t("scans.section.probes")}
            <Show when={probes.latest()}>
              <span class="muted scans-count">{formatNumber(probes.latest()?.length ?? 0)}</span>
            </Show>
          </h2>
          <ErrorNotice error={probes.value.error} />
          <Show when={probes.latest()}>
            {(list) => (
              <div class="table-wrap">
                <table class="plain scans-table" aria-label={t("scans.probes.label")} data-testid="scans-probes">
                  <thead>
                    <tr>
                      <th scope="col">{t("scans.probe.col.name")}</th>
                      <th scope="col">{t("scans.probe.col.sync")}</th>
                      <th scope="col">{t("scans.probe.col.scope")}</th>
                      <th scope="col">{t("scans.probe.col.switch")}</th>
                      <th scope="col" class="r">
                        <span class="sr-only">{t("scans.probe.col.config")}</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={list()}>
                      {(probe) => (
                        <tr data-testid={`probe-row-${probe.node}`} data-state={probe.kill_switch.stopped ? "stopped" : "active"}>
                          <td>
                            <A href={nodeScanPath(probe.node)} class="scan-probe-name">
                              {probe.name}
                            </A>
                            <Show when={probe.in_process}>
                              <span class="tag scan-in-process" data-testid="probe-in-process">
                                {t("scans.probe.in_process")}
                              </span>
                            </Show>
                          </td>
                          <td>
                            <span class={`tag ${probe.in_sync ? "ok" : "discrepancy"}`} data-testid="probe-sync" data-state={probe.in_sync ? "in_sync" : "out_of_sync"}>
                              {probe.in_sync ? t("scans.probe.in_sync") : t("scans.probe.out_of_sync")}
                            </span>
                          </td>
                          <td>
                            <ScopeCell probe={probe} />
                          </td>
                          <td>
                            <SwitchCell probe={probe} />
                          </td>
                          <td class="r">
                            <A href={nodeScanPath(probe.node)} class="btn sm" data-testid="probe-config" aria-label={t("scans.probe.config_named", { name: probe.name })}>
                              <Icon name="scan" size="sm" />
                              {t("scans.probe.config")}
                            </A>
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            )}
          </Show>
        </section>
      </div>

      <Show when={stopping()}>
        <StopDialog onDone={stopped} onClose={() => setStopping(false)} />
      </Show>
    </div>
  );
}
