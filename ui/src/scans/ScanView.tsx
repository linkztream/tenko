// One scan job (/scans/:id; SCAN-09): the target and state, the progress of each probe's part,
// and what the scan found compared with the facts before it: the counts per fact type and the
// changed facts one by one. Read again every two seconds until the scan is terminal.
import { A, useParams } from "@solidjs/router";
import { createResource, For, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { ApiError } from "../api/problem";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { TimeAgo } from "../grid/cells";
import { formatDateTime, formatNumber, t } from "../i18n";
import { getScan, listProbes } from "./api";
import { diffTotals, isTerminal, type ProbeProgress, type ScanView as Scan, nodeScanPath, SCANS_PATH } from "./model";
import { pollWhile } from "./poll";
import { ProgressBar, StateTag } from "./ProgressBar";
import { Requester } from "./Requester";
import { changeWord, factTypeWord, kindWord, noteText, partGlyph, partStateWord, stateGlyph, stateWord, targetKindWord, targetText, valueText } from "./text";
import "./scans.css";

/** The names of the probes, by node, for the parts of a scan; empty when the list cannot be read. */
function useProbeNames(): () => ReadonlyMap<number, string> {
  const [names] = createResource(async () => {
    try {
      return new Map((await listProbes()).items.map((p) => [p.node, p.name] as const));
    } catch {
      return new Map<number, string>();
    }
  });
  return () => names.latest ?? new Map<number, string>();
}

function PartRow(props: { part: ProbeProgress; name: string }) {
  return (
    <tr data-testid={`scan-probe-${props.part.node}`} data-state={props.part.state}>
      <td>
        <A href={nodeScanPath(props.part.node)}>{props.name}</A>
      </td>
      <td class="mono scan-command" title={props.part.command}>
        {props.part.command.slice(0, 8)}
      </td>
      <td>
        <StateTag glyph={partGlyph(props.part.state)} state={props.part.state} word={partStateWord(props.part.state)} progress={props.part.progress} />
      </td>
      <td>
        <ProgressBar value={props.part.progress} label={t("scans.progress.label", { target: props.part.target })} />
      </td>
      <td class="num">
        {props.part.batches != null ? t("scans.part.ingested", { ingested: props.part.ingested, batches: props.part.batches }) : formatNumber(props.part.ingested)}
      </td>
      <td>
        <Show when={props.part.detail} fallback={<span class="muted">–</span>}>
          {(detail) => noteText(detail())}
        </Show>
      </td>
    </tr>
  );
}

function Body(props: { scan: Scan }) {
  const names = useProbeNames();
  const scan = () => props.scan;
  const partName = (node: number) => names().get(node) ?? t("scans.probe.node_unnamed", { id: node });
  const totals = () => diffTotals(scan().diff);
  const types = () => Object.entries(scan().diff?.counts ?? {}).sort(([a], [b]) => a.localeCompare(b));

  return (
    <>
      <dl class="scans-facts" aria-label={t("scans.view.facts")} data-testid="scan-facts">
        <div>
          <dt>{t("scans.col.state")}</dt>
          <dd>
            <StateTag glyph={stateGlyph(scan().state)} state={scan().state} word={stateWord(scan().state)} progress={scan().progress} />
          </dd>
        </div>
        <div>
          <dt>{t("scans.col.progress")}</dt>
          <dd>
            <ProgressBar value={scan().progress} label={t("scans.progress.label", { target: targetText(scan()) })} testid="scan-progress" />
          </dd>
        </div>
        <div>
          <dt>{t("scans.col.target")}</dt>
          <dd>
            {targetKindWord(scan().target.kind)} · <span class="mono">{scan().target.value}</span>
          </dd>
        </div>
        <div>
          <dt>{t("scans.view.networks")}</dt>
          <dd class="mono">{scan().networks.join(", ")}</dd>
        </div>
        <div>
          <dt>{t("scans.col.kinds")}</dt>
          <dd>{scan().kinds.map(kindWord).join(", ")}</dd>
        </div>
        <div>
          <dt>{t("scans.col.requested_by")}</dt>
          <dd>
            <Show when={scan().requested_by} fallback={<span class="muted">–</span>}>
              {(id) => <Requester id={id()} />}
            </Show>
          </dd>
        </div>
        <div>
          <dt>{t("scans.col.created")}</dt>
          <dd>
            <TimeAgo at={scan().created_at} />
          </dd>
        </div>
        <div>
          <dt>{t("scans.col.finished")}</dt>
          <dd>
            <TimeAgo at={scan().finished_at} />
          </dd>
        </div>
        <div>
          <dt>{t("scans.view.deadline")}</dt>
          <dd>{formatDateTime(scan().deadline)}</dd>
        </div>
        <Show when={scan().error}>
          {(error) => (
            <div>
              <dt>{t("scans.view.error")}</dt>
              <dd data-testid="scan-error">{noteText(error())}</dd>
            </div>
          )}
        </Show>
      </dl>

      <section class="scans-section" aria-labelledby="scan-parts-heading">
        <h2 id="scan-parts-heading" class="scans-heading">
          {t("scans.view.probes")}
        </h2>
        <div class="table-wrap">
          <table class="plain scans-table" aria-label={t("scans.view.probes_label")}>
            <thead>
              <tr>
                <th scope="col">{t("scans.part.col.node")}</th>
                <th scope="col">{t("scans.part.col.command")}</th>
                <th scope="col">{t("scans.col.state")}</th>
                <th scope="col">{t("scans.col.progress")}</th>
                <th scope="col">{t("scans.part.col.ingested")}</th>
                <th scope="col">{t("scans.part.col.detail")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={scan().probes}>{(part) => <PartRow part={part} name={partName(part.node)} />}</For>
            </tbody>
          </table>
        </div>
      </section>

      <section class="scans-section" aria-labelledby="scan-diff-heading" data-testid="scan-diff">
        <h2 id="scan-diff-heading" class="scans-heading">
          {t("scans.diff.heading")}
        </h2>
        <Show
          when={scan().diff}
          fallback={
            <p class="muted" data-testid="scan-diff-waiting">
              {isTerminal(scan().state) ? t("scans.diff.pending") : t("scans.diff.waiting")}
            </p>
          }
        >
          {(diff) => (
            <>
              <div class="table-wrap">
                <table class="plain scans-table scans-totals" aria-label={t("scans.diff.totals_label")} data-testid="scan-diff-totals">
                  <thead>
                    <tr>
                      <th scope="col">{t("scans.diff.col.type")}</th>
                      <th scope="col" class="r">{changeWord("new")}</th>
                      <th scope="col" class="r">{changeWord("changed")}</th>
                      <th scope="col" class="r">{changeWord("gone")}</th>
                      <th scope="col" class="r">{changeWord("unchanged")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={types()}>
                      {([type, counts]) => (
                        <tr data-testid={`diff-total-${type}`}>
                          <th scope="row">{factTypeWord(type)}</th>
                          <td class="r num" data-col="new">{formatNumber(counts.new)}</td>
                          <td class="r num" data-col="changed">{formatNumber(counts.changed)}</td>
                          <td class="r num" data-col="gone">{formatNumber(counts.gone)}</td>
                          <td class="r num" data-col="unchanged">{formatNumber(counts.unchanged)}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                  <tfoot>
                    <tr data-testid="diff-total-all">
                      <th scope="row">{t("scans.diff.total")}</th>
                      <td class="r num" data-col="new">{formatNumber(totals().new)}</td>
                      <td class="r num" data-col="changed">{formatNumber(totals().changed)}</td>
                      <td class="r num" data-col="gone">{formatNumber(totals().gone)}</td>
                      <td class="r num" data-col="unchanged">{formatNumber(totals().unchanged)}</td>
                    </tr>
                  </tfoot>
                </table>
              </div>
              <Show
                when={diff().items.length > 0}
                fallback={
                  <p class="muted" data-testid="scan-diff-empty">
                    {t("scans.diff.empty")}
                  </p>
                }
              >
                <div class="table-wrap">
                  <table class="plain scans-table" aria-label={t("scans.diff.items_label")} data-testid="scan-diff-items">
                    <thead>
                      <tr>
                        <th scope="col">{t("scans.diff.col.type")}</th>
                        <th scope="col">{t("scans.diff.col.subject")}</th>
                        <th scope="col">{t("scans.diff.col.before")}</th>
                        <th scope="col">{t("scans.diff.col.after")}</th>
                        <th scope="col">{t("scans.diff.col.change")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={diff().items}>
                        {(item, n) => (
                          <tr data-testid={`diff-row-${n()}`} data-state={item.change}>
                            <td data-col="type">{factTypeWord(item.fact_type)}</td>
                            <td class="mono" data-col="subject">{item.subject}</td>
                            <td class="mono scan-value" data-col="before">{valueText(item.before)}</td>
                            <td class="mono scan-value" data-col="after">{valueText(item.after)}</td>
                            <td data-col="change">
                              <span class={`tag scan-change ${item.change}`} data-state={item.change}>
                                {changeWord(item.change)}
                              </span>
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
              </Show>
              <Show when={diff().truncated}>
                <Notice kind="info" testid="scan-diff-truncated">
                  {t("scans.diff.truncated")}
                </Notice>
              </Show>
            </>
          )}
        </Show>
      </section>
    </>
  );
}

function ScanBody(props: { id: string }) {
  const live = createLiveQuery<Scan>({
    topics: ["discovery"],
    fetch: async (signal) => ({ value: await getScan(props.id, signal) }),
  });
  pollWhile(() => {
    const scan = live.latest();
    return scan !== undefined && !isTerminal(scan.state);
  }, live.refetch);
  const missing = () => {
    const err = live.value.error;
    return err instanceof ApiError && err.status === 404;
  };

  return (
    <div class="page" data-testid="page-scan">
      <PageHead
        crumbs={
          <A href={SCANS_PATH} class="scans-back">
            <Icon name="chev-r" size="xs" class="scans-back-icon" />
            {t("scans.action.back")}
          </A>
        }
        title={
          <Show when={live.latest()} fallback={t("scans.view.tab")}>
            {(scan) => t("scans.view.title", { target: targetText(scan()) })}
          </Show>
        }
        sub={
          <Show when={live.latest()}>
            {(scan) => <span data-testid="scan-state" data-state={scan().state}>{stateWord(scan().state)}</span>}
          </Show>
        }
      />
      <div class="page-body">
        <Show
          when={!missing()}
          fallback={
            <Notice kind="warn" role="alert" title={t("scans.view.not_found_title")} testid="scan-not-found">
              {t("scans.view.not_found")}
            </Notice>
          }
        >
          <ErrorNotice error={live.value.error} />
          <Show when={live.latest()} fallback={<Show when={!live.value.error}><p class="muted" role="status">{t("scans.view.loading")}</p></Show>}>
            {(scan) => <Body scan={scan()} />}
          </Show>
        </Show>
      </div>
    </div>
  );
}

export default function ScanView() {
  const params = useParams<{ id: string }>();
  return (
    <Show when={params.id} keyed>
      {(id) => <ScanBody id={id} />}
    </Show>
  );
}
