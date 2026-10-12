// The queued changes (/cluster/queue; OPS-26, WP3.9). While a controller has no quorum it
// refuses writes; an IPAM write can be queued on it. This view lists what this controller holds
// ("On this controller": cancel a change before the heal) and what became of the person's
// queued changes after the heal ("After the heal": applied ones with their job, and the ones
// that no longer fit the data, which the person re-applies after a new preview or discards).
// A server without WP3.9 has no queue; the view says so calmly instead of showing an error.
import { A, useNavigate } from "@solidjs/router";
import { createSignal, For, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { ApiError, errorMessage, hasErrorMessage, isApiError } from "../api/problem";
import { paths } from "../app/paths";
import { ConfirmDialog } from "../components/Dialog";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { toast } from "../components/toast";
import { TimeAgo } from "../grid/cells";
import { loadPacks, t } from "../i18n";
import { PlanDialog } from "../ipam/plan/PlanDialog";
import { cancelQueued, discardQueued, listQueue, listQueuedChanges, reapplyQueued } from "./api";
import { type QueueConflict, type QueuedChange, type QueueItem, type QueueSummary, CLUSTER_PATH } from "./model";
import { loadConflicts } from "./PartitionStatus";
import "./cluster.css";

/** What a list read found: the items, or the fact that this server keeps no queue. */
interface Loaded<T> {
  items: T[];
  available: boolean;
}

async function load<T>(read: () => Promise<{ items: T[] }>): Promise<Loaded<T>> {
  try {
    return { items: (await read()).items, available: true };
  } catch (err) {
    // A server without WP3.9 does not know the routes (404) or does not implement them (501).
    if (isApiError(err) && (err.status === 404 || err.status === 501)) return { items: [], available: false };
    throw err;
  }
}

/** "Update address", "Delete prefix": what a queued change does, in words. */
export function summaryText(summary: QueueSummary | null | undefined): string {
  if (!summary) return t("cluster.queue.what_unknown");
  return t("cluster.queue.action", { action: summary.action, kind: t("cluster.queue.kind", { kind: summary.kind }) });
}

/** Why a change did not apply by itself, in words; the problem code stays visible beside it. */
export function conflictText(conflict: QueueConflict): string {
  if (conflict.code === "ipam.plan.stale") return t("cluster.queue.conflict.stale");
  if (hasErrorMessage(conflict.code)) {
    return errorMessage(new ApiError({ status: 409, code: conflict.code, title: "", detail: conflict.detail ?? "", params: conflict.params ?? {} }));
  }
  return conflict.detail || t("cluster.queue.conflict.other");
}

export default function QueueView() {
  const navigate = useNavigate();
  const topics = ["ipam", "cluster"] as const;
  const local = createLiveQuery<Loaded<QueueItem>>({
    topics,
    fetch: async (signal) => ({ value: await load(() => listQueue(signal)) }),
  });
  const changes = createLiveQuery<Loaded<QueuedChange>>({
    topics,
    fetch: async (signal) => ({ value: await load(() => listQueuedChanges(signal)) }),
  });

  const [cancelling, setCancelling] = createSignal<QueueItem | null>(null);
  const [reapplying, setReapplying] = createSignal<QueuedChange | null>(null);
  const [discarding, setDiscarding] = createSignal<QueuedChange | null>(null);

  const localItems = () => local.latest()?.items ?? [];
  // Conflicts first: they are the ones that wait for the person.
  const changeItems = () => {
    const items = changes.latest()?.items ?? [];
    return [...items].sort((a, b) => Number(b.state === "conflict") - Number(a.state === "conflict"));
  };
  // Both lists come with the same package; either one missing means no queue on this server.
  const unavailable = () => local.latest()?.available === false || changes.latest()?.available === false;
  const loaded = () => local.latest() !== undefined && changes.latest() !== undefined;
  const error = () => local.value.error ?? changes.value.error;

  const refresh = () => {
    local.refetch();
    changes.refetch();
    void loadConflicts();
  };

  const cancel = async (item: QueueItem) => {
    setCancelling(null);
    try {
      await cancelQueued(item.id);
      toast({ kind: "ok", title: t("cluster.queue.cancelled") });
      refresh();
    } catch (err) {
      toast({ kind: "bad", title: t("cluster.queue.cancel_failed"), body: errorMessage(err) });
    }
  };

  const discard = async (change: QueuedChange) => {
    setDiscarding(null);
    try {
      await discardQueued(change.id, change.revision);
      toast({ kind: "ok", title: t("cluster.queue.discarded") });
      refresh();
    } catch (err) {
      toast({ kind: "bad", title: t("cluster.queue.discard_failed"), body: errorMessage(err) });
    }
  };

  // The preview of a re-apply is the plan dialog of IPAM, whose strings are the ipam pack's.
  const openReapply = async (change: QueuedChange) => {
    await loadPacks(["ipam"]);
    setReapplying(change);
  };

  return (
    <div class="page" data-testid="page-cluster-queue">
      <PageHead
        title={t("cluster.queue.title")}
        crumbs={<A href={CLUSTER_PATH}>{t("cluster.title")}</A>}
      />
      <div class="page-body">
        <ErrorNotice error={error()} />
        <Show when={unavailable()}>
          <Notice kind="info" role="status" testid="queue-unavailable">
            {t("cluster.queue.unavailable")}
          </Notice>
        </Show>
        <Show when={loaded() && !unavailable()}>
          <section class="page-section" aria-labelledby="queue-local-title" data-testid="queue-local">
            <h2 id="queue-local-title">
              {t("cluster.queue.local.title")}
              <span class="aside">{t("cluster.queue.count", { count: localItems().length })}</span>
            </h2>
            <p>{t("cluster.queue.local.intro")}</p>
            <Show when={localItems().length > 0} fallback={<p class="muted" data-testid="queue-local-empty">{t("cluster.queue.local.empty")}</p>}>
              <div class="table-wrap">
                <table class="plain" aria-label={t("cluster.queue.local.title")}>
                  <thead>
                    <tr>
                      <th scope="col">{t("cluster.queue.col.change")}</th>
                      <th scope="col">{t("cluster.queue.col.request")}</th>
                      <th scope="col">{t("cluster.queue.col.queued")}</th>
                      <th scope="col">{t("cluster.queue.col.expires")}</th>
                      <th scope="col">{t("cluster.queue.col.state")}</th>
                      <th scope="col" class="r">
                        <span class="sr-only">{t("cluster.queue.col.actions")}</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={localItems()}>
                      {(item) => (
                        <tr data-testid={`queue-item-${item.id}`} data-id={item.id} data-state={item.state}>
                          <td>
                            <span data-testid="queue-item-summary">{summaryText(item.summary)}</span>
                            <Show when={item.summary?.key}>{(key) => <span class="mono"> {key()}</span>}</Show>
                          </td>
                          <td class="mono">
                            {item.method.toUpperCase()} {item.path}
                          </td>
                          <td>
                            <TimeAgo at={item.queued_at} />
                          </td>
                          <td>
                            <TimeAgo at={item.expires_at} />
                          </td>
                          <td>
                            <span class={`tag queue-state ${item.state}`} data-state={item.state} data-testid="queue-item-state">
                              {t(`cluster.queue.state.${item.state}`)}
                            </span>
                          </td>
                          <td class="r">
                            <button
                              type="button"
                              class="btn sm"
                              data-testid={`queue-cancel-${item.id}`}
                              aria-label={t("cluster.queue.cancel_named", { what: summaryText(item.summary) })}
                              onClick={() => setCancelling(item)}
                            >
                              {t("common.action.cancel")}
                            </button>
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </section>

          <section class="page-section" aria-labelledby="queue-changes-title" data-testid="queue-changes">
            <h2 id="queue-changes-title">
              {t("cluster.queue.changes.title")}
              <span class="aside">{t("cluster.queue.count", { count: changeItems().length })}</span>
            </h2>
            <p>{t("cluster.queue.changes.intro")}</p>
            <Show when={changeItems().length > 0} fallback={<p class="muted" data-testid="queue-changes-empty">{t("cluster.queue.changes.empty")}</p>}>
              <div class="table-wrap">
                <table class="plain" aria-label={t("cluster.queue.changes.title")}>
                  <thead>
                    <tr>
                      <th scope="col">{t("cluster.queue.col.change")}</th>
                      <th scope="col">{t("cluster.queue.col.queued")}</th>
                      <th scope="col">{t("cluster.queue.col.state")}</th>
                      <th scope="col">{t("cluster.queue.col.result")}</th>
                      <th scope="col" class="r">
                        <span class="sr-only">{t("cluster.queue.col.actions")}</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={changeItems()}>
                      {(change) => (
                        <tr data-testid={`queued-change-${change.id}`} data-id={change.id} data-state={change.state}>
                          <td>
                            <span data-testid="queued-change-summary">{summaryText(change.summary)}</span>
                            <Show when={change.summary?.key}>{(key) => <span class="mono"> {key()}</span>}</Show>
                          </td>
                          <td>
                            <TimeAgo at={change.queued_at} />
                          </td>
                          <td>
                            <span class={`tag queue-state ${change.state}`} data-state={change.state} data-testid="queued-change-state">
                              {t(`cluster.queue.change_state.${change.state}`)}
                            </span>
                          </td>
                          <td>
                            <Show when={change.state === "conflict" && change.conflict}>
                              {(conflict) => (
                                <span data-testid="queued-change-conflict" data-code={conflict().code}>
                                  {conflictText(conflict())} <code class="mono muted">{conflict().code}</code>
                                </span>
                              )}
                            </Show>
                            <Show when={change.job_id}>
                              {(job) => (
                                <A href={paths.job(job())} data-testid="queued-change-job">
                                  {t("cluster.done.open_job")}
                                </A>
                              )}
                            </Show>
                          </td>
                          <td class="r">
                            <Show when={change.state === "conflict"}>
                              <div class="cluster-actions end">
                                <button
                                  type="button"
                                  class="btn sm primary"
                                  data-testid={`queued-reapply-${change.id}`}
                                  aria-label={t("cluster.queue.reapply_named", { what: summaryText(change.summary) })}
                                  onClick={() => void openReapply(change)}
                                >
                                  {t("cluster.queue.reapply")}
                                </button>
                                <button
                                  type="button"
                                  class="btn sm"
                                  data-testid={`queued-discard-${change.id}`}
                                  aria-label={t("cluster.queue.discard_named", { what: summaryText(change.summary) })}
                                  onClick={() => setDiscarding(change)}
                                >
                                  {t("cluster.queue.discard")}
                                </button>
                              </div>
                            </Show>
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </section>
        </Show>
      </div>

      <Show when={cancelling()} keyed>
        {(item) => (
          <ConfirmDialog
            testid="dialog-cancel-queued"
            title={t("cluster.queue.cancel_title")}
            body={<p>{t("cluster.queue.cancel_body", { what: summaryText(item.summary) })}</p>}
            confirmLabel={t("cluster.queue.cancel_confirm")}
            cancelLabel={t("cluster.queue.keep")}
            danger
            onClose={() => setCancelling(null)}
            onConfirm={() => void cancel(item)}
          />
        )}
      </Show>
      <Show when={discarding()} keyed>
        {(change) => (
          <ConfirmDialog
            testid="dialog-discard-queued"
            title={t("cluster.queue.discard_title")}
            body={<p>{t("cluster.queue.discard_body", { what: summaryText(change.summary) })}</p>}
            confirmLabel={t("cluster.queue.discard")}
            cancelLabel={t("common.action.cancel")}
            danger
            onClose={() => setDiscarding(null)}
            onConfirm={() => void discard(change)}
          />
        )}
      </Show>
      <Show when={reapplying()} keyed>
        {(change) => (
          <PlanDialog
            testid="dialog-reapply"
            title={t("cluster.queue.reapply_title")}
            confirmLabel={t("cluster.queue.reapply_confirm")}
            intro={<p class="muted">{t("cluster.queue.reapply_intro", { what: summaryText(change.summary) })}</p>}
            send={(options) =>
              reapplyQueued(change.id, {
                dryRun: options.dryRun,
                acknowledge: options.acknowledge,
                ifMatch: options.dryRun ? undefined : change.revision,
              })
            }
            onDone={(result) => {
              setReapplying(null);
              const job = result.job_id;
              toast({
                kind: "ok",
                title: t("cluster.queue.reapplied"),
                actions: job ? [{ label: t("cluster.done.open_job"), run: () => navigate(paths.job(job)) }] : [],
              });
              refresh();
            }}
            onClose={() => setReapplying(null)}
          />
        )}
      </Show>
    </div>
  );
}
