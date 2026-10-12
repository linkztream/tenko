// What the shell shows of the partition state (OPS-26), loaded with the cluster pack once there is
// something to show: the banner while this controller is isolated or electing a leader (how long,
// and that writes are refused but can be queued) or while queued changes wait for a decision after
// a heal; the age of the local copy in the status bar; and the dialog of a refused write. One
// module, so the first load names one lazy chunk for all of them.
import { A } from "@solidjs/router";
import { createEffect, createSignal, on, Show } from "solid-js";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { formatDateTime, formatDuration, t } from "../i18n";
import { now } from "../shell/status";
import { listQueuedChanges, queueChange, queueRequestOf } from "./api";
import { type QueueItem, CLUSTER_QUEUE_PATH } from "./model";
import { partition, refusesWrites, type RefusedWrite } from "./partition";

/** What `Tenko-Staleness: since=<RFC 3339>; revision=<n>` says. */
export interface Staleness {
  since: string;
  revision: number | null;
}

/** Parses the `Tenko-Staleness` header; null when absent or malformed. */
export function parseStaleness(header: string | null | undefined): Staleness | null {
  if (!header) return null;
  const fields = new Map<string, string>();
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) fields.set(part.slice(0, i).trim().toLowerCase(), part.slice(i + 1).trim());
  }
  const since = fields.get("since");
  if (!since || Number.isNaN(Date.parse(since))) return null;
  const revision = Number(fields.get("revision"));
  return {
    since,
    revision: fields.has("revision") && Number.isInteger(revision) ? revision : null,
  };
}

/** The time since `since` in its largest whole unit, for "isolated for 4 min". */
export function sinceText(since: string | null | undefined, at: number): string | null {
  const from = since ? Date.parse(since) : Number.NaN;
  if (Number.isNaN(from)) return null;
  const secs = Math.max(0, Math.floor((at - from) / 1000));
  const unit = secs >= 86_400 ? 86_400 : secs >= 3600 ? 3600 : secs >= 60 ? 60 : 1;
  return formatDuration(Math.floor(secs / unit) * unit);
}

/** Counts the person's queued changes that wait for a decision; errors leave the count as it is. */
export async function loadConflicts(): Promise<void> {
  try {
    const { items } = await listQueuedChanges();
    partition.setConflicts(items.filter((c) => c.state === "conflict").length);
  } catch {
    // No queue on this server yet, or no access: nothing to show.
  }
}

/**
 * The partition banner; it cannot be dismissed. One at a time: isolation, election, decisions.
 * When the quorum comes back it forgets the staleness and loads the decisions the heal left.
 */
/**
 * The one lazy entry of the shell: the stale status with `status`, the dialog of a refused write
 * with `refused`, else the banner.
 */
export default function PartitionStatus(props: { status?: boolean; refused?: RefusedWrite }) {
  return (
    <Show when={!props.status} fallback={<StaleStatus />}>
      <Show when={props.refused} fallback={<PartitionBanner />}>
        {(refused) => <NoQuorumDialog refused={refused()} onClose={() => partition.setRefused(null)} />}
      </Show>
    </Show>
  );
}

function PartitionBanner() {
  createEffect(
    on(
      () => refusesWrites(partition.quorum()),
      (refusing, was) => {
        if (was && !refusing) {
          partition.setStaleness(null);
          void loadConflicts();
        }
      },
    ),
  );
  const banner = () => {
    const quorum = partition.quorum();
    const duration = sinceText(quorum?.since, now()) ?? "–";
    if (quorum?.state === "isolated") {
      return {
        state: "isolated",
        kind: "danger",
        title: t("cluster.partition.isolated.title"),
        body: t("cluster.partition.isolated.body", { duration }),
      };
    }
    if (quorum?.state === "electing") {
      return {
        state: "electing",
        kind: "warn",
        title: t("cluster.partition.electing.title"),
        body: t("cluster.partition.electing.body", { duration }),
      };
    }
    const count = partition.conflicts();
    return count > 0
      ? {
          state: "conflicts",
          kind: "warn",
          title: "",
          body: t("cluster.partition.conflicts", { count }),
        }
      : null;
  };

  return (
    <Show when={banner()}>
      {(b) => (
        <div
          class={`banner ${b().kind}`}
          role={b().kind === "danger" ? "alert" : "status"}
          data-testid="cluster-banner"
          data-state={b().state}
        >
          <Icon name="alert" />
          <Show when={b().title}>
            <strong>{b().title}</strong>
          </Show>
          <span class="grow">{b().body}</span>
          <A class="btn sm" href={CLUSTER_QUEUE_PATH}>
            {b().title ? t("cluster.partition.queue_link") : t("cluster.partition.review")}
          </A>
        </div>
      )}
    </Show>
  );
}

/**
 * The age of the local copy while this controller answers without a quorum: from the
 * `Tenko-Staleness` header of the last answer, else from the isolation the banner shows.
 */
export function StaleStatus() {
  const stale = () => {
    const header = parseStaleness(partition.staleness());
    if (header) return header;
    const quorum = partition.quorum();
    return quorum?.state === "isolated" ? { since: quorum.since, revision: quorum.applied ?? null } : null;
  };
  return (
    <Show when={stale()}>
      {(s) => (
        <span
          class="status-stale"
          title={t("cluster.partition.stale_title", {
            revision: s().revision ?? "–",
          })}
          data-testid="status-stale"
        >
          <span class="dot bad" />
          {t("cluster.partition.stale", {
            age: sinceText(s().since, now()) ?? "–",
          })}
        </span>
      )}
    </Show>
  );
}

/**
 * The dialog of a write refused with 503 `cluster.no_quorum`: the controller cannot reach a quorum,
 * so it refuses changes. An IPAM write (`queueable`) can be queued on this controller; it is planned
 * again and applied when the cluster heals, or waits for the person's decision.
 */
export function NoQuorumDialog(props: { refused: RefusedWrite; onClose: () => void }) {
  const queueable = () => props.refused.error.params.queueable === "true";
  const since = () => props.refused.error.params.since;
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [queued, setQueued] = createSignal<QueueItem | null>(null);

  const queue = async () => {
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      setQueued(await queueChange(queueRequestOf(props.refused.write)));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("cluster.no_quorum.title")} onClose={props.onClose} testid="dialog-no-quorum">
      <h2 class="dialog-title">{t("cluster.no_quorum.title")}</h2>
      <p>
        <Show when={since()} fallback={t("cluster.no_quorum.body")}>
          {(at) => t("cluster.no_quorum.body_since", { since: formatDateTime(at()) })}
        </Show>
      </p>
      <Show
        when={queued()}
        fallback={
          <p class="muted" data-testid="no-quorum-hint">
            {queueable() ? t("cluster.no_quorum.queueable") : t("cluster.no_quorum.not_queueable")}
          </p>
        }
      >
        {(item) => (
          <p role="status" data-testid="no-quorum-queued">
            {t("cluster.no_quorum.queued", { expires: formatDateTime(item().expires_at) })}{" "}
            <A href={CLUSTER_QUEUE_PATH} onClick={() => props.onClose()}>
              {t("cluster.no_quorum.show_queue")}
            </A>
          </p>
        )}
      </Show>
      <ErrorNotice error={error()} />
      <div class="dialog-actions">
        <button type="button" class="btn ghost" onClick={() => props.onClose()} data-testid="no-quorum-close">
          {queued() ? t("common.action.close") : t("common.action.cancel")}
        </button>
        <Show when={queueable() && !queued()}>
          <button type="button" class="btn primary" disabled={busy()} onClick={() => void queue()} data-testid="no-quorum-queue">
            {t("cluster.no_quorum.queue")}
          </button>
        </Show>
      </div>
    </Dialog>
  );
}
