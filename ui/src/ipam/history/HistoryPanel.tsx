// The history of one IPAM object (IPAM-09), newest first: who did what and when, the job that
// carried it and the fields it changed. A deleted object can be restored from here. The list
// follows the live events: a change of the object loads the first page again.
import { createEffect, createSignal, For, on, onCleanup, onMount, Show } from "solid-js";
import { events } from "../../api/events";
import { writesAny } from "../../auth/gate";
import type { HistoryEntry } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { PrincipalLabel } from "../../components/Principal";
import { TimeAgo } from "../../grid/cells";
import { t } from "../../i18n";
import { historyPage, type Collection } from "../collections";
import { RestoreDialog } from "../DeleteDialog";
import "../forms.css";

/** The kind of object a collection holds, for the words of the restore dialog. */
const KIND_OF: Readonly<Record<Collection, string>> = {
  tenants: "tenant",
  vrfs: "vrf",
  sites: "site",
  vlans: "vlan",
  prefixes: "prefix",
  ranges: "range",
  addresses: "address",
  hosts: "host",
  interfaces: "interface",
};

interface PanelProps {
  collection: Collection;
  id: string;
  /** What the person knows the object by, for the restore dialog and the headings. */
  label: string;
  deleted?: boolean | undefined;
  revision?: number | null | undefined;
  /**
   * Whether the principal may restore the object (the caller judges it by the object's anchors).
   * Without an answer, anybody who writes anything sees the button; the server decides.
   */
  mayRestore?: boolean | undefined;
  /** Called after the object was restored from the history. */
  onRestored?: (() => void) | undefined;
}

export function HistoryPanel(props: PanelProps) {
  const [entries, setEntries] = createSignal<HistoryEntry[]>([]);
  const [next, setNext] = createSignal<string | null>(null);
  const [loaded, setLoaded] = createSignal(false);
  const [loadingMore, setLoadingMore] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [restoring, setRestoring] = createSignal(false);
  let controller: AbortController | undefined;
  let generation = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const aborted = (err: unknown) => err instanceof DOMException && err.name === "AbortError";

  /** The first page; what was loaded further is dropped, as the list may have moved on. */
  const load = async () => {
    controller?.abort();
    controller = new AbortController();
    const mine = ++generation;
    try {
      const page = await historyPage(props.collection, props.id, null, controller.signal);
      if (mine !== generation) return;
      setEntries(page.items);
      setNext(page.next_cursor ?? null);
      setError(null);
    } catch (err) {
      if (mine !== generation || aborted(err)) return;
      setError(err);
    } finally {
      if (mine === generation) setLoaded(true);
    }
  };

  const loadMore = async () => {
    const cursor = next();
    if (!cursor || loadingMore()) return;
    const mine = generation;
    setLoadingMore(true);
    try {
      const page = await historyPage(props.collection, props.id, cursor, controller?.signal);
      if (mine !== generation) return;
      setEntries([...entries(), ...page.items]);
      setNext(page.next_cursor ?? null);
    } catch (err) {
      if (mine === generation && !aborted(err)) setError(err);
    } finally {
      setLoadingMore(false);
    }
  };

  createEffect(
    on(
      () => [props.collection, props.id] as const,
      () => {
        setLoaded(false);
        void load();
      },
    ),
  );

  onMount(() => {
    const schedule = () => {
      clearTimeout(timer);
      timer = setTimeout(() => void load(), 150);
    };
    // eslint-disable-next-line solid/reactivity -- an event callback, like an event handler
    const off = events.subscribe("ipam", (event) => {
      if ([...event.objects, ...event.deleted].some((o) => o.id === props.id)) schedule();
    });
    // eslint-disable-next-line solid/reactivity -- an event callback, like an event handler
    const offReset = events.onReset("ipam", () => void load());
    onCleanup(() => {
      off();
      offReset();
      clearTimeout(timer);
      controller?.abort();
    });
  });

  return (
    <section class="history" data-testid="history-panel" aria-label={t("ipam.history.label", { label: props.label })}>
      <Show when={props.deleted && (props.mayRestore ?? writesAny())}>
        <div class="history-head">
          <button type="button" class="btn" data-testid="history-restore" onClick={() => setRestoring(true)}>
            <Icon name="undo" />
            {t("ipam.do.restore")}
          </button>
        </div>
      </Show>
      <Show when={error()}>
        <ErrorNotice error={error()} />
        <button type="button" class="btn sm history-more" onClick={() => void load()}>
          {t("common.action.retry")}
        </button>
      </Show>
      <Show when={loaded()} fallback={<p class="muted" role="status">{t("common.loading")}</p>}>
        <Show when={entries().length > 0} fallback={<Show when={!error()}><p class="muted">{t("ipam.history.empty")}</p></Show>}>
          <ol class="history-list">
            <For each={entries()}>{(entry) => <Entry entry={entry} />}</For>
          </ol>
        </Show>
        <Show when={next()}>
          <button type="button" class="btn sm history-more" data-testid="history-more" disabled={loadingMore()} onClick={() => void loadMore()}>
            {t("ipam.history.more")}
          </button>
        </Show>
      </Show>
      <Show when={restoring()}>
        <RestoreDialog
          collection={props.collection}
          id={props.id}
          kind={KIND_OF[props.collection]}
          label={props.label}
          revision={props.revision}
          onClose={() => setRestoring(false)}
          onDone={() => {
            setRestoring(false);
            void load();
            props.onRestored?.();
          }}
        />
      </Show>
    </section>
  );
}

function Entry(props: { entry: HistoryEntry }) {
  const changes = () => props.entry.changes ?? [];
  return (
    <li class="history-entry" data-testid="history-entry" data-action={props.entry.action}>
      <div class="history-line">
        <span class={`history-action ${props.entry.action}`}>{t(`ipam.plan.change.${props.entry.action}`)}</span>
        <PrincipalLabel principal={props.entry.by} />
        <TimeAgo at={props.entry.at} />
        <Show when={props.entry.job_kind}>{(kind) => <span class="tag mono">{kind()}</span>}</Show>
      </div>
      <Show when={changes().length > 0}>
        <ul class="history-changes">
          <For each={changes()}>
            {(change) => (
              <li data-field={change.field}>
                <span class="muted">{change.field}:</span> <del class="mono">{change.old ?? "–"}</del>
                {" → "}
                <ins class="mono">{change.new ?? "–"}</ins>
              </li>
            )}
          </For>
        </ul>
      </Show>
    </li>
  );
}

/** The history in a dialog of its own, for lists whose rows have no page. */
export function HistoryDialog(props: PanelProps & { onClose: () => void }) {
  return (
    <Dialog label={t("ipam.history.title", { label: props.label })} onClose={props.onClose} class="dialog history-dialog">
      <div data-testid="dialog-history">
        <h2 class="dialog-title">{t("ipam.history.title", { label: props.label })}</h2>
        <HistoryPanel
          collection={props.collection}
          id={props.id}
          label={props.label}
          deleted={props.deleted}
          mayRestore={props.mayRestore}
          revision={props.revision}
          onRestored={() => {
            props.onRestored?.();
            props.onClose();
          }}
        />
        <div class="dialog-actions">
          <button type="button" class="btn" onClick={() => props.onClose()}>
            {t("common.action.close")}
          </button>
        </div>
      </div>
    </Dialog>
  );
}
