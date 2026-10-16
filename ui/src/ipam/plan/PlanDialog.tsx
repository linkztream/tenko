// Preview, then apply (API-09): the dialog runs the write as a dry run first, shows the
// plan with its warnings, and applies it with the acknowledged warning codes when the person
// confirms. The confirm button names the action ("Delete prefix"); it stays disabled until
// every blocking warning is acknowledged. When the data changed in between (`ipam.plan.stale`)
// or a new blocking warning appeared, the dialog previews again instead of failing.
import { useNavigate } from "@solidjs/router";
import { createSignal, onMount, Show, type JSX } from "solid-js";
import { isApiError } from "../../api/problem";
import type { PlanView, PlanWarning } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { ErrorNotice, Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { paths } from "../../app/paths";
import { t } from "../../i18n";
import { codesToAcknowledge } from "./describe";
import { PlanPreview } from "./PlanPreview";
import "./plan.css";

/** What every IPAM write answers (WriteResponse and BulkResponse share these members). */
export interface WriteLike {
  dry_run: boolean;
  plan?: PlanView | null;
  warnings: PlanWarning[];
  job_id?: string | null;
  revision?: number | null;
}

export interface SendOptions {
  dryRun: boolean;
  acknowledge: string[];
}

export type Send<R extends WriteLike> = (options: SendOptions) => Promise<R>;

export function PlanDialog<R extends WriteLike>(props: {
  title: string;
  /** The verb of the confirm button, naming the action and the count. */
  confirmLabel: string;
  danger?: boolean;
  /** Context above the plan, for example what the form will create. */
  intro?: JSX.Element;
  /** What the preview found, shown above the plan (the next free address, for example). */
  describe?: (preview: R) => JSX.Element;
  /** The confirm label once the preview is known ("Claim 192.0.2.6"). */
  confirmFor?: (preview: R) => string;
  send: Send<R>;
  onDone: (result: R) => void;
  onClose: () => void;
  testid?: string;
}) {
  const [preview, setPreview] = createSignal<R | null>(null);
  const [error, setError] = createSignal<unknown>(null);
  const [busy, setBusy] = createSignal(true);
  const [note, setNote] = createSignal<string | null>(null);
  const [acked, setAcked] = createSignal<ReadonlySet<string>>(new Set());
  let confirm: HTMLButtonElement | undefined;

  const runPreview = async () => {
    setBusy(true);
    setError(null);
    try {
      setPreview(() => null);
      const result = await props.send({ dryRun: true, acknowledge: [...acked()] });
      setPreview(() => result);
      queueMicrotask(() => confirm?.focus());
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  onMount(() => void runPreview());

  const blocking = () => codesToAcknowledge(preview()?.warnings ?? []).filter((c) => !acked().has(c));

  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await props.send({ dryRun: false, acknowledge: [...acked()] });
      props.onDone(result);
    } catch (err) {
      if (isApiError(err, "ipam.plan.stale") || isApiError(err, "ipam.plan.unacknowledged")) {
        setNote(t("ipam.plan.stale"));
        await runPreview();
        return;
      }
      setError(err);
      setBusy(false);
    }
  };

  return (
    <Dialog label={props.title} onClose={props.onClose} class="dialog plan-dialog">
      <div data-testid={props.testid ?? "dialog-plan"} class="plan-dialog-body">
        <h2 class="dialog-title">{props.title}</h2>
        {props.intro}
        <Show when={note()}>
          <Notice kind="info" role="status">
            {note()}
          </Notice>
        </Show>
        <Show when={preview() && props.describe}>{props.describe?.(preview() as R)}</Show>
        <Show when={preview()} fallback={<Show when={!error()}><p class="muted" role="status">{t("ipam.plan.previewing")}</p></Show>}>
          {(p) => (
            <PlanPreview
              plan={p().plan}
              warnings={p().warnings}
              acknowledged={acked()}
              onAcknowledge={(code, on) => {
                const next = new Set(acked());
                if (on) next.add(code);
                else next.delete(code);
                setAcked(next);
              }}
            />
          )}
        </Show>
        <ErrorNotice error={error()} />
        <Show when={preview() && blocking().length > 0}>
          <p class="muted">{t("ipam.plan.ack_needed")}</p>
        </Show>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="plan-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button
            ref={confirm}
            type="button"
            class={props.danger ? "btn danger" : "btn primary"}
            disabled={busy() || !preview() || blocking().length > 0}
            data-testid="plan-confirm"
            onClick={() => void apply()}
          >
            {preview() && props.confirmFor ? props.confirmFor(preview() as R) : props.confirmLabel}
          </button>
        </div>
      </div>
    </Dialog>
  );
}

/** The result toast of a write: the verb of the action and a way to the job that carried it. */
export function useWriteToast() {
  const navigate = useNavigate();
  return (title: string, result: WriteLike, extra: { label: string; run: () => void }[] = []) => {
    const actions = [...extra];
    const job = result.job_id;
    if (job) actions.push({ label: t("ipam.plan.open_job"), run: () => navigate(paths.job(job)) });
    toast({ kind: "ok", title, actions });
  };
}
