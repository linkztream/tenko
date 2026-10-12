// Stopping the scans of one probe from the controllers (docs/scanning.md, section 7.6): the
// optional reason that is kept with the kill switch and the audit record, then the stop command.
import { createSignal } from "solid-js";
import { errorMessage } from "../api/problem";
import { Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { stopNodeScans } from "../scans/api";

/** The longest reason the controllers keep. */
const MAX_REASON = 200;

export function StopProbeDialog(props: { node: number; name: string; onStopped: () => void; onClose: () => void }) {
  const [reason, setReason] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const tooLong = () => reason().trim().length > MAX_REASON;

  const submit = async (e: Event) => {
    e.preventDefault();
    if (busy() || tooLong()) return;
    setBusy(true);
    setError(null);
    try {
      await stopNodeScans(props.node, reason().trim() || undefined);
      toast({ kind: "ok", title: t("nodes.scan.stop.done", { name: props.name }) });
      props.onStopped();
    } catch (err) {
      setError(err);
      toast({ kind: "bad", title: t("nodes.scan.stop.failed", { name: props.name }), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("nodes.scan.stop.title", { name: props.name })} onClose={props.onClose} class="dialog nodes-dialog">
      <form class="nodes-form" data-testid="dialog-stop-probe" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("nodes.scan.stop.title", { name: props.name })}</h2>
        <p>{t("nodes.scan.stop.body")}</p>
        <div class="field">
          <label for="stop-reason">{t("nodes.scan.stop.reason")}</label>
          <textarea
            id="stop-reason"
            class="input"
            rows={3}
            value={reason()}
            data-testid="field-reason"
            aria-invalid={tooLong() ? "true" : undefined}
            aria-describedby="stop-reason-help"
            onInput={(e) => setReason(e.currentTarget.value)}
          />
          <small id="stop-reason-help" class={tooLong() ? "help bad" : "help"}>
            {tooLong() ? t("nodes.scan.stop.reason_too_long", { max: MAX_REASON }) : t("nodes.scan.stop.reason_help", { max: MAX_REASON })}
          </small>
        </div>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn danger" disabled={busy()} data-testid="form-submit">
            {t("nodes.scan.stop.submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
