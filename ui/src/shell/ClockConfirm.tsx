// The confirmation of a held clock (`POST /system/clock/confirm`), from the clock's finding: the
// node's time in UTC and in the browser's time zone to compare with, and the confirm. The
// request names the node of the finding, which alone confirms; the server needs a sign-in
// within five minutes and the system administration right, and its refusal shows in the dialog.
//
// Test ids: `dialog-clock-confirm`, `form-cancel`, `form-submit`.
import { createResource, createSignal } from "solid-js";
import { api } from "../api/client";
import { Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { formatDateTime, t } from "../i18n";

export function ClockConfirm(props: { node: string; onClose: () => void; onDone?: () => void }) {
  // The node's own time: the host sample of its status, read when the dialog opens.
  const [status] = createResource(() => api.get("/api/v1/system/status").catch(() => null));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const read = (options: Intl.DateTimeFormatOptions) => {
    const at = status()?.host?.sampled_at;
    return at ? formatDateTime(at, options) : "…";
  };
  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post("/api/v1/system/clock/confirm", { body: { node: props.node } });
      props.onDone?.();
      props.onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  const title = () => t("shell.clock.confirm.title", { node: props.node });

  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog" testid="dialog-clock-confirm">
      <h2 class="dialog-title">{title()}</h2>
      <div class="dialog-body">
        <ErrorNotice error={error()} />
        <p>
          {t("shell.clock.confirm.body", {
            utc: read({ dateStyle: "medium", timeStyle: "medium", timeZone: "UTC" }),
            local: read({ dateStyle: "medium", timeStyle: "long" }),
          })}
        </p>
      </div>
      <div class="dialog-actions">
        <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
          {t("common.action.cancel")}
        </button>
        <button type="button" class="btn primary" data-testid="form-submit" disabled={busy()} onClick={() => void confirm()}>
          {t("shell.clock.confirm.confirm")}
        </button>
      </div>
    </Dialog>
  );
}
