// The dialog of the scans page: stopping every scan, with an optional reason that the probes
// show next to their kill switch and the audit log keeps.
import { createSignal } from "solid-js";
import { Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { t } from "../i18n";
import { stopAllScans } from "./api";
import type { KillSwitchResult } from "./model";

/** The longest reason the server keeps, in characters. */
const MAX_REASON = 200;

/** Turns the kill switch of every probe on; `onDone` gets the commands the server sent. */
export function StopDialog(props: { onDone: (result: KillSwitchResult) => void; onClose: () => void }) {
  const [reason, setReason] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  const submit = async (e: Event) => {
    e.preventDefault();
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      props.onDone(await stopAllScans(reason().trim() || undefined));
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("scans.stop.title")} onClose={props.onClose} class="dialog scans-dialog" testid="dialog-stop-scans">
      <form class="scans-form" onSubmit={(e) => void submit(e)}>
        <h2 class="dialog-title">{t("scans.stop.title")}</h2>
        <p>{t("scans.stop.body")}</p>
        <div class="field">
          <label for="stop-scans-reason">{t("scans.stop.reason")}</label>
          <textarea
            id="stop-scans-reason"
            class="input"
            rows={3}
            maxLength={MAX_REASON}
            value={reason()}
            data-testid="field-reason"
            aria-describedby="stop-scans-reason-help"
            onInput={(e) => setReason(e.currentTarget.value)}
          />
          <small id="stop-scans-reason-help" class="help">
            {t("scans.stop.reason_hint")}
          </small>
        </div>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="confirm-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn danger" data-testid="confirm-ok" disabled={busy()}>
            {t("scans.stop.confirm")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
