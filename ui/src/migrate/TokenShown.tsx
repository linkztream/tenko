// The token of a mirror, shown once after its creation or replacement (plan section 2.1, rule
// 2): the token, its end and the fingerprint the exporter pins, each to copy. Closing the dialog
// forgets the token; the server never shows it again.
import { createSignal, Show } from "solid-js";
import { copyText } from "../auth/account/shared";
import { Dialog } from "../components/Dialog";
import { Notice } from "../components/Notice";
import { formatDateTime, t } from "../i18n";
import type { MirrorCreated } from "./api";

export function TokenShown(props: { created: MirrorCreated; onClose: () => void }) {
  // Esc and a click outside must not lose a secret the server shows once: close after the box.
  const [stored, setStored] = createSignal(false);
  const close = () => {
    if (stored()) props.onClose();
  };
  return (
    <Dialog label={t("migrate.token.title")} onClose={close} class="dialog" testid="dialog-mirror-token">
      <h2 class="dialog-title">{t("migrate.token.title")}</h2>
      <div class="dialog-body">
        <Notice kind="warn">{t("migrate.token.once")}</Notice>
        <dl class="kv">
          <dt>{t("migrate.token.token")}</dt>
          <dd class="mono" data-testid="mirror-token">
            {props.created.token}
          </dd>
          <Show when={props.created.token_expires_at}>
            {(end) => (
              <>
                <dt>{t("migrate.token.expires")}</dt>
                <dd>{formatDateTime(end())}</dd>
              </>
            )}
          </Show>
          <dt>{t("migrate.token.fingerprint")}</dt>
          <dd class="mono" data-testid="mirror-fingerprint">
            {props.created.ca_fingerprint ?? t("migrate.token.no_fingerprint")}
          </dd>
        </dl>
        <label class="ackrow">
          <input type="checkbox" class="cb" checked={stored()} data-testid="mirror-token-stored" onChange={(e) => setStored(e.currentTarget.checked)} />
          {t("migrate.token.stored")}
        </label>
      </div>
      <div class="dialog-actions">
        <button type="button" class="btn" data-testid="mirror-token-copy" onClick={() => void copyText(props.created.token)}>
          {t("migrate.token.copy")}
        </button>
        <button type="button" class="btn primary" data-testid="mirror-token-done" disabled={!stored()} onClick={close}>
          {t("migrate.token.done")}
        </button>
      </div>
    </Dialog>
  );
}
