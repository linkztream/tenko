// Deleting a secret (IAM-15). The page reads what uses the secret before it opens this
// dialog: while a host or a connector still uses it, the dialog only lists them and says
// they must be unbound first (there is no delete button); otherwise it asks for a
// confirmation that names the secret. The server has the last word: a 409
// `vault.secret.in_use` (something bound it meanwhile) turns the confirmation into the list,
// a 409 `vault.secret.conflict` offers to load the latest revision.
import { createSignal, Show, untrack } from "solid-js";
import { isApiError } from "../api/problem";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { t } from "../i18n";
import { deleteSecret, getSecret, secretReferences, type OperatorSecret, type SecretReferences } from "./api";
import { ConflictNotice } from "./FormParts";
import { revisionOf } from "./model";
import { referenceCount, ReferenceLists } from "./References";
import "./secrets.css";

export function DeleteSecretDialog(props: {
  secret: OperatorSecret;
  references: SecretReferences;
  onDeleted: () => void;
  /** The person loaded the latest version of a secret that had changed: the list is stale. */
  onReloaded?: () => void;
  onClose: () => void;
}) {
  const [base, setBase] = createSignal(untrack(() => props.secret));
  const [references, setReferences] = createSignal(untrack(() => props.references));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  const used = () => referenceCount(references()) > 0;
  const refused = () => isApiError(error(), "vault.secret.in_use");

  const confirm = async () => {
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      await deleteSecret(base().id, revisionOf(base()));
      props.onDeleted();
    } catch (err) {
      setError(err);
      if (isApiError(err, "vault.secret.in_use")) {
        try {
          setReferences(await secretReferences(base().id));
        } catch {
          // The refusal itself is shown below.
        }
      }
    } finally {
      setBusy(false);
    }
  };

  const reload = async () => {
    if (busy()) return;
    setBusy(true);
    try {
      const [secret, refs] = await Promise.all([getSecret(base().id), secretReferences(base().id)]);
      setBase(secret);
      setReferences(refs);
      setError(null);
      props.onReloaded?.();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Show
      when={used() || refused()}
      fallback={
        <ConfirmDialog
          title={t("secrets.delete.title", { name: base().name })}
          body={
            <>
              <ConflictNotice error={error()} busy={busy()} onReload={() => void reload()} />
              <Show when={!isApiError(error(), "vault.secret.conflict")}>
                <ErrorNotice error={error()} />
              </Show>
              <p>{t("secrets.delete.body", { name: base().name })}</p>
            </>
          }
          confirmLabel={t("secrets.delete.confirm")}
          cancelLabel={t("common.action.cancel")}
          danger
          busy={busy()}
          onConfirm={() => void confirm()}
          onClose={props.onClose}
        />
      }
    >
      <Dialog
        label={t("secrets.delete.in_use_title", { name: base().name })}
        onClose={props.onClose}
        class="dialog secret-dialog"
        testid="dialog-secret-delete"
      >
        <h2 class="dialog-title">{t("secrets.delete.in_use_title", { name: base().name })}</h2>
        <div class="dialog-body">
          <Show when={!used()}>
            <ErrorNotice error={error()} />
          </Show>
          <p>{t("secrets.delete.in_use_lead")}</p>
          <ReferenceLists references={references()} />
          <p class="muted">{t("secrets.delete.in_use_hint")}</p>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn primary" data-testid="secret-delete-close" onClick={() => props.onClose()}>
            {t("common.action.close")}
          </button>
        </div>
      </Dialog>
    </Show>
  );
}
