// Replacing the value of a secret (IAM-15): one field, sent with the revision the person
// looked at. Like the value of a new secret, it lives in a signal only until the request has
// ended and is never shown. Bindings to hosts and connectors are not touched.
import { createSignal, onCleanup, Show, untrack } from "solid-js";
import { isApiError } from "../api/problem";
import { Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { t } from "../i18n";
import { getSecret, updateSecret, type OperatorSecret } from "./api";
import { ConflictNotice, FieldNote } from "./FormParts";
import { fieldProblem, generalProblem, revisionOf } from "./model";
import "./secrets.css";

export function ReplaceValueDialog(props: {
  secret: OperatorSecret;
  onSaved: (secret: OperatorSecret) => void;
  /** The person loaded the latest version of a secret that had changed: the list is stale. */
  onReloaded?: () => void;
  onClose: () => void;
}) {
  const [base, setBase] = createSignal(untrack(() => props.secret));
  const [value, setValue] = createSignal("");
  const [cleared, setCleared] = createSignal(false);
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [reloaded, setReloaded] = createSignal(false);
  let input: HTMLInputElement | HTMLTextAreaElement | undefined;

  const forgetValue = () => {
    setValue("");
    if (input) input.value = "";
  };
  onCleanup(forgetValue);

  const required = () => submitted() && value() === "" && !cleared();
  const valueError = () =>
    fieldProblem(error(), "value") ?? (required() ? t("secrets.form.error.value_required") : undefined);
  const otherError = () => {
    const general = generalProblem(error());
    return isApiError(general, "vault.secret.conflict") ? null : general;
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    if (busy()) return;
    setSubmitted(true);
    if (value() === "") return;
    setBusy(true);
    setError(null);
    setReloaded(false);
    let saved: OperatorSecret | undefined;
    try {
      saved = await updateSecret(base().id, { value: value() }, revisionOf(base()));
    } catch (err) {
      setError(err);
    } finally {
      // The request is over, whatever it said: the value does not stay in the form.
      setCleared(true);
      forgetValue();
      setBusy(false);
    }
    if (saved) props.onSaved(saved);
  };

  const reload = async () => {
    if (busy()) return;
    setBusy(true);
    try {
      setBase(await getSecret(base().id));
      setError(null);
      setReloaded(true);
      props.onReloaded?.();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const title = () => t("secrets.replace.title", { name: props.secret.name });

  return (
    <Dialog
      label={title()}
      onClose={props.onClose}
      class="dialog secret-dialog"
      testid="dialog-secret-value"
      initialFocus={() => input}
    >
      <form class="secret-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{title()}</h2>
        <div class="dialog-body">
          <ConflictNotice error={error()} busy={busy()} onReload={() => void reload()} />
          <ErrorNotice error={otherError()} />
          <Show when={reloaded()}>
            <p class="muted" role="status" data-testid="secret-reloaded">
              {t("secrets.form.reloaded")}
            </p>
          </Show>
          <p>{t("secrets.replace.lead")}</p>
          <div class="field">
            <label for="sv-value">{t("secrets.replace.field")}</label>
            {/* An SSH key has line breaks, which a password field drops: it gets a text area. */}
            <Show
              when={base().kind === "ssh_key"}
              fallback={
                <input
                  ref={(el) => (input = el)}
                  id="sv-value"
                  class="input mono"
                  type="password"
                  data-testid="field-value"
                  autocomplete="new-password"
                  autocapitalize="off"
                  spellcheck={false}
                  value={value()}
                  aria-invalid={valueError() ? "true" : undefined}
                  aria-describedby="sv-value-help"
                  onInput={(e) => {
                    setCleared(false);
                    setValue(e.currentTarget.value);
                  }}
                />
              }
            >
              <textarea
                ref={(el) => (input = el)}
                id="sv-value"
                class="input mono"
                rows={6}
                data-testid="field-value"
                autocomplete="off"
                autocapitalize="off"
                spellcheck={false}
                value={value()}
                aria-invalid={valueError() ? "true" : undefined}
                aria-describedby="sv-value-help"
                onInput={(e) => {
                  setCleared(false);
                  setValue(e.currentTarget.value);
                }}
              />
            </Show>
            <FieldNote
              id="sv-value-help"
              help={
                cleared()
                  ? t("secrets.form.value_cleared")
                  : base().kind === "ssh_key"
                    ? t("secrets.form.value_key_help")
                    : t("secrets.form.value_help")
              }
              error={valueError()}
            />
          </div>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("secrets.replace.submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
