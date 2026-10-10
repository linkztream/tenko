// The form that creates a secret or edits its metadata (IAM-15). The value is typed only
// when a secret is created: it lives in a signal until the request has ended, whatever the
// answer was, and is never shown. An edit sends only the members that changed, `null` to
// clear the user name or the notes, with the revision the person looked at; if someone else
// changed the secret meanwhile, the dialog says so and offers to load the latest version.
import { createSignal, For, onCleanup, Show, untrack } from "solid-js";
import { errorMessage, isApiError } from "../api/problem";
import { Dialog } from "../components/Dialog";
import { ErrorNotice, Notice } from "../components/Notice";
import { t } from "../i18n";
import {
  createSecret,
  getSecret,
  updateSecret,
  type NewOperatorSecret,
  type OperatorSecret,
  type OperatorSecretPatch,
  type SecretKind,
} from "./api";
import { ConflictNotice, FieldNote } from "./FormParts";
import { fieldProblem, generalProblem, kindText, parseTags, revisionOf, SECRET_KINDS, tagsText } from "./model";
import "./secrets.css";

export function SecretFormDialog(props: {
  /** The secret to edit; absent when a new secret is created. */
  secret?: OperatorSecret;
  onSaved: (secret: OperatorSecret) => void;
  /** The person loaded the latest version of a secret that had changed: the list is stale. */
  onReloaded?: () => void;
  onClose: () => void;
}) {
  const [base, setBase] = createSignal<OperatorSecret | undefined>(untrack(() => props.secret));
  const editing = () => base() !== undefined;
  const [name, setName] = createSignal(untrack(() => props.secret?.name ?? ""));
  const [kind, setKind] = createSignal<SecretKind>(untrack(() => props.secret?.kind ?? "password"));
  const [username, setUsername] = createSignal(untrack(() => props.secret?.username ?? ""));
  const [tags, setTags] = createSignal(untrack(() => tagsText(props.secret?.tags ?? [])));
  const [notes, setNotes] = createSignal(untrack(() => props.secret?.notes ?? ""));
  // The value of a new secret: kept only until the request has ended.
  const [value, setValue] = createSignal("");
  const [cleared, setCleared] = createSignal(false);
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [reloaded, setReloaded] = createSignal(false);
  let nameInput: HTMLInputElement | undefined;
  let valueInput: HTMLInputElement | HTMLTextAreaElement | undefined;

  const forgetValue = () => {
    setValue("");
    if (valueInput) valueInput.value = "";
  };
  onCleanup(forgetValue);

  /** The members that differ from the secret on screen, in the shape of the PATCH body. */
  const changes = (): OperatorSecretPatch => {
    const secret = base();
    const patch: OperatorSecretPatch = {};
    if (!secret) return patch;
    const nextName = name().trim();
    if (nextName !== secret.name) patch.name = nextName;
    if (kind() !== secret.kind) patch.kind = kind();
    const nextUser = username().trim();
    if (nextUser !== (secret.username ?? "")) patch.username = nextUser === "" ? null : nextUser;
    const nextTags = parseTags(tags());
    if (nextTags.join(",") !== secret.tags.join(",")) patch.tags = nextTags;
    const nextNotes = notes().trim() === "" ? "" : notes();
    if (nextNotes !== (secret.notes ?? "")) patch.notes = nextNotes === "" ? null : nextNotes;
    return patch;
  };
  const unchanged = () => editing() && Object.keys(changes()).length === 0;

  const nameError = () =>
    fieldProblem(error(), "name") ??
    (submitted() && name().trim() === "" ? t("secrets.form.error.name_required") : undefined);
  const valueRequired = () => submitted() && !editing() && value() === "" && !cleared();
  const valueError = () =>
    fieldProblem(error(), "value") ?? (valueRequired() ? t("secrets.form.error.value_required") : undefined);
  const pinCoupling = () => isApiError(error(), "vault.pin_coupling");
  const otherError = () => {
    const general = generalProblem(error());
    return isApiError(general, "vault.pin_coupling") || isApiError(general, "vault.secret.conflict") ? null : general;
  };

  const newBody = (): NewOperatorSecret => {
    const body: NewOperatorSecret = { name: name().trim(), kind: kind(), tags: parseTags(tags()), value: value() };
    const user = username().trim();
    if (user !== "") body.username = user;
    if (notes().trim() !== "") body.notes = notes();
    return body;
  };

  const send = async (): Promise<OperatorSecret | undefined> => {
    const current = base();
    try {
      if (current) {
        const patch = changes();
        if (Object.keys(patch).length === 0) return undefined;
        return await updateSecret(current.id, patch, revisionOf(current));
      }
      return await createSecret(newBody());
    } catch (err) {
      setError(err);
      return undefined;
    } finally {
      // The request is over, whatever it said: the value does not stay in the form.
      if (!editing() && value() !== "") setCleared(true);
      forgetValue();
    }
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    if (busy()) return;
    setSubmitted(true);
    if (name().trim() === "" || (!editing() && value() === "")) return;
    setBusy(true);
    setError(null);
    setReloaded(false);
    const saved = await send();
    setBusy(false);
    if (saved) props.onSaved(saved);
  };

  const reload = async () => {
    const current = base();
    if (!current || busy()) return;
    setBusy(true);
    try {
      const fresh = await getSecret(current.id);
      setBase(fresh);
      setName(fresh.name);
      setKind(fresh.kind);
      setUsername(fresh.username ?? "");
      setTags(tagsText(fresh.tags));
      setNotes(fresh.notes ?? "");
      setError(null);
      setReloaded(true);
      props.onReloaded?.();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const title = () =>
    editing() ? t("secrets.form.edit_title", { name: props.secret?.name ?? "" }) : t("secrets.form.create_title");

  return (
    <Dialog
      label={title()}
      onClose={props.onClose}
      class="dialog secret-dialog"
      testid="dialog-secret-form"
      initialFocus={() => nameInput}
    >
      <form class="secret-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{title()}</h2>
        <div class="dialog-body">
          <Show when={pinCoupling()}>
            <Notice kind="warn" role="alert" title={t("secrets.form.pin_title")} testid="secret-pin-coupling">
              {errorMessage(error())}
            </Notice>
          </Show>
          <ConflictNotice error={error()} busy={busy()} onReload={() => void reload()} />
          <ErrorNotice error={otherError()} />
          <Show when={reloaded()}>
            <p class="muted" role="status" data-testid="secret-reloaded">
              {t("secrets.form.reloaded")}
            </p>
          </Show>

          <div class="field">
            <label for="sf-name">{t("secrets.form.name")}</label>
            <input
              ref={nameInput}
              id="sf-name"
              class="input"
              data-testid="field-name"
              autocomplete="off"
              value={name()}
              aria-invalid={nameError() ? "true" : undefined}
              aria-describedby="sf-name-help"
              onInput={(e) => setName(e.currentTarget.value)}
            />
            <FieldNote id="sf-name-help" help={t("secrets.form.name_help")} error={nameError()} />
          </div>

          <div class="field">
            <label for="sf-kind">{t("secrets.form.kind")}</label>
            <select
              id="sf-kind"
              class="select"
              data-testid="field-kind"
              aria-invalid={fieldProblem(error(), "kind") ? "true" : undefined}
              aria-describedby={fieldProblem(error(), "kind") ? "sf-kind-help" : undefined}
              onChange={(e) => setKind(e.currentTarget.value as SecretKind)}
            >
              <For each={SECRET_KINDS}>
                {(k) => (
                  <option value={k} selected={k === kind()}>
                    {kindText(k)}
                  </option>
                )}
              </For>
            </select>
            <FieldNote id="sf-kind-help" error={fieldProblem(error(), "kind")} />
          </div>

          <div class="field">
            <label for="sf-username">{t("secrets.form.username")}</label>
            <input
              id="sf-username"
              class="input"
              data-testid="field-username"
              autocomplete="off"
              autocapitalize="off"
              spellcheck={false}
              value={username()}
              aria-invalid={fieldProblem(error(), "username") ? "true" : undefined}
              aria-describedby="sf-username-help"
              onInput={(e) => setUsername(e.currentTarget.value)}
            />
            <FieldNote
              id="sf-username-help"
              help={t("secrets.form.username_help")}
              error={fieldProblem(error(), "username")}
            />
          </div>

          <div class="field">
            <label for="sf-tags">{t("secrets.form.tags")}</label>
            <input
              id="sf-tags"
              class="input mono"
              data-testid="field-tags"
              autocomplete="off"
              autocapitalize="off"
              spellcheck={false}
              value={tags()}
              aria-invalid={fieldProblem(error(), "tags") ? "true" : undefined}
              aria-describedby="sf-tags-help"
              onInput={(e) => setTags(e.currentTarget.value)}
            />
            <FieldNote id="sf-tags-help" help={t("secrets.form.tags_help")} error={fieldProblem(error(), "tags")} />
          </div>

          <div class="field">
            <label for="sf-notes">{t("secrets.form.notes")}</label>
            <textarea
              id="sf-notes"
              class="input"
              rows={3}
              data-testid="field-notes"
              value={notes()}
              aria-invalid={fieldProblem(error(), "notes") ? "true" : undefined}
              aria-describedby="sf-notes-help"
              onInput={(e) => setNotes(e.currentTarget.value)}
            />
            <FieldNote id="sf-notes-help" help={t("secrets.form.notes_help")} error={fieldProblem(error(), "notes")} />
          </div>

          <Show when={!editing()}>
            <div class="field">
              <label for="sf-value">{t("secrets.form.value")}</label>
              {/* An SSH key has line breaks, which a password field drops: it gets a text area. */}
              <Show
                when={kind() === "ssh_key"}
                fallback={
                  <input
                    ref={(el) => (valueInput = el)}
                    id="sf-value"
                    class="input mono"
                    type="password"
                    data-testid="field-value"
                    autocomplete="new-password"
                    autocapitalize="off"
                    spellcheck={false}
                    value={value()}
                    aria-invalid={valueError() ? "true" : undefined}
                    aria-describedby="sf-value-help"
                    onInput={(e) => {
                      setCleared(false);
                      setValue(e.currentTarget.value);
                    }}
                  />
                }
              >
                <textarea
                  ref={(el) => (valueInput = el)}
                  id="sf-value"
                  class="input mono"
                  rows={6}
                  data-testid="field-value"
                  autocomplete="off"
                  autocapitalize="off"
                  spellcheck={false}
                  value={value()}
                  aria-invalid={valueError() ? "true" : undefined}
                  aria-describedby="sf-value-help"
                  onInput={(e) => {
                    setCleared(false);
                    setValue(e.currentTarget.value);
                  }}
                />
              </Show>
              <FieldNote
                id="sf-value-help"
                help={
                  cleared()
                    ? t("secrets.form.value_cleared")
                    : kind() === "ssh_key"
                      ? t("secrets.form.value_key_help")
                      : t("secrets.form.value_help")
                }
                error={valueError()}
              />
            </div>
          </Show>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy() || unchanged()}>
            {editing() ? t("secrets.form.edit_submit") : t("secrets.form.create_submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
