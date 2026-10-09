// The dialogs of the user detail page. A confirmation names its action and the account;
// a refusal from the server (the last administrator, a stale revision) stays in the
// dialog, in words, so the person can change the request or give up.
import { createSignal, For, Show, untrack, type JSX } from "solid-js";
import { api } from "../api/client";
import type { RoleInfo, RoleName, UserInfo } from "../api/types";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { availableLocales, t } from "../i18n";
import { FieldHelp, fieldMessages, ReloadedNote } from "./fields";
import { session } from "../auth/session";

/** A confirmation whose action can fail: busy while it runs, the error inside the dialog. */
export function RunDialog(props: {
  title: string;
  body: JSX.Element;
  confirmLabel: string;
  danger?: boolean;
  run: () => Promise<void>;
  onStale?: (err: unknown) => void;
  onClose: () => void;
}) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const confirm = async () => {
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      await props.run();
      props.onClose();
    } catch (err) {
      props.onStale?.(err);
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <ConfirmDialog
      title={props.title}
      body={
        <>
          <ErrorNotice error={error()} />
          <ReloadedNote error={error()} />
          {props.body}
        </>
      }
      confirmLabel={props.confirmLabel}
      cancelLabel={t("common.action.cancel")}
      danger={props.danger}
      busy={busy()}
      onConfirm={() => void confirm()}
      onClose={props.onClose}
    />
  );
}

// ---------------------------------------------------------------------------------
// Display name and language

export function EditUserDialog(props: {
  user: UserInfo;
  onSaved: (user: UserInfo) => void;
  onStale?: (err: unknown) => void;
  onClose: () => void;
}) {
  const [displayName, setDisplayName] = createSignal(untrack(() => props.user.display_name));
  const [language, setLanguage] = createSignal(untrack(() => props.user.language ?? ""));
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  const nameError = () => {
    if (error() && fieldMessages(error(), "display_name").length > 0) return fieldMessages(error(), "display_name")[0];
    if (submitted() && displayName().trim() === "") return t("settings.users.error.display_required");
    return undefined;
  };
  const unchanged = () =>
    displayName().trim() === props.user.display_name && language() === (props.user.language ?? "");
  const generalError = () => (error() && fieldMessages(error(), "display_name").length === 0 ? error() : null);

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    if (displayName().trim() === "" || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const next = await api.patch("/api/v1/users/{id}", {
        path: { id: props.user.id },
        body: { display_name: displayName().trim(), language: language() },
        ifMatch: props.user.revision,
      });
      props.onSaved(next);
      toast({ kind: "ok", title: t("settings.users.saved_details", { name: props.user.name }) });
      props.onClose();
    } catch (err) {
      props.onStale?.(err);
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("settings.users.edit.title")} onClose={props.onClose} class="dialog wide">
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("settings.users.edit.title")}</h2>
        <div class="dialog-body">
          <ErrorNotice error={generalError()} />
          <ReloadedNote error={generalError()} />
          <div class="field">
            <label for="ud-display">{t("settings.users.field.display_name")}</label>
            <input
              id="ud-display"
              class="input"
              autocomplete="off"
              value={displayName()}
              aria-invalid={nameError() ? "true" : undefined}
              aria-describedby="ud-display-help"
              onInput={(e) => setDisplayName(e.currentTarget.value)}
            />
            <FieldHelp id="ud-display-help" error={nameError()} />
          </div>
          <div class="field">
            <label for="ud-language">{t("settings.users.field.language")}</label>
            <select
              id="ud-language"
              class="select"
              onChange={(e) => setLanguage(e.currentTarget.value)}
            >
              <option value="" selected={language() === ""}>
                {t("shell.account.language_auto")}
              </option>
              <For each={availableLocales()}>
                {(l) => (
                  <option value={l.code} selected={language() === l.code}>
                    {l.name}
                  </option>
                )}
              </For>
            </select>
          </div>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" disabled={busy() || unchanged()}>
            {t("settings.users.edit.submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------------
// Roles

/** The role choices of a form: a checkbox for each role with what the role allows. */
export function RoleChoices(props: {
  roles: readonly RoleInfo[];
  value: readonly RoleName[];
  onChange: (value: RoleName[]) => void;
  error?: string | undefined;
  idPrefix: string;
}) {
  const toggle = (name: RoleName, on: boolean) => {
    const next = on ? [...props.value, name] : props.value.filter((r) => r !== name);
    props.onChange(next);
  };
  return (
    <fieldset class="field" aria-describedby={`${props.idPrefix}-help`}>
      <legend class="label">{t("settings.users.field.roles")}</legend>
      <div class="choices">
        <For each={props.roles}>
          {(r) => (
            <label class="choice">
              <input
                type="checkbox"
                class="cb"
                checked={props.value.includes(r.name)}
                onChange={(e) => toggle(r.name, e.currentTarget.checked)}
              />
              <span>
                <strong>{t(`role.${r.name}.name`)}</strong>
                <small class="muted">{t(`role.${r.name}.description`)}</small>
              </span>
            </label>
          )}
        </For>
      </div>
      <FieldHelp id={`${props.idPrefix}-help`} error={props.error} />
    </fieldset>
  );
}

export function RolesDialog(props: {
  user: UserInfo;
  roles: readonly RoleInfo[];
  onSaved: (user: UserInfo) => void;
  onStale?: (err: unknown) => void;
  onClose: () => void;
}) {
  const [value, setValue] = createSignal<RoleName[]>(untrack(() => [...props.user.roles]));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const own = () => session()?.user.id === props.user.id;
  const unchanged = () => {
    const a = [...value()].sort().join(",");
    const b = [...props.user.roles].sort().join(",");
    return a === b;
  };
  const losingAdmin = () => own() && props.user.roles.includes("admin") && !value().includes("admin");

  const submit = async (e: Event) => {
    e.preventDefault();
    if (busy() || unchanged() || value().length === 0) return;
    setBusy(true);
    setError(null);
    try {
      const next = await api.put("/api/v1/users/{id}/roles", {
        path: { id: props.user.id },
        body: { roles: value() },
        ifMatch: props.user.revision,
      });
      props.onSaved(next);
      toast({ kind: "ok", title: t("settings.users.saved_roles", { name: props.user.name }) });
      props.onClose();
    } catch (err) {
      props.onStale?.(err);
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("settings.users.roles.title")} onClose={props.onClose} class="dialog wide">
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("settings.users.roles.title")}</h2>
        <div class="dialog-body">
          <ErrorNotice error={error()} />
          <ReloadedNote error={error()} />
          <RoleChoices
            idPrefix="ur"
            roles={props.roles}
            value={value()}
            onChange={setValue}
            error={value().length === 0 ? t("settings.users.error.roles_required") : undefined}
          />
          <Show when={losingAdmin()}>
            <Notice kind="warn">{t("settings.users.roles.own_admin")}</Notice>
          </Show>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" disabled={busy() || unchanged() || value().length === 0}>
            {t("settings.users.roles.submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------------
// A new password for the account

export function PasswordDialog(props: {
  user: UserInfo;
  onSaved: (user: UserInfo) => void;
  onStale?: (err: unknown) => void;
  onClose: () => void;
}) {
  const [password, setPassword] = createSignal("");
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  const policyMessages = () => fieldMessages(error(), "password");
  const fieldError = () => {
    if (policyMessages().length > 0) return policyMessages().join(" ");
    if (submitted() && password() === "") return t("settings.users.error.password_required");
    return undefined;
  };
  const generalError = () => (error() && policyMessages().length === 0 ? error() : null);

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    if (password() === "" || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const next = await api.patch("/api/v1/users/{id}", {
        path: { id: props.user.id },
        body: { password: password() },
        ifMatch: props.user.revision,
      });
      props.onSaved(next);
      toast({ kind: "ok", title: t("settings.users.saved_password", { name: props.user.name }) });
      props.onClose();
    } catch (err) {
      props.onStale?.(err);
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("settings.users.password.title")} onClose={props.onClose} class="dialog wide">
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("settings.users.password.title")}</h2>
        <div class="dialog-body">
          <ErrorNotice error={generalError()} />
          <ReloadedNote error={generalError()} />
          <p>{t("settings.users.password.lead", { name: props.user.name })}</p>
          <div class="field">
            <label for="up-password">{t("settings.users.field.new_password")}</label>
            <input
              id="up-password"
              class="input"
              type="password"
              autocomplete="new-password"
              value={password()}
              aria-invalid={fieldError() ? "true" : undefined}
              aria-describedby="up-password-help"
              onInput={(e) => setPassword(e.currentTarget.value)}
            />
            <FieldHelp id="up-password-help" help={t("settings.users.password.help")} error={fieldError()} />
          </div>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" disabled={busy()}>
            {t("settings.users.password.submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
