// Adding a user: name, display name, roles, an optional initial password and a language.
// The server has the last word (a taken name, the password policy); its field errors land
// on the field they belong to.
import { createSignal, For, Show, untrack } from "solid-js";
import { api } from "../api/client";
import { errorMessage, isApiError } from "../api/problem";
import type { RoleInfo, RoleName, UserCreate, UserInfo } from "../api/types";
import { Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { availableLocales, t } from "../i18n";
import { FieldHelp, fieldMessages } from "./fields";
import { RoleChoices } from "./UserDialogs";

const MAX_NAME = 64;

function nameProblem(raw: string): string | undefined {
  const name = raw.trim();
  if (name === "") return t("settings.users.error.name_required");
  if (Array.from(name).length > MAX_NAME) return t("settings.users.error.name_length");
  if (/\s/.test(name)) return t("settings.users.error.name_spaces");
  return undefined;
}

export function AddUserDialog(props: {
  roles: readonly RoleInfo[];
  onCreated: (user: UserInfo) => void;
  onClose: () => void;
}) {
  const [name, setName] = createSignal("");
  const [displayName, setDisplayName] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [language, setLanguage] = createSignal("");
  const [roles, setRoles] = createSignal<RoleName[]>(
    untrack(() => (props.roles.some((r) => r.name === "viewer") ? ["viewer"] : [])),
  );
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  // A taken name has no field list: the code itself says which field it is about.
  const nameTaken = () => isApiError(error(), "users.name_taken");
  const serverField = (field: string) => fieldMessages(error(), field).join(" ") || undefined;
  const nameError = () =>
    nameTaken() ? errorMessage(error()) : (serverField("name") ?? (submitted() ? nameProblem(name()) : undefined));
  const displayError = () => serverField("display_name");
  const passwordError = () => serverField("password");
  const rolesError = () =>
    serverField("roles") ?? (submitted() && roles().length === 0 ? t("settings.users.error.roles_required") : undefined);
  const fieldErrored = () => nameTaken() || ["name", "display_name", "password", "roles"].some((f) => serverField(f));
  const generalError = () => (error() && !fieldErrored() ? error() : null);

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    if (busy() || nameProblem(name()) || roles().length === 0) return;
    const body: UserCreate = { name: name().trim(), roles: roles() };
    if (displayName().trim() !== "") body.display_name = displayName().trim();
    if (password() !== "") body.password = password();
    if (language() !== "") body.language = language();
    setBusy(true);
    setError(null);
    try {
      props.onCreated(await api.post("/api/v1/users", { body }));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("settings.users.add.title")} onClose={props.onClose} class="dialog wide">
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("settings.users.add.title")}</h2>
        <div class="dialog-body">
          <ErrorNotice error={generalError()} />
          <div class="field">
            <label for="au-name">{t("settings.users.field.name")}</label>
            <input
              id="au-name"
              class="input mono"
              autocomplete="off"
              autocapitalize="off"
              spellcheck={false}
              value={name()}
              aria-invalid={nameError() ? "true" : undefined}
              aria-describedby="au-name-help"
              onInput={(e) => {
                setName(e.currentTarget.value);
                if (nameTaken()) setError(null);
              }}
            />
            <FieldHelp id="au-name-help" help={t("settings.users.field.name_help")} error={nameError()} />
          </div>
          <div class="field">
            <label for="au-display">{t("settings.users.field.display_name")}</label>
            <input
              id="au-display"
              class="input"
              autocomplete="off"
              value={displayName()}
              aria-invalid={displayError() ? "true" : undefined}
              aria-describedby="au-display-help"
              onInput={(e) => setDisplayName(e.currentTarget.value)}
            />
            <FieldHelp id="au-display-help" help={t("settings.users.field.display_help")} error={displayError()} />
          </div>
          <RoleChoices idPrefix="au-roles" roles={props.roles} value={roles()} onChange={setRoles} error={rolesError()} />
          <div class="field">
            <label for="au-password">{t("settings.users.field.password")}</label>
            <input
              id="au-password"
              class="input"
              type="password"
              autocomplete="new-password"
              value={password()}
              aria-invalid={passwordError() ? "true" : undefined}
              aria-describedby="au-password-help"
              onInput={(e) => setPassword(e.currentTarget.value)}
            />
            <FieldHelp id="au-password-help" help={t("settings.users.field.password_help")} error={passwordError()} />
          </div>
          <div class="field">
            <label for="au-language">{t("settings.users.field.language")}</label>
            <select id="au-language" class="select" onChange={(e) => setLanguage(e.currentTarget.value)}>
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
          <Show when={props.roles.length === 0}>
            <p class="muted">{t("common.loading")}</p>
          </Show>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" disabled={busy()}>
            {t("settings.users.add.submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
