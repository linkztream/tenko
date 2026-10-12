// Creates an API token (IAM-10): a name, a lifetime within the profile's maximum (TGL-05) and,
// for a scoped token, its grants and special scopes. The personal token page offers both kinds
// (`personal`); a service account's tokens are always scoped. The new token is shown once.
import { createMemo, createSignal, For, Show, untrack } from "solid-js";
import type { components } from "../../api/generated/schema";
import { lifetimeChoices, tokenMaxDays } from "../../auth/account/client";
import { session } from "../../auth/session";
import { Dialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { formatNumber, t } from "../../i18n";
import type { ScopeCatalog } from "./data";
import { scopedTokenBody, type TokenCreate, type TokenScope } from "./model";
import { rowsToGrants, TokenGrantsEditor, TokenOnceDialog, type GrantRow } from "./TokenGrants";

type CreatedToken = components["schemas"]["CreatedToken"];

/** The value of the lifetime choice that creates a token without an expiry. */
const NO_EXPIRY = "none";

export function TokenDialog(props: {
  /** Offers a personal token, which acts with every right of its owner. */
  personal?: boolean;
  catalog: ScopeCatalog | undefined;
  /** Sends the request; the answer holds the secret. */
  create: (body: TokenCreate) => Promise<CreatedToken>;
  onCreated: () => void;
  onClose: () => void;
}) {
  const max = createMemo(() => {
    const profile = session()?.profile;
    return profile ? tokenMaxDays(profile) : 30;
  });
  const choices = createMemo(() => lifetimeChoices(max()));
  const [name, setName] = createSignal("");
  const [lifetime, setLifetime] = createSignal(String(choices().includes(90) ? 90 : (choices()[0] ?? 30)));
  const [scoped, setScoped] = createSignal(!untrack(() => props.personal));
  const [rows, setRows] = createSignal<GrantRow[]>([{ key: 1, role: "viewer", scope: undefined }]);
  const [scopes, setScopes] = createSignal<TokenScope[]>([]);
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [created, setCreated] = createSignal<CreatedToken | null>(null);
  let nameInput!: HTMLInputElement;

  const nameError = () => (submitted() && !name().trim() ? t("access.token.error.name") : undefined);
  const grantsError = () => {
    if (!submitted() || !scoped()) return undefined;
    const grants = rowsToGrants(rows());
    if (!grants) return t("access.token.error.scope");
    if (grants.length === 0 && scopes().length === 0) return t("access.token.error.empty");
    return undefined;
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    if (nameError()) {
      nameInput.focus();
      return;
    }
    if (grantsError() || busy()) return;
    const days = lifetime() === NO_EXPIRY ? null : Number(lifetime());
    const body: TokenCreate = scoped()
      ? scopedTokenBody(name().trim(), days, rowsToGrants(rows()) ?? [], scopes())
      : { name: name().trim(), expires_in_days: days };
    setBusy(true);
    setError(null);
    try {
      setCreated(await props.create(body));
      props.onCreated();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Show
      when={created()}
      fallback={
        <Dialog
          label={t("access.token.create_title")}
          onClose={props.onClose}
          class="dialog wide"
          testid="dialog-token"
          initialFocus={() => nameInput}
        >
          <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
            <h2 class="dialog-title">{t("access.token.create_title")}</h2>
            <div class="dialog-body">
              <ErrorNotice error={error()} />
              <div class="field">
                <label for="token-name">{t("access.token.name")}</label>
                <input
                  ref={nameInput}
                  id="token-name"
                  class="input"
                  data-testid="field-name"
                  maxlength={100}
                  autocomplete="off"
                  aria-invalid={nameError() ? "true" : undefined}
                  aria-describedby="token-name-help"
                  value={name()}
                  onInput={(e) => setName(e.currentTarget.value)}
                />
                <span class={nameError() ? "help bad field-error" : "help"} id="token-name-help">
                  {nameError() ?? t("access.token.name_help")}
                </span>
              </div>
              <div class="field">
                <label for="token-lifetime">{t("access.token.lifetime")}</label>
                <select
                  id="token-lifetime"
                  class="select"
                  data-testid="field-lifetime"
                  aria-describedby="token-lifetime-help"
                  onChange={(e) => setLifetime(e.currentTarget.value)}
                >
                  <For each={choices()}>
                    {(days) => (
                      <option value={String(days)} selected={lifetime() === String(days)}>
                        {t("access.token.days", { count: days })}
                      </option>
                    )}
                  </For>
                  <Show when={max() === null}>
                    <option value={NO_EXPIRY} selected={lifetime() === NO_EXPIRY}>
                      {t("access.token.no_expiry")}
                    </option>
                  </Show>
                </select>
                <span class="help" id="token-lifetime-help">
                  {max() === null ? t("access.token.max_none") : t("access.token.max_days", { days: formatNumber(max() ?? 0) })}
                </span>
              </div>
              <Show when={props.personal}>
                <fieldset class="field">
                  <legend class="label">{t("access.token.kind")}</legend>
                  <div class="choices" role="radiogroup" aria-label={t("access.token.kind")}>
                    <label class="choice">
                      <input
                        type="radio"
                        name="token-kind"
                        checked={!scoped()}
                        data-testid="field-kind-personal"
                        onChange={() => setScoped(false)}
                      />
                      <span>
                        <strong>{t("access.token.kind_personal")}</strong>
                        <small class="muted">{t("access.token.kind_personal_help")}</small>
                      </span>
                    </label>
                    <label class="choice">
                      <input
                        type="radio"
                        name="token-kind"
                        checked={scoped()}
                        data-testid="field-kind-scoped"
                        onChange={() => setScoped(true)}
                      />
                      <span>
                        <strong>{t("access.token.kind_scoped")}</strong>
                        <small class="muted">{t("access.token.kind_scoped_help")}</small>
                      </span>
                    </label>
                  </div>
                </fieldset>
              </Show>
              <Show when={scoped()}>
                <TokenGrantsEditor
                  id="token"
                  catalog={props.catalog}
                  rows={rows()}
                  onRows={setRows}
                  scopes={scopes()}
                  onScopes={setScopes}
                  error={grantsError()}
                />
              </Show>
            </div>
            <div class="dialog-actions">
              <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
                {t("common.action.cancel")}
              </button>
              <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
                {t("common.action.create")}
              </button>
            </div>
          </form>
        </Dialog>
      }
    >
      {(token) => <TokenOnceDialog name={token().info.name} token={token().token} onClose={props.onClose} />}
    </Show>
  );
}
