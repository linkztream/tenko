// Creates an API token (IAM-10): a name, a lifetime within the profile's maximum (TGL-05) and,
// for a scoped token, its grants and special scopes. The personal token page offers both kinds
// (`personal`); a service account's tokens are always scoped, may renew themselves (IAM-20,
// under TGL-46), may be bound to client networks (IAM-21) and to an enrolled host's
// certificate (IAM-23, required under TGL-47 in Hardened). The new token is shown once.
import { createMemo, createResource, createSignal, For, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { lifetimeChoices, tokenMaxDays } from "../../auth/account/client";
import { session } from "../../auth/session";
import { Dialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { formatNumber, t } from "../../i18n";
import type { ScopeCatalog } from "./data";
import type { Lineage } from "./integrations";
import { scopedTokenBody, type TokenCreate, type TokenScope } from "./model";
import { rowsToGrants, TokenGrantsEditor, TokenOnceDialog, type GrantRow } from "./TokenGrants";

type CreatedToken = components["schemas"]["CreatedToken"];

/** The value of the lifetime choice that creates a token without an expiry. */
const NO_EXPIRY = "none";

export function TokenDialog(props: {
  /** Offers a personal token, which acts with every right of its owner. */
  personal?: boolean;
  catalog: ScopeCatalog | undefined;
  /** The service account's enrolled hosts whose certificate a token can be bound to. */
  hosts?: readonly Lineage[] | undefined;
  /** Sends the request; the answer holds the secret. */
  create: (body: TokenCreate) => Promise<CreatedToken>;
  onCreated: () => void;
  onClose: () => void;
}) {
  // TGL-46 decides whether a service account's token may renew itself, TGL-47 whether it
  // must be bound to a host's certificate.
  const [settings] = createResource(
    () => !props.personal,
    // Unknown (null) when the settings cannot be read: renewal stays off, binding optional.
    () =>
      api
        .get("/api/v1/settings/security")
        .then((view) => ({
          renewal: view.toggles.some((tg) => tg.id === "TGL-46" && (tg.value as unknown) === true),
          binding: view.toggles.some(
            (tg) => tg.id === "TGL-47" && (tg.value as { require_binding?: boolean } | null)?.require_binding === true,
          ),
        }))
        .catch(() => null),
  );
  const renewal = () => (settings.loading ? undefined : (settings()?.renewal ?? null));
  const bindingRequired = () => settings()?.binding === true;
  const [lineage, setLineage] = createSignal("");
  const [renewable, setRenewable] = createSignal(false);
  const [prefixes, setPrefixes] = createSignal("");
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
  // IAM-20: a renewable token always expires.
  const lifetimeError = () =>
    submitted() && renewable() && renewal() === true && lifetime() === NO_EXPIRY ? t("access.token.error.renewable_expiry") : undefined;
  const lineageError = () => (submitted() && bindingRequired() && lineage() === "" ? t("access.token.error.lineage") : undefined);
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
    if (grantsError() || lifetimeError() || lineageError() || busy()) return;
    const days = lifetime() === NO_EXPIRY ? null : Number(lifetime());
    const body: TokenCreate = scoped()
      ? {
          ...scopedTokenBody(name().trim(), days, rowsToGrants(rows()) ?? [], scopes()),
          renewable: renewable() && renewal() === true,
          source_prefixes: prefixes()
            .split(/[\s,]+/)
            .filter((entry) => entry !== ""),
          ...(lineage() !== "" ? { lineage: lineage() } : {}),
        }
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
                <span class={lifetimeError() ? "help bad field-error" : "help"} id="token-lifetime-help">
                  {lifetimeError() ??
                    (max() === null ? t("access.token.max_none") : t("access.token.max_days", { days: formatNumber(max() ?? 0) }))}
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
              <Show when={!props.personal}>
                <div class="field">
                  <label for="token-lineage">{t("access.token.lineage")}</label>
                  <select
                    id="token-lineage"
                    class="select"
                    data-testid="field-lineage"
                    aria-invalid={lineageError() ? "true" : undefined}
                    aria-describedby="token-lineage-help"
                    onChange={(e) => setLineage(e.currentTarget.value)}
                  >
                    <option value="" selected={lineage() === ""} disabled={bindingRequired()}>
                      {bindingRequired() ? t("access.token.lineage_choose") : t("access.token.lineage_none")}
                    </option>
                    <For each={props.hosts ?? []}>
                      {(host) => (
                        <option value={host.id} selected={lineage() === host.id}>
                          {host.label}
                        </option>
                      )}
                    </For>
                  </select>
                  <span class={lineageError() ? "help bad field-error" : "help"} id="token-lineage-help">
                    {lineageError() ??
                      ((props.hosts ?? []).length === 0
                        ? t("access.token.lineage_no_hosts")
                        : bindingRequired()
                          ? t("access.token.lineage_required")
                          : t("access.token.lineage_help"))}
                  </span>
                </div>
                <div class="field">
                  <label class="ackrow">
                    <input
                      type="checkbox"
                      class="cb"
                      checked={renewable() && renewal() === true}
                      disabled={renewal() !== true}
                      data-testid="field-renewable"
                      aria-describedby="token-renewable-help"
                      onChange={(e) => setRenewable(e.currentTarget.checked)}
                    />
                    {t("access.token.renewable")}
                  </label>
                  <span class="help" id="token-renewable-help">
                    {renewal() === false ? t("access.token.renewable_off") : t("access.token.renewable_help")}
                  </span>
                </div>
                <div class="field">
                  <label for="token-prefixes">{t("access.token.source_prefixes")}</label>
                  <textarea
                    id="token-prefixes"
                    class="input mono"
                    rows={3}
                    spellcheck={false}
                    data-testid="field-source_prefixes"
                    aria-describedby="token-prefixes-help"
                    value={prefixes()}
                    onInput={(e) => setPrefixes(e.currentTarget.value)}
                  />
                  <span class="help" id="token-prefixes-help">
                    {t("access.token.source_prefixes_help")}
                  </span>
                </div>
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
      {(token) => (
        <TokenOnceDialog
          name={token().info.name}
          token={token().token}
          renewalSecret={token().renewal_secret ?? undefined}
          onClose={props.onClose}
        />
      )}
    </Show>
  );
}
