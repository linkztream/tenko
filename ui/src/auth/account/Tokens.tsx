import { createMemo, createSignal, For, Match, Show, Switch } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import type { CreatedToken, TokenInfo } from "../../api/types";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDate, formatNumber, formatRelative, t } from "../../i18n";
import { catalogNames, createScopeCatalog, type ScopeCatalog } from "../../settings/access/data";
import { scopedTokenBody, tokenReach, type TokenScope } from "../../settings/access/model";
import { rowsToGrants, TokenGrantsEditor, type GrantRow } from "../../settings/access/TokenGrants";
import "../../settings/access/access.css";
import { session } from "../session";
import { lifetimeChoices, tokenMaxDays } from "./client";
import { copyText, describeError, latest } from "./shared";

/** The value of the lifetime choice that creates a token without an expiry. */
const NO_EXPIRY = "none";

/**
 * Personal and scoped API tokens (IAM-10): list with what each may do, create (shown once) and
 * revoke. A scoped token acts with the grants and special scopes chosen at creation, never with
 * more than its owner has (docs/access.md section 7).
 */
export default function Tokens() {
  const query = createLiveQuery<TokenInfo[]>({
    topics: ["admin"],
    fetch: async (signal) => {
      const all = await fetchAll<TokenInfo>("/api/v1/auth/tokens", { signal });
      return { value: all.items, revision: all.revision };
    },
  });
  const [creating, setCreating] = createSignal(false);
  const [revoking, setRevoking] = createSignal<TokenInfo | null>(null);
  const [revokeError, setRevokeError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const tokens = () => latest(query);
  // The names of the VRFs, sites and prefixes that scoped tokens name.
  const catalog = createScopeCatalog();
  const names = createMemo(() => catalogNames(latest(catalog)));

  const revoke = async (token: TokenInfo) => {
    setRevokeError(null);
    setBusy(true);
    try {
      await api.delete("/api/v1/auth/tokens/{id}", { path: { id: token.id } });
      setRevoking(null);
      toast({ title: t("account.tokens.revoked", { name: token.name }), kind: "ok" });
      query.refetch();
    } catch (err) {
      setRevokeError(describeError(err));
    } finally {
      setBusy(false);
    }
  };

  const expired = (token: TokenInfo) => !!token.expires_at && Date.parse(token.expires_at) <= Date.now();

  return (
    <div class="page-body acct-stack">
      <section class="page-section" aria-labelledby="acct-tokens">
        <div class="acct-head">
          <h2 id="acct-tokens">{t("account.tokens.title")}</h2>
          <button type="button" class="btn" onClick={() => setCreating(true)}>
            <Icon name="plus" size="sm" />
            {t("account.tokens.create")}
          </button>
        </div>
        <p>{t("account.tokens.lede")}</p>

        <Show when={query.value.error}>
          <div class="note bad" role="alert">
            <Icon name="alert" size="sm" />
            <span class="grow">{describeError(query.value.error)}</span>
            <button type="button" class="btn sm" onClick={() => query.refetch()}>
              {t("common.action.retry")}
            </button>
          </div>
        </Show>

        <Show
          when={tokens()}
          fallback={
            <Show when={!query.value.error}>
              <p class="muted">{t("common.loading")}</p>
            </Show>
          }
        >
          {(list) => (
            <Show when={list().length > 0} fallback={<p class="muted">{t("account.tokens.none")}</p>}>
              <div class="table-wrap">
                <table class="plain">
                  <caption class="sr-only">{t("account.tokens.title")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("account.tokens.col.name")}</th>
                      <th scope="col">{t("account.tokens.col.prefix")}</th>
                      <th scope="col">{t("account.tokens.col.created")}</th>
                      <th scope="col">{t("account.tokens.col.expires")}</th>
                      <th scope="col">{t("account.tokens.col.last_used")}</th>
                      <th scope="col">{t("access.token.col.reach")}</th>
                      <th scope="col" class="r">
                        <span class="sr-only">{t("account.sessions.col.actions")}</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={list()}>
                      {(token) => (
                        <tr>
                          <td>{token.name}</td>
                          <td>
                            <span class="mono">{token.prefix}</span>
                            <span aria-hidden="true">…</span>
                          </td>
                          <td class="num">{formatDate(token.created_at)}</td>
                          <td class="num">
                            <Show when={token.expires_at} fallback={t("common.never")}>
                              {(at) => (
                                <>
                                  {formatDate(at())}
                                  <Show when={expired(token)}>
                                    <span class="tag conflict acct-this">{t("account.tokens.expired")}</span>
                                  </Show>
                                </>
                              )}
                            </Show>
                          </td>
                          <td class="num">
                            <Show when={token.last_used_at} fallback={t("common.never")}>
                              {(at) => <span title={formatDate(at(), { dateStyle: "medium", timeStyle: "short" })}>{formatRelative(at())}</span>}
                            </Show>
                          </td>
                          <td data-testid="token-reach" data-scoped={token.scoped ? "true" : "false"}>
                            <ul class="plain-list">
                              <For each={tokenReach(token, names())}>{(line) => <li>{line}</li>}</For>
                            </ul>
                          </td>
                          <td class="r">
                            <button
                              type="button"
                              class="btn sm"
                              aria-label={t("account.tokens.revoke_named", { name: token.name })}
                              onClick={() => {
                                setRevokeError(null);
                                setRevoking(token);
                              }}
                            >
                              {t("common.action.revoke")}
                            </button>
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          )}
        </Show>
      </section>

      <Show when={creating()}>
        <CreateTokenDialog catalog={latest(catalog)} onCreated={() => query.refetch()} onClose={() => setCreating(false)} />
      </Show>

      <Show when={revoking()}>
        {(token) => (
          <ConfirmDialog
            title={t("account.tokens.revoke_title", { name: token().name })}
            body={
              <>
                <p>{t("account.tokens.revoke_body")}</p>
                <Show when={revokeError()}>
                  <Notice kind="bad" role="alert">
                    {revokeError()}
                  </Notice>
                </Show>
              </>
            }
            confirmLabel={t("common.action.revoke")}
            cancelLabel={t("common.action.cancel")}
            danger
            busy={busy()}
            onConfirm={() => void revoke(token())}
            onClose={() => setRevoking(null)}
          />
        )}
      </Show>
    </div>
  );
}

/**
 * Asks for a name and a lifetime, then shows the token once. The dialog stays open until
 * the person confirms the token is stored.
 */
function CreateTokenDialog(props: { catalog: ScopeCatalog | undefined; onCreated: () => void; onClose: () => void }) {
  const max = createMemo(() => {
    const profile = session()?.profile;
    return profile ? tokenMaxDays(profile) : 30;
  });
  const choices = createMemo(() => lifetimeChoices(max()));
  const [name, setName] = createSignal("");
  const [lifetime, setLifetime] = createSignal(String(choices().includes(90) ? 90 : (choices()[0] ?? 30)));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [created, setCreated] = createSignal<CreatedToken | null>(null);
  const [stored, setStored] = createSignal(false);
  // A scoped token: its grants (a role over the installation or a scope) and special scopes.
  const [scoped, setScoped] = createSignal(false);
  const [rows, setRows] = createSignal<GrantRow[]>([{ key: 1, role: "viewer", scope: undefined }]);
  const [scopes, setScopes] = createSignal<TokenScope[]>([]);
  const [tried, setTried] = createSignal(false);
  const grantsError = () => {
    if (!tried() || !scoped()) return undefined;
    const grants = rowsToGrants(rows());
    if (!grants) return t("access.token.error.scope");
    if (grants.length === 0 && scopes().length === 0) return t("access.token.error.empty");
    return undefined;
  };
  let nameInput!: HTMLInputElement;

  const submit = async (e: Event) => {
    e.preventDefault();
    if (!name().trim()) {
      nameInput.focus();
      return;
    }
    setTried(true);
    if (grantsError()) return;
    setError(null);
    setBusy(true);
    try {
      const days = lifetime() === NO_EXPIRY ? null : Number(lifetime());
      const body = scoped()
        ? scopedTokenBody(name().trim(), days, rowsToGrants(rows()) ?? [], scopes())
        : { name: name().trim(), expires_in_days: days };
      const token = await api.post("/api/v1/auth/tokens", { body });
      setCreated(token);
      props.onCreated();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const closeWhenStored = () => {
    if (!created() || stored()) props.onClose();
  };

  return (
    <Switch>
      <Match when={created()}>
        {(token) => (
          <Dialog label={t("account.tokens.created_title")} onClose={closeWhenStored} class="dialog wide">
            <h2 class="dialog-title">{t("account.tokens.created_title")}</h2>
            <div class="dialog-body">
              <p>{t("account.tokens.created_body", { name: token().info.name })}</p>
              <div class="form-row">
                <code class="secret acct-token">
                  {token().token}
                </code>
                <button type="button" class="btn sm" onClick={() => void copyText(token().token)}>
                  <Icon name="copy" size="sm" />
                  {t("common.action.copy")}
                </button>
              </div>
              <label class="ackrow">
                <input
                  type="checkbox"
                  class="cb"
                  checked={stored()}
                  onChange={(e) => setStored(e.currentTarget.checked)}
                />
                {t("account.tokens.stored")}
              </label>
            </div>
            <div class="dialog-actions">
              <button type="button" class="btn primary" disabled={!stored()} onClick={closeWhenStored}>
                {t("common.action.close")}
              </button>
            </div>
          </Dialog>
        )}
      </Match>
      <Match when={true}>
        <Dialog
          label={t("account.tokens.create_title")}
          onClose={props.onClose}
          class="dialog wide"
          testid="dialog-token"
          initialFocus={() => nameInput}
        >
          <h2 class="dialog-title">{t("account.tokens.create_title")}</h2>
          <form class="dialog-body" onSubmit={(e) => void submit(e)} novalidate>
            <div class="field">
              <label for="acct-token-name">{t("account.tokens.name")}</label>
              <input
                ref={nameInput}
                id="acct-token-name"
                class="input"
                maxlength={100}
                autocomplete="off"
                aria-describedby="acct-token-name-help"
                value={name()}
                onInput={(e) => setName(e.currentTarget.value)}
              />
              <span class="help" id="acct-token-name-help">
                {t("account.tokens.name_help")}
              </span>
            </div>
            <div class="field">
              <label for="acct-token-lifetime">{t("account.tokens.lifetime")}</label>
              <select
                id="acct-token-lifetime"
                class="select"
                aria-describedby="acct-token-lifetime-help"
                value={lifetime()}
                onChange={(e) => setLifetime(e.currentTarget.value)}
              >
                <For each={choices()}>
                  {(days) => (
                    <option value={String(days)} selected={lifetime() === String(days)}>
                      {t("account.tokens.days", { count: days })}
                    </option>
                  )}
                </For>
                <Show when={max() === null}>
                  <option value={NO_EXPIRY} selected={lifetime() === NO_EXPIRY}>
                    {t("account.tokens.no_expiry")}
                  </option>
                </Show>
              </select>
              <span class="help" id="acct-token-lifetime-help">
                {max() === null
                  ? t("account.tokens.max_none", { profile: t(`profile.${session()?.profile ?? "lab"}.name`) })
                  : t("account.tokens.max_days", {
                      profile: t(`profile.${session()?.profile ?? "home"}.name`),
                      days: formatNumber(max() ?? 0),
                    })}
              </span>
            </div>
            <fieldset class="field">
              <legend class="label">{t("access.token.kind")}</legend>
              <div class="choices" role="radiogroup" aria-label={t("access.token.kind")}>
                <label class="choice">
                  <input
                    type="radio"
                    name="acct-token-kind"
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
                  <input type="radio" name="acct-token-kind" checked={scoped()} data-testid="field-kind-scoped" onChange={() => setScoped(true)} />
                  <span>
                    <strong>{t("access.token.kind_scoped")}</strong>
                    <small class="muted">{t("access.token.kind_scoped_help")}</small>
                  </span>
                </label>
              </div>
            </fieldset>
            <Show when={scoped()}>
              <TokenGrantsEditor
                id="acct-token"
                catalog={props.catalog}
                rows={rows()}
                onRows={setRows}
                scopes={scopes()}
                onScopes={setScopes}
                error={grantsError()}
              />
            </Show>
            <ErrorNotice error={error()} />
            <div class="dialog-actions">
              <button type="button" class="btn ghost" onClick={() => props.onClose()}>
                {t("common.action.cancel")}
              </button>
              <button type="submit" class="btn primary" disabled={busy()}>
                {t("common.action.create")}
              </button>
            </div>
          </form>
        </Dialog>
      </Match>
    </Switch>
  );
}
