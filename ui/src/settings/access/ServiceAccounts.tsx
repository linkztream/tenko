// Service accounts (IAM-10, docs/access.md section 6): accounts for automation, without a
// password, a second factor or a session, that act only through scoped tokens. The list, the
// dialog that creates one, and the tokens of one account (`ServiceAccountTokens`, also on the
// account's user page).
import { A } from "@solidjs/router";
import { createEffect, createSignal, For, Show } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { api } from "../../api/client";
import { createLiveQuery, latest } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import { paths } from "../../app/paths";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDate, formatRelative, t } from "../../i18n";
import { fieldMessages } from "../fields";
import { RunDialog } from "../UserDialogs";
import { rolesText } from "../userModel";
import { catalogNames, type ScopeCatalog } from "./data";
import { roleName, ROLES, tokenReach, validAccountName, type RoleName, type TokenInfo, type UserInfo } from "./model";
import { TokenDialog } from "./TokenDialog";

export function ServiceAccountsSection(props: { catalog: ScopeCatalog | undefined }) {
  // The owners are administrators: their names come from the users.
  const accounts = createLiveQuery<{ accounts: UserInfo[]; owners: Map<string, string> }>({
    topics: ["admin"],
    fetch: async (signal) => {
      const [all, users] = await Promise.all([
        fetchAll<UserInfo>("/api/v1/access/service-accounts", { signal }),
        fetchAll<UserInfo>("/api/v1/users", { signal }),
      ]);
      return { value: { accounts: all.items, owners: new Map(users.items.map((u) => [u.id, u.name])) }, revision: all.revision };
    },
  });
  const [adding, setAdding] = createSignal(false);
  const [open, setOpen] = createSignal<string | null>(null);
  // The rows keep their identity across reads (reconciled by id): an account's open token panel
  // and its dialogs survive the refetch that any change of the access tables triggers.
  const [rows, setRows] = createStore<{ list: UserInfo[] | undefined }>({ list: undefined });
  createEffect(() => {
    const read = latest(accounts)?.accounts;
    if (read) setRows("list", reconcile(read, { key: "id" }));
  });
  const list = () => rows.list;
  const owner = (id: string | null | undefined) => (id ? latest(accounts)?.owners.get(id) : undefined);

  return (
    <section class="page-section" aria-labelledby="access-sa" data-testid="access-service-accounts">
      <div class="access-head">
        <h2 id="access-sa">{t("access.sa.heading")}</h2>
        <button type="button" class="btn" data-testid="access-service-account-add" onClick={() => setAdding(true)}>
          <Icon name="plus" size="sm" />
          {t("access.sa.add")}
        </button>
      </div>
      <p class="muted">{t("access.sa.lede")}</p>
      <ErrorNotice error={accounts.value.error} />
      <Show
        when={list()}
        fallback={
          <Show when={!accounts.value.error}>
            <p class="muted" role="status">
              {t("common.loading")}
            </p>
          </Show>
        }
      >
        {(rows) => (
          <Show when={rows().length > 0} fallback={<p class="muted">{t("access.sa.none")}</p>}>
            <ul class="card access-accounts">
              <For each={rows()}>
                {(account) => (
                  <li data-testid="access-service-account" data-key={account.name}>
                    <div class="access-account">
                      <div class="action-text">
                        <A href={paths.user(account.id)} class="mono">
                          {account.name}
                        </A>
                        <span class="muted">
                          {t("access.sa.summary", {
                            display: account.display_name,
                            roles: account.roles.length > 0 ? rolesText(account.roles) : t("access.sa.grants_only"),
                            owner: owner(account.owner) ?? account.owner ?? t("common.none"),
                          })}
                        </span>
                      </div>
                      <button
                        type="button"
                        class="btn sm"
                        aria-expanded={open() === account.id}
                        data-testid="access-service-account-tokens"
                        onClick={() => setOpen(open() === account.id ? null : account.id)}
                      >
                        {t("access.sa.tokens")}
                      </button>
                    </div>
                    <Show when={open() === account.id}>
                      <ServiceAccountTokens account={account} catalog={props.catalog} />
                    </Show>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        )}
      </Show>
      <Show when={adding()}>
        <AddServiceAccountDialog onCreated={() => accounts.refetch()} onClose={() => setAdding(false)} />
      </Show>
    </section>
  );
}

/** The scoped tokens of one service account: list, create (shown once) and revoke. */
export function ServiceAccountTokens(props: { account: UserInfo; catalog: ScopeCatalog | undefined }) {
  const tokens = createLiveQuery<TokenInfo[]>({
    topics: ["admin"],
    fetch: async (signal) => {
      const all = await fetchAll<TokenInfo>("/api/v1/access/service-accounts/{id}/tokens", {
        signal,
        path: { id: props.account.id },
      });
      return { value: all.items, revision: all.revision };
    },
  });
  const [creating, setCreating] = createSignal(false);
  const [revoking, setRevoking] = createSignal<TokenInfo | null>(null);
  const names = () => catalogNames(props.catalog);
  const expired = (token: TokenInfo) => !!token.expires_at && Date.parse(token.expires_at) <= Date.now();

  const revoke = async (token: TokenInfo) => {
    await api.delete("/api/v1/access/service-accounts/{id}/tokens/{token}", { path: { id: props.account.id, token: token.id } });
    tokens.refetch();
    toast({ kind: "ok", title: t("access.sa.token_revoked", { name: token.name }) });
  };

  return (
    <div class="access-tokens" data-testid="access-sa-tokens">
      <div class="access-head">
        <h3>{t("access.sa.tokens_of", { name: props.account.name })}</h3>
        <button type="button" class="btn sm" data-testid="access-sa-token-create" onClick={() => setCreating(true)}>
          <Icon name="plus" size="sm" />
          {t("access.token.create")}
        </button>
      </div>
      <ErrorNotice error={tokens.value.error} />
      <Show when={latest(tokens)} fallback={<p class="muted">{t("common.loading")}</p>}>
        {(list) => (
          <Show when={list().length > 0} fallback={<p class="muted">{t("access.sa.no_tokens")}</p>}>
            <div class="table-wrap">
              <table class="plain">
                <caption class="sr-only">{t("access.sa.tokens_of", { name: props.account.name })}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("access.token.col.name")}</th>
                    <th scope="col">{t("access.token.col.reach")}</th>
                    <th scope="col">{t("access.token.col.expires")}</th>
                    <th scope="col">{t("access.token.col.last_used")}</th>
                    <th scope="col" class="r">
                      <span class="sr-only">{t("access.col.actions")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <For each={list()}>
                    {(token) => (
                      <tr data-testid="access-sa-token" data-key={token.name}>
                        <td>
                          {token.name} <span class="mono muted">{token.prefix}…</span>
                        </td>
                        <td>
                          <ul class="plain-list">
                            <For each={tokenReach(token, names())}>{(line) => <li>{line}</li>}</For>
                          </ul>
                        </td>
                        <td class="num">
                          <Show when={token.expires_at} fallback={t("common.never")}>
                            {(at) => (
                              <>
                                {formatDate(at())}
                                <Show when={expired(token)}>
                                  {" "}
                                  <span class="tag conflict">{t("access.token.expired")}</span>
                                </Show>
                              </>
                            )}
                          </Show>
                        </td>
                        <td class="num">
                          <Show when={token.last_used_at} fallback={t("common.never")}>
                            {(at) => formatRelative(at())}
                          </Show>
                        </td>
                        <td class="r">
                          <button
                            type="button"
                            class="btn sm"
                            data-testid="access-sa-token-revoke"
                            aria-label={t("access.token.revoke_named", { name: token.name })}
                            onClick={() => setRevoking(token)}
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
      <Show when={creating()}>
        <TokenDialog
          catalog={props.catalog}
          create={(body) => api.post("/api/v1/access/service-accounts/{id}/tokens", { path: { id: props.account.id }, body })}
          onCreated={() => tokens.refetch()}
          onClose={() => setCreating(false)}
        />
      </Show>
      <Show when={revoking()}>
        {(token) => (
          <RunDialog
            title={t("access.token.revoke_title", { name: token().name })}
            body={<p>{t("access.token.revoke_body", { account: props.account.name })}</p>}
            confirmLabel={t("common.action.revoke")}
            danger
            run={() => revoke(token())}
            onClose={() => setRevoking(null)}
          />
        )}
      </Show>
    </div>
  );
}

function AddServiceAccountDialog(props: { onCreated: (account: UserInfo) => void; onClose: () => void }) {
  const [name, setName] = createSignal("");
  const [display, setDisplay] = createSignal("");
  const [roles, setRoles] = createSignal<RoleName[]>([]);
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  const nameError = () =>
    fieldMessages(error(), "name")[0] ?? (submitted() && !validAccountName(name().trim()) ? t("access.sa.error.name") : undefined);

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    if (!validAccountName(name().trim()) || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const account = await api.post("/api/v1/access/service-accounts", {
        body: { name: name().trim(), display_name: display().trim() || null, roles: roles() },
      });
      toast({ kind: "ok", title: t("access.sa.created", { name: account.name }) });
      props.onCreated(account);
      props.onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("access.sa.add_title")} onClose={props.onClose} class="dialog" testid="dialog-service-account">
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("access.sa.add_title")}</h2>
        <div class="dialog-body">
          <ErrorNotice error={error()} />
          <p class="muted">{t("access.sa.add_lede")}</p>
          <div class="field">
            <label for="sa-name">{t("access.sa.field.name")}</label>
            <input
              id="sa-name"
              class="input mono"
              data-testid="field-name"
              autocomplete="off"
              spellcheck={false}
              maxlength={64}
              aria-invalid={nameError() ? "true" : undefined}
              aria-describedby="sa-name-help"
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
            />
            <span class={nameError() ? "help bad field-error" : "help"} id="sa-name-help">
              {nameError() ?? t("access.sa.field.name_help")}
            </span>
          </div>
          <div class="field">
            <label for="sa-display">{t("access.sa.field.display_name")}</label>
            <input
              id="sa-display"
              class="input"
              data-testid="field-display_name"
              autocomplete="off"
              value={display()}
              onInput={(e) => setDisplay(e.currentTarget.value)}
            />
          </div>
          <fieldset class="field">
            <legend class="label">{t("access.sa.field.roles")}</legend>
            <p class="help">{t("access.sa.field.roles_help")}</p>
            <For each={ROLES}>
              {(role) => (
                <label class="ackrow">
                  <input
                    type="checkbox"
                    class="cb"
                    checked={roles().includes(role)}
                    data-testid={`field-role-${role}`}
                    onChange={(e) =>
                      setRoles(e.currentTarget.checked ? [...roles(), role] : roles().filter((r) => r !== role))
                    }
                  />
                  {roleName(role)}
                </label>
              )}
            </For>
          </fieldset>
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
  );
}
