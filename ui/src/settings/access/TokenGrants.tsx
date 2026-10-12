// The parts of a scoped token (IAM-10, docs/access.md section 7) that the personal token dialog
// and the service account token dialog share: the grants (a role over the whole installation
// or over a scope) and the special scopes `metrics` and `audit:read`, and the dialog that shows
// a new token once.
import { createSignal, For, Index, Show, untrack } from "solid-js";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { t } from "../../i18n";
import { copyText } from "../../auth/account/shared";
import type { ScopeCatalog } from "./data";
import { GRANTABLE_ROLES, ROLES, roleName, TOKEN_SCOPES, tokenScopeText, type RoleName, type ScopeRule, type TokenGrant, type TokenScope } from "./model";
import { ScopePicker } from "./ScopePicker";

/** One row of the editor; `scope` is `undefined` while a scope is being picked. */
export interface GrantRow {
  key: number;
  role: RoleName;
  scope: ScopeRule | null | undefined;
}

/** The complete grants of the rows, or `undefined` when a row still lacks its scope. */
export function rowsToGrants(rows: readonly GrantRow[]): TokenGrant[] | undefined {
  const out: TokenGrant[] = [];
  for (const row of rows) {
    if (row.scope === undefined) return undefined;
    out.push(row.scope ? { role: row.role, scope: row.scope } : { role: row.role });
  }
  return out;
}

/**
 * The grants and special scopes of a scoped token. A grant over the whole installation may carry
 * any role the owner holds globally; a grant over a scope carries operator or viewer.
 */
export function TokenGrantsEditor(props: {
  id: string;
  catalog: ScopeCatalog | undefined;
  rows: readonly GrantRow[];
  onRows: (rows: GrantRow[]) => void;
  scopes: readonly TokenScope[];
  onScopes: (scopes: TokenScope[]) => void;
  error?: string | undefined;
}) {
  let next = untrack(() => props.rows.reduce((max, row) => Math.max(max, row.key), 0)) + 1;
  const update = (key: number, change: Partial<GrantRow>) =>
    props.onRows(props.rows.map((row) => (row.key === key ? { ...row, ...change } : row)));
  const rolesFor = (row: GrantRow): readonly RoleName[] => (row.scope === null ? ROLES : GRANTABLE_ROLES);

  return (
    <div class="token-grants" data-testid="token-grants">
      <fieldset class="field">
        <legend class="label">{t("access.token.grants")}</legend>
        <p class="help">{t("access.token.grants_help")}</p>
        <Index each={props.rows}>
          {(row, i) => (
            <div class="token-grant card" data-testid="token-grant" data-index={i}>
              <div class="field">
                <label for={`${props.id}-role-${row().key}`}>{t("access.grants.field.role")}</label>
                <select
                  id={`${props.id}-role-${row().key}`}
                  class="select"
                  data-testid="field-token-role"
                  onChange={(e) => update(row().key, { role: e.currentTarget.value as RoleName })}
                >
                  <For each={rolesFor(row())}>
                    {(r) => (
                      <option value={r} selected={r === row().role}>
                        {roleName(r)}
                      </option>
                    )}
                  </For>
                </select>
              </div>
              <ScopePicker
                id={`${props.id}-scope-${row().key}`}
                catalog={props.catalog}
                initial={row().scope}
                everything
                onChange={(scope) =>
                  update(row().key, {
                    scope,
                    // A scope narrows the role to operator or viewer.
                    role: scope && !GRANTABLE_ROLES.includes(row().role) ? "viewer" : row().role,
                  })
                }
              />
              <button
                type="button"
                class="btn sm ghost"
                data-testid="token-grant-remove"
                aria-label={t("access.token.remove_grant", { n: i + 1 })}
                onClick={() => props.onRows(props.rows.filter((r) => r.key !== row().key))}
              >
                <Icon name="x" size="sm" />
                {t("common.action.remove")}
              </button>
            </div>
          )}
        </Index>
        <div class="form-row">
          <button
            type="button"
            class="btn sm"
            data-testid="token-grant-add"
            onClick={() => props.onRows([...props.rows, { key: next++, role: "viewer", scope: null }])}
          >
            <Icon name="plus" size="sm" />
            {t("access.token.add_grant")}
          </button>
        </div>
      </fieldset>
      <fieldset class="field">
        <legend class="label">{t("access.token.scopes")}</legend>
        <For each={TOKEN_SCOPES}>
          {(scope) => (
            <label class="ackrow">
              <input
                type="checkbox"
                class="cb"
                checked={props.scopes.includes(scope)}
                data-testid={`field-token-scope-${scope === "audit:read" ? "audit_read" : scope}`}
                onChange={(e) =>
                  props.onScopes(e.currentTarget.checked ? [...props.scopes, scope] : props.scopes.filter((s) => s !== scope))
                }
              />
              <span>
                {tokenScopeText(scope)}
                <small class="muted access-help">{t(`access.token_scope.${scope === "audit:read" ? "audit_read" : scope}_help`)}</small>
              </span>
            </label>
          )}
        </For>
      </fieldset>
      <Show when={props.error}>
        <p class="help bad field-error" role="alert" data-testid="token-grants-error">
          <Icon name="alert" size="xs" />
          {props.error}
        </p>
      </Show>
    </div>
  );
}

/** Shows a new token once; it closes only after the person confirms it is stored. */
export function TokenOnceDialog(props: { name: string; token: string; onClose: () => void }) {
  const [stored, setStored] = createSignal(false);
  const close = () => {
    if (stored()) props.onClose();
  };
  return (
    <Dialog label={t("access.token.created_title")} onClose={close} class="dialog wide" testid="dialog-token-created">
      <h2 class="dialog-title">{t("access.token.created_title")}</h2>
      <div class="dialog-body">
        <p>{t("access.token.created_body", { name: props.name })}</p>
        <div class="form-row">
          <code class="secret acct-token" data-testid="token-secret">
            {props.token}
          </code>
          <button type="button" class="btn sm" onClick={() => void copyText(props.token)}>
            <Icon name="copy" size="sm" />
            {t("common.action.copy")}
          </button>
        </div>
        <label class="ackrow">
          <input
            type="checkbox"
            class="cb"
            checked={stored()}
            data-testid="token-stored"
            onChange={(e) => setStored(e.currentTarget.checked)}
          />
          {t("access.token.stored")}
        </label>
      </div>
      <div class="dialog-actions">
        <button type="button" class="btn primary" data-testid="token-done" disabled={!stored()} onClick={close}>
          {t("common.action.close")}
        </button>
      </div>
    </Dialog>
  );
}
