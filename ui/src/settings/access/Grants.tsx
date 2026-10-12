// Scoped grants (IAM-01): the list with who holds what where, the dialog that gives a person or
// a service account a role over a VRF, a site or a prefix, and the revocation, which takes the
// grants issued under a delegable grant along (docs/access.md section 5). The access page shows
// every grant; the user page shows the grants of one account with `subject`.
import { createMemo, createSignal, For, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery, latest, type LiveQuery } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDateTime, t } from "../../i18n";
import { fieldMessages } from "../fields";
import { RunDialog } from "../UserDialogs";
import { catalogNames, type ScopeCatalog } from "./data";
import {
  GRANTABLE_ROLES,
  grantText,
  roleName,
  scopeText,
  sortGrants,
  type GrantSubject,
  type GrantView,
  type RoleName,
  type ScopeRule,
} from "./model";
import { ScopePicker } from "./ScopePicker";

/** The grants, all of them or those of one holder. Must be called inside a component. */
export function createGrants(subject?: () => string | undefined): LiveQuery<GrantView[]> {
  return createLiveQuery<GrantView[]>({
    topics: ["admin"],
    fetch: async (signal) => {
      const id = subject?.();
      const all = await fetchAll<GrantView>("/api/v1/access/grants", { signal, query: id ? { subject: id } : {} });
      return { value: sortGrants(all.items), revision: all.revision };
    },
  });
}

/** A holder in words: the display name, with "service account" for one. */
export function subjectLabel(subject: GrantSubject): string {
  return subject.kind === "service"
    ? t("access.subject.service", { name: subject.display_name || subject.name })
    : subject.display_name || subject.name;
}

/** The grants as a table, with the revoke button per grant. */
export function GrantsSection(props: {
  /** Only the grants of this account, which is also the holder of a new grant. */
  subject?: GrantSubject | undefined;
  catalog: ScopeCatalog | undefined;
  /** A heading id unique on the page. */
  headingId: string;
}) {
  const grants = createGrants(() => props.subject?.id);
  const [adding, setAdding] = createSignal(false);
  const [revoking, setRevoking] = createSignal<GrantView | null>(null);
  const names = createMemo(() => catalogNames(props.catalog));
  const list = () => latest(grants);
  const issuedUnder = (grant: GrantView) => (list() ?? []).filter((g) => g.parent === grant.id).length;

  const revoke = async (grant: GrantView) => {
    const answer = await api.delete("/api/v1/access/grants/{id}", { path: { id: grant.id } });
    grants.refetch();
    toast({
      kind: "ok",
      title: t("access.grants.revoked", { count: answer.revoked.length, holder: grant.subject.name }),
    });
  };

  return (
    <section class="page-section" aria-labelledby={props.headingId} data-testid="access-grants">
      <div class="access-head">
        <h2 id={props.headingId}>{t("access.grants.heading")}</h2>
        <button type="button" class="btn" data-testid="access-grant-add" onClick={() => setAdding(true)}>
          <Icon name="plus" size="sm" />
          {t("access.grants.add")}
        </button>
      </div>
      <p class="muted">{props.subject ? t("access.grants.lede_user") : t("access.grants.lede")}</p>
      <ErrorNotice error={grants.value.error} />
      <Show
        when={list()}
        fallback={
          <Show when={!grants.value.error}>
            <p class="muted" role="status">
              {t("common.loading")}
            </p>
          </Show>
        }
      >
        {(rows) => (
          <Show when={rows().length > 0} fallback={<p class="muted" data-testid="access-grants-empty">{t("access.grants.none")}</p>}>
            <div class="table-wrap">
              <table class="plain">
                <caption class="sr-only">{t("access.grants.heading")}</caption>
                <thead>
                  <tr>
                    <Show when={!props.subject}>
                      <th scope="col">{t("access.grants.col.holder")}</th>
                    </Show>
                    <th scope="col">{t("access.grants.col.role")}</th>
                    <th scope="col">{t("access.grants.col.scope")}</th>
                    <th scope="col">{t("access.grants.col.delegable")}</th>
                    <th scope="col">{t("access.grants.col.granted")}</th>
                    <th scope="col" class="r">
                      <span class="sr-only">{t("access.col.actions")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <For each={rows()}>
                    {(grant) => (
                      <tr data-testid="access-grant" data-key={grant.id} data-role={grant.role}>
                        <Show when={!props.subject}>
                          <td>{subjectLabel(grant.subject)}</td>
                        </Show>
                        <td>{roleName(grant.role)}</td>
                        <td data-testid="access-grant-scope">{scopeText(grant.scope, names())}</td>
                        <td>
                          {grant.delegable ? t("common.yes") : t("common.no")}
                          <Show when={grant.parent}>
                            {" "}
                            <span class="tag">{t("access.grants.delegated")}</span>
                          </Show>
                        </td>
                        <td class="num">{formatDateTime(grant.granted_at)}</td>
                        <td class="r">
                          <button
                            type="button"
                            class="btn sm"
                            data-testid="access-grant-revoke"
                            aria-label={t("access.grants.revoke_named", { grant: grantText(grant, names()), holder: grant.subject.name })}
                            onClick={() => setRevoking(grant)}
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

      <Show when={adding()}>
        <GrantDialog
          subject={props.subject}
          catalog={props.catalog}
          onCreated={() => grants.refetch()}
          onClose={() => setAdding(false)}
        />
      </Show>
      <Show when={revoking()}>
        {(grant) => (
          <RunDialog
            title={t("access.grants.revoke_title", { holder: grant().subject.name })}
            body={
              <>
                <p>{t("access.grants.revoke_body", { grant: grantText(grant(), names()), holder: grant().subject.name })}</p>
                <Show when={grant().delegable}>
                  <p class="muted">{t("access.grants.revoke_cascade", { count: issuedUnder(grant()) })}</p>
                </Show>
              </>
            }
            confirmLabel={t("common.action.revoke")}
            danger
            run={() => revoke(grant())}
            onClose={() => setRevoking(null)}
          />
        )}
      </Show>
    </section>
  );
}

/** Gives a person or a service account a role over a scope. */
export function GrantDialog(props: {
  /** The holder, fixed; otherwise the dialog offers the accounts a grant can name. */
  subject?: GrantSubject | undefined;
  catalog: ScopeCatalog | undefined;
  onCreated: (grant: GrantView) => void;
  onClose: () => void;
}) {
  const fixed = untrack(() => props.subject);
  const subjects = createLiveQuery<GrantSubject[]>({
    topics: ["admin"],
    fetch: async (signal) => {
      if (fixed) return { value: [fixed] };
      const all = await fetchAll<GrantSubject>("/api/v1/access/subjects", { signal });
      return { value: all.items, revision: all.revision };
    },
  });
  const [subject, setSubject] = createSignal(fixed?.id ?? "");
  const [role, setRole] = createSignal<RoleName>("operator");
  const [scope, setScope] = createSignal<ScopeRule | null | undefined>(undefined);
  const [delegable, setDelegable] = createSignal(false);
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  const subjectError = () => fieldMessages(error(), "subject")[0] ?? (submitted() && !subject() ? t("access.grants.error.subject") : undefined);
  const scopeError = () => fieldMessages(error(), "scope")[0] ?? (submitted() && !scope() ? t("access.grants.error.scope") : undefined);

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    const rule = scope();
    if (!subject() || !rule || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const grant = await api.post("/api/v1/access/grants", {
        body: { subject: subject(), role: role(), scope: rule, delegable: delegable() },
      });
      toast({ kind: "ok", title: t("access.grants.created", { holder: grant.subject.name }) });
      props.onCreated(grant);
      props.onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("access.grants.add_title")} onClose={props.onClose} class="dialog wide" testid="dialog-grant">
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("access.grants.add_title")}</h2>
        <div class="dialog-body">
          <ErrorNotice error={error()} />
          <div class="field">
            <label for="grant-subject">{t("access.grants.field.subject")}</label>
            <select
              id="grant-subject"
              class="select"
              data-testid="field-subject"
              disabled={!!fixed}
              aria-invalid={subjectError() ? "true" : undefined}
              aria-describedby={subjectError() ? "grant-subject-error" : undefined}
              onChange={(e) => setSubject(e.currentTarget.value)}
            >
              <Show when={!fixed}>
                <option value="" selected={subject() === ""}>
                  {t("access.picker.choose")}
                </option>
              </Show>
              <For each={latest(subjects) ?? []}>
                {(s) => (
                  <option value={s.id} selected={s.id === subject()}>
                    {t("access.subject.option", { name: s.name, label: subjectLabel(s) })}
                  </option>
                )}
              </For>
            </select>
            <Show when={subjectError()}>
              <span class="help bad field-error" id="grant-subject-error">
                {subjectError()}
              </span>
            </Show>
          </div>

          <fieldset class="field">
            <legend class="label">{t("access.grants.field.role")}</legend>
            <div class="choices" role="radiogroup" aria-label={t("access.grants.field.role")}>
              <For each={GRANTABLE_ROLES}>
                {(r) => (
                  <label class="choice">
                    <input
                      type="radio"
                      name="grant-role"
                      value={r}
                      checked={role() === r}
                      onChange={() => setRole(r)}
                      data-testid={`field-role-${r}`}
                    />
                    <span>
                      <strong>{roleName(r)}</strong>
                      <small class="muted">{r === "operator" ? t("access.role.operator_grant") : t("access.role.viewer_grant")}</small>
                    </span>
                  </label>
                )}
              </For>
            </div>
          </fieldset>

          <ScopePicker id="grant-scope" catalog={props.catalog} onChange={setScope} error={scopeError()} />

          <label class="ackrow">
            <input
              type="checkbox"
              class="cb"
              checked={delegable()}
              data-testid="field-delegable"
              onChange={(e) => setDelegable(e.currentTarget.checked)}
            />
            <span>
              {t("access.grants.field.delegable")}
              <small class="muted access-help">{t("access.grants.field.delegable_help")}</small>
            </span>
          </label>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("access.grants.add_confirm")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
