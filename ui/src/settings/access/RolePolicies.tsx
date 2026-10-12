// The four roles and the sign-in requirement of each (IAM-06, docs/access.md sections 2 and 8):
// what the role may do, whether it can be granted over a scope, and the MFA policy in force,
// which is the stricter of the stored policy and the profile's. Changing a policy stores it;
// "Follow the profile" removes the stored one.
import { createSignal, For, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery, latest } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import { Dialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { globalOnly, MFA_LEVELS, mfaText, roleDescription, roleName, ROLES, type RoleMfa, type RolePolicyView } from "./model";

export function RolesSection() {
  const policies = createLiveQuery<RolePolicyView[]>({
    topics: ["admin"],
    fetch: async (signal) => {
      const all = await fetchAll<RolePolicyView>("/api/v1/access/role-policies", { signal });
      return { value: all.items, revision: all.revision };
    },
  });
  const [editing, setEditing] = createSignal<RolePolicyView | null>(null);
  const policyOf = (role: string) => latest(policies)?.find((p) => p.role === role);

  return (
    <section class="page-section" aria-labelledby="access-roles" data-testid="access-roles">
      <h2 id="access-roles">{t("access.roles.heading")}</h2>
      <p class="muted">{t("access.roles.lede")}</p>
      <ErrorNotice error={policies.value.error} />
      <div class="table-wrap">
        <table class="plain">
          <caption class="sr-only">{t("access.roles.heading")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("access.roles.col.role")}</th>
              <th scope="col">{t("access.roles.col.may")}</th>
              <th scope="col">{t("access.roles.col.held")}</th>
              <th scope="col">{t("access.roles.col.mfa")}</th>
              <th scope="col" class="r">
                <span class="sr-only">{t("access.col.actions")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <For each={ROLES}>
              {(role) => (
                <tr data-testid="access-role" data-key={role}>
                  <th scope="row">{roleName(role)}</th>
                  <td>{roleDescription(role)}</td>
                  <td>{globalOnly(role) ? t("access.roles.global_only") : t("access.roles.global_or_grant")}</td>
                  <td data-testid="access-role-mfa" data-mfa={policyOf(role)?.mfa}>
                    <Show when={policyOf(role)} fallback={<span class="muted">{t("common.loading")}</span>}>
                      {(p) => (
                        <>
                          {mfaText(p().mfa)}
                          <small class="muted access-help">
                            {p().stored
                              ? t("access.roles.stored", { profile: mfaText(p().profile_default) })
                              : t("access.roles.follows_profile")}
                          </small>
                        </>
                      )}
                    </Show>
                  </td>
                  <td class="r">
                    <button
                      type="button"
                      class="btn sm"
                      data-testid="access-role-policy-edit"
                      disabled={!policyOf(role)}
                      aria-label={t("access.roles.edit_named", { role: roleName(role) })}
                      onClick={() => setEditing(policyOf(role) ?? null)}
                    >
                      {t("access.roles.edit")}
                    </button>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>
      <Show when={editing()}>
        {(policy) => (
          <PolicyDialog policy={policy()} onSaved={() => policies.refetch()} onClose={() => setEditing(null)} />
        )}
      </Show>
    </section>
  );
}

/** "Follow the profile" or one of the three requirements. */
type Choice = RoleMfa | "profile";

function PolicyDialog(props: { policy: RolePolicyView; onSaved: () => void; onClose: () => void }) {
  const start = untrack(() => props.policy);
  const [choice, setChoice] = createSignal<Choice>(start.stored ?? "profile");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const weaker = () => {
    const c = choice();
    return c !== "profile" && MFA_LEVELS.indexOf(c) < MFA_LEVELS.indexOf(props.policy.profile_default);
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      const c = choice();
      const path = { role: props.policy.role };
      if (c === "profile") await api.delete("/api/v1/access/role-policies/{role}", { path });
      else await api.put("/api/v1/access/role-policies/{role}", { path, body: { mfa: c } });
      toast({ kind: "ok", title: t("access.roles.saved", { role: roleName(props.policy.role) }) });
      props.onSaved();
      props.onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      label={t("access.roles.dialog_title", { role: roleName(props.policy.role) })}
      onClose={props.onClose}
      class="dialog"
      testid="dialog-role-policy"
    >
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("access.roles.dialog_title", { role: roleName(props.policy.role) })}</h2>
        <div class="dialog-body">
          <ErrorNotice error={error()} />
          <fieldset class="field">
            <legend class="label">{t("access.roles.col.mfa")}</legend>
            <div class="choices" role="radiogroup" aria-label={t("access.roles.col.mfa")}>
              <For each={["profile", ...MFA_LEVELS] as Choice[]}>
                {(c) => (
                  <label class="choice">
                    <input
                      type="radio"
                      name="role-mfa"
                      value={c}
                      checked={choice() === c}
                      onChange={() => setChoice(c)}
                      data-testid={`field-mfa-${c}`}
                    />
                    <span>
                      <strong>
                        {c === "profile" ? t("access.roles.follow_profile", { profile: mfaText(props.policy.profile_default) }) : mfaText(c)}
                      </strong>
                      <small class="muted">{t(`access.mfa.${c}_help`)}</small>
                    </span>
                  </label>
                )}
              </For>
            </div>
          </fieldset>
          <Show when={weaker()}>
            <p class="note" role="status" data-testid="role-policy-weaker">
              {t("access.roles.weaker", { profile: mfaText(props.policy.profile_default) })}
            </p>
          </Show>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("common.action.save")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
