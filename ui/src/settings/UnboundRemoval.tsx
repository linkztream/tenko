// What a change that starts to require certificate-bound service-account tokens (TGL-47)
// removes, before it is made: the server's dry run of the same change, so the count shown is
// the count the change removes. Loosening the requirement later brings none of them back.
import { createEffect, createResource, Show } from "solid-js";
import { api } from "../api/client";
import type { SettingsPatch } from "../api/types";
import { ErrorNotice, Notice } from "../components/Notice";
import { formatList, t } from "../i18n";

/**
 * The removal a change would make; `onCount` hears the count once the dry run answered, and
 * `undefined` while it has not (a dialog holds its confirmation until then).
 */
export function UnboundRemoval(props: {
  patch: SettingsPatch | undefined;
  revision: number | null | undefined;
  onCount: (count: number | undefined) => void;
}) {
  const [plan] = createResource(
    () => props.patch && { patch: props.patch, revision: props.revision },
    async ({ patch, revision }) => {
      const view = await api.patch("/api/v1/settings/security", { body: patch, query: { dry_run: true }, ifMatch: revision ?? undefined });
      return view.unbound_tokens_removed ?? { count: 0, accounts: [] };
    },
  );
  createEffect(() => props.onCount(plan.loading || plan.error ? undefined : plan()?.count));
  return (
    <Show when={props.patch}>
      <Show when={!plan.error} fallback={<ErrorNotice error={plan.error} />}>
        <Show when={plan()}>
          {(p) => (
            <Show
              when={p().count > 0}
              fallback={<Notice kind="info" testid="unbound-removal">{t("settings.security.unbound.none")}</Notice>}
            >
              <Notice kind="bad" title={t("settings.security.unbound.title", { count: p().count })} testid="unbound-removal">
                <p>
                  {t("settings.security.unbound.body", {
                    count: p().count,
                    accounts: formatList(p().accounts.map((a) => t("settings.security.unbound.account", { name: a.name, count: a.tokens }))),
                  })}
                </p>
                <p>{t("settings.security.unbound.permanent")}</p>
              </Notice>
            </Show>
          )}
        </Show>
      </Show>
    </Show>
  );
}
