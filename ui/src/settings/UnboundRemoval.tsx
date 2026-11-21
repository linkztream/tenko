// What a change that starts to require certificate-bound service-account tokens (TGL-47)
// removes, before it is made: the server's dry run of the same change, so the count shown is
// the count the change removes. Loosening the requirement later brings none of them back.
import { createEffect, createResource, Show } from "solid-js";
import { api } from "../api/client";
import type { SettingsPatch } from "../api/types";
import { ErrorNotice, Notice } from "../components/Notice";
import { formatList, t } from "../i18n";

async function dryRun(patch: SettingsPatch, revision: number | null | undefined) {
  const view = await api.patch("/api/v1/settings/security", { body: patch, query: { dry_run: true }, ifMatch: revision ?? undefined });
  return view.unbound_tokens_removed ?? { count: 0, accounts: [] };
}

/**
 * Asks the dry run again, as a dialog saves: a token made since the person read the count is
 * removed by the save too, and the settings revision does not change when one is made.
 */
export const removalGrew = async (patch: SettingsPatch, revision: number | null | undefined, seen: number | undefined) =>
  (await dryRun(patch, revision)).count > (seen ?? 0);

/**
 * The removal a change would make; `onCount` hears the count once the dry run answered, and
 * `undefined` while it has not (a dialog holds its confirmation until then). `again` changes
 * to read it anew; `grew` says that the new count is larger than the one confirmed.
 */
export function UnboundRemoval(props: {
  patch: SettingsPatch | undefined;
  revision: number | null | undefined;
  onCount: (count: number | undefined) => void;
  again?: number;
  grew?: boolean;
}) {
  const [plan] = createResource(
    () => props.patch && { patch: props.patch, revision: props.revision, again: props.again },
    ({ patch, revision }) => dryRun(patch, revision),
  );
  createEffect(() => props.onCount(plan.loading || plan.error ? undefined : plan()?.count));
  return (
    <Show when={props.patch}>
      <Show when={props.grew}>
        <Notice kind="warn" testid="unbound-grew">{t("settings.security.unbound.grew")}</Notice>
      </Show>
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
