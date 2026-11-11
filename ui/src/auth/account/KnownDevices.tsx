import { createSignal, Show } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import type { KnownDeviceInfo } from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { KnownDeviceList } from "./KnownDeviceList";
import { describeError, latest } from "./shared";

/**
 * The known devices of the account: browsers that completed a sign-in and so pass the account-wide
 * delay of the sign-in lock. The page lists them by date, and forgets one or all.
 */
export default function KnownDevices() {
  const query = createLiveQuery<KnownDeviceInfo[]>({
    topics: ["admin"],
    fetch: async (signal) => {
      const all = await fetchAll<KnownDeviceInfo>("/api/v1/auth/known-devices", { signal });
      return { value: all.items, revision: all.revision };
    },
  });
  // What the open dialog is about: one device, or "all".
  const [asking, setAsking] = createSignal<KnownDeviceInfo | "all">();
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const devices = () => latest(query);
  const count = () => devices()?.length ?? 0;

  const forget = async () => {
    const what = asking();
    if (!what) return;
    setError(null);
    setBusy(true);
    const total = count();
    try {
      if (what === "all") {
        await api.delete("/api/v1/auth/known-devices", {});
        toast({ title: t("account.devices.forgotten_all", { count: total }), kind: "ok" });
      } else {
        await api.delete("/api/v1/auth/known-devices/{id}", { path: { id: what.id } });
        toast({ title: t("account.devices.forgotten"), kind: "ok" });
      }
    } catch (err) {
      setError(describeError(err));
    }
    setBusy(false);
    setAsking(undefined);
    query.refetch();
  };

  return (
    <div class="page-body acct-stack">
      <section class="page-section" aria-labelledby="acct-devices">
        <div class="acct-head">
          <h2 id="acct-devices">{t("account.devices.title")}</h2>
          <button type="button" class="btn" disabled={count() === 0} onClick={() => setAsking("all")}>
            {t("account.devices.forget_all")}
          </button>
        </div>
        <p>{t("account.devices.lede")}</p>

        <Show when={query.value.error}>
          <div class="note bad" role="alert">
            <Icon name="alert" size="sm" />
            <span class="grow">{describeError(query.value.error)}</span>
            <button type="button" class="btn sm" onClick={() => query.refetch()}>
              {t("common.action.retry")}
            </button>
          </div>
        </Show>
        <Show when={error()}>
          <Notice kind="bad" role="alert">
            {error()}
          </Notice>
        </Show>

        <Show
          when={devices()}
          fallback={
            <Show when={!query.value.error}>
              <p class="muted">{t("common.loading")}</p>
            </Show>
          }
        >
          {(list) => (
            <Show when={list().length > 0} fallback={<p class="muted">{t("account.devices.none")}</p>}>
              <KnownDeviceList devices={list()} caption={t("account.devices.title")} onForget={(d) => setAsking(d)} />
            </Show>
          )}
        </Show>
      </section>

      <Show when={asking()}>
        {(what) => (
          <ConfirmDialog
            title={what() === "all" ? t("account.devices.confirm_all_title") : t("account.devices.confirm_title")}
            body={
              <p>
                {what() === "all"
                  ? t("account.devices.confirm_all_body", { count: count() })
                  : t("account.devices.confirm_body")}
              </p>
            }
            confirmLabel={
              what() === "all"
                ? t("account.devices.confirm_all_button", { count: count() })
                : t("account.devices.confirm_button")
            }
            cancelLabel={t("common.action.cancel")}
            danger
            busy={busy()}
            onConfirm={() => void forget()}
            onClose={() => setAsking(undefined)}
          />
        )}
      </Show>
    </div>
  );
}
