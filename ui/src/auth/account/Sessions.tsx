import { createSignal, For, Show } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import type { SessionSummary } from "../../api/types";
import { Addr } from "../../components/Addr";
import { ConfirmDialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDateTime, formatRelative, t } from "../../i18n";
import { signOut } from "../session";
import { clientLabel } from "./client";
import { describeError, latest } from "./shared";

/** The sessions of the account (IAM-08): where it is signed in, revoke one or all the others. */
export default function Sessions() {
  const query = createLiveQuery<SessionSummary[]>({
    topics: ["admin"],
    fetch: async (signal) => {
      const all = await fetchAll<SessionSummary>("/api/v1/auth/sessions", { signal });
      return { value: all.items, revision: all.revision };
    },
  });
  const [asking, setAsking] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const sessions = () => latest(query);
  const others = () => (sessions() ?? []).filter((s) => !s.current);

  const revoke = async (s: SessionSummary) => {
    setError(null);
    try {
      await api.delete("/api/v1/auth/sessions/{id}", { path: { id: s.id } });
      toast({ title: t("account.sessions.revoked"), kind: "ok" });
    } catch (err) {
      setError(describeError(err));
    }
    query.refetch();
  };

  const revokeOthers = async () => {
    setError(null);
    setBusy(true);
    const targets = others();
    const results = await Promise.allSettled(
      targets.map((s) => api.delete("/api/v1/auth/sessions/{id}", { path: { id: s.id } })),
    );
    const failed = results.filter((r) => r.status === "rejected");
    const done = results.length - failed.length;
    setBusy(false);
    setAsking(false);
    if (done > 0) toast({ title: t("account.sessions.revoked_many", { count: done }), kind: "ok" });
    const first = failed[0];
    if (first) setError(describeError(first.reason));
    query.refetch();
  };

  return (
    <div class="page-body acct-stack">
      <section class="page-section" aria-labelledby="acct-sessions">
        <div class="acct-head">
          <h2 id="acct-sessions">{t("account.sessions.title")}</h2>
          <button type="button" class="btn" disabled={others().length === 0} onClick={() => setAsking(true)}>
            {t("account.sessions.sign_out_others")}
          </button>
        </div>
        <p>{t("account.sessions.lede")}</p>

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

        <Show when={sessions()} fallback={<Show when={!query.value.error}><p class="muted">{t("common.loading")}</p></Show>}>
          {(list) => (
            <div class="table-wrap">
              <table class="plain">
                <caption class="sr-only">{t("account.sessions.title")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("account.sessions.col.client")}</th>
                    <th scope="col">{t("account.sessions.col.address")}</th>
                    <th scope="col">{t("account.sessions.col.signed_in")}</th>
                    <th scope="col">{t("account.sessions.col.last_activity")}</th>
                    <th scope="col">{t("account.sessions.col.expires")}</th>
                    <th scope="col">{t("account.sessions.col.strength")}</th>
                    <th scope="col" class="r">
                      <span class="sr-only">{t("account.sessions.col.actions")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <For each={list()}>
                    {(s) => (
                      <tr>
                        <td>
                          <span class="acct-client" title={s.user_agent ?? undefined}>
                            {clientLabel(s.user_agent)}
                          </span>
                          <Show when={s.current}>
                            <span class="tag accent acct-this">{t("account.sessions.this")}</span>
                          </Show>
                        </td>
                        <td>
                          <Show when={s.source_ip} fallback={<span class="muted">{t("common.unknown")}</span>}>
                            {(ip) => <Addr value={ip()} />}
                          </Show>
                        </td>
                        <td class="num">{formatDateTime(s.created_at)}</td>
                        <td class="num" title={formatDateTime(s.last_seen_at)}>
                          {formatRelative(s.last_seen_at)}
                        </td>
                        <td class="num">{formatDateTime(s.expires_at)}</td>
                        <td>{t(`account.sessions.strength.${s.strength}`)}</td>
                        <td class="r">
                          <Show
                            when={s.current}
                            fallback={
                              <button
                                type="button"
                                class="btn sm"
                                aria-label={t("account.sessions.revoke_named", { client: clientLabel(s.user_agent) })}
                                onClick={() => void revoke(s)}
                              >
                                {t("common.action.revoke")}
                              </button>
                            }
                          >
                            <button type="button" class="btn sm" onClick={() => void signOut()}>
                              {t("account.sessions.sign_out")}
                            </button>
                          </Show>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          )}
        </Show>
        <Show when={sessions() && others().length === 0}>
          <p class="muted">{t("account.sessions.none_other")}</p>
        </Show>
      </section>

      <Show when={asking()}>
        <ConfirmDialog
          title={t("account.sessions.confirm_title")}
          body={<p>{t("account.sessions.confirm_body", { count: others().length })}</p>}
          confirmLabel={t("account.sessions.confirm_button", { count: others().length })}
          cancelLabel={t("common.action.cancel")}
          danger
          busy={busy()}
          onConfirm={() => void revokeOthers()}
          onClose={() => setAsking(false)}
        />
      </Show>
    </div>
  );
}
