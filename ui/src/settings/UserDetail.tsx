// One user: the facts, then the things an administrator can do with the account. Anything
// that ends access or cannot be undone is confirmed by a button that names the action and
// the account; every result is a toast with the same verb.
import { A, useNavigate } from "@solidjs/router";
import { createEffect, createSignal, For, Show, type JSX } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { fetchAll } from "../api/paginate";
import { isApiError } from "../api/problem";
import type { RoleInfo, UserInfo } from "../api/types";
import { paths } from "../app/paths";
import { session } from "../auth/session";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatDateTime, formatRelative, t, tx } from "../i18n";
import { EditUserDialog, PasswordDialog, RolesDialog, RunDialog } from "./UserDialogs";
import { languageName, methodParts, rolesText, UserStatus } from "./userModel";
import "./settings.css";

type Dialog = "edit" | "roles" | "password" | "disable" | "sign-out" | "break-glass" | "delete";

interface UserData {
  user: UserInfo;
  roles: RoleInfo[];
}

/** One row of the action list: what it is, what it does, the button. */
function ActionRow(props: { title: string; children: JSX.Element; action: JSX.Element }) {
  return (
    <li class="action-row">
      <div class="action-text">
        <strong>{props.title}</strong>
        <span class="muted">{props.children}</span>
      </div>
      <div class="action-button">{props.action}</div>
    </li>
  );
}

export default function UserDetail(props: { id: string }) {
  const navigate = useNavigate();
  const live = createLiveQuery<UserData>({
    topics: ["admin"],
    fetch: async (signal) => {
      const [user, roles] = await Promise.all([
        api.get("/api/v1/users/{id}", { path: { id: props.id }, signal }),
        fetchAll<RoleInfo>("/api/v1/roles", { signal }),
      ]);
      return { value: { user, roles: roles.items }, revision: undefined };
    },
  });

  // The user on screen: the last answer of the server, from a read or from our own change.
  const [current, setCurrent] = createSignal<UserData>();
  createEffect(() => {
    const state = live.value.state;
    if (state === "ready" || state === "refreshing") setCurrent(live.value());
  });
  const [dialog, setDialog] = createSignal<Dialog>();
  const [actionError, setActionError] = createSignal<unknown>(null);
  const [busy, setBusy] = createSignal<string>();

  const setUser = (user: UserInfo) => setCurrent((d) => (d ? { ...d, user } : d));
  const stale = (err: unknown) => {
    if (isApiError(err, "sys.store.precondition_failed")) live.refetch();
  };

  /** Runs an action that has no dialog; the error shows above the actions. */
  const direct = async (key: string, run: () => Promise<void>) => {
    setBusy(key);
    setActionError(null);
    try {
      await run();
    } catch (err) {
      stale(err);
      setActionError(err);
    } finally {
      setBusy(undefined);
    }
  };

  const mine = () => session()?.user.id;
  const gone = () => live.value.error && isApiError(live.value.error, "users.not_found");

  return (
    <div class="page-body">
      <Show
        when={current()}
        fallback={
          <>
            <nav class="crumbs" aria-label={t("settings.users.crumbs")}>
              <A href={paths.settings("users")}>{t("settings.nav.users")}</A>
            </nav>
            <Show
              when={live.value.error}
              fallback={
                <p class="muted" role="status">
                  {t("common.loading")}
                </p>
              }
            >
              <ErrorNotice error={live.value.error} />
              <div class="form-row">
                <A class="btn" href={paths.settings("users")}>
                  {t("settings.users.back")}
                </A>
                <Show when={!gone()}>
                  <button type="button" class="btn" onClick={() => live.refetch()}>
                    {t("common.action.retry")}
                  </button>
                </Show>
              </div>
            </Show>
          </>
        }
      >
        {(data) => {
          const user = () => data().user;
          const own = () => user().id === mine();
          const name = () => user().name;

          const enable = () =>
            direct("enable", async () => {
              setUser(
                await api.patch("/api/v1/users/{id}", {
                  path: { id: user().id },
                  body: { disabled: false },
                  ifMatch: user().revision,
                }),
              );
              toast({ kind: "ok", title: t("settings.users.enabled", { name: name() }) });
            });

          const unlock = () =>
            direct("unlock", async () => {
              setUser(await api.post("/api/v1/users/{id}/unlock", { path: { id: user().id } }));
              toast({ kind: "ok", title: t("settings.users.unlocked", { name: name() }) });
            });

          const runDisable = async () => {
            setUser(
              await api.patch("/api/v1/users/{id}", {
                path: { id: user().id },
                body: { disabled: true },
                ifMatch: user().revision,
              }),
            );
            toast({ kind: "ok", title: t("settings.users.disabled", { name: name() }) });
          };

          const runSignOut = async () => {
            await api.delete("/api/v1/users/{id}/sessions", { path: { id: user().id } });
            toast({ kind: "ok", title: t("settings.users.signed_out", { name: name() }) });
          };

          const runBreakGlass = async () => {
            const enabled = !user().break_glass;
            await api.put("/api/v1/system/break-glass", { body: { user_id: user().id, enabled } });
            live.refetch();
            toast({
              kind: "ok",
              title: enabled
                ? t("settings.users.break_glass.made", { name: name() })
                : t("settings.users.break_glass.removed", { name: name() }),
            });
          };

          const runDelete = async () => {
            await api.delete("/api/v1/users/{id}", { path: { id: user().id }, ifMatch: user().revision });
            toast({ kind: "ok", title: t("settings.users.deleted", { name: name() }) });
            navigate(paths.settings("users"));
          };

          return (
            <>
              <nav class="crumbs" aria-label={t("settings.users.crumbs")}>
                <A href={paths.settings("users")}>{t("settings.nav.users")}</A>
                <Icon name="chev-r" size="xs" />
                <span aria-current="page">{name()}</span>
              </nav>

              <section class="page-section" aria-labelledby="ud-title">
                <h2 id="ud-title">
                  {user().display_name}
                  <Show when={own()}>
                    <span class="tag accent">{t("settings.users.you")}</span>
                  </Show>
                </h2>
                <div class="card facts">
                  <dl class="kv">
                    <dt>{t("settings.users.col.name")}</dt>
                    <dd class="mono">{name()}</dd>
                    <dt>{t("settings.users.col.display_name")}</dt>
                    <dd>{user().display_name}</dd>
                    <dt>{t("settings.users.col.roles")}</dt>
                    <dd>{rolesText(user().roles)}</dd>
                    <dt>{t("settings.users.col.status")}</dt>
                    <dd>
                      <UserStatus user={user()} />
                    </dd>
                    <dt>{t("settings.users.col.methods")}</dt>
                    <dd>
                      <Show when={methodParts(user().factors).length > 0} fallback={t("common.none")}>
                        <ul class="plain-list">
                          <For each={methodParts(user().factors)}>{(part) => <li>{part}</li>}</For>
                        </ul>
                      </Show>
                    </dd>
                    <dt>{t("settings.users.field.language")}</dt>
                    <dd>{languageName(user().language)}</dd>
                    <dt>{t("settings.users.created")}</dt>
                    <dd>{formatDateTime(user().created_at)}</dd>
                    <dt>{t("settings.users.col.last_login")}</dt>
                    <dd>
                      <Show when={user().last_login_at} fallback={t("common.never")}>
                        {(at) => (
                          <>
                            {formatRelative(at())} <span class="muted">({formatDateTime(at())})</span>
                          </>
                        )}
                      </Show>
                    </dd>
                  </dl>
                </div>
              </section>

              <section class="page-section" aria-labelledby="ud-actions">
                <h2 id="ud-actions">{t("settings.users.actions")}</h2>
                <ErrorNotice error={actionError()} />
                <ul class="card action-list">
                  <ActionRow
                    title={t("settings.users.action.details")}
                    action={
                      <button type="button" class="btn" onClick={() => setDialog("edit")}>
                        {t("settings.users.action.edit")}
                      </button>
                    }
                  >
                    {t("settings.users.action.details_help")}
                  </ActionRow>

                  <ActionRow
                    title={t("settings.users.col.roles")}
                    action={
                      <button type="button" class="btn" disabled={user().break_glass} onClick={() => setDialog("roles")}>
                        {t("settings.users.action.roles")}
                      </button>
                    }
                  >
                    {user().break_glass
                      ? t("settings.users.action.roles_break_glass")
                      : t("settings.users.action.roles_help", { roles: rolesText(user().roles) })}
                  </ActionRow>

                  <Show when={user().lock}>
                    <ActionRow
                      title={t("settings.users.action.lock")}
                      action={
                        <button
                          type="button"
                          class="btn"
                          disabled={busy() === "unlock"}
                          onClick={() => void unlock()}
                        >
                          {t("settings.users.action.unlock")}
                        </button>
                      }
                    >
                      {t("settings.users.action.unlock_help", { name: name() })}
                    </ActionRow>
                  </Show>

                  <ActionRow
                    title={t("settings.users.action.access")}
                    action={
                      <Show
                        when={user().disabled}
                        fallback={
                          <button type="button" class="btn danger" disabled={own()} onClick={() => setDialog("disable")}>
                            {t("settings.users.action.disable")}
                          </button>
                        }
                      >
                        <button
                          type="button"
                          class="btn"
                          disabled={busy() === "enable"}
                          onClick={() => void enable()}
                        >
                          {t("settings.users.action.enable")}
                        </button>
                      </Show>
                    }
                  >
                    {user().disabled
                      ? t("settings.users.action.enable_help", { name: name() })
                      : own()
                        ? t("settings.users.action.own_disable")
                        : t("settings.users.action.disable_help", { name: name() })}
                  </ActionRow>

                  <ActionRow
                    title={t("settings.users.action.sessions")}
                    action={
                      <button type="button" class="btn danger" onClick={() => setDialog("sign-out")}>
                        {t("settings.users.action.sign_out")}
                      </button>
                    }
                  >
                    {t("settings.users.action.sign_out_help", { name: name() })}
                  </ActionRow>

                  <ActionRow
                    title={t("settings.users.field.password")}
                    action={
                      <button type="button" class="btn" disabled={user().break_glass} onClick={() => setDialog("password")}>
                        {t("settings.users.action.password")}
                      </button>
                    }
                  >
                    {user().break_glass
                      ? t("settings.users.action.password_break_glass")
                      : t("settings.users.action.password_help", { name: name() })}
                  </ActionRow>

                  <ActionRow
                    title={t("settings.users.status.break_glass")}
                    action={
                      <button type="button" class="btn" onClick={() => setDialog("break-glass")}>
                        {user().break_glass
                          ? t("settings.users.action.break_glass_remove")
                          : t("settings.users.action.break_glass_make")}
                      </button>
                    }
                  >
                    {user().break_glass
                      ? t("settings.users.action.break_glass_on")
                      : t("settings.users.action.break_glass_off")}
                  </ActionRow>

                  <ActionRow
                    title={t("settings.users.action.remove")}
                    action={
                      <button type="button" class="btn danger" disabled={own()} onClick={() => setDialog("delete")}>
                        {t("settings.users.action.delete")}
                      </button>
                    }
                  >
                    {own() ? t("settings.users.action.own_delete") : t("settings.users.action.delete_help", { name: name() })}
                  </ActionRow>
                </ul>
              </section>

              <Show when={dialog() === "edit"}>
                <EditUserDialog user={user()} onSaved={setUser} onStale={stale} onClose={() => setDialog(undefined)} />
              </Show>
              <Show when={dialog() === "roles"}>
                <RolesDialog
                  user={user()}
                  roles={data().roles}
                  onSaved={setUser}
                  onStale={stale}
                  onClose={() => setDialog(undefined)}
                />
              </Show>
              <Show when={dialog() === "password"}>
                <PasswordDialog user={user()} onSaved={setUser} onStale={stale} onClose={() => setDialog(undefined)} />
              </Show>

              <Show when={dialog() === "disable"}>
                <RunDialog
                  title={t("settings.users.disable.title", { name: name() })}
                  body={<p>{t("settings.users.disable.body", { name: name() })}</p>}
                  confirmLabel={t("settings.users.disable.confirm", { name: name() })}
                  danger
                  onStale={stale}
                  run={runDisable}
                  onClose={() => setDialog(undefined)}
                />
              </Show>

              <Show when={dialog() === "sign-out"}>
                <RunDialog
                  title={t("settings.users.sign_out.title", { name: name() })}
                  body={<p>{t("settings.users.sign_out.body", { name: name() })}</p>}
                  confirmLabel={t("settings.users.sign_out.confirm", { name: name() })}
                  danger
                  onStale={stale}
                  run={runSignOut}
                  onClose={() => setDialog(undefined)}
                />
              </Show>

              <Show when={dialog() === "break-glass"}>
                <RunDialog
                  title={
                    user().break_glass
                      ? t("settings.users.break_glass.remove_title", { name: name() })
                      : t("settings.users.break_glass.make_title", { name: name() })
                  }
                  body={
                    <>
                      <p>
                        {user().break_glass
                          ? t("settings.users.break_glass.remove_body", { name: name() })
                          : t("settings.users.break_glass.make_body")}
                      </p>
                      <Show when={!user().break_glass && user().factors.hardware_keys === 0}>
                        <Notice kind="warn">{t("settings.users.break_glass.no_key", { name: name() })}</Notice>
                      </Show>
                    </>
                  }
                  confirmLabel={
                    user().break_glass
                      ? t("settings.users.break_glass.remove_confirm", { name: name() })
                      : t("settings.users.break_glass.make_confirm", { name: name() })
                  }
                  onStale={stale}
                  run={runBreakGlass}
                  onClose={() => setDialog(undefined)}
                />
              </Show>

              <Show when={dialog() === "delete"}>
                <RunDialog
                  title={t("settings.users.delete.title", { name: name() })}
                  body={
                    <>
                      <p>{tx("settings.users.delete.body", { name: <strong>{name()}</strong> })}</p>
                      <p class="muted">{t("settings.users.delete.note")}</p>
                    </>
                  }
                  confirmLabel={t("settings.users.delete.confirm", { name: name() })}
                  danger
                  onStale={stale}
                  run={runDelete}
                  onClose={() => setDialog(undefined)}
                />
              </Show>
            </>
          );
        }}
      </Show>
    </div>
  );
}
