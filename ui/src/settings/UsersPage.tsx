// The user list (IAM): who can sign in, with which roles and methods, and in what state.
// A row opens the user; "Add user" opens a dialog. The list follows the admin topic, so a
// lock, a sign-in or a change by another administrator shows up without a reload.
import { A, useNavigate } from "@solidjs/router";
import { createSignal, For, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { paths } from "../app/paths";
import { fetchAll } from "../api/paginate";
import type { RoleInfo, UserInfo } from "../api/types";
import { session } from "../auth/session";
import { formatDateTime, formatRelative, t } from "../i18n";
import { AddUserDialog } from "./AddUserDialog";
import { methodsText, rolesText, UserStatus } from "./userModel";
import "./settings.css";

interface UsersData {
  users: UserInfo[];
  roles: RoleInfo[];
}

export default function UsersPage() {
  const navigate = useNavigate();
  const live = createLiveQuery<UsersData>({
    topics: ["admin"],
    fetch: async (signal) => {
      const [users, roles] = await Promise.all([
        fetchAll<UserInfo>("/api/v1/users", { signal }),
        fetchAll<RoleInfo>("/api/v1/roles", { signal }),
      ]);
      return {
        value: { users: users.items, roles: roles.items },
        revision: typeof users.revision === "number" ? users.revision : undefined,
      };
    },
  });
  const [adding, setAdding] = createSignal(false);

  const data = () => (live.value.state === "ready" || live.value.state === "refreshing" ? live.value() : undefined);
  const mine = () => session()?.user.id;

  const open = (e: MouseEvent, user: UserInfo) => {
    // A click on the link or a button inside the row does its own thing.
    if ((e.target as HTMLElement).closest("a, button")) return;
    navigate(paths.user(user.id));
  };

  return (
    <div class="page-body wide">
      <Show
        when={data()}
        fallback={
          <Show
            when={live.value.error}
            fallback={
              <p class="muted" role="status">
                {t("common.loading")}
              </p>
            }
          >
            <ErrorNotice error={live.value.error} />
            <div>
              <button type="button" class="btn" onClick={() => live.refetch()}>
                {t("common.action.retry")}
              </button>
            </div>
          </Show>
        }
      >
        {(d) => (
          <section class="page-section" aria-labelledby="users-heading">
            <h2 id="users-heading">
              {t("settings.nav.users")}
              <span class="aside">{t("settings.users.count", { count: d().users.length })}</span>
            </h2>
            <div class="toolbar">
              <button type="button" class="btn primary" onClick={() => setAdding(true)}>
                {t("settings.users.add_button")}
              </button>
            </div>
            <div class="table-wrap">
              <table class="plain users" aria-label={t("settings.users.table")}>
                <thead>
                  <tr>
                    <th scope="col">{t("settings.users.col.name")}</th>
                    <th scope="col">{t("settings.users.col.display_name")}</th>
                    <th scope="col">{t("settings.users.col.roles")}</th>
                    <th scope="col">{t("settings.users.col.methods")}</th>
                    <th scope="col">{t("settings.users.col.status")}</th>
                    <th scope="col">{t("settings.users.col.last_login")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={d().users}>
                    {(user) => (
                      <tr class="clickable" data-user={user.name} onClick={(e) => open(e, user)}>
                        <td>
                          <A class="mono user-link" href={paths.user(user.id)}>
                            {user.name}
                          </A>
                          <Show when={user.id === mine()}>
                            {" "}
                            <span class="tag accent">{t("settings.users.you")}</span>
                          </Show>
                        </td>
                        <td>{user.display_name}</td>
                        <td>{rolesText(user.roles)}</td>
                        <td class="wrap">{methodsText(user.factors)}</td>
                        <td>
                          <UserStatus user={user} />
                        </td>
                        <td title={user.last_login_at ? formatDateTime(user.last_login_at) : undefined}>
                          {user.last_login_at ? formatRelative(user.last_login_at) : t("common.never")}
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
            <Show when={adding()}>
              <AddUserDialog
                roles={d().roles}
                onClose={() => setAdding(false)}
                onCreated={(user) => {
                  setAdding(false);
                  live.refetch();
                  toast({
                    kind: "ok",
                    title: t("settings.users.added", { name: user.name }),
                    actions: [{ label: t("settings.users.open"), run: () => navigate(paths.user(user.id)) }],
                  });
                }}
              />
            </Show>
          </section>
        )}
      </Show>
    </div>
  );
}
