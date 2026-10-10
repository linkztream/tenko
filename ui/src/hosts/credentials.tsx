// The credentials of a host (IAM-16, API-11): the operator secrets bound to it, each with its
// role and user name, and "Copy password", which goes through the audited reveal dialog with
// the host in view (the Hardened profile reveals only then). Administrators bind and unbind.
// Viewers see neither secrets nor bindings: the server answers them 403, and the section
// stays empty. The list follows the `secrets` topic.
import { A } from "@solidjs/router";
import { createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery } from "../api/live";
import { errorMessage, isApiError } from "../api/problem";
import type { Host } from "../api/types";
import { isAdmin } from "../auth/session";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatRelative, t } from "../i18n";
import {
  CREDENTIAL_ROLES,
  hostCredentials,
  listSecrets,
  setHostCredentials,
  type CredentialRole,
  type HostCredentialItem,
  type HostCredentials,
  type OperatorSecret,
} from "../secrets/api";
import { secretsPath } from "../secrets/paths";
import { RevealDialog, type RevealTarget } from "../secrets/RevealDialog";

type Loaded = { state: "ok"; value: HostCredentials } | { state: "hidden" };

export function HostCredentialsSection(props: { host: Host }) {
  const live = createLiveQuery<Loaded>({
    topics: ["secrets"],
    fetch: async (signal) => {
      try {
        return { value: { state: "ok", value: await hostCredentials(props.host.id, signal) } };
      } catch (err) {
        // Viewers may not see credentials; the section shows nothing for them.
        if (isApiError(err) && err.status === 403) return { value: { state: "hidden" } };
        throw err;
      }
    },
  });
  const [reveal, setReveal] = createSignal<RevealTarget | null>(null);
  const [binding, setBinding] = createSignal(false);
  const [unbinding, setUnbinding] = createSignal<HostCredentialItem | null>(null);
  const [busy, setBusy] = createSignal(false);

  const loaded = (): HostCredentials | undefined => {
    const v = live.value.state === "ready" || live.value.state === "refreshing" ? live.value() : undefined;
    return v?.state === "ok" ? v.value : undefined;
  };
  const hidden = () => {
    const v = live.value.state === "ready" || live.value.state === "refreshing" ? live.value() : undefined;
    return v?.state === "hidden";
  };

  const unbind = async (item: HostCredentialItem) => {
    const current = loaded();
    if (!current) return;
    setBusy(true);
    try {
      await setHostCredentials(
        props.host.id,
        current.items
          .filter((other) => other.secret.id !== item.secret.id)
          .map((other) => ({ secret: other.secret.id, role: other.role })),
        current.version,
      );
      toast({ kind: "ok", title: t("hosts.credentials.unbound", { name: item.secret.name }) });
      setUnbinding(null);
      live.refetch();
    } catch (err) {
      toast({ kind: "bad", title: t("hosts.credentials.unbind_failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Show when={!hidden()}>
      <div class="host-credentials" data-testid="host-credentials">
        <h3 class="credentials-title">
          <Icon name="key" size="sm" /> {t("hosts.credentials.title")}
          <Show when={isAdmin()}>
            <button type="button" class="btn sm aside-btn" data-testid="credential-bind" onClick={() => setBinding(true)}>
              <Icon name="plus" size="sm" /> {t("hosts.credentials.bind")}
            </button>
          </Show>
        </h3>
        <Show when={live.value.error}>
          <ErrorNotice error={live.value.error} />
        </Show>
        <Show
          when={loaded()}
          fallback={
            <Show when={!live.value.error}>
              <p class="muted" role="status">
                {t("common.loading")}
              </p>
            </Show>
          }
        >
          {(credentials) => (
            <Show
              when={credentials().items.length > 0}
              fallback={
                <p class="muted" data-testid="credentials-empty">
                  {t("hosts.credentials.empty")}
                </p>
              }
            >
              <table class="plain" aria-label={t("hosts.credentials.title")}>
                <thead>
                  <tr>
                    <th scope="col">{t("hosts.credentials.col.name")}</th>
                    <th scope="col">{t("hosts.credentials.col.role")}</th>
                    <th scope="col">{t("hosts.credentials.col.user")}</th>
                    <th scope="col">{t("hosts.credentials.col.revealed")}</th>
                    <th scope="col">
                      <span class="sr-only">{t("hosts.credentials.col.actions")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <For each={credentials().items}>
                    {(item) => (
                      <tr data-testid="credential" data-id={item.secret.id} data-key={item.secret.name} data-role={item.role}>
                        <td>
                          <A href={secretsPath(item.secret.id)}>{item.secret.name}</A>
                        </td>
                        <td>{t(`hosts.credentials.role.${item.role}`)}</td>
                        <td class="mono">{item.secret.username ?? "–"}</td>
                        <td class="muted">
                          {item.secret.last_revealed
                            ? t("hosts.credentials.revealed_by", {
                                user: item.secret.last_revealed.user_name ?? "–",
                                when: formatRelative(item.secret.last_revealed.at),
                              })
                            : t("hosts.credentials.never_revealed")}
                        </td>
                        <td class="actions">
                          <button
                            type="button"
                            class="btn sm"
                            data-testid="credential-copy"
                            data-id={item.secret.id}
                            onClick={() => setReveal({ id: item.secret.id, name: item.secret.name, host: props.host.id })}
                          >
                            <Icon name="copy" size="sm" /> {t("hosts.credentials.copy")}
                          </button>
                          <Show when={isAdmin()}>
                            <button
                              type="button"
                              class="btn sm ghost"
                              data-testid="credential-unbind"
                              data-id={item.secret.id}
                              aria-label={t("hosts.credentials.unbind_label", { name: item.secret.name })}
                              onClick={() => setUnbinding(item)}
                            >
                              <Icon name="x" size="sm" />
                            </button>
                          </Show>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
              <p class="help">
                <Icon name="eye" size="xs" /> {t("hosts.credentials.audit_hint")}
              </p>
            </Show>
          )}
        </Show>
      </div>
      <Show when={reveal()}>{(target) => <RevealDialog target={target()} onClose={() => setReveal(null)} />}</Show>
      <Show when={binding() && loaded()}>
        {(current) => (
          <BindDialog
            host={props.host}
            current={current()}
            onClose={() => setBinding(false)}
            onDone={() => {
              setBinding(false);
              live.refetch();
            }}
          />
        )}
      </Show>
      <Show when={unbinding()}>
        {(item) => (
          <ConfirmDialog
            title={t("hosts.credentials.unbind_title", { name: item().secret.name })}
            body={<p>{t("hosts.credentials.unbind_body", { name: item().secret.name, host: props.host.name })}</p>}
            confirmLabel={t("hosts.credentials.unbind")}
            cancelLabel={t("common.action.cancel")}
            danger
            busy={busy()}
            onConfirm={() => void unbind(item())}
            onClose={() => setUnbinding(null)}
          />
        )}
      </Show>
    </Show>
  );
}

/** Binds an operator secret to the host with a role (administrators). */
function BindDialog(props: { host: Host; current: HostCredentials; onClose: () => void; onDone: () => void }) {
  const [secrets, setSecrets] = createSignal<OperatorSecret[] | null>(null);
  const [secret, setSecret] = createSignal("");
  const [role, setRole] = createSignal<CredentialRole>("admin");
  const [error, setError] = createSignal<unknown>(null);
  const [busy, setBusy] = createSignal(false);
  // The set of the moment the dialog opened; a change meanwhile is refused by its version.
  const bound = untrack(() => new Set(props.current.items.map((item) => item.secret.id)));

  void listSecrets()
    .then((all) => {
      const free = all.filter((s) => !bound.has(s.id));
      setSecrets(free);
      setSecret(free[0]?.id ?? "");
    })
    .catch((err: unknown) => setError(err));

  const submit = async (e: Event) => {
    e.preventDefault();
    if (!secret()) return;
    setBusy(true);
    setError(null);
    try {
      await setHostCredentials(
        props.host.id,
        [
          ...props.current.items.map((item) => ({ secret: item.secret.id, role: item.role })),
          { secret: secret(), role: role() },
        ],
        props.current.version,
      );
      toast({ kind: "ok", title: t("hosts.credentials.bound") });
      props.onDone();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("hosts.credentials.bind_title", { host: props.host.name })} onClose={props.onClose} testid="dialog-credential-bind">
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("hosts.credentials.bind_title", { host: props.host.name })}</h2>
        <div class="dialog-body">
          <ErrorNotice error={error()} />
          <Show
            when={secrets()}
            fallback={
              <p class="muted" role="status">
                {t("common.loading")}
              </p>
            }
          >
            {(list) => (
              <Show
                when={list().length > 0}
                fallback={
                  <p class="muted">
                    {t("hosts.credentials.none_free")} <A href={secretsPath()}>{t("hosts.credentials.manage")}</A>
                  </p>
                }
              >
                <div class="field">
                  <label for="bind-secret">{t("hosts.credentials.field.secret")}</label>
                  <select
                    id="bind-secret"
                    class="select"
                    data-testid="field-secret"
                    value={secret()}
                    onChange={(e) => setSecret(e.currentTarget.value)}
                  >
                    <For each={list()}>
                      {(s) => (
                        <option value={s.id}>
                          {s.username ? t("hosts.credentials.option", { name: s.name, user: s.username }) : s.name}
                        </option>
                      )}
                    </For>
                  </select>
                </div>
                <div class="field">
                  <label for="bind-role">{t("hosts.credentials.field.role")}</label>
                  <select
                    id="bind-role"
                    class="select"
                    data-testid="field-role"
                    value={role()}
                    onChange={(e) => setRole(e.currentTarget.value as CredentialRole)}
                  >
                    <For each={CREDENTIAL_ROLES}>{(r) => <option value={r}>{t(`hosts.credentials.role.${r}`)}</option>}</For>
                  </select>
                </div>
              </Show>
            )}
          </Show>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy() || !secret()}>
            {t("hosts.credentials.bind")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
