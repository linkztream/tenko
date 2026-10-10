// The operator secrets page (IAM-15, IAM-16): the list of the secrets with their metadata, the
// detail of one (/secrets/:id), and the dialogs that create, change, reveal and delete. A
// secret is never shown here; "Reveal" goes through the audited reveal dialog. Operators and
// administrators see the list and may reveal; administrators also create, change and delete.
// Everyone else sees only a note that their role shows no secrets. The list follows the
// `secrets` topic, so a change by another administrator or a binding on a host page shows up
// without a reload.
//
// The list is read whole and filtered here (the vault holds few secrets), so the detail of
// the secret in the URL does not depend on the filter.
import { A, useNavigate, useParams } from "@solidjs/router";
import { createMemo, createSignal, For, Match, Show, Switch } from "solid-js";
import { createLiveQuery } from "../api/live";
import { errorMessage } from "../api/problem";
import { hasRole, isAdmin } from "../auth/session";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { toast } from "../components/toast";
import { formatDateTime, formatNumber, formatRelative, t } from "../i18n";
import {
  listSecrets,
  secretReferences,
  type OperatorSecret,
  type SecretKind,
  type SecretReferences,
} from "./api";
import { DeleteSecretDialog } from "./DeleteSecretDialog";
import { kindText, matchesFilter, SECRET_KINDS } from "./model";
import { Dash, LastReveal, SecretActions, TagList } from "./Parts";
import { secretsPath } from "./paths";
import { ReplaceValueDialog } from "./ReplaceValueDialog";
import { RevealDialog } from "./RevealDialog";
import { SecretDetail } from "./SecretDetail";
import { SecretFormDialog } from "./SecretForm";
import "./secrets.css";

type Dialog =
  | { kind: "create" }
  | { kind: "edit" | "replace" | "reveal"; secret: OperatorSecret }
  | { kind: "delete"; secret: OperatorSecret; references: SecretReferences };

/** Who may see the secrets at all: operators and administrators (IAM-15). */
const canSee = (): boolean => isAdmin() || hasRole("operator");

export default function SecretsPage() {
  return (
    <div class="page secrets-page" data-testid="page-secrets">
      <Show when={canSee()} fallback={<NoAccess />}>
        <SecretsList />
      </Show>
    </div>
  );
}

/** A person whose role shows no secrets: the page says so and offers nothing else. */
function NoAccess() {
  return (
    <>
      <PageHead title={t("secrets.title")} />
      <div class="page-body">
        <Notice kind="info" title={t("secrets.no_access.title")} testid="secrets-no-access">
          {t("secrets.no_access.body")}
        </Notice>
      </div>
    </>
  );
}

function SecretsList() {
  const params = useParams<{ id?: string }>();
  const navigate = useNavigate();
  const live = createLiveQuery<OperatorSecret[]>({
    topics: ["secrets"],
    fetch: async (signal) => ({ value: await listSecrets({}, signal) }),
  });
  const [text, setText] = createSignal("");
  const [kind, setKind] = createSignal<SecretKind | "">("");
  const [dialog, setDialog] = createSignal<Dialog>();
  // The secret whose references are being read for a delete.
  const [checking, setChecking] = createSignal<string>();

  const all = () => (live.value.state === "ready" || live.value.state === "refreshing" ? live.value() : undefined);
  const refreshing = () => live.value.state === "refreshing";
  const visible = createMemo(() => (all() ?? []).filter((s) => matchesFilter(s, text(), kind())));
  const filtered = () => text().trim() !== "" || kind() !== "";
  const writer = () => isAdmin();

  const dialogSecret = (which: "edit" | "replace" | "reveal"): OperatorSecret | undefined => {
    const d = dialog();
    return d && d.kind === which ? d.secret : undefined;
  };
  const deleting = () => {
    const d = dialog();
    return d?.kind === "delete" ? d : undefined;
  };
  const creating = () => dialog()?.kind === "create";
  const closeDialog = () => setDialog(undefined);

  const askDelete = async (secret: OperatorSecret) => {
    if (checking()) return;
    setChecking(secret.id);
    try {
      setDialog({ kind: "delete", secret, references: await secretReferences(secret.id) });
    } catch (err) {
      toast({ kind: "bad", title: t("secrets.delete.check_failed"), body: errorMessage(err) });
    } finally {
      setChecking(undefined);
    }
  };

  const actions = {
    onReveal: (secret: OperatorSecret) => setDialog({ kind: "reveal", secret }),
    onEdit: (secret: OperatorSecret) => setDialog({ kind: "edit", secret }),
    onReplace: (secret: OperatorSecret) => setDialog({ kind: "replace", secret }),
    onDelete: (secret: OperatorSecret) => void askDelete(secret),
  };

  const open = (e: MouseEvent, secret: OperatorSecret) => {
    // A click on the link or a button inside the row does its own thing.
    if ((e.target as HTMLElement).closest("a, button")) return;
    navigate(secretsPath(secret.id));
  };

  const countText = () => {
    const list = all();
    if (!list) return undefined;
    return filtered() && visible().length !== list.length
      ? t("secrets.count_filtered", { shown: visible().length, total: list.length })
      : t("secrets.count", { count: list.length });
  };

  return (
    <>
      <PageHead title={t("secrets.title")} sub={countText()} />
      <div class="filterbar" role="toolbar" aria-label={t("secrets.filter.label")} data-testid="filterbar">
        <label class="query">
          <Icon name="search" size="sm" />
          <input
            value={text()}
            placeholder={t("secrets.filter.placeholder")}
            aria-label={t("secrets.filter.label")}
            spellcheck={false}
            autocomplete="off"
            data-testid="filter-input"
            onInput={(e) => setText(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape" && text() !== "") {
                e.preventDefault();
                e.stopPropagation();
                setText("");
              }
            }}
          />
        </label>
        <select
          class="select"
          aria-label={t("secrets.filter.kind")}
          data-testid="field-kind-filter"
          onChange={(e) => setKind(e.currentTarget.value as SecretKind | "")}
        >
          <option value="" selected={kind() === ""}>
            {t("secrets.filter.kind_all")}
          </option>
          <For each={SECRET_KINDS}>
            {(k) => (
              <option value={k} selected={kind() === k}>
                {kindText(k)}
              </option>
            )}
          </For>
        </select>
        <Show when={writer()}>
          <div class="right">
            <button type="button" class="btn primary" data-testid="secrets-create" onClick={() => setDialog({ kind: "create" })}>
              <Icon name="plus" size="sm" /> {t("secrets.action.create")}
            </button>
          </div>
        </Show>
      </div>

      <div class="page-body wide">
        <Show
          when={all()}
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
          {(list) => (
            <div class="secrets-split">
              <section class="secrets-list" aria-label={t("secrets.title")}>
                <Show
                  when={visible().length > 0}
                  fallback={
                    <p class="muted" data-testid="secrets-empty">
                      {list().length === 0
                        ? writer()
                          ? t("secrets.empty_admin")
                          : t("secrets.empty")
                        : t("secrets.no_match")}
                    </p>
                  }
                >
                  <div class="table-wrap">
                    <table class="plain secrets-table" aria-label={t("secrets.title")}>
                      <thead>
                        <tr>
                          <th scope="col">{t("secrets.col.name")}</th>
                          <th scope="col">{t("secrets.col.kind")}</th>
                          <th scope="col">{t("secrets.col.user")}</th>
                          <th scope="col">{t("secrets.col.tags")}</th>
                          <th scope="col" class="r">
                            {t("secrets.col.hosts")}
                          </th>
                          <th scope="col">{t("secrets.col.revealed")}</th>
                          <th scope="col">{t("secrets.col.updated")}</th>
                          <th scope="col" class="r">
                            <span class="sr-only">{t("secrets.col.actions")}</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={visible()}>
                          {(secret) => (
                            <tr
                              class="secret-row"
                              classList={{ selected: secret.id === params.id }}
                              aria-current={secret.id === params.id ? "true" : undefined}
                              data-testid="secret"
                              data-id={secret.id}
                              data-key={secret.name}
                              onClick={(e) => open(e, secret)}
                            >
                              <td>
                                <A class="secret-link" href={secretsPath(secret.id)}>
                                  {secret.name}
                                </A>
                              </td>
                              <td>{kindText(secret.kind)}</td>
                              <td class="mono">
                                <Show when={secret.username} fallback={<Dash label={t("secrets.no_user")} />}>
                                  {(name) => name()}
                                </Show>
                              </td>
                              <td>
                                <TagList tags={secret.tags} />
                              </td>
                              <td class="num r">{formatNumber(secret.hosts.length)}</td>
                              <td>
                                <LastReveal secret={secret} />
                              </td>
                              <td class="num" title={formatDateTime(secret.updated_at)}>
                                {formatRelative(secret.updated_at)}
                              </td>
                              <td class="r">
                                <SecretActions
                                  secret={secret}
                                  canWrite={writer()}
                                  checking={checking() !== undefined}
                                  {...actions}
                                />
                              </td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </div>
                </Show>
              </section>

              <Show when={params.id} keyed>
                {(id) => {
                  const secret = () => list().find((s) => s.id === id);
                  return (
                    <Show
                      when={secret()}
                      fallback={
                        <Show
                          when={!refreshing()}
                          fallback={
                            <p class="muted" role="status">
                              {t("common.loading")}
                            </p>
                          }
                        >
                          <div class="secret-missing" data-testid="secret-missing">
                            <Notice kind="bad" role="alert">
                              {t("errors.vault.secret.not_found")}
                            </Notice>
                            <A class="btn" href={secretsPath()}>
                              {t("secrets.detail.back")}
                            </A>
                          </div>
                        </Show>
                      }
                    >
                      {(current) => (
                        <SecretDetail secret={current()} canWrite={writer()} checking={checking() !== undefined} {...actions} />
                      )}
                    </Show>
                  );
                }}
              </Show>
            </div>
          )}
        </Show>
      </div>

      <Switch>
        <Match when={creating()}>
          <SecretFormDialog
            onClose={closeDialog}
            onSaved={(secret) => {
              closeDialog();
              live.refetch();
              toast({ kind: "ok", title: t("secrets.created", { name: secret.name }) });
              navigate(secretsPath(secret.id));
            }}
          />
        </Match>
        <Match when={dialogSecret("edit")}>
          {(secret) => (
            <SecretFormDialog
              secret={secret()}
              onClose={closeDialog}
              onReloaded={() => live.refetch()}
              onSaved={(saved) => {
                closeDialog();
                live.refetch();
                toast({ kind: "ok", title: t("secrets.saved", { name: saved.name }) });
              }}
            />
          )}
        </Match>
        <Match when={dialogSecret("replace")}>
          {(secret) => (
            <ReplaceValueDialog
              secret={secret()}
              onClose={closeDialog}
              onReloaded={() => live.refetch()}
              onSaved={(saved) => {
                closeDialog();
                live.refetch();
                toast({ kind: "ok", title: t("secrets.replaced", { name: saved.name }) });
              }}
            />
          )}
        </Match>
        <Match when={dialogSecret("reveal")}>
          {(secret) => (
            <RevealDialog
              target={{ id: secret().id, name: secret().name }}
              onClose={() => {
                closeDialog();
                // The reveal stamps the secret; the list shows it without waiting for the event.
                live.refetch();
              }}
            />
          )}
        </Match>
        <Match when={deleting()}>
          {(target) => (
            <DeleteSecretDialog
              secret={target().secret}
              references={target().references}
              onClose={closeDialog}
              onReloaded={() => live.refetch()}
              onDeleted={() => {
                const gone = target().secret;
                closeDialog();
                live.refetch();
                toast({ kind: "ok", title: t("secrets.deleted", { name: gone.name }) });
                if (params.id === gone.id) navigate(secretsPath());
              }}
            />
          )}
        </Match>
      </Switch>
    </>
  );
}
