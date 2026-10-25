// The roles of one node (docs/cluster.md, "Changing a node's roles"; OPS-01): the four roles as
// switches, the roles it runs now, the pin of `--roles` read-only, the findings of the server
// (a drop-in the node lacks, the host's resolver pointing at a node that leaves the dns role)
// and, after a change, the node followed through its restart until it is back. A change asks
// first, because the node restarts to apply it. A node that is gone shows nothing here: the
// view around the editor says so.
import { createEffect, createResource, createSignal, For, onCleanup, Show, type JSX } from "solid-js";
import { getNodeRoles, putNodeRoles, type NodeRoles } from "../api/nodes";
import { ApiError, errorMessage } from "../api/problem";
import { isAdmin } from "../auth/session";
import { ConfirmDialog } from "../components/Dialog";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatList, t } from "../i18n";
import { roleWord } from "./model";
import { canonical, changeOf, findingText, lockOf, nextPhase, preparationOf, ROLES, sameRoles, unpreparedOn, type RestartPhase, type RolePreparation, type RoleName } from "./roles";

/** How often a restarting node is asked for its roles. */
const POLL_MS = 1_500;
/** How long the editor follows a restart before it says the node is late. */
const DEADLINE_MS = 180_000;

function words(roles: readonly string[]): string {
  return roles.length === 0 ? "–" : formatList(roles.map(roleWord));
}

/** The warning for a role the draft switches on and the machine is not prepared for. */
function UnpreparedNotice(props: { item: RolePreparation }) {
  return (
    <Notice kind="warn" testid="node-roles-unprepared">
      <span data-role={props.item.role}>
        {t("nodes.roles.unprepared", { role: roleWord(props.item.role), missing: formatList(props.item.missing ?? []) })}
        <Show when={props.item.command}>
          {(command) => (
            <>
              {" "}
              <code data-testid="node-roles-unprepared-command">{command()}</code>
            </>
          )}
        </Show>
      </span>
    </Notice>
  );
}

export function RolesEditor(props: {
  id: number | string;
  /** Without its own heading and region, inside a section that names it. */
  bare?: boolean;
  pollMs?: number;
  deadlineMs?: number;
  /** The roles of the node each time they are read or saved, for the view around the editor. */
  onRoles?: (roles: NodeRoles) => void;
}) {
  const [roles, { refetch, mutate }] = createResource(
    () => String(props.id),
    (id) => getNodeRoles(id),
  );
  const current = () => (roles.error ? undefined : roles.latest);
  const gone = () => roles.error instanceof ApiError && roles.error.code === "cluster.node.not_found";
  createEffect(() => {
    const known = current();
    if (known) props.onRoles?.(known);
  });
  const [draft, setDraft] = createSignal<RoleName[] | null>(null);
  const selected = (): RoleName[] => draft() ?? canonical(current()?.configured ?? []);
  const dirty = () => {
    const d = draft();
    const c = current();
    return d !== null && c !== undefined && !sameRoles(d, c.configured);
  };
  const [confirming, setConfirming] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [failed, setFailed] = createSignal<unknown>();
  const [saved, setSaved] = createSignal<NodeRoles | null>(null);
  const [phase, setPhase] = createSignal<RestartPhase | null>(null);
  const editable = () => isAdmin() && current() !== undefined && !current()?.pinned;
  const unprepared = () => {
    const c = current();
    return c ? unpreparedOn(selected(), c.configured, c.prepared) : [];
  };
  const findings = () => saved()?.findings ?? current()?.findings ?? [];

  let timer: ReturnType<typeof setTimeout> | undefined;
  onCleanup(() => clearTimeout(timer));

  /** Asks the node for its roles until it runs `wanted` or the deadline passes. */
  const follow = (wanted: readonly string[]) => {
    const deadline = Date.now() + (props.deadlineMs ?? DEADLINE_MS);
    setPhase("waiting");
    const poll = async () => {
      let answer: NodeRoles | undefined;
      try {
        answer = await getNodeRoles(props.id);
      } catch {
        answer = undefined;
      }
      const next = nextPhase(phase() ?? "waiting", wanted, answer, Date.now() > deadline);
      setPhase(next);
      if (next === "back" && answer) {
        mutate(answer);
        setSaved(null);
        return;
      }
      if (next !== "late") timer = setTimeout(() => void poll(), props.pollMs ?? POLL_MS);
    };
    timer = setTimeout(() => void poll(), props.pollMs ?? POLL_MS);
  };

  const toggle = (role: RoleName, on: boolean) => {
    const next = on ? [...selected(), role] : selected().filter((r) => r !== role);
    setDraft(canonical(next));
    setSaved(null);
  };

  const save = async () => {
    const c = current();
    if (!c) return;
    setBusy(true);
    setFailed(undefined);
    try {
      const answer = await putNodeRoles(props.id, selected(), c.revision);
      setConfirming(false);
      setDraft(null);
      setSaved(answer);
      mutate(answer);
      toast({ kind: "ok", title: t("nodes.roles.saved") });
      if (answer.restart === "scheduled") follow(answer.configured);
    } catch (err) {
      setConfirming(false);
      setFailed(err);
      toast({
        kind: "bad",
        title: t("nodes.roles.save_failed"),
        body: errorMessage(err),
      });
    } finally {
      setBusy(false);
    }
  };

  const restartWord = (p: RestartPhase) =>
    p === "back"
      ? t("nodes.roles.restart.back", {
          roles: words(current()?.running ?? []),
        })
      : t(`nodes.roles.restart.${p}`);

  const frame = (body: JSX.Element) =>
    props.bare ? (
      <div class="node-roles" data-testid="node-roles" data-id={String(props.id)}>
        {body}
      </div>
    ) : (
      <section class="section node-roles" aria-labelledby={`node-roles-${props.id}`} data-testid="node-roles" data-id={String(props.id)}>
        <h3 id={`node-roles-${props.id}`}>{t("nodes.roles.title")}</h3>
        {body}
      </section>
    );

  return (
    <Show when={!gone()}>
      {frame(
        <>
          <Show when={roles.error}>
            <ErrorNotice error={roles.error} />
          </Show>
          <Show
            when={current()}
            fallback={
              <Show when={!roles.error}>
                <p class="muted" role="status">
                  {t("common.loading")}
                </p>
              </Show>
            }
          >
            {(c) => (
              <div class="nodes-form">
                <Show when={c().pinned}>
                  <Notice kind="info" testid="node-roles-pinned">
                    {t("nodes.roles.pinned", {
                      roles: (c().running ?? c().configured).join(","),
                    })}
                  </Notice>
                </Show>
                <fieldset class="nodes-fieldset" disabled={!editable() || busy() || phase() === "waiting" || phase() === "down"}>
                  <legend class="sr-only">{t("nodes.roles.legend")}</legend>
                  <For each={ROLES}>
                    {(role) => {
                      const lock = () => lockOf(role, c());
                      return (
                        <label class="check-row" data-locked={lock() ?? ""}>
                          <input
                            type="checkbox"
                            class="cb"
                            checked={selected().includes(role)}
                            disabled={lock() !== undefined}
                            data-testid={`node-role-${role}`}
                            onChange={(e) => toggle(role, e.currentTarget.checked)}
                          />
                          <span>
                            <span class="node-role-name">
                              {roleWord(role)}
                              <Show when={preparationOf(role, c().prepared)}>
                                {(p) => (
                                  <span
                                    class={`tag ${p().prepared ? "ok" : "discrepancy"}`}
                                    data-testid={`node-role-prepared-${role}`}
                                    data-state={p().prepared ? "prepared" : "unprepared"}
                                  >
                                    {p().prepared ? t("nodes.roles.prepared.yes") : t("nodes.roles.prepared.no")}
                                  </span>
                                )}
                              </Show>
                            </span>
                            <small class="help">{lock() ? t(`nodes.roles.lock.${lock()!}`) : t(`nodes.roles.hint.${role}`)}</small>
                          </span>
                        </label>
                      );
                    }}
                  </For>
                </fieldset>
                <For each={unprepared()}>{(item) => <UnpreparedNotice item={item} />}</For>
                <Show when={c().running}>
                  {(running) => (
                    <p class="muted" data-testid="node-roles-running">
                      {t("nodes.roles.running", { roles: words(running()) })}
                    </p>
                  )}
                </Show>
                <For each={findings()}>
                  {(finding) => (
                    <Notice kind="warn" testid="node-roles-finding" code={finding.code}>
                      {findingText(finding)}
                    </Notice>
                  )}
                </For>
                <Show when={phase()}>
                  {(p) => (
                    <Notice kind={p() === "back" ? "ok" : p() === "late" ? "warn" : "info"} role="status" testid="node-roles-restart">
                      <span data-phase={p()}>{restartWord(p())}</span>
                    </Notice>
                  )}
                </Show>
                <Show when={saved()?.restart === "required"}>
                  <Notice kind="warn" testid="node-roles-restart-required">
                    {t("nodes.roles.restart.required")}
                  </Notice>
                </Show>
                <Show when={saved()?.restart === "on_node"}>
                  <Notice kind="info" testid="node-roles-on-node">
                    {t("nodes.roles.restart.on_node")}
                  </Notice>
                </Show>
                <ErrorNotice error={failed()} />
                <Show when={editable()}>
                  <div class="row-actions">
                    <button type="button" class="btn primary" data-testid="node-roles-save" disabled={!dirty() || busy()} onClick={() => setConfirming(true)}>
                      {t("nodes.roles.save")}
                    </button>
                    <Show when={dirty()}>
                      <button type="button" class="btn" data-testid="node-roles-reset" onClick={() => setDraft(null)}>
                        {t("nodes.roles.reset")}
                      </button>
                    </Show>
                  </div>
                </Show>
                <Show when={confirming()}>
                  <ConfirmDialog
                    title={t("nodes.roles.confirm_title")}
                    testid="node-roles-confirm"
                    body={
                      <>
                        <Show when={changeOf(c().configured, selected()).on.length > 0}>
                          <p>
                            {t("nodes.roles.confirm_on", {
                              roles: words(changeOf(c().configured, selected()).on),
                            })}
                          </p>
                        </Show>
                        <Show when={changeOf(c().configured, selected()).off.length > 0}>
                          <p>
                            {t("nodes.roles.confirm_off", {
                              roles: words(changeOf(c().configured, selected()).off),
                            })}
                          </p>
                        </Show>
                        <For each={unprepared()}>{(item) => <UnpreparedNotice item={item} />}</For>
                        <p>{c().running ? t("nodes.roles.confirm_restart") : t("nodes.roles.confirm_on_node")}</p>
                      </>
                    }
                    confirmLabel={t("nodes.roles.confirm")}
                    cancelLabel={t("common.action.cancel")}
                    busy={busy()}
                    onClose={() => setConfirming(false)}
                    onConfirm={() => void save()}
                  />
                </Show>
              </div>
            )}
          </Show>
          <Show when={roles.error}>
            <button type="button" class="btn" onClick={() => void refetch()}>
              {t("common.action.retry")}
            </button>
          </Show>
        </>,
      )}
    </Show>
  );
}
