// The three tabs of a mirror's page (plan section 3.3): the diff of a mirrored scope, the loss
// report with its acknowledgment, and the settings with the token, the commands and deletion.
// Every text of the source (names, details, values) is shown as text, never as markup.
import { createResource, createSignal, For, Show, untrack } from "solid-js";
import { copyText } from "../auth/account/shared";
import { isAdmin } from "../auth/session";
import { ConfirmDialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { t } from "../i18n";
import { ackLosses, deleteMirror, getDiff, getLosses, replaceMirrorToken, updateMirror, type MirrorCreated, type MirrorItem } from "./api";
import { installCommands } from "./model";
import { TokenShown } from "./TokenShown";

/** Runs an action, keeping its error for the tab's notice. */
function useAction() {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const run = async (work: () => Promise<unknown>, done?: () => void) => {
    setBusy(true);
    setError(null);
    try {
      await work();
      done?.();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run };
}

export function ScopesTab(props: { mirror: MirrorItem }) {
  const [chosen, setChosen] = createSignal<string | null>(untrack(() => props.mirror.scopes?.[0]?.cidr) ?? null);
  const [diff] = createResource(chosen, (cidr) => getDiff(props.mirror.id, cidr));
  return (
    <section class="mirror-scopes" data-testid="mirror-scopes">
      <Show when={(props.mirror.scopes ?? []).length > 0} fallback={<p class="muted">{t("migrate.scopes.none")}</p>}>
        <div class="form-row" role="group" aria-label={t("migrate.scopes.choose")}>
          <For each={props.mirror.scopes ?? []}>
            {(scope) => (
              <button type="button" class="btn" aria-pressed={chosen() === scope.cidr} data-testid="mirror-scope" onClick={() => setChosen(scope.cidr)}>
                <span class="mono">{scope.cidr}</span> {scope.name ?? ""} <span class="muted">{t(scope.active ? "migrate.scopes.active" : "migrate.scopes.inactive")}</span>
              </button>
            )}
          </For>
        </div>
      </Show>
      <ErrorNotice error={diff.error} />
      <Show when={diff.latest}>
        {(d) => (
          <>
            <p data-testid="mirror-diff-summary">
              {t("migrate.diff.summary", {
                source: t(d().source_active ? "migrate.scopes.active" : "migrate.scopes.inactive"),
                tenko: t(d().tenko_scope ? (d().tenko_enabled ? "migrate.diff.enabled" : "migrate.diff.disabled") : "migrate.diff.missing"),
                losses: d().losses_open,
              })}
            </p>
            <Show when={d().rows.length > 0} fallback={<p data-testid="mirror-diff-empty">{t("migrate.diff.empty")}</p>}>
              <div class="table-wrap">
                <table class="plain" data-testid="mirror-diff">
                  <thead>
                    <tr>
                      <th>{t("migrate.diff.col.kind")}</th>
                      <th>{t("migrate.diff.col.item")}</th>
                      <th>{t("migrate.diff.col.mirror")}</th>
                      <th>{t("migrate.diff.col.tenko")}</th>
                      <th>{t("migrate.diff.col.action")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={d().rows}>
                      {(row) => (
                        <tr data-kind={row.kind} data-action={row.action}>
                          <td>{t(`migrate.diff.kind.${row.kind}`)}</td>
                          <td class="mono">{row.item}</td>
                          <td class="mono">{row.mirror ?? ""}</td>
                          <td class="mono">{row.tenko ?? ""}</td>
                          <td title={row.reason ?? undefined}>{t(`migrate.diff.action.${row.action}`)}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}

export function LossesTab(props: { mirror: MirrorItem; onChange: () => void }) {
  const [losses, { refetch }] = createResource(() => props.mirror.id, (id) => getLosses(id));
  const [picked, setPicked] = createSignal<ReadonlySet<string>>(new Set());
  const action = useAction();
  const toggle = (key: string, on: boolean) => {
    const next = new Set(picked());
    if (on) next.add(key);
    else next.delete(key);
    setPicked(next);
  };
  const acknowledge = () =>
    action.run(
      // eslint-disable-next-line solid/reactivity -- an action of a click, like an event handler
      () => ackLosses(props.mirror.id, losses.latest?.sequence ?? 0, [...picked()]),
      // eslint-disable-next-line solid/reactivity -- an action of a click, like an event handler
      () => {
        setPicked(new Set<string>());
        void refetch();
        props.onChange();
      },
    );
  return (
    <section class="mirror-losses" data-testid="mirror-losses">
      <ErrorNotice error={losses.error ?? action.error()} />
      <Show when={losses.latest}>
        {(report) => (
          <Show when={report().entries.length > 0} fallback={<p class="muted">{t("migrate.losses.none")}</p>}>
            <div class="table-wrap">
              <table class="plain">
                <thead>
                  <tr>
                    <th>
                      <span class="sr-only">{t("migrate.losses.col.pick")}</span>
                    </th>
                    <th>{t("migrate.losses.col.where")}</th>
                    <th>{t("migrate.losses.col.code")}</th>
                    <th>{t("migrate.losses.col.detail")}</th>
                    <th>{t("migrate.losses.col.scope")}</th>
                    <th>{t("migrate.losses.col.ack")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={report().entries}>
                    {(item) => (
                      <tr data-testid="mirror-loss" data-acked={item.ack ? "true" : "false"}>
                        <td>
                          <input
                            type="checkbox"
                            aria-label={t("migrate.losses.pick", { key: item.key })}
                            disabled={!isAdmin() || !!item.ack}
                            checked={picked().has(item.key)}
                            onChange={(e) => toggle(item.key, e.currentTarget.checked)}
                          />
                        </td>
                        <td class="mono">{`${item.entry.location.sheet ?? ""} ${item.entry.location.column ?? ""}`}</td>
                        <td class="mono">{item.entry.code}</td>
                        <td>{item.entry.detail}</td>
                        <td class="mono">{item.scope ?? t("migrate.losses.every_scope")}</td>
                        <td>{item.ack ? t("migrate.losses.acked") : t("migrate.losses.open")}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
            <Show when={isAdmin()}>
              <div class="form-row">
                <button type="button" class="btn primary" data-testid="mirror-ack" disabled={action.busy() || picked().size === 0} onClick={() => void acknowledge()}>
                  {t("migrate.losses.ack", { count: picked().size })}
                </button>
              </div>
            </Show>
          </Show>
        )}
      </Show>
    </section>
  );
}

export function SettingsTab(props: { mirror: MirrorItem; onChange: () => void; onDeleted: () => void }) {
  const [name, setName] = createSignal(untrack(() => props.mirror.name));
  const [interval, setIntervalSecs] = createSignal(untrack(() => props.mirror.interval_secs) ?? 60);
  const [deleting, setDeleting] = createSignal(false);
  const [created, setCreated] = createSignal<MirrorCreated | null>(null);
  const action = useAction();
  const commands = () => installCommands(props.mirror, window.location.origin);
  // eslint-disable-next-line solid/reactivity -- an action of a click, like an event handler
  const save = (change: { name?: string; enabled?: boolean; interval_secs?: number }) => action.run(() => updateMirror(props.mirror.id, change), props.onChange);
  // eslint-disable-next-line solid/reactivity -- an action of a click, like an event handler
  const replaceToken = () => action.run(async () => setCreated(await replaceMirrorToken(props.mirror.id)), props.onChange);
  return (
    <section class="mirror-settings" data-testid="mirror-settings">
      <ErrorNotice error={action.error()} />
      <form
        class="form-row"
        onSubmit={(e) => {
          e.preventDefault();
          void save({ name: name().trim(), interval_secs: interval() });
        }}
      >
        <div class="field">
          <label for="mirror-settings-name">{t("migrate.create.name")}</label>
          <input id="mirror-settings-name" class="input" required disabled={!isAdmin()} value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        </div>
        <div class="field">
          <label for="mirror-settings-interval">{t("migrate.settings.interval")}</label>
          <input
            id="mirror-settings-interval"
            class="input"
            type="number"
            min={10}
            max={3600}
            disabled={!isAdmin()}
            value={interval()}
            onInput={(e) => setIntervalSecs(e.currentTarget.valueAsNumber)}
          />
        </div>
        <Show when={isAdmin()}>
          <button type="submit" class="btn" disabled={action.busy()} data-testid="mirror-save">
            {t("migrate.settings.save")}
          </button>
          <button type="button" class="btn" disabled={action.busy()} data-testid="mirror-enabled" onClick={() => void save({ enabled: !props.mirror.enabled })}>
            {t(props.mirror.enabled ? "migrate.settings.disable" : "migrate.settings.enable")}
          </button>
        </Show>
      </form>
      <h3 class="section-title">{t("migrate.settings.commands")}</h3>
      <p class="muted">{t("migrate.settings.commands_help")}</p>
      <For each={commands()}>
        {(command) => (
          <div class="form-row">
            <code class="mono grow" data-testid="mirror-command">
              {command}
            </code>
            <button type="button" class="btn ghost" onClick={() => void copyText(command)}>
              {t("migrate.settings.copy")}
            </button>
          </div>
        )}
      </For>
      <Show when={isAdmin()}>
        <div class="form-row">
          <button type="button" class="btn" disabled={action.busy()} data-testid="mirror-token-replace" onClick={() => void replaceToken()}>
            {t("migrate.settings.token")}
          </button>
          <button type="button" class="btn danger" data-testid="mirror-delete" onClick={() => setDeleting(true)}>
            {t("migrate.settings.delete")}
          </button>
        </div>
      </Show>
      <Show when={created()}>{(answer) => <TokenShown created={answer()} onClose={() => setCreated(null)} />}</Show>
      <Show when={deleting()}>
        <ConfirmDialog
          title={t("migrate.delete.title", { name: props.mirror.name })}
          body={<p>{t("migrate.delete.body")}</p>}
          confirmLabel={t("migrate.settings.delete")}
          cancelLabel={t("migrate.create.cancel")}
          danger
          busy={action.busy()}
          onClose={() => setDeleting(false)}
          // eslint-disable-next-line solid/reactivity -- an action of a click, like an event handler
          onConfirm={() => void action.run(() => deleteMirror(props.mirror.id), props.onDeleted)}
        />
      </Show>
    </section>
  );
}
