// The mirrored sources on the connectors page, beside the plugin instances (plan section 2.4):
// one card per mirror with its freshness, the counts of its latest snapshot, the server and the
// exporter's version, and its open losses. A push moves the freshness in the server's memory
// only, so the cards read the list again every few seconds instead of waiting for an event.
// Administrators create a mirror here; its token is shown once.
import { A } from "@solidjs/router";
import { createResource, createSignal, For, onCleanup, Show } from "solid-js";
import { isAdmin } from "../auth/session";
import { Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { formatDuration, formatRelative, t } from "../i18n";
import { createMirror, listMirrors, sourceList, type MirrorCreated, type MirrorItem } from "./api";
import { mirrorState, shortId } from "./model";
import { migratePaths } from "./paths";
import { TokenShown } from "./TokenShown";
import "./migrate.css";

/** How often the cards read the list again, in milliseconds. */
export const REFRESH_MS = 5_000;

export function MirrorCard(props: { mirror: MirrorItem }) {
  const m = () => props.mirror;
  const state = () => mirrorState(m());
  return (
    <article class="card mirror-card" data-testid="mirror-card" data-id={m().id} data-state={state()}>
      <header class="form-row">
        <A href={migratePaths.mirror(m().id)} class="conn-link">
          <strong>{m().name}</strong>
        </A>
        <span class="mono muted grow" title={m().id} data-testid="mirror-short-id">
          {shortId(m().id)}
        </span>
        <span class={`pill ${state() === "stale" ? "danger" : ""}`} data-testid="mirror-state">
          {t(`migrate.state.${state()}`)}
        </span>
      </header>
      <dl class="kv">
        <dt>{t("migrate.card.last_push")}</dt>
        <dd data-testid="mirror-age">
          {m().age_secs === undefined || m().age_secs === null ? t("migrate.card.never") : t("migrate.card.ago", { age: formatDuration(m().age_secs ?? 0) })}
        </dd>
        <dt>{t("migrate.card.last_change")}</dt>
        <dd>{m().last_change ? formatRelative(m().last_change ?? "") : t("migrate.card.never")}</dd>
        <dt>{t("migrate.card.sequence")}</dt>
        <dd class="mono">{m().last_sequence ?? "-"}</dd>
        <Show when={m().counts}>
          {(counts) => (
            <>
              <dt>{t("migrate.card.counts")}</dt>
              <dd>{t("migrate.card.counts_text", { scopes: counts().scopes, reservations: counts().reservations, leases: counts().leases })}</dd>
            </>
          )}
        </Show>
        <Show when={m().source}>
          {(source) => (
            <>
              <dt>{t("migrate.card.source")}</dt>
              <dd>
                <span class="mono">{source().server}</span> <span class="muted">{`${source().adapter} ${source().adapter_version}`}</span>
              </dd>
            </>
          )}
        </Show>
        <dt>{t("migrate.card.losses")}</dt>
        <dd data-testid="mirror-losses-open">{m().losses_open}</dd>
      </dl>
    </article>
  );
}

function CreateMirror(props: { onClose: () => void; onCreated: (created: MirrorCreated) => void }) {
  const [name, setName] = createSignal("");
  const [sources, setSources] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const submit = async (e: SubmitEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      props.onCreated(await createMirror(name().trim(), null, sourceList(sources())));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog label={t("migrate.create.title")} onClose={props.onClose} class="dialog" testid="dialog-mirror-create">
      <form onSubmit={(e) => void submit(e)}>
        <h2 class="dialog-title">{t("migrate.create.title")}</h2>
        <div class="dialog-body">
          <p class="muted">{t("migrate.create.body")}</p>
          <div class="field">
            <label for="mirror-name">{t("migrate.create.name")}</label>
            <input id="mirror-name" class="input" required maxLength={64} value={name()} onInput={(e) => setName(e.currentTarget.value)} data-testid="mirror-name" />
            <span class="help">{t("migrate.create.name_help")}</span>
          </div>
          <div class="field">
            <label for="mirror-sources">{t("migrate.create.sources")}</label>
            <input id="mirror-sources" class="input mono" value={sources()} onInput={(e) => setSources(e.currentTarget.value)} data-testid="mirror-sources" />
            <span class="help">{t("migrate.create.sources_help")}</span>
          </div>
          <ErrorNotice error={error()} />
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("migrate.create.cancel")}
          </button>
          <button type="submit" class="btn primary" disabled={busy() || !name().trim()} data-testid="mirror-create-submit">
            {t("migrate.create.submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function MirrorCards() {
  const [error, setError] = createSignal<unknown>(null);
  const [mirrors, { refetch }] = createResource<MirrorItem[] | undefined>(async (_, { value }) => {
    try {
      const list = await listMirrors();
      setError(null);
      return list;
    } catch (err) {
      setError(err);
      // The list read last stays: one failed poll is not "no mirrors".
      return value;
    }
  });
  const timer = setInterval(() => {
    if (!document.hidden && !mirrors.loading) void refetch();
  }, REFRESH_MS);
  onCleanup(() => clearInterval(timer));
  const [creating, setCreating] = createSignal(false);
  const [created, setCreated] = createSignal<MirrorCreated | null>(null);
  return (
    <section class="connectors-mirrors" aria-labelledby="conn-mirrors" data-testid="mirror-cards">
      <header class="form-row">
        <h2 id="conn-mirrors" class="section-title grow">
          {t("migrate.cards.title")}
        </h2>
        <Show when={isAdmin()}>
          <button type="button" class="btn" data-testid="mirror-create" onClick={() => setCreating(true)}>
            {t("migrate.create.open")}
          </button>
        </Show>
      </header>
      <ErrorNotice error={error()} />
      <Show when={(mirrors() ?? []).length > 0} fallback={<p class="muted">{t("migrate.cards.empty")}</p>}>
        <div class="mirror-cards">
          <For each={mirrors()}>{(mirror) => <MirrorCard mirror={mirror} />}</For>
        </div>
      </Show>
      <Show when={creating()}>
        <CreateMirror
          onClose={() => setCreating(false)}
          onCreated={(answer) => {
            setCreating(false);
            setCreated(answer);
            void refetch();
          }}
        />
      </Show>
      <Show when={created()}>{(answer) => <TokenShown created={answer()} onClose={() => setCreated(null)} />}</Show>
    </section>
  );
}
