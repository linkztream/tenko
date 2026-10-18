// The cache section of the DNS settings page: what the node's cache holds, as the cache view of
// Windows DNS and `rndc dumpdb -cache` show it. Nothing is read until the administrator asks,
// since every page read is audited (`dns.cache.read`): the entries are the names the clients
// asked. A suffix narrows the listing to a name and the names under it; the table shows the
// name, type, the time the entry stays fresh, its view, the stale flag, its hits and the data;
// pages follow the cursor of the server. With a suffix applied, "flush" empties those entries
// through the node command `dns.cache.flush`, after a confirmation.
import { createResource, createSignal, For, Show } from "solid-js";
import { errorMessage } from "../../api/problem";
import { ConfirmDialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatNumber, t } from "../../i18n";
import { cacheSuffix, entryData, flushCache, listCache, ttlLeft, type DnsCacheEntry } from "./cache";

function Ttl(props: { entry: DnsCacheEntry }) {
  const left = () => ttlLeft(props.entry.ttl);
  return (
    <Show when={!props.entry.stale} fallback={<span class="muted">{t("dns.cache.ttl_none")}</span>}>
      {t(`dns.cache.ttl_${left().unit}`, { value: formatNumber(left().value) })}
    </Show>
  );
}

function Entries(props: { entries: DnsCacheEntry[] }) {
  return (
    <div class="table-wrap">
      <table class="plain dns-cache-table" data-testid="dns-cache-table">
        <caption class="sr-only">{t("dns.cache.title")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("dns.cache.col.name")}</th>
            <th scope="col">{t("dns.cache.col.type")}</th>
            <th scope="col">{t("dns.cache.col.ttl")}</th>
            <th scope="col">{t("dns.cache.col.view")}</th>
            <th scope="col">{t("dns.cache.col.stale")}</th>
            <th scope="col" class="r">
              {t("dns.cache.col.hits")}
            </th>
            <th scope="col">{t("dns.cache.col.data")}</th>
          </tr>
        </thead>
        <tbody>
          <For each={props.entries}>
            {(entry, index) => (
              <tr data-testid="dns-cache-row" data-index={index()} data-key={entry.name} data-type={entry.type} data-stale={String(entry.stale)}>
                <td class="mono">{entry.name}</td>
                <td class="mono">{entry.type}</td>
                <td class="nowrap">
                  <Ttl entry={entry} />
                </td>
                <td>
                  <Show when={entry.view} fallback={<span class="muted">{t("dns.cache.view_default")}</span>}>
                    {(view) => <span class="mono">{view()}</span>}
                  </Show>
                </td>
                <td>
                  <Show when={entry.stale}>
                    <span class="tag discrepancy" data-testid="dns-cache-stale" title={t("dns.cache.stale_hint")}>
                      {t("dns.cache.stale")}
                    </span>
                  </Show>
                </td>
                <td class="r">{formatNumber(entry.hits)}</td>
                <td class="mono dns-cache-data" data-testid="dns-cache-data">
                  {entryData(entry)}
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}

export function CacheSection(props: { node: number }) {
  const [typed, setTyped] = createSignal("");
  const [invalid, setInvalid] = createSignal(false);
  // The suffix of the pages shown, and the cursors from the first page to the one shown;
  // undefined until the administrator asks.
  const [shown, setShown] = createSignal<{ suffix: string; cursors: (string | undefined)[]; tick: number }>();
  const [confirming, setConfirming] = createSignal(false);
  const [busy, setBusy] = createSignal(false);

  const request = () => {
    const current = shown();
    if (!current) return undefined;
    return { suffix: current.suffix, cursor: current.cursors[current.cursors.length - 1], tick: current.tick };
  };
  const [page] = createResource(request, (r) => listCache(props.node, r.suffix, r.cursor));

  const show = (event: Event) => {
    event.preventDefault();
    const suffix = cacheSuffix(typed());
    setInvalid(suffix === null);
    if (suffix === null) return;
    setShown({ suffix, cursors: [undefined], tick: (shown()?.tick ?? 0) + 1 });
  };
  const move = (cursors: (string | undefined)[]) => {
    const current = shown();
    if (current) setShown({ ...current, cursors });
  };
  const next = () => {
    const cursor = page.latest?.next;
    const current = shown();
    if (cursor && current) move([...current.cursors, cursor]);
  };
  const previous = () => move(shown()?.cursors.slice(0, -1) ?? [undefined]);
  const suffix = () => shown()?.suffix ?? "";

  const flush = async () => {
    const current = shown();
    if (!current || busy()) return;
    setBusy(true);
    try {
      await flushCache(props.node, current.suffix);
      toast({ kind: "ok", title: t("dns.cache.flushed", { suffix: current.suffix }) });
      setConfirming(false);
      setShown({ ...current, cursors: [undefined], tick: current.tick + 1 });
    } catch (err) {
      toast({ kind: "bad", title: t("dns.cache.flush_failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page-section dns-set-group" data-testid="dns-cache">
      <h2>{t("dns.cache.title")}</h2>
      <p class="muted dns-set-doc" data-testid="dns-cache-audit-note">
        {t("dns.cache.lede")}
      </p>
      <form class="dns-cache-form" data-testid="dns-cache-form" onSubmit={show} novalidate>
        <div class="field">
          <label for="dns-cache-suffix">{t("dns.cache.suffix")}</label>
          <input
            id="dns-cache-suffix"
            class="input mono"
            value={typed()}
            placeholder={t("dns.cache.suffix_placeholder")}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={invalid() ? "true" : undefined}
            data-testid="field-cache-suffix"
            onInput={(event) => setTyped(event.currentTarget.value)}
          />
          <Show when={invalid()}>
            <span class="help bad" data-testid="field-error" data-field="suffix">
              {t("dns.cache.suffix_invalid")}
            </span>
          </Show>
        </div>
        <div class="dns-cache-actions">
          <button type="submit" class="btn primary" data-testid="dns-cache-show">
            {shown() ? t("dns.cache.reload") : t("dns.cache.show")}
          </button>
          <Show when={suffix()}>
            <button type="button" class="btn" data-testid="dns-cache-flush" disabled={busy()} onClick={() => setConfirming(true)}>
              {t("dns.cache.flush", { suffix: suffix() })}
            </button>
          </Show>
        </div>
      </form>
      <Show when={page.error}>
        <ErrorNotice error={page.error} />
      </Show>
      <Show when={shown() && !page.error && page.latest}>
        {(current) => (
          <>
            <Show
              when={current().items.length > 0}
              fallback={
                <div class="empty" data-testid="dns-cache-empty">
                  <h3>{suffix() ? t("dns.cache.empty_suffix", { suffix: suffix() }) : t("dns.cache.empty")}</h3>
                </div>
              }
            >
              <Entries entries={current().items} />
            </Show>
            <div class="dns-cache-paging" data-testid="dns-cache-paging" data-page={shown()?.cursors.length}>
              <button type="button" class="btn" data-testid="dns-cache-previous" disabled={(shown()?.cursors.length ?? 1) <= 1 || page.loading} onClick={previous}>
                {t("dns.cache.previous")}
              </button>
              <span class="muted">{t("dns.cache.page", { page: shown()?.cursors.length ?? 1 })}</span>
              <button type="button" class="btn" data-testid="dns-cache-next" disabled={!current().next || page.loading} onClick={next}>
                {t("dns.cache.next")}
              </button>
            </div>
          </>
        )}
      </Show>
      <Show when={confirming()}>
        <ConfirmDialog
          testid="dns-cache-flush-dialog"
          title={t("dns.cache.flush_title", { suffix: suffix() })}
          body={<p>{t("dns.cache.flush_body", { suffix: suffix() })}</p>}
          confirmLabel={t("dns.cache.flush_confirm")}
          cancelLabel={t("dns.cache.flush_cancel")}
          danger
          busy={busy()}
          onConfirm={() => void flush()}
          onClose={() => setConfirming(false)}
        />
      </Show>
    </section>
  );
}
