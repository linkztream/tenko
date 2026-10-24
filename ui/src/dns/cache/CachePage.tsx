// The cache view of the DNS area (/dns/cache): what the node's cache holds, as the cache view of
// the Windows DNS manager shows it. Nothing is read until the administrator asks, since every
// page read is audited (`dns.cache.read`): the entries are the names the clients asked. A press
// of the button reads the entries at or below the suffix, page by page up to the cap of
// cache.ts, and builds the tree of names once; expanding, collapsing and selecting a folder
// never read again, and nothing refreshes on its own. The left pane is the tree of folders from
// "(root)" down, the right pane the records of the folder selected: the folders under it, its
// own entries as "(same as parent folder)", then the entries of the names under it, each with
// its type, the time it stays fresh, its view, its validation state (with the extended error
// code of a bogus entry), the stale flag, its hits and the data, and each signature as a row of
// its own. With a suffix applied, "flush" empties those entries through the node command
// `dns.cache.flush`, after a confirmation, and reads again.
//
// Keyboard (WAI-ARIA tree, as PrefixTree.tsx): Up and Down move and select, Right opens a folder
// or goes to its first folder, Left closes it or goes to its parent, Home and End jump, Enter
// on a "show more" shows more. A folder row of the right pane opens its folder on a double click
// or Enter.
import { createEffect, createMemo, createResource, createSignal, createUniqueId, For, Match, onCleanup, onMount, Show, Switch } from "solid-js";
import { ApiError, errorMessage } from "../../api/problem";
import { ConfirmDialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { logicalArrow } from "../../grid/focus";
import { formatDateTime, formatNumber, t } from "../../i18n";
import { DnsNav } from "../DnsNav";
import { nodeDns } from "../log/api";
import { NodeSelect, useDnsNode } from "../node";
import { DnsProblem, unavailable } from "../Parts";
import { CACHE_PAGE, CACHE_PAGES, flushCache, readCache, type CacheListing, type DnsCacheEntry, type Rrsig } from "./api";
import {
  buildCacheTree,
  cacheSuffix,
  entryData,
  folderChildren,
  paneRows,
  pathTo,
  rrsigTime,
  ttlLeft,
  utcMinute,
  visibleFolders,
  WINDOW,
  type CacheNode,
  type TreeItem,
} from "./model";
import "../dns.css";
import "./cache.css";

function notDns(err: unknown): boolean {
  return err instanceof ApiError && err.code === "dns.node.not_dns";
}

function Ttl(props: { entry: DnsCacheEntry }) {
  const left = () => ttlLeft(props.entry.ttl);
  return (
    <Show when={!props.entry.stale} fallback={<span class="muted">{t("dns.cache.ttl_none")}</span>}>
      {t(`dns.cache.ttl_${left().unit}`, { value: formatNumber(left().value) })}
    </Show>
  );
}

function View(props: { entry: DnsCacheEntry }) {
  return (
    <Show when={props.entry.view} fallback={<span class="muted">{t("dns.cache.view_default")}</span>}>
      {(view) => <span class="mono">{view()}</span>}
    </Show>
  );
}

/** The validation state of an entry, the extended error code of a bogus one beside it, and
 * when the signatures expire as the hint of a secure one. */
function State(props: { entry: DnsCacheEntry }) {
  const expiry = () => props.entry.signature_expiry;
  return (
    <>
      <span
        class="tag"
        classList={{ discrepancy: props.entry.state === "bogus" }}
        title={expiry() ? t("dns.cache.signature_expiry", { time: formatDateTime(expiry() ?? "") }) : undefined}
      >
        {t(`dns.sec.${props.entry.state}`)}
      </span>
      <Show when={props.entry.ede != null}>
        <span class="tag mono" data-testid="dns-cache-ede" title={t("dns.cache.ede_hint", { code: props.entry.ede ?? 0 })}>
          {t("dns.cache.ede", { code: props.entry.ede ?? 0 })}
        </span>
      </Show>
    </>
  );
}

/** The name of a row relative to the folder selected; null is the folder's own records. */
function Name(props: { label: string | null }) {
  return (
    <Show when={props.label !== null} fallback={<span class="muted dns-cache-same">{t("dns.cache.same_as_parent")}</span>}>
      <span class="mono">{props.label}</span>
    </Show>
  );
}

/** The data of a row, clamped to three lines so one long value cannot take over the page. Whether
 * it is clamped is read from the rendered height, never from the length of the text; only then
 * does the button that opens the cell show. The full text stays in the DOM for assistive
 * technology and in the cell's title. */
function DataCell(props: { text: string; hint?: string }) {
  const id = createUniqueId();
  let box: HTMLDivElement | undefined;
  const [open, setOpen] = createSignal(false);
  const [clamped, setClamped] = createSignal(false);
  const measure = () => {
    if (box && !open()) setClamped(box.scrollHeight > box.clientHeight);
  };
  onMount(() => {
    measure();
    if (typeof ResizeObserver !== "undefined" && box) {
      const observer = new ResizeObserver(measure);
      observer.observe(box);
      onCleanup(() => observer.disconnect());
    }
  });
  createEffect(() => {
    void props.text;
    queueMicrotask(measure);
  });
  return (
    <td class="mono dns-cache-data" data-testid="dns-cache-data" title={props.hint ?? props.text}>
      <div id={id} ref={box} class="dns-cache-text" classList={{ open: open() }}>
        {props.text}
      </div>
      <Show when={clamped() || open()}>
        <button
          type="button"
          class="btn ghost sm dns-cache-toggle"
          data-testid="dns-cache-data-toggle"
          aria-expanded={open()}
          aria-controls={id}
          onClick={() => setOpen(!open())}
        >
          {open() ? t("dns.cache.data_less") : t("dns.cache.data_more")}
        </button>
      </Show>
    </td>
  );
}

function EntryRow(props: { entry: DnsCacheEntry; label: string | null }) {
  return (
    <tr
      data-testid="dns-cache-row"
      data-key={props.entry.name}
      data-type={props.entry.type}
      data-stale={String(props.entry.stale)}
      data-own={String(props.label === null)}
    >
      <td>
        <Name label={props.label} />
      </td>
      <td class="mono">{props.entry.type}</td>
      <td class="nowrap">
        <Ttl entry={props.entry} />
      </td>
      <td>
        <View entry={props.entry} />
      </td>
      <td data-testid="dns-cache-state" data-state={props.entry.state}>
        <State entry={props.entry} />
      </td>
      <td>
        <Show when={props.entry.stale}>
          <span class="tag discrepancy" data-testid="dns-cache-stale" title={t("dns.cache.stale_hint")}>
            {t("dns.cache.stale")}
          </span>
        </Show>
      </td>
      <td class="r">{formatNumber(props.entry.hits)}</td>
      <DataCell text={entryData(props.entry)} />
    </tr>
  );
}

/** A signature of an entry's answer, summarised as the Windows DNS manager does: the type
 * covered, the signer and the expiry in UTC. The state, the stale flag and the hits are the
 * entry's and stay on its row. */
function SignatureRow(props: { entry: DnsCacheEntry; record: Rrsig; label: string | null }) {
  return (
    <tr data-testid="dns-cache-row" data-key={props.entry.name} data-type="RRSIG" data-covered={props.record.type_covered} data-own={String(props.label === null)}>
      <td>
        <Name label={props.label} />
      </td>
      <td class="mono">{props.record.type}</td>
      <td class="nowrap">
        <Ttl entry={props.entry} />
      </td>
      <td>
        <View entry={props.entry} />
      </td>
      <td />
      <td />
      <td />
      <DataCell
        hint={t("dns.cache.signature_hint")}
        text={t("dns.cache.signature", {
          type: props.record.type_covered,
          signer: props.record.signer,
          time: utcMinute(rrsigTime(props.record.expiration)),
        })}
      />
    </tr>
  );
}

function FolderRow(props: { node: CacheNode; onOpen: (node: CacheNode) => void }) {
  return (
    <tr
      class="dns-cache-folder-row"
      data-testid="dns-cache-folder-row"
      data-key={props.node.name}
      tabIndex={0}
      title={t("dns.cache.open_hint")}
      onDblClick={() => props.onOpen(props.node)}
      onKeyDown={(event) => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        props.onOpen(props.node);
      }}
    >
      <td>
        <span class="dns-cache-folder-name">
          <Icon name="folder" size="sm" />
          <span class="mono">{props.node.label}</span>
        </span>
      </td>
      <td colSpan={7} />
    </tr>
  );
}

/** The tree and the right pane of one read. The tree is built once, from the entries the read
 * gave; the state of the panes (what is expanded, what is selected, how many rows are shown)
 * lives here, so a new read starts them afresh. Expanding goes through `toggle` alone, and the
 * tree takes entries with `createCacheTree().add`, so a folder's names could later be read on
 * its own (the suffix of the listing route) when it is expanded and added there. */
function CacheBrowser(props: { listing: CacheListing }) {
  let list!: HTMLUListElement;
  // The listing does not change while this component lives: a new read makes a new one.
  // eslint-disable-next-line solid/reactivity
  const tree = buildCacheTree(props.listing.items, props.listing.suffix);
  const start = (tree.suffix ? tree.byName.get(tree.suffix) : undefined) ?? tree.root;
  const [expanded, setExpanded] = createSignal<ReadonlySet<string>>(new Set(pathTo(start.name)));
  const [selected, setSelected] = createSignal<CacheNode>(start);
  const [shown, setShown] = createSignal<ReadonlyMap<string, number>>(new Map());
  const [paneLimit, setPaneLimit] = createSignal(WINDOW);

  const items = createMemo(() => visibleFolders(tree, expanded(), shown()));
  const rows = createMemo(() => paneRows(tree, selected()));
  const key = (item: TreeItem) => (item.kind === "folder" ? `n${item.node.id}` : `m${item.parent.id}`);
  const [activeKey, setActiveKey] = createSignal(`n${start.id}`);
  const activeIndex = () => {
    const i = items().findIndex((item) => key(item) === activeKey());
    return i < 0 ? 0 : i;
  };
  const elementId = (item: TreeItem) => `dns-cache-tree-${key(item)}`;

  const hasFolders = (node: CacheNode) => folderChildren(tree, node).length > 0;
  const isOpen = (node: CacheNode) => hasFolders(node) && expanded().has(node.name);

  const select = (node: CacheNode) => {
    if (node === selected()) return;
    setSelected(node);
    setPaneLimit(WINDOW);
  };
  const toggle = (node: CacheNode, open?: boolean) => {
    const next = new Set(expanded());
    const shouldOpen = open ?? !next.has(node.name);
    if (shouldOpen) next.add(node.name);
    else {
      next.delete(node.name);
      // A folder closed over the selection takes it, as in the Windows DNS manager.
      if (selected() !== node && pathTo(selected().name).includes(node.name)) {
        select(node);
        setActiveKey(`n${node.id}`);
      }
    }
    setExpanded(next);
  };
  const showMore = (parent: CacheNode) => {
    const next = new Map(shown());
    next.set(parent.name, (next.get(parent.name) ?? WINDOW) + WINDOW);
    setShown(next);
  };
  const moveTo = (i: number) => {
    const item = items()[Math.max(0, Math.min(items().length - 1, i))];
    if (!item) return;
    setActiveKey(key(item));
    if (item.kind === "folder") select(item.node);
    document.getElementById(elementId(item))?.scrollIntoView?.({ block: "nearest" });
  };
  // A folder row of the right pane: open the path to it, select it, and give the tree the focus.
  const open = (node: CacheNode) => {
    const next = new Set(expanded());
    for (const name of pathTo(node.name).slice(0, -1)) next.add(name);
    setExpanded(next);
    // A folder past the window of its parent's folders is shown by widening the window.
    const parent = node.parent ? tree.byName.get(node.parent) : undefined;
    if (parent) {
      const at = folderChildren(tree, parent).indexOf(node);
      const limit = shown().get(parent.name) ?? WINDOW;
      if (at >= limit) setShown(new Map(shown()).set(parent.name, Math.ceil((at + 1) / WINDOW) * WINDOW));
    }
    select(node);
    setActiveKey(`n${node.id}`);
    list.focus({ preventScroll: true });
    document.getElementById(`dns-cache-tree-n${node.id}`)?.scrollIntoView?.({ block: "nearest" });
  };

  const onKeyDown = (event: KeyboardEvent) => {
    const all = items();
    const i = activeIndex();
    const item = all[i];
    if (!item) return;
    // In a right-to-left layout ArrowLeft opens and ArrowRight closes (grid/focus.ts).
    switch (logicalArrow(event.key, event.currentTarget as Element)) {
      case "ArrowDown":
        event.preventDefault();
        moveTo(i + 1);
        break;
      case "ArrowUp":
        event.preventDefault();
        moveTo(i - 1);
        break;
      case "Home":
        event.preventDefault();
        moveTo(0);
        break;
      case "End":
        event.preventDefault();
        moveTo(all.length - 1);
        break;
      case "ArrowRight":
        event.preventDefault();
        if (item.kind !== "folder") break;
        if (hasFolders(item.node) && !isOpen(item.node)) toggle(item.node, true);
        else if (isOpen(item.node)) moveTo(i + 1);
        break;
      case "ArrowLeft": {
        event.preventDefault();
        if (item.kind === "folder" && isOpen(item.node)) toggle(item.node, false);
        else {
          const parent = item.kind === "folder" ? item.node.parent : item.parent.name;
          const p = all.findIndex((x) => x.kind === "folder" && x.node.name === parent);
          if (p >= 0) moveTo(p);
        }
        break;
      }
      case "Enter":
        event.preventDefault();
        if (item.kind === "more") showMore(item.parent);
        else select(item.node);
        break;
    }
  };

  const label = (node: CacheNode) => (node === tree.root ? t("dns.cache.root") : node.label);

  return (
    <div class="dns-cache-browser" data-testid="dns-cache-browser">
      <div class="dns-cache-tree">
        <ul
          ref={list}
          class="tree"
          role="tree"
          aria-label={t("dns.cache.tree_label")}
          tabIndex={0}
          aria-activedescendant={items().length ? elementId(items()[activeIndex()] as TreeItem) : undefined}
          onKeyDown={onKeyDown}
          data-testid="dns-cache-tree"
        >
          <For each={items()}>
            {(item) => (
              <Show
                when={item.kind === "folder" ? item.node : undefined}
                fallback={
                  <li
                    role="treeitem"
                    id={elementId(item)}
                    aria-level={(item.kind === "more" ? item.parent.depth : 0) + 2}
                    aria-selected="false"
                    data-testid="dns-cache-tree-more"
                    data-parent={item.kind === "more" ? item.parent.name : undefined}
                  >
                    <div
                      class="tnode more"
                      classList={{ active: key(item) === activeKey() }}
                      style={{ "--depth": (item.kind === "more" ? item.parent.depth : 0) + 1 }}
                      onClick={() => {
                        setActiveKey(key(item));
                        list.focus({ preventScroll: true });
                        if (item.kind === "more") showMore(item.parent);
                      }}
                    >
                      <span class="tw" />
                      <span class="lbl">{t("dns.cache.more", { count: formatNumber(Math.min(WINDOW, item.kind === "more" ? item.hidden : 0)) })}</span>
                    </div>
                  </li>
                }
              >
                {(node) => (
                  <li
                    role="treeitem"
                    id={elementId(item)}
                    aria-level={node().depth + 1}
                    aria-expanded={hasFolders(node()) ? isOpen(node()) : undefined}
                    aria-selected={node() === selected()}
                    data-testid="dns-cache-node"
                    data-key={node().name}
                  >
                    <div
                      class="tnode"
                      classList={{ active: key(item) === activeKey(), selected: node() === selected() }}
                      style={{ "--depth": node().depth }}
                      onClick={() => {
                        setActiveKey(key(item));
                        list.focus({ preventScroll: true });
                        select(node());
                      }}
                    >
                      <span
                        class="tw"
                        onClick={(event) => {
                          event.stopPropagation();
                          if (hasFolders(node())) toggle(node());
                        }}
                      >
                        <Show when={hasFolders(node())}>
                          <Icon name={isOpen(node()) ? "chev-d" : "chev-r"} />
                        </Show>
                      </span>
                      <span class="lbl">
                        <Icon name="folder" size="sm" />
                        <span class="mono">{label(node())}</span>
                      </span>
                    </div>
                  </li>
                )}
              </Show>
            )}
          </For>
        </ul>
      </div>
      <div class="dns-cache-pane">
        <p class="dns-cache-folder mono" data-testid="dns-cache-folder" data-key={selected().name}>
          {selected() === tree.root ? t("dns.cache.root") : selected().name}
        </p>
        <div class="table-wrap">
          <table class="plain dns-cache-table" data-testid="dns-cache-table">
            <caption class="sr-only">{t("dns.cache.title")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("dns.cache.col.name")}</th>
                <th scope="col">{t("dns.cache.col.type")}</th>
                <th scope="col">{t("dns.cache.col.ttl")}</th>
                <th scope="col">{t("dns.cache.col.view")}</th>
                <th scope="col">{t("dns.cache.col.state")}</th>
                <th scope="col">{t("dns.cache.col.stale")}</th>
                <th scope="col" class="r">
                  {t("dns.cache.col.hits")}
                </th>
                <th scope="col">{t("dns.cache.col.data")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={rows().slice(0, paneLimit())}>
                {(row) =>
                  row.kind === "folder" ? (
                    <FolderRow node={row.node} onOpen={open} />
                  ) : row.kind === "entry" ? (
                    <EntryRow entry={row.entry} label={row.label} />
                  ) : (
                    <SignatureRow entry={row.entry} record={row.record} label={row.label} />
                  )
                }
              </For>
            </tbody>
          </table>
        </div>
        <Show when={rows().length > paneLimit()}>
          <div class="dns-cache-more">
            <button type="button" class="btn" data-testid="dns-cache-pane-more" onClick={() => setPaneLimit(paneLimit() + WINDOW)}>
              {t("dns.cache.more", { count: formatNumber(Math.min(WINDOW, rows().length - paneLimit())) })}
            </button>
            <span class="muted">{t("dns.cache.rows_shown", { shown: formatNumber(paneLimit()), total: formatNumber(rows().length) })}</span>
          </div>
        </Show>
      </div>
    </div>
  );
}

/** The suffix form, the tree of names and the flush of one node's cache. The node is fixed for
 * the life of the component: the page keys it by node, so another node starts a new read. */
function CacheView(props: { node: number }) {
  const [typed, setTyped] = createSignal("");
  const [invalid, setInvalid] = createSignal(false);
  // The suffix of the read asked for and a counter that makes every press a new read;
  // undefined until the administrator asks. Nothing else starts a read.
  const [request, setRequest] = createSignal<{ suffix: string; tick: number }>();
  const [confirming, setConfirming] = createSignal(false);
  const [busy, setBusy] = createSignal(false);

  // A new press stops the pages of the read before it.
  let reading: AbortController | undefined;
  onCleanup(() => reading?.abort());
  const [listing] = createResource(request, (r) => {
    reading?.abort();
    reading = new AbortController();
    return readCache(props.node, r.suffix, reading.signal);
  });

  const read = (suffix: string) => setRequest({ suffix, tick: (request()?.tick ?? 0) + 1 });
  const show = (event: Event) => {
    event.preventDefault();
    const suffix = cacheSuffix(typed());
    setInvalid(suffix === null);
    if (suffix !== null) read(suffix);
  };
  const suffix = () => request()?.suffix ?? "";

  const flush = async () => {
    const current = request();
    if (!current || busy()) return;
    setBusy(true);
    try {
      await flushCache(props.node, current.suffix);
      toast({ kind: "ok", title: t("dns.cache.flushed", { suffix: current.suffix }) });
      setConfirming(false);
      read(current.suffix);
    } catch (err) {
      toast({ kind: "bad", title: t("dns.cache.flush_failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="dns-cache" data-testid="dns-cache">
      <p class="muted dns-cache-lede" data-testid="dns-cache-audit-note">
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
            {request() ? t("dns.cache.reload") : t("dns.cache.show")}
          </button>
          <Show when={suffix()}>
            <button type="button" class="btn" data-testid="dns-cache-flush" disabled={busy()} onClick={() => setConfirming(true)}>
              {t("dns.cache.flush", { suffix: suffix() })}
            </button>
          </Show>
        </div>
      </form>
      <Show when={listing.error}>
        <ErrorNotice error={listing.error} />
      </Show>
      <Show when={!listing.error && listing.latest} keyed>
        {(current) => (
          <Show
            when={current.items.length > 0}
            fallback={
              <div class="empty" data-testid="dns-cache-empty">
                <h3>{current.suffix ? t("dns.cache.empty_suffix", { suffix: current.suffix }) : t("dns.cache.empty")}</h3>
              </div>
            }
          >
            <Show when={current.capped}>
              <Notice kind="warn" testid="dns-cache-capped">
                {t("dns.cache.capped", { count: formatNumber(CACHE_PAGE * CACHE_PAGES) })}
              </Notice>
            </Show>
            <CacheBrowser listing={current} />
          </Show>
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

export default function CachePage() {
  const { nodes, node, choose } = useDnsNode();
  const [status] = createResource(node, (id) => nodeDns(id));

  return (
    <div class="page dns-page" data-testid="page-dns-cache">
      <DnsNav />
      <PageHead title={t("dns.cache.title")} sub={t("dns.cache.sub")} />
      <div class="page-body dns-cache-body">
        <Show when={nodes.error}>
          <ErrorNotice error={nodes.error} />
        </Show>
        <Show when={nodes.latest && nodes.latest.length === 0}>
          <Notice kind="info" role="status" testid="dns-cache-no-node">
            {t("dns.cache.no_node")}
          </Notice>
        </Show>
        <Show when={(nodes.latest?.length ?? 0) > 0}>
          <NodeSelect nodes={nodes.latest ?? []} node={node()} onChoose={choose} />
        </Show>
        <Switch>
          <Match when={status.error && unavailable(status.error)}>
            <DnsProblem error={status.error} />
          </Match>
          <Match when={status.error && notDns(status.error)}>
            <Notice kind="info" role="status" title={t("dns.cache.not_dns_title")} testid="dns-cache-not-dns">
              {t("dns.cache.not_dns_body")}
            </Notice>
          </Match>
          <Match when={status.error}>
            <ErrorNotice error={status.error} />
          </Match>
          <Match when={status.latest && node()}>
            {/* Keyed by the node: choosing another one drops the entries read from the first. */}
            <Show when={node()} keyed>
              {(id) => <CacheView node={id} />}
            </Show>
          </Match>
        </Switch>
      </div>
    </div>
  );
}
