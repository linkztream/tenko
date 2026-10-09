// The IPAM view (/ipam and /ipam/prefixes/<network>/<length>): the prefix tree of the VRF in
// view on the left, the selected prefix on the right (design: shell-and-ipam mockup).
// `[` focuses the tree and `]` the grid. A prefix in the URL is looked up in the VRF in view
// (or the `vrf` of the link); when it exists in other VRFs only, the view switches to it, and
// when several VRFs have it, it asks which one.
import { useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { createEffect, createMemo, createResource, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { api } from "../api/client";
import { events } from "../api/events";
import { createLiveQuery } from "../api/live";
import { fetchAll } from "../api/paginate";
import type { Prefix, TreeNode, Vlan } from "../api/types";
import { decodeSegment, paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { t } from "../i18n";
import { isTyping } from "../shell/keyboard";
import { useCommands } from "../shell/commands";
import { IpamNav } from "./IpamNav";
import { PrefixForm } from "./prefix/PrefixForm";
import { PrefixPane } from "./prefix/PrefixPane";
import { VrfOverview } from "./prefix/VrfOverview";
import { useScope } from "./scope";
import { ScopeSwitcher } from "./ScopeSwitcher";
import { PrefixTree, useTree } from "./tree/PrefixTree";
import { createVlanStyles } from "./vlan/palette";
import "./ipam.css";

/** VLANs by id with their colors, for the chips of the tree and the prefix pane. */
export function useVlans() {
  const live = createLiveQuery<Vlan[]>({
    topics: ["ipam"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => o.kind === "vlan"),
    fetch: async (signal) => {
      const all = await fetchAll<Vlan>("/api/v1/vlans", { signal });
      return { value: all.items, revision: all.revision as number };
    },
  });
  const list = () => (live.value.state === "ready" || live.value.state === "refreshing" ? live.value() : []);
  const styles = createVlanStyles(() => list().map((v) => v.vid));
  const byId = createMemo(() => new Map(list().map((v) => [v.id, v])));
  return {
    list,
    vlanOf: (id: string) => {
      const v = byId().get(id);
      return v ? { vid: v.vid, name: v.name, style: styles().get(v.vid) } : undefined;
    },
  };
}

export default function IpamView() {
  const params = useParams();
  const [search, setSearch] = useSearchParams();
  const navigate = useNavigate();
  const scope = useScope();
  const vlans = useVlans();
  const [filter, setFilter] = createSignal("");
  const [creating, setCreating] = createSignal(false);
  let treeList: HTMLUListElement | undefined;

  const cidr = () => (params.network ? `${decodeSegment(params.network)}/${decodeSegment(params.length)}` : null);
  const linkVrf = () => (typeof search.vrf === "string" ? search.vrf : undefined);

  // A `vrf` in the link selects that VRF once.
  createEffect(() => {
    const id = linkVrf();
    if (id && scope.vrfById(id) && scope.vrf()?.id !== id) scope.choose(id);
  });

  const vrfId = () => scope.vrf()?.id;
  const tree = useTree(vrfId);

  /** The prefix of the URL in the VRF in view, or the VRFs that have it. */
  const [found, { refetch }] = createResource(
    () => {
      const c = cidr();
      const v = vrfId();
      return c && v ? ([c, v] as const) : false;
    },
    async ([c, v]) => {
      const here = await api.get("/api/v1/prefixes", { query: { vrf: v, within: c, limit: 50 } });
      const exact = here.items.find((p) => p.cidr === c);
      if (exact) return { prefix: exact as Prefix, elsewhere: [] as Prefix[] };
      const all = await api.get("/api/v1/prefixes", { query: { within: c, limit: 200 } });
      return { prefix: null, elsewhere: all.items.filter((p) => p.cidr === c) as Prefix[] };
    },
  );

  // Exactly one other VRF has it: show it there.
  createEffect(() => {
    const f = found();
    if (f && !f.prefix && f.elsewhere.length === 1) scope.choose(f.elsewhere[0]!.vrf);
  });

  // Keep the prefix current: an event that touches it reads it again.
  const off = events.subscribe("ipam", (e) => {
    const id = found()?.prefix?.id;
    if (id && [...e.objects, ...e.deleted].some((o) => o.kind === "prefix" && o.id === id)) void refetch();
  });
  onCleanup(off);

  const selected = () => found()?.prefix ?? null;
  const node = () => tree.tree()?.nodes.find((n) => n.id === selected()?.id);

  const open = (n: TreeNode) => navigate(paths.prefix(n.cidr));

  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || isTyping(e) || e.ctrlKey || e.metaKey || e.altKey) return;
      if (document.querySelector("[aria-modal='true']")) return;
      if (e.key === "[") {
        e.preventDefault();
        treeList?.focus();
      } else if (e.key === "]") {
        e.preventDefault();
        document.querySelector<HTMLElement>(".ipam-main table.grid")?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  useCommands(() => [
    {
      id: "ipam.new_prefix",
      group: "actions",
      icon: "plus",
      label: () => t("ipam.tree.add"),
      run: () => setCreating(true),
    },
    {
      id: "ipam.focus_tree",
      group: "actions",
      icon: "layers",
      label: () => t("ipam.command.focus_tree"),
      keys: ["["],
      run: () => treeList?.focus(),
    },
  ]);

  return (
    <div class="page ipam-page" data-testid="page-ipam">
      <IpamNav />
      <div class="ipam">
        <aside class="tree-pane" aria-label={t("ipam.tree.label")}>
          <div class="tree-head">
            <ScopeSwitcher scope={scope} onChange={() => navigate(paths.ipam())} />
          </div>
          <div class="tree-head">
            <label class="query tree-filter">
              <Icon name="filter" size="sm" />
              <input
                value={filter()}
                placeholder={t("ipam.tree.filter")}
                aria-label={t("ipam.tree.filter")}
                data-testid="tree-filter"
                spellcheck={false}
                onInput={(e) => setFilter(e.currentTarget.value)}
              />
            </label>
            <button
              type="button"
              class="icon-btn"
              aria-label={t("ipam.tree.add")}
              title={t("ipam.tree.add")}
              data-testid="ipam-add-prefix"
              disabled={!scope.vrf()}
              onClick={() => setCreating(true)}
            >
              <Icon name="plus" />
            </button>
          </div>
          <PrefixTree
            tree={tree.tree()}
            error={tree.error()}
            selectedId={selected()?.id}
            filter={filter()}
            onOpen={open}
            onDrop={(n, items) => navigate(paths.move(n.id, items.map((i) => ({ kind: i.kind, id: i.id }))))}
            vlanOf={vlans.vlanOf}
            ref={(el) => (treeList = el)}
          />
          <div class="tree-foot">
            <span class="kbd">[</span> {t("ipam.tree.key_tree")} <span class="kbd">]</span> {t("ipam.tree.key_grid")}
            <span class="grow">{t("ipam.tree.drag_hint")}</span>
          </div>
        </aside>
        <section class="ipam-main" aria-label={selected()?.cidr ?? t("ipam.overview.label")}>
          <Show when={found.error}>
            <div class="page-body">
              <ErrorNotice error={found.error} />
            </div>
          </Show>
          <Show
            when={selected()}
            fallback={
              <Show
                when={cidr() && found() && !found()?.prefix}
                fallback={<VrfOverview scope={scope} tree={tree.tree()} vlanOf={vlans.vlanOf} onOpen={open} />}
              >
                <div class="page-body">
                  <Show
                    when={(found()?.elsewhere.length ?? 0) > 1}
                    fallback={<p class="muted">{t("ipam.prefix.not_found", { cidr: cidr() ?? "" })}</p>}
                  >
                    <p>{t("ipam.prefix.in_several", { cidr: cidr() ?? "" })}</p>
                    <ul class="list">
                      <For each={found()?.elsewhere ?? []}>
                        {(p) => (
                          <li>
                            <button
                              type="button"
                              class="btn sm"
                              onClick={() => {
                                scope.choose(p.vrf);
                                setSearch({ vrf: p.vrf });
                              }}
                            >
                              {(() => {
                                const v = scope.vrfById(p.vrf);
                                return t("ipam.scope.option", { tenant: scope.tenantOf(v)?.name ?? "", vrf: v?.name ?? p.vrf });
                              })()}
                            </button>
                          </li>
                        )}
                      </For>
                    </ul>
                  </Show>
                </div>
              </Show>
            }
          >
            {(prefix) => (
              <PrefixPane
                prefix={prefix()}
                node={node()}
                tree={tree.tree()}
                vrf={scope.vrf()}
                vlanOf={vlans.vlanOf}
                onChanged={() => {
                  void refetch();
                  tree.refetch();
                }}
              />
            )}
          </Show>
        </section>
      </div>
      <Show when={creating() && scope.vrf()}>
        <PrefixForm
          vrf={scope.vrf()!}
          parentCidr={selected()?.role === "supernet" ? selected()?.cidr : undefined}
          onClose={() => setCreating(false)}
          onDone={(p) => {
            setCreating(false);
            tree.refetch();
            navigate(paths.prefix(p.cidr));
          }}
        />
      </Show>
    </div>
  );
}
