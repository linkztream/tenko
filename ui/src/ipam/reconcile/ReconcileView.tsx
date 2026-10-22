// The reconciliation view (/ipam/reconcile): what intent, the leases, the DNS zones and the
// scans each say about an address, side by side, with the finding and the rule that decides who
// wins. One list per kind (conflicts, ghost addresses, unknown devices, orphaned records, PTR
// mismatches), each read page by page. The filters live in the URL: `prefix` and `host` take
// ids, `kind` narrows the page to one list.
import { useSearchParams } from "@solidjs/router";
import { createResource, createSignal, For, Show } from "solid-js";
import { api } from "../../api/client";
import { fetchAll } from "../../api/paginate";
import { errorMessage } from "../../api/problem";
import type { Host, Prefix } from "../../api/types";
import { Icon } from "../../components/Icon";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { ToggleChip } from "../../grid/FilterBar";
import { t } from "../../i18n";
import { IpamNav } from "../IpamNav";
import { isKind, KIND_TITLE, KINDS } from "./model";
import { ReconcileList } from "./ReconcileList";
import "./reconcile.css";

/** A single value of a query parameter; a repeated parameter counts as absent. */
function one(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

export default function ReconcileView() {
  const [search, setSearch] = useSearchParams();

  const kind = () => {
    const k = one(search.kind);
    return isKind(k) ? k : undefined;
  };
  const prefix = () => one(search.prefix);
  const host = () => one(search.host);
  const shown = () => (kind() ? [kind() as (typeof KINDS)[number]] : KINDS);

  // The networks to choose from. A list that cannot be read leaves the drop-down with the
  // network of the URL only; the page still works.
  const [prefixes] = createResource(async (): Promise<Prefix[]> => {
    try {
      return (await fetchAll<Prefix>("/api/v1/prefixes", { max: 5000 })).items;
    } catch {
      return [];
    }
  });
  const prefixOptions = () => {
    const list = prefixes() ?? [];
    return [...list].sort((a, b) => a.cidr.localeCompare(b.cidr, undefined, { numeric: true }));
  };

  // The name of the host of the URL, for its chip.
  const [hostInfo] = createResource(host, async (id): Promise<Host | null> => {
    try {
      return (await api.get("/api/v1/hosts/{id}", { path: { id } })) as Host;
    } catch {
      return null;
    }
  });

  const [hostText, setHostText] = createSignal("");
  const [unknown, setUnknown] = createSignal<string | null>(null);
  const applyHost = async (e: SubmitEvent) => {
    e.preventDefault();
    const name = hostText().trim();
    if (!name) return;
    try {
      const page = await api.get("/api/v1/hosts", { query: { q: name, limit: 50 } });
      const found = (page.items as Host[]).find((h) => h.name.toLowerCase() === name.toLowerCase());
      if (!found) {
        setUnknown(name);
        return;
      }
      setUnknown(null);
      setHostText("");
      setSearch({ host: found.id });
    } catch (err) {
      toast({ kind: "bad", title: t("ipam.reconcile.filter.host"), body: errorMessage(err) });
    }
  };

  return (
    <div class="page reconcile-page" data-testid="page-ipam-reconcile">
      <IpamNav />
      <PageHead title={t("ipam.reconcile.title")} sub={t("ipam.reconcile.sub")} />
      <div class="filterbar" role="toolbar" aria-label={t("ipam.reconcile.filter.label")} data-testid="reconcile-filters">
        <select
          class="select"
          aria-label={t("ipam.reconcile.filter.prefix")}
          data-testid="filter-prefix"
          onChange={(e) => setSearch({ prefix: e.currentTarget.value || undefined })}
        >
          <option value="" selected={!prefix()}>
            {t("ipam.reconcile.filter.all_prefixes")}
          </option>
          <For each={prefixOptions()}>
            {(p) => (
              <option value={p.id} selected={prefix() === p.id}>
                {p.cidr}
              </option>
            )}
          </For>
        </select>
        <form class="reconcile-host-form" onSubmit={(e) => void applyHost(e)}>
          <input
            class="input mono"
            aria-label={t("ipam.reconcile.filter.host")}
            placeholder={t("ipam.reconcile.filter.host_placeholder")}
            data-testid="filter-host-input"
            autocomplete="off"
            spellcheck={false}
            value={hostText()}
            onInput={(e) => setHostText(e.currentTarget.value)}
          />
          <button type="submit" class="btn" data-testid="filter-host-apply" disabled={hostText().trim() === ""}>
            {t("ipam.reconcile.filter.host_apply")}
          </button>
        </form>
        <Show when={host()}>
          {(id) => (
            <span class="chip applied" data-testid="filter-host">
              {t("ipam.reconcile.filter.host_chip", { host: hostInfo()?.name ?? id().slice(0, 8) })}
              <button
                type="button"
                class="chip-x"
                data-testid="filter-chip-remove"
                aria-label={t("ipam.reconcile.filter.remove_host")}
                onClick={() => setSearch({ host: undefined })}
              >
                <Icon name="x" size="xs" />
              </button>
            </span>
          )}
        </Show>
        <span class="divider" />
        <div class="reconcile-kinds" role="group" aria-label={t("ipam.reconcile.filter.kind")}>
          <ToggleChip pressed={!kind()} onToggle={() => setSearch({ kind: undefined })} testid="filter-kind-all">
            {t("ipam.reconcile.filter.all_kinds")}
          </ToggleChip>
          <For each={KINDS}>
            {(k) => (
              <ToggleChip pressed={kind() === k} onToggle={() => setSearch({ kind: kind() === k ? undefined : k })} testid={`filter-kind-${k}`}>
                {t(KIND_TITLE[k])}
              </ToggleChip>
            )}
          </For>
        </div>
      </div>
      <Show when={unknown()}>
        {(name) => (
          <p class="muted reconcile-note" role="status" data-testid="filter-host-unknown">
            {t("ipam.reconcile.filter.host_unknown", { name: name() })}
          </p>
        )}
      </Show>
      <div class="reconcile-body">
        <For each={shown()}>{(k) => <ReconcileList kind={k} prefix={prefix()} host={host()} />}</For>
      </div>
    </div>
  );
}
