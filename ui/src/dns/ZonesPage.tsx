// The zone list (/dns): every zone with its kind and serving state, the RRset count, the
// serial served now and the mix of origins (manual records, records IPAM keeps), a search over
// the names, and the create and delete dialogs. When the API answers 501 (the DNS service is
// not built yet) or the module is switched off, the page says so and offers no action.
import { useNavigate, useSearchParams } from "@solidjs/router";
import { createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";
import { createLiveQuery, latest } from "../api/live";
import { Icon } from "../components/Icon";
import { PageHead } from "../components/PageHead";
import { DataGrid } from "../grid/DataGrid";
import { TimeAgo } from "../grid/cells";
import type { Column, RowAction } from "../grid/types";
import { formatNumber, t } from "../i18n";
import { hasOrigin, listZones, servedSerial, type Origin, type Zone } from "./api";
import { mayWriteDns } from "./access";
import { DnsNav } from "./DnsNav";
import { DnsProblem, originWord, unavailable, ZoneChips } from "./Parts";
import { dnsPaths } from "./paths";
import { CreateZoneDialog, DeleteZoneDialog } from "./ZoneDialogs";
import "./dns.css";

const MIX: readonly Origin[] = ["manual", "ipam"];
/** The zones whose origin mix is asked record by record when the server does not report it. */
const PROBE_LIMIT = 100;

/**
 * The origins present in each zone: `Zone.origins` when the server reports it, otherwise one
 * one-item read per origin of the mix for the first zones of the list.
 */
function useOrigins(zones: () => readonly Zone[] | undefined) {
  const missing = createMemo(() => (zones() ?? []).filter((z) => z.origins === undefined).slice(0, PROBE_LIMIT));
  const [probed] = createResource(
    () => (missing().length > 0 ? missing().map((z) => z.id).join(",") : false),
    async () => {
      const out = new Map<string, Origin[]>();
      await Promise.all(
        missing().map(async (zone) => {
          const present = await Promise.all(MIX.map((origin) => hasOrigin(zone.id, origin).catch(() => false)));
          out.set(
            zone.id,
            MIX.filter((_, i) => present[i]),
          );
        }),
      );
      return out;
    },
  );
  return (zone: Zone): Origin[] | undefined => {
    if (zone.origins) return zone.origins.filter((o) => o.rrsets > 0).map((o) => o.origin);
    return probed.error ? undefined : probed.latest?.get(zone.id);
  };
}

export default function ZonesPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const initial = typeof params.q === "string" ? params.q : "";
  const [text, setText] = createSignal(initial);
  const [applied, setApplied] = createSignal(initial);
  const [creating, setCreating] = createSignal(false);
  const [deleting, setDeleting] = createSignal<Zone | null>(null);

  const query = createLiveQuery({
    topics: ["dns"],
    fetch: async (signal) => {
      const page = await listZones(signal);
      return { value: page.items, revision: page.revision };
    },
  });
  const zones = () => latest(query);
  const origins = useOrigins(zones);
  const rows = createMemo(() => {
    const needle = applied().trim().toLowerCase();
    const all = zones() ?? [];
    return needle ? all.filter((z) => z.name.includes(needle) || (z.description ?? "").toLowerCase().includes(needle)) : all;
  });
  const blocked = () => unavailable(query.value.error);

  let timer: ReturnType<typeof setTimeout> | undefined;
  const onInput = (value: string) => {
    setText(value);
    clearTimeout(timer);
    timer = setTimeout(() => {
      setApplied(value);
      setParams({ q: value || undefined });
    }, 200);
  };
  onCleanup(() => clearTimeout(timer));

  const columns: Column<Zone>[] = [
    { id: "name", header: () => t("dns.col.zone"), fixed: true, text: (z) => z.name, render: (z) => <span class="mono">{z.name}</span> },
    { id: "kind", header: () => t("dns.col.kind"), width: 230, text: (z) => z.kind, render: (z) => <ZoneChips zone={z} /> },
    {
      id: "rrsets",
      header: () => t("dns.col.rrsets"),
      width: 110,
      align: "right",
      text: (z) => String(z.rrsets),
      render: (z) => <span class="num">{formatNumber(z.rrsets)}</span>,
    },
    {
      id: "serial",
      header: () => t("dns.col.serial"),
      width: 130,
      align: "right",
      text: (z) => String(servedSerial(z) ?? ""),
      render: (z) => <span class="num mono">{servedSerial(z) ?? "–"}</span>,
    },
    {
      id: "origins",
      header: () => t("dns.col.origins"),
      width: 170,
      render: (z) => (
        <span class="dns-chips" data-testid="zone-origins" data-key={(origins(z) ?? []).join(",")}>
          <For each={origins(z) ?? []}>{(o) => <span class={o === "manual" ? "tag" : "tag proposal"}>{originWord(o)}</span>}</For>
        </span>
      ),
    },
    { id: "description", header: () => t("dns.col.description"), text: (z) => z.description ?? "", render: (z) => <span class="muted">{z.description ?? ""}</span> },
    { id: "updated", header: () => t("dns.col.updated"), width: 120, hidden: true, render: (z) => <TimeAgo at={z.updated.at} /> },
  ];

  const actions: RowAction<Zone>[] = [
    { id: "open", label: () => t("dns.do.open"), run: (z) => navigate(dnsPaths.zone(z.id)) },
    { id: "import", label: () => t("dns.do.import"), hidden: () => !mayWriteDns(), run: (z) => navigate(dnsPaths.zoneImport(z.id)) },
    { id: "delete", label: () => t("dns.do.delete"), danger: true, hidden: () => !mayWriteDns(), run: (z) => setDeleting(z) },
  ];

  return (
    <div class="page dns-page list-page" data-testid="page-dns">
      <DnsNav />
      <PageHead
        title={t("dns.zones.title")}
        sub={t("dns.zones.sub")}
        actions={
          <Show when={mayWriteDns() && !blocked()}>
            <button type="button" class="btn primary" data-testid="dns-zone-create" onClick={() => setCreating(true)}>
              <Icon name="plus" />
              {t("dns.zone.create.action")}
            </button>
          </Show>
        }
      />
      <Show
        when={!blocked()}
        fallback={
          <div class="page-body">
            <DnsProblem error={query.value.error} />
          </div>
        }
      >
        <div class="filterbar" role="toolbar" aria-label={t("dns.zones.filter_label")} data-testid="filterbar">
          <label class="query">
            <Icon name="search" size="sm" />
            <input
              class="dns-search"
              value={text()}
              placeholder={t("dns.zones.filter_placeholder")}
              aria-label={t("dns.zones.filter_label")}
              spellcheck={false}
              data-testid="filter-input"
              onInput={(e) => onInput(e.currentTarget.value)}
            />
          </label>
        </div>
        <div class="dns-list-body">
          <DataGrid
            id="dns-zones"
            label={t("dns.zones.title")}
            noSelection
            columns={columns}
            rows={rows()}
            rowId={(z) => z.id}
            rowKey={(z) => z.name}
            rowLabel={(z) => z.name}
            loading={query.value.loading}
            initial={zones() === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            onOpen={(z) => navigate(dnsPaths.zone(z.id))}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dns-zones-empty">
                <h3>{applied() ? t("grid.empty.filtered") : t("dns.zones.empty")}</h3>
                <Show when={!applied()}>
                  <p>{t("dns.zones.empty_body")}</p>
                </Show>
              </div>
            }
          />
        </div>
      </Show>
      <Show when={creating()}>
        <CreateZoneDialog
          onClose={() => setCreating(false)}
          onDone={(zone) => {
            setCreating(false);
            query.refetch();
            navigate(dnsPaths.zone(zone.id));
          }}
        />
      </Show>
      <Show when={deleting()} keyed>
        {(zone) => (
          <DeleteZoneDialog
            zone={zone}
            onClose={() => setDeleting(null)}
            onDone={() => {
              setDeleting(null);
              query.refetch();
            }}
          />
        )}
      </Show>
    </div>
  );
}
