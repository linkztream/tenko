// The observations (/discovery/observations): every fact the sources reported, newest first,
// over GET /observations with the server's filters (text, type, current or expired, and a
// source, MAC, address or network from the URL), live on the `discovery` topic. A row opens
// the picture of its subject across sources; the lookup field opens it for any MAC address,
// IP address or name.
import { useNavigate, useSearchParams } from "@solidjs/router";
import { createEffect, createSignal, For, on, onCleanup, Show } from "solid-js";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { PageHead } from "../components/PageHead";
import { TimeAgo } from "../grid/cells";
import { DataGrid } from "../grid/DataGrid";
import { FilterBar, ToggleChip } from "../grid/FilterBar";
import { createColumnState } from "../grid/prefs";
import { createListSource } from "../grid/source";
import { sortParam, type Column, type SortState } from "../grid/types";
import { formatNumber, t } from "../i18n";
import { FACT_TYPES, type FactType, type ObservedFact } from "./api";
import { DiscoveryNav } from "./DiscoveryNav";
import { FactState } from "./FactTable";
import { factTypeWord, isCurrent, lookupSubject, observedText, sourceKeyText, sourceText, type SourceNames } from "./model";
import { useSourceNames } from "./refs";
import "./discovery.css";

type Currency = "current" | "expired" | "all";
const CURRENCIES: readonly Currency[] = ["current", "expired", "all"];

function one(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

const factId = (f: ObservedFact) => `${f.source_key}|${f.subject_key}`;

function factColumns(names: () => SourceNames): Column<ObservedFact>[] {
  return [
    {
      id: "state",
      header: () => t("discovery.col.state"),
      width: 100,
      text: (f) => (isCurrent(f) ? t("discovery.fact.current") : t("discovery.fact.expired")),
      render: (f) => <FactState fact={f} />,
    },
    {
      id: "type",
      header: () => t("discovery.col.type"),
      width: 140,
      text: (f) => factTypeWord(f.observed.type),
      render: (f) => factTypeWord(f.observed.type),
    },
    {
      id: "observed",
      header: () => t("discovery.col.observed"),
      width: 360,
      fixed: true,
      text: (f) => observedText(f.observed),
      render: (f) => <span class="mono fact-observed">{observedText(f.observed)}</span>,
    },
    {
      id: "source",
      header: () => t("discovery.col.source"),
      width: 240,
      sort: "source",
      text: (f) => sourceText(f.source, names()),
      render: (f) => sourceText(f.source, names()),
    },
    {
      id: "subject",
      header: () => t("discovery.col.subject_key"),
      width: 220,
      sort: "subject",
      hidden: true,
      render: (f) => <span class="mono">{f.subject_key}</span>,
    },
    {
      id: "first_seen",
      header: () => t("discovery.col.first_seen"),
      width: 110,
      sort: "first_seen",
      render: (f) => <TimeAgo at={f.first_seen} />,
    },
    {
      id: "last_seen",
      header: () => t("discovery.col.last_seen"),
      width: 110,
      sort: "last_seen",
      render: (f) => <TimeAgo at={f.last_seen} />,
    },
    {
      id: "sightings",
      header: () => t("discovery.col.sightings"),
      width: 100,
      align: "right",
      render: (f) => <span class="num">{formatNumber(f.sightings ?? 1)}</span>,
    },
  ];
}

export default function ObservationsView() {
  const navigate = useNavigate();
  const [search, setSearch] = useSearchParams();
  const names = useSourceNames();

  const type = (): FactType | undefined => {
    const v = one(search.type);
    return v && (FACT_TYPES as readonly string[]).includes(v) ? (v as FactType) : undefined;
  };
  const currency = (): Currency => {
    const v = one(search.current);
    return v === "expired" || v === "all" ? v : "current";
  };
  const fixed = () => ({ source: one(search.source), mac: one(search.mac), ip: one(search.ip), within: one(search.within) });

  const [text, setText] = createSignal(one(search.q) ?? "");
  const [query, setQuery] = createSignal(one(search.q) ?? "");
  let typing: ReturnType<typeof setTimeout> | undefined;
  createEffect(
    on(
      text,
      (value) => {
        clearTimeout(typing);
        typing = setTimeout(() => {
          setQuery(value.trim());
          setSearch({ q: value.trim() || undefined }, { replace: true });
        }, 300);
      },
      { defer: true },
    ),
  );
  onCleanup(() => clearTimeout(typing));

  const [sort, setSort] = createSignal<SortState | null>(null);
  const source = createListSource<ObservedFact>({
    path: "/api/v1/observations",
    query: () => ({
      ...fixed(),
      q: query() || undefined,
      type: type(),
      current: currency() === "all" ? undefined : currency() === "current",
      sort: sortParam(sort()),
    }),
    rowId: factId,
    topics: ["discovery"],
  });

  const columns = factColumns(names);
  const columnState = createColumnState("observations", () => columns);

  const [lookup, setLookup] = createSignal("");
  const open = (fact: ObservedFact) => {
    const subject = lookupSubject(fact);
    if (subject) navigate(paths.observation(subject));
  };

  const applied = () =>
    (Object.entries(fixed()) as [string, string | undefined][])
      .filter((entry): entry is [string, string] => entry[1] !== undefined)
      // A source is a source key or a connector instance (the connector page links with its id).
      .map(([name, value]) => ({ name, value: name === "source" ? (names().connector(value) ?? sourceKeyText(value, names())) : value }));

  const onGridClick = (e: MouseEvent) => {
    const el = e.target as HTMLElement;
    if (el.closest("a, button, input, select, textarea")) return;
    const id = el.closest<HTMLElement>("tr[data-id]")?.dataset.id;
    const row = id ? source.rows().find((f) => factId(f) === id) : undefined;
    if (row) open(row);
  };

  return (
    <div class="page observations-page" data-testid="page-discovery-observations">
      <PageHead title={t("shell.nav.discovery")} sub={t("discovery.observations.sub")} />
      <DiscoveryNav />
      <form
        class="lookup page-section discovery-lookup"
        data-testid="discovery-lookup"
        onSubmit={(e) => {
          e.preventDefault();
          const value = lookup().trim();
          if (value) navigate(paths.observation(value));
        }}
      >
        <div class="field">
          <label for="obs-lookup">{t("discovery.lookup.label")}</label>
          <input
            id="obs-lookup"
            class="input mono"
            data-testid="field-subject"
            autocomplete="off"
            spellcheck={false}
            placeholder={t("discovery.lookup.placeholder")}
            value={lookup()}
            onInput={(e) => setLookup(e.currentTarget.value)}
          />
        </div>
        <button type="submit" class="btn" data-testid="form-submit" disabled={lookup().trim() === ""}>
          <Icon name="search" />
          {t("discovery.lookup.submit")}
        </button>
      </form>
      <FilterBar
        label={t("discovery.observations.filter_label")}
        placeholder={t("discovery.observations.filter_placeholder")}
        value={text()}
        onInput={setText}
        columns={columnState}
      >
        <span class="divider" />
        <For each={CURRENCIES}>
          {(c) => (
            <ToggleChip pressed={currency() === c} onToggle={() => setSearch({ current: c === "current" ? undefined : c })} testid={`filter-current-${c}`}>
              {t(`discovery.observations.${c}`)}
            </ToggleChip>
          )}
        </For>
        <span class="divider" />
        <For each={FACT_TYPES}>
          {(ft) => (
            <ToggleChip pressed={type() === ft} onToggle={() => setSearch({ type: type() === ft ? undefined : ft })} testid={`filter-type-${ft}`}>
              {factTypeWord(ft)}
            </ToggleChip>
          )}
        </For>
        <For each={applied()}>
          {(f) => (
            <span class="chip applied" data-testid={`filter-${f.name}`}>
              {f.value}
              <button
                type="button"
                class="chip-x"
                data-testid="filter-chip-remove"
                aria-label={t("discovery.filter.remove", { filter: f.value })}
                onClick={() => setSearch({ [f.name]: undefined })}
              >
                <Icon name="x" size="xs" />
              </button>
            </span>
          )}
        </For>
      </FilterBar>
      <div class="observations-grid" onClick={onGridClick}>
        <DataGrid
          id="observations"
          label={t("discovery.observations.grid_label")}
          columns={columns}
          columnState={columnState}
          rows={source.rows()}
          rowId={factId}
          rowKey={(f) => f.subject_key}
          rowLabel={(f) => observedText(f.observed)}
          noSelection
          sort={sort()}
          onSort={setSort}
          loading={source.loading()}
          initial={source.initial()}
          hasMore={source.hasMore()}
          onLoadMore={source.loadMore}
          error={source.error()}
          onRetry={source.reload}
          flashed={source.flashed}
          onOpen={open}
          onOpenPage={open}
          empty={
            <div class="empty" data-testid="observations-empty">
              <h3>{t("discovery.observations.empty")}</h3>
              <Show when={currency() === "current" && !query() && !type() && applied().length === 0}>
                <p>{t("discovery.observations.empty_body")}</p>
              </Show>
            </div>
          }
        />
      </div>
    </div>
  );
}
