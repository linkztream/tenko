// The delegation pools of a DHCPv6 scope (WP9.2): a section of the pools tab, below the address
// pools, that lists the IPAM ranges of the role Delegation pool with the length of the prefixes they
// hand to routers, how many prefixes that is and how many are bound, and adds one. A pool is
// moved, changed and deleted on the page of the network in IPAM.
import { createSignal, Show } from "solid-js";
import { Icon } from "../../components/Icon";
import { DataGrid } from "../../grid/DataGrid";
import type { Column } from "../../grid/types";
import { formatDuration, formatNumber, t } from "../../i18n";
import { may } from "../../auth/gate";
import { mayWriteDhcp } from "../access";
import type { Pool, Scope } from "../api";
import { PdPoolDialog } from "./PdPoolDialog";

/** The lease time a delegation pool hands out with: its range's, else the scope's. */
function pdLease(pool: Pool): string {
  return pool.lease_secs ? t("dhcp.pool.lease_range", { lease: formatDuration(pool.lease_secs) }) : t("dhcp.pool.lease_scope");
}

export function PdPools(props: {
  scope: Scope;
  /** The delegation pools of the scope. */
  pools: readonly Pool[];
  loading?: boolean | undefined;
  /** Nothing has been read yet. */
  initial?: boolean | undefined;
  error?: unknown;
  onRetry?: (() => void) | undefined;
  /** A pool was added: read the list again. */
  onChanged: () => void;
}) {
  const [adding, setAdding] = createSignal(false);
  const mayAdd = () => mayWriteDhcp() && may.prefix(props.scope.prefix);
  const columns: Column<Pool>[] = [
    {
      id: "range",
      header: () => t("dhcp.col.range"),
      width: 330,
      fixed: true,
      text: (p) => `${p.first} – ${p.last}`,
      render: (p) => (
        <span class="mono" data-testid="pd-pool-row" data-key={`${p.first}-${p.last}`}>{`${p.first} – ${p.last}`}</span>
      ),
    },
    {
      id: "len",
      header: () => t("dhcp.pd.col.len"),
      width: 130,
      align: "right",
      text: (p) => (p.delegated_len == null ? "" : `/${p.delegated_len}`),
      render: (p) => (
        <span class="num mono" data-testid="pd-pool-len" data-value={String(p.delegated_len ?? "")}>
          {p.delegated_len == null ? "" : `/${p.delegated_len}`}
        </span>
      ),
    },
    {
      id: "size",
      header: () => t("dhcp.pd.col.size"),
      width: 110,
      align: "right",
      text: (p) => String(p.size),
      render: (p) => (
        <span class="num" data-testid="pd-pool-size" data-value={String(p.size)}>
          {formatNumber(p.size)}
        </span>
      ),
    },
    {
      id: "leased",
      header: () => t("dhcp.pd.col.leased"),
      width: 100,
      align: "right",
      text: (p) => String(p.leased),
      render: (p) => (
        <span class="num" data-testid="pd-pool-leased" data-value={String(p.leased)}>
          {formatNumber(p.leased)}
        </span>
      ),
    },
    { id: "lease", header: () => t("dhcp.col.lease"), text: pdLease, render: (p) => <span>{pdLease(p)}</span> },
  ];
  return (
    <section class="dhcp-pd" aria-labelledby="dhcp-pd-title" data-testid="pd-pools">
      <div class="dhcp-section-head">
        <h2 id="dhcp-pd-title">{t("dhcp.pd.title")}</h2>
        <Show when={mayAdd()}>
          <button type="button" class="btn primary" data-testid="pd-pool-add" onClick={() => setAdding(true)}>
            <Icon name="plus" />
            {t("dhcp.pd.add")}
          </button>
        </Show>
      </div>
      <p class="muted">{t("dhcp.pd.note")}</p>
      <div class="dhcp-box dhcp-pd-box">
        <DataGrid
          id="dhcp-pd-pools"
          label={t("dhcp.pd.title")}
          noSelection
          columns={columns}
          rows={[...props.pools]}
          rowId={(p) => p.range}
          rowKey={(p) => `${p.first}-${p.last}`}
          rowLabel={(p) => `${p.first} – ${p.last}`}
          loading={props.loading}
          initial={props.initial}
          error={props.error}
          onRetry={props.onRetry}
          empty={
            <div class="empty" data-testid="pd-pools-empty">
              <h3>{t("dhcp.pd.empty")}</h3>
              <p>{t("dhcp.pd.empty_body")}</p>
            </div>
          }
        />
      </div>
      <Show when={adding()}>
        <PdPoolDialog
          scope={props.scope}
          onClose={() => setAdding(false)}
          onDone={() => {
            setAdding(false);
            props.onChanged();
          }}
        />
      </Show>
    </section>
  );
}
