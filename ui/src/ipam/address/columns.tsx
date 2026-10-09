// Columns of the address grids (the addresses of a prefix and the global address list).
// The lists are read with `expand=host`, so host, mode and MAC come with every bound row;
// a free gap of a prefix is a full-width row.
import { A } from "@solidjs/router";
import { Show } from "solid-js";
import type { AddressRow as Row, PrefixAddressItem } from "../../api/types";
import { paths } from "../../app/paths";
import { Addr, Mac } from "../../components/Addr";
import { DeletedTag, DnsName, LockFlag, ModeBadge, StatusBadge, Tags, TimeAgo } from "../../grid/cells";
import type { Column } from "../../grid/types";
import { t } from "../../i18n";

/** A row of a prefix's address list: an address, or a free gap. */
export type PrefixRow = PrefixAddressItem;

export function rowAddress(row: PrefixRow): Row | null {
  return row.type === "address" ? row.data : null;
}

export function addressRowId(row: PrefixRow): string {
  return row.type === "address" ? row.data.id : `free:${row.data.first}`;
}

export function addressRowKey(row: PrefixRow): string {
  return row.type === "address" ? row.data.ip : row.data.first;
}

function HostCell(props: { address: Row }) {
  return (
    <Show when={props.address.host}>
      {(host) => (
        <A href={paths.host(host().name)} tabIndex={-1} class="hostname">
          {host().name}
        </A>
      )}
    </Show>
  );
}

function ModeCell(props: { address: Row }) {
  return (
    <Show when={props.address.host}>
      {(host) => (
        <>
          <ModeBadge mode={host().mode} /> <LockFlag locked={host().lock} />
        </>
      )}
    </Show>
  );
}

function MacCell(props: { address: Row }) {
  return <Show when={props.address.interface_detail?.mac}>{(mac) => <Mac value={mac()} />}</Show>;
}

/** The address when it is bound to an interface (the host columns need one). */
function bound(a: Row | null): Row | undefined {
  return a?.interface ? a : undefined;
}

export interface AddressColumnOptions {
  /** The prefix length, so the emphasized host part splits at the right octet. */
  prefixLength?: number;
  /** Adds the prefix and VRF columns (the global list). */
  withPrefix?: (address: Row) => string | undefined;
}

/** The columns for rows of type T, given how a row yields its address. */
export function addressColumns<T>(get: (row: T) => Row | null, options: AddressColumnOptions = {}): Column<T>[] {
  const cols: Column<T>[] = [
    {
      id: "ip",
      header: () => t("ipam.col.address"),
      width: 150,
      sort: "ip",
      fixed: true,
      text: (r) => get(r)?.ip ?? "",
      render: (r) => <Show when={get(r)}>{(a) => <Addr value={a().ip} prefixLength={options.prefixLength} />}</Show>,
    },
    {
      id: "dns_name",
      header: () => t("ipam.col.dns_name"),
      sort: "dns_name",
      text: (r) => get(r)?.dns_name ?? "",
      editable: (r) => !!get(r) && !get(r)?.meta.deleted,
      render: (r) => <DnsName name={get(r)?.dns_name} />,
    },
    {
      id: "host",
      header: () => t("ipam.col.host"),
      width: 150,
      render: (r) => <Show when={bound(get(r))}>{(a) => <HostCell address={a()} />}</Show>,
    },
    {
      id: "mode",
      header: () => t("ipam.col.mode"),
      width: 130,
      render: (r) => <Show when={bound(get(r))}>{(a) => <ModeCell address={a()} />}</Show>,
    },
    {
      id: "mac",
      header: () => t("ipam.col.mac"),
      width: 156,
      render: (r) => <Show when={bound(get(r))}>{(a) => <MacCell address={a()} />}</Show>,
    },
    {
      id: "status",
      header: () => t("ipam.col.status"),
      width: 110,
      sort: "status",
      text: (r) => get(r)?.status ?? "",
      render: (r) => (
        <Show when={get(r)}>
          {(a) => (
            <>
              <StatusBadge status={a().status} /> <DeletedTag deleted={a().meta.deleted} />
            </>
          )}
        </Show>
      ),
    },
    {
      id: "tags",
      header: () => t("ipam.col.tags"),
      width: 160,
      hidden: true,
      render: (r) => <Tags tags={get(r)?.meta.tags} />,
    },
    {
      id: "updated",
      header: () => t("ipam.col.updated"),
      width: 120,
      sort: "updated",
      hidden: true,
      render: (r) => <TimeAgo at={get(r)?.meta.updated.at} />,
    },
  ];
  if (options.withPrefix) {
    const prefixOf = options.withPrefix;
    const prefixCidr = (a: Row | null) => (a ? prefixOf(a) : undefined);
    cols.splice(1, 0, {
      id: "prefix",
      header: () => t("ipam.col.prefix"),
      width: 160,
      render: (r) => <Show when={prefixCidr(get(r))}>{(cidr) => <Addr value={cidr()} />}</Show>,
    });
  }
  return cols;
}
