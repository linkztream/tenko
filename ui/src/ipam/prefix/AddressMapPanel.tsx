// The address map of a network above its address grid (UI-Q3): reads the network's address
// objects, takes its ranges and the findings inside it from the pane, and draws the map in its
// own chunk so the first page load does not grow. Enter on a cell opens the address; on a block
// cell (a network larger than /22) it lists the block's addresses.
//
// The chunk and the addresses load into plain signals rather than through Suspense or a
// resource: the map is secondary to the grid and must never hold a navigation's transition.
import { useNavigate } from "@solidjs/router";
import { createEffect, createMemo, createSignal, on, onCleanup, Show, type Component } from "solid-js";
import { Dynamic } from "solid-js/web";
import { fetchAll } from "../../api/paginate";
import type { Range } from "../../api/types";
import { paths } from "../../app/paths";
import type { AddressMapProps } from "../../components/AddressMap";
import { mapLayout, type MapAddress, type MapFinding } from "../../components/addressMapCells";
import { ErrorNotice } from "../../components/Notice";
import { t } from "../../i18n";
import { rowAddress, type PrefixRow } from "../address/columns";

/** The most address objects the map reads; a fuller network is drawn with the first ones. */
export const MAP_ADDRESS_LIMIT = 20_000;

let mapModule: Promise<Component<AddressMapProps>> | undefined;
const loadMap = () => (mapModule ??= import("../../components/AddressMap").then((m) => m.default));

export function AddressMapPanel(props: {
  prefixId: string;
  cidr: string;
  /** Changes when the addresses may have changed (the grid's live reloads). */
  version: unknown;
  network: boolean;
  ranges: readonly Range[];
  findings: readonly MapFinding[];
}) {
  const navigate = useNavigate();
  const drawn = () => mapLayout(props.cidr).mode !== "none";
  const [map, setMap] = createSignal<Component<AddressMapProps> | null>(null);
  const [addresses, setAddresses] = createSignal<{ items: MapAddress[]; truncated: boolean } | null>(null);
  const [error, setError] = createSignal<unknown>(null);
  let alive = true;
  onCleanup(() => (alive = false));

  createEffect(() => {
    if (drawn() && !map()) void loadMap().then((c) => alive && setMap(() => c));
  });
  createEffect(
    on(
      () => [props.prefixId, props.version, drawn()] as const,
      ([id, , draw]) => {
        if (!draw) return;
        const controller = new AbortController();
        onCleanup(() => controller.abort());
        fetchAll<PrefixRow>("/api/v1/prefixes/{id}/addresses", { path: { id }, limit: 1000, max: MAP_ADDRESS_LIMIT, signal: controller.signal })
          .then((all) => {
            if (!alive || controller.signal.aborted) return;
            const items = all.items.map(rowAddress).flatMap((a) => (a && !a.meta.deleted ? [{ ip: a.ip, name: a.dns_name }] : []));
            setAddresses({ items, truncated: all.truncated });
            setError(null);
          })
          .catch((err: unknown) => {
            if (alive && !controller.signal.aborted) setError(err);
          });
      },
    ),
  );
  const ranges = createMemo(() => props.ranges.map((r) => ({ first: r.first, last: r.last, role: r.role })));

  return (
    <section class="map-panel" data-testid="address-map-panel" aria-labelledby="address-map-title">
      <h2 id="address-map-title">{t("ipam.map.title")}</h2>
      <Show when={error()}>
        <ErrorNotice error={error()} />
      </Show>
      <Show
        when={drawn()}
        fallback={
          <p class="amap-none muted" data-testid="address-map-none">
            {t("ipam.map.too_large")}
          </p>
        }
      >
        <Show when={map() && addresses()}>
          <Dynamic
            component={map()!}
            cidr={props.cidr}
            network={props.network}
            addresses={addresses()!.items}
            ranges={ranges()}
            findings={props.findings}
            onOpen={(ip: string) => navigate(paths.address(ip))}
            onOpenBlock={(cidr: string) => navigate(paths.addresses({ q: `within:${cidr}` }))}
          />
          <Show when={addresses()!.truncated}>
            <p class="muted">{t("ipam.map.partial", { count: MAP_ADDRESS_LIMIT })}</p>
          </Show>
        </Show>
      </Show>
    </section>
  );
}
