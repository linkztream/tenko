// The address map of a prefix (UI-Q3 of the UI plan, design/README.md "Address map"): one CSS
// grid cell per address for a prefix of up to 1,024 addresses, one cell per block of 256 above
// that (addressMapCells.ts). A cell is colored only where a finding sits, in its severity's fill with
// the paired `-on` token for the digits (4.5:1, AddressMap.contrast.test.ts); the other states
// are quiet fills with ordinary ink, so free runs stand out as the empty cells. The 11 px digits
// are the last octet (the last digits of the last hextet for IPv6), or the block's in-use count.
//
// Keyboard: the map is one tab stop (a WAI-ARIA grid with a roving tab index); the arrows move,
// Home and End go to the start and end of the row, Ctrl+Home and Ctrl+End to the first and last
// cell, Enter opens the address (or the block's addresses). Hover and focus say the address and
// its state in the readout under the map. No chart library; the route loads it as its own chunk.
import { createMemo, createSignal, For, Show } from "solid-js";
import { t } from "../i18n";
import {
  addressCells,
  blockCells,
  mapLayout,
  type AddressCell,
  type BlockCell,
  type CellState,
  type MapAddress,
  type MapFinding,
  type MapRange,
  type Severity,
} from "./addressMapCells";
import "./address-map.css";

export interface AddressMapProps {
  cidr: string;
  /** Whether the prefix is a network (its edge addresses are never usable). */
  network?: boolean;
  addresses: readonly MapAddress[];
  ranges: readonly MapRange[];
  findings: readonly MapFinding[];
  onOpen?: (ip: string) => void;
  onOpenBlock?: (cidr: string) => void;
}

type Cell = AddressCell | BlockCell;

const stateWord = (state: CellState) => t(`ipam.map.state.${state}`);
const severityWord = (severity: Severity) => t(`ipam.map.severity.${severity}`);

function cellLabel(cell: Cell): string {
  if (cell.kind === "block") {
    return t("ipam.map.block_cell", { cidr: cell.cidr, in_use: cell.inUse, size: cell.size, findings: cell.findings });
  }
  return cell.severity
    ? t("ipam.map.cell_finding", { ip: cell.ip, state: stateWord(cell.state), severity: severityWord(cell.severity) })
    : t("ipam.map.cell", { ip: cell.ip, state: stateWord(cell.state) });
}

export default function AddressMap(props: AddressMapProps) {
  const layout = createMemo(() => mapLayout(props.cidr));
  const cells = createMemo<Cell[]>(() => {
    const l = layout();
    if (l.mode === "addresses") return addressCells(props.cidr, props.addresses, props.ranges, props.findings, { network: props.network });
    if (l.mode === "blocks") return blockCells(props.cidr, props.addresses, props.ranges, props.findings);
    return [];
  });
  const columns = () => (layout().mode === "none" ? 1 : (layout() as { columns: number }).columns);
  const rows = createMemo(() => {
    const all = cells();
    const n = columns();
    const out: { index: number; cells: { cell: Cell; index: number }[] }[] = [];
    for (let r = 0; r * n < all.length; r++) {
      out.push({ index: r, cells: all.slice(r * n, r * n + n).map((cell, c) => ({ cell, index: r * n + c })) });
    }
    return out;
  });
  const [active, setActive] = createSignal(0);
  const [shown, setShown] = createSignal<number | null>(null);
  let grid!: HTMLDivElement;
  const cellId = (i: number) => `amap-${props.cidr.replace(/[^0-9a-f]/gi, "-")}-${i}`;

  const focusCell = (i: number) => {
    const n = cells().length;
    if (n === 0) return;
    const next = Math.max(0, Math.min(n - 1, i));
    setActive(next);
    setShown(next);
    grid.querySelector<HTMLElement>(`#${cellId(next)}`)?.focus();
  };
  const open = (cell: Cell) => {
    if (cell.kind === "address") props.onOpen?.(cell.ip);
    else props.onOpenBlock?.(cell.cidr);
  };
  const onKeyDown = (e: KeyboardEvent) => {
    const i = active();
    const n = columns();
    const rtl = getComputedStyle(grid).direction === "rtl";
    const step = rtl ? -1 : 1;
    switch (e.key) {
      case "ArrowRight":
        focusCell(i + step);
        break;
      case "ArrowLeft":
        focusCell(i - step);
        break;
      case "ArrowDown":
        focusCell(i + n);
        break;
      case "ArrowUp":
        focusCell(i - n);
        break;
      case "Home":
        focusCell(e.ctrlKey ? 0 : i - (i % n));
        break;
      case "End":
        focusCell(e.ctrlKey ? cells().length - 1 : i - (i % n) + n - 1);
        break;
      case "Enter": {
        const cell = cells()[i];
        if (cell) open(cell);
        break;
      }
      default:
        return;
    }
    e.preventDefault();
  };

  const classOf = (cell: Cell) => {
    if (cell.kind === "block") return { block: true, used: cell.inUse > 0, [`sev-${cell.severity}`]: !!cell.severity };
    return { [cell.state]: true, [`sev-${cell.severity}`]: !!cell.severity };
  };
  const readout = () => {
    const i = shown();
    return i === null ? undefined : cells()[i];
  };

  return (
    <Show
      when={layout().mode !== "none"}
      fallback={<p class="amap-none muted" data-testid="address-map-none">{t("ipam.map.too_large")}</p>}
    >
      <div class="amap-wrap" data-testid="address-map" data-mode={layout().mode}>
        <ul class="amap-legend" aria-label={t("ipam.map.legend")}>
          <Show when={layout().mode === "addresses"}>
            <li>
              <span class="sw used" aria-hidden="true" />
              {stateWord("used")}
            </li>
            <li>
              <span class="sw held" aria-hidden="true" />
              {stateWord("held")}
            </li>
            <li>
              <span class="sw free" aria-hidden="true" />
              {stateWord("free")}
            </li>
            <Show when={props.network !== false}>
              <li>
                <span class="sw edge" aria-hidden="true" />
                {stateWord("edge")}
              </li>
            </Show>
          </Show>
          <li>
            <span class="sw sev-act" aria-hidden="true" />
            {severityWord("act")}
          </li>
          <li>
            <span class="sw sev-review" aria-hidden="true" />
            {severityWord("review")}
          </li>
          <li>
            <span class="sw sev-info" aria-hidden="true" />
            {severityWord("info")}
          </li>
        </ul>
        <div
          ref={grid}
          class="amap"
          role="grid"
          aria-label={
            layout().mode === "blocks"
              ? t("ipam.map.label_blocks", { cidr: props.cidr, count: cells().length, columns: columns() })
              : t("ipam.map.label", { cidr: props.cidr, count: cells().length, columns: columns() })
          }
          style={{ "--amap-columns": columns() }}
          onKeyDown={onKeyDown}
          onMouseLeave={() => setShown(null)}
        >
          <For each={rows()}>
            {(row) => (
              <div role="row" class="amap-row">
                <For each={row.cells}>
                  {({ cell, index }) => (
                    <span
                      role="gridcell"
                      id={cellId(index)}
                      class="amap-cell"
                      classList={classOf(cell)}
                      tabIndex={index === active() ? 0 : -1}
                      aria-label={cellLabel(cell)}
                      data-testid="amap-cell"
                      data-state={cell.kind === "address" ? cell.state : cell.inUse > 0 ? "used" : "free"}
                      data-severity={cell.severity}
                      onMouseEnter={() => setShown(index)}
                      onFocus={() => {
                        setActive(index);
                        setShown(index);
                      }}
                      onClick={() => {
                        setActive(index);
                        open(cell);
                      }}
                    >
                      {cell.kind === "address" ? cell.digits : cell.inUse}
                    </span>
                  )}
                </For>
              </div>
            )}
          </For>
        </div>
        <p class="amap-readout" aria-live="polite" data-testid="address-map-readout">
          <Show when={readout()} keyed fallback={<span class="muted">{t("ipam.map.hint")}</span>}>
            {(c) => {
              return c.kind === "address" ? (
                <>
                  <span class="mono">{c.ip}</span>
                  <span>{stateWord(c.state)}</span>
                  <Show when={c.name}>
                    <span class="mono">{c.name}</span>
                  </Show>
                  <For each={c.findings}>
                    {(f) => (
                      <span class={`sev sev-${f.severity}`}>
                        {severityWord(f.severity)}: {f.label}
                      </span>
                    )}
                  </For>
                </>
              ) : (
                <>
                  <span class="mono">{c.cidr}</span>
                  <span>{t("ipam.map.block_in_use", { in_use: c.inUse, size: c.size })}</span>
                  <Show when={c.findings > 0}>
                    <span class={`sev sev-${c.severity}`}>{t("ipam.map.block_findings", { count: c.findings })}</span>
                  </Show>
                </>
              );
            }}
          </Show>
        </p>
      </div>
    </Show>
  );
}
