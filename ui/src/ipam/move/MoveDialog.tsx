// The keyboard twin of dragging onto the tree (M, "Move to network"): pick the target
// network from the networks of the VRF in view, then the move preview opens as a page.
import { useNavigate } from "@solidjs/router";
import { createMemo, createSignal, For, Show } from "solid-js";
import type { TreeNode, TreeResponse } from "../../api/types";
import { paths } from "../../app/paths";
import { Addr } from "../../components/Addr";
import { Dialog } from "../../components/Dialog";
import type { DragItem } from "../../grid/dnd";
import { UtilizationMeter } from "../../grid/cells";
import { t } from "../../i18n";

export function MoveDialog(props: {
  tree: TreeResponse | undefined;
  items: readonly DragItem[];
  onClose: () => void;
  /** Picks a network for something else than a move (the dashboard claim): no navigation. */
  onPick?: (node: TreeNode) => void;
  title?: string;
}) {
  const navigate = useNavigate();
  const [query, setQuery] = createSignal("");
  const [active, setActive] = createSignal(0);
  let input!: HTMLInputElement;

  const networks = createMemo(() => {
    const q = query().trim().toLowerCase();
    return (props.tree?.nodes ?? []).filter(
      (n) =>
        n.role === "network" &&
        (!q || n.cidr.toLowerCase().includes(q) || (n.description ?? "").toLowerCase().includes(q)),
    );
  });

  const choose = (n: TreeNode | undefined) => {
    if (!n) return;
    if (props.onPick) {
      props.onPick(n);
      return;
    }
    // Read the items first: closing may unmount the owner that provides them.
    const objects = props.items.map((i) => ({ kind: i.kind, id: i.id }));
    props.onClose();
    navigate(paths.move(n.id, objects));
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(networks().length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      choose(networks()[active()]);
    }
  };

  return (
    <Dialog label={props.title ?? t("ipam.move.choose_title", { count: props.items.length })} onClose={props.onClose} class="dialog move-dialog" initialFocus={() => input}>
      <div data-testid="dialog-move-target">
        <h2 class="dialog-title">{props.title ?? t("ipam.move.choose_title", { count: props.items.length })}</h2>
        <Show when={!props.onPick}>
          <p class="muted">{t("ipam.move.choose_body")}</p>
        </Show>
        <input
          ref={input}
          class="input"
          value={query()}
          placeholder={t("ipam.tree.filter")}
          aria-label={t("ipam.tree.filter")}
          role="combobox"
          aria-expanded="true"
          aria-controls="move-targets"
          aria-activedescendant={networks().length ? `move-target-${active()}` : undefined}
          onInput={(e) => {
            setQuery(e.currentTarget.value);
            setActive(0);
          }}
          onKeyDown={onKeyDown}
        />
        <ul class="move-targets" id="move-targets" role="listbox" aria-label={t("ipam.tree.label")}>
          <For each={networks()}>
            {(n, i) => (
              <li
                id={`move-target-${i()}`}
                role="option"
                aria-selected={i() === active()}
                data-key={n.cidr}
                onMouseMove={() => setActive(i())}
                onClick={() => choose(n)}
              >
                <Addr value={n.cidr} />
                <span class="muted">{n.description ?? ""}</span>
                <UtilizationMeter percent={n.utilization.percent} level={n.level} compact />
              </li>
            )}
          </For>
        </ul>
        <Show when={networks().length === 0}>
          <p class="muted">{t("ipam.move.no_target")}</p>
        </Show>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
        </div>
      </div>
    </Dialog>
  );
}
