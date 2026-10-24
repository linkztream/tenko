// The node choice the query log and the cache view of the DNS area share: the nodes whose DNS
// role may be read, the node chosen, and the select that chooses it. The choice is held for the
// session, outside the pages, so moving from the log to the cache (and back) keeps the node.
import { createMemo, createResource, createSignal, For } from "solid-js";
import { t } from "../i18n";
import { logNodes } from "./log/api";

const [chosen, choose] = createSignal<number>();

export function useDnsNode() {
  const [nodes] = createResource(() => logNodes());
  // A node no longer in the list gives way to the first one.
  const node = createMemo(() => {
    const list = nodes.latest;
    const id = chosen();
    return id !== undefined && list?.includes(id) ? id : list?.[0];
  });
  return { nodes, node, choose };
}

export function NodeSelect(props: { nodes: readonly number[]; node: number | undefined; onChoose: (id: number) => void }) {
  return (
    <div class="dns-node">
      <label for="dns-node">{t("dns.log.node_label")}</label>
      <select id="dns-node" class="select" data-testid="field-node" value={String(props.node ?? "")} onChange={(e) => props.onChoose(Number(e.currentTarget.value))}>
        <For each={props.nodes}>{(id) => <option value={String(id)}>{t("dns.log.node", { id })}</option>}</For>
      </select>
    </div>
  );
}
