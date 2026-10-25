// The other writes of the host lifecycle that go through the plan dialog: reinstating one host
// or the selection, and deleting the selection (decommissioned hosts are cleaned up in a batch).
import { createSignal, For, Show } from "solid-js";
import type { Host } from "../api/types";
import { t } from "../i18n";
import { PlanDialog, type WriteLike } from "../ipam/plan/PlanDialog";
import { bulkDelete, bulkReinstate, reinstateHost } from "./lifecycle";
import "../ipam/forms.css";

type Target = Pick<Host, "id" | "name"> & { meta: Pick<Host["meta"], "revision"> };

function Names(props: { hosts: readonly Pick<Host, "name">[] }) {
  return (
    <ul class="plain-list mono">
      <For each={props.hosts.slice(0, 12)}>{(h) => <li>{h.name}</li>}</For>
    </ul>
  );
}

export function reinstateTitle(hosts: readonly Pick<Host, "name">[]): string {
  return hosts.length === 1 ? t("hosts.reinstate.title", { name: hosts[0]?.name ?? "" }) : t("hosts.bulk.reinstate_title", { count: hosts.length });
}

/** Reinstates hosts: the addresses they released that are still free are bound again. */
export function ReinstateDialog(props: { hosts: readonly Target[]; onDone: (result: WriteLike) => void; onClose: () => void }) {
  const title = () => reinstateTitle(props.hosts);
  return (
    <PlanDialog<WriteLike>
      title={title()}
      confirmLabel={title()}
      testid="dialog-reinstate"
      intro={
        <>
          <p class="muted">{t("hosts.reinstate.intro")}</p>
          <Show when={props.hosts.length > 1}>
            <Names hosts={props.hosts} />
          </Show>
        </>
      }
      send={(o) => (props.hosts.length === 1 ? reinstateHost(props.hosts[0] as Target, o) : bulkReinstate(props.hosts, o))}
      onDone={props.onDone}
      onClose={props.onClose}
    />
  );
}

/** Deletes the selected hosts; with the check box what they contain goes along. */
export function DeleteManyDialog(props: { hosts: readonly Target[]; onDone: (result: WriteLike) => void; onClose: () => void }) {
  const [cascade, setCascade] = createSignal(false);
  const title = () => t("hosts.bulk.delete_title", { count: props.hosts.length });
  // The preview is for one choice of the check box: a new choice is a new dialog.
  return (
    <Show when={{ cascade: cascade() }} keyed>
      {(choice) => (
        <PlanDialog<WriteLike>
          title={title()}
          confirmLabel={title()}
          danger
          testid="dialog-hosts-delete"
          intro={
            <>
              <Names hosts={props.hosts} />
              <label class="delete-cascade">
                <input
                  type="checkbox"
                  class="cb"
                  checked={choice.cascade}
                  data-testid="delete-cascade"
                  onChange={(e) => setCascade(e.currentTarget.checked)}
                />
                {t("ipam.delete.cascade")}
              </label>
            </>
          }
          send={(o) => bulkDelete(props.hosts, choice.cascade, o)}
          onDone={props.onDone}
          onClose={props.onClose}
        />
      )}
    </Show>
  );
}
