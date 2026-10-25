// What a person can do about an address conflict besides dismissing it, in the proposal panel:
// decommission one of the hosts in the conflict (its addresses are released, its facts raise no
// more proposals), or keep both (the conflict is closed as it stands). A host whose claim comes
// only from a stopped guest is offered first, as the usual way out. Both need the right of
// deciding the proposal; decommissioning a host needs the right to delete that host.
import { createResource, createSignal, For, Show } from "solid-js";
import { may } from "../auth/gate";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { DecommissionDialog, decommissionTitle } from "../hosts/DecommissionDialog";
import { readHost } from "../hosts/lifecycle";
import { t } from "../i18n";
import { useWriteToast } from "../ipam/plan/PlanDialog";
import { toast } from "../components/toast";
import { MAX_REASON_BYTES, type Proposal } from "./api";
import { conflictHosts, isAddressConflict, keepProposal } from "./conflicts";
import type { Host } from "../api/types";
import "./conflicts.css";

type Open = { kind: "decommission"; host: Host } | { kind: "keep" } | null;

function bytes(text: string): number {
  return new TextEncoder().encode(text.trim()).length;
}

export function AddressConflictActions(props: { proposal: Proposal }) {
  const writeToast = useWriteToast();
  const [dialog, setDialog] = createSignal<Open>(null);
  const ids = () => conflictHosts(props.proposal);
  // The hosts as they are now, the one with only a dormant claim first; a host that cannot be read has no button.
  const [hosts, { refetch }] = createResource(
    () => (isAddressConflict(props.proposal) ? ids().hosts.join(",") : false),
    async (key) => {
      const read = await Promise.all(key.split(",").map((id) => readHost(id)));
      const dormant = new Set(ids().dormant);
      const found = read.filter((h): h is Host => h !== null);
      return [...found.filter((h) => dormant.has(h.id)), ...found.filter((h) => !dormant.has(h.id))];
    },
  );
  const dormant = (h: Host) => ids().dormant.includes(h.id);
  const offered = (h: Host) => !h.decommissioned && !h.meta.deleted && may.host(h);

  return (
    <Show when={isAddressConflict(props.proposal)}>
      <For each={hosts.latest ?? []}>
        {(h) => (
          <Show when={offered(h)}>
            <span class="conflict-host">
              <button
                type="button"
                class={dormant(h) ? "btn primary" : "btn"}
                data-testid="conflict-decommission"
                data-host={h.id}
                data-dormant={dormant(h) ? "true" : "false"}
                onClick={() => setDialog({ kind: "decommission", host: h })}
              >
                <Icon name="clock" />
                {t("discovery.conflict.decommission", { name: h.name })}
              </button>
              <Show when={dormant(h)}>
                <span class="muted conflict-why" data-testid="conflict-dormant">
                  {t("discovery.conflict.dormant")}
                </span>
              </Show>
            </span>
          </Show>
        )}
      </For>
      <button type="button" class="btn" data-testid="conflict-keep" onClick={() => setDialog({ kind: "keep" })}>
        <Icon name="check" />
        {t("discovery.conflict.keep")}
      </button>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "decommission" ? (
            <DecommissionDialog
              hosts={[d.host]}
              onClose={() => setDialog(null)}
              onDone={(r) => {
                setDialog(null);
                writeToast(decommissionTitle([d.host]), r);
                void refetch();
              }}
            />
          ) : (
            <KeepBothDialog
              proposal={props.proposal}
              onClose={() => setDialog(null)}
              onDone={() => {
                setDialog(null);
                toast({ kind: "ok", title: t("discovery.conflict.kept") });
              }}
            />
          )
        }
      </Show>
    </Show>
  );
}

/** Keeps both claims, with an optional reason (the pattern of the reject dialog). */
function KeepBothDialog(props: { proposal: Proposal; onDone: () => void; onClose: () => void }) {
  const [reason, setReason] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const tooLong = () => bytes(reason()) > MAX_REASON_BYTES;

  const submit = async (e: Event) => {
    e.preventDefault();
    if (tooLong() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      await keepProposal(props.proposal, reason());
      props.onDone();
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("discovery.conflict.keep_title")} onClose={props.onClose} class="dialog discovery-dialog">
      <form class="discovery-form" data-testid="dialog-keep" onSubmit={(e) => void submit(e)}>
        <h2 class="dialog-title">{t("discovery.conflict.keep_title")}</h2>
        <p>{t("discovery.conflict.keep_body")}</p>
        <div class="field">
          <label for="keep-reason">{t("discovery.reject.reason")}</label>
          <textarea
            id="keep-reason"
            class="input"
            rows={3}
            value={reason()}
            data-testid="keep-reason"
            aria-invalid={tooLong() ? "true" : undefined}
            aria-describedby="keep-reason-help"
            onInput={(e) => setReason(e.currentTarget.value)}
          />
          <small id="keep-reason-help" class={tooLong() ? "help bad" : "help"}>
            <Show when={tooLong()} fallback={t("discovery.reject.reason_hint")}>
              <Icon name="alert" size="xs" /> {t("discovery.reject.reason_too_long", { max: MAX_REASON_BYTES })}
            </Show>
          </small>
        </div>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" disabled={busy() || tooLong()} data-testid="form-submit">
            {t("discovery.conflict.keep")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
