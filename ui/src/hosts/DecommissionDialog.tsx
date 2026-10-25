// Decommissioning hosts: a first step asks for an optional reason and whether the DNS names of
// the released addresses stay; the second is the plan dialog (a dry run with what changes, then
// the apply at the revision of each host). Used by the hosts list (one host or the selection),
// the host page and the Discovery page.
import { createSignal, Show } from "solid-js";
import type { Host } from "../api/types";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import { PlanDialog, type WriteLike } from "../ipam/plan/PlanDialog";
import { bulkDecommission, decommissionHost, MAX_REASON_BYTES, reasonBytes, type DecommissionChoice } from "./lifecycle";
import "../ipam/forms.css";

type Target = Pick<Host, "id" | "name"> & { meta: Pick<Host["meta"], "revision"> };

/** The title of the dialog: the name of one host, or how many hosts. */
export function decommissionTitle(hosts: readonly Pick<Host, "name">[]): string {
  return hosts.length === 1 ? t("hosts.decommission.title", { name: hosts[0]?.name ?? "" }) : t("hosts.bulk.decommission_title", { count: hosts.length });
}

export function DecommissionDialog(props: { hosts: readonly Target[]; onDone: (result: WriteLike) => void; onClose: () => void }) {
  const [choice, setChoice] = createSignal<DecommissionChoice | null>(null);
  const title = () => decommissionTitle(props.hosts);
  return (
    <Show when={choice()} keyed fallback={<ChoiceForm title={title()} count={props.hosts.length} onSubmit={setChoice} onClose={props.onClose} />}>
      {(picked) => (
        <PlanDialog<WriteLike>
          title={title()}
          confirmLabel={title()}
          danger
          testid="dialog-decommission-plan"
          intro={
            <>
              <Show when={picked.reason.trim() !== ""}>
                <p class="muted" data-testid="decommission-reason-shown">
                  {picked.reason.trim()}
                </p>
              </Show>
              <p class="muted">{picked.keepDns ? t("hosts.decommission.dns_kept") : t("hosts.decommission.dns_removed")}</p>
            </>
          }
          send={(o) => (props.hosts.length === 1 ? decommissionHost(props.hosts[0] as Target, picked, o) : bulkDecommission(props.hosts, picked, o))}
          onDone={props.onDone}
          onClose={props.onClose}
        />
      )}
    </Show>
  );
}

function ChoiceForm(props: { title: string; count: number; onSubmit: (choice: DecommissionChoice) => void; onClose: () => void }) {
  const [reason, setReason] = createSignal("");
  const [keepDns, setKeepDns] = createSignal(false);
  const tooLong = () => reasonBytes(reason()) > MAX_REASON_BYTES;
  return (
    <Dialog label={props.title} onClose={props.onClose} class="dialog form-dialog">
      <form
        class="form"
        data-testid="dialog-decommission"
        onSubmit={(e) => {
          e.preventDefault();
          if (!tooLong()) props.onSubmit({ reason: reason(), keepDns: keepDns() });
        }}
      >
        <h2 class="dialog-title">{props.title}</h2>
        <p>{props.count === 1 ? t("hosts.decommission.intro") : t("hosts.decommission.intro_many")}</p>
        <div class="field">
          <label for="decommission-reason">{t("hosts.decommission.reason")}</label>
          <textarea
            id="decommission-reason"
            class="input"
            rows={3}
            value={reason()}
            data-testid="decommission-reason"
            aria-invalid={tooLong() ? "true" : undefined}
            aria-describedby="decommission-reason-help"
            onInput={(e) => setReason(e.currentTarget.value)}
          />
          <small id="decommission-reason-help" class={tooLong() ? "help bad" : "help"}>
            <Show when={tooLong()} fallback={t("hosts.decommission.reason_hint", { max: MAX_REASON_BYTES })}>
              <Icon name="alert" size="xs" /> {t("hosts.decommission.reason_too_long", { max: MAX_REASON_BYTES })}
            </Show>
          </small>
        </div>
        <div class="field">
          <label class="ackrow">
            <input
              type="checkbox"
              class="cb"
              checked={keepDns()}
              aria-describedby="decommission-dns-help"
              data-testid="decommission-keep-dns"
              onChange={(e) => setKeepDns(e.currentTarget.checked)}
            />
            {t("hosts.decommission.keep_dns")}
          </label>
          <small id="decommission-dns-help" class="help">
            {t("hosts.decommission.keep_dns_hint")}
          </small>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" disabled={tooLong()} data-testid="form-submit">
            {t("hosts.decommission.review")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
