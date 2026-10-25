// The release of a lease (WP7.5): a confirmation with an optional reason for the audit record. The
// server refuses a lease that is not active (409) or has gone (404); its message stays in the
// dialog and the list is read again, so the row shows what the server has.
import { createSignal } from "solid-js";
import { ApiError } from "../../api/problem";
import { ConfirmDialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { releaseLease } from "./api";
import { clientMac, colons, displayAddr, type Lease } from "./model";

export function ReleaseDialog(props: { lease: Lease; onClose: () => void; onDone: () => void; onRefused: () => void }) {
  const [reason, setReason] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  // WP9.2: a delegated prefix is named with its length; the release itself goes by the first address.
  const shown = () => displayAddr(props.lease);
  // A client with a MAC address is named by it; a DHCPv6 client whose DUID holds none, by the DUID.
  const body = () => {
    const mac = clientMac(props.lease);
    return mac !== "" || !props.lease.duid
      ? t("dhcp.lease.release_body", { addr: shown(), mac })
      : t("dhcp.leases6.release_body_duid", { addr: shown(), duid: colons(props.lease.duid) });
  };
  return (
    <ConfirmDialog
      title={t("dhcp.lease.release_title", { addr: shown() })}
      testid="dialog-lease-release"
      danger
      busy={busy()}
      confirmLabel={t("dhcp.lease.release_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        if (busy()) return;
        setBusy(true);
        setError(undefined);
        releaseLease(props.lease, reason())
          .then(() => {
            toast({ kind: "ok", title: t("dhcp.lease.released", { addr: shown() }) });
            props.onDone();
          })
          .catch((err: unknown) => {
            setError(err);
            if (err instanceof ApiError && (err.code === "dhcp.lease.state" || err.code === "dhcp.lease.not_found")) props.onRefused();
          })
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p data-testid="release-body">{body()}</p>
          <div class="field dhcp-reason">
            <label for="dhcp-lease-reason">{t("dhcp.lease.reason")}</label>
            <input
              id="dhcp-lease-reason"
              class="input"
              value={reason()}
              autocomplete="off"
              data-testid="field-reason"
              onInput={(e) => setReason(e.currentTarget.value)}
            />
            <span class="help">{t("dhcp.lease.reason_help")}</span>
          </div>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}
