// Integration certificates (ADR 0035, docs/integrations.md): one row per enrolled host with
// the state of its certificate at a glance (active, expiring, lapsed, revoked), the enrollment
// codes that still wait, a dialog that makes a code (shown once), and revocation, confirmed
// with what it ends. Administrators only; the server decides every change.
import { createMemo, createSignal, For, Show } from "solid-js";
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { createLiveQuery, latest } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDate, formatDateTime, formatRelative, t } from "../../i18n";
import { RunDialog } from "../UserDialogs";
import { fingerprintPairs } from "../../nodes/model";
import { lineages, waitingCodes, type CertRecord, type EnrollmentCode, type Lineage } from "./integrations";
import { EnrollmentCodeDialog } from "./EnrollmentCode";
import type { UserInfo } from "./model";

/** The class of each state's tag: calm while active, loud when a person must act. */
const TAG: Record<Lineage["state"], string> = {
  active: "tag ok",
  expiring: "tag discrepancy",
  lapsed: "tag conflict",
  revoked: "tag",
};

export function IntegrationCertificatesSection() {
  const data = createLiveQuery<{ certs: CertRecord[]; codes: EnrollmentCode[]; accounts: UserInfo[] }>({
    topics: ["admin"],
    fetch: async (signal) => {
      const [certs, codes, accounts] = await Promise.all([
        api.get("/api/v1/integrations/certificates", { signal }),
        api.get("/api/v1/integrations/enrollments", { signal }),
        fetchAll<components["schemas"]["UserInfo"]>("/api/v1/access/service-accounts", { signal }),
      ]);
      return { value: { certs: certs.items, codes: codes.items, accounts: accounts.items } };
    },
  });
  const [enrolling, setEnrolling] = createSignal(false);
  const [revoking, setRevoking] = createSignal<Lineage | null>(null);
  const now = () => Date.now();
  const rows = createMemo(() => {
    const read = latest(data);
    return read ? lineages(read.certs, now()) : undefined;
  });
  const codes = createMemo(() => waitingCodes(latest(data)?.codes ?? [], now()));
  const accountName = (id: string) => latest(data)?.accounts.find((a) => a.id === id)?.name ?? id;

  const revoke = async (lineage: Lineage) => {
    await api.delete("/api/v1/integrations/certificates/{serial}", { path: { serial: lineage.current.serial } });
    data.refetch();
    toast({ kind: "ok", title: t("integrations.revoked", { label: lineage.label }) });
  };
  const withdraw = async (code: EnrollmentCode) => {
    await api.delete("/api/v1/integrations/enrollments/{id}", { path: { id: code.id } });
    data.refetch();
    toast({ kind: "ok", title: t("integrations.code.withdrawn", { account: accountName(code.account) }) });
  };

  return (
    <section class="page-section" aria-labelledby="access-integrations" data-testid="access-integrations">
      <div class="access-head">
        <h2 id="access-integrations">{t("integrations.heading")}</h2>
        <button type="button" class="btn" data-testid="integrations-enroll" onClick={() => setEnrolling(true)}>
          <Icon name="plus" size="sm" />
          {t("integrations.enroll")}
        </button>
      </div>
      <p class="muted">{t("integrations.lede")}</p>
      <ErrorNotice error={data.value.error} />
      <Show
        when={rows()}
        fallback={
          <Show when={!data.value.error}>
            <p class="muted" role="status">
              {t("common.loading")}
            </p>
          </Show>
        }
      >
        {(list) => (
          <Show when={list().length > 0} fallback={<p class="muted">{t("integrations.none")}</p>}>
            <div class="table-wrap">
              <table class="plain">
                <caption class="sr-only">{t("integrations.heading")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("integrations.col.host")}</th>
                    <th scope="col">{t("integrations.col.state")}</th>
                    <th scope="col">{t("integrations.col.until")}</th>
                    <th scope="col">{t("integrations.col.key")}</th>
                    <th scope="col" class="r">
                      <span class="sr-only">{t("access.col.actions")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <For each={list()}>
                    {(lineage) => (
                      <tr data-testid="integration-lineage" data-key={lineage.label} data-state={lineage.state}>
                        <td>
                          <strong>{lineage.label}</strong>
                          <span class="muted"> {t("integrations.of_account", { account: accountName(lineage.account) })}</span>
                        </td>
                        <td>
                          <span class={TAG[lineage.state]} data-testid="integration-state">
                            {t(`integrations.state.${lineage.state}`)}
                          </span>
                          <small class="help">{stateHelp(lineage)}</small>
                        </td>
                        <td class="num">{formatDate(lineage.current.not_after)}</td>
                        <td>
                          <span class="mono muted" title={lineage.current.key_sha256}>
                            {fingerprintPairs(lineage.current.key_sha256.slice(0, 16))}
                          </span>
                        </td>
                        <td class="r">
                          <Show when={lineage.state !== "revoked"}>
                            <button
                              type="button"
                              class="btn sm"
                              data-testid="integration-revoke"
                              aria-label={t("integrations.revoke_named", { label: lineage.label })}
                              onClick={() => setRevoking(lineage)}
                            >
                              {t("common.action.revoke")}
                            </button>
                          </Show>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        )}
      </Show>
      <Show when={codes().length > 0}>
        <h3>{t("integrations.codes.heading")}</h3>
        <ul class="card access-accounts">
          <For each={codes()}>
            {(code) => (
              <li data-testid="integration-code">
                <div class="access-account">
                  <span>
                    {t("integrations.codes.waiting", {
                      account: accountName(code.account),
                      expires: formatDateTime(code.expires_at),
                    })}
                    <Show when={code.source}>
                      {(source) => <span class="muted"> {t("integrations.codes.from", { source: source() })}</span>}
                    </Show>
                  </span>
                  <button type="button" class="btn sm" data-testid="integration-code-withdraw" onClick={() => void withdraw(code)}>
                    {t("integrations.codes.withdraw")}
                  </button>
                </div>
              </li>
            )}
          </For>
        </ul>
      </Show>
      <Show when={enrolling()}>
        <EnrollmentCodeDialog
          accounts={(latest(data)?.accounts ?? []).filter((a) => !a.disabled)}
          onCreated={() => data.refetch()}
          onClose={() => setEnrolling(false)}
        />
      </Show>
      <Show when={revoking()}>
        {(lineage) => (
          <RunDialog
            title={t("integrations.revoke_title", { label: lineage().label })}
            body={
              <>
                <p>{t("integrations.revoke_body", { label: lineage().label, account: accountName(lineage().account) })}</p>
                <p>{t("integrations.revoke_after")}</p>
              </>
            }
            confirmLabel={t("common.action.revoke")}
            danger
            run={() => revoke(lineage())}
            onClose={() => setRevoking(null)}
          />
        )}
      </Show>
    </section>
  );
}

/** One line under a state: what it means for this host and, where needed, what to do. */
function stateHelp(lineage: Lineage): string {
  switch (lineage.state) {
    case "active":
      return lineage.pending
        ? t("integrations.help.renewed")
        : t("integrations.help.active", { renewed: formatRelative(lineage.current.issued_at) });
    case "expiring":
      return t("integrations.help.expiring");
    case "lapsed":
      return t("integrations.help.lapsed");
    case "revoked":
      return t("integrations.help.revoked", { reason: lineage.current.reason ?? t("common.none") });
  }
}
