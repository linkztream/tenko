// The status of the hash chain on top of the audit log (IAM-18): the result of
// GET /api/v1/audit/verify, read when the page opens, after every new record and when
// someone presses "Verify again". Intact is a calm note with a check; broken is a loud alert
// with an icon and words that say which record breaks the chain, why, and what to do.
import { A } from "@solidjs/router";
import { Match, Show, Switch, type Accessor } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { errorMessage } from "../api/problem";
import type { AuditVerifyReport } from "../api/types";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { formatDateTime, t, tDynamic } from "../i18n";
import { shortHash } from "./model";

/** Quiet time after the last new record before the chain is checked again. */
const CHECK_PAUSE_MS = 1000;

export interface Checked {
  report: AuditVerifyReport;
  /** When the answer arrived (milliseconds since the epoch); the report has no time of its own. */
  checkedAt: number;
}

export interface Chain {
  checked: Accessor<Checked | undefined>;
  error: Accessor<unknown>;
  /** A check is running. */
  busy: Accessor<boolean>;
  verify: () => void;
}

/** Must be called inside a component. Reads the chain and follows the `audit` topic. */
export function createChain(): Chain {
  const live = createLiveQuery<Checked>({
    topics: ["audit"],
    // A check reads the whole log: a burst of records becomes one check.
    debounceMs: CHECK_PAUSE_MS,
    fetch: async (signal) => {
      const report = await api.get("/api/v1/audit/verify", { signal });
      return { value: { report, checkedAt: Date.now() }, revision: report.revision };
    },
  });
  const ready = () => live.value.state === "ready" || live.value.state === "refreshing";
  return {
    checked: () => (ready() ? live.value() : undefined),
    error: () => live.value.error,
    busy: () => live.value.loading,
    verify: () => live.refetch(),
  };
}

function when(at: number): string {
  return formatDateTime(at, { dateStyle: "medium", timeStyle: "medium" });
}

/** The reason of a break in words; the codec errors share one sentence. */
function reasonText(code: string): string {
  return tDynamic(`audit.chain.reason.${code}`) ?? t("audit.chain.reason.other");
}

function VerifyButton(props: { chain: Chain }) {
  return (
    <button
      type="button"
      class="btn"
      data-testid="audit-verify"
      aria-disabled={props.chain.busy() ? "true" : undefined}
      aria-busy={props.chain.busy() ? "true" : undefined}
      onClick={() => {
        if (!props.chain.busy()) props.chain.verify();
      }}
    >
      <Icon name="refresh" size="sm" />
      {props.chain.busy() ? t("audit.chain.verifying") : t("audit.chain.verify")}
    </button>
  );
}

function Intact(props: { chain: Chain; checked: Checked }) {
  const report = () => props.checked.report;
  return (
    <div class="note ok" role="status">
      <Icon name="check" size="sm" />
      <div class="grow chain-body">
        <Show when={report().head.seq > 0} fallback={<strong>{t("audit.chain.empty")}</strong>}>
          <strong>{t("audit.chain.intact", { count: report().checked, seq: String(report().head.seq) })}</strong>
        </Show>
        <span class="chain-meta muted">
          <Show when={report().head.seq > 0}>
            <span>
              {t("audit.chain.head")}{" "}
              <span class="mono" title={report().head.hash} data-testid="audit-chain-head" data-key={String(report().head.seq)}>
                {shortHash(report().head.hash)}
              </span>
            </span>
          </Show>
          <span>{t("audit.chain.checked", { time: when(props.checked.checkedAt) })}</span>
        </span>
      </div>
      <VerifyButton chain={props.chain} />
    </div>
  );
}

function Broken(props: { chain: Chain; checked: Checked }) {
  const report = () => props.checked.report;
  // The server names the break; without one the chain still ends after the last record that verified.
  const found = () => report().first_break ?? { seq: report().head.seq + 1, code: "other", detail: "" };
  return (
    <div class="note bad" role="alert">
      <Icon name="alert" size="sm" />
      <div class="grow chain-body">
        <strong>{t("audit.chain.broken", { seq: String(found().seq) })}</strong>
        <p>{reasonText(found().code)}</p>
        <Show when={found().detail}>
          <p class="muted chain-detail">{t("audit.chain.detail", { detail: found().detail })}</p>
        </Show>
        <p>
          {t("audit.chain.verified_before", { count: report().checked })}{" "}
          <A href={paths.auditRecord(found().seq)}>{t("audit.chain.open_record", { seq: String(found().seq) })}</A>
        </p>
        <p>{t("audit.chain.advice")}</p>
        <span class="chain-meta muted">{t("audit.chain.checked", { time: when(props.checked.checkedAt) })}</span>
      </div>
      <VerifyButton chain={props.chain} />
    </div>
  );
}

export function ChainStatus(props: { chain: Chain }) {
  const state = () => {
    const checked = props.chain.checked();
    if (checked) return checked.report.intact ? "intact" : "broken";
    return props.chain.error() ? "error" : "checking";
  };
  return (
    <section class="audit-chain" aria-label={t("audit.chain.label")} data-testid="audit-chain" data-state={state()}>
      <Switch>
        <Match when={props.chain.checked()}>
          {(checked) => (
            <Show when={checked().report.intact} fallback={<Broken chain={props.chain} checked={checked()} />}>
              <Intact chain={props.chain} checked={checked()} />
            </Show>
          )}
        </Match>
        <Match when={props.chain.error()}>
          <div class="note bad" role="alert">
            <Icon name="alert" size="sm" />
            <div class="grow chain-body">
              <strong>{t("audit.chain.failed")}</strong>
              <p>{errorMessage(props.chain.error())}</p>
            </div>
            <VerifyButton chain={props.chain} />
          </div>
        </Match>
        <Match when={true}>
          <div class="note" role="status">
            <Icon name="clock" size="sm" />
            <div class="grow">{t("audit.chain.checking")}</div>
          </div>
        </Match>
      </Switch>
    </section>
  );
}
