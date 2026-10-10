// Small pieces of the connectors views: the health of an instance (glyph and word), the
// supervised process in words, the last run, and the actions on an instance (run now, check
// now, enable, disable, delete) with their result toasts.
import { useNavigate } from "@solidjs/router";
import { Match, Show, Switch } from "solid-js";
import { errorMessage } from "../api/problem";
import { paths } from "../app/paths";
import { hasRole, isAdmin } from "../auth/session";
import { Icon } from "../components/Icon";
import { toast } from "../components/toast";
import { TimeAgo } from "../grid/cells";
import { formatDateTime, formatNumber, t } from "../i18n";
import { checkConnector, deleteConnector, runConnector, setConnectorEnabled, type ConnectorView, type LastRun, type SupervisorStatus } from "./api";
import { connectorHealth, healthIcon, healthWord, processWord } from "./model";

/** Who changes, runs and checks connectors: administrators and operators. */
export const isConnectorEditor = (): boolean => isAdmin() || hasRole("operator");

export function HealthBadge(props: { connector: Pick<ConnectorView, "enabled" | "health" | "last_run"> }) {
  const h = () => connectorHealth(props.connector);
  return (
    <span class={`conn-health ${h()}`} data-health={h()} data-testid="connector-health">
      <Icon name={healthIcon(h())} size="xs" />
      {healthWord(h())}
    </span>
  );
}

/** The supervised process: its state and when it changes next. */
export function ProcessText(props: { process: SupervisorStatus }) {
  const p = () => props.process;
  return (
    <span class="conn-process" data-state={p().state}>
      {processWord(p().state)}
      <Switch>
        <Match when={p().state === "running" && (p() as { since: string }).since}>
          {(since) => (
            <span class="muted">
              {" "}
              <TimeAgo at={since()} />
            </span>
          )}
        </Match>
        <Match when={(p().state === "backoff" || p().state === "circuit_open") && (p() as { until: string }).until}>
          {(until) => <span class="muted"> {t("connectors.process.until", { at: formatDateTime(until()) })}</span>}
        </Match>
      </Switch>
    </span>
  );
}

/** The last run in one line: outcome, when, and what it handed on. */
export function LastRunText(props: { run: LastRun | null | undefined }) {
  return (
    <Show when={props.run} fallback={<span class="muted">{t("connectors.run.never")}</span>}>
      {(r) => (
        <span class={`conn-run ${r().outcome}`} data-outcome={r().outcome}>
          <Icon name={r().outcome === "succeeded" ? "check" : "alert"} size="xs" />
          {r().outcome === "succeeded" ? t("connectors.run.succeeded", { count: r().observations }) : t("connectors.run.failed")}{" "}
          <TimeAgo at={r().finished_at} />
        </span>
      )}
    </Show>
  );
}

/** A number of seconds as the form shows it, or the default it falls back to. */
export function secondsText(value: number | null | undefined, fallback: number): string {
  return value ? t("connectors.seconds", { secs: formatNumber(value) }) : t("connectors.seconds_default", { secs: formatNumber(fallback) });
}

/** The actions on one instance, with their toasts; `onChanged` refreshes what the view shows. */
export function useConnectorActions(onChanged: () => void) {
  const navigate = useNavigate();
  return {
    run: async (c: ConnectorView) => {
      try {
        const { job } = await runConnector(c.id);
        toast({ kind: "ok", title: t("connectors.toast.run", { name: c.name }), actions: [{ label: t("connectors.toast.open_job"), run: () => navigate(paths.job(job)) }] });
        onChanged();
      } catch (err) {
        toast({ kind: "bad", title: t("connectors.toast.run_failed", { name: c.name }), body: errorMessage(err) });
      }
    },
    check: async (c: ConnectorView) => {
      try {
        const report = await checkConnector(c.id);
        const word = t(`connectors.remote.${report.health}`);
        toast({
          kind: report.health === "healthy" ? "ok" : "bad",
          title: t("connectors.toast.checked", { name: c.name, health: word }),
          body: report.detail ?? undefined,
        });
        onChanged();
      } catch (err) {
        toast({ kind: "bad", title: t("connectors.toast.check_failed", { name: c.name }), body: errorMessage(err) });
        onChanged();
      }
    },
    setEnabled: async (c: ConnectorView, enabled: boolean) => {
      try {
        await setConnectorEnabled(c.id, enabled);
        toast({ kind: "ok", title: enabled ? t("connectors.toast.enabled", { name: c.name }) : t("connectors.toast.disabled", { name: c.name }) });
        onChanged();
      } catch (err) {
        toast({ kind: "bad", title: t("connectors.toast.change_failed", { name: c.name }), body: errorMessage(err) });
      }
    },
    remove: async (c: ConnectorView): Promise<boolean> => {
      try {
        await deleteConnector(c.id);
        toast({ kind: "ok", title: t("connectors.toast.deleted", { name: c.name }) });
        onChanged();
        return true;
      } catch (err) {
        toast({ kind: "bad", title: t("connectors.toast.delete_failed", { name: c.name }), body: errorMessage(err) });
        return false;
      }
    },
  };
}
