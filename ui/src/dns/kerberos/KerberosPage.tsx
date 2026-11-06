// The Kerberos section of the DNS area (/dns/kerberos, scope `dns.keys`; identity plan section
// 3.18): the account of secure dynamic updates. Without an account the page is the wizard
// (KerberosWizard.tsx); with one it is the status: the principal, who owns the password, the
// rotation, the key versions with their states, the SPNs, the findings of the last self-test
// each with its fix, and the actions (run the self-test, rotate now for an account Tenko owns,
// delete from Tenko). Never a key, a password or a secret reference: the server sends none.
// The zones of the realm with their modes come with WP13.4.
import { A } from "@solidjs/router";
import { createSignal, For, Show } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { paths } from "../../app/paths";
import { ConfirmDialog } from "../../components/Dialog";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { formatDateTime, t } from "../../i18n";
import { mayKeys } from "../access";
import { DnsNav } from "../DnsNav";
import { DnsProblem, unavailable } from "../Parts";
import {
  checkKerberos,
  deleteKerberos,
  getKerberos,
  rotateKerberos,
  type KerberosAccount,
  type KerberosFinding,
  type KerberosStatus,
} from "./api";
import { KerberosWizard } from "./KerberosWizard";
import { findingKey } from "./model";
import "../dns.css";

function when(value: string | null | undefined): string {
  return value ? formatDateTime(value) : "–";
}

/** One finding: its title and its fix in the person's language, the server's words below. */
function Finding(props: { finding: KerberosFinding }) {
  const key = () => findingKey(props.finding.code);
  const params = () => props.finding.params ?? {};
  const values = () => ({
    spn: params().spn ?? "",
    kvno: params().kvno ?? "",
    held: params().held ?? "",
    skew: params().skew_secs ?? "",
    etype: params().etype ?? "",
    failures: params().failures ?? "",
    reason: params().reason ?? "other",
  });
  return (
    <Notice
      kind={key() === "clock_skew" || key() === "rotation_failed" ? "warn" : "bad"}
      role="status"
      title={t(`dns.kerberos.finding.${key()}.title`, values())}
      testid="kerberos-finding"
    >
      <p data-testid="kerberos-finding-fix" data-code={props.finding.code}>
        {t(`dns.kerberos.finding.${key()}.fix`, values())}
      </p>
      <p class="muted mono" data-testid="kerberos-finding-detail">
        {props.finding.detail}
      </p>
    </Notice>
  );
}

function AccountView(props: { status: KerberosStatus; account: KerberosAccount; onChanged: () => void }) {
  const [busy, setBusy] = createSignal<"check" | "rotate" | "delete" | null>(null);
  const [error, setError] = createSignal<unknown>();
  const [deleting, setDeleting] = createSignal(false);
  const [job, setJob] = createSignal<string | null>(null);
  const account = () => props.account;

  const run = async (what: "check" | "rotate") => {
    setBusy(what);
    setError(undefined);
    try {
      if (what === "check") {
        await checkKerberos();
        toast({ kind: "ok", title: t("dns.kerberos.checked") });
      } else {
        const started = await rotateKerberos();
        setJob(started.job_id);
        toast({ kind: "ok", title: t("dns.kerberos.rotation_started") });
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(null);
      props.onChanged();
    }
  };

  const remove = async () => {
    setBusy("delete");
    setError(undefined);
    try {
      await deleteKerberos();
      toast({ kind: "ok", title: t("dns.kerberos.deleted") });
      setDeleting(false);
      props.onChanged();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div class="page-body dns-form" data-testid="kerberos-status">
      <For each={props.status.findings ?? []}>{(finding) => <Finding finding={finding} />}</For>
      <Show when={(props.status.findings ?? []).length === 0 && account().last_check}>
        <Notice kind="ok" role="status" testid="kerberos-passed">
          {t("dns.kerberos.passed", { at: when(account().last_check) })}
        </Notice>
      </Show>
      <ErrorNotice error={error()} />
      <section class="page-section" data-testid="kerberos-account" data-owned={String(account().owned)}>
        <h2>{t("dns.kerberos.account")}</h2>
        <dl class="kv">
          <dt>{t("dns.kerberos.principal")}</dt>
          <dd class="mono" data-testid="kerberos-principal">
            {account().principal}
          </dd>
          <dt>{t("dns.kerberos.password")}</dt>
          <dd data-testid="kerberos-owner">{account().owned ? t("dns.kerberos.owned") : t("dns.kerberos.imported")}</dd>
          <dt>{t("dns.kerberos.rotation")}</dt>
          <dd data-testid="kerberos-rotation">
            {account().owned && account().rotation_days > 0
              ? t("dns.kerberos.rotation_every", {
                  days: account().rotation_days,
                })
              : t("dns.kerberos.rotation_none")}
          </dd>
          <dt>{t("dns.kerberos.last_rotation")}</dt>
          <dd>{when(account().last_rotation)}</dd>
          <dt>{t("dns.kerberos.next_rotation")}</dt>
          <dd data-testid="kerberos-next-rotation">{when(account().next_rotation)}</dd>
          <dt>{t("dns.kerberos.last_check")}</dt>
          <dd data-testid="kerberos-last-check">{when(account().last_check)}</dd>
          <dt>{t("dns.kerberos.kdcs")}</dt>
          <dd class="mono">{account().kdcs.length > 0 ? account().kdcs.join(", ") : t("dns.kerberos.kdcs_found")}</dd>
        </dl>
      </section>
      <section class="page-section" data-testid="kerberos-versions">
        <h2>{t("dns.kerberos.versions")}</h2>
        <div class="table-wrap">
          <table class="plain">
            <thead>
              <tr>
                <th>{t("dns.kerberos.col.kvno")}</th>
                <th>{t("dns.kerberos.col.state")}</th>
                <th>{t("dns.kerberos.col.etypes")}</th>
                <th>{t("dns.kerberos.col.created")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={[...account().versions].sort((a, b) => b.kvno - a.kvno)}>
                {(version) => (
                  <tr data-testid="kerberos-version" data-kvno={String(version.kvno)} data-state={version.state}>
                    <td class="mono">{version.kvno}</td>
                    <td>{t(`dns.kerberos.state.${version.state}`)}</td>
                    <td class="mono">{version.etypes.join(", ")}</td>
                    <td>{when(version.created)}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </section>
      <section class="page-section" data-testid="kerberos-spns">
        <h2>{t("dns.kerberos.spns")}</h2>
        <ul>
          <For each={account().spns}>
            {(spn) => (
              <li class="mono" data-testid="kerberos-spn">
                {spn}
              </li>
            )}
          </For>
        </ul>
      </section>
      <Show when={props.status.contexts}>
        {(contexts) => (
          <section class="page-section" data-testid="kerberos-contexts">
            <h2>{t("dns.kerberos.contexts")}</h2>
            <p>
              {t("dns.kerberos.contexts_line", {
                negotiating: contexts().negotiating,
                established: contexts().established,
                refused: contexts().refused_last_hour,
              })}
            </p>
          </section>
        )}
      </Show>
      <Show when={mayKeys()}>
        <section class="page-section" data-testid="kerberos-actions">
          <h2>{t("dns.kerberos.actions")}</h2>
          <div class="form-row">
            <button type="button" class="btn" data-testid="kerberos-check" disabled={busy() !== null} onClick={() => void run("check")}>
              {t("dns.kerberos.check_now")}
            </button>
            <Show when={account().owned}>
              <button type="button" class="btn" data-testid="kerberos-rotate" disabled={busy() !== null} onClick={() => void run("rotate")}>
                {t("dns.kerberos.rotate_now")}
              </button>
            </Show>
            <button
              type="button"
              class="btn danger"
              data-testid="kerberos-delete"
              disabled={busy() !== null}
              onClick={() => setDeleting(true)}
            >
              {t("dns.kerberos.delete")}
            </button>
          </div>
          <Show when={job()}>
            {(id) => (
              <p data-testid="kerberos-rotation-job">
                <A href={paths.job(id())}>{t("dns.kerberos.rotation_job")}</A>
              </p>
            )}
          </Show>
        </section>
      </Show>
      <Show when={deleting()}>
        <ConfirmDialog
          title={t("dns.kerberos.delete_title", {
            principal: account().principal,
          })}
          testid="dialog-kerberos-delete"
          body={<p>{t("dns.kerberos.delete_body")}</p>}
          confirmLabel={t("dns.kerberos.delete")}
          cancelLabel={t("common.action.cancel")}
          danger
          busy={busy() === "delete"}
          onConfirm={() => void remove()}
          onClose={() => setDeleting(false)}
        />
      </Show>
    </div>
  );
}

export default function KerberosPage() {
  const query = createLiveQuery({
    topics: ["dns", "jobs"],
    // A session without `dns.keys` reads nothing: the server would refuse it.
    fetch: async (signal) => ({
      value: mayKeys() ? await getKerberos(signal) : null,
    }),
  });
  const [shown, setShown] = createSignal<KerberosStatus | null>(null);
  const status = () => shown() ?? latest(query) ?? undefined;
  const refresh = () => {
    setShown(null);
    query.refetch();
  };
  return (
    <div class="page dns-page" data-testid="page-dns-kerberos">
      <DnsNav />
      <PageHead title={t("dns.kerberos.title")} sub={t("dns.kerberos.sub")} />
      <Show when={query.value.error && !status()}>
        <div class="page-body">
          <Show when={unavailable(query.value.error)} fallback={<ErrorNotice error={query.value.error} />}>
            <DnsProblem error={query.value.error} />
          </Show>
        </div>
      </Show>
      <Show when={!mayKeys()}>
        <div class="page-body">
          <Notice kind="info" role="status" testid="kerberos-no-access">
            {t("dns.kerberos.no_access")}
          </Notice>
        </div>
      </Show>
      <Show when={status()}>
        {(s) => (
          <Show
            when={s().account}
            fallback={
              <Show when={mayKeys()}>
                <KerberosWizard
                  onDone={(next) => {
                    setShown(next);
                    query.refetch();
                  }}
                />
              </Show>
            }
          >
            {(account) => <AccountView status={s()} account={account()} onChanged={refresh} />}
          </Show>
        )}
      </Show>
    </div>
  );
}
