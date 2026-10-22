// The network boot tab of a scope (/dhcp/scopes/<prefix>/boot). Network boot in Tenko is options
// and policies (docs/dhcp.md, section 16.2), so the tab edits nothing new: a form over six options
// of the scope's own option set (the next server, the TFTP server name, the boot file and the three
// PXELINUX options), saved with the set's revision and replacing only those six, and the list of
// the scope's policies that set a boot file per client type, with a dialog that adds one (a class,
// a policy and its option 67).
import { A } from "@solidjs/router";
import { createEffect, createResource, createSignal, For, Show } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { ApiError, errorMessage } from "../../api/problem";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { mayWriteDhcp } from "../access";
import { getOptionSet, listClasses, listPolicies, putOptionSet, type DhcpClass, type OptionSet, type Policy, type Scope } from "../api";
import { dhcpPaths } from "../paths";
import { conditionWords } from "../words";
import { AddBootDialog } from "./AddBootDialog";
import { listPolicySets } from "./api";
import { BOOT_FIELDS, bootPolicies, buildSet, draftOfSet, EMPTY_DRAFT, fieldOfCode, type BootDraft, type BootField, type BootProblem } from "./model";
import "./boot.css";

/** The part of an element id and a test id that names a field: `field-boot-pxelinux-config`. */
const FIELD_ID: Readonly<Record<BootField, string>> = {
  next_server: "boot-next-server",
  tftp_name: "boot-tftp-name",
  file: "boot-file",
  pxe_config: "boot-pxelinux-config",
  pxe_prefix: "boot-pxelinux-prefix",
  pxe_reboot: "boot-pxelinux-reboot",
};

function problemMessage(problem: BootProblem): string {
  return problem === "long" ? t("dhcp.boot.check.long") : t(`dhcp.optset.check.${problem}`);
}

/** The field an option error of the server names, by the code and space it reports. */
function fieldOfError(err: unknown): BootField | undefined {
  if (!(err instanceof ApiError) || (err.params.space ?? "dhcp4") !== "dhcp4") return undefined;
  const code = Number(err.params.code);
  return Number.isInteger(code) ? fieldOfCode(code) : undefined;
}

/** One input of the form: its label, what it is for, and where its value comes from while it is empty. */
function BootInput(props: {
  field: BootField;
  value: string;
  /** The server's text for this option; undefined when the server sets none or could not be read. */
  server: string | undefined;
  /** Whether the server's option set was read, so that "none" can be said. */
  serverKnown: boolean;
  error: string | undefined;
  readOnly: boolean;
  onInput: (value: string) => void;
}) {
  const id = () => FIELD_ID[props.field];
  const empty = () => props.value.trim() === "";
  return (
    <div class="field">
      <label for={`dhcp-f-${id()}`}>{t(`dhcp.boot.field.${props.field}`)}</label>
      <input
        id={`dhcp-f-${id()}`}
        class="input mono"
        value={props.value}
        readOnly={props.readOnly}
        spellcheck={false}
        autocomplete="off"
        inputmode={props.field === "pxe_reboot" ? "numeric" : undefined}
        aria-invalid={props.error ? "true" : undefined}
        aria-describedby={`dhcp-f-${id()}-help`}
        data-testid={`field-${id()}`}
        onInput={(e) => props.onInput(e.currentTarget.value)}
      />
      <Show when={props.error}>
        <span class="help bad" data-testid="field-error" data-field={id()}>
          {props.error}
        </span>
      </Show>
      <span class="help" id={`dhcp-f-${id()}-help`}>
        {t(`dhcp.boot.hint.${props.field}`)}
      </span>
      <Show when={empty() && props.serverKnown}>
        <span class="help" data-testid="boot-inherited" data-field={id()} data-server={props.server ?? ""}>
          {props.server !== undefined ? t("dhcp.boot.inherited", { value: props.server }) : t("dhcp.boot.inherited_none")}
        </span>
      </Show>
    </div>
  );
}

function BootForm(props: { scope: Scope }) {
  const [set, { refetch }] = createResource(
    () => `scope:${props.scope.prefix}`,
    (owner) => getOptionSet(owner),
  );
  // The server's set tells what applies while the scope sets nothing; a set that cannot be read says nothing.
  const [server] = createResource(() => getOptionSet("server").catch(() => undefined));
  const [draft, setDraft] = createSignal<BootDraft>({ ...EMPTY_DRAFT });
  const [errors, setErrors] = createSignal<Partial<Record<BootField, string>>>({});
  const [top, setTop] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const writable = () => mayWriteDhcp();

  // The form follows the set the server holds: on load and after a save.
  createEffect(() => {
    const current = latest(set);
    if (!current) return;
    setDraft(draftOfSet(current.values));
    setErrors({});
    setTop(undefined);
  });

  const serverDraft = () => {
    const current = server.error ? undefined : server.latest;
    return current ? draftOfSet(current.values) : undefined;
  };

  const save = async (event?: Event) => {
    event?.preventDefault();
    const current = latest(set);
    if (!current || busy() || !writable()) return;
    const built = buildSet(current.values, draft());
    if (!built.ok) {
      const messages: Partial<Record<BootField, string>> = {};
      for (const field of BOOT_FIELDS) {
        const problem = built.errors[field];
        if (problem) messages[field] = problemMessage(problem);
      }
      setErrors(messages);
      setTop(undefined);
      return;
    }
    setErrors({});
    setTop(undefined);
    if (!built.changed) {
      toast({ kind: "info", title: t("dhcp.boot.unchanged") });
      return;
    }
    setBusy(true);
    try {
      await putOptionSet(current, built.values);
      toast({ kind: "ok", title: t("dhcp.boot.saved") });
      await refetch();
    } catch (err) {
      const field = fieldOfError(err);
      if (field) setErrors({ [field]: errorMessage(err) });
      else setTop(err);
    } finally {
      setBusy(false);
    }
  };

  const input = (field: BootField) => (
    <BootInput
      field={field}
      value={draft()[field]}
      server={serverDraft()?.[field] || undefined}
      serverKnown={serverDraft() !== undefined}
      error={errors()[field]}
      readOnly={!writable()}
      onInput={(value) => setDraft((d) => ({ ...d, [field]: value }))}
    />
  );

  return (
    <Show when={latest(set)} fallback={<ErrorNotice error={set.error} />}>
      <form class="dhcp-form boot-form" data-testid="boot-form" novalidate onSubmit={(e) => void save(e)}>
        <div class="field-row">
          {input("next_server")}
          {input("tftp_name")}
        </div>
        <div class="field-row">{input("file")}</div>
        <div class="field-row">
          {input("pxe_config")}
          {input("pxe_prefix")}
          {input("pxe_reboot")}
        </div>
        <ErrorNotice error={top()} />
        <Show when={writable()}>
          <div class="dhcp-actions">
            <button type="submit" class="btn primary" disabled={busy()} data-testid="boot-save">
              {t("dhcp.boot.save")}
            </button>
          </div>
        </Show>
      </form>
    </Show>
  );
}

interface BootData {
  policies: Policy[];
  classes: DhcpClass[];
  sets: OptionSet[];
}

function BootPolicies(props: { scope: Scope }) {
  const [adding, setAdding] = createSignal(false);
  const query = createLiveQuery<BootData>({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const [policies, classes, sets] = await Promise.all([listPolicies(signal), listClasses(signal), listPolicySets(signal)]);
      return { value: { policies: policies.items, classes: classes.items, sets }, revision: policies.revision };
    },
  });
  const data = () => latest(query);
  const className = (id: string) => data()?.classes.find((c) => c.id === id)?.name ?? id;
  const rows = () => {
    const d = data();
    return d ? bootPolicies(props.scope.prefix, d.policies, d.sets) : [];
  };
  const scopePolicies = () => (data()?.policies ?? []).filter((p) => p.scope === props.scope.prefix);

  return (
    <>
      <ErrorNotice error={query.value.error} />
      <Show when={data()}>
        <Show
          when={rows().length > 0}
          fallback={
            <p class="muted" data-testid="boot-policies-empty">
              {t("dhcp.boot.policies_empty")}
            </p>
          }
        >
          <div class="table-wrap">
            <table class="plain" data-testid="boot-policies">
              <caption class="sr-only">{t("dhcp.boot.policies_title")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("dhcp.col.order")}</th>
                  <th scope="col">{t("dhcp.col.name")}</th>
                  <th scope="col">{t("dhcp.col.condition")}</th>
                  <th scope="col">{t("dhcp.boot.col.file")}</th>
                  <th scope="col">{t("dhcp.col.enabled")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={rows()}>
                  {(row) => (
                    <tr data-testid="boot-policy" data-key={row.policy.name} data-file={row.file} data-enabled={row.policy.enabled === false ? "off" : "on"}>
                      <td class="num">{row.policy.order}</td>
                      <td class="mono">{row.policy.name}</td>
                      <td data-testid="boot-policy-condition">{conditionWords(row.policy.condition, className)}</td>
                      <td class="mono boot-file">{row.file}</td>
                      <td>
                        <span class={row.policy.enabled === false ? "tag" : "tag accent"}>{row.policy.enabled === false ? t("dhcp.scope.disabled") : t("dhcp.scope.enabled")}</span>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
        <p class="muted" data-testid="boot-policies-note">
          {t("dhcp.boot.policies_note")}
        </p>
        <div class="dhcp-actions boot-actions">
          <Show when={mayWriteDhcp()}>
            <button type="button" class="btn" data-testid="boot-add" onClick={() => setAdding(true)}>
              <Icon name="plus" />
              {t("dhcp.boot.add_button")}
            </button>
          </Show>
          <A href={dhcpPaths.policies()} data-testid="boot-policies-link">
            {t("dhcp.boot.policies_link")}
          </A>
        </div>
        <Show when={adding()}>
          <AddBootDialog
            scope={props.scope}
            classes={data()?.classes ?? []}
            policies={scopePolicies()}
            onClose={() => setAdding(false)}
            onDone={() => {
              setAdding(false);
              query.refetch();
            }}
          />
        </Show>
      </Show>
    </>
  );
}

export function BootTab(props: { scope: Scope }) {
  return (
    <div class="page-body dhcp-tab boot-tab" data-testid="scope-boot">
      <section class="page-section" aria-labelledby="dhcp-boot-form-title">
        <h2 id="dhcp-boot-form-title">{t("dhcp.boot.form_title")}</h2>
        <p class="muted">{t("dhcp.boot.form_help", { network: props.scope.cidr })}</p>
        <BootForm scope={props.scope} />
      </section>
      <section class="page-section" aria-labelledby="dhcp-boot-policies-title">
        <h2 id="dhcp-boot-policies-title">{t("dhcp.boot.policies_title")}</h2>
        <p class="muted">{t("dhcp.boot.policies_help")}</p>
        <BootPolicies scope={props.scope} />
      </section>
    </div>
  );
}
