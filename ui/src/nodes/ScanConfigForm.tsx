// The form of a probe's scan configuration (docs/scanning.md, section 12): every key of the
// `[scan]` section, each method as a fieldset, the SNMP devices as a table with their vault
// secrets. Administrators edit and save with the revision they read (`If-Match`); everyone else
// reads. A configuration that changed on the controllers meanwhile never overwrites the edits:
// a note offers to load it instead, and a refused save (412) says the same.
import { createEffect, createMemo, createResource, createSignal, createUniqueId, For, Match, on, Show, Switch, untrack, type JSX } from "solid-js";
import { createStore, produce, reconcile } from "solid-js/store";
import { fetchAll } from "../api/paginate";
import { ApiError, errorMessage, type FieldError } from "../api/problem";
import type { Vrf } from "../api/types";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatList, t, tDynamic } from "../i18n";
import { Field, FieldNote, FieldRow, SelectInput, withCurrent, type Option } from "../ipam/formKit";
import { shortId } from "../components/Principal";
import { listSecrets } from "../secrets/api";
import { getScanConfig, updateScanConfig } from "../scans/api";
import { CONFIG_METHODS, type ConfigMethod, type ProbeConfigView, type ScanConfig } from "../scans/model";
import { moduleRunning } from "../updates/modules";
import { blankDevice, configOf, draftErrors, draftOf, positionsOf, sameConfig, within, type Draft, type SnmpDevice } from "./scanDraft";
import "./nodes.css";

/** The tag that marks a secret as meant for SNMP devices; any operator secret may still be chosen. */
const SNMP_TAG = "snmp";

type TextKey = "prefixes" | "exclude" | "blackout" | "ports" | "servers";

/** The words of the codes a configuration field can be refused with. */
function errorWord(code: string): string {
  switch (code) {
    case "scans.config.cidr":
      return t("nodes.scan.error.cidr");
    case "scans.config.min":
      return t("nodes.scan.error.min");
    case "scans.config.port":
      return t("nodes.scan.error.port");
    case "scans.config.unknown":
      return t("nodes.scan.error.unknown");
    case "scans.config.type":
      return t("nodes.scan.error.type");
    default:
      return t("nodes.scan.error.invalid");
  }
}

/** The name of a method, its help line and the like: texts looked up by the method key. */
export function methodWord(key: ConfigMethod, part: "name" | "help"): string {
  return tDynamic(`nodes.scan.method.${key}.${part}`) ?? key;
}

/** A number as the input shows it: empty for a missing value or one that is not a number. */
function shown(value: number | null | undefined): string {
  return value === null || value === undefined || Number.isNaN(value) ? "" : String(value);
}

const asNumber = (text: string): number => (text.trim() === "" ? Number.NaN : Number(text));
const asOptional = (text: string): number | null => (text.trim() === "" ? null : Number(text));

/** A number input with its label, help and error line. */
function NumberField(props: {
  name: string;
  label: string;
  help?: string | undefined;
  error: string | undefined;
  value: number | null | undefined;
  optional?: boolean;
  onChange: (value: number | null) => void;
}) {
  return (
    <Field name={props.name} label={props.label} help={props.help} error={props.error}>
      {(c) => (
        <input
          {...c}
          class="input num"
          type="number"
          inputmode="numeric"
          step="1"
          value={shown(props.value)}
          onInput={(e) => props.onChange(props.optional ? asOptional(e.currentTarget.value) : asNumber(e.currentTarget.value))}
        />
      )}
    </Field>
  );
}

/** A switch (a checkbox with the role `switch`) with its label and help. */
function SwitchField(props: { name: string; label: string; help?: string | undefined; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label class="check-row">
      <input
        type="checkbox"
        class="cb"
        role="switch"
        checked={props.checked}
        data-testid={`field-${props.name}`}
        onChange={(e) => props.onChange(e.currentTarget.checked)}
      />
      <span>
        {props.label}
        <Show when={props.help}>
          <small class="help">{props.help}</small>
        </Show>
      </span>
    </label>
  );
}

/** A group of fields under a heading. */
function Group(props: { title: string; children: JSX.Element; testid?: string }) {
  return (
    <fieldset class="nodes-fieldset scan-group" data-testid={props.testid}>
      <legend>{props.title}</legend>
      {props.children}
    </fieldset>
  );
}

export function ScanConfigForm(props: {
  node: number;
  /** The configuration as the controllers last reported it. */
  view: ProbeConfigView;
  admin: boolean;
  /** Called after a save or a reload with the view that is now current, so the page can show it. */
  onChanged: (view: ProbeConfigView) => void;
}) {
  const [base, setBase] = createSignal(untrack(() => props.view));
  const [draft, setDraft] = createStore<Draft>(untrack(() => draftOf(props.view.config)));
  const [tried, setTried] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [serverErrors, setServerErrors] = createSignal<readonly FieldError[]>([]);
  const [stale, setStale] = createSignal(false);
  const [remote, setRemote] = createSignal<ProbeConfigView | null>(null);
  const noteId = createUniqueId();
  let form!: HTMLFormElement;

  // The VRFs and the vault secrets the selects offer; a failed read leaves them empty.
  const [vrfs] = createResource(async () => {
    if (!moduleRunning("ipam")) return [] as Vrf[];
    try {
      return (await fetchAll<Vrf>("/api/v1/vrfs")).items;
    } catch {
      return [] as Vrf[];
    }
  });
  const [secrets] = createResource(async () => {
    if (!props.admin) return [];
    try {
      return await listSecrets();
    } catch {
      return [];
    }
  });

  const current = () => configOf(draft);
  const clientErrors = createMemo(() => draftErrors(current()));
  const dirty = createMemo(() => !sameConfig(current(), base().config));
  const shownErrors = (): readonly { field: string; code: string }[] => [...(tried() ? clientErrors() : []), ...serverErrors()];

  /** Takes `view` as the configuration being edited, dropping every edit. */
  const adopt = (view: ProbeConfigView) => {
    setBase(view);
    setDraft(reconcile(draftOf(view.config)));
    setRemote(null);
    setStale(false);
    setTried(false);
    setError(null);
    setServerErrors([]);
  };

  // A newer configuration on the controllers replaces a draft nobody edited and waits as a note
  // while there are edits. A change of the probe's state alone (applied scope, kill switch) is
  // none of this form's business.
  createEffect(
    on(
      () => props.view,
      (view) => {
        const b = base();
        if (view.revision === b.revision && view.stored === b.stored) return;
        if (dirty()) setRemote(view);
        else adopt(view);
      },
      { defer: true },
    ),
  );
  createEffect(() => {
    const waiting = remote();
    if (waiting && !dirty()) adopt(waiting);
  });

  const edit = (change: () => void) => {
    setServerErrors([]);
    setError(null);
    change();
  };
  const set = <K extends keyof ScanConfig>(key: K, value: ScanConfig[K]) =>
    edit(() =>
      setDraft(
        produce((d) => {
          d.config[key] = value;
        }),
      ),
    );
  const setText = (key: TextKey, value: string) => edit(() => setDraft(key, value));
  const setMethod = (key: ConfigMethod, field: string, value: unknown) =>
    edit(() =>
      setDraft(
        produce((d) => {
          (d.config[key] as unknown as Record<string, unknown>)[field] = value;
        }),
      ),
    );
  const setDevice = (index: number, patch: Partial<SnmpDevice>) =>
    edit(() =>
      setDraft(
        produce((d) => {
          const device = d.config.snmp.devices[index];
          if (device) Object.assign(device, patch);
        }),
      ),
    );
  const addDevice = () => {
    edit(() =>
      setDraft(
        produce((d) => {
          d.config.snmp.devices.push(blankDevice());
        }),
      ),
    );
    const last = draft.config.snmp.devices.length - 1;
    queueMicrotask(() => form.querySelector<HTMLElement>(`[data-testid="device-address-${last}"]`)?.focus());
  };
  const removeDevice = (index: number) =>
    edit(() =>
      setDraft(
        produce((d) => {
          d.config.snmp.devices.splice(index, 1);
        }),
      ),
    );

  /** The message of the first error of a field, with the lines or entries it names for a list. */
  const errorText = (name: string, list?: "lines" | "entries"): string | undefined => {
    const found = shownErrors().filter((e) => within(e.field, name));
    const first = found[0];
    if (!first) return undefined;
    const word = errorWord(first.code);
    if (!list) return word;
    const positions = positionsOf(
      found.filter((e) => e.code === first.code),
      name,
    );
    if (positions.length === 0) return word;
    const args = { count: positions.length, positions: formatList(positions.map(String)) };
    return `${word} ${list === "lines" ? t("nodes.scan.error.lines", args) : t("nodes.scan.error.entries", args)}`;
  };

  /** The errors of the server that name a field this form does not show. */
  const unplaced = createMemo(() => {
    const placed = [
      ...Object.keys(base().config).filter((key) => !CONFIG_METHODS.some((m) => m.key === key)),
      ...CONFIG_METHODS.map((m) => m.key),
    ];
    return serverErrors().filter((e) => !placed.some((name) => within(e.field, name)));
  });

  /** The failed save when the server named fields, which the form shows beside them. */
  const fieldFailure = () => {
    const e = error();
    return e instanceof ApiError && e.fieldErrors.length > 0 ? e : null;
  };

  const focusFirstInvalid = () => form.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();

  const save = async (e: Event) => {
    e.preventDefault();
    if (!props.admin || busy()) return;
    setTried(true);
    const config = current();
    if (draftErrors(config).length > 0) {
      queueMicrotask(focusFirstInvalid);
      return;
    }
    setBusy(true);
    setError(null);
    setServerErrors([]);
    try {
      const answer = await updateScanConfig(props.node, config, base().revision ?? undefined);
      adopt(answer);
      props.onChanged(answer);
      toast({ kind: "ok", title: t("nodes.scan.form.saved") });
    } catch (err) {
      if (err instanceof ApiError && (err.status === 412 || err.is("node.config.revision_mismatch"))) {
        setStale(true);
      } else if (err instanceof ApiError && err.fieldErrors.length > 0) {
        setServerErrors(err.fieldErrors);
        setError(err);
        queueMicrotask(focusFirstInvalid);
      } else {
        setError(err);
        toast({ kind: "bad", title: t("nodes.scan.form.failed"), body: errorMessage(err) });
      }
    } finally {
      setBusy(false);
    }
  };

  /** Drops the edits and shows what the controllers hold now. */
  const reload = async () => {
    setBusy(true);
    try {
      const view = remote() ?? (await getScanConfig(props.node));
      adopt(view);
      props.onChanged(view);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const vrfOptions = (): Option[] =>
    withCurrent(
      [{ value: "", label: t("nodes.scan.vrf.default") }, ...(vrfs() ?? []).map((v) => ({ value: v.id, label: v.name }))],
      draft.config.vrf ?? "",
      (id) => shortId(id),
    );
  const secretOptions = (current: string | null | undefined): Option[] => {
    const all = secrets() ?? [];
    const tagged = all.filter((s) => s.tags.includes(SNMP_TAG));
    const rest = all.filter((s) => !s.tags.includes(SNMP_TAG));
    return withCurrent(
      [{ value: "", label: t("nodes.scan.devices.no_secret") }, ...tagged.map((s) => ({ value: s.id, label: s.name })), ...rest.map((s) => ({ value: s.id, label: s.name }))],
      current ?? "",
      (id) => shortId(id),
    );
  };

  const rateOptions = (): Option<ScanConfig["rate"]>[] => [
    { value: "normal", label: t("nodes.scan.rate.normal") },
    { value: "slow", label: t("nodes.scan.rate.slow") },
    { value: "slowest", label: t("nodes.scan.rate.slowest") },
    { value: "unlimited", label: t("nodes.scan.rate.unlimited") },
  ];
  const authOptions = (): Option[] => [
    { value: "", label: t("nodes.scan.devices.no_auth") },
    ...(["sha1", "sha224", "sha256", "sha384", "sha512"] as const).map((v) => ({ value: v, label: v.toUpperCase() })),
  ];
  const privacyOptions = (): Option[] => [
    { value: "", label: t("nodes.scan.devices.no_privacy") },
    { value: "aes128", label: "AES-128" },
  ];

  /** The fields of the SNMP devices that carry errors, for the line under the table. */
  const deviceErrors = () =>
    shownErrors()
      .filter((e) => within(e.field, "snmp.devices"))
      .map((e) => {
        const match = /^snmp\.devices\[(\d+)\](?:\.(\w+))?/.exec(e.field);
        return { field: e.field, index: Number(match?.[1] ?? 0), member: match?.[2] ?? "", code: e.code };
      });
  const deviceInvalid = (index: number, member: string) =>
    deviceErrors().some((e) => e.index === index && e.member === member) ? ("true" as const) : undefined;
  const lacking = () => new Set(props.view.lacking_secrets ?? []);

  /** The fields every method has: the switch, the interval and the lifetime of a sighting. */
  const common = (key: ConfigMethod, optionsOnly = false): JSX.Element => {
    const method = () => draft.config[key];
    return (
      <>
        <SwitchField
          name={`${key}.enabled`}
          label={t("nodes.scan.method.enabled")}
          checked={method().enabled}
          onChange={(v) => setMethod(key, "enabled", v)}
        />
        <Show when={!optionsOnly}>
          <FieldRow>
            <NumberField
              name={`${key}.interval_secs`}
              label={t("nodes.scan.method.interval")}
              help={t("nodes.scan.method.interval_help")}
              error={errorText(`${key}.interval_secs`)}
              value={method().interval_secs}
              onChange={(v) => setMethod(key, "interval_secs", v ?? Number.NaN)}
            />
            <NumberField
              name={`${key}.ttl_secs`}
              label={t("nodes.scan.method.ttl")}
              help={t("nodes.scan.method.ttl_help")}
              error={errorText(`${key}.ttl_secs`)}
              value={method().ttl_secs}
              optional
              onChange={(v) => setMethod(key, "ttl_secs", v)}
            />
          </FieldRow>
        </Show>
      </>
    );
  };

  const timeout = (key: "icmp" | "tcp_connect" | "reverse_dns" | "llmnr" | "snmp" | "arp_sweep" | "tcp_syn" | "os_fingerprint") => (
    <NumberField
      name={`${key}.timeout_ms`}
      label={t("nodes.scan.method.timeout")}
      help={t("nodes.scan.method.timeout_help")}
      error={errorText(`${key}.timeout_ms`)}
      value={draft.config[key].timeout_ms}
      onChange={(v) => setMethod(key, "timeout_ms", v ?? Number.NaN)}
    />
  );

  /** The interface override of a raw-socket method; empty means the one the probe's address chooses. */
  const rawInterface = (key: "arp_sweep" | "tcp_syn" | "os_fingerprint" | "lldp" | "dhcp_snoop") => (
    <Field name={`${key}.interface`} label={t("nodes.scan.raw.interface")} help={t("nodes.scan.raw.interface_help")} error={errorText(`${key}.interface`)}>
      {(c) => (
        <input
          {...c}
          class="input mono"
          spellcheck={false}
          autocomplete="off"
          value={draft.config[key].interface ?? ""}
          onInput={(e) => {
            const text = e.currentTarget.value.trim();
            setMethod(key, "interface", text === "" ? null : text);
          }}
        />
      )}
    </Field>
  );

  /** The listen window of a passive raw-socket method. */
  const listen = (key: "lldp" | "dhcp_snoop") => (
    <NumberField
      name={`${key}.listen_secs`}
      label={t("nodes.scan.raw.listen")}
      help={t("nodes.scan.raw.listen_help")}
      error={errorText(`${key}.listen_secs`)}
      value={draft.config[key].listen_secs}
      onChange={(v) => setMethod(key, "listen_secs", v ?? Number.NaN)}
    />
  );

  const methodFields = (key: ConfigMethod): JSX.Element => (
    <Switch>
      <Match when={key === "arp_sweep"}>
        <FieldRow>
          {timeout("arp_sweep")}
          {rawInterface("arp_sweep")}
        </FieldRow>
      </Match>
      <Match when={key === "tcp_syn"}>
        <FieldRow>
          {timeout("tcp_syn")}
          <Field name="tcp_syn.targets" label={t("nodes.scan.tcp.targets")} help={t("nodes.scan.tcp.targets_help")} error={errorText("tcp_syn.targets")}>
            {(c) => (
              <SelectInput
                {...c}
                value={draft.config.tcp_syn.targets}
                options={[
                  { value: "known", label: t("nodes.scan.tcp.targets_known") },
                  { value: "all", label: t("nodes.scan.tcp.targets_all") },
                ]}
                onChange={(v) => setMethod("tcp_syn", "targets", v)}
              />
            )}
          </Field>
        </FieldRow>
        {rawInterface("tcp_syn")}
      </Match>
      <Match when={key === "os_fingerprint"}>
        <FieldRow>
          {timeout("os_fingerprint")}
          {rawInterface("os_fingerprint")}
        </FieldRow>
      </Match>
      <Match when={key === "lldp"}>
        <FieldRow>
          {listen("lldp")}
          {rawInterface("lldp")}
        </FieldRow>
        <SwitchField
          name="lldp.cdp"
          label={t("nodes.scan.lldp.cdp")}
          help={t("nodes.scan.lldp.cdp_help")}
          checked={draft.config.lldp.cdp}
          onChange={(v) => setMethod("lldp", "cdp", v)}
        />
      </Match>
      <Match when={key === "dhcp_snoop"}>
        <FieldRow>
          {listen("dhcp_snoop")}
          {rawInterface("dhcp_snoop")}
        </FieldRow>
      </Match>
      <Match when={key === "icmp"}>{timeout("icmp")}</Match>
      <Match when={key === "tcp_connect"}>
        <Field name="tcp_connect.ports" label={t("nodes.scan.tcp.ports")} help={t("nodes.scan.tcp.ports_help")} error={errorText("tcp_connect.ports", "entries")}>
          {(c) => <input {...c} class="input mono" spellcheck={false} autocomplete="off" value={draft.ports} onInput={(e) => setText("ports", e.currentTarget.value)} />}
        </Field>
        <FieldRow>
          {timeout("tcp_connect")}
          <Field name="tcp_connect.targets" label={t("nodes.scan.tcp.targets")} help={t("nodes.scan.tcp.targets_help")} error={errorText("tcp_connect.targets")}>
            {(c) => (
              <SelectInput
                {...c}
                value={draft.config.tcp_connect.targets}
                options={[
                  { value: "known", label: t("nodes.scan.tcp.targets_known") },
                  { value: "all", label: t("nodes.scan.tcp.targets_all") },
                ]}
                onChange={(v) => setMethod("tcp_connect", "targets", v)}
              />
            )}
          </Field>
        </FieldRow>
        <SwitchField
          name="tcp_connect.tls_hint"
          label={t("nodes.scan.tcp.tls_hint")}
          help={t("nodes.scan.tcp.tls_hint_help")}
          checked={draft.config.tcp_connect.tls_hint}
          onChange={(v) => setMethod("tcp_connect", "tls_hint", v)}
        />
      </Match>
      <Match when={key === "reverse_dns"}>
        <Field name="reverse_dns.servers" label={t("nodes.scan.dns.servers")} help={t("nodes.scan.dns.servers_help")} error={errorText("reverse_dns.servers", "lines")}>
          {(c) => (
            <textarea {...c} class="input mono" rows={2} spellcheck={false} value={draft.servers} onInput={(e) => setText("servers", e.currentTarget.value)} />
          )}
        </Field>
        {timeout("reverse_dns")}
      </Match>
      <Match when={key === "mdns"}>
        <FieldRow>
          <NumberField
            name="mdns.listen_secs"
            label={t("nodes.scan.mdns.listen")}
            help={t("nodes.scan.mdns.listen_help")}
            error={errorText("mdns.listen_secs")}
            value={draft.config.mdns.listen_secs}
            onChange={(v) => setMethod("mdns", "listen_secs", v ?? Number.NaN)}
          />
          <NumberField
            name="mdns.unicast_port"
            label={t("nodes.scan.mdns.unicast_port")}
            help={t("nodes.scan.mdns.unicast_port_help")}
            error={errorText("mdns.unicast_port")}
            value={draft.config.mdns.unicast_port}
            onChange={(v) => setMethod("mdns", "unicast_port", v ?? Number.NaN)}
          />
        </FieldRow>
        <Field name="mdns.group" label={t("nodes.scan.mdns.group")} help={t("nodes.scan.mdns.group_help")} error={errorText("mdns.group")}>
          {(c) => (
            <input {...c} class="input mono" spellcheck={false} autocomplete="off" value={draft.config.mdns.group} onInput={(e) => setMethod("mdns", "group", e.currentTarget.value)} />
          )}
        </Field>
        <SwitchField
          name="mdns.passive"
          label={t("nodes.scan.mdns.passive")}
          help={t("nodes.scan.mdns.passive_help")}
          checked={draft.config.mdns.passive}
          onChange={(v) => setMethod("mdns", "passive", v)}
        />
      </Match>
      <Match when={key === "llmnr"}>
        <FieldRow>
          <NumberField
            name="llmnr.port"
            label={t("nodes.scan.llmnr.port")}
            error={errorText("llmnr.port")}
            value={draft.config.llmnr.port}
            onChange={(v) => setMethod("llmnr", "port", v ?? Number.NaN)}
          />
          {timeout("llmnr")}
        </FieldRow>
      </Match>
      <Match when={key === "snmp"}>
        <FieldRow>
          {timeout("snmp")}
          <NumberField
            name="snmp.retries"
            label={t("nodes.scan.snmp.retries")}
            help={t("nodes.scan.snmp.retries_help")}
            error={errorText("snmp.retries")}
            value={draft.config.snmp.retries}
            onChange={(v) => setMethod("snmp", "retries", v ?? Number.NaN)}
          />
        </FieldRow>
        <SwitchField
          name="snmp.attach_on_lldp_ports"
          label={t("nodes.scan.snmp.lldp_ports")}
          help={t("nodes.scan.snmp.lldp_ports_help")}
          checked={draft.config.snmp.attach_on_lldp_ports}
          onChange={(v) => setMethod("snmp", "attach_on_lldp_ports", v)}
        />
        {devices()}
      </Match>
    </Switch>
  );

  /** The table of SNMP devices. */
  const devices = (): JSX.Element => (
    <div class="scan-devices" data-testid="scan-devices" role="group" aria-labelledby={`${noteId}-devices`}>
      <h3 id={`${noteId}-devices`}>{t("nodes.scan.devices.title")}</h3>
      <p class="help">{t("nodes.scan.devices.help")}</p>
      <Show when={draft.config.snmp.devices.length > 0} fallback={<p class="muted" data-testid="scan-devices-empty">{t("nodes.scan.devices.empty")}</p>}>
        <div class="scan-table-wrap">
          <table class="scan-table">
            <thead>
              <tr>
                <th scope="col">{t("nodes.scan.devices.address")}</th>
                <th scope="col">{t("nodes.scan.devices.port")}</th>
                <th scope="col">{t("nodes.scan.devices.name")}</th>
                <th scope="col">{t("nodes.scan.devices.user")}</th>
                <th scope="col">{t("nodes.scan.devices.auth")}</th>
                <th scope="col">{t("nodes.scan.devices.auth_secret")}</th>
                <th scope="col">{t("nodes.scan.devices.privacy")}</th>
                <th scope="col">{t("nodes.scan.devices.privacy_secret")}</th>
                <Show when={props.admin}>
                  <th scope="col">
                    <span class="sr-only">{t("nodes.scan.devices.actions")}</span>
                  </th>
                </Show>
              </tr>
            </thead>
            <tbody>
              <For each={draft.config.snmp.devices}>
                {(device, i) => {
                  const label = (column: string) => t("nodes.scan.devices.row_label", { column, n: i() + 1 });
                  return (
                    <tr data-testid="scan-device" data-index={i()} classList={{ lacking: lacking().has(device.address) }}>
                      <td>
                        <input
                          class="input mono"
                          spellcheck={false}
                          autocomplete="off"
                          value={device.address}
                          aria-label={label(t("nodes.scan.devices.address"))}
                          aria-invalid={deviceInvalid(i(), "address")}
                          aria-describedby={deviceErrors().length > 0 ? `${noteId}-device-errors` : undefined}
                          data-testid={`device-address-${i()}`}
                          onInput={(e) => setDevice(i(), { address: e.currentTarget.value })}
                        />
                        <Show when={lacking().has(device.address)}>
                          <span class="tag discrepancy" data-testid="device-lacking">
                            <Icon name="key" size="xs" />
                            {t("nodes.scan.devices.lacking")}
                          </span>
                        </Show>
                      </td>
                      <td>
                        <input
                          class="input num scan-port"
                          type="number"
                          inputmode="numeric"
                          value={shown(device.port)}
                          aria-label={label(t("nodes.scan.devices.port"))}
                          aria-invalid={deviceInvalid(i(), "port")}
                          data-testid={`device-port-${i()}`}
                          onInput={(e) => setDevice(i(), { port: asNumber(e.currentTarget.value) })}
                        />
                      </td>
                      <td>
                        <input
                          class="input"
                          spellcheck={false}
                          autocomplete="off"
                          value={device.name ?? ""}
                          aria-label={label(t("nodes.scan.devices.name"))}
                          data-testid={`device-name-${i()}`}
                          onInput={(e) => setDevice(i(), { name: e.currentTarget.value })}
                        />
                      </td>
                      <td>
                        <input
                          class="input mono"
                          spellcheck={false}
                          autocomplete="off"
                          value={device.user}
                          aria-label={label(t("nodes.scan.devices.user"))}
                          aria-invalid={deviceInvalid(i(), "user")}
                          data-testid={`device-user-${i()}`}
                          onInput={(e) => setDevice(i(), { user: e.currentTarget.value })}
                        />
                      </td>
                      <td>
                        <SelectInput
                          aria-label={label(t("nodes.scan.devices.auth"))}
                          data-testid={`device-auth-${i()}`}
                          value={device.auth ?? ""}
                          options={authOptions()}
                          onChange={(v) => setDevice(i(), { auth: v === "" ? null : (v as SnmpDevice["auth"]) })}
                        />
                      </td>
                      <td>
                        <SelectInput
                          aria-label={label(t("nodes.scan.devices.auth_secret"))}
                          data-testid={`device-auth-secret-${i()}`}
                          value={device.auth_secret ?? ""}
                          options={secretOptions(device.auth_secret)}
                          onChange={(v) => setDevice(i(), { auth_secret: v === "" ? null : v })}
                        />
                      </td>
                      <td>
                        <SelectInput
                          aria-label={label(t("nodes.scan.devices.privacy"))}
                          data-testid={`device-privacy-${i()}`}
                          value={device.privacy ?? ""}
                          options={privacyOptions()}
                          onChange={(v) => setDevice(i(), { privacy: v === "" ? null : (v as SnmpDevice["privacy"]) })}
                        />
                      </td>
                      <td>
                        <SelectInput
                          aria-label={label(t("nodes.scan.devices.privacy_secret"))}
                          data-testid={`device-privacy-secret-${i()}`}
                          value={device.privacy_secret ?? ""}
                          options={secretOptions(device.privacy_secret)}
                          onChange={(v) => setDevice(i(), { privacy_secret: v === "" ? null : v })}
                        />
                      </td>
                      <Show when={props.admin}>
                        <td>
                          <button
                            type="button"
                            class="icon-btn"
                            aria-label={t("nodes.scan.devices.remove", { n: i() + 1 })}
                            title={t("nodes.scan.devices.remove", { n: i() + 1 })}
                            data-testid={`device-remove-${i()}`}
                            onClick={() => removeDevice(i())}
                          >
                            <Icon name="trash" />
                          </button>
                        </td>
                      </Show>
                    </tr>
                  );
                }}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
      <Show when={deviceErrors().length > 0}>
        <ul class="scan-device-errors" id={`${noteId}-device-errors`}>
          <For each={deviceErrors()}>
            {(e) => (
              <li>
                <FieldNote
                  id={`${noteId}-${e.field}`}
                  field={e.field}
                  error={t("nodes.scan.devices.error", {
                    n: e.index + 1,
                    column: e.member ? (tDynamic(`nodes.scan.devices.${e.member}`) ?? e.member) : t("nodes.scan.devices.title"),
                    error: errorWord(e.code),
                  })}
                />
              </li>
            )}
          </For>
        </ul>
      </Show>
      <Show when={props.admin}>
        <div class="row-actions">
          <button type="button" class="btn sm" data-testid="device-add" onClick={addDevice}>
            <Icon name="plus" />
            {t("nodes.scan.devices.add")}
          </button>
        </div>
      </Show>
    </div>
  );

  return (
    <form
      ref={form}
      class="nodes-form scan-form"
      aria-label={t("nodes.scan.form.label")}
      data-testid="scan-config-form"
      data-dirty={dirty() ? "true" : "false"}
      onSubmit={(e) => void save(e)}
      novalidate
    >
      <Show when={!props.admin}>
        <Notice kind="info" testid="scan-config-readonly">
          {t("nodes.scan.form.readonly")}
        </Notice>
      </Show>
      <Show when={stale()}>
        <Notice kind="warn" role="alert" testid="scan-config-stale">
          {t("nodes.scan.form.stale")}{" "}
          <button type="button" class="btn sm" disabled={busy()} data-testid="scan-config-reload" onClick={() => void reload()}>
            <Icon name="refresh" />
            {t("nodes.scan.form.reload")}
          </button>
        </Notice>
      </Show>
      <Show when={!stale() && remote()}>
        <Notice kind="warn" role="status" testid="scan-config-remote">
          {t("nodes.scan.form.remote")}{" "}
          <button type="button" class="btn sm" disabled={busy()} data-testid="scan-config-reload" onClick={() => void reload()}>
            <Icon name="refresh" />
            {t("nodes.scan.form.reload")}
          </button>
        </Notice>
      </Show>
      <Show when={unplaced().length > 0}>
        <Notice kind="bad" role="alert" testid="scan-config-errors" title={t("nodes.scan.error.general")}>
          <ul class="scan-error-list">
            <For each={unplaced()}>
              {(e) => (
                <li>
                  <span class="mono">{e.field}</span>: {errorWord(e.code)}
                </li>
              )}
            </For>
          </ul>
        </Notice>
      </Show>
      <Show when={error() && !stale() && !fieldFailure()}>
        <ErrorNotice error={error()} />
      </Show>

      <fieldset class="nodes-fieldset scan-fields" disabled={!props.admin}>
        <Group title={t("nodes.scan.group.general")} testid="scan-group-general">
          <div class="scan-switches">
            <SwitchField name="enabled" label={t("nodes.scan.field.enabled")} help={t("nodes.scan.field.enabled_help")} checked={draft.config.enabled} onChange={(v) => set("enabled", v)} />
            <SwitchField name="active" label={t("nodes.scan.field.active")} help={t("nodes.scan.field.active_help")} checked={draft.config.active} onChange={(v) => set("active", v)} />
          </div>
          <FieldRow>
            <Field name="rate" label={t("nodes.scan.field.rate")} help={t("nodes.scan.field.rate_help")} error={errorText("rate")}>
              {(c) => <SelectInput {...c} value={draft.config.rate} options={rateOptions()} onChange={(v) => set("rate", v)} />}
            </Field>
            <NumberField
              name="packets_per_second"
              label={t("nodes.scan.field.pps")}
              help={t("nodes.scan.field.pps_help")}
              error={errorText("packets_per_second")}
              value={draft.config.packets_per_second}
              optional
              onChange={(v) => set("packets_per_second", v)}
            />
          </FieldRow>
          <FieldRow three>
            <NumberField
              name="concurrency"
              label={t("nodes.scan.field.concurrency")}
              help={t("nodes.scan.field.concurrency_help")}
              error={errorText("concurrency")}
              value={draft.config.concurrency}
              onChange={(v) => set("concurrency", v ?? Number.NaN)}
            />
            <NumberField
              name="per_host_interval_ms"
              label={t("nodes.scan.field.per_host")}
              help={t("nodes.scan.field.per_host_help")}
              error={errorText("per_host_interval_ms")}
              value={draft.config.per_host_interval_ms}
              onChange={(v) => set("per_host_interval_ms", v ?? Number.NaN)}
            />
            <NumberField
              name="max_hosts_per_prefix"
              label={t("nodes.scan.field.max_hosts")}
              help={t("nodes.scan.field.max_hosts_help")}
              error={errorText("max_hosts_per_prefix")}
              value={draft.config.max_hosts_per_prefix}
              onChange={(v) => set("max_hosts_per_prefix", v ?? Number.NaN)}
            />
          </FieldRow>
          <FieldRow>
            <Field name="vrf" label={t("nodes.scan.field.vrf")} help={t("nodes.scan.field.vrf_help")} error={errorText("vrf")}>
              {(c) => <SelectInput {...c} value={draft.config.vrf ?? ""} options={vrfOptions()} onChange={(v) => set("vrf", v === "" ? null : v)} />}
            </Field>
            <Field name="timezone" label={t("nodes.scan.field.timezone")} help={t("nodes.scan.field.timezone_help")} error={errorText("timezone")}>
              {(c) => (
                <input
                  {...c}
                  class="input mono"
                  spellcheck={false}
                  autocomplete="off"
                  value={draft.config.timezone ?? ""}
                  onInput={(e) => set("timezone", e.currentTarget.value === "" ? null : e.currentTarget.value)}
                />
              )}
            </Field>
          </FieldRow>
        </Group>

        <Group title={t("nodes.scan.group.scope")} testid="scan-group-scope">
          <FieldRow>
            <Field name="prefixes" label={t("nodes.scan.field.prefixes")} help={t("nodes.scan.field.prefixes_help")} error={errorText("prefixes", "lines")}>
              {(c) => (
                <textarea {...c} class="input mono" rows={4} spellcheck={false} placeholder="192.0.2.0/24" value={draft.prefixes} onInput={(e) => setText("prefixes", e.currentTarget.value)} />
              )}
            </Field>
            <Field name="exclude" label={t("nodes.scan.field.exclude")} help={t("nodes.scan.field.exclude_help")} error={errorText("exclude", "lines")}>
              {(c) => (
                <textarea {...c} class="input mono" rows={4} spellcheck={false} placeholder="192.0.2.1" value={draft.exclude} onInput={(e) => setText("exclude", e.currentTarget.value)} />
              )}
            </Field>
          </FieldRow>
          <Field name="blackout" label={t("nodes.scan.field.blackout")} help={t("nodes.scan.field.blackout_help")} error={errorText("blackout", "lines")}>
            {(c) => (
              <textarea {...c} class="input mono" rows={3} spellcheck={false} value={draft.blackout} onInput={(e) => setText("blackout", e.currentTarget.value)} />
            )}
          </Field>
        </Group>

        <Group title={t("nodes.scan.group.methods")} testid="scan-group-methods">
          <For each={CONFIG_METHODS}>
            {({ key, raw }) => (
              <fieldset class="nodes-fieldset scan-method" classList={{ raw }} data-testid={`method-${key}`} data-raw={raw ? "true" : "false"}>
                <legend>
                  {methodWord(key, "name")}
                  <Show when={raw}>
                    <span class="tag discrepancy" data-testid={`method-${key}-raw`}>
                      <Icon name="lock" size="xs" />
                      {t("nodes.scan.method.raw")}
                    </span>
                  </Show>
                </legend>
                <p class="help">{methodWord(key, "help")}</p>
                {common(key)}
                {methodFields(key)}
              </fieldset>
            )}
          </For>
        </Group>
      </fieldset>

      <Show when={props.admin}>
        <div class="dialog-actions scan-actions">
          <button
            type="button"
            class="btn ghost"
            disabled={!dirty() || busy()}
            data-testid="scan-config-revert"
            onClick={() => {
              adopt(base());
            }}
          >
            {t("nodes.scan.form.revert")}
          </button>
          <button type="submit" class="btn primary" disabled={!dirty() || busy()} data-testid="scan-config-save">
            {t("common.action.save")}
          </button>
        </div>
      </Show>
    </form>
  );
}
