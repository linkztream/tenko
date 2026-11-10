// The "Secure updates (Kerberos)" part of the update section on the settings tab of a primary
// zone: the realms whose GSS-TSIG tickets the zone accepts, the ownership rule and its hold, the
// privileged groups and the DnsUpdateProxy group, all by SID. The draft keeps what the form
// edits; the policy it belongs to is carried through unchanged by `createUpdateDraft`.
import { createSignal, For, Show } from "solid-js";
import { Icon } from "../components/Icon";
import { Notice } from "../components/Notice";
import { t } from "../i18n";
import type { KerberosUpdate } from "./api";
import { Check, profileInForce } from "./Parts";

/** A security identifier: `S-1-` and at least one more sub-authority. */
const SID = /^S-1-\d+(-\d+)+$/;
const HOLD_MAX = 3650;
const HOLD_DEFAULT = 14;

/** The groups with a fixed relative identifier, by the last part of their SID. */
const RIDS = { "512": "domain_admins", "516": "domain_controllers", "519": "enterprise_admins" } as const;
const DOMAIN_GROUPS = ["512", "516", "519"] as const;

/** The name of a well-known group a SID ends with, when it does. */
function ridName(sid: string): string | undefined {
  const rid = sid.slice(sid.lastIndexOf("-") + 1);
  if (!Object.hasOwn(RIDS, rid)) return undefined;
  return t(`dns.update.kerberos.rid_${RIDS[rid as keyof typeof RIDS]}`);
}

/** The settings as the form edits them, every default filled in, so two of them compare as text. */
export function kerberosOf(k: KerberosUpdate | null | undefined) {
  return {
    realms: [...(k?.realms ?? [])],
    ownership: k?.ownership ?? "windows",
    owner_hold_days: k?.owner_hold_days ?? HOLD_DEFAULT,
    privileged: [...(k?.privileged ?? [])],
    update_proxy: k?.update_proxy ?? null,
  };
}

/** Realms as typed: separated by commas or spaces, upper case. */
function splitRealms(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((r) => r.trim().toUpperCase())
    .filter((r) => r !== "");
}

/** The typed days when they are a whole number in range, otherwise null. */
function parseHold(text: string): number | null {
  const s = text.trim();
  if (!/^\d{1,4}$/.test(s)) return null;
  const n = Number(s);
  return n <= HOLD_MAX ? n : null;
}

/** The Kerberos part of the update form as signals, with the local checks and the value to send. */
export function createKerberosDraft(initial: KerberosUpdate | null | undefined) {
  const first = kerberosOf(initial);
  const [enabled, setEnabled] = createSignal(initial !== null && initial !== undefined);
  const [realms, setRealms] = createSignal(first.realms.join(", "));
  const [ownership, setOwnership] = createSignal<"windows" | "none">(first.ownership);
  const [hold, setHold] = createSignal(String(first.owner_hold_days));
  const [privileged, setPrivileged] = createSignal<string[]>(first.privileged);
  const [proxy, setProxy] = createSignal(first.update_proxy ?? "");
  const [sidText, setSidText] = createSignal("");
  const [domainSid, setDomainSid] = createSignal("");
  const [local, setLocal] = createSignal<Record<string, string>>({});

  const addSids = (sids: readonly string[]) => setPrivileged((now) => [...now, ...sids.filter((s) => !now.includes(s))]);

  return {
    enabled,
    setEnabled,
    realms,
    setRealms,
    ownership,
    setOwnership,
    hold,
    setHold,
    privileged,
    removePrivileged: (sid: string) => setPrivileged((now) => now.filter((s) => s !== sid)),
    proxy,
    setProxy,
    sidText,
    setSidText,
    domainSid,
    setDomainSid,
    /** The errors of the add buttons (not of the save). */
    local,
    addSid: () => {
      const sid = sidText().trim().toUpperCase();
      if (!SID.test(sid)) {
        setLocal({ ...local(), "update.kerberos.privileged": t("dns.update.kerberos.sid_invalid") });
        return;
      }
      setLocal({ ...local(), "update.kerberos.privileged": "" });
      addSids([sid]);
      setSidText("");
    },
    addDomainGroups: () => {
      const sid = domainSid().trim().toUpperCase();
      if (!SID.test(sid)) {
        setLocal({ ...local(), "update.kerberos.domain_sid": t("dns.update.kerberos.sid_invalid") });
        return;
      }
      setLocal({ ...local(), "update.kerberos.domain_sid": "" });
      addSids(DOMAIN_GROUPS.map((rid) => `${sid}-${rid}`));
      setDomainSid("");
    },
    /** The errors by field id when Kerberos is on; empty when it may be sent. */
    check: (): Record<string, string> => {
      const errors: Record<string, string> = {};
      if (!enabled()) return errors;
      if (splitRealms(realms()).length === 0) errors["update.kerberos.realms"] = t("dns.update.kerberos.realms_required");
      if (parseHold(hold()) === null) errors["update.kerberos.owner_hold_days"] = t("dns.update.kerberos.hold_invalid");
      const p = proxy().trim();
      if (p !== "" && !SID.test(p.toUpperCase())) errors["update.kerberos.update_proxy"] = t("dns.update.kerberos.sid_invalid");
      return errors;
    },
    /** The settings to send, on top of those the zone has (fields this form does not know stay). */
    value: (base: KerberosUpdate | null | undefined): KerberosUpdate => ({
      ...base,
      realms: splitRealms(realms()),
      ownership: ownership(),
      owner_hold_days: parseHold(hold()) ?? HOLD_DEFAULT,
      privileged: privileged(),
      update_proxy: proxy().trim() === "" ? null : proxy().trim().toUpperCase(),
    }),
  };
}

export type KerberosDraft = ReturnType<typeof createKerberosDraft>;

/** One labeled single-line control with its error or help (the DNS `Field` is for `dns-f-` ids only). */
function Line(props: { id: string; label: string; error: string | undefined; help: string; value: string; disabled: boolean; onInput: (v: string) => void }) {
  return (
    <div class="field">
      <label for={`dns-f-${props.id}`}>{props.label}</label>
      <input
        id={`dns-f-${props.id}`}
        class="input mono"
        value={props.value}
        disabled={props.disabled}
        spellcheck={false}
        autocomplete="off"
        aria-invalid={props.error ? "true" : undefined}
        aria-describedby={props.error ? `dns-f-${props.id}-error` : `dns-f-${props.id}-help`}
        data-testid={`field-${props.id}`}
        onInput={(e) => props.onInput(e.currentTarget.value)}
      />
      <Show
        when={props.error}
        fallback={
          <span class="help" id={`dns-f-${props.id}-help`}>
            {props.help}
          </span>
        }
      >
        <span class="help bad" id={`dns-f-${props.id}-error`} data-testid="field-error" data-field={props.id}>
          {props.error}
        </span>
      </Show>
    </div>
  );
}

/** The Kerberos subsection; `errors` holds the checks and the server's refusals by field id. */
export function KerberosSection(props: { draft: KerberosDraft; errors: Record<string, string>; disabled: boolean }) {
  const d = () => props.draft;
  const error = (id: string) => props.errors[id] || d().local()[id] || undefined;
  const profileName = () => t(`profile.${profileInForce()}.name`);
  const ownershipHelp = () => {
    const base = t("dns.update.kerberos.ownership_help");
    return profileInForce() === "hardened" ? `${base} ${t("dns.update.kerberos.ownership_hardened", { profile: profileName() })}` : base;
  };
  const onEnter = (e: KeyboardEvent, action: () => void) => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    action();
  };
  return (
    <div class="dns-kerberos" role="group" aria-labelledby="dns-kerberos-title" data-testid="zone-kerberos" data-state={d().enabled() ? "on" : "off"}>
      <h3 id="dns-kerberos-title">{t("dns.update.kerberos.title")}</h3>
      <p>{t("dns.update.kerberos.body")}</p>
      <Check
        id="update.kerberos.enabled"
        label={t("dns.update.kerberos.enable")}
        help={t("dns.update.kerberos.enable_help")}
        checked={d().enabled()}
        disabled={props.disabled}
        onChange={d().setEnabled}
      />
      <Show when={d().enabled()}>
        <Line
          id="update.kerberos.realms"
          label={t("dns.update.kerberos.realms")}
          help={t("dns.update.kerberos.realms_help")}
          error={error("update.kerberos.realms")}
          value={d().realms()}
          disabled={props.disabled}
          onInput={d().setRealms}
        />
        <div class="field-row">
          <div class="field">
            <label for="dns-f-update.kerberos.ownership">{t("dns.update.kerberos.ownership")}</label>
            <select
              id="dns-f-update.kerberos.ownership"
              class="select"
              value={d().ownership()}
              disabled={props.disabled}
              aria-describedby="dns-f-update.kerberos.ownership-help"
              data-testid="field-update.kerberos.ownership"
              onChange={(e) => d().setOwnership(e.currentTarget.value as "windows" | "none")}
            >
              <option value="windows">{t("dns.update.kerberos.ownership_windows")}</option>
              <option value="none">{t("dns.update.kerberos.ownership_none")}</option>
            </select>
            <span class="help" id="dns-f-update.kerberos.ownership-help" data-testid="kerberos-ownership-help">
              {ownershipHelp()}
            </span>
          </div>
          <Line
            id="update.kerberos.owner_hold_days"
            label={t("dns.update.kerberos.hold")}
            help={t("dns.update.kerberos.hold_help")}
            error={error("update.kerberos.owner_hold_days")}
            value={d().hold()}
            disabled={props.disabled}
            onInput={d().setHold}
          />
        </div>
        <div class="field" role="group" aria-labelledby="dns-kerberos-privileged-label" data-testid="kerberos-privileged-list">
          <span id="dns-kerberos-privileged-label" class="label">
            {t("dns.update.kerberos.privileged")}
          </span>
          <Show
            when={d().privileged().length > 0}
            fallback={
              <Notice kind="warn" role="status" testid="kerberos-no-privileged">
                {t("dns.update.kerberos.no_privileged")}
              </Notice>
            }
          >
            <ul class="dns-draft" aria-label={t("dns.update.kerberos.privileged")}>
              <For each={d().privileged()}>
                {(sid) => (
                  <li data-testid="kerberos-privileged" data-key={sid}>
                    <span class="mono">{sid}</span>
                    <Show when={ridName(sid)}>{(name) => <span class="muted"> {name()}</span>}</Show>
                    <button
                      type="button"
                      class="icon-btn"
                      aria-label={t("dns.update.kerberos.privileged_remove", { sid })}
                      data-testid="kerberos-privileged-remove"
                      disabled={props.disabled}
                      onClick={() => d().removePrivileged(sid)}
                    >
                      <Icon name="x" size="xs" />
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </Show>
          <div class="form-row">
            <input
              id="dns-f-update.kerberos.sid"
              class="input mono"
              value={d().sidText()}
              disabled={props.disabled}
              spellcheck={false}
              autocomplete="off"
              aria-label={t("dns.update.kerberos.sid_label")}
              aria-invalid={error("update.kerberos.privileged") ? "true" : undefined}
              aria-describedby="dns-f-update.kerberos.privileged-help"
              data-testid="field-update.kerberos.sid"
              onInput={(e) => d().setSidText(e.currentTarget.value)}
              onKeyDown={(e) => onEnter(e, () => d().addSid())}
            />
            <button type="button" class="btn sm" data-testid="kerberos-sid-add" disabled={props.disabled} onClick={() => d().addSid()}>
              {t("dns.update.kerberos.sid_add")}
            </button>
          </div>
          <Show
            when={error("update.kerberos.privileged")}
            fallback={
              <span class="help" id="dns-f-update.kerberos.privileged-help">
                {t("dns.update.kerberos.privileged_help")}
              </span>
            }
          >
            {(message) => (
              <span class="help bad" id="dns-f-update.kerberos.privileged-help" data-testid="field-error" data-field="update.kerberos.privileged">
                {message()}
              </span>
            )}
          </Show>
          <div class="form-row">
            <input
              id="dns-f-update.kerberos.domain_sid"
              class="input mono"
              value={d().domainSid()}
              disabled={props.disabled}
              spellcheck={false}
              autocomplete="off"
              aria-label={t("dns.update.kerberos.domain_sid")}
              aria-invalid={error("update.kerberos.domain_sid") ? "true" : undefined}
              aria-describedby="dns-f-update.kerberos.domain_sid-help"
              data-testid="field-update.kerberos.domain_sid"
              onInput={(e) => d().setDomainSid(e.currentTarget.value)}
              onKeyDown={(e) => onEnter(e, () => d().addDomainGroups())}
            />
            <button type="button" class="btn sm" data-testid="kerberos-domain-add" disabled={props.disabled} onClick={() => d().addDomainGroups()}>
              {t("dns.update.kerberos.domain_add")}
            </button>
          </div>
          <Show
            when={error("update.kerberos.domain_sid")}
            fallback={
              <span class="help" id="dns-f-update.kerberos.domain_sid-help">
                {t("dns.update.kerberos.domain_help")}
              </span>
            }
          >
            {(message) => (
              <span class="help bad" id="dns-f-update.kerberos.domain_sid-help" data-testid="field-error" data-field="update.kerberos.domain_sid">
                {message()}
              </span>
            )}
          </Show>
        </div>
        <Line
          id="update.kerberos.update_proxy"
          label={t("dns.update.kerberos.proxy")}
          help={t("dns.update.kerberos.proxy_help")}
          error={error("update.kerberos.update_proxy")}
          value={d().proxy()}
          disabled={props.disabled}
          onInput={d().setProxy}
        />
      </Show>
    </div>
  );
}
