// Creating an enrollment token (docs/cluster.md, section 1): the roles the node may take, its
// name, the VRF of its observations and how long the token lives; then the token, shown this
// once, with the exact `tenko node enroll` command line to run on the node and the fingerprint
// of the CA root to compare. Nothing here keeps the token: closing the dialog forgets it.
import { createResource, createSignal, For, Show } from "solid-js";
import { fetchAll } from "../api/paginate";
import { createEnrollment, ENROLL_ROLES, type CreatedEnrollment, type EnrollRole } from "../api/nodes";
import type { Vrf } from "../api/types";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatDateTime, t } from "../i18n";
import { Field, FieldRow, SelectInput } from "../ipam/formKit";
import { copyValue } from "../secrets/clipboard";
import { moduleRunning } from "../updates/modules";
import { DEFAULT_LIFETIME, enrollCommand, fingerprintPairs, LIFETIMES, lifetimeWord, roleWord } from "./model";
import "./nodes.css";

const NAME_RULE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

/** The longest life of a controller token (docs/cluster.md, section 1.1). */
const CONTROLLER_MAX_LIFETIME = 3_600;

export function EnrollDialog(props: {
  onCreated: () => void;
  onClose: () => void;
  /**
   * Fixes the roles of the token and hides the role choice: the cluster page asks for
   * `["controller"]`. The nodes page leaves it out and lets the person choose.
   */
  roles?: readonly string[];
  /** The title of the dialog, instead of the one of a node token. */
  title?: string;
  /** The text under the title, instead of the one about nodes. */
  intro?: string;
  /** The text under the token, instead of the one that names the roles of a node. */
  next?: string;
}) {
  const [roles, setRoles] = createSignal<EnrollRole[]>(["probe"]);
  const fixed = () => props.roles !== undefined && props.roles.length > 0;
  const lifetimes = () => (props.roles?.includes("controller") ? LIFETIMES.filter((s) => s <= CONTROLLER_MAX_LIFETIME) : LIFETIMES);
  const [name, setName] = createSignal("");
  const [vrf, setVrf] = createSignal("");
  const [lifetime, setLifetime] = createSignal(String(DEFAULT_LIFETIME));
  const [tried, setTried] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [created, setCreated] = createSignal<CreatedEnrollment | null>(null);

  const [vrfs] = createResource(async () => {
    if (!moduleRunning("ipam")) return [] as Vrf[];
    try {
      return (await fetchAll<Vrf>("/api/v1/vrfs")).items;
    } catch {
      return [] as Vrf[];
    }
  });

  const nameError = () => {
    const n = name().trim();
    return n !== "" && !NAME_RULE.test(n) ? t("nodes.enroll.name_rule") : undefined;
  };
  const rolesError = () => (!fixed() && roles().length === 0 ? t("nodes.enroll.roles_required") : undefined);

  const toggleRole = (role: EnrollRole, on: boolean) => setRoles(on ? [...new Set([...roles(), role])] : roles().filter((r) => r !== role));

  const submit = async (e: Event) => {
    e.preventDefault();
    setTried(true);
    if (nameError() || rolesError() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const answer = await createEnrollment({
        roles: props.roles ? [...props.roles] : ENROLL_ROLES.filter((r) => roles().includes(r)),
        name: name().trim() || null,
        vrf: vrf() || null,
        expires_in_secs: Number(lifetime()),
      });
      setCreated(answer);
      props.onCreated();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const copy = async (text: string, done: string) => {
    const outcome = await copyValue(text);
    toast(outcome === "copied" ? { kind: "ok", title: done } : { kind: "bad", title: t("nodes.enroll.copy_blocked") });
  };

  return (
    <Dialog label={props.title ?? t("nodes.enroll.title")} onClose={props.onClose} class="dialog nodes-dialog">
      <Show
        when={created()}
        fallback={
          <form class="nodes-form" data-testid="dialog-enroll" onSubmit={(e) => void submit(e)} novalidate>
            <h2 class="dialog-title">{props.title ?? t("nodes.enroll.title")}</h2>
            <p class="muted">{props.intro ?? t("nodes.enroll.intro")}</p>
            <Show when={!fixed()}>
              <fieldset class="nodes-fieldset">
                <legend>{t("nodes.enroll.roles")}</legend>
                <For each={ENROLL_ROLES}>
                  {(role) => (
                    <label class="check-row">
                      <input
                        type="checkbox"
                        class="cb"
                        checked={roles().includes(role)}
                        data-testid={`field-role-${role}`}
                        onChange={(e) => toggleRole(role, e.currentTarget.checked)}
                      />
                      <span>
                        {roleWord(role)}
                        <small class="help">{t(`nodes.enroll.role_hint.${role}`)}</small>
                      </span>
                    </label>
                  )}
                </For>
                <Show when={tried() && rolesError()}>
                  <p class="help bad" role="alert">
                    <Icon name="alert" size="xs" /> {rolesError()}
                  </p>
                </Show>
              </fieldset>
            </Show>
            <FieldRow>
              <Field name="name" label={t("nodes.enroll.name")} help={t("nodes.enroll.name_help")} error={tried() ? nameError() : undefined}>
                {(c) => <input {...c} class="input mono" autocomplete="off" spellcheck={false} value={name()} onInput={(e) => setName(e.currentTarget.value)} />}
              </Field>
              <Field name="lifetime" label={t("nodes.enroll.lifetime")} help={t("nodes.enroll.lifetime_help")}>
                {(c) => (
                  <SelectInput {...c} value={lifetime()} options={lifetimes().map((s) => ({ value: String(s), label: lifetimeWord(s) }))} onChange={setLifetime} />
                )}
              </Field>
            </FieldRow>
            <Show when={(vrfs() ?? []).length > 1}>
              <Field name="vrf" label={t("nodes.enroll.vrf")} help={t("nodes.enroll.vrf_help")}>
                {(c) => (
                  <SelectInput
                    {...c}
                    value={vrf()}
                    options={[{ value: "", label: t("nodes.enroll.vrf_default") }, ...(vrfs() ?? []).map((v) => ({ value: v.id, label: v.name }))]}
                    onChange={setVrf}
                  />
                )}
              </Field>
            </Show>
            <ErrorNotice error={error()} />
            <div class="dialog-actions">
              <button type="button" class="btn ghost" onClick={() => props.onClose()}>
                {t("common.action.cancel")}
              </button>
              <button type="submit" class="btn primary" disabled={busy()} data-testid="form-submit">
                {t("nodes.enroll.create")}
              </button>
            </div>
          </form>
        }
      >
        {(c) => {
          const command = () => enrollCommand(c(), window.location.origin);
          return (
            <div class="nodes-form" data-testid="dialog-enroll-token">
              <h2 class="dialog-title">{t("nodes.enroll.created_title")}</h2>
              <Notice kind="warn" testid="enroll-once">
                {t("nodes.enroll.once", { expires: formatDateTime(c().enrollment.expires_at) })}
              </Notice>
              <div class="field">
                <span class="label">{t("nodes.enroll.command")}</span>
                <pre class="enroll-command mono" data-testid="enroll-command" tabIndex={0}>
                  {command()}
                </pre>
                <div class="row-actions">
                  <button type="button" class="btn primary" data-testid="nodes-copy-command" onClick={() => void copy(command(), t("nodes.enroll.copied_command"))}>
                    <Icon name="copy" />
                    {t("nodes.enroll.copy_command")}
                  </button>
                </div>
              </div>
              <div class="field">
                <span class="label">{t("nodes.enroll.token")}</span>
                <code class="enroll-token mono" data-testid="enroll-token">
                  {c().token}
                </code>
                <div class="row-actions">
                  <button type="button" class="btn" data-testid="nodes-copy-token" onClick={() => void copy(c().token, t("nodes.enroll.copied_token"))}>
                    <Icon name="copy" />
                    {t("nodes.enroll.copy_token")}
                  </button>
                </div>
              </div>
              <div class="field">
                <span class="label">{t("nodes.enroll.fingerprint")}</span>
                <code class="enroll-fingerprint mono" data-testid="enroll-fingerprint">
                  {fingerprintPairs(c().ca_fingerprint)}
                </code>
                <small class="help">{t("nodes.enroll.fingerprint_help")}</small>
              </div>
              <p class="muted">{props.next ?? t("nodes.enroll.next", { roles: c().enrollment.roles.map(roleWord).join(", ") })}</p>
              <div class="dialog-actions">
                <button type="button" class="btn primary" data-testid="enroll-done" onClick={() => props.onClose()}>
                  {t("nodes.enroll.done")}
                </button>
              </div>
            </div>
          );
        }}
      </Show>
    </Dialog>
  );
}
