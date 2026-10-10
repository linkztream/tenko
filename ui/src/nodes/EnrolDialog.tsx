// Creating an enrolment token (docs/cluster.md, section 1): the roles the node may take, its
// name, the VRF of its observations and how long the token lives; then the token, shown this
// once, with the exact `tenko node enrol` command line to run on the node and the fingerprint
// of the CA root to compare. Nothing here keeps the token: closing the dialog forgets it.
import { createResource, createSignal, For, Show } from "solid-js";
import { fetchAll } from "../api/paginate";
import { createEnrolment, ENROL_ROLES, type CreatedEnrolment, type EnrolRole } from "../api/nodes";
import type { Vrf } from "../api/types";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatDateTime, t } from "../i18n";
import { Field, FieldRow, SelectInput } from "../ipam/formKit";
import { copyValue } from "../secrets/clipboard";
import { moduleRunning } from "../updates/modules";
import { DEFAULT_LIFETIME, enrolCommand, fingerprintPairs, LIFETIMES, lifetimeWord, roleWord } from "./model";

const NAME_RULE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

export function EnrolDialog(props: { onCreated: () => void; onClose: () => void }) {
  const [roles, setRoles] = createSignal<EnrolRole[]>(["probe"]);
  const [name, setName] = createSignal("");
  const [vrf, setVrf] = createSignal("");
  const [lifetime, setLifetime] = createSignal(String(DEFAULT_LIFETIME));
  const [tried, setTried] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [created, setCreated] = createSignal<CreatedEnrolment | null>(null);

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
    return n !== "" && !NAME_RULE.test(n) ? t("nodes.enrol.name_rule") : undefined;
  };
  const rolesError = () => (roles().length === 0 ? t("nodes.enrol.roles_required") : undefined);

  const toggleRole = (role: EnrolRole, on: boolean) => setRoles(on ? [...new Set([...roles(), role])] : roles().filter((r) => r !== role));

  const submit = async (e: Event) => {
    e.preventDefault();
    setTried(true);
    if (nameError() || rolesError() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const answer = await createEnrolment({
        roles: ENROL_ROLES.filter((r) => roles().includes(r)),
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
    toast(outcome === "copied" ? { kind: "ok", title: done } : { kind: "bad", title: t("nodes.enrol.copy_blocked") });
  };

  return (
    <Dialog label={t("nodes.enrol.title")} onClose={props.onClose} class="dialog nodes-dialog">
      <Show
        when={created()}
        fallback={
          <form class="nodes-form" data-testid="dialog-enrol" onSubmit={(e) => void submit(e)} novalidate>
            <h2 class="dialog-title">{t("nodes.enrol.title")}</h2>
            <p class="muted">{t("nodes.enrol.intro")}</p>
            <fieldset class="nodes-fieldset">
              <legend>{t("nodes.enrol.roles")}</legend>
              <For each={ENROL_ROLES}>
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
                      <small class="help">{t(`nodes.enrol.role_hint.${role}`)}</small>
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
            <FieldRow>
              <Field name="name" label={t("nodes.enrol.name")} help={t("nodes.enrol.name_help")} error={tried() ? nameError() : undefined}>
                {(c) => <input {...c} class="input mono" autocomplete="off" spellcheck={false} value={name()} onInput={(e) => setName(e.currentTarget.value)} />}
              </Field>
              <Field name="lifetime" label={t("nodes.enrol.lifetime")} help={t("nodes.enrol.lifetime_help")}>
                {(c) => (
                  <SelectInput {...c} value={lifetime()} options={LIFETIMES.map((s) => ({ value: String(s), label: lifetimeWord(s) }))} onChange={setLifetime} />
                )}
              </Field>
            </FieldRow>
            <Show when={(vrfs() ?? []).length > 1}>
              <Field name="vrf" label={t("nodes.enrol.vrf")} help={t("nodes.enrol.vrf_help")}>
                {(c) => (
                  <SelectInput
                    {...c}
                    value={vrf()}
                    options={[{ value: "", label: t("nodes.enrol.vrf_default") }, ...(vrfs() ?? []).map((v) => ({ value: v.id, label: v.name }))]}
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
                {t("nodes.enrol.create")}
              </button>
            </div>
          </form>
        }
      >
        {(c) => {
          const command = () => enrolCommand(c(), window.location.origin);
          return (
            <div class="nodes-form" data-testid="dialog-enrol-token">
              <h2 class="dialog-title">{t("nodes.enrol.created_title")}</h2>
              <Notice kind="warn" testid="enrol-once">
                {t("nodes.enrol.once", { expires: formatDateTime(c().enrolment.expires_at) })}
              </Notice>
              <div class="field">
                <span class="label">{t("nodes.enrol.command")}</span>
                <pre class="enrol-command mono" data-testid="enrol-command" tabIndex={0}>
                  {command()}
                </pre>
                <div class="row-actions">
                  <button type="button" class="btn primary" data-testid="nodes-copy-command" onClick={() => void copy(command(), t("nodes.enrol.copied_command"))}>
                    <Icon name="copy" />
                    {t("nodes.enrol.copy_command")}
                  </button>
                </div>
              </div>
              <div class="field">
                <span class="label">{t("nodes.enrol.token")}</span>
                <code class="enrol-token mono" data-testid="enrol-token">
                  {c().token}
                </code>
                <div class="row-actions">
                  <button type="button" class="btn" data-testid="nodes-copy-token" onClick={() => void copy(c().token, t("nodes.enrol.copied_token"))}>
                    <Icon name="copy" />
                    {t("nodes.enrol.copy_token")}
                  </button>
                </div>
              </div>
              <div class="field">
                <span class="label">{t("nodes.enrol.fingerprint")}</span>
                <code class="enrol-fingerprint mono" data-testid="enrol-fingerprint">
                  {fingerprintPairs(c().ca_fingerprint)}
                </code>
                <small class="help">{t("nodes.enrol.fingerprint_help")}</small>
              </div>
              <p class="muted">{t("nodes.enrol.next", { roles: c().enrolment.roles.map(roleWord).join(", ") })}</p>
              <div class="dialog-actions">
                <button type="button" class="btn primary" data-testid="enrol-done" onClick={() => props.onClose()}>
                  {t("nodes.enrol.done")}
                </button>
              </div>
            </div>
          );
        }}
      </Show>
    </Dialog>
  );
}
