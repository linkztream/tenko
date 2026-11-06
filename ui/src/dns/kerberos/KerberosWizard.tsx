// The wizard of the Kerberos account (identity plan section 3.18, ID-Q4): either the adopt of
// a computer account an administrator pre-staged with the static PowerShell block of
// docs/active-directory.md section 4.1, or the import of a keytab made with `ktpass` or
// `msktutil`.
//
// Adopt, in three steps: the realm and its KDCs; the account name and the SPNs, shown with the
// values the administrator types at the prompts of the block (as text: the wizard never shows
// or generates code for an administrator to run, R130); the one-time password and the rotation
// interval. Tenko then changes the password so that only it knows it, stores the keys and runs
// the self-test, whose findings the status shows. No administrator credential is asked for.
//
// The one-time password and the keytab are held in signals only until the request is sent and
// are cleared when it returns, whatever the answer.
import { createSignal, For, Match, Show, Switch } from "solid-js";
import { ErrorNotice, Notice } from "../../components/Notice";
import { t } from "../../i18n";
import { describedBy, Field, fieldErrors } from "../Parts";
import { adoptKerberos, importKerberos, type KerberosStatus } from "./api";
import {
  accountName,
  base64url,
  blockName,
  canonicalRealm,
  MAX_KEYTAB_BYTES,
  parseLines,
  POWERSHELL_SECTION,
  validAccountName,
  validKdc,
  validRealm,
  validSpns,
} from "./model";

type Path = "adopt" | "import";

/** The realm, the KDCs and the SPNs: what both paths ask. */
function useCommon() {
  const [realm, setRealm] = createSignal("");
  const [kdcs, setKdcs] = createSignal("");
  const [spns, setSpns] = createSignal("");
  const check = (e: Record<string, string>) => {
    if (!validRealm(realm())) e.realm = t("dns.kerberos.check.realm");
    if (!validSpns(parseLines(spns()))) e.spns = t("dns.kerberos.check.spns");
    if (!parseLines(kdcs()).every(validKdc)) e.kdcs = t("dns.kerberos.check.kdcs");
  };
  return { realm, setRealm, kdcs, setKdcs, spns, setSpns, check };
}

function CommonFields(props: { common: ReturnType<typeof useCommon>; errors: Record<string, string>; show: "realm" | "spns" }) {
  return (
    <Switch>
      <Match when={props.show === "realm"}>
        <Field id="realm" label={t("dns.kerberos.field.realm")} error={props.errors.realm} help={t("dns.kerberos.field.realm_help")}>
          <input
            id="dns-f-realm"
            class="input mono"
            value={props.common.realm()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={props.errors.realm ? "true" : undefined}
            aria-describedby={describedBy("realm", props.errors.realm, "help")}
            data-testid="field-realm"
            onInput={(e) => props.common.setRealm(e.currentTarget.value)}
          />
        </Field>
        <Field id="kdcs" label={t("dns.kerberos.field.kdcs")} error={props.errors.kdcs} help={t("dns.kerberos.field.kdcs_help")}>
          <textarea
            id="dns-f-kdcs"
            class="input mono"
            rows={2}
            value={props.common.kdcs()}
            spellcheck={false}
            aria-invalid={props.errors.kdcs ? "true" : undefined}
            aria-describedby={describedBy("kdcs", props.errors.kdcs, "help")}
            data-testid="field-kdcs"
            onInput={(e) => props.common.setKdcs(e.currentTarget.value)}
          />
        </Field>
      </Match>
      <Match when={props.show === "spns"}>
        <Field id="spns" label={t("dns.kerberos.field.spns")} error={props.errors.spns} help={t("dns.kerberos.field.spns_help")}>
          <textarea
            id="dns-f-spns"
            class="input mono"
            rows={3}
            value={props.common.spns()}
            spellcheck={false}
            aria-invalid={props.errors.spns ? "true" : undefined}
            aria-describedby={describedBy("spns", props.errors.spns, "help")}
            data-testid="field-spns"
            onInput={(e) => props.common.setSpns(e.currentTarget.value)}
          />
        </Field>
      </Match>
    </Switch>
  );
}

/**
 * One value of the block. There is deliberately no copy button: this page is served by Tenko,
 * the block runs as a domain administrator, and a value on the clipboard could carry more
 * lines than the prompt reads, which the console would then run (R130). The values are short
 * and typed by hand.
 */
function ValueRow(props: { label: string; value: string; testid: string }) {
  return (
    <>
      <dt>{props.label}</dt>
      <dd>
        <code class="mono" data-testid={props.testid}>
          {props.value}
        </code>
      </dd>
    </>
  );
}

/** The values the administrator types at the prompts of the PowerShell block. */
function BlockValues(props: { name: string; spns: string[]; realm: string }) {
  return (
    <section class="page-section" data-testid="kerberos-block-values">
      <h3>{t("dns.kerberos.block.title")}</h3>
      <p>{t("dns.kerberos.block.body", { section: POWERSHELL_SECTION })}</p>
      <dl class="kv">
        <ValueRow label={t("dns.kerberos.block.name")} value={props.name} testid="block-name" />
        <dt>{t("dns.kerberos.block.ou")}</dt>
        <dd>{t("dns.kerberos.block.ou_value")}</dd>
        <For each={props.spns}>
          {(spn, i) => <ValueRow label={t("dns.kerberos.block.spn", { n: i() + 1 })} value={spn} testid={`block-spn-${i()}`} />}
        </For>
        <ValueRow label={t("dns.kerberos.block.realm")} value={props.realm} testid="block-realm" />
      </dl>
      <Notice kind="info" role="status" testid="kerberos-block-safety">
        {t("dns.kerberos.block.safety")}
      </Notice>
    </section>
  );
}

function AdoptForm(props: { onDone: (status: KerberosStatus) => void; onCancel: () => void }) {
  const common = useCommon();
  const [step, setStep] = createSignal(1);
  const [name, setName] = createSignal("TENKO-DNS");
  const [password, setPassword] = createSignal("");
  const [rotation, setRotation] = createSignal("30");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const checkStep = (n: number): boolean => {
    const e: Record<string, string> = {};
    if (n >= 1) {
      if (!validRealm(common.realm())) e.realm = t("dns.kerberos.check.realm");
      if (!parseLines(common.kdcs()).every(validKdc)) e.kdcs = t("dns.kerberos.check.kdcs");
    }
    if (n >= 2) {
      if (!validAccountName(name())) e.name = t("dns.kerberos.check.name");
      if (!validSpns(parseLines(common.spns()))) e.spns = t("dns.kerberos.check.spns");
    }
    if (n >= 3) {
      if (password() === "") e.password = t("dns.kerberos.check.password");
      const days = Number(rotation());
      if (!Number.isInteger(days) || days < 0 || days > 365) e.rotation = t("dns.kerberos.check.rotation");
    }
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const next = (event: Event) => {
    event.preventDefault();
    if (checkStep(step())) setStep(step() + 1);
  };

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy() || !checkStep(3)) return;
    setBusy(true);
    setError(undefined);
    const secret = password();
    try {
      const status = await adoptKerberos({
        realm: canonicalRealm(common.realm()),
        name: accountName(name()),
        password: secret,
        spns: parseLines(common.spns()),
        kdcs: parseLines(common.kdcs()),
        rotation_days: Number(rotation()),
      });
      props.onDone(status);
    } catch (err) {
      const fields = fieldErrors(err);
      if (Object.keys(fields).length > 0) setErrors(fields);
      else setError(err);
    } finally {
      // The one-time password is used once, whatever the answer.
      setPassword("");
      setBusy(false);
    }
  };

  return (
    <form
      class="page-body dns-form"
      data-testid="kerberos-adopt"
      data-step={step()}
      onSubmit={(e) => (step() < 3 ? next(e) : void submit(e))}
      novalidate
    >
      <ol class="steps" aria-label={t("dns.kerberos.steps")}>
        <For each={[1, 2, 3]}>
          {(n) => (
            <li aria-current={step() === n ? "step" : undefined} data-testid={`kerberos-step-${n}`}>
              {t(`dns.kerberos.step.${n === 1 ? "realm" : n === 2 ? "account" : "password"}`)}
            </li>
          )}
        </For>
      </ol>
      <Switch>
        <Match when={step() === 1}>
          <CommonFields common={common} errors={errors()} show="realm" />
        </Match>
        <Match when={step() === 2}>
          <Field id="name" label={t("dns.kerberos.field.name")} error={errors().name} help={t("dns.kerberos.field.name_help")}>
            <input
              id="dns-f-name"
              class="input mono"
              value={name()}
              spellcheck={false}
              autocomplete="off"
              aria-invalid={errors().name ? "true" : undefined}
              aria-describedby={describedBy("name", errors().name, "help")}
              data-testid="field-name"
              onInput={(e) => setName(e.currentTarget.value)}
            />
          </Field>
          <CommonFields common={common} errors={errors()} show="spns" />
          <Show when={validAccountName(name()) && validSpns(parseLines(common.spns())) && validRealm(common.realm())}>
            <BlockValues name={blockName(name())} spns={parseLines(common.spns())} realm={canonicalRealm(common.realm())} />
          </Show>
        </Match>
        <Match when={step() === 3}>
          <p>
            {t("dns.kerberos.password_intro", {
              name: accountName(name()),
              realm: canonicalRealm(common.realm()),
            })}
          </p>
          <Field
            id="password"
            label={t("dns.kerberos.field.password")}
            error={errors().password}
            help={t("dns.kerberos.field.password_help")}
          >
            <input
              id="dns-f-password"
              class="input mono"
              type="password"
              autocomplete="off"
              value={password()}
              aria-invalid={errors().password ? "true" : undefined}
              aria-describedby={describedBy("password", errors().password, "help")}
              data-testid="field-password"
              onInput={(e) => setPassword(e.currentTarget.value)}
            />
          </Field>
          <Field
            id="rotation"
            label={t("dns.kerberos.field.rotation")}
            error={errors().rotation}
            help={t("dns.kerberos.field.rotation_help")}
          >
            <input
              id="dns-f-rotation"
              class="input"
              type="number"
              min={0}
              max={365}
              value={rotation()}
              aria-invalid={errors().rotation ? "true" : undefined}
              aria-describedby={describedBy("rotation", errors().rotation, "help")}
              data-testid="field-rotation"
              onInput={(e) => setRotation(e.currentTarget.value)}
            />
          </Field>
        </Match>
      </Switch>
      <ErrorNotice error={error()} />
      <div class="form-row">
        <Show
          when={step() > 1}
          fallback={
            <button type="button" class="btn" data-testid="kerberos-cancel" onClick={() => props.onCancel()}>
              {t("common.action.cancel")}
            </button>
          }
        >
          <button type="button" class="btn" data-testid="kerberos-back" onClick={() => setStep(step() - 1)}>
            {t("dns.kerberos.back")}
          </button>
        </Show>
        <button type="submit" class="btn primary" data-testid={step() < 3 ? "kerberos-next" : "form-submit"} disabled={busy()}>
          {step() < 3 ? t("dns.kerberos.next") : busy() ? t("dns.kerberos.adopting") : t("dns.kerberos.adopt_submit")}
        </button>
      </div>
    </form>
  );
}

function ImportForm(props: { onDone: (status: KerberosStatus) => void; onCancel: () => void }) {
  const common = useCommon();
  const [name, setName] = createSignal("");
  const [keytab, setKeytab] = createSignal<string | null>(null);
  const [file, setFile] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const pick = async (input: HTMLInputElement) => {
    const chosen = input.files?.[0];
    setKeytab(null);
    setFile("");
    if (!chosen) return;
    if (chosen.size > MAX_KEYTAB_BYTES) {
      setErrors({ ...errors(), keytab: t("dns.kerberos.check.keytab_size") });
      input.value = "";
      return;
    }
    const bytes = new Uint8Array(await chosen.arrayBuffer());
    setKeytab(base64url(bytes));
    bytes.fill(0);
    setFile(chosen.name);
    const { keytab: _read, ...rest } = errors();
    setErrors(rest);
    // The file stays on the person's disk; the input lets go of it.
    input.value = "";
  };

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    common.check(e);
    if (keytab() === null) e.keytab = t("dns.kerberos.check.keytab");
    if (name().trim() !== "" && !validAccountName(name())) e.name = t("dns.kerberos.check.name");
    setErrors(e);
    if (Object.keys(e).length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      const status = await importKerberos({
        realm: canonicalRealm(common.realm()),
        name: name().trim() === "" ? null : accountName(name()),
        keytab: keytab() ?? "",
        spns: parseLines(common.spns()),
        kdcs: parseLines(common.kdcs()),
      });
      props.onDone(status);
    } catch (err) {
      const fields = fieldErrors(err);
      if (Object.keys(fields).length > 0) setErrors(fields);
      else setError(err);
    } finally {
      setKeytab(null);
      setFile("");
      setBusy(false);
    }
  };

  return (
    <form class="page-body dns-form" data-testid="kerberos-import" onSubmit={(e) => void submit(e)} novalidate>
      <p>{t("dns.kerberos.import_intro")}</p>
      <CommonFields common={common} errors={errors()} show="realm" />
      <Field
        id="keytab"
        label={t("dns.kerberos.field.keytab")}
        error={errors().keytab}
        help={file() ? t("dns.kerberos.field.keytab_chosen", { file: file() }) : t("dns.kerberos.field.keytab_help")}
      >
        <input
          id="dns-f-keytab"
          class="input"
          type="file"
          aria-invalid={errors().keytab ? "true" : undefined}
          aria-describedby={describedBy("keytab", errors().keytab, "help")}
          data-testid="field-keytab"
          onChange={(e) => void pick(e.currentTarget)}
        />
      </Field>
      <Field id="name" label={t("dns.kerberos.field.import_name")} error={errors().name} help={t("dns.kerberos.field.import_name_help")}>
        <input
          id="dns-f-name"
          class="input mono"
          value={name()}
          spellcheck={false}
          autocomplete="off"
          aria-invalid={errors().name ? "true" : undefined}
          aria-describedby={describedBy("name", errors().name, "help")}
          data-testid="field-name"
          onInput={(e) => setName(e.currentTarget.value)}
        />
      </Field>
      <CommonFields common={common} errors={errors()} show="spns" />
      <ErrorNotice error={error()} />
      <div class="form-row">
        <button type="button" class="btn" data-testid="kerberos-cancel" onClick={() => props.onCancel()}>
          {t("common.action.cancel")}
        </button>
        <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
          {busy() ? t("dns.kerberos.importing") : t("dns.kerberos.import_submit")}
        </button>
      </div>
    </form>
  );
}

/** The set-up: the choice between the adopt (recommended) and the keytab import, then its form. */
export function KerberosWizard(props: { onDone: (status: KerberosStatus) => void }) {
  const [path, setPath] = createSignal<Path | null>(null);
  return (
    <Switch>
      <Match when={path() === "adopt"}>
        <AdoptForm onDone={props.onDone} onCancel={() => setPath(null)} />
      </Match>
      <Match when={path() === "import"}>
        <ImportForm onDone={props.onDone} onCancel={() => setPath(null)} />
      </Match>
      <Match when={path() === null}>
        <div class="page-body" data-testid="kerberos-setup">
          <section class="page-section">
            <h2>{t("dns.kerberos.setup.title")}</h2>
            <p>{t("dns.kerberos.setup.body")}</p>
            <div class="form-row">
              <button type="button" class="btn primary" data-testid="kerberos-choose-adopt" onClick={() => setPath("adopt")}>
                {t("dns.kerberos.setup.adopt")}
              </button>
              <button type="button" class="btn" data-testid="kerberos-choose-import" onClick={() => setPath("import")}>
                {t("dns.kerberos.setup.import")}
              </button>
            </div>
            <p class="muted">{t("dns.kerberos.setup.no_admin")}</p>
          </section>
        </div>
      </Match>
    </Switch>
  );
}
