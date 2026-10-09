import { createSignal, Show } from "solid-js";
import { Notice } from "../../components/Notice";
import { t } from "../../i18n";
import { session } from "../session";
import { createMethodsData } from "./data";
import { PasskeySection } from "./PasskeySection";
import { PasswordSection } from "./PasswordSection";
import { RecoverySection } from "./RecoverySection";
import { CodesDialog } from "./shared";
import { TotpSection } from "./TotpSection";

/** Sign-in methods: password or PIN, passkeys, authenticator app and recovery codes. */
export default function Methods() {
  const data = createMethodsData();
  const [codes, setCodes] = createSignal<string[] | null>(null);
  const [reauth, setReauth] = createSignal(false);

  return (
    <div class="page-body acct-stack">
      <Show when={session()}>
        {(s) => (
          <section class="acct-summary" aria-label={t("account.methods.summary_label")}>
            <Show when={s().flags.password_change_required}>
              <Notice kind="warn" role="status">
                {t("account.methods.flag_password")}
              </Notice>
            </Show>
            <Show when={s().flags.mfa_enrolment_required}>
              <Notice kind="warn" role="status">
                {t("account.methods.flag_mfa")}
              </Notice>
            </Show>
            <Show when={reauth()}>
              <Notice kind="info" role="status">
                {t("account.methods.reauthenticate")}
              </Notice>
            </Show>
            <p>{t("account.methods.signed_in_with", { method: t(`auth.strength.${s().strength}`) })}</p>
            <p>
              {t("account.methods.requires", {
                profile: t(`profile.${s().profile}.name`),
                method: t(`auth.strength.${s().required_strength}`),
              })}
            </p>
          </section>
        )}
      </Show>

      <PasswordSection />
      <PasskeySection data={data} onCodes={setCodes} onReauthenticate={() => setReauth(true)} />
      <TotpSection data={data} onCodes={setCodes} onReauthenticate={() => setReauth(true)} />
      <RecoverySection data={data} onCodes={setCodes} />

      <Show when={codes()}>
        {(list) => (
          <CodesDialog codes={list()} fileBase={session()?.user.name ?? "tenko"} onClose={() => setCodes(null)} />
        )}
      </Show>
    </div>
  );
}
