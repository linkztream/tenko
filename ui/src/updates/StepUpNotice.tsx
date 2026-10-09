// The answer to `auth.step_up_required`: installing needs a fresh sign-in with a stronger
// method. "Sign in again" signs out and opens the sign-in page with the updates page as the
// place to return to (the `next` parameter of the sign-in route).
import { useNavigate } from "@solidjs/router";
import { paths } from "../app/paths";
import { signOut } from "../auth/session";
import { Notice } from "../components/Notice";
import { t } from "../i18n";
import { UPDATES_PATH } from "./paths";

export function StepUpNotice() {
  const navigate = useNavigate();
  const signInAgain = async () => {
    await signOut();
    navigate(paths.signIn(UPDATES_PATH), { replace: true });
  };
  return (
    <Notice kind="warn" title={t("updates.stepup.title")} role="alert" testid="updates-stepup">
      <p>{t("updates.stepup.body")}</p>
      <p>
        <button type="button" class="btn" onClick={() => void signInAgain()} data-testid="updates-signin-again">
          {t("updates.stepup.button")}
        </button>
      </p>
    </Notice>
  );
}
