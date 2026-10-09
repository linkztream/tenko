import { Mark } from "../../components/Mark";
import { t } from "../../i18n";

/** While the session is being checked: the mark and one line, nothing that jumps. */
export default function Splash() {
  return (
    <div class="splash" role="status">
      <Mark class="mark splash-mark" />
      <span>{t("shell.splash")}</span>
    </div>
  );
}
