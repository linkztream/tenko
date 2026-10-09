import { useLocation } from "@solidjs/router";
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { AREAS } from "../areas";

/** An area of the rail that is not built yet. */
export default function Placeholder() {
  const location = useLocation();
  const area = () => AREAS.find((a) => a.path !== "/" && location.pathname.startsWith(a.path));
  const name = () => (area() ? t(area()!.label) : "");
  return (
    <div class="page">
      <PageHead title={name()} />
      <div class="empty">
        <h3>{t("shell.placeholder.title", { area: name() })}</h3>
        <p>{t("shell.placeholder.body")}</p>
        <p class="muted mono">{location.pathname}</p>
      </div>
    </div>
  );
}
