// The page of a module this installation does not run.
import { A } from "@solidjs/router";
import { paths } from "../app/paths";
import { Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";
import type { ModuleName } from "./modules";
import "./updates.css";

export default function ModuleDisabled(props: { module: ModuleName }) {
  const name = () => t(`updates.module.name.${props.module}`);
  return (
    <div class="page" data-testid="page-module-disabled" data-key={props.module}>
      <PageHead title={name()} />
      <div class="page-body">
        <div class="upd-module-off">
          <Notice kind="info" title={t("updates.module.title")}>
            {t("updates.module.body", { module: name() })}
          </Notice>
          <A class="btn" href={paths.dashboard()} data-testid="module-disabled-home">
            {t("updates.module.home")}
          </A>
        </div>
      </div>
    </div>
  );
}
