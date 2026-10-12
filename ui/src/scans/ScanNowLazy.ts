// "Scan now" for the pages of other areas (the prefix pane, the host page): the component loads
// with the scans pack on first render, so those pages carry neither its code nor its strings.
import { lazy } from "solid-js";
import { withPacks } from "../i18n";

export const ScanNowLazy = lazy(withPacks(["scans"], () => import("./ScanNow")));
