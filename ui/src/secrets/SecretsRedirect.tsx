// /secrets and everything under it, the address before the page moved under Settings
// (/settings/secrets): bookmarks, deep links and the `next` of a sign-in keep working. The
// redirect replaces the history entry, so Back does not return to the old address, and it
// keeps the query and the fragment. It carries no words, so it loads without a message pack.
import { Navigate, useLocation } from "@solidjs/router";
import { migratedSecretsPath } from "./paths";

export default function SecretsRedirect() {
  const location = useLocation();
  return <Navigate href={`${migratedSecretsPath(location.pathname)}${location.search}${location.hash}`} />;
}
