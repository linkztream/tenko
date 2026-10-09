// How the shell shows a hit of GET /search: its identifier, what kind of object it is and
// where it leads. The deep links are the canonical ones of app/paths.ts, built from the
// object's identifier (address, prefix, host name, MAC), so they stay readable.
import type { SearchHit } from "../api/types";
import { paths } from "../app/paths";
import type { IconName } from "../components/Icon";
import { tDynamic } from "../i18n";

/** The identifier a person types for the object: an address, a prefix, a host name or a MAC. */
export function hitIdentifier(hit: SearchHit): string | undefined {
  const item = hit.item;
  switch (item.kind) {
    case "address":
      return item.data.ip;
    case "prefix":
      return item.data.cidr;
    case "host":
      return item.data.name;
    case "interface":
      return item.data.mac ?? undefined;
    default:
      return undefined;
  }
}

/** Where a search hit leads. */
export function hitHref(hit: SearchHit): string {
  const id = hitIdentifier(hit);
  switch (hit.item.kind) {
    case "address":
      return id ? paths.address(id) : paths.search(hit.label);
    case "prefix":
      return id ? paths.prefix(id) : paths.search(hit.label);
    case "host":
      return id ? paths.host(id) : paths.search(hit.label);
    case "interface":
      return id ? paths.mac(id) : paths.search(hit.label);
    default:
      return paths.search(hit.label);
  }
}

/** The main text of a hit: the identifier where there is one, else the server's label. */
export function hitTitle(hit: SearchHit): string {
  return hitIdentifier(hit) ?? hit.label;
}

/** The secondary text: the label when the title is the identifier, then the kind in words. */
export function hitSubtitle(hit: SearchHit): string {
  const kind = tDynamic(`shell.search.kind.${hit.item.kind}`) ?? hit.item.kind;
  const id = hitIdentifier(hit);
  return id && hit.label !== id ? `${hit.label} · ${kind}` : kind;
}

const ICON: Record<string, IconName> = { prefix: "layers", host: "server", interface: "cable", vlan: "link", range: "layers" };

export function hitIcon(hit: SearchHit): IconName {
  return ICON[hit.item.kind] ?? "ipam";
}
