// Links to the objects a proposal or an observation names by id: prefixes, hosts, interfaces
// and addresses of IPAM, read once per id and kept for the page's lifetime (a view shows few
// distinct objects), and the names of connector instances and nodes for the sources.
import { A } from "@solidjs/router";
import { createResource, Match, Show, Switch } from "solid-js";
import { api } from "../api/client";
import { fetchAll } from "../api/paginate";
import type { Address, Host, Interface, ObjectRef, Prefix } from "../api/types";
import { paths } from "../app/paths";
import { Addr } from "../components/Addr";
import { shortId } from "../components/Principal";
import { kindTitle } from "../ipam/words";
import type { SourceNames } from "./model";

const cache = new Map<string, Promise<unknown>>();

/** Reads an object once; a failed read is forgotten so that a later view may try again. */
function once<T>(key: string, load: () => Promise<T>): Promise<T | null> {
  let p = cache.get(key) as Promise<T | null> | undefined;
  if (!p) {
    p = load().catch(() => {
      cache.delete(key);
      return null;
    });
    cache.set(key, p);
  }
  return p;
}

/** Forgets every object read (tests, and after a write that renamed something). */
export function resetRefs(): void {
  cache.clear();
}

export function readPrefix(id: string): Promise<Prefix | null> {
  return once(`prefix/${id}`, () => api.get("/api/v1/prefixes/{id}", { path: { id } }) as Promise<Prefix>);
}

export function readHost(id: string): Promise<Host | null> {
  return once(`host/${id}`, () => api.get("/api/v1/hosts/{id}", { path: { id } }) as Promise<Host>);
}

export function readAddress(id: string): Promise<Address | null> {
  return once(`address/${id}`, () => api.get("/api/v1/addresses/{id}", { path: { id } }) as Promise<Address>);
}

export function readInterface(id: string): Promise<Interface | null> {
  return once(`interface/${id}`, () => api.get("/api/v1/interfaces/{id}", { path: { id } }) as Promise<Interface>);
}

/** A prefix by id as a link with its CIDR; the short id while it loads or when it is gone. */
export function PrefixRef(props: { id: string }) {
  const [prefix] = createResource(() => props.id, readPrefix);
  return (
    <Show when={prefix()} fallback={<span class="mono muted">{shortId(props.id)}</span>}>
      {(p) => (
        <A href={paths.prefix(p().cidr, p().vrf)} class="mono">
          <Addr value={p().cidr} />
        </A>
      )}
    </Show>
  );
}

/** An IPAM object by reference: hosts, addresses and prefixes as links, others by kind and short id. */
export function ObjectLink(props: { object: ObjectRef }) {
  const [label] = createResource(
    () => props.object,
    async (o): Promise<{ text: string; href: string } | null> => {
      switch (o.kind) {
        case "host": {
          const h = await readHost(o.id);
          return h ? { text: h.name, href: paths.host(h.name) } : null;
        }
        case "address": {
          const a = await readAddress(o.id);
          return a ? { text: a.ip, href: paths.address(a.ip, a.vrf) } : null;
        }
        case "prefix": {
          const p = await readPrefix(o.id);
          return p ? { text: p.cidr, href: paths.prefix(p.cidr, p.vrf) } : null;
        }
        case "interface": {
          const i = await readInterface(o.id);
          if (!i) return null;
          const h = await readHost(i.host);
          return { text: h ? `${h.name} ${i.name}` : i.name, href: h ? paths.host(h.name) : "" };
        }
        default:
          return null;
      }
    },
  );
  return (
    <span class="obj-ref" data-kind={props.object.kind} data-id={props.object.id}>
      <span class="muted">{kindTitle(props.object.kind)}</span>{" "}
      <Switch fallback={<span class="mono">{shortId(props.object.id)}</span>}>
        <Match when={label()?.href}>
          <A href={label()!.href} class="mono">
            {label()!.text}
          </A>
        </Match>
        <Match when={label()}>
          <span class="mono">{label()!.text}</span>
        </Match>
      </Switch>
    </span>
  );
}

/**
 * The names of connector instances and nodes, for the sources of observations. Read once per
 * view; without permission or on an error the ids stand in.
 */
export function useSourceNames(): () => SourceNames {
  const [connectors] = createResource(async () => {
    try {
      const page = await fetchAll<{ id: string; name: string }>("/api/v1/connectors", { limit: 1000 });
      return new Map(page.items.map((c) => [c.id, c.name]));
    } catch {
      return new Map<string, string>();
    }
  });
  const [nodes] = createResource(async () => {
    try {
      const page = await fetchAll<{ id: number; name: string }>("/api/v1/nodes", { limit: 1000 });
      return new Map(page.items.map((n) => [n.id, n.name]));
    } catch {
      return new Map<number, string>();
    }
  });
  return () => {
    const c = connectors();
    const n = nodes();
    return {
      connector: (id) => c?.get(id),
      node: (id) => n?.get(id),
    };
  };
}
