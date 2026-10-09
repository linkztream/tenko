import { splitAddress, splitMac } from "../app/format/address";

/**
 * An IP address or prefix in the data font. Plain by default; with "Emphasize host
 * part" on (html[data-emphasize="host"]), the network part is gray and the host bold.
 */
export function Addr(props: { value: string; prefixLength?: number }) {
  const parts = () => splitAddress(props.value, props.prefixLength);
  return (
    <span class="addr">
      <span class="net">{parts().net}</span>
      <span class="host">{parts().host}</span>
      {parts().len ? <span class="len">{parts().len}</span> : null}
    </span>
  );
}

/** A MAC address; with the preference on, the vendor part is gray. */
export function Mac(props: { value: string }) {
  const parts = () => splitMac(props.value);
  return (
    <span class="mac">
      <span class="oui">{parts().oui}</span>
      {parts().rest}
    </span>
  );
}
