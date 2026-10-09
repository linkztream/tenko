// A QR code drawn in the browser, without any network request: the encoder (uqr, MIT
// licence, recorded in public/licenses/uqr.txt) is loaded on first use, so it is not part of
// the first page load. Used for the otpauth URI of the TOTP enrolment; the text stays
// visible next to it for devices without a camera.
import { createResource, Show } from "solid-js";

/** The dark modules of a QR matrix as one SVG path (one square per module, x and y offset by `border`). */
export function qrPath(matrix: readonly (readonly boolean[])[], border: number): string {
  let d = "";
  matrix.forEach((row, y) => {
    row.forEach((dark, x) => {
      if (dark) d += `M${x + border} ${y + border}h1v1h-1z`;
    });
  });
  return d;
}

export function QrCode(props: { text: string; label: string; size?: number }) {
  const [code] = createResource(
    () => props.text,
    async (text) => {
      const { encode } = await import("uqr");
      // Medium error correction; no border from the encoder, the SVG adds the quiet zone.
      return encode(text, { ecc: "M", border: 0 });
    },
  );
  const border = 4;
  return (
    <Show when={code()}>
      {(qr) => {
        const n = () => qr().size + border * 2;
        return (
          <svg
            class="qr"
            role="img"
            aria-label={props.label}
            viewBox={`0 0 ${n()} ${n()}`}
            width={props.size ?? 196}
            height={props.size ?? 196}
            shape-rendering="crispEdges"
            data-testid="qr-code"
            data-version={qr().version}
          >
            <rect class="qr-light" width={n()} height={n()} />
            <path class="qr-dark" d={qrPath(qr().data, border)} />
          </svg>
        );
      }}
    </Show>
  );
}
