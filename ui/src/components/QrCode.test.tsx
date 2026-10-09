import { render, screen } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { QrCode, qrPath } from "./QrCode";

describe("QrCode", () => {
  it("draws one square per dark module, offset by the quiet zone", () => {
    expect(qrPath([[true, false], [false, true]], 4)).toBe("M4 4h1v1h-1zM5 5h1v1h-1z");
  });

  it("encodes an otpauth URI in the browser and labels the image", async () => {
    const uri = "otpauth://totp/Tenko:alex@tenko1.example.test?secret=JBSWY3DPEHPK3PXP&issuer=Tenko&digits=6&period=30";
    render(() => <QrCode text={uri} label="QR code of the key" />);
    const svg = await screen.findByRole("img", { name: "QR code of the key" });
    const version = Number(svg.getAttribute("data-version"));
    expect(version).toBeGreaterThanOrEqual(5);
    const size = 17 + 4 * version + 8;
    expect(svg.getAttribute("viewBox")).toBe(`0 0 ${size} ${size}`);
    const d = svg.querySelector("path")?.getAttribute("d") ?? "";
    // The top-left finder pattern starts with a dark row of seven modules.
    for (let x = 0; x < 7; x++) expect(d).toContain(`M${x + 4} 4h1v1h-1z`);
  });
});
