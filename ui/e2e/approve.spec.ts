// The approval page of a takeover script (/approve, ADR 0038) against the real server.
//
// Arrangement: the internal CA transport, which approvals need. The script's side runs in a
// request context of its own, without the browser's cookies: it asks for an approval with the
// request body of the test vector (crates/tenko-auth/tests/fixtures/approval-code.json) and a
// P-256 key of its own, computes the code over the node's root as the script does (checked
// against the vector first) and collects with a signature in `r || s` form.
//
// Scenarios:
// - An approved request is collected once: the page shows the request, Enter in the code field
//   and on the page approves nothing, Approve, the collect answers a `tnka_` session, a second
//   collect is refused as consumed.
// - A denied request is never collected.
// - A wrong code is refused on the page.
// - The page renders in Swedish.

import { createHash, generateKeyPairSync, sign, X509Certificate, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { APIRequestContext, Page } from "@playwright/test";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import type { TenkoServer } from "./support/server";

const VECTOR = JSON.parse(readFileSync(resolve(import.meta.dirname, "../../crates/tenko-auth/tests/fixtures/approval-code.json"), "utf8")) as {
  code: { request_body: string; root_sha256: string; key_uncompressed: string; approval_id: string; code: string };
};
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** The approval code (`code` in tenko-auth's approval/code.rs). */
function approvalCode(domain: string, root: Buffer, body: string, key: Buffer, id: string): string {
  const digest = createHash("sha256")
    .update("tenko-takeover-approval-v1")
    .update(Buffer.from([0, domain.length]))
    .update(domain)
    .update(root)
    .update(createHash("sha256").update(body).digest())
    .update(key)
    .update(Buffer.from(id.replace(/-/g, ""), "hex"))
    .digest();
  const bits = BigInt(`0x${digest.subarray(0, 10).toString("hex")}`);
  const chars = Array.from({ length: 16 }, (_, i) => ALPHABET[Number((bits >> BigInt(75 - 5 * i)) & 31n)]).join("");
  return chars.match(/.{4}/g)!.join("-");
}

interface Script {
  context: APIRequestContext;
  id: string;
  code: string;
  collect: () => Promise<{ status: number; body: { code?: string; secret?: string } }>;
}

/** Asks the server for an approval as the takeover script does. */
async function requestApproval(server: TenkoServer, newContext: () => Promise<APIRequestContext>): Promise<Script> {
  const v = VECTOR.code;
  expect(approvalCode("corp.example.test", Buffer.from(v.root_sha256, "hex"), v.request_body, Buffer.from(v.key_uncompressed, "hex"), v.approval_id)).toBe(v.code);
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x!, "base64url"), Buffer.from(jwk.y!, "base64url")]);
  const body = JSON.stringify({ ...JSON.parse(v.request_body), key: point.toString("base64url") });
  const context = await newContext();
  const asked = await context.post("/api/v1/auth/approvals", { data: body, headers: { "content-type": "application/json" } });
  expect(asked.status(), await asked.text()).toBe(201);
  const ticket = (await asked.json()) as { id: string; nonce: string };
  const root = createHash("sha256").update(new X509Certificate(await server.caRootPem()).raw).digest();
  const code = approvalCode("corp.example.test", root, body, point, ticket.id);
  return { context, id: ticket.id, code, collect: () => collect(context, privateKey, ticket) };
}

async function collect(context: APIRequestContext, key: KeyObject, ticket: { id: string; nonce: string }) {
  const message = Buffer.concat([
    Buffer.from("tenko-takeover-collect-v1"),
    Buffer.from([0]),
    Buffer.from(ticket.id.replace(/-/g, ""), "hex"),
    Buffer.from(ticket.nonce, "base64url"),
  ]);
  const signature = sign("sha256", message, { key, dsaEncoding: "ieee-p1363" }).toString("base64url");
  const answer = await context.post(`/api/v1/auth/approvals/${ticket.id}/collect`, { data: { signature } });
  return { status: answer.status(), body: (await answer.json()) as { code?: string; secret?: string } };
}

async function lookUp(page: Page, code: string): Promise<void> {
  await page.goto("/approve");
  await page.getByTestId("field-code").fill(code.toLowerCase());
  await page.getByTestId("field-code").press("Enter");
}

test.use({ transport: "internal_ca" });

test.describe("the approval page", () => {
  let script: Script | undefined;
  test.afterEach(async () => {
    await script?.context.dispose();
    script = undefined;
  });

  test("an approved request is collected once", async ({ page, server, signedIn, playwright }) => {
    void signedIn;
    script = await requestApproval(server, () => playwright.request.newContext({ baseURL: server.url, ignoreHTTPSErrors: true }));
    await lookUp(page, script.code);
    const request = page.getByTestId("approve-request");
    await expect(request.getByTestId("approve-domain")).toHaveText("corp.example.test");
    await expect(request.getByTestId("approve-code")).toHaveText(script.code);
    await expect(request.getByTestId("approve-user")).toHaveText("CORP\\admin");
    await expect(request.getByTestId("approve-source")).not.toBeEmpty();
    await expect(request.getByTestId("approve-check")).toContainText("Never approve a code that someone sends you.");
    // The Enter that looked the code up, and stray ones on the page, never approve.
    await page.keyboard.press("Enter");
    await page.keyboard.press("Enter");
    await expect(page.getByTestId("approve-approved")).toHaveCount(0);
    await expect(page.getByTestId("approve-approve")).toBeEnabled();
    expect((await script.collect()).body.code).toBe("auth.approval.pending");

    await page.getByTestId("approve-approve").click();
    await expect(page.getByTestId("approve-approved")).toBeVisible();
    await expect(page.getByTestId("approve-approve")).toBeDisabled();
    const first = await script.collect();
    expect(first.status).toBe(200);
    expect(first.body.secret).toMatch(/^tnka_/);
    const second = await script.collect();
    expect(second.status).toBe(409);
    expect(second.body.code).toBe("auth.approval.consumed");
  });

  test("a denied request is never collected", async ({ page, server, signedIn, playwright }) => {
    void signedIn;
    script = await requestApproval(server, () => playwright.request.newContext({ baseURL: server.url, ignoreHTTPSErrors: true }));
    await lookUp(page, script.code);
    await page.getByTestId("approve-deny").click();
    await expect(page.getByTestId("approve-denied")).toBeVisible();
    const answer = await script.collect();
    expect(answer.status).toBe(403);
    expect(answer.body.code).toBe("auth.approval.denied");
  });

  test("a wrong code is refused on the page", async ({ page, signedIn }) => {
    void signedIn;
    await lookUp(page, "Z1SX-2C7Z-FC16-JJ2F");
    await expect(page.getByTestId("error-notice")).toHaveAttribute("data-code", "auth.approval.code");
    await expect(page.getByTestId("field-code")).toBeVisible();
  });

  test.describe("in Swedish", () => {
    test.use({ locale: "sv-SE" });

    test("renders in Swedish", async ({ page, server, signedIn, playwright }, testInfo) => {
      void signedIn;
      script = await requestApproval(server, () => playwright.request.newContext({ baseURL: server.url, ignoreHTTPSErrors: true }));
      await lookUp(page, script.code);
      await expect(page.getByTestId("approve-request")).toBeVisible();
      await expect(page.getByTestId("approve-approve")).toHaveText("Godkänn");
      await expectRendered(page, page.getByTestId("page-approve"), "sv", testInfo, "approve");
    });
  });
});
