// A platform authenticator for passkey tests: Chromium's virtual authenticator over the
// DevTools protocol (WebAuthn domain). It behaves like a built-in authenticator with user
// verification (Windows Hello, Touch ID): internal transport, resident (discoverable)
// credentials, the user always verified and present. Hardware security keys, imported
// certificates and a reverse proxy in front stay manual tests (E2).

import type { CDPSession, Page } from "@playwright/test";

export interface VirtualAuthenticator {
  cdp: CDPSession;
  id: string;
  /** The credentials the authenticator holds. */
  credentials(): Promise<Array<{ credentialId: string; rpId?: string; isResidentCredential: boolean; signCount: number }>>;
  remove(): Promise<void>;
}

export async function addPlatformAuthenticator(page: Page): Promise<VirtualAuthenticator> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return {
    cdp,
    id: authenticatorId,
    async credentials() {
      const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
      return credentials;
    },
    async remove() {
      await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
    },
  };
}
