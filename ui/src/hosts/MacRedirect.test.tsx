import { screen, waitFor } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { server } from "../api/mock/node";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import MacRedirect from "./MacRedirect";

beforeEach(async () => {
  await signInAlex();
});

const open = (mac: string) => renderRoute(MacRedirect, { url: `/ipam/macs/${mac}`, path: "/ipam/macs/:mac", routes: { "/ipam/hosts/:fqdn": () => <div data-testid="host-route" /> } });

describe("the page of a MAC address", () => {
  it("goes to the host that has the address", async () => {
    open("00:00:5e:00:53:0b");
    expect(await screen.findByTestId("host-route")).toBeTruthy();
  });

  it("says that a host could not be read instead of saying that no host has the address", async () => {
    server.use(http.get("/api/v1/hosts/:id", () => HttpResponse.json({ status: 500, code: "sys.internal", title: "Failed", detail: "", params: {} }, { status: 500 })));
    open("00:00:5e:00:53:0b");
    expect(await screen.findByTestId("error-notice")).toBeTruthy();
    await waitFor(() => expect(screen.queryByText(/no host/i)).toBeNull());
  });
});
