// The requests of the Kerberos account of secure dynamic updates (/dns/kerberos, scope
// `dns.keys`; identity plan section 3.18): the status, the adopt of a pre-staged computer
// account with its one-time password, the keytab import, the self-test, the rotation job and
// the delete. The one-time password and the keytab go to the server once, in the body, and
// are never kept by the UI after the request.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";

type S = components["schemas"];

export type KerberosStatus = S["KerberosStatus"];
export type KerberosAccount = S["KerberosAccountItem"];
export type KerberosFinding = S["KerberosFinding"];
export type KeyVersion = S["KeyVersionMeta"];
export type KerberosAdopt = S["KerberosAdopt"];
export type KerberosImport = S["KerberosImport"];

export function getKerberos(signal?: AbortSignal): Promise<KerberosStatus> {
  return api.get("/api/v1/dns/kerberos", { signal });
}

export function adoptKerberos(body: KerberosAdopt): Promise<KerberosStatus> {
  return api.post("/api/v1/dns/kerberos/adopt", { body });
}

export function importKerberos(body: KerberosImport): Promise<KerberosStatus> {
  return api.post("/api/v1/dns/kerberos/import", { body });
}

export function checkKerberos(): Promise<KerberosStatus> {
  return api.post("/api/v1/dns/kerberos/check", {});
}

export function rotateKerberos(): Promise<S["DnsJobStarted"]> {
  return api.post("/api/v1/dns/kerberos/rotate", {});
}

export function deleteKerberos(): Promise<void> {
  return api.delete("/api/v1/dns/kerberos", {});
}
