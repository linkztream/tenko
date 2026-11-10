# The early Windows probe of risk R120

The probe is now step W5 of the Windows lab, [windows/README.md](windows/README.md), with the
Kerberos account adopted through the block of the runbook rather than a keytab; this page
keeps the stand-alone form for a probe outside the full lab.

Risk R120 of the identity plan: Windows may do something in a secure dynamic update that no
specification says (TKEY only over TCP, the retry after BADKEY, the reuse of a context, the
TSIG digest of the first signed message). The probe has one real Windows domain controller
register its records in a Tenko zone through TKEY and GSS-TSIG, once, before the rest of
Slice 13 builds on what the container lab shows. It is owner-run (API-18) and is the first
step of the Windows lab of E44; its captures become test fixtures.

Use a test domain only, never a production one. The names below are placeholders: replace
`CORP.EXAMPLE.TEST`, `corp.example.test`, `ns1.corp.example.test` and `192.0.2.53` with the
test domain's realm, its DNS name, the Tenko node's name and its address.

## What it needs

- A Windows Server 2022 or 2025 test domain with one controller **without the DNS Server
  role**, and a Tenko node built from a branch where the Kerberos account can be imported
  (the keytab import of the account's lifecycle; until it is merged the import answers 501
  and the probe cannot run).
- On the controller: an administrator session with the ActiveDirectory module, `ktpass`,
  `nltest` and `pktmon` (all in the box).
- On the Tenko node: the web UI or the API with an administrator's session, and `dig`
  somewhere that reaches the node.

## Steps

1. **The account** (on the controller, as a domain administrator). A computer account for
   Tenko with its SPN, AES only, and a keytab for it:

   ```powershell
   New-ADComputer -Name TENKO-DNS -SAMAccountName 'TENKO-DNS$' `
     -ServicePrincipalNames 'DNS/ns1.corp.example.test' `
     -KerberosEncryptionType AES128,AES256
   ktpass /princ DNS/ns1.corp.example.test@CORP.EXAMPLE.TEST /mapuser 'CORP\TENKO-DNS$' `
     /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /pass * /out C:\r120\tenko.keytab
   setspn -L 'TENKO-DNS$'
   ```

   `ktpass` sets the account's password to the one typed; the keytab holds the key of that
   password. Note the SIDs of the privileged groups:

   ```powershell
   (Get-ADGroup 'Domain Controllers').SID.Value
   (Get-ADGroup 'Domain Admins').SID.Value
   ```

2. **The keys on the node.** Import `tenko.keytab` for the realm `CORP.EXAMPLE.TEST` with the
   SPN `DNS/ns1.corp.example.test` (the account page of the web UI, or `POST
   /dns/kerberos/import` with an administrator's session). Delete the keytab file from the
   controller afterwards.

3. **The zones** (on the node). An access list with one Kerberos entry for the realm, and
   the primary zones `corp.example.test` and `_msdcs.corp.example.test` with that list in
   `update.allowed`, `require_tsig` on, and the Kerberos settings: the realm, ownership
   `windows`, the two SIDs of step 1 as privileged groups. The SOA `mname` of both zones is
   `ns1.corp.example.test`, and the zone has its A record `192.0.2.53`: Windows asks for a
   ticket to the server the SOA names.

4. **The controller's DNS client** points at the node only:

   ```powershell
   Get-NetAdapter
   Set-DnsClientServerAddress -InterfaceAlias '<adapter>' -ServerAddresses 192.0.2.53
   ```

5. **The capture and the registration** (on the controller):

   ```powershell
   pktmon filter remove
   pktmon filter add -p 53
   pktmon start --capture --pkt-size 0 -f C:\r120\register.etl
   ipconfig /registerdns
   nltest /dsregdns
   Restart-Service netlogon
   Start-Sleep -Seconds 120
   pktmon stop
   pktmon etl2pcap C:\r120\register.etl -o C:\r120\register.pcapng
   ```

6. **What the node saw.** In the audit log: `dns.update.apply` with the controller's
   principal (`<DC>$@CORP.EXAMPLE.TEST`), its SID and the ownership decision; any
   `dns.update.refuse` or `dns.gss.refuse` with its reason. In the metrics:
   `tenko_dns_tkey_total` by outcome and `tenko_dns_updates_total{auth="gss"}`. With `dig`:
   the records of the controller's `Netlogon.dns`
   (`%SystemRoot%\System32\config\netlogon.dns`), for example
   `dig @192.0.2.53 _ldap._tcp.dc._msdcs.corp.example.test SRV`.

7. **A restart of the node.** Restart the Tenko service (the contexts are dropped), then on
   the controller capture again as in step 5 with `-f C:\r120\after-restart.etl`, and run
   only `nltest /dsregdns`. Windows should get BADKEY on its old context, negotiate again,
   and register.

8. **Optional:** set `UpdateSecurityLevel` to 256 (secure only) by group policy
   (Computer Configuration, Administrative Templates, Network, DNS Client, Update security
   level) and repeat step 7.

## What to hand back

Give the lead the two `.pcapng` files, the node's log of the probe's minutes (`tenko` at
level `debug` for `tenko_dns::tkey` and `tenko_dns::update` if possible), the audit records,
and the answers to these questions as far as the captures show them:

| Question | Where it shows |
|---|---|
| Does Windows send TKEY over TCP only, and the updates over UDP or TCP? | The capture's transports |
| Which SPNEGO mechanism list does it send, and does the negotiation take one TKEY leg? | The TKEY query's key data, `tenko_dns_tkey_total{outcome="continue"}` |
| Does it accept the signed TKEY answer, and sign the update on the same context? | An update follows the TKEY answer without a new TKEY |
| What does it do after BADKEY on a dropped context (step 7)? | A new TKEY after the NOTAUTH |
| Does it reuse a context for several updates, and for how long? | Several updates under one key name |
| Is any update refused, and why? | `dns.update.refuse` and its reason |

The captures are of a test domain only. Captures of a real domain are never committed; the
ones of the test domain go to `windows/` with the Windows lab (E44).
