# The compose Active Directory lab

The container lab of Slice 13 ([identity-plan.md](../../../docs/plans/identity-plan.md)
section 3.19, ID-Q18): a Samba Active Directory domain controller provisioned without its
own DNS, a Linux client with MIT Kerberos, and one Tenko DDI node that is the primary of the
domain's zones and takes the secure dynamic updates (GSS-TSIG) of both. It is where the
acceptance rows of E43, E47, E48 and E49 run, weekly on hosted runners and by hand; the
Windows proof (E44) is the owner's lab and is not in containers: its steps are
[windows/README.md](windows/README.md), with the early probe of risk R120 as its step W5. It is a lab, not a deployment example: the realm is
`LAB.EXAMPLE.TEST`, every address is a documentation value (`198.51.100.0/24`), every secret
is generated per run, and the repository is public and so are the runners' logs, so nothing
of a real domain is ever written here.

## What runs

| Service | What | Reached at |
|---|---|---|
| `samba` | Samba 4.19 of Ubuntu 24.04 (`samba.Dockerfile`) as the domain controller of `LAB.EXAMPLE.TEST` (`samba-tool domain provision --dns-backend=NONE` at the first start, `samba-entrypoint.sh`): the KDC on 88, the password service on 464, LDAP on 389 and 636. Its DNS is the Tenko node, so its own `samba_dnsupdate` registers the locator records there with `nsupdate -g` (a controller-shaped client). It runs with `CAP_SYS_ADMIN`, which Samba needs to keep the ACLs of its shares in extended attributes | `198.51.100.2`, `dc01.lab.example.test` |
| `tenko` | One node with `--roles controller,dns`, the DNS module on and the Lab profile, primary of `lab.example.test` and `_msdcs.lab.example.test`. The DNS role listens on 53 inside the lab network: the image runs without privileges or capabilities, and the container's network namespace lets unprivileged processes bind from port 53 up (`net.ipv4.ip_unprivileged_port_start`). The API is plain HTTP on 8443 (the Lab profile allows it), on the lab network only | `198.51.100.3`, `ns1.lab.example.test` |
| `client` | Ubuntu 24.04 (`client.Dockerfile`) with MIT Kerberos (`kinit`, `klist`), BIND's `nsupdate -g`, `curl` and Python with the MIT GSSAPI bindings for `gss_client.py`; its DNS is the Tenko node. The round also calls the node's API from here, since a Docker Desktop host does not reach the lab network | `198.51.100.4`, `ws01.lab.example.test` |

The controller and the client are built from `ubuntu:24.04` pinned by digest; the Tenko image
is built from `deploy/Dockerfile` (or named by `TENKO_IMAGE`). Samba is GPL-licensed and
Keycloak Apache-2.0; both are only run as containers, nothing of them is copied into the
repository or linked (ADR 0026). The work directory `LAB_DIR` holds what a run generates:
the administrator password of the controller and the passwords of the users `alice` and
`bob` under `secrets/`, the key-encryption key of the node (`secrets/kek`), the lab's
`secrets/krb5.conf` (the controller as the KDC by address, no reverse lookups, TCP for
tickets with a PAC; the controller reads it from the mount, the round writes it into the
client), the node's `tenko.toml`, and under `out/` the keytab of Tenko's computer account that
the controller exports.

## The rounds

| Round | Script | Checks |
|---|---|---|
| `gss` | `gss.sh` (below) | E43: secure dynamic updates with GSS-TSIG from the controller and a Linux client; E46: the ownership rows a Samba controller can exercise |
| `account` | [`account/round.sh`](account/README.md), with `account.override.yml` under the project `tenkoadaccount` | E45: the lifecycle of Tenko's Kerberos account (adopt, rotation, recovery, the self-test's findings, the keytab import) |

The two rounds share the services of `compose.yml`; `account` runs the controller with a provisioning of its own (the pre-staged account, `faketime` for the skew row), so it is an override under its own project rather than services of this file.

## The round `gss` (E43)

`gss.sh` sets the lab up and runs the rows of E43, one `PASS` or `FAIL` line each:

1. The node starts and is set up through its API under the Lab profile; the controller
   provisions the realm; the users `alice` and `bob` and Tenko's computer account
   `TENKO-DNS$` (the SPN `DNS/ns1.lab.example.test`, `msDS-SupportedEncryptionTypes` 24)
   are created with `samba-tool`, and the account's keytab is exported and imported into
   the node with `POST /dns/kerberos/import`, the request `tenko dns kerberos import`
   sends. The route takes an interactive session, so the round signs in rather than using a
   token.
2. The access list `ad-lab` (every principal of `LAB.EXAMPLE.TEST`) and the two zones,
   secure only (`require_tsig`, the Kerberos settings of the realm, ownership `windows`,
   Domain Controllers and Domain Admins privileged by their SIDs from the controller), and
   the address of `ns1.lab.example.test`, the SOA's `mname`, whose SPN the clients ask a
   ticket for. The round runs under the Lab profile (for the plain HTTP API), which
   requires no signature whatever `require_tsig` says: what refuses an unsigned update here
   is the list, which names principals and no address. Under Standard and Hardened
   `require_tsig` holds as well.
3. The rows:

| Row | Check |
|---|---|
| `gss.dc` | The controller's `samba_dnsupdate --all-names` registers its records with `nsupdate -g` as `DC01$`: the `_ldap._tcp` SRV records and the controller's A record answer |
| `gss.mutual` | `gss_client.py negotiate` as `alice`: TKEY completes in one leg with mutual authentication, and the TKEY answer's GSS-TSIG verifies at MIT's side with no request MAC in its digest ([MS-GSSA] 3.1.5.1) |
| `gss.add.udp` | `nsupdate -g` adds `ws-alice.lab.example.test` over UDP; the next query answers it |
| `gss.replace` | `prereq yxrrset`, delete and add in one signed update replace the address |
| `gss.add.tcp` | `nsupdate -g -v` adds `ws-tcp.lab.example.test` over TCP |
| `gss.delete` | A signed update deletes it: NXDOMAIN at once |
| `gss.unsigned` | An unsigned update is REFUSED |
| `gss.badkey` | An update signed on a context the node never held: NOTAUTH with BADKEY |
| `gss.badtime` | An update signed 600 s in the past: NOTAUTH with BADTIME, the answer signed |
| `gss.replay` | A signed update sent twice is applied once; the second is NOTAUTH with BADSIG |
| `gss.expired` | An update on a context past its lifetime (`[dns.gss] context_max_secs = 60` in the round): NOTAUTH with BADKEY |
| `gss.second` | `bob` is REFUSED on the name `alice` created and owns |
| `gss.ntlm` | A TKEY offer of NTLM alone is refused with BADKEY |

Then the rows of E46 (the ownership of section 3.6 of the identity plan) that a Samba
controller can exercise; the Rust tests (`crates/tenko-dns/tests/gss_update.rs`) hold every
row of the table, these show the same against a real KDC and real `nsupdate -g` clients. The
round creates two more computer accounts for them, `WSBOB$` and `SRV01$`.

| Row | Check |
|---|---|
| `own.dc_host` | The controller owns the host name its `samba_dnsupdate` registered: the owner view lists `dc01` owned by `DC01$`, `created` |
| `own.dc_refresh` | The controller's next registration succeeds and the owner stays |
| `own.dc_refused` | A user (`alice`) is REFUSED on the controller's host record |
| `own.locator` | A user is REFUSED on a locator name (`_ldap._tcp`) |
| `own.service_name` | A user is REFUSED creating the well-known service name `wpad`, and nothing answers there; the domain administrator creates it |
| `own.admin` | The domain administrator changes a name it does not own; the owner stays `alice` |
| `own.import` | The dry run of a zone file in the Windows dialect lists `wsbob` (an aging mark) as claimable and not `srv01` (static); the import with the dry run's digest makes `wsbob` claimable, and both answer |
| `own.claim_other` | Another principal (`bob`) cannot claim the imported dynamic name |
| `own.claim` | `WSBOB$` claims its own imported name and owns it, `claimed` |
| `own.static` | `SRV01$` cannot claim its static record |
| `own.release` | After a release through the owner view, the name is not open to another principal |
| `own.assign` | The name reassigned to `bob` with his SID: `bob` changes it and owns it, `assigned` |

Every successful `nsupdate -g` row is also a check of the answers' signatures: `nsupdate`
verifies the GSS-TSIG of the TKEY answer and of each update answer and reports a failure.

## Running it

From the repository root, with Docker and the compose plugin (Docker Desktop on Windows
works from Git Bash):

```sh
bash deploy/compose/lab-ad/gss.sh                       # builds tenko:lab first
TENKO_IMAGE=tenko:lab bash deploy/compose/lab-ad/gss.sh # reuses an image
KEEP=1 bash deploy/compose/lab-ad/gss.sh                # keeps the lab for hand tests
```

`docker compose config` validates the file on its own:

```sh
LAB_DIR=$(mktemp -d) docker compose -f deploy/compose/lab-ad/compose.yml config
```

## What the later packages fill in

| Package | Adds to the lab |
|---|---|
| WP13.4 | `windows/`: the steps and the packet captures of the owner-run Windows lab (E44), committed after the run |
| WP13.5 | A Keycloak service with a realm export for OpenID Connect (E47), and the crafted-token rows |
| WP13.6 | The LDAP rounds against the controller over LDAPS and StartTLS (E48): the private CA generated per run that nothing trusts, so that the chain import is what makes LDAPS work; an OpenLDAP container for the `memberOf` row; the five-minute UI test under `ui/e2e` |
| WP13.7 | `curl --negotiate` from the client against the web UI (E49) |
| WP13.8 | The measurements M45 to M49 on the musl binary, with their scripts under `bench/phase4-identity/` |
