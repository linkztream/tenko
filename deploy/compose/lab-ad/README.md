# The compose Active Directory lab

The container lab of Slice 13 ([identity-plan.md](../../../docs/plans/identity-plan.md)
section 3.19, ID-Q18): a Samba Active Directory domain controller provisioned without its
own DNS, a Linux client with MIT Kerberos, and one Tenko DDI node that is the primary of the
domain's zones and takes the secure dynamic updates (GSS-TSIG) of both. It is where the
acceptance rows of E43, E47, E48 and E49 run, weekly on hosted runners and by hand; the
Windows proof (E44) is the owner's lab and is not in containers. It is a lab, not a
deployment example: the realm is `LAB.EXAMPLE.TEST`, every address is a documentation value
(`198.51.100.0/24`), every secret is generated per run, and the repository is public and so
are the runners' logs, so nothing of a real domain is ever written here.

WP13.0 declares the services; nothing runs a round yet. The table says what each later
package fills in.

## What runs

| Service | What | Reached at |
|---|---|---|
| `samba` | Samba as the domain controller of `LAB.EXAMPLE.TEST` (`samba-tool domain provision --dns-backend=NONE`): the KDC on 88, the password service on 464, LDAP on 389 and LDAPS on 636 with a certificate of the lab's private CA. Its DNS is the Tenko node, so its own `samba_dnsupdate` registers the locator records there with `nsupdate -g` (a controller-shaped client) | `198.51.100.2`, `dc01.lab.example.test` |
| `tenko` | One node with `--roles controller,dns`, the DNS module on and the Lab profile, primary of `lab.example.test` and `_msdcs.lab.example.test`. The DNS role listens on 53 inside the lab network; the API is plain HTTP on 8443 (the Lab profile allows it), on the lab network only | `198.51.100.3`, `ns1.lab.example.test` |
| `client` | A Linux client with MIT Kerberos (`kinit`, `klist`), BIND's `nsupdate -g` and `curl`; its DNS is the Tenko node | `198.51.100.4`, `ws01.lab.example.test` |

The images are named by variables (`SAMBA_IMAGE`, `CLIENT_IMAGE`, `TENKO_IMAGE`) with a tag
default so that the files stand without a registry; the package that runs a round pins
each image by digest. Samba is GPL-licensed and Keycloak Apache-2.0; both are only run as
containers, nothing of them is copied into the repository or linked (ADR 0026). The work
directory `LAB_DIR` holds what a run generates: the administrator password and the one-time
password of Tenko's computer account under `secrets/`, the key-encryption key of the node
(`secrets/kek`), the private CA and the controller's LDAPS certificate under `tls/`, and the
node's `tenko.toml`.

## What the later packages fill in

| Package | Adds to the lab |
|---|---|
| WP13.2 | The round `gss` (E43): the Samba image's provisioning and `samba_dnsupdate`, the client's `krb5.conf`, the zones set to secure only, the rows of E43 (adds, replaces and deletes over UDP and TCP, mutual authentication, an unsigned update refused, BADKEY on an unknown or expired context, BADTIME on a skewed clock, a replayed update refused, a second principal refused on an owned name, NTLM alone refused), and the captures kept as test fixtures |
| WP13.3 | The adoption of the pre-staged computer account with the one-time password of the run, the forced rotation, the restart between the password change and the commit, the self-test's findings (E45) |
| WP13.4 | `windows/`: the steps and the packet captures of the owner-run Windows lab (E44), committed after the run |
| WP13.5 | A Keycloak service with a realm export for OpenID Connect (E47), and the crafted-token rows |
| WP13.6 | The LDAP rounds against the controller over LDAPS and StartTLS (E48): the private CA generated per run that nothing trusts, so that the chain import is what makes LDAPS work; an OpenLDAP container for the `memberOf` row; the five-minute UI test under `ui/e2e` |
| WP13.7 | `curl --negotiate` from the client against the web UI (E49) |
| WP13.8 | The measurements M45 to M49 on the musl binary, with their scripts under `bench/phase4-identity/` |

## Running it

Nothing runs yet beyond `docker compose config`, which validates the file:

```sh
LAB_DIR=$(mktemp -d) docker compose -f deploy/compose/lab-ad/compose.yml config
```

The round scripts of the later packages generate `LAB_DIR`, start the services, run their
rows and print a summary, like `smoke.sh` of [lab-dns](../lab-dns/README.md).
