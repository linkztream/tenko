# The round `account` of the Active Directory lab

The lifecycle of Tenko's Kerberos service account (E45 of
[identity-plan.md](../../../../docs/plans/identity-plan.md), sections 3.1 and 3.10) against a
Samba AD domain controller: the adopt of a pre-staged computer account with its one-time
password, a forced rotation, a restart between the password change and the commit, each
finding of the self-test, and the import of a keytab as `ktpass` writes it. It uses the
services of [compose.yml](../compose.yml) with [account.override.yml](../account.override.yml)
under a project name of its own (`tenkoadaccount`), so it never shares containers with
another round.

```sh
bash deploy/compose/lab-ad/account/round.sh                      # builds tenko:lab first
TENKO_IMAGE=tenko:lab bash deploy/compose/lab-ad/account/round.sh
KEEP=1 bash deploy/compose/lab-ad/account/round.sh               # leave the lab running
```

It needs bash and Docker with the compose plugin, nothing else on the host: the API is
reached from the client container inside the lab network, so the round runs on Docker
Desktop as well as on a Linux host. It prints one PASS or FAIL line per row and a summary,
and tears the lab down (containers, volumes, network, the work directory) also after a
failure, after printing the logs.

| File | What |
|---|---|
| `round.sh` | The round: the images, the secrets of the run, the services, the rows |
| `samba.sh` | The controller's start: `samba-tool domain provision` of `LAB.EXAMPLE.TEST` without DNS, with the default password policy except the minimum age (the round rotates several times in minutes), `alice`, and `TENKO-DNS$` pre-staged with what [active-directory.md](../../../../docs/active-directory.md) section 4.1 sets (the SPN `DNS/ns1.lab.example.test`, AES only, the one-time password) through `samba-tool`, since the block itself needs Windows; Samba under `faketime` when the round asks for a skewed clock |
| `samba.Dockerfile`, `client.Dockerfile` | Ubuntu 24.04 (pinned by digest) with Samba, `ldb-tools`, `iptables` and `faketime`; with MIT Kerberos, `curl` and `jq` |
| `api.sh` | Tenko's API from the client container; secrets reach it from files, never from an argument |

## The rows

| Row | What it shows |
|---|---|
| `adopt.taken` | `POST /dns/kerberos/adopt` takes `TENKO-DNS$` over; the version Tenko holds is the controller's `msDS-KeyVersionNumber` |
| `adopt.otp_gone` | `kinit` with the one-time password fails afterwards: the password is Tenko's |
| `finding.spn_missing` | An SPN no account holds (`DNS/ns2...`) is `dns.gss.spn_missing`, naming it |
| `check.pass` | With the SPN added on the controller (`samba-tool spn add`) the self-test passes |
| `client.kvno` | alice's service ticket for the SPN names the version Tenko holds |
| `rotate.moves`, `rotate.old_ticket` | `POST /dns/kerberos/rotate` moves the version on Tenko and the controller; the old version is kept as previous, and alice's ticket from before the rotation is under it |
| `restart.recovered` | The controller drops its change-password answers (`iptables`); Tenko is killed after the controller took the new password and before Tenko committed it; after the restart Tenko holds the new version as current, no version pending |
| `finding.weak_etype` | `msDS-SupportedEncryptionTypes` = 4 (RC4 only) is `dns.gss.weak_etype` |
| `finding.spn_duplicate` | The SPN on a second computer account as well is `dns.gss.spn_duplicate` |
| `finding.clock_skew` | The controller's clock 120 s ahead is `dns.gss.clock_skew` |
| `finding.self_test` | The account disabled is `dns.gss.self_test_failed`, reason `disabled` |
| `import.works` | After a reset of the password, a keytab written with `ktutil` as `ktpass` writes it (the account and its SPN, both AES types) imports, and the self-test passes |
| `finding.kvno_unknown` | A keytab of a key version the KDC does not issue is `dns.gss.kvno_unknown` |
| `adopt.no_secret` | No answer of the API carried the one-time password |

That the TKEY handler accepts a client's ticket with the keys this round leaves in Tenko is the
round `gss` of the lab; this round shows that the keys and the versions Tenko holds are the
ones the controller issues tickets under.

## Secrets

Every secret is generated per run into the work directory and removed with it: the
controller's administrator password, alice's, the one-time password, the password of the
reset before the import rows, Tenko's administrator password and its key-encryption key. None is printed. They
reach Tenko's API and `kinit` and `ktutil` from files or on standard input; inside the
controller container `samba-tool` takes the passwords it sets as arguments, which only that
container's processes see.
