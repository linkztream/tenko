# Keytab fixtures

Keytabs written by MIT Kerberos' `ktutil` (krb5 1.20.1 on Ubuntu 24.04), made by `make.sh`
in this directory, with the keys `klist -Kekt` read back from each in the `.klist` file
beside it (`kvno principal enctype key`). Realm, accounts and passwords are those of the
fictitious lab realm `CORP.EXAMPLE.TEST`; no key of a real domain is in here.

| File | Content |
| --- | --- |
| `user-alice.keytab` | `alice@CORP.EXAMPLE.TEST`, version 2, AES-256 and AES-128, default salt, password `Al1ce-Pass-lab` |
| `computer-tenko-dns.keytab` | `TENKO-DNS$` and its SPN `DNS/tenko.corp.example.test`, versions 2 and 3, both AES types, the MS-KILE computer salt `CORP.EXAMPLE.TESThosttenko-dns.corp.example.test`, passwords `Lab-Machine-Pass-1-2` and `Lab-Machine-Pass-1-3` |
| `mixed-enctypes.keytab` | the SPN in version 4 with AES-256, RC4 and 3DES entries (password `Lab-Machine-Pass-1`) |
| `kvno-300.keytab` | `TENKO-DNS$` in version 300: the 8-bit field holds 44, the 32-bit field 300 |

`ktpass` on Windows writes the same format (version 2, `KRB5_NT_PRINCIPAL`, the 32-bit key
version); a keytab from a domain controller is the first thing to import in the owner's lab.
