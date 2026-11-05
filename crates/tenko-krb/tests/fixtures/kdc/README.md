# Recorded KDC exchanges

Exchanges of `tenko-krb`'s client with a live MIT Kerberos KDC and `kadmind` (krb5 1.20.1 on
Ubuntu 24.04) and with a Samba AD domain controller, both for the fictitious realm
`CORP.EXAMPLE.TEST`, recorded by the ignored tests `client::tests::dns_28_live_mit_kdc` and
`client::tests::dns_28_live_samba_adopt` (see `samba-provision.sh` for the second):

```sh
bash lab-mit.sh /tmp/mitlab
TENKO_KRB_LAB=/tmp/mitlab TENKO_WRITE_FIXTURES=1 cargo test -p tenko-krb dns_28_live_mit_kdc -- --ignored
```

| File | Content |
| --- | --- |
| `lab-mit.sh` | The KDC on 127.0.0.1:1088 and `kadmind` with the change-password port 1464, the principals and their lab passwords |
| `as-alice.txt` | The AS exchange of `alice` for `krbtgt`: the time and nonce of the request, the KDC's `KDC_ERR_PREAUTH_REQUIRED` with `PA-ETYPE-INFO2` (`reply1`) and the AS-REP to the request with `PA-ENC-TIMESTAMP` (`reply2`) |
| `tgs-dns.txt` | The TGS exchange with that TGT for `DNS/tenko.corp.example.test` |
| `kpasswd-rotate.txt` | The AS exchange of `rotate` for `kadmin/changepw`, the subkey and sequence number of the change-password request, `kadmind`'s answer to the request without a target (result 1, malformed) and its answer to the request that names it (success) |
| `samba-provision.sh` | A Samba 4.19 AD domain controller in a container with `alice` and the pre-staged computer account `TENKO-DNS$` (one-time password, the SPN, AES only) |
| `samba-adopt.txt` | The adopt flow against it, recorded by `dns_28_live_samba_adopt`: the AS exchange of `TENKO-DNS$` for `kadmin/changepw` with the one-time password (the KDC names the MS-KILE salt), the RFC 3244 change without a target, the key version of the new password, and alice's AS and TGS exchanges for `DNS/tenko.corp.example.test`, whose ticket the replay accepts with keys derived from the new password and the salt |
| `dns.keytab` | The lab's keytab for `DNS/tenko.corp.example.test` (version 2), which the acceptor uses for the service ticket |

The replays decrypt the recorded answers with the lab passwords and keys; the requests Tenko
builds differ from the recorded ones only in their random confounders. No key or password of
a real domain is in here.
