#!/bin/bash
# The domain controller of the round `account` (E45), inside the samba container: at first
# start `samba-tool domain provision` of LAB.EXAMPLE.TEST without DNS, the user alice and the
# computer account TENKO-DNS$ pre-staged as docs/active-directory.md section 4.1 does it (the
# SPN DNS/ns1.lab.example.test, AES only, the one-time password of the run); then Samba in
# the foreground. A file /lab/out/skew with a number of seconds starts Samba's clock that far
# ahead (faketime), for the clock-skew row. Every secret comes from /lab/secrets, generated
# per run by round.sh.
set -euo pipefail

realm=LAB.EXAMPLE.TEST
if [[ ! -f /var/lib/samba/private/sam.ldb ]]; then
  samba-tool domain provision --realm="$realm" --domain=LAB --server-role=dc \
    --dns-backend=NONE --adminpass="$(cat /lab/secrets/admin)" \
    --host-name=dc01 --host-ip=198.51.100.2 \
    --option='interfaces = eth0' --option='bind interfaces only = yes'
  cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
  # The default policy (complexity, a history of 24), but no minimum age: the round rotates
  # several times in a few minutes, which a one-day minimum age would refuse.
  samba-tool domain passwordsettings set --min-pwd-age=0 >/dev/null
  samba-tool user create alice "$(cat /lab/secrets/alice)" >/dev/null
  samba-tool computer create TENKO-DNS >/dev/null
  samba-tool spn add DNS/ns1.lab.example.test 'TENKO-DNS$' >/dev/null
  printf 'dn: CN=TENKO-DNS,CN=Computers,DC=lab,DC=example,DC=test\nchangetype: modify\nreplace: msDS-SupportedEncryptionTypes\nmsDS-SupportedEncryptionTypes: 24\n' |
    ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null
  samba-tool user setpassword 'TENKO-DNS$' --newpassword="$(cat /lab/secrets/otp)" >/dev/null
fi
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
touch /lab/out/READY
if [[ -s /lab/out/skew ]]; then
  exec faketime -f "+$(cat /lab/out/skew)s" samba -M single -i --no-process-group
fi
exec samba -M single -i --no-process-group
