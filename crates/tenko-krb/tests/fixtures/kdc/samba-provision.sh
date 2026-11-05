#!/bin/bash
# A Samba AD domain controller for CORP.EXAMPLE.TEST on the loopback interface, with the
# user alice and the computer account TENKO-DNS$ pre-staged as identity plan section 3.1
# describes (the one-time password One-Time-Pass-1, the SPN DNS/tenko.corp.example.test,
# AES only), for the ignored test client::tests::dns_28_live_samba_adopt. It runs inside
# an ubuntu:24.04 container on the host network (the KDC on 127.0.0.1:88, kpasswd on 464):
#
#   docker run -d --name tenko-samba-dc --network host --cap-add SYS_ADMIN \
#     -v "$LAB:/lab" ubuntu:24.04 /lab/samba-provision.sh    # $LAB holds this script
#   # wait for $LAB/out/READY, then:
#   TENKO_SAMBA_LAB=1 cargo test -p tenko-krb dns_28_live_samba_adopt -- --ignored
set -eux
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq samba samba-dsdb-modules samba-vfs-modules winbind krb5-user ldb-tools >/dev/null
rm -f /etc/samba/smb.conf /etc/krb5.conf
samba-tool domain provision --use-rfc2307 --realm=CORP.EXAMPLE.TEST --domain=CORP \
  --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass='Adm1n-Pass-lab' \
  --host-name=dc1 --host-ip=127.0.0.1 \
  --option='interfaces = lo' --option='bind interfaces only = yes' \
  --option='dns forwarder = 127.0.0.254'
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
samba -M single -i --no-process-group > /lab/out/samba.log 2>&1 &
for _ in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/88) 2>/dev/null && break; sleep 1; done
samba-tool domain passwordsettings set --complexity=off --min-pwd-age=0 --history-length=0
samba-tool user create alice 'Al1ce-Pass-lab'
samba-tool computer create TENKO-DNS
samba-tool spn add DNS/tenko.corp.example.test 'TENKO-DNS$'
cat > /tmp/aes.ldif <<EOT
dn: CN=TENKO-DNS,CN=Computers,DC=corp,DC=example,DC=test
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 24
EOT
ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/aes.ldif
samba-tool user setpassword 'TENKO-DNS$' --newpassword='One-Time-Pass-1'
echo PROVISIONED > /lab/out/READY
wait
