#!/bin/bash
# Runs inside an ubuntu:24.04 container with the host network (scripts/lab-samba.sh).
# Provisions the Samba AD DC for CORP.EXAMPLE.TEST on the loopback interface, creates the
# user alice and the computer account tenko with the SPN DNS/tenko.corp.example.test and
# msDS-SupportedEncryptionTypes 24 (AES only), exports the account's keytab to /lab/out
# and keeps the controller running.
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
samba-tool user create alice 'Al1ce-Pass-lab'
samba-tool computer create tenko
samba-tool spn add DNS/tenko.corp.example.test 'tenko$'
cat > /tmp/aes.ldif <<EOT
dn: CN=tenko,CN=Computers,DC=corp,DC=example,DC=test
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 24
EOT
ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/aes.ldif
rm -f /lab/out/tenko.keytab
samba-tool domain exportkeytab /lab/out/tenko.keytab --principal='DNS/tenko.corp.example.test'
klist -Kek /lab/out/tenko.keytab | tee /lab/out/tenko.keytab.txt
echo PROVISIONED > /lab/out/READY
wait
