#!/bin/bash
# A Samba AD domain controller for CORP.EXAMPLE.TEST in a container on the host network
# (the KDC on 127.0.0.1:88), and an MIT client configuration on the host pointing at it.
#
#   bash scripts/lab-samba.sh /opt/sambalab
#   export KRB5_CONFIG=/opt/sambalab/krb5.conf; echo Al1ce-Pass-lab | kinit alice
#
# The service keys are in $LAB/out/tenko.keytab.txt once $LAB/out/READY exists.
set -eu
LAB=${1:-/opt/sambalab}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$LAB/out"
cp "$HERE/samba-provision.sh" "$LAB/provision.sh"
docker rm -f samba-dc >/dev/null 2>&1 || true
docker run -d --name samba-dc --network host --cap-add SYS_ADMIN -v "$LAB:/lab" ubuntu:24.04 /lab/provision.sh
cat > "$LAB/krb5.conf" <<EOT
[libdefaults]
    default_realm = CORP.EXAMPLE.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    dns_canonicalize_hostname = false
    rdns = false
    default_ccache_name = FILE:$LAB/ccache
[realms]
    CORP.EXAMPLE.TEST = {
        kdc = 127.0.0.1:88
        kpasswd_server = 127.0.0.1:464
    }
[domain_realm]
    .corp.example.test = CORP.EXAMPLE.TEST
    corp.example.test = CORP.EXAMPLE.TEST
EOT
sed "s|$LAB/ccache|$LAB/ccache128|; /\[libdefaults\]/a\    default_tgs_enctypes = aes128-cts-hmac-sha1-96\n    default_tkt_enctypes = aes128-cts-hmac-sha1-96" "$LAB/krb5.conf" > "$LAB/krb5-aes128.conf"
echo "provisioning in the background; wait for $LAB/out/READY (a few minutes), then read $LAB/out/tenko.keytab.txt"
