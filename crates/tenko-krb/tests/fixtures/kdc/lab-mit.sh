#!/bin/bash
# An MIT Kerberos KDC and kadmind for the fictitious realm CORP.EXAMPLE.TEST on the local
# host, for the live client tests of tenko-krb (src/client/tests.rs) and the recording of
# tests/fixtures/kdc/. Needs krb5-kdc, krb5-admin-server and krb5-user (Debian and Ubuntu
# package names); runs as any user that may bind the ports below.
#
#   bash lab-mit.sh <dir>        # starts krb5kdc (port 1088) and kadmind (kpasswd 1464)
#   TENKO_KRB_LAB=<dir> cargo test -p tenko-krb live_mit -- --ignored
#
# The principals: alice (password Al1ce-Pass-lab), TENKO-DNS$ (password Lab-Machine-Pass-1,
# pre-authentication required) with DNS/tenko.corp.example.test in the keytab dns.keytab,
# and rotate (password Rotate-Pass-0) whose password the change-password test changes.
set -eu
LAB=${1:?lab directory}
mkdir -p "$LAB/db"
cat > "$LAB/krb5.conf" <<EOT
[libdefaults]
    default_realm = CORP.EXAMPLE.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
    CORP.EXAMPLE.TEST = {
        kdc = 127.0.0.1:1088
        admin_server = 127.0.0.1:1749
        kpasswd_server = 127.0.0.1:1464
    }
EOT
cat > "$LAB/kdc.conf" <<EOT
[kdcdefaults]
    kdc_ports = 1088
    kdc_tcp_ports = 1088
[realms]
    CORP.EXAMPLE.TEST = {
        database_name = $LAB/db/principal
        acl_file = $LAB/kadm5.acl
        key_stash_file = $LAB/db/stash
        kadmind_port = 1749
        kpasswd_port = 1464
        max_life = 10h
        max_renewable_life = 7d
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
[logging]
    kdc = FILE:$LAB/kdc.log
    admin_server = FILE:$LAB/kadmind.log
EOT
echo '*/admin@CORP.EXAMPLE.TEST *' > "$LAB/kadm5.acl"
export KRB5_CONFIG="$LAB/krb5.conf" KRB5_KDC_PROFILE="$LAB/kdc.conf"
kdb5_util create -s -P lab-master-key -r CORP.EXAMPLE.TEST > /dev/null
kadmin.local -q "addprinc -pw Al1ce-Pass-lab +requires_preauth alice" > /dev/null
kadmin.local -q "addprinc -pw Lab-Machine-Pass-1 +requires_preauth TENKO-DNS\$" > /dev/null
kadmin.local -q "addprinc -randkey DNS/tenko.corp.example.test" > /dev/null
kadmin.local -q "addprinc -pw Rotate-Pass-0 +requires_preauth rotate" > /dev/null
kadmin.local -q "ktadd -k $LAB/dns.keytab DNS/tenko.corp.example.test" > /dev/null
krb5kdc -P "$LAB/kdc.pid"
kadmind -P "$LAB/kadmind.pid"
sleep 1
echo "KDC 127.0.0.1:1088, kpasswd 127.0.0.1:1464, keytab $LAB/dns.keytab"
