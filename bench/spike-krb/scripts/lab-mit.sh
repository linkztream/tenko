#!/bin/bash
# An MIT Kerberos KDC for the fictitious realm CORP.EXAMPLE.TEST on the local host, as the
# spike used it: the service principal DNS/tenko.corp.example.test with AES-256 and AES-128
# keys, DNS/tenko128.corp.example.test with an AES-128 key only, and the user alice.
# Needs krb5-kdc, krb5-admin-server and krb5-user (Debian/Ubuntu package names).
#
#   bash scripts/lab-mit.sh /opt/mitlab
#   export KRB5_CONFIG=/opt/mitlab/krb5.conf; echo Client-Pass-1 | kinit alice
#
# Prints the service keys (klist -Kek) to paste into `spike-krb serve --key`.
set -eu
LAB=${1:-/opt/mitlab}
mkdir -p "$LAB/db"
cat > "$LAB/krb5.conf" <<EOT
[libdefaults]
    default_realm = CORP.EXAMPLE.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    dns_canonicalize_hostname = false
    rdns = false
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_ccache_name = FILE:$LAB/ccache
[realms]
    CORP.EXAMPLE.TEST = {
        kdc = 127.0.0.1:1088
        admin_server = 127.0.0.1:1749
    }
[domain_realm]
    .corp.example.test = CORP.EXAMPLE.TEST
    corp.example.test = CORP.EXAMPLE.TEST
EOT
# The same, but asking for AES-128 session keys (the AES-128 fixtures).
sed "s|$LAB/ccache|$LAB/ccache128|; s/default_tgs_enctypes = .*/default_tgs_enctypes = aes128-cts-hmac-sha1-96/; s/default_tkt_enctypes = .*/default_tkt_enctypes = aes128-cts-hmac-sha1-96/" "$LAB/krb5.conf" > "$LAB/krb5-aes128.conf"
cat > "$LAB/kdc.conf" <<EOT
[kdcdefaults]
    kdc_ports = 1088
    kdc_tcp_ports = 1088
[realms]
    CORP.EXAMPLE.TEST = {
        database_name = $LAB/db/principal
        acl_file = $LAB/kadm5.acl
        key_stash_file = $LAB/db/stash
        max_life = 10h
        max_renewable_life = 7d
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
[logging]
    kdc = FILE:$LAB/kdc.log
EOT
echo '*/admin@CORP.EXAMPLE.TEST *' > "$LAB/kadm5.acl"
export KRB5_CONFIG="$LAB/krb5.conf" KRB5_KDC_PROFILE="$LAB/kdc.conf"
kdb5_util create -s -P lab-master-key -r CORP.EXAMPLE.TEST
kadmin.local -q "addprinc -randkey DNS/tenko.corp.example.test"
kadmin.local -q "addprinc -randkey -e aes128-cts-hmac-sha1-96:normal DNS/tenko128.corp.example.test"
kadmin.local -q "addprinc -pw Client-Pass-1 alice"
kadmin.local -q "ktadd -k $LAB/dns.keytab DNS/tenko.corp.example.test"
kadmin.local -q "ktadd -e aes128-cts-hmac-sha1-96:normal -k $LAB/dns128.keytab DNS/tenko128.corp.example.test"
krb5kdc -n > "$LAB/kdc.stdout" 2>&1 &
sleep 1
klist -Kek "$LAB/dns.keytab"
klist -Kek "$LAB/dns128.keytab"
