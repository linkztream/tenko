#!/bin/bash
# Writes the keytab fixtures with MIT Kerberos' ktutil (krb5 1.20.1) and records the keys
# klist reads back from each. The realm, the accounts and the passwords are those of the
# fictitious lab realm CORP.EXAMPLE.TEST; no key of a real domain is in here.
#
#   bash make.sh        # in this directory; needs ktutil and klist (krb5-user)
set -eu
cd "$(dirname "$0")"
rm -f ./*.keytab ./*.klist

# addent <keytab> <principal> <kvno> <enctype> <password> [salt]
addent() {
  local salt="" read=""
  if [ -n "${6:-}" ]; then salt="-s $6"; fi
  if [ -f "$1" ]; then read="rkt $1"; fi
  rm -f "$1.new"
  printf '%s\naddent -password -p %s -k %s -e %s %s\n%s\nwkt %s.new\nq\n' \
    "$read" "$2" "$3" "$4" "$salt" "$5" "$1" | ktutil > /dev/null
  mv "$1.new" "$1"
}

USER_PW='Al1ce-Pass-lab'
COMPUTER_PW='Lab-Machine-Pass-1'
COMPUTER_SALT='CORP.EXAMPLE.TESThosttenko-dns.corp.example.test'

# A user account with the default salt (the realm and the name).
addent user-alice.keytab alice@CORP.EXAMPLE.TEST 2 aes256-cts-hmac-sha1-96 "$USER_PW"
addent user-alice.keytab alice@CORP.EXAMPLE.TEST 2 aes128-cts-hmac-sha1-96 "$USER_PW"

# The computer account Tenko owns, with its MS-KILE salt, under its own name and its SPN
# (as ktpass writes it), in two key versions (the previous and the current).
for kvno in 2 3; do
  pw="$COMPUTER_PW-$kvno"
  for etype in aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96; do
    addent computer-tenko-dns.keytab 'TENKO-DNS$@CORP.EXAMPLE.TEST' "$kvno" "$etype" "$pw" "$COMPUTER_SALT"
    addent computer-tenko-dns.keytab DNS/tenko.corp.example.test@CORP.EXAMPLE.TEST "$kvno" "$etype" "$pw" "$COMPUTER_SALT"
  done
done

# AES beside RC4 and 3DES entries, which the import refuses.
addent mixed-enctypes.keytab DNS/tenko.corp.example.test@CORP.EXAMPLE.TEST 4 aes256-cts-hmac-sha1-96 "$COMPUTER_PW" "$COMPUTER_SALT"
addent mixed-enctypes.keytab DNS/tenko.corp.example.test@CORP.EXAMPLE.TEST 4 arcfour-hmac "$COMPUTER_PW"
addent mixed-enctypes.keytab DNS/tenko.corp.example.test@CORP.EXAMPLE.TEST 4 des3-cbc-sha1 "$COMPUTER_PW" "$COMPUTER_SALT"

# A key version above 255: the 8-bit field holds its low octet, the 32-bit field the rest.
addent kvno-300.keytab 'TENKO-DNS$@CORP.EXAMPLE.TEST' 300 aes256-cts-hmac-sha1-96 "$COMPUTER_PW" "$COMPUTER_SALT"

for kt in ./*.keytab; do
  klist -Kekt "$kt" | sed -n 's/^ *\([0-9]*\) [^ ]* [^ ]* \([^ ]*\) (\([^)]*\)) *(0x\([0-9a-f]*\))$/\1 \2 \3 \4/p' > "${kt%.keytab}.klist"
done
