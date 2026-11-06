# The domain controller of the round `account` (E45): Samba 4 from Ubuntu 24.04 with the
# tools the round drives it with (ldb-tools for msDS-KeyVersionNumber and the encryption
# types, iptables for the lost answer of the restart row, faketime for the clock-skew row).
# Built by account/round.sh; nothing of Samba is copied into the repository (GPL, ADR 0026).
# The recommended packages are installed: `samba-tool domain provision` needs the
# provisioning templates of samba-ad-provision.
FROM ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq samba samba-ad-provision samba-dsdb-modules samba-vfs-modules \
      winbind krb5-user ldb-tools iptables faketime \
 && rm -rf /var/lib/apt/lists/* /etc/samba/smb.conf /etc/krb5.conf
