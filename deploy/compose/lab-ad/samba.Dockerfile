# The domain controller of the AD lab: Samba 4.19 of Ubuntu 24.04 as an Active Directory
# domain controller without its own DNS (identity plan section 3.19). Samba is GPL-licensed
# and runs only as this container; nothing of it is copied into the repository.
# bind9-dnsutils brings the nsupdate that samba_dnsupdate runs with -g.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        samba samba-ad-dc samba-ad-provision samba-dsdb-modules samba-vfs-modules winbind \
        krb5-user ldb-tools \
        bind9-dnsutils python3-dnspython ca-certificates \
    && rm -rf /var/lib/apt/lists/* /etc/samba/smb.conf

COPY samba-entrypoint.sh /usr/local/bin/samba-entrypoint.sh
ENTRYPOINT ["/bin/bash", "/usr/local/bin/samba-entrypoint.sh"]
