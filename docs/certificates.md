# Certificates

Every node serves its API and web UI over TLS (OPS-22, TGL-08). This page covers the four ways a node gets its certificate, where to see what it serves, when it warns about expiry, how a renewed certificate gets from an ACME client such as the one in OPNsense to the node without manual work, and how admin computers come to trust the internal CA.

Related: [SECURITY-PROFILES.md](SECURITY-PROFILES.md) (TGL-08), [QUICKSTART.md](QUICKSTART.md), [`deploy/tenko.example.toml`](../deploy/tenko.example.toml) (the `[tls]` section), [cluster.md](cluster.md) (the certificates of the cluster port, which are not these).

## 1. The four modes

`[tls] mode` in `tenko.toml` chooses the mode. It is read at start, so a change of mode needs a restart.

| `mode` | Who holds the certificate | Renewal | Profiles | Keys in `[tls]` |
|---|---|---|---|---|
| `internal_ca` (default) | Tenko: a server certificate from its own certificate authority for the host name of setup | Automatic: checked every `renew_check_hours` (24) and renewed 30 days before it ends | Home (default), Standard, Hardened, Lab | `host_name`, `alt_names`, `addresses`, `renew_check_hours` |
| `imported` | You: a chain (leaf first) and a key as PEM files on the node | You or your ACME client replace the files; the node loads them (section 4) | Standard, Hardened, Lab, Home | `cert_path`, `key_path`, `watch_interval_secs` (5), `accept_external_replacement` |
| `reverse_proxy` | A proxy in front of Tenko (HAProxy, nginx, Caddy) | In the proxy | every profile | `trusted_proxies`, `proxy_protocol`, `public_host` |
| `plain` | Nobody: plain HTTP from every source | none | Lab only | none |

`tls13_only` (always on under Hardened) and `hsts` apply to the first two modes. DNS over TLS and DNS over HTTPS use the certificate of the listener unless `[dns.tls] certificate` and `key` name files of their own, which are watched the same way.

## 2. What the node serves

**Settings → Certificates** shows, for the node you are connected to:

- the mode and the lowest TLS version;
- the certificate in use: subject, names (DNS and IP), issuer, validity, days left, chain length, SHA-256 fingerprint and when the node loaded it;
- for `internal_ca`: the CA root (subject, validity, fingerprint) and its download;
- for `imported`: the paths of the two files, how often they are checked, whether a certificate replaced from outside is accepted and what the profile in force says about that;
- for `reverse_proxy`: the trusted proxies, whether the PROXY protocol is expected and the public host name;
- a newer certificate that is on disk but not in use (section 4.3).

The page reads when it opens and when you press Refresh, never on its own. The same facts are `GET /api/v1/system/tls` (needs read access to the system; a token works). The answer names the paths of the files and never their contents; the private key is not part of any answer.

## 3. Expiry

The days left are whole days. The status of the node (`GET /api/v1/system/status`, the start page) raises a warning while the certificate in use is closer to its end than 30 days:

| Days left | State | Status warning | The page shows |
|---|---|---|---|
| 30 or more | `valid` | none | the days left, plain |
| fewer than 30 | `warning` | `sys.tls.certificate_expiry` (`params.state = warning`) | the days left in the warning style and a note |
| fewer than 7 | `critical` | `sys.tls.certificate_expiry` | the error style |
| past its end | `expired` | `sys.tls.certificate_expiry` | the error style, "expired on" |
| validity not begun | `not_yet_valid` | `sys.tls.certificate_expiry` | the error style; check the clock |

The server log carries one warning line each time the certificate moves into the next state. With `internal_ca` the warning is rare: Tenko renews 30 days before the end. With `imported` it means the renewal chain of section 5 did not deliver: check the ACME client first, then the node (`sys.tls.reload_failed`).

Other TLS warnings in the status: `sys.tls.no_certificate` (TLS is on and nothing is installed), `sys.tls.reload_failed` (the last load failed and the previous certificate stays in use) and `sys.tls.plain_http` (Lab).

## 4. A certificate replaced from outside

In mode `imported` the node reads the two files at start and, while it runs, looks at them every `watch_interval_secs`. Whether it then loads a changed certificate is a decision of the security profile, because the files can be written by something other than Tenko (your ACME client, a deployment tool, a person):

| Profile | `accept_external_replacement` unset | May be set |
|---|---|---|
| Lab | on | `false` turns it off |
| Home | on | `false` turns it off |
| Standard | off | `true` turns it on |
| Hardened | off | never: `true` is refused by `tenko config check` and at start when the file says Hardened, and ignored when the stored profile is Hardened |

The profile that counts is the one stored by first-run setup; `profile.name` of the file only decides before setup.

### 4.1 Accepted

A changed pair of files is parsed (certificate, chain and key must belong together) and installed for new connections without a restart; open connections keep the certificate they started with. An upload writes two files, one after the other. In the moment between them the node can see a new certificate with the old key: the load fails with `sys.tls.reload_failed`, the previous certificate stays in use and the next check loads the complete pair, which clears the warning. A failure that stays means the files do not belong together or are not PEM.

### 4.2 Not accepted

The node still checks the files, but it does not load what it finds. The certificate in use stays, and the change is reported as pending (section 4.3). The next start loads whatever is on disk, as every start does, and a start that cannot load the files stops with the reason.

### 4.3 Pending

A newer certificate that is on disk and not in use is reported in three places until a restart: `GET /system/tls` (`pending`, with the same facts as the certificate in use and the time it was first seen), the status warning `sys.tls.certificate_pending` and the Certificates page. Putting the old files back clears it. A pending certificate that fails to parse is reported as `sys.tls.reload_failed` instead.

Under Hardened this is the whole flow for a renewal: the upload lands, the warning says a newer certificate waits, the operator restarts the node in a maintenance window (`sudo systemctl restart tenko`). Start the restart on one node at a time in a cluster.

## 5. OPNsense ACME client to a node

The goal: OPNsense renews a certificate with its ACME client and the node serves the renewed certificate without anyone copying files. The automation "Upload certificate via SFTP" of the OPNsense ACME client does the transfer.

### 5.1 Who may do what

This is the rule the runbook is built on: no process that runs with more rights than the service account ever executes or loads a file that account, or a less trusted account, can write. A certificate is data. It is read, never executed, so a dedicated upload account that writes the certificate directory while the `tenko` account only reads it does not cross that line.

The account is created once, at installation time, with the rest of the installation. That is the last time root is used for it: neither renewals nor the node's own start need root afterwards.

| Path | Owner : group | Mode | Written by | Read by | Executed by |
|---|---|---|---|---|---|
| `/srv/tenko-certs` (the chroot) | `root : root` | `0755` | root, at installation | `sshd` (to enter the chroot), `tenko-cert` | nobody |
| `/srv/tenko-certs/certs` | `tenko-cert : tenko-certs` | `2750` (setgid) | root creates it; `tenko-cert` adds and replaces files in it | `tenko` (through the group), `tenko-cert` | nobody |
| `fullchain.pem` | `tenko-cert : tenko-certs` | `0640` | `tenko-cert` (the SFTP upload) | `tenko` | nobody |
| `privkey.pem` | `tenko-cert : tenko-certs` | `0640` | `tenko-cert` (the SFTP upload) | `tenko`, `tenko-cert` | nobody |
| `/etc/ssh/tenko-cert.authorized_keys` | `root : root` | `0644` | root, at installation | `sshd` | nobody |
| `Match User tenko-cert` in `sshd_config` | `root : root` | `0644` | root, at installation | `sshd` | `sshd` (as configuration) |
| `/etc/tenko/tenko.toml` | `root : tenko` | `0640` | root | `tenko` | nobody |

What follows from it:

- `tenko-cert` is in the group `tenko-certs` only, not in `tenko`, so it can read nothing of the node's configuration, key-encryption material or data. `tenko` is a member of `tenko-certs` and reads the directory through that group; it cannot write there (`2750`).
- `tenko-cert` has no shell and is chrooted by `sshd` to a directory that holds only the certificate directory. It can write nothing outside `certs`, start nothing and forward nothing.
- `sshd` runs as root, but loads only root-owned configuration and keys; `tenko-cert` writes none of it. Nothing in the upload directory is executed by anyone; if `/srv` is a filesystem of its own, mount it `noexec` and that is a rule of the system as well.
- The file mode that the client asks for does not matter: `certs` is `2750`, so other accounts cannot enter it whatever the files say.

What the upload account can do if it is taken over (for example if the OPNsense box is): replace the certificate and key the node serves with a pair of its choosing. For a name under a public CA that is as much as the ACME client could do anyway, since it holds the account that obtains certificates. That is the reason for the profile rule in section 4: on by default in Lab and Home, a deliberate opt-in in Standard, never in Hardened.

### 5.2 On the node, once, as root

The names are examples; `tenko-node-1.example.test` is the node and `tenko-cert` the upload account.

```sh
# The group that connects the two accounts, the upload account and the chroot.
groupadd --system tenko-certs
useradd --system --gid tenko-certs --home-dir /srv/tenko-certs --no-create-home \
        --shell /usr/sbin/nologin tenko-cert
usermod -aG tenko-certs tenko

# sshd needs the chroot to be owned by root and not writable by anyone else.
install -d -m 0755 -o root -g root /srv/tenko-certs
install -d -m 2750 -o tenko-cert -g tenko-certs /srv/tenko-certs/certs

# The public key of the OPNsense automation (section 5.4); one line.
install -m 0644 -o root -g root /dev/null /etc/ssh/tenko-cert.authorized_keys
```

Add this to `/etc/ssh/sshd_config` (or to a file it includes), then check and reload:

```
Match User tenko-cert
    ChrootDirectory /srv/tenko-certs
    ForceCommand internal-sftp -u 0027 -d /certs
    AuthorizedKeysFile /etc/ssh/tenko-cert.authorized_keys
    AuthenticationMethods publickey
    PasswordAuthentication no
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
```

```sh
sshd -t && systemctl reload ssh
```

The key file lives outside the home directory on purpose: `tenko-cert` owns nothing sshd reads before it chroots. If `sshd` says the account is locked, the account has the password marker `!`; set `usermod -p '*' tenko-cert` (a password nobody can type, not a locked account). Restart `tenko` once so that the service picks up its new group (`systemctl restart tenko`).

Point the node at the files in `/etc/tenko/tenko.toml`:

```toml
[tls]
mode = "imported"
cert_path = "/srv/tenko-certs/certs/fullchain.pem"
key_path = "/srv/tenko-certs/certs/privkey.pem"
# Standard only: accept_external_replacement = true
```

`tenko config check --config /etc/tenko/tenko.toml` checks the keys, including the profile rule. A start in mode `imported` stops when the files are missing or do not belong together, so upload the first certificate (section 5.4) before you change the mode, keep running on `internal_ca` until then, and switch with one restart.

### 5.3 The first start on an installation that already runs

If the node runs on `internal_ca`, nothing changes until the files exist: the upload of section 5.4 only creates them. Then set the mode, run `tenko config check` and restart once. Browsers then see the certificate of your public CA, which they trust already; the internal CA root is no longer needed by them (the cluster port keeps using it, [cluster.md](cluster.md)).

### 5.4 In OPNsense

The labels below are the ones of the ACME client plugin (**Services → ACME Client**); they differ a little between releases, so check them against the version you run.

1. **Certificates**: have the certificate for the node's host name issued (for example `ddi.example.test`) with auto renewal on. Challenge type and DNS provider are your choice and have nothing to do with Tenko.
2. **Automations → Add**: Run Command "Upload certificate via SFTP".
   - Host: the node, `tenko-node-1.example.test`, port 22.
   - Host key: what `ssh-keyscan -t ed25519 tenko-node-1.example.test` prints for the node (check it against the node's own `/etc/ssh/ssh_host_ed25519_key.pub`).
   - User: `tenko-cert`. Identity type: ed25519. Save the automation and open it again: the identity (a public key) is shown. Put that line in `/etc/ssh/tenko-cert.authorized_keys` on the node.
   - Remote path: `/certs` (inside the chroot).
   - Fullchain file name: `fullchain.pem`. Key file name: `privkey.pem`. Leave the certificate and CA file names empty, so that only these two files are written.
3. In the certificate, set this automation as the one that runs after every issue and renewal, and press **Issue/Renew** once to upload the first pair.
4. On the node: `ls -l /srv/tenko-certs/certs` shows both files owned by `tenko-cert`, group `tenko-certs`, mode `0640`, and `sudo -u tenko cat /srv/tenko-certs/certs/fullchain.pem > /dev/null` works.

One automation per node. A cluster has one upload account and one automation per controller, each with its own key.

### 5.5 What to expect

| Profile and setting | After a renewal |
|---|---|
| Lab, Home (default) | Within `watch_interval_secs` plus the upload the node serves the new certificate. The page shows the new fingerprint and "loaded". |
| Standard, `accept_external_replacement = true` | The same. |
| Standard (default), Hardened | The upload lands. The status carries `sys.tls.certificate_pending`, the page shows the newer certificate beside the one in use, and the one in use keeps running until `systemctl restart tenko`. |

Watch the days left. A renewal that does not arrive shows up as `sys.tls.certificate_expiry` 30 days before the end, which leaves time to look.

### 5.6 Restarting after an upload

Where the upload is not accepted, someone restarts the node. Do that by hand or from your change process. The OPNsense automation "Run remote command via SSH" can send a restart, but that is a root-capable action started by an outside event, and so the opposite of what Hardened means; if you do automate it under Standard, give it an account of its own that may run exactly `systemctl restart tenko.service` (a `sudoers` or polkit rule for that command and nothing else, with the key restricted by `command=` in `authorized_keys`), and never point it at a script in a directory that `tenko-cert` or `tenko` can write.

## 6. The internal CA's root

With `internal_ca` the node's certificate is signed by a CA that no browser knows. Admin computers need its root once.

1. **Get it.** Settings → Certificates has "Download the CA root certificate". Without a session: `https://<node>:8443/api/v1/system/ca-root` (public, PEM), `tenko ca-root --url https://<node>:8443 --fingerprint <sha256> -o ca-root.pem`, or `<data_dir>/tls/ca-root.pem` on the node.
2. **Check it.** The SHA-256 fingerprint is on the Certificates page, in the setup result and in the start log (`CA root at … (SHA-256 …)`). Compare it with the file before you trust it: `openssl x509 -in ca-root.pem -noout -fingerprint -sha256` prints it with colons.
3. **Install it** as a trusted root on the computers you administer from:

   | System | Command or place |
   |---|---|
   | Debian, Ubuntu | copy to `/usr/local/share/ca-certificates/tenko-ca-root.crt`, then `sudo update-ca-certificates` |
   | Windows | `certutil -addstore -f Root ca-root.pem` in an elevated prompt, or a Group Policy "Trusted Root Certification Authorities" for a domain |
   | macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca-root.pem` |
   | Firefox | Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import (Firefox keeps its own store) |
   | `tenko` commands | `--ca-file ca-root.pem` (or the saved sign-in) |

4. The root changes only when the CA is created again; the node's own certificate is renewed under it, so there is nothing to redistribute at a renewal. A clustered controller trusts the root through enrolment ([cluster.md](cluster.md)).

Install the root only on computers you administer from: a computer that trusts it trusts every certificate this CA signs. The CA's key is kept encrypted in the vault like the other secrets.

## 7. Reverse proxy

With `reverse_proxy` the certificate is the proxy's, issued and renewed there (for HAProxy with an ACME client, see the notes in [deploy/README.md](../deploy/README.md)). Tenko shows the proxies it trusts and the public host name on the Certificates page and nothing else about the certificate, because it never holds it. `tls.trusted_proxies` are the only sources that may connect and the only ones whose forwarded headers are believed.

## 8. Reference

| What | Where |
|---|---|
| `GET /api/v1/system/tls` | the facts of section 2; operation `get_tls` |
| `GET /api/v1/system/ca-root` | the CA root as PEM, public, `404 tls.no_internal_ca` in the other modes |
| `GET /api/v1/system/status` | `tls` (mode, certificate, days left) and the warnings below |
| `sys.tls.certificate_expiry` | the certificate in use has fewer than 30 days left, is expired or not yet valid |
| `sys.tls.certificate_pending` | a newer certificate is on disk and not in use; restart to apply it |
| `sys.tls.reload_failed` | the last load of the files failed; the previous certificate stays in use |
| `sys.tls.no_certificate` | TLS is on and no certificate is installed |
| `sys.tls.plain_http` | plain HTTP from every source (Lab) |
| `[tls] accept_external_replacement` | section 4 |
