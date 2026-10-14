# Operator secrets

This document describes how Tenko DDI stores, protects, reveals and uses the credentials that a person gives it: the password of a NAS, an API key for a controller, an SSH key, the login of a printer that an import brought along. It covers the model and its limits, who may do what, the audit records, the reveal and the clipboard path of the UI, the remote access hand-off, the way connectors and imports use the same secrets, the key-encryption key that protects them all (its providers, its distribution to the controllers of a cluster and its rotation), and the open items. It is for administrators who run Tenko, for people who write clients against the API, and for reviewers. Requirements are cited by ID and defined in [REQUIREMENTS.md](REQUIREMENTS.md) (IAM-07, IAM-15, IAM-16, API-11); the profile toggle TGL-24 and the never-off control NEVER-01 are defined in [SECURITY-PROFILES.md](SECURITY-PROFILES.md). The vault itself is described in [ARCHITECTURE.md](ARCHITECTURE.md#secrets-and-the-vault), the connector side in [plugins.md](plugins.md#7-secrets), and the endpoints in the [OpenAPI document](api/openapi.json). Where this document and the code disagree, the code is right and the document has a defect.

Terms used below: a **secret** is an operator secret. A **reveal** is the one operation that returns a stored value to a person. A **binding** attaches a secret to a host as a credential. A **step-up** is a new sign-in that a request asks for because the current session is too weak or too old.

Contents:

1. [The model](#1-the-model)
2. [Policy](#2-policy)
3. [Audit records](#3-audit-records)
4. [The reveal and the clipboard](#4-the-reveal-and-the-clipboard)
5. [Remote access hand-off](#5-remote-access-hand-off)
6. [Connectors and imports](#6-connectors-and-imports)
7. [Writes](#7-writes)
8. [The key-encryption key](#8-the-key-encryption-key)
9. [Open items](#9-open-items)

## 1. The model

The vault knows two classes of secret.

| Class | Examples | Revealable | Counts for the PIN rule |
|---|---|---|---|
| `system` | TOTP seeds, the keys of the internal CA and of TLS | Never | No |
| `operator` | Credentials a person stores: host logins, API keys, SSH keys, tokens, connector credentials, imported logins | Yes, with an audit record | Yes |

An operator secret is a vault secret of class `operator` plus a metadata record. The vault side follows IAM-15: every write draws a fresh 256-bit data key (DEK), encrypts the value with AES-256-GCM and wraps the DEK with the active key-encryption key (KEK). The KEK comes from the operating system's key store (DPAPI on Windows, `systemd-creds` with TPM2 where available on Linux, an explicit key file for containers and CI), and the server does not start without it. The envelope is stored in `vault.secrets`, a table that accepts nothing but envelopes, so the Raft log, snapshots and backups hold ciphertext only (NEVER-01, which no profile switches off). Replacing a value draws a new DEK. In memory the plaintext lives in buffers that are wiped when they are dropped.

### The metadata record

| Field | Meaning |
|---|---|
| `name` | What people see. Not unique. |
| `kind` | `password`, `api_key`, `ssh_key`, `token` or `other`. |
| `tags` | Purpose tags such as `unifi` or `api_key`. Lower case, sorted. They say what a secret is meant for; a connector form uses them to offer matching secrets (section 6). |
| `username` | The user name that goes with the secret. Not secret: the remote hand-off writes it into `.rdp` files and `ssh://` links. |
| `notes` | Free text. Not secret: never put a value here. |
| `origin` | `manual` (created by a person) or `import` (stored by an import). |
| `format` | How the stored value is laid out: `plain` (the value as UTF-8 text) or `login_password` (a JSON object with a login and a password, written by imports). Internal; API answers do not show it. |
| Times | `created_at`, `updated_at` (record or value changed) and `value_updated_at` (the value was last written). |
| `last_revealed` | When, by whom (id and login name at the time) and for which host the secret was revealed last. Never the reason or the value. |
| `hosts` | The hosts the secret is bound to, with the role. |

### Tables

| Table | Key | Holds |
|---|---|---|
| `vault.secrets` | secret | The envelope. Secret-bearing. |
| `vault.secret_meta` | secret | The vault's own non-secret metadata: class, purpose, owning object, label, times. |
| `vault.operator_index` | secret | One row per operator secret, so that "does the vault hold one" is a one-row scan. |
| `vault.operator_meta` | secret | The metadata record above. |
| `vault.reveals` | secret | The stamp of the last reveal. |
| `vault.host_bindings` | host, secret | The role and the time of a binding. |
| `vault.secret_hosts` | secret, host | The reverse index of the bindings. |
| `vault.reveal_log` | person, sequence | One row per reveal: when and which secret. The rate limit counts them (section 2). |

The name `vault.reveals` predates the cluster-wide rate limit and keeps its meaning (the last reveal of each secret); the reveals the limit counts have their own table, `vault.reveal_log`.

Three counters belong to the model. The counter of a host (`vault.host_credentials`) versions its set of bindings and is the `ETag` of `GET /hosts/{id}/credentials`. The counter of a secret (`vault.secret_bindings`) moves with every binding change and guards deletion: a delete commits only if nobody bound the secret in the meantime. The counter of a person (`vault.reveal_count`) numbers their reveals and makes the rate limit strict (section 2).

### Host bindings and roles

A secret may be bound to any number of hosts, and a host has up to 32 credentials. Each binding carries a role: `admin` (the administrative login of the device), `rdp`, `ssh`, `web` or `other`. A secret has one role on a host. The remote hand-off takes the user name of the `rdp` or `ssh` credential and falls back to the `admin` one (section 5). A secret that a host binds or a connector references cannot be deleted: the answer is 409 `vault.secret.in_use` with the counts, and `GET /secrets/{id}/references` lists the hosts and connector instances.

### Why system secrets are never revealable

Tenko uses system secrets itself and no person needs their value; a reveal route would turn one stolen operator session into the CA key or somebody's TOTP seed. Three layers enforce it. The secrets endpoints treat a system secret as absent (404 `vault.secret.not_found`). The vault refuses to reveal one (403 `vault.secret.not_revealable`) and records the refusal. The class is part of the authenticated data of the envelope, so an envelope relabelled from `system` to `operator` fails authentication. Connectors get operator secrets only (`connect.secret.not_operator`).

### What never contains a value

| Place | How the value stays out |
|---|---|
| Lists and views | `GET /secrets`, `GET /secrets/{id}`, the references and the credentials of a host return the record, never the value or its layout. |
| Audit records | Built from names, kinds, codes, roles and ids. A changed note is recorded as a changed field without its text. The reason of a reveal is the one free-text member, and it is what the person typed, so a reason should not contain a value. |
| Logs | The `Debug` output of every type that holds a value prints a length (`<14 bytes redacted>`) at most. The rate limit logs the secret id and the principal. Error answers never repeat the request body. |
| Events | The `secrets` topic of `GET /events` carries references to the changed objects (from `vault.operator_meta`, `vault.reveals` and `vault.host_bindings`), not bodies. The envelope tables map to no topic. |
| Errors | The messages and parameters of the model's errors name fields, ids and counts. |
| Job records | Edits are not jobs (section 7). |
| Idempotency records | A keyed request leaves a fingerprint, and a response that holds a value leaves a marker only (section 4). |

### Limits

| Item | Limit |
|---|---|
| Name | 1 to 128 characters after trimming; no control characters. |
| User name | At most 256 characters; no control characters; an empty one means none. |
| Notes | At most 2,000 characters; line breaks and tabs are the only control characters; blank means none. |
| Purpose tag | 1 to 64 characters of `a-z`, `0-9`, `.`, `_` and `-`; upper case is folded to lower case. |
| Tags per secret | 16, stored sorted without duplicates. |
| Value | 1 byte to 64 KiB (65,536 bytes), sent as text. An empty value is 422 `vault.secret.invalid` with the parameter `field` set to `value`; a larger one is 413 `vault.secret.too_large`. |
| Reveal reason | At most 200 visible characters. |
| Credentials per host | 32, one binding per secret. |
| Reveals | 10 per person per minute (section 2). |
| Clipboard | Cleared 30 seconds after a reveal (`clear_after_secs`, section 4). |

## 2. Policy

### Who may do what

| Operation | Endpoint | Viewer | Operator | Administrator |
|---|---|---|---|---|
| List secrets (metadata) | `GET /secrets` | Empty list | Yes | Yes |
| Show a secret, its references | `GET /secrets/{id}`, `GET /secrets/{id}/references` | 403 | Yes | Yes |
| Create | `POST /secrets` | 403 | 403 | Yes |
| Change metadata or value | `PATCH /secrets/{id}` | 403 | 403 | Yes |
| Delete | `DELETE /secrets/{id}` | 403 | 403 | Yes, unless referenced |
| Reveal | `POST /secrets/{id}/reveal` | 403 | Under TGL-24 | Under TGL-24 |
| Read the credentials of a host | `GET /hosts/{id}/credentials` | 403 | Yes | Yes |
| Bind and unbind credentials | `PUT /hosts/{id}/credentials` | 403 | 403 | Yes |
| Remote hand-off | `GET /hosts/{id}/remote` | Yes, without a bound user name | Yes | Yes |
| Reference a secret from a connector | `POST`, `PATCH /connectors` | No | No | Yes |

Creating a secret needs the right to reveal as well as the right to create, which is what ties the PIN rule to it. A reference from a connector needs the right to reveal and to update the secret (section 6).

**Personal API tokens never reveal.** A token may read the metadata its owner may read, but creating, changing, deleting, binding and revealing need an interactive session. A token that tries gets 403 `auth.forbidden`, and a reveal attempt is recorded.

### The PIN coupling rule

IAM-07 and CON-07 say that a PIN may be the only factor of an account only while the vault holds no secrets that an account can reach. For operator secrets the rule works in four places. System secrets do not count (they would end PIN-only sign-in at the first TOTP enrolment).

- **A PIN session never reveals.** Revealing needs a session of at least password strength in every profile, and the answer to a weaker one is 403 `auth.step_up_required` with `required` set to `password`.
- **Once the vault holds an operator secret**, an account that may reveal (an administrator or an operator) needs at least password strength for every action, not only for secrets.
- **`POST /secrets` is refused with 409 `vault.pin_coupling`** while an enabled account that may reveal signs in with a PIN alone, meaning a PIN-kind password and neither TOTP nor a passkey or security key. The parameter `accounts` lists their login names, comma separated. Disabled accounts and the break-glass account (hardware key only, IAM-09) are not counted. The administrator gives those accounts a stronger factor or another role first.
- **`PATCH /settings/security` is refused with 409 `settings.pin_coupling`** when it would let a PIN stand alone while the vault holds an operator secret: the change touches the password policy (TGL-01) or the MFA requirement (TGL-02), and the result is a PIN-admitting password preset with MFA optional. Every other change passes, also under the Home and Lab defaults, whose settings already admit a PIN with MFA optional: a change of the reveal policy, the lockout or the session lifetime does not weaken the PIN rule.

### The reveal policy (TGL-24)

On top of the role and the PIN rule, the profile decides how fresh and how strong a session must be. The setting is `secret_reveal`, shown with its profile default under `/settings/security`; a change is audited with the old and the new value.

| Profile | `step_up` | `bound_host_only` | A reveal needs |
|---|---|---|---|
| Home | `session` | No | A signed-in session of password strength or stronger. |
| Standard | `fresh` | No | A sign-in within the last five minutes, by any method. |
| Hardened | `passkey` | Yes | A sign-in with a passkey or a hardware security key within the last five minutes. The request names a host that the secret is bound to. |
| Lab | `session` | No | As Home. |

Five minutes are counted from the sign-in that created the session, not from the last request. No value is weaker than Home, so the toggle never raises the warning banner.

A refused step-up is 403 `auth.step_up_required`, and the parameter `required` says what to do:

| `required` | Raised by | The client must |
|---|---|---|
| `password` | The PIN rule | Sign in with a password or a stronger method. |
| `fresh` | `step_up` is `fresh` and the session is older than five minutes | Sign in again, with any method. |
| `passkey` | `step_up` is `passkey`, or TGL-03 for an administrator | Sign in with a passkey or a hardware security key. |
| `password_totp` | TGL-02 asks the account for a second factor | Sign in with a password and a TOTP code, or with a passkey or a hardware security key. |

**The host binding of Hardened.** When `bound_host_only` is set, a reveal that names no host is refused with 403 `vault.reveal.host_required`. In every profile a reveal that names a host is refused with 403 `vault.reveal.not_bound` when the secret is not bound to that host. In Hardened a secret can therefore be revealed from the view of a host it is bound to, and never from the secrets page, where no host is in view.

### The rate limit

One person may reveal 10 times in any 60 seconds; the eleventh answers 429 `vault.reveal.rate_limited` with `Retry-After`. The limit belongs to the person, so all their sessions and tokens share it, and it holds across every controller of a cluster: each reveal first reserves a row in the replicated table `vault.reveal_log`, in a write that expects the person's counter `vault.reveal_count` to be unchanged, so two controllers that reserve at the same moment cannot both take the last slot (the loser reads again). The reservation carries no audit record of its own; the reveal that follows is audited. Expired rows are deleted by the person's next reservation. Only reveals that passed the role, the policy and the host checks count, so a refused reveal does not use up the allowance. The window is measured with the clock of the controller that serves the request, so clock skew between controllers shifts it by the skew (R35).

## 3. Audit records

Every record carries the principal, the time, the source address of a request that came over the network, and its place in the hash chain (IAM-18). Values never appear.

| Action | Written when | Outcome | Objects | Details |
|---|---|---|---|---|
| `vault.secret.create` | `POST /secrets` | success | The secret | `name`, `kind`, `class` (`operator`), `purpose` (`vault.operator`), `kek` (the active KEK). |
| `vault.secret.update` | `PATCH` changed the metadata | success | The secret | `name` (the new one) and one change per changed field: `name`, `kind`, `tags` and `username` with old and new text, `notes` without text. Not written when nothing changed. |
| `vault.secret.replace` | `PATCH` carried a `value` | success | The secret | `class`, `kek`. |
| `vault.secret.delete` | `DELETE` | success | The secret | `name`. |
| `vault.secret.reveal` | A reveal returned the value | success | The secret and the host, if named | `class` (`operator`), `kind`, `name`, `host`, `reason`. |
| `vault.secret.reveal` | A reveal was refused | denied | The secret and the host, if named | `code` of the refusal (`auth.forbidden`, `auth.step_up_required`, `vault.reveal.host_required`, `vault.reveal.not_bound`, `vault.secret.not_found`, `vault.secret.invalid` for a bad reason), `host`, `reason`. A system secret refused by the vault carries `class` (`system`). |
| `vault.secret.reveal` | The vault failed before or while committing | failed, with the error code | The secret and the host, if named | `kind`, `name`, `host`, `reason`. |
| `vault.host.credentials` | `PUT /hosts/{id}/credentials` changed the set | success | The host and every secret bound, unbound or changed | One change per secret on the field `role`: old empty for a new binding, new empty for an unbound one. Not written when the set is unchanged. |
| `vault.secret.adopt` | Server start found secrets without a record (section 6) | success | The adopted secrets | `count`. |
| `connect.secret.inject` | A connector call carries secrets (section 6) | success | The connector instance and the secrets | `plugin`, `purposes`, `call`. The principal is `system:connector`. |

Key rotation and the key-encryption key write their own records (section 8):

| Action | Written when | Details |
|---|---|---|
| `vault.secret.rotate_dek` | A secret was re-encrypted under a fresh data key | `class`, `kek`. |
| `vault.kek.rotate_request` | `POST /system/kek/rotate` | `kek` (the active one), `epoch`. |
| `vault.kek.activate` | A new generation became active: an online rotation after the distribution, or a key the configuration introduced on a single controller | `kek`, `epoch`, `cause` (`rotation`, `configuration`), `unreachable` (members that fetch it at their next start). |
| `vault.kek.rotate` | A rotation finished, online or with `tenko kek rotate` | `kek`, `retired`, `rewrapped`, `epoch`, `online` for an online rotation. |
| `vault.kek.rotate_failed` | An online rotation failed | `error`. |
| `vault.kek.downgrade` | A start found a weaker protection or refused a plain generation (R15) | Objects: the node. `cause` (`provider`, `plain_generation`), `from`, `to`, `strongest`, `generation`, `file`. |
| `vault.kek.transfer` | A controller received the generations (join or fetch) | Written by the cluster service: `generations` (identifiers), `node`, `enrolment` or `purpose` (`fetch`). Never the material. |

**The order guarantee.** The value is returned only after the audit record of the reveal has committed. The record and the last-revealed stamp go into one store write; only when that write returns does the vault hand the decrypted bytes on. If the write fails, for example without a quorum, the person gets the error and no value, and the vault tries to record a failed reveal. The reveal never takes the request's idempotency key, so a replay cannot return a value without a new record. A connector injection follows the same rule: its record is written before the secrets are resolved, and a call whose record cannot be written fails with 503 `connect.audit_unavailable` and injects nothing.

The log can err in one direction only. A reveal cannot happen unrecorded, but a record can exist for a reveal whose answer was lost on the way, or whose value could not be read as text (422 `vault.secret.not_text`, which is decided after the commit). Refusals are recorded on a best-effort basis, because the person gets the refusal in any case. A reveal refused by the rate limit is not recorded; the node logs a warning with the secret id and the principal.

## 4. The reveal and the clipboard

### What the API returns

`POST /secrets/{id}/reveal` takes an optional JSON body, `{"host": "<host id>", "reason": "text"}`, and an empty body is allowed. The answer is 200 with `Cache-Control: no-store`:

```json
{
  "id": "3f1c2c3e-1c7a-4f64-9a43-0d6c3b1f0a11",
  "value": "example-password-not-real",
  "username": "admin",
  "kind": "password",
  "revealed_at": "2026-10-10T08:15:00Z",
  "clear_after_secs": 30
}
```

`username` is the user name of the record, or the login of an imported value. `clear_after_secs` is the time after which a client should clear the clipboard.

| Status | Code | When |
|---|---|---|
| 401 | `auth.unauthenticated` | No valid session. |
| 403 | `auth.forbidden` | The role may not reveal, or the caller is a personal token. |
| 403 | `auth.step_up_required` | The session is too weak or too old (section 2); the parameter `required` says what to do. |
| 403 | `vault.reveal.host_required`, `vault.reveal.not_bound` | The host rules of section 2. |
| 404 | `vault.secret.not_found` | No such operator secret, system secrets included. |
| 422 | `vault.secret.invalid` | The reason is longer than 200 characters or has control characters. |
| 422 | `vault.secret.not_text` | The stored value cannot be read as text. The reveal record exists. |
| 429 | `vault.reveal.rate_limited` | More than 10 reveals in a minute; `Retry-After` gives the seconds. |

### Retries and the Idempotency-Key

A reveal is never replayed. The middleware that implements `Idempotency-Key` keeps the response of a keyed `POST` for 24 hours by default, except that a response with `Cache-Control: no-store` leaves only a bodiless marker. A retry with the same key and the same request therefore gets 409 `sys.idempotency_not_replayable`; the handler does not run a second time, so there is no second value and no second record. The same key with another request is 422 `sys.idempotency_mismatch`. A client that lost a reveal answer asks again with a new key and gets a new record in the log.

### The reveal dialog

The UI reveals from the secrets page (Settings, Secrets, at `/settings/secrets`; the former `/secrets` address redirects there) and, next to a credential of a host, from the host view ("Copy password"). Both use one dialog, which sends the host in view when there is one and a reason when its caller supplies one.

1. Opening the dialog is the request: the reveal starts at once, and the dialog says that it is writing the audit record.
2. If the API answers 403 `auth.step_up_required`, the dialog asks for the step-up in place. For `required` = `passkey` it offers a passkey or security key only. Otherwise it asks for the password of the signed-in account, a TOTP code when the server asks for a second factor, or a passkey. The new sign-in creates a new session, which is what makes it fresh; the previous session ends, and the dialog repeats the reveal.
3. It copies the value to the clipboard and schedules a clearing after `clear_after_secs` (30 seconds). When the time is up, the page reads the clipboard; if it still holds the value, the page replaces it with an empty text, and if it holds something else, the page leaves it alone. When the browser does not let the page read the clipboard, the page clears it regardless, because a password left behind is worse than a lost clipboard entry. If the browser refuses the write in the first place, nothing is copied: the dialog says so and offers "Copy" for another try.
4. The dialog shows a countdown. It never renders the value unless the person presses "Show value", and it shows the user name and the line "This reveal is in the audit log as (login name), (time)".
5. When the clipboard has been cleared, or left alone because it holds something else, the dialog says which and drops the value. If the browser did not allow the clearing, the dialog says so; copying anything else removes the value.
6. When the dialog closes, it drops the value. The timer belongs to the page, not to the dialog, so closing the dialog early does not keep the value on the clipboard. A later reveal replaces a pending clearing.

### What the clipboard path does not protect

- **Other applications.** While the value is on the clipboard, any program on the machine can read it. Clipboard managers and history features record it, and clearing the clipboard does not remove their copy. A synced clipboard, or a remote session that redirects the clipboard, carries the value to other devices.
- **A page that is gone.** If the tab is closed, the browser quits or the computer sleeps before the timer runs out, nothing clears the clipboard.
- **The browser's memory.** The value is a JavaScript string between the answer and the dialog's end. It cannot be wiped and may stay in memory until the engine collects it, in a crash report or in a memory dump.
- **The screen.** After "Show", screen capture, screen sharing and onlookers see the value.
- **The person who revealed it.** A value that was pasted into a ticket, a chat or a shell history is outside Tenko's reach.

The control for all of these is the audit record: who revealed which secret, for which host, when and why. After a suspected exposure, replace the value (`PATCH /secrets/{id}` with a `value`), which draws a new DEK and writes `vault.secret.replace`.

## 5. Remote access hand-off

`GET /hosts/{id}/remote` (API-11) builds what the operating system needs to open a Remote Desktop or SSH session, without a secret. It needs only the right to read the host.

| Query | Meaning |
|---|---|
| `protocol` | Required: `rdp` or `ssh`. |
| `address` | An IP address of the host, or the DNS name of one of its addresses (compared ignoring case and a trailing dot), used as given. It must belong to a live address of the host (or of the chosen interface), else 422 `remote.address_unknown`. The host page sends the DNS name of an address when it has one. |
| `interface` | One interface of the host. Narrows the target; 422 `remote.interface_unknown` if it is not a live interface of the host. |
| `port` | 1 to 65535. Default 3389 for RDP, 22 for SSH. |
| `user` | A user name, at most 256 characters, no control characters. |

**Target.** Without `address`, the target is the live address of the host or interface that sorts first, IPv4 before IPv6, by its DNS name when it has one and otherwise as an IP address. A host without a live address gets its host name.

**User name.** The `user` parameter wins. Otherwise the endpoint takes the user name of the credential bound to the host with the role `rdp` (for RDP) or `ssh` (for SSH), then of the `admin` one. A caller that may not read secrets, such as a viewer, never learns a bound user name.

**RDP** answers 200 with `application/x-rdp` as an attachment named after the host (`nas01.example.com.rdp`), with CRLF line ends:

```text
full address:s:192.0.2.10:3389
username:s:admin
prompt for credentials:i:1
administrative session:i:0
screen mode id:i:2
authentication level:i:2
```

An IPv6 address is written in brackets (`[2001:db8::10]:3389`), and control characters are removed from every value so that none can start another setting. The `username` line is left out when no user name is known.

**SSH** answers 200 with JSON: `uri`, `host`, `port` and `username`. The URI is `ssh://[user@]host[:port]`, with the user percent-encoded and the port left out when it is 22, for example `ssh://admin@nas01.example.com` or `ssh://admin@192.0.2.10:2222`.

**Why no secret travels in them.** An `.rdp` file lands in a downloads folder and a backup, and an `ssh://` link is handed to a handler and may reach a log or a process list. The `.rdp` file asks for the password when it opens (`prompt for credentials:i:1`). The password reaches the clipboard only through the audited reveal: "copy password" in the host view lists the credentials of the host from `GET /hosts/{id}/credentials` (metadata only) and calls `POST /secrets/{id}/reveal` with that host in the body. Naming the host satisfies the host binding of Hardened and puts the host into the audit record. The host view (`ui/src/hosts/Connect.tsx`) builds neither the file nor the link. It calls this endpoint with `address` (the DNS name of the address when it has one), with `port` when it is not the default and with `user` when one is typed; the server fills in what it leaves out, as described above. For RDP it saves the returned text as a download named after the host; for SSH it opens the returned `uri`. It remembers the ports and the user name per host in the browser's local storage. `ui/src/hosts/handoff.ts` holds the same two builders for the mock API of the development server and the component tests; the server's text is identical to it byte for byte.

## 6. Connectors and imports

### Connectors

A connector instance does not hold secrets in its settings (the manifest refuses a settings property that looks like one). It references operator secrets by purpose: a map from a purpose that the plugin's manifest declares (for example `api_key`) to a secret. The API validates the references: only declared purposes, every required purpose present, and every reference an existing operator secret (`connect.secret.undeclared`, `connect.secret.missing`, `connect.secret.not_found`, `connect.secret.not_operator`).

Purpose tags help the connector form: it offers the secrets whose tags include the purpose the plugin needs. A tag is a hint and not a rule; any operator secret may be referenced.

**Setting a reference needs the right to reveal and to update the secret.** A reference lets a plugin use the secret against whatever target the settings name, which would otherwise get around the reveal policy: the person never sees the value, but a plugin of their choice receives it. Operators may reveal under TGL-24 but not update, so an operator can manage connectors without secrets, and a secret-bearing connector needs an administrator. Changing the settings of an instance that already holds references re-checks the right on every referenced secret, because new settings can redirect them.

**Injection.** For each call that needs secrets, the connector host writes the audit record `connect.secret.inject`, then resolves the references from the vault into the call's context, and the context wipes them when the call ends. A purpose the manifest does not declare is never injected. An injection is not a reveal: no person sees the value, so TGL-24 and the rate limit do not apply. The gates are the right to set the reference and the audit record.

### Imports

Credential columns of an import (login, password) are never IPAM fields. Each host's login and password become one operator secret:

| Part | Value |
|---|---|
| Value | A JSON object with `login` and `password` (format `login_password`). |
| Record | Name `Login of <host>`, kind `password`, origin `import`, user name set to the login. |
| Vault metadata | Purpose `import.host_credential`, owned by the host. |
| Binding | To the host with the role `admin`. |

A reveal of such a secret returns the password as `value` and the login as `username`; a user name that a person edited on the record wins over the login. Replacing the value by hand turns the secret into a plain one.

Applying an import with credential columns is refused with 403 `import.credentials.vault_required` unless the server has a vault and the importing account passes both create and reveal on secrets, which in practice is an administrator with a session of password strength or stronger. The parameter `reason` is `vault_unavailable`, `step_up_required`, `forbidden`, `unauthenticated` or `pin_coupling`, and `required` names the weakest strength for a step-up. `pin_coupling`, with `accounts` naming the enabled accounts that may reveal but sign in with a PIN alone, is the rule of `POST /secrets` (section 2); it is checked after the importing account's own check, at the preview and at the apply alike. Setting `options.credentials` to `skip` in the mapping leaves the credential columns out and applies the rest.

A re-import with an unchanged credential writes nothing. With a changed one it stores a new secret and binds it in place of the old binding; the final job step `import.finish` then deletes the replaced secret, unless a person has bound it to another host or a connector instance references it in the meantime. If a chunk of the import fails, the compensation deletes the new secrets and binds the old ones again.

### Secrets stored before this model

At every start the server adopts operator secrets that have no record, such as credentials imported by earlier builds. Each gets a record derived from the vault metadata (the name from the vault label, else `Secret <purpose>`; kind `password`; origin `import` and format `login_password` for the import purpose, else `manual` and `plain`) and, when the metadata names a host as owner, an `admin` binding to it. One `vault.secret.adopt` record is written per batch of up to 256 secrets. Running it again is harmless, also on several nodes. Until a secret is adopted it is still listed with its derived record, but it has no revision and so no `ETag`.

## 7. Writes

**One write per edit.** A create, a change, a delete or a change of bindings is one store write: the envelope, the vault metadata, the record, the bindings, the counters and the audit records commit together or not at all. The write is proposed directly, as user and settings administration is, and not as an inline job. An inline job keeps its write in the job record, which would keep a copy of an envelope after the secret was deleted. Because of this no envelope lands in a job record, and the audit log is the history of changes.

**Concurrency.** `PATCH` and `DELETE` on a secret take `If-Match` with the revision of the metadata, as `GET /secrets/{id}` returns it in `ETag`. `PUT /hosts/{id}/credentials` takes the `version` of the host's set of bindings, as `GET /hosts/{id}/credentials` returns it. A stale value is 409 `vault.secret.conflict` or `vault.host_credentials.conflict`. An absent header or `*` means no precondition. A delete also fails with `vault.secret.conflict` when a binding appeared between the check and the write. A `PATCH` that changes nothing returns the current secret without a write or a record. A `PUT` of the same set does the same.

**The Idempotency-Key.** The UI sends no `Idempotency-Key` with `POST /secrets`, although its client adds one to every other `POST`. For a keyed request the middleware stores a SHA-256 fingerprint of the method, path, content type and body, to recognise a retry, and the store table that holds it is replicated, snapshotted and backed up like any other. A body that holds a value should not leave even a hash behind, because the hash of a short password can be tested offline. The cost is that a create whose answer was lost, when retried, shows up as a second secret with the same name; the person sees it and deletes one. Clients of the API should do the same. The middleware handles `POST` only, so `PATCH` with a new value is not affected. The store's own deduplication is off for these writes: a new envelope holds random keys and nonces and never repeats.

## 8. The key-encryption key

The KEK wraps the data key of every secret (section 1). It is the one key whose loss makes every secret unreadable and whose theft makes every secret readable, so it is never stored in the store, a snapshot, a log line, an audit record or an error, and the server does not start without it. This section covers the providers that protect it at rest, its generations, the refusal of unprotected generations (R15), how the controllers of a cluster share it (S3-Q5, R22), rotation, and the status an administrator sees. The design is recorded in ADR 0014.

### Providers

The provider is chosen per host in `[kek]` of `tenko.toml`; it is a property of the host, not of the installation, so the controllers of one cluster may use different providers.

| `provider` | Platform | The KEK at rest | Protection reported |
|---|---|---|---|
| `platform` (default) | Windows, Linux | `dpapi` on Windows, `systemd_creds` on Linux | as below |
| `dpapi` | Windows | Generation files in `kek.dir` (default `<data_dir>/kek`) sealed with DPAPI for the service account (`scope = "user"`, default) or the machine (`"machine"`); the file name is bound into the seal | `dpapi_user`, `dpapi_machine` |
| `systemd_creds` | Linux | Generation files in `kek.dir`, sealed by running `systemd-creds encrypt` as the service account (TPM2 and host key with `with_key = "auto"` when a TPM2 is usable). Where the tool cannot seal for the account, new generations are plain files with mode 0600 and a loud warning | `systemd_creds_tpm2`, `systemd_creds_host`, `plain_file` |
| `systemd_credential` | Linux | The credential `credential` (default `tenko_kek`) that the unit passes with `LoadCredentialEncrypted=tenko_kek:/etc/tenko/kek.cred`: the service manager decrypts it with the host key (and the TPM2, when it was encrypted for one) into `$CREDENTIALS_DIRECTORY`, readable by the service account only. Later generations live in `kek.dir`, wrapped under the credential | `systemd_creds_host`; `systemd_creds_tpm2` when `with_key = "tpm2"` declares how the credential was encrypted (Tenko cannot see it) |
| `file` | any | An explicit key file `path` (32 raw bytes, 64 hexadecimal digits or base64), for containers with a mounted secret and for CI; earlier key files in `retired`. Later generations live in `kek.dir`, wrapped under the key file. Every start logs "THE KEY-ENCRYPTION KEY IS A PLAIN FILE" | `plain_file` |

The identifier of a key file or a credential is `file-` and eight hexadecimal digits of the key's SHA-256, so an installation that passed the credential to the `file` provider (the unit of Slice 2) switches to `systemd_credential` without re-wrapping anything. Generation identifiers are `<sealer>-<number>-<8 random hexadecimal digits>` (`dpapi-2-3f9a0c2e`, `cred-1-…`, `wrap-1-…`, `plain-1-…`).

A wrapped generation (`kek-NNNNNN.wrap`) is the generation file encrypted with AES-256-GCM under the root key (the key file or the credential), with the file name bound into the additional data. It has the protection of its root: whoever cannot read the root key cannot read it. The `file` and `systemd_credential` providers need it because the service account cannot seal anything with the host's own key store.

### Generations and the KEK state

A host holds numbered generations. The generation that wraps new data keys is the **active** one; the others stay loaded so that envelopes they wrapped still open, until a rotation has re-wrapped them. Which generation is active is not decided by the host but by the installation's KEK state in the store, which every controller reads:

| Table | Key | Holds |
|---|---|---|
| `vault.kek_state` | `()` | The active generation, the generations envelopes may still name (identifiers and times, never material; once a rotation has re-wrapped everything, only the active one), the KEK epoch, the generation of an online rotation that is being distributed, the generations of failed rotations, and the rotation in progress or the last one |
| `vault.kek_acks` | generation, node | A controller holds the generation of an online rotation |
| `vault.kek_protection` | node | The protection of the controller's active KEK at its last start, and the strongest protection it ever had |
| `vault.alarms` | alarm key | The alarms of this section (`vault.kek.downgrade`), routed to the `system` event topic |

The counter `vault.kek_epoch` moves in the same write that changes the active generation. Every write that carries a new envelope expects the epoch its KEK belongs to, so an envelope wrapped by the previous KEK cannot commit once a rotation has activated the next one; the vault then switches to the active generation and writes again. The vault records the state at its first start after this change; a store from before it has none, and the host's newest generation is active.

On a single controller a key that the configuration introduces (a new key file with the old one under `retired`) becomes active at the next start, with a new epoch, as before. In a cluster such a key is not used: the controller warns and keeps the installation's active generation, and the administrator rotates online.

### Plain generations and downgrades (R15)

Anyone who can write the key directory could drop a plain generation numbered above the sealed ones; it would become active and every new secret would be protected by a file. Three rules close that hole.

- **Refusal.** A plain generation newer than the newest sealed generation of its directory is not loaded. The start goes on with the sealed generations, logs an error naming the file, and the vault raises the alarm `vault.kek.downgrade` (cause `plain_generation`, the generation number and the file name) with an audit record of the same name. A plain generation older than a sealed one still loads, because envelopes may need it until a rotation has finished; the log says to remove it. A provider never creates or imports a plain generation beside a sealed one either (409 `vault.kek.plain_refused`).
- **`[kek] allow_plain = true`** lifts the refusal for a host where it is intended (a container that lost its TPM, for example). Every start that uses it logs a loud warning. Off by default in every profile.
- **The downgrade alarm.** Every start records the protection of the active KEK in `vault.kek_protection`. A start whose protection is weaker than the strongest this controller ever had raises `vault.kek.downgrade` (cause `provider`, parameters `from` and `to`) once, when it becomes weaker, with an audit record. The status shows the warning for as long as the protection stays weaker. The ranking is: memory, a plain file, then DPAPI in machine scope and `systemd-creds` with the host key, then DPAPI in user scope and `systemd-creds` with a TPM2.

The rules apply per controller. A cluster whose members use different providers is legitimate; the status lists the protection of every controller.

### Controllers of a cluster

An installation has one set of generations (S3-Q5): every controller holds every generation, each sealed with its own provider, under the same identifiers, so every controller opens every envelope. The material moves between controllers in exactly two cases, both over the cluster port (mutual TLS 1.3 between enrolled controllers):

- **Join.** `tenko cluster join` enrols the host as a controller (the enrolment token needs an administrator with a sign-in within the last five minutes), then asks a member for the generations with `Cluster.TransferKek`, sending the public half of a one-time X25519 key that only the joining host holds. The member seals every generation to it (X25519, HKDF-SHA-256, AES-256-GCM, bound to the joining node and its enrolment token) and records `vault.kek.transfer` with the generation identifiers, the node and the enrolment, never the material. A second transfer for the same token is refused. The joiner seals the generations with its own provider and drops the one-time key.
- **Fetch.** A controller that lacks a generation the state lists (it was stopped during an online rotation, or it follows a rotation now) asks a member the same way with an empty token; the transfer is bound to the asking node. At start this happens in the `cluster` step, before the vault opens; a controller that cannot reach any member while it lacks the active generation does not start (`vault.kek.unavailable`).

The format of the sealed transfer is documented in the code (`tenko_vault::transfer`) and has a fuzz target (`kek_transfer`).

### Rotation

**Online, on a cluster or a single controller.** `POST /system/kek/rotate` (administrator, with a sign-in within the last five minutes) records the request in the KEK state and answers 202; a second request while one runs is 409 `vault.kek.rotation_in_progress`. The leader carries it out in phases, which `GET /system/kek` shows:

1. `requested`: the leader creates the next generation with its own provider.
2. `distributing`: every running controller fetches the new generation, seals it and acknowledges it. The leader waits for every member it heard from within the last ten seconds. Members it cannot reach are listed as unreachable and fetch the generation when they start. A reachable member that has not acknowledged after two minutes fails the rotation (`failed`, with the members named); nothing changed for the envelopes then, the new generation stays unused on the hosts that hold it, and a new request may follow.
3. `rewrapping`: in one write the leader makes the new generation active with a new epoch (`vault.kek.activate`); every controller switches on the change. The leader re-wraps every envelope in paged writes (the data stays encrypted; only the wrapped data keys change).
4. `done`: `vault.kek.rotate` records the new generation, the retired ones, the number of envelopes and the epoch.

Every write of the leader carries the leader epoch, so a deposed leader cannot change the state; the next leader continues from the recorded phase.

**Offline, on a stopped single controller.** `tenko kek rotate` creates the next generation, makes it active, re-wraps every envelope and removes the generations no envelope uses any more (`--keep-retired` keeps them). The `file` and `systemd_credential` providers write the new generation into `kek.dir`, wrapped under the root key; the root key itself is kept and named in the report. A member of a cluster is refused: it rotates online, so that every controller holds the new generation before anything is wrapped with it.

### Status

`GET /system/kek` (any signed-in role that may read the system status) returns this controller's provider, the protection, the active generation, the epoch, every generation of the installation with whether this controller holds it, the generations it lacks, the refused files, the strongest protection it had, the protection of every controller, the rotation, and the warnings. `GET /system/status` carries a short fragment of the same and the warnings:

| Code | Meaning |
|---|---|
| `vault.kek.weak` | The active KEK of this controller has no OS protection (a plain file). |
| `vault.kek.downgrade` | The protection is weaker than this controller had (`cause` `provider`), or a plain generation was refused (`cause` `plain_generation`). |
| `vault.kek.missing` | This controller lacks generations of the installation. |
| `vault.kek.rotation_failed` | The last online rotation failed; `error` says why. |

Backups carry the generations wrapped under the backup key (WP3.4b, `docs/backup.md`), so a restore on a new host needs no copy of the KEK directory.

<a id="8-open-items"></a>

## 9. Open items

- **Zeroization ends at the HTTP response body.** The decrypted bytes, the data keys and the reveal answer are wiped when they are dropped. The serialized JSON of the response, the buffers of the HTTP and TLS stack, and the request body of a create or a replacement are not wiped, and in the browser the value is a JavaScript string.
- **Many simultaneous reveals by one person.** A reservation that loses the race against other controllers eight times in a row answers 503 (`sys.store.timeout`, retryable) instead of 429. It needs more than eight reveals of the same person within the same few milliseconds.
- **A rotation with a stopped member.** A member that was unreachable during an online rotation cannot start until it reaches another member, because it lacks the active generation. Removing a retired generation from a host is a manual step (`tenko kek rotate` on a single controller; on a cluster member, delete the generation file after the rotation, once `GET /system/kek` lists it as retired on every controller).
- **The protection of a systemd credential is declared.** Tenko cannot see which key encrypted the credential; the status says TPM2 only when `with_key = "tpm2"` says so.
