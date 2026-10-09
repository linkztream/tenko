# Windows service

Status: planned, not implemented yet. Everything below describes the intended
behavior; none of these commands exist today.

## Planned commands

```
tenko-server service install --roles dns,dhcp --config "C:\ProgramData\Tenko\tenko.toml"
tenko-server service uninstall
tenko-server service start
tenko-server service stop
```

`service install` (planned) registers a Windows service with:

- name `tenko-server`, display name `Tenko DDI Server`
- start type automatic
- the virtual service account `NT SERVICE\tenko-server`

## Planned layout

- State lives in `C:\ProgramData\Tenko\`, with ACLs restricted to the service
  account and Administrators.
- Secrets at rest are protected with DPAPI (machine scope) through the
  `tenko-vault` crate.
- Logs go to the Windows Event Log and a rolling file.

## Coexistence with Windows roles

- The DHCP role cannot run next to the Windows DHCP Server service on the same
  host: both bind UDP 67.
- The DNS role cannot run next to the Windows DNS Server service on the same
  addresses: both bind UDP/TCP 53.

Stop or uninstall those Windows roles first, or migrate with the planned
migration tooling.
