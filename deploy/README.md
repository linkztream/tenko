# Deployment templates

- `Dockerfile`: multi-stage build of the `tenko-server` container image
  (build from the repository root).
- `compose/`: Docker Compose examples, including a macvlan setup for DHCP.
- `systemd/`: hardened unit file for running `tenko-server` on Linux.
- `windows/`: notes on the planned Windows service (not implemented yet).

Everything here is a template for Phase 0. The binary does not serve traffic
yet, so none of these files are ready for production use.
