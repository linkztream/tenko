# ADR 0003: Embedded single-page UI

- Status: Accepted (embedding mechanism refined by ADR 0008)
- Date: 2026-10-09

## Context

DDI needs a fast UI that serves both a home user and an enterprise administrator. The UI has demanding interaction patterns:

- keyboard-driven bulk grids over thousands of addresses and records (API-08);
- live updates of leases, jobs and scan results;
- multiselect and drag and drop with a preview before every apply, and a job panel with per-item status (API-09);
- an interactive topology map that must handle thousands of nodes (IPAM-20);
- dark mode, Swedish and English, WCAG accessibility.

DDI ships as one binary (ADR 0004), so the UI must not require a separate web server or runtime. The product is API-first: the CLI, a future Terraform provider and the UI must all be able to do the same things (API-01 to API-03).

## Decision

- The UI is a **single-page application written in SolidJS and TypeScript**, built with Vite.
- The built assets are **embedded in the binary** (via `include_dir`) and served by the controller role.
- The UI uses **only the public API**: REST with an OpenAPI specification derived from the server types, plus Server-Sent Events for live updates. There are no UI-only endpoints (API-02, API-05).
- Cold start and bundle size are measured in Spike C (Phase 0) and tracked per release.

## Consequences

- One artifact to ship, sign and upgrade; no web server or Node.js runtime in production.
- API completeness is enforced by construction: anything the UI can do, the CLI and automation can do.
- SolidJS fine-grained reactivity updates only the cells that change, which suits large live-updating grids and job panels.
- The build needs a JavaScript toolchain; CI builds the UI before compiling the binary.
- UI strings must be externalized from the start for Swedish and English.
- The graph library for the topology map is chosen in a Phase 1 spike (sigma.js with graphology for WebGL, ELK for hierarchical layout).

## Alternatives considered

- **Server-rendered HTML with HTMX.** Less JavaScript and simple deployment, but drag and drop, keyboard bulk editing, live job panels and a WebGL topology map would still need substantial client-side code. Server-rendered fragments also become a second, UI-specific API surface, which undermines API-first.
- **React or Next.js.** Large ecosystem, but a heavier runtime and virtual-DOM overhead in large grids. Next.js assumes a Node.js server or a static export that gives up most of its benefits, and neither fits a single embedded binary better than a plain SPA.
