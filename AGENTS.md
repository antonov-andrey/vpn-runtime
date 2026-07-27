# Repository Guidelines

## Table Of Contents

- [Required Standards](#required-standards)
- [Scope](#scope)
- [Security](#security)
- [Python](#python)
- [Verification](#verification)

## Required Standards

- `project-standards:aws-cloudformation-developer`
- `project-standards:docker-compose-developer`
- `project-standards:http-api-client-developer`
- `project-standards:kubernetes-developer`
- `project-standards:legacy-python-maintainer`
- `project-standards:project-documentation-developer`
- `project-standards:project-foundation`
- `project-standards:project-instruction-developer`
- `project-standards:project-standard-audit`
- `project-standards:pytest-developer`
- `project-standards:python-cli-developer`
- `project-standards:python-developer`
- `project-standards:python-logging-developer`
- `project-standards:python-retry-developer`
- `project-standards:react-ui-developer`
- `project-standards:rest-api-server-developer`
- `project-standards:runtime-config-developer`
- `project-standards:sqlalchemy-developer`
- `project-standards:submodule-developer`
- `project-standards:typescript-developer`
- `project-standards:zitadel-developer`
- `workflow-container-agent-tools:workflow-container-developer` applies to workflow-container gateway integration.

If one required provider skill is unavailable, continue read-only discovery only and do not mutate this repository until the provider is restored.

## Scope
- This repository owns reusable VPN gateway execution and exact VPN configuration validation.
- Shared workflow-container ecosystem authoring and code quality rules belong to `workflow-container-agent-tools:workflow-container-developer`.
- `workflow-control-center` owns `VpnConfig`, `VpnConfigVersion`, publication, authorization, connection slots, run scheduling, Kubernetes orchestration, and active-Version rotation.
- `browser-runtime` is one ordinary SOCKS5 consumer and must not be imported by this repository.
- Do not add workflow-specific, browser-specific, user-management, billing, or Product API behavior.
- Keep protocol adapters explicit. Only OpenVPN is supported until another protocol is implemented and tested as a separate adapter.
- Gluetun and the SOCKS5 server are pinned implementation components, not public APIs. Do not expose their raw control surfaces.

## Security
- A gateway must keep proxy target traffic fail-closed whenever the VPN tunnel is unavailable.
- VPN source snapshots are read-only. Runtime credentials must be written only to attempt-local mode-`0600` files.
- Reject absolute paths, traversal, symlinks, external credential paths, hooks, plugins, and scripts before starting provider software.
- Do not log VPN config bytes, login, password, private keys, or generated authentication files.
- Gateway processes may receive only the minimum tunnel capabilities and device access required by the selected protocol.

## Python
- Python code uses Python 3.14.
- Python code must be formatted with Black using target version `py314` and line length `120`.
- Public API, stable runtime boundaries, and non-trivial modules must have docstrings that describe real behavior.
- Stable configuration and status objects must use strict Pydantic v2 models.
- Tests must use `pytest`.
- Tests must not assert instruction or design prose; those artifacts require semantic review.

## Verification
- Run `python -m pytest -q` after behavior changes.
- Run `python -m compileall vpn_runtime` before handoff.
- Run the container integration suite with real `/dev/net/tun`, a valid OpenVPN snapshot, controlled DNS/HTTPS endpoints, and SOCKS5 egress before runtime handoff.
- Re-read `README.md` and `DESIGN.md` after changes to runtime boundaries.
