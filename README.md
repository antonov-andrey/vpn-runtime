# vpn-runtime

Reusable VPN gateway and validation runtime for platform-managed `VpnConfigVersion` snapshots.

The runtime currently supports `protocol="openvpn"`. One process boundary owns one exact configuration snapshot, one VPN tunnel, one fail-closed SOCKS5 listener, readiness, reconnect, and cleanup. `workflow-control-center` owns users, publication, Versions, connection slots, Kubernetes resources, and active-Version switching.

## Input

The platform mounts one exact read-only directory:

```text
<config-root>/
  config.json
  provider.ovpn
```

`config.json` has the protocol-neutral shape:

```json
{
  "config_path": "provider.ovpn",
  "login": "user",
  "password": "secret"
}
```

`config_path` is relative to the snapshot root and stays inside it. `login` and `password` are either both non-empty or both omitted/empty strings for certificate-only authentication; JSON `null`, NUL, CR, and LF are rejected. Every `remote` uses a literal IP address so fail-closed bootstrap never needs ordinary DNS. The OpenVPN adapter rejects absolute paths, traversal, symlinks, external `auth-user-pass` files, scripts, hooks, plugins, management endpoints, log paths, and unsupported inline blocks. It fingerprints the complete source tree, creates a private attempt copy and mode-`0600` credential files, rewrites only contained file references in that copy, and never mutates the snapshot. The pinned Gluetun process receives only attempt-local `*_SECRETFILE` paths; raw credentials never enter its environment, and its fixed authentication path is an owned link into the same attempt root that is removed before credential cleanup.

## Gateway

The final image pins Gluetun `v3.41.1` by OCI index digest and Dante server `1.4.4-r0`. Gluetun receives explicit `PUID=0` and `PGID=0`, so its generated OpenVPN configuration and the owned authentication link stay readable across retries without broad filesystem-override capabilities; ordinary Dante request handling still runs as `vpnproxy`. Dante binds outbound connections explicitly to `tun0`; Gluetun owns the firewall and health recovery. Target hostname resolution occurs through the proxy side. The listener starts only after tunnel health succeeds, is stopped while health is lost, and cannot fall back to the ordinary interface during initial connection, reconnect, or provider outage.

The platform starts a gateway in prepared state without opening a provider connection. A strict control command addressed to the exact Pod UID activates, reports, or stops one fenced generation through a mode-`0600` local Unix socket:

```bash
vpn-runtime-control --socket-path /runtime/vpn/control.sock activate 42
vpn-runtime-control --socket-path /runtime/vpn/control.sock status 42
vpn-runtime-control --socket-path /runtime/vpn/control.sock stop 42
```

Commands are idempotent for the current generation and reject older generations. Redacted status is atomically persisted for readiness and restart fencing. There is no public REST API, shell command execution, or exposed upstream Gluetun control/health port.

Ordinary provider reconnect stays inside the same gateway, slot, Pod, and Service. Existing TCP connections may fail once; new target traffic remains blocked until tunnel readiness returns.

## Validation

The validation runner uses the same pinned final image and protocol adapter as the gateway. It performs:

- strict static parsing and unsafe-directive rejection;
- real tunnel establishment;
- SOCKS5 TCP access to a platform-owned HTTPS endpoint by hostname;
- proof that target DNS and target traffic use the tunnel;
- fail-closed proof while the tunnel is unavailable;
- clean shutdown with no remaining provider connection.

The report contains status, phase, failure classification, observed exit IP, proof flags, microsecond timestamps, and concrete redacted diagnostics. It never contains configuration or credential bytes. The HTTPS check emits a SOCKS5 domain-name target, so successful TLS verification proves proxy-side target DNS.

## Development

```bash
uv venv --python 3.14
source .venv/bin/activate
uv pip install -e ".[test]"
python -m pytest -q
python -m compileall vpn_runtime
docker build -f docker/Dockerfile -t vpn-runtime:local .
```
