# vpn-runtime

Reusable VPN gateway and validation runtime for platform-managed `VpnConfigVersion` snapshots.

The runtime currently supports `protocol="openvpn"`. One gateway process boundary owns one exact configuration snapshot, one VPN tunnel, one fail-closed SOCKS5 listener, readiness, reconnect, and bounded cleanup. The repository also supplies the credentialless stable fail-closed proxy used to atomically switch gateway generations. `workflow-control-center` owns users, publication, Versions, connection slots, Kubernetes resources, and active-Version orchestration; VPN state does not control `WorkflowRun` lifecycle.

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

`config_path` is relative to the snapshot root and stays inside it. `login` and `password` are either both non-empty or both omitted/empty strings for certificate-only authentication; JSON `null`, NUL, CR, and LF are rejected. An OpenVPN `remote` may use a valid hostname or a literal IP address. The source hostname remains unchanged: before each provider attempt the runtime resolves it through the standard container resolver and writes the selected IP only into that private attempt copy required by pinned Gluetun. A later provider attempt performs a fresh lookup and rotates multiple current addresses, so an obsolete server IP cannot permanently prevent recovery. The OpenVPN adapter rejects absolute paths, traversal, symlinks, external `auth-user-pass` files, scripts, hooks, plugins, management endpoints, log paths, and unsupported inline blocks. It fingerprints the complete source tree, creates a private attempt copy and mode-`0600` credential files, rewrites only contained file references in that copy, and never mutates the snapshot. The pinned Gluetun process receives only attempt-local `*_SECRETFILE` paths; raw credentials never enter its environment, and its fixed authentication path is an owned link into the same attempt root that is removed before credential cleanup.

## Gateway

The final image pins Gluetun `v3.41.1` by OCI index digest, Dante server `1.4.4-r0`, and dnsmasq `2.91-r1`. Gluetun receives explicit `PUID=0` and `PGID=0`, so its generated OpenVPN configuration and the owned authentication link stay readable across retries without broad filesystem-override capabilities; ordinary Dante request handling still runs as `vpnproxy`. Gluetun preserves the standard container resolver and grants bootstrap egress only to its exact nameserver addresses. That resolver is used by runtime control traffic, including each OpenVPN remote lookup, regardless of tunnel state.

Dante binds outbound target connections explicitly to `tun0`. UID-scoped firewall rules redirect only DNS from `vpnproxy` to a local dnsmasq process, whose upstream sockets are explicitly bound to `tun0`; other container processes continue to use the standard resolver. The container requires `/dev/net/tun` and exactly `CHOWN`, `KILL`, `NET_ADMIN`, `NET_RAW`, `SETGID`, and `SETUID`; dnsmasq uses `NET_RAW` to bind upstream sockets to the tunnel interface, while the owning supervisor uses `KILL` to stop its own dnsmasq and Dante children after they drop to isolated UIDs. The DNS forwarder and SOCKS listener start only after tunnel health succeeds, stop as one unit when either child or tunnel health is lost, and cannot fall back to the ordinary interface during initial connection, reconnect, or provider outage.

The platform starts a gateway in prepared state without opening a provider connection. Optional DNS prefetch is not attempt identity: activation repeats the authoritative standard-DNS lookup immediately before starting the provider. A strict control command addressed to the exact Pod UID activates, reports, or stops one fenced generation through a mode-`0600` local Unix socket:

```bash
vpn-runtime-control --socket-path /runtime/vpn/control.sock activate 42
vpn-runtime-control --socket-path /runtime/vpn/control.sock status 42
vpn-runtime-control --socket-path /runtime/vpn/control.sock stop 42
```

Commands are idempotent for the current generation and reject older generations. Redacted status is atomically persisted for readiness and restart fencing. Persisted generation never restores process readiness or an upstream after restart. There is no public REST API, shell command execution, or exposed upstream Gluetun control/health port.

Ordinary provider reconnect stays inside the same gateway, slot, Pod, and Service. Existing TCP connections may fail once; new target traffic remains blocked until tunnel readiness returns. Each Version provides immutable `connection_attempt_timeout_seconds`, `provider_recovery_grace_seconds`, and `process_stop_timeout_seconds` with baseline defaults `180`, `180`, and `30`; concrete values must also satisfy the platform safety ranges accepted from real ARM64 measurements and resource-ownership limits. An attempt has one monotonic connection deadline, current Gluetun gets the configured recovery grace, and owned process groups share one bounded TERM/KILL stop deadline. After provider exit or grace expiry, the runtime replaces only its private attempt in the same Pod, resolves source hostnames again with the standard resolver, and restores target DNS and SOCKS only after the new tunnel is ready. Gateway mode retries transient attempts indefinitely with exponential backoff from 1 to 300 seconds; validation mode returns after one bounded lifecycle so WCC can release and fairly reacquire a slot. Health is observed every 5 seconds independently of retry backoff.

The stable proxy is a separate minimal non-root OCI image target without gateway packages or capabilities. It accepts only exact run traffic and only the selected gateway upstream. It has no direct fallback, VPN secret, `/dev/net/tun`, AWS identity, or Kubernetes token. It generates a new runtime instance identity and starts disabled after every process or Pod restart. Its private Unix control socket supports generation-fenced disable, atomic exact-upstream switch, and status; commands bind expected Pod UID and runtime instance identity, and equal-generation idempotence is scoped to that exact instance. The platform rechecks status and binds applied state to the same tuple; raw component APIs are not exposed.

## Validation

The validation runner uses the same pinned final image and protocol adapter as the gateway. It performs:

- strict static parsing and unsafe-directive rejection;
- real tunnel establishment;
- standard-DNS OpenVPN hostname bootstrap and fresh provider-attempt resolution;
- SOCKS5 TCP access to a private platform-owned presigned S3 nonce by hostname;
- proof that target DNS and target traffic use the tunnel;
- fail-closed proof while the tunnel is unavailable;
- clean shutdown with no remaining provider connection.

The report contains status, phase, failure classification, proof flags, microsecond timestamps, and concrete redacted diagnostics. Exit IP, presigned URL, nonce, configuration, and credential bytes are absent. The validation Job has no AWS credentials; exact nonce bytes prove egress, while the SOCKS5 domain-name target and successful TLS verification prove proxy-side target DNS.

## Development

```bash
uv venv --python 3.14
source .venv/bin/activate
uv pip install -e ".[test]"
python -m pytest -q
python -m compileall vpn_runtime
docker build \
  --build-arg GLUETUN_IMAGE=ghcr.io/qdm12/gluetun@sha256:1a5bf4b4820a879cdf8d93d7ef0d2d963af56670c9ebff8981860b6804ebc8ab \
  --build-arg PYTHON_IMAGE=public.ecr.aws/docker/library/python:3.14-alpine3.22 \
  -f docker/Dockerfile -t vpn-runtime:local .
```

Product release resolves both supported base selectors to exact platform digests. `python-alpine` is the explicit libc compatibility variant: Python artifacts are copied into the Alpine/musl Gluetun final image and therefore cannot reuse the platform's canonical Debian/glibc Python image. Python build/runtime dependencies are installed only from committed hash-locked requirements; the local selectors above are not a Product release identity.
