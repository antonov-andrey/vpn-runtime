# VPN Runtime

## Purpose

`vpn-runtime` owns protocol-specific VPN configuration validation, tunnel process lifecycle, fail-closed SOCKS5 egress, readiness, reconnect, prepared activation, and clean shutdown for one exact configuration snapshot. It is independent from browser automation and concrete workflows.

`workflow-control-center` owns Product resources, authorization, publication, active Version, connection slots, queues, Kubernetes topology, stable Services, generation fencing, and run failure policy. `browser-runtime` and workflow containers are ordinary consumers of the resulting SOCKS5 URL.

## Protocol Boundary

`protocol` is supplied separately from the snapshot and currently accepts only `openvpn`. The snapshot root contains one strict `config.json` whose `config_path` resolves to a local `.ovpn` file. Optional `login` and `password` must occur together. Additional certificate and key files may exist only inside the same immutable root.

Validation fingerprints the complete tree without following symlinks. It rejects absolute paths, traversal, special filesystem objects, external `auth-user-pass` paths, executable hooks, plugins, management endpoints, provider-owned log paths, unsupported inline blocks, and invalid `remote` host tokens. A valid `remote` may use a hostname or literal IP address. Runtime rechecks the fingerprint, resolves every source hostname with the standard container resolver before each provider attempt, copies the tree into one attempt-local private directory, writes selected IP addresses and contained references only into that copy, creates generated credential files with mode `0600`, and deletes the whole generation after stop. The immutable source hostname is never rewritten. Successive attempts repeat DNS resolution and rotate multiple current addresses.

Each future protocol is a separate adapter behind the same validated gateway lifecycle. A protocol is not accepted merely because Gluetun supports it; the platform contract, parser, security policy, real validation, and cleanup proof must all exist first.

## Gateway Boundary

The final image tracks Python `3.14` patch updates on the Alpine `3.22` branch and pins the multi-platform Gluetun `v3.41.1` OCI index digest, Dante server `1.4.4-r0`, and dnsmasq `2.91-r1`. The adapter supplies one transformed custom-provider configuration, explicit `PUID=0` and `PGID=0`, and only path-valued `OPENVPN_USER_SECRETFILE` and `OPENVPN_PASSWORD_SECRETFILE` settings. Root identity keeps Gluetun's generated OpenVPN configuration and owned authentication link readable across retries without a broad filesystem-override capability; ordinary Dante request handling still drops to the dedicated `vpnproxy` identity and target-DNS forwarding drops to the distinct `vpndns` identity. Raw credentials never enter the child environment. Gluetun's fixed authentication path is an owned link into the current attempt and is removed before the attempt is deleted. Gluetun health/control listeners remain loopback-only and are not stable platform contracts.

One gateway owns one tunnel, one tunnel-bound target-DNS forwarder, and one TCP SOCKS5 listener. The standard container resolver remains installed and its exact nameserver IPs receive bootstrap egress through the ordinary interface; runtime control traffic and OpenVPN remote lookup use this resolver independently of tunnel health. Dante's external interface is exactly `tun0`. Firewall rules scoped to UID `vpnproxy` translate only TCP and UDP port-53 requests to the local dnsmasq listener, and dnsmasq binds every upstream resolver socket explicitly to `tun0`. The forwarder does not read the standard resolver, and neither target connections nor target DNS can fall back to the ordinary interface. The container receives `/dev/net/tun` and only `CHOWN`, `KILL`, `NET_ADMIN`, `NET_RAW`, `SETGID` and `SETUID`; `NET_RAW` is required by dnsmasq for interface-bound upstream sockets, while `KILL` lets the owning supervisor stop its own dnsmasq and Dante children after they drop to their isolated UIDs. Readiness is true only when the current fenced generation has an established tunnel, an accepting target-DNS forwarder, installed UID-scoped rules, and an accepting SOCKS listener.

Provider reconnect is one local lifecycle. The stable listener and Service remain the same where possible, target egress stays blocked, and readiness is false until recovery. Gluetun may first recover its current connection locally. Failure of either dnsmasq or Dante first stops the complete user plane and only then replaces both children, so one generation never owns duplicate listeners. Provider-process exit or 30 seconds without tunnel health causes the runtime to stop user egress, replace the private provider attempt, repeat standard-DNS resolution, and restore dnsmasq and Dante only after tunnel readiness. The runtime does not freeze workflow or browser processes and does not select another Version.

## Prepared Activation And Fencing

A replacement gateway Pod starts in prepared state after static validation but without opening a provider connection. The image runs a minimal daemon with a mode-`0600` local Unix socket, atomic redacted status file, and shell-free control CLI. Platform `pods/exec` commands `activate <generation>`, `status <generation>`, and `stop <generation>` are idempotent for the same generation and reject smaller generations. The durable highest generation is restored as prepared rather than falsely restoring process readiness. The controller verifies exact Pod UID before every command.

Activation starts the exact validated snapshot and publishes readiness only after tunnel and SOCKS checks. Stop prevents new target work, closes the provider connection, proves owned child processes exited, and leaves no reusable credential file. The runtime does not decide when Service selectors change or when old Pods are deleted.

## Validation Boundary

The validation runner and production gateway for one `VpnConfigVersion` use the same exact pinned image digest, parser, adapter, Gluetun digest, SOCKS implementation, and security configuration. Platform-owned fixtures provide a controlled HTTPS hostname and expected observation channel. Validation proves strict parsing, real connection, proxy-side DNS, tunnel egress, fail-closed behavior, and clean shutdown. It records the observed exit IP but does not require a specific country or require it to differ from an unrelated baseline.

Infrastructure failures are distinguishable from deterministic config/test failures through structured phases and diagnostics. Retry policy and `VpnConfigVersion` state transitions belong to `workflow-control-center`.

## Security Boundary

The gateway receives only the exact immutable snapshot and private runtime storage. It does not receive Product DB, S3, KMS, registry, Kubernetes API, browser profile, workflow input, or other users' configurations. Only the gateway container receives `/dev/net/tun` and the minimum network capability required by the protocol.

Logs, health, validation reports, and process errors redact configuration bodies, credentials, private keys, generated authentication files, and provider tokens. There is no user-facing or cluster-public management API.

## Verification Contract

Unit tests cover strict config shape, path containment, symlink and directive rejection, hostname acceptance, attempt-local IP rendering, repeated resolution, standard resolver preservation, UID-scoped DNS rules, credential pairing, generated-file permissions, generation fencing, readiness state, and redaction. Container integration tests use real `/dev/net/tun` and valid OpenVPN credentials to prove standard-DNS hostname bootstrap, tunnel establishment, controlled HTTPS access by hostname through SOCKS5, proxy-side DNS through `tun0`, ordinary system DNS outside the tunnel, distinguishable observed exit IP, fail-closed behavior during tunnel loss, fresh provider-attempt recovery, prepared activation without an extra provider connection, and clean process shutdown. Kubernetes integration in `workflow-control-center` owns slot accounting, stable Services, multi-gateway orchestration, active-Version rotation, and WorkflowRun recovery.
