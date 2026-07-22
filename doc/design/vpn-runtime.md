# VPN Runtime Design

## Purpose

`vpn-runtime` owns protocol-specific VPN configuration validation, tunnel process lifecycle, fail-closed SOCKS5 egress, readiness, reconnect, prepared activation, and clean shutdown for one exact configuration snapshot. It is independent from browser automation and concrete workflows.

`workflow-control-center` owns Product resources, authorization, publication, active Version, connection slots, queues, Kubernetes topology, stable Services, generation fencing, and run failure policy. `browser-runtime` and workflow containers are ordinary consumers of the resulting SOCKS5 URL.

## Protocol Boundary

`protocol` is supplied separately from the snapshot and currently accepts only `openvpn`. The snapshot root contains one strict `config.json` whose `config_path` resolves to a local `.ovpn` file. Optional `login` and `password` must occur together. Additional certificate and key files may exist only inside the same immutable root.

Validation fingerprints the complete tree without following symlinks. It rejects absolute paths, traversal, special filesystem objects, external `auth-user-pass` paths, executable hooks, plugins, management endpoints, provider-owned log paths, unsupported inline blocks, and any `remote` hostname whose bootstrap would require ordinary DNS. Runtime rechecks the fingerprint, copies the tree into one generation-local private attempt, rewrites contained references only in that copy, creates generated credential files with mode `0600`, and deletes the whole attempt after stop.

Each future protocol is a separate adapter behind the same validated gateway lifecycle. A protocol is not accepted merely because Gluetun supports it; the platform contract, parser, security policy, real validation, and cleanup proof must all exist first.

## Gateway Boundary

The final image pins the multi-platform Gluetun `v3.41.1` OCI index digest, the Python base OCI index digest, and Dante server `1.4.4-r0`. The adapter supplies one transformed custom-provider configuration, explicit `PUID=0` and `PGID=0`, and only path-valued `OPENVPN_USER_SECRETFILE` and `OPENVPN_PASSWORD_SECRETFILE` settings. Root identity keeps Gluetun's generated OpenVPN configuration and owned authentication link readable across retries without a broad filesystem-override capability; ordinary Dante request handling still drops to the dedicated `vpnproxy` identity. Raw credentials never enter the child environment. Gluetun's fixed authentication path is an owned link into the current attempt and is removed before the attempt is deleted. Gluetun health/control listeners remain loopback-only and are not stable platform contracts.

One gateway owns one tunnel and one TCP SOCKS5 listener. Dante's external interface is exactly `tun0`; target connections and target DNS can leave only through that interface. Root-owned provider transport may reach the literal VPN server IP through bootstrap egress, while normal Dante request handling runs as the dedicated `vpnproxy` user. Readiness is true only when the current fenced generation has an established tunnel and accepting SOCKS listener.

Provider reconnect is one local lifecycle. The stable listener and Service remain the same where possible, target egress stays blocked, and readiness is false until recovery. The runtime does not freeze workflow or browser processes and does not select another Version.

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

Unit tests cover strict config shape, path containment, symlink and directive rejection, credential pairing, generated-file permissions, generation fencing, readiness state, and redaction. Container integration tests use real `/dev/net/tun` and valid OpenVPN credentials to prove tunnel establishment, controlled HTTPS access by hostname through SOCKS5, proxy-side DNS, distinguishable observed exit IP, fail-closed behavior during tunnel loss, reconnect, prepared activation without an extra provider connection, and clean process shutdown. Kubernetes integration in `workflow-control-center` owns slot accounting, stable Services, multi-gateway orchestration, active-Version rotation, and WorkflowRun recovery.
