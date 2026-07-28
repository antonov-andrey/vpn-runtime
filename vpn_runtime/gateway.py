"""Prepared Gluetun and fail-closed Dante SOCKS5 gateway lifecycle."""

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vpn_runtime.config import OpenvpnAttempt, OpenvpnSnapshot, VpnProtocol

DEFAULT_DANTE_EXECUTABLE_PATH = Path("/usr/sbin/sockd")
DEFAULT_DNSMASQ_EXECUTABLE_PATH = Path("/usr/sbin/dnsmasq")
DEFAULT_GLUETUN_AUTHENTICATION_PATH = Path("/etc/openvpn/auth.conf")
DEFAULT_GLUETUN_EXECUTABLE_PATH = Path("/gluetun-entrypoint")
DEFAULT_HEALTH_PORT = 9999
DEFAULT_IPTABLES_EXECUTABLE_PATH = Path("/usr/sbin/iptables")
DEFAULT_PROXY_DNS_PORT = 5353
DEFAULT_SOCKS_PORT = 1080
DEFAULT_SYSTEM_RESOLV_CONF_PATH = Path("/etc/resolv.conf")
PROXY_DNS_UPSTREAM_IP_LIST = ["1.1.1.1", "1.0.0.1"]
VPN_PROXY_GID = 1000
VPN_PROXY_UID = 1000

_DANTE_CONFIG_TEMPLATE = """logoutput: stderr
internal: {socks_host} port = {socks_port}
external: tun0
clientmethod: none
socksmethod: none
user.privileged: vpnproxy
user.unprivileged: vpnproxy
client pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error
}}
socks pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: connect
    log: error
}}
"""


class GatewayConfigurationError(RuntimeError):
    """Raised when provider output proves one deterministic snapshot failure."""


class GatewayState(StrEnum):
    """Observable states of one fenced gateway generation."""

    ACTIVATING = "activating"
    FAILED = "failed"
    PREPARED = "prepared"
    READY = "ready"
    RECONNECTING = "reconnecting"
    STOPPED = "stopped"
    STOPPING = "stopping"


class GatewayStatus(BaseModel):
    """Redacted current state of one exact gateway generation."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    diagnostic: str = ""
    generation: int = Field(ge=0)
    state: GatewayState
    t_update: datetime


class GatewayConfig(BaseModel):
    """Validated process, path, endpoint, and timeout configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)

    activation_timeout_seconds: int = Field(default=120, ge=1)
    config_root_path: Path
    dante_executable_path: Path = DEFAULT_DANTE_EXECUTABLE_PATH
    dnsmasq_executable_path: Path = DEFAULT_DNSMASQ_EXECUTABLE_PATH
    gluetun_authentication_path: Path = DEFAULT_GLUETUN_AUTHENTICATION_PATH
    gluetun_executable_path: Path = DEFAULT_GLUETUN_EXECUTABLE_PATH
    health_port: int = Field(default=DEFAULT_HEALTH_PORT, ge=1, le=65535)
    iptables_executable_path: Path = DEFAULT_IPTABLES_EXECUTABLE_PATH
    process_stop_timeout_seconds: int = Field(default=10, ge=1)
    protocol: VpnProtocol
    provider_reconnect_timeout_seconds: int = Field(default=30, ge=1)
    proxy_dns_port: int = Field(default=DEFAULT_PROXY_DNS_PORT, ge=1024, le=65535)
    reconnect_poll_seconds: float = Field(default=1.0, gt=0)
    runtime_root_path: Path
    socks_host: str = "0.0.0.0"
    socks_port: int = Field(default=DEFAULT_SOCKS_PORT, ge=1, le=65535)
    system_resolv_conf_path: Path = DEFAULT_SYSTEM_RESOLV_CONF_PATH

    @model_validator(mode="after")
    def path_separation_validate(self) -> Self:
        """Keep immutable source and mutable runtime roots disjoint.

        Returns:
            Validated configuration.
        """

        if (
            self.config_root_path == self.runtime_root_path
            or self.config_root_path.is_relative_to(self.runtime_root_path)
            or self.runtime_root_path.is_relative_to(self.config_root_path)
        ):
            raise ValueError("config_root_path and runtime_root_path must be disjoint")
        return self


class GatewayRuntime:
    """Own one exact provider process, SOCKS listener, readiness loop, and cleanup."""

    def __init__(
        self,
        config: GatewayConfig,
        status_callback: Callable[[GatewayStatus], None] | None = None,
    ) -> None:
        """Validate the snapshot without opening a provider connection.

        Args:
            config: Exact gateway runtime configuration.
            status_callback: Optional synchronous observer for durable status persistence.
        """

        if config.protocol is not VpnProtocol.OPENVPN:
            raise ValueError(f"unsupported VPN protocol: {config.protocol}")
        self.config = config
        self._attempt_root_path: Path | None = None
        self._configuration_failure_diagnostic = ""
        self._dante_process: asyncio.subprocess.Process | None = None
        self._dnsmasq_process: asyncio.subprocess.Process | None = None
        self._gluetun_process: asyncio.subprocess.Process | None = None
        self._gluetun_authentication_link_is_owned = False
        self._health_monitor_task: asyncio.Task[None] | None = None
        self._output_task_list: list[asyncio.Task[None]] = []
        self._provider_attempt_number = 0
        self._provider_attempt_root_path: Path | None = None
        self._proxy_dns_redirect_is_owned = False
        self._recent_diagnostic_list: list[str] = []
        self._snapshot = OpenvpnSnapshot.from_root(config.config_root_path)
        self._status = GatewayStatus(
            diagnostic="",
            generation=0,
            state=GatewayState.PREPARED,
            t_update=datetime.now(timezone.utc),
        )
        self._status_callback = status_callback
        self._system_dns_server_ip_list = self._system_dns_server_ip_list_get()
        self._status_notify()

    @property
    def status(self) -> GatewayStatus:
        """Return the latest immutable redacted gateway status."""

        return self._status

    async def activate(self, generation: int) -> None:
        """Start one exact fenced generation and wait for SOCKS readiness.

        Args:
            generation: Positive controller-owned generation.

        Raises:
            RuntimeError: If provider or proxy readiness cannot be established.
        """

        if generation < 1:
            raise ValueError("generation must be positive")
        if any(
            process is not None
            for process in [
                self._dante_process,
                self._dnsmasq_process,
                self._gluetun_process,
            ]
        ):
            await self.stop()
        self._status_set(generation=generation, state=GatewayState.ACTIVATING)
        self._configuration_failure_diagnostic = ""
        self._provider_attempt_number = 0
        self.config.runtime_root_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.config.runtime_root_path, 0o700)
        attempt_root_path = self.config.runtime_root_path / f"generation_{generation}"
        if attempt_root_path.exists():
            shutil.rmtree(attempt_root_path)
        self._attempt_root_path = attempt_root_path
        try:
            attempt_root_path.mkdir(mode=0o700)
            await self._provider_attempt_start()
            await self._gluetun_ready_wait(self.config.activation_timeout_seconds)
            await self._user_plane_start()
        except BaseException as exc:
            diagnostic = self._diagnostic_redact(str(exc))
            await self._process_cleanup()
            self._status_set(generation=generation, state=GatewayState.FAILED, diagnostic=diagnostic)
            if isinstance(exc, asyncio.CancelledError):
                raise
            if isinstance(exc, GatewayConfigurationError):
                raise GatewayConfigurationError(diagnostic) from exc
            raise RuntimeError(diagnostic) from exc
        self._status_set(generation=generation, state=GatewayState.READY)
        self._health_monitor_task = asyncio.create_task(self._health_monitor(generation))

    async def stop(self) -> None:
        """Stop owned processes and remove every generated credential and attempt file."""

        generation = self._status.generation
        if self._status.state is GatewayState.STOPPED and not self.have_owned_processes():
            return
        self._status_set(generation=generation, state=GatewayState.STOPPING)
        health_monitor_task = self._health_monitor_task
        self._health_monitor_task = None
        if health_monitor_task is not None and health_monitor_task is not asyncio.current_task():
            health_monitor_task.cancel()
            await asyncio.gather(health_monitor_task, return_exceptions=True)
        await self._process_cleanup()
        self._status_set(generation=generation, state=GatewayState.STOPPED)

    def have_owned_processes(self) -> bool:
        """Return whether one provider or SOCKS child is still running."""

        return any(
            process is not None and process.returncode is None
            for process in [
                self._dante_process,
                self._dnsmasq_process,
                self._gluetun_process,
            ]
        )

    async def provider_interrupt_for_validation(self) -> None:
        """Stop provider recovery and user egress so validation can prove fail-closed behavior."""

        health_monitor_task = self._health_monitor_task
        self._health_monitor_task = None
        if health_monitor_task is not None:
            health_monitor_task.cancel()
            await asyncio.gather(health_monitor_task, return_exceptions=True)
        await self._user_plane_stop()
        await self._process_stop(self._gluetun_process)
        self._gluetun_process = None

    def _diagnostic_redact(self, diagnostic: str) -> str:
        """Remove exact credentials and generated auth paths from one diagnostic."""

        redacted_diagnostic = diagnostic
        for secret_value in [
            self._snapshot.document.login.get_secret_value(),
            self._snapshot.document.password.get_secret_value(),
        ]:
            if secret_value:
                redacted_diagnostic = redacted_diagnostic.replace(secret_value, "[REDACTED]")
        if self._provider_attempt_root_path is not None:
            for credential_filename in ["openvpn-auth.txt", "openvpn-password.txt", "openvpn-user.txt"]:
                redacted_diagnostic = redacted_diagnostic.replace(
                    str(self._provider_attempt_root_path / "private" / credential_filename),
                    "[GENERATED_AUTH_FILE]",
                )
        return redacted_diagnostic

    def _gluetun_authentication_link_prepare(self, openvpn_attempt: OpenvpnAttempt) -> None:
        """Keep Gluetun's fixed authentication file inside the private attempt root.

        Args:
            openvpn_attempt: Exact materialized paths for the current generation.
        """

        if openvpn_attempt.authentication_path is None:
            return
        authentication_path = self.config.gluetun_authentication_path
        if authentication_path.exists() or authentication_path.is_symlink():
            raise RuntimeError(f"Gluetun authentication path is not clean: {authentication_path}")
        if not authentication_path.parent.is_dir():
            raise RuntimeError(f"Gluetun authentication directory is missing: {authentication_path.parent}")
        authentication_path.symlink_to(openvpn_attempt.authentication_path)
        self._gluetun_authentication_link_is_owned = True

    def _gluetun_authentication_link_remove(self) -> None:
        """Remove the owned fixed-path link without deleting any unexpected file."""

        if not self._gluetun_authentication_link_is_owned:
            return
        authentication_path = self.config.gluetun_authentication_path
        if not authentication_path.is_symlink():
            raise RuntimeError(f"owned Gluetun authentication link was replaced: {authentication_path}")
        authentication_path.unlink()
        self._gluetun_authentication_link_is_owned = False

    async def _provider_attempt_restart(self) -> None:
        """Replace one unhealthy provider attempt after a fresh system-DNS resolution."""

        await self._user_plane_stop()
        await self._process_stop(self._gluetun_process)
        self._gluetun_process = None
        self._gluetun_authentication_link_remove()
        if self._provider_attempt_root_path is not None:
            await asyncio.to_thread(shutil.rmtree, self._provider_attempt_root_path, True)
            self._provider_attempt_root_path = None
        self._configuration_failure_diagnostic = ""
        await self._provider_attempt_start()
        await self._gluetun_ready_wait(self.config.provider_reconnect_timeout_seconds)

    async def _provider_attempt_start(self) -> None:
        """Resolve remote hostnames and start one private provider attempt."""

        if self._attempt_root_path is None:
            raise RuntimeError("generation root is unavailable")
        self._provider_attempt_number += 1
        provider_attempt_root_path = self._attempt_root_path / f"provider_attempt_{self._provider_attempt_number}"
        self._provider_attempt_root_path = provider_attempt_root_path
        remote_ip_by_hostname_map = await self._remote_ip_by_hostname_map_get()
        openvpn_attempt = await asyncio.to_thread(
            self._snapshot.attempt_materialize,
            provider_attempt_root_path,
            remote_ip_by_hostname_map,
        )
        self._gluetun_authentication_link_prepare(openvpn_attempt)
        await self._gluetun_start(openvpn_attempt)

    def _proxy_dns_redirect_set(self, *, enabled: bool) -> None:
        """Add or remove UID-scoped DNS redirects for the SOCKS process.

        Args:
            enabled: Whether DNS from the SOCKS identity must reach the tunnel-bound forwarder.
        """

        for transport_protocol in ["tcp", "udp"]:
            rule_by_table_map = {
                "filter": [
                    "OUTPUT",
                    "-p",
                    transport_protocol,
                    "-d",
                    "127.0.0.1",
                    "--dport",
                    str(self.config.proxy_dns_port),
                    "-m",
                    "owner",
                    "--uid-owner",
                    str(VPN_PROXY_UID),
                    "-j",
                    "ACCEPT",
                ],
                "nat": [
                    "OUTPUT",
                    "-p",
                    transport_protocol,
                    "--dport",
                    "53",
                    "-m",
                    "owner",
                    "--uid-owner",
                    str(VPN_PROXY_UID),
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"127.0.0.1:{self.config.proxy_dns_port}",
                ],
            }
            for table_name, rule_argument_list in rule_by_table_map.items():
                check_result = subprocess.run(
                    [
                        str(self.config.iptables_executable_path),
                        "-t",
                        table_name,
                        "-C",
                        *rule_argument_list,
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                )
                if check_result.returncode not in {0, 1}:
                    raise RuntimeError(f"failed to inspect proxy DNS firewall rule: {check_result.stderr.strip()}")
                rule_exists = check_result.returncode == 0
                if rule_exists == enabled:
                    continue
                action_result = subprocess.run(
                    [
                        str(self.config.iptables_executable_path),
                        "-t",
                        table_name,
                        "-A" if enabled else "-D",
                        *rule_argument_list,
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                )
                if action_result.returncode != 0:
                    raise RuntimeError(f"failed to update proxy DNS firewall rule: {action_result.stderr.strip()}")
                if enabled:
                    self._proxy_dns_redirect_is_owned = True
        self._proxy_dns_redirect_is_owned = enabled

    async def _remote_ip_by_hostname_map_get(self) -> dict[str, str]:
        """Resolve every source hostname with the preserved system resolver.

        Returns:
            Selected IP address by source hostname.
        """

        remote_ip_by_hostname_map: dict[str, str] = {}
        for remote_hostname in self._snapshot.remote_hostname_list:
            try:
                address_info_list = await asyncio.to_thread(
                    socket.getaddrinfo,
                    remote_hostname,
                    None,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                )
            except socket.gaierror as exc:
                raise RuntimeError("system DNS could not resolve an OpenVPN remote hostname") from exc
            remote_ip_list: list[str] = []
            for address_family, _, _, _, socket_address in address_info_list:
                if address_family not in {socket.AF_INET, socket.AF_INET6}:
                    continue
                remote_ip = str(ipaddress.ip_address(socket_address[0]))
                if remote_ip not in remote_ip_list:
                    remote_ip_list.append(remote_ip)
            remote_ip_list.sort(key=lambda remote_ip: ipaddress.ip_address(remote_ip).version)
            if not remote_ip_list:
                raise RuntimeError("system DNS returned no usable address for an OpenVPN remote hostname")
            selection_index = (self._provider_attempt_number - 1) % len(remote_ip_list)
            remote_ip_by_hostname_map[remote_hostname] = remote_ip_list[selection_index]
        return remote_ip_by_hostname_map

    def _system_dns_server_ip_list_get(self) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Read the standard container nameservers before provider startup.

        Returns:
            Unique system DNS server addresses.
        """

        try:
            resolv_conf_line_list = self.config.system_resolv_conf_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise ValueError("failed to read the system resolver configuration") from exc
        system_dns_server_ip_list: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for resolv_conf_line in resolv_conf_line_list:
            token_list = resolv_conf_line.split()
            if len(token_list) < 2 or token_list[0] != "nameserver":
                continue
            try:
                dns_server_ip = ipaddress.ip_address(token_list[1])
            except ValueError as exc:
                raise ValueError("system resolver contains an invalid nameserver address") from exc
            if dns_server_ip not in system_dns_server_ip_list:
                system_dns_server_ip_list.append(dns_server_ip)
        if not system_dns_server_ip_list:
            raise ValueError("system resolver contains no nameserver address")
        return system_dns_server_ip_list

    async def _user_plane_start(self) -> None:
        """Start tunnel-bound DNS and SOCKS only after provider readiness."""

        try:
            await self._dnsmasq_start()
            await asyncio.to_thread(self._proxy_dns_redirect_set, enabled=True)
            await self._dante_start()
            await self._socks_ready_wait()
        except BaseException:
            await self._user_plane_stop()
            raise

    async def _user_plane_stop(self) -> None:
        """Stop SOCKS and target DNS before provider replacement or shutdown."""

        await self._process_stop(self._dante_process)
        self._dante_process = None
        await self._process_stop(self._dnsmasq_process)
        self._dnsmasq_process = None
        if self._proxy_dns_redirect_is_owned:
            await asyncio.to_thread(self._proxy_dns_redirect_set, enabled=False)

    async def _dante_start(self) -> None:
        """Start a SOCKS5 listener explicitly bound to the tunnel interface."""

        if self._attempt_root_path is None:
            raise RuntimeError("attempt root is unavailable")
        proxy_runtime_root_path = self._attempt_root_path / "proxy"
        proxy_runtime_root_path.mkdir(mode=0o770, exist_ok=True)
        dante_config_path = proxy_runtime_root_path / "sockd.conf"
        dante_config_path.write_text(
            _DANTE_CONFIG_TEMPLATE.format(
                socks_host=self.config.socks_host,
                socks_port=self.config.socks_port,
            ),
            encoding="utf-8",
        )
        os.chmod(dante_config_path, 0o600)
        for traversable_path in [self.config.runtime_root_path, self._attempt_root_path]:
            os.chown(traversable_path, -1, VPN_PROXY_GID)
            os.chmod(traversable_path, 0o710)
        os.chown(proxy_runtime_root_path, -1, VPN_PROXY_GID)
        os.chmod(proxy_runtime_root_path, 0o770)
        self._dante_process = await asyncio.create_subprocess_exec(
            str(self.config.dante_executable_path),
            "-f",
            str(dante_config_path),
            "-p",
            str(proxy_runtime_root_path / "sockd.pid"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        self._output_task_list.append(asyncio.create_task(self._process_output_forward("dante", self._dante_process)))

    async def _dnsmasq_start(self) -> None:
        """Start a target-DNS forwarder whose upstream sockets are bound to the tunnel."""

        self._dnsmasq_process = await asyncio.create_subprocess_exec(
            str(self.config.dnsmasq_executable_path),
            "--bind-interfaces",
            "--cache-size=1000",
            "--group=vpndns",
            "--keep-in-foreground",
            "--listen-address=127.0.0.1",
            "--no-hosts",
            "--no-resolv",
            f"--port={self.config.proxy_dns_port}",
            "--strict-order",
            *[f"--server={upstream_ip}@tun0" for upstream_ip in PROXY_DNS_UPSTREAM_IP_LIST],
            "--user=vpndns",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        self._output_task_list.append(
            asyncio.create_task(self._process_output_forward("dnsmasq", self._dnsmasq_process))
        )
        await self._dnsmasq_ready_wait()

    async def _dnsmasq_ready_wait(self) -> None:
        """Wait until the tunnel-bound DNS forwarder accepts a local TCP connection."""

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.config.activation_timeout_seconds
        while loop.time() < deadline:
            if self._dnsmasq_process is None or self._dnsmasq_process.returncode is not None:
                raise RuntimeError(f"dnsmasq exited before target DNS readiness: {self._recent_diagnostic_get()}")
            try:
                connection = await asyncio.to_thread(
                    socket.create_connection,
                    ("127.0.0.1", self.config.proxy_dns_port),
                    0.5,
                )
            except OSError:
                await asyncio.sleep(0.2)
                continue
            connection.close()
            return
        raise RuntimeError("target DNS forwarder readiness timed out")

    async def _gluetun_ready_wait(self, timeout_seconds: int) -> None:
        """Wait until Gluetun health proves the exact tunnel is usable.

        Args:
            timeout_seconds: Maximum wait for this provider attempt.
        """

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        while loop.time() < deadline:
            if self._configuration_failure_diagnostic:
                raise GatewayConfigurationError(self._configuration_failure_diagnostic)
            if self._gluetun_process is None or self._gluetun_process.returncode is not None:
                raise RuntimeError(f"Gluetun exited before tunnel readiness: {self._recent_diagnostic_get()}")
            if await self._health_server_is_ready():
                return
            await asyncio.sleep(0.5)
        raise RuntimeError(f"Gluetun tunnel readiness timed out: {self._recent_diagnostic_get()}")

    async def _gluetun_start(self, openvpn_attempt: OpenvpnAttempt) -> None:
        """Start pinned Gluetun with one curated custom-provider environment."""

        environment_by_name_map = {
            "DNS_KEEP_NAMESERVER": "on",
            "DNS_SERVER": "off",
            "FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT": "on",
            "FIREWALL_INPUT_PORTS": str(self.config.socks_port),
            "HEALTH_RESTART_VPN": "on",
            "HEALTH_SERVER_ADDRESS": f"127.0.0.1:{self.config.health_port}",
            "HEALTH_TARGET_ADDRESSES": "cloudflare.com:443,github.com:443",
            "HTTP_CONTROL_SERVER_ADDRESS": "127.0.0.1:8000",
            "HTTP_CONTROL_SERVER_LOG": "off",
            "LOG_LEVEL": "info",
            "OPENVPN_CUSTOM_CONFIG": str(openvpn_attempt.config_path),
            "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            "PGID": "0",
            "PPROF_BLOCK_PROFILE_RATE": "0",
            "PPROF_ENABLED": "no",
            "PPROF_HTTP_SERVER_ADDRESS": "127.0.0.1:6060",
            "PPROF_MUTEX_PROFILE_RATE": "0",
            "PUBLICIP_ENABLED": "off",
            "PUID": "0",
            "STORAGE_FILEPATH": "",
            "TZ": "UTC",
            "VERSION_INFORMATION": "off",
            "VPN_SERVICE_PROVIDER": "custom",
            "VPN_TYPE": "openvpn",
        }
        system_dns_server_cidr_list = [
            f"{dns_server_ip}/{32 if dns_server_ip.version == 4 else 128}"
            for dns_server_ip in self._system_dns_server_ip_list
            if not dns_server_ip.is_loopback
        ]
        if system_dns_server_cidr_list:
            environment_by_name_map["FIREWALL_OUTBOUND_SUBNETS"] = ",".join(system_dns_server_cidr_list)
        if openvpn_attempt.user_path is not None and openvpn_attempt.password_path is not None:
            environment_by_name_map["OPENVPN_PASSWORD_SECRETFILE"] = str(openvpn_attempt.password_path)
            environment_by_name_map["OPENVPN_USER_SECRETFILE"] = str(openvpn_attempt.user_path)
        self._gluetun_process = await asyncio.create_subprocess_exec(
            str(self.config.gluetun_executable_path),
            cwd=openvpn_attempt.config_path.parent,
            env=environment_by_name_map,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        self._output_task_list.append(
            asyncio.create_task(self._process_output_forward("gluetun", self._gluetun_process))
        )

    async def _health_monitor(self, generation: int) -> None:
        """Suppress user egress during reconnect and refresh stale provider DNS."""

        loop = asyncio.get_running_loop()
        reconnect_start_time: float | None = None
        try:
            while self._status.generation == generation:
                gluetun_is_ready = (
                    self._gluetun_process is not None
                    and self._gluetun_process.returncode is None
                    and await self._health_server_is_ready()
                )
                if not gluetun_is_ready:
                    await self._user_plane_stop()
                    if reconnect_start_time is None:
                        reconnect_start_time = loop.time()
                    self._status_set(generation=generation, state=GatewayState.RECONNECTING)
                    provider_exited = self._gluetun_process is None or self._gluetun_process.returncode is not None
                    reconnect_timed_out = (
                        loop.time() - reconnect_start_time >= self.config.provider_reconnect_timeout_seconds
                    )
                    if provider_exited or reconnect_timed_out:
                        try:
                            await self._provider_attempt_restart()
                        except GatewayConfigurationError:
                            raise
                        except RuntimeError as exc:
                            self._status_set(
                                generation=generation,
                                state=GatewayState.RECONNECTING,
                                diagnostic=self._diagnostic_redact(str(exc)),
                            )
                            await asyncio.sleep(self.config.reconnect_poll_seconds)
                            continue
                        reconnect_start_time = None
                else:
                    reconnect_start_time = None
                    if (
                        self._dante_process is None
                        or self._dante_process.returncode is not None
                        or self._dnsmasq_process is None
                        or self._dnsmasq_process.returncode is not None
                    ):
                        await self._user_plane_stop()
                        await self._user_plane_start()
                    self._status_set(generation=generation, state=GatewayState.READY)
                await asyncio.sleep(self.config.reconnect_poll_seconds)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._user_plane_stop()
            self._status_set(
                generation=generation,
                state=GatewayState.FAILED,
                diagnostic=self._diagnostic_redact(str(exc)),
            )

    async def _health_server_is_ready(self) -> bool:
        """Return whether the loopback Gluetun health endpoint responds with HTTP 200."""

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.config.health_port),
                timeout=1,
            )
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            await writer.drain()
            status_line = await asyncio.wait_for(reader.readline(), timeout=1)
            writer.close()
            await writer.wait_closed()
        except OSError, TimeoutError:
            return False
        return status_line.startswith(b"HTTP/1.1 200") or status_line.startswith(b"HTTP/1.0 200")

    async def _process_cleanup(self) -> None:
        """Stop user egress before provider transport and remove all private runtime files."""

        await self._user_plane_stop()
        await self._process_stop(self._gluetun_process)
        self._gluetun_process = None
        self._gluetun_authentication_link_remove()
        if self._output_task_list:
            await asyncio.gather(*self._output_task_list, return_exceptions=True)
            self._output_task_list.clear()
        self._provider_attempt_root_path = None
        if self._attempt_root_path is not None:
            await asyncio.to_thread(shutil.rmtree, self._attempt_root_path, True)
            self._attempt_root_path = None

    async def _process_output_forward(
        self,
        process_name: str,
        process: asyncio.subprocess.Process,
    ) -> None:
        """Forward redacted child diagnostics as structured line events."""

        if process.stdout is None:
            return
        async for output_line in process.stdout:
            diagnostic = self._diagnostic_redact(output_line.decode(encoding="utf-8", errors="replace").rstrip())
            self._recent_diagnostic_list.append(f"{process_name}: {diagnostic}")
            del self._recent_diagnostic_list[:-20]
            if process_name == "gluetun" and any(
                marker in diagnostic.upper()
                for marker in [
                    "AUTH_FAILED",
                    "CANNOT LOAD",
                    "CANNOT PRE-LOAD",
                    "ERROR OPENING",
                    "OPTIONS ERROR",
                    "UNRECOGNIZED OPTION",
                    "NO CLIENT-SIDE AUTHENTICATION METHOD",
                    "YOU MUST DEFINE CA FILE",
                ]
            ):
                self._configuration_failure_diagnostic = diagnostic
            print(
                json.dumps(
                    {
                        "diagnostic": diagnostic,
                        "event_name": "vpn_runtime.child_output",
                        "process_name": process_name,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )

    def _recent_diagnostic_get(self) -> str:
        """Return a bounded redacted child-output tail for concrete failures."""

        return " | ".join(self._recent_diagnostic_list) or "no child diagnostic"

    async def _process_stop(self, process: asyncio.subprocess.Process | None) -> None:
        """Terminate one owned process group and prove its wrapper exited."""

        if process is None or process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=self.config.process_stop_timeout_seconds)
        except TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()

    async def _socks_ready_wait(self) -> None:
        """Wait for the SOCKS listener while proving its child remains alive."""

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.config.activation_timeout_seconds
        connect_host = "127.0.0.1" if self.config.socks_host == "0.0.0.0" else self.config.socks_host
        while loop.time() < deadline:
            if self._dante_process is None or self._dante_process.returncode is not None:
                raise RuntimeError("Dante exited before SOCKS5 readiness")
            try:
                connection = await asyncio.to_thread(
                    socket.create_connection,
                    (connect_host, self.config.socks_port),
                    0.5,
                )
            except OSError:
                await asyncio.sleep(0.2)
                continue
            connection.close()
            return
        raise RuntimeError("SOCKS5 listener readiness timed out")

    def _status_notify(self) -> None:
        """Publish one immutable status snapshot to the configured observer."""

        if self._status_callback is not None:
            self._status_callback(self._status)

    def _status_set(self, *, generation: int, state: GatewayState, diagnostic: str = "") -> None:
        """Replace and publish one redacted lifecycle status."""

        self._status = GatewayStatus(
            diagnostic=self._diagnostic_redact(diagnostic),
            generation=generation,
            state=state,
            t_update=datetime.now(timezone.utc),
        )
        self._status_notify()
