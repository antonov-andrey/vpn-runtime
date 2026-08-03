"""Behavior tests for prepared gateway lifecycle, cleanup, and redaction."""

import asyncio
import json
import os
from pathlib import Path
import signal
import socket
import subprocess

import pytest

from vpn_runtime.config import VpnProtocol
import vpn_runtime.gateway as gateway_module
from vpn_runtime.gateway import (
    GatewayConfig,
    GatewayRuntime,
    GatewayState,
    GatewaySupervisorFailure,
)


def _config_root_create(tmp_path: Path) -> Path:
    """Create one valid minimal provider snapshot.

    Args:
        tmp_path: Temporary test root.

    Returns:
        Provider snapshot path.
    """

    config_root_path = tmp_path / "config"
    config_root_path.mkdir()
    config_root_path.joinpath("config.json").write_text(
        json.dumps(
            {
                "config_path": "provider.ovpn",
                "login": "vpn-user",
                "password": "vpn-password",
            }
        ),
        encoding="utf-8",
    )
    config_root_path.joinpath("provider.ovpn").write_text(
        "client\nremote 203.0.113.10 1194\nauth-user-pass\n",
        encoding="utf-8",
    )
    return config_root_path


def _gateway_get(tmp_path: Path) -> GatewayRuntime:
    """Create one prepared runtime around a valid exact snapshot.

    Args:
        tmp_path: Temporary test root.

    Returns:
        Prepared runtime.
    """

    gluetun_root_path = tmp_path / "gluetun"
    gluetun_root_path.mkdir()
    system_resolv_conf_path = tmp_path / "resolv.conf"
    system_resolv_conf_path.write_text("nameserver 10.96.0.10\n", encoding="utf-8")
    return GatewayRuntime(
        GatewayConfig(
            config_root_path=_config_root_create(tmp_path),
            gluetun_authentication_path=gluetun_root_path / "auth.conf",
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=tmp_path / "runtime",
            system_resolv_conf_path=system_resolv_conf_path,
        )
    )


def test_gateway_construction_is_prepared_and_opens_no_provider_connection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Perform static validation without creating any child process.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def process_create(*args: object, **kwargs: object) -> None:
        """Fail if prepared construction attempts process startup.

        Args:
            *args: Additional positional arguments.
            **kwargs: Provider keyword arguments.
        """

        raise AssertionError("prepared construction must not create a process")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", process_create)

    gateway = _gateway_get(tmp_path)

    assert gateway.status.state is GatewayState.PREPARED
    assert gateway.status.generation == 0
    assert not gateway.have_owned_processes()
    assert not (tmp_path / "runtime").exists()


def test_gateway_config_uses_approved_runtime_defaults(tmp_path: Path) -> None:
    """Keep connection, recovery, and graceful-stop defaults explicit and independent.

    Args:
        tmp_path: Temporary directory path.
    """

    gateway = _gateway_get(tmp_path)

    assert gateway.config.connection_attempt_timeout_seconds == 180
    assert gateway.config.provider_recovery_grace_seconds == 180
    assert gateway.config.process_stop_timeout_seconds == 30
    assert gateway_module.DEFAULT_HEALTH_POLL_INTERVAL_SECONDS == 5.0
    assert gateway_module.PROVIDER_RETRY_INITIAL_SECONDS == 1.0
    assert gateway_module.PROVIDER_RETRY_MAXIMUM_SECONDS == 300.0


def test_gateway_activation_shares_one_provider_attempt_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not reset readiness time independently for provider, DNS, and SOCKS.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Prove all activation phases share one provider-attempt deadline."""

        gateway = _gateway_get(tmp_path)
        deadline_list: list[float] = []
        monitor_release = asyncio.Event()

        async def provider_attempt_start() -> float:
            """Return one deterministic provider-process start time.

            Returns:
                One deterministic provider-process start time.
            """

            return 100.0

        async def readiness_wait(connection_deadline: float) -> None:
            """Capture the provider readiness deadline.

            Args:
                connection_deadline: Connection deadline.
            """

            deadline_list.append(connection_deadline)

        async def user_plane_start(connection_deadline: float) -> None:
            """Capture the same deadline inherited by DNS and SOCKS.

            Args:
                connection_deadline: Connection deadline.
            """

            deadline_list.append(connection_deadline)

        async def health_monitor(generation: int) -> None:
            """Keep the synthetic active generation alive until stop.

            Args:
                generation: Generation.
            """

            await monitor_release.wait()

        monkeypatch.setattr(gateway, "_provider_attempt_start", provider_attempt_start)
        monkeypatch.setattr(gateway, "_gluetun_ready_wait", readiness_wait)
        monkeypatch.setattr(gateway, "_user_plane_start", user_plane_start)
        monkeypatch.setattr(gateway, "_health_monitor", health_monitor)

        await gateway.activate(generation=1)
        assert deadline_list == [280.0, 280.0]
        await gateway.stop()

    asyncio.run(run())


def test_gateway_activation_reaches_ready_and_stop_removes_generated_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Materialize one generation, report readiness, and erase its whole attempt root.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Activate one ready gateway and prove stop erases generated credentials."""

        gateway = _gateway_get(tmp_path)
        chown_call_list: list[tuple[Path, int, int]] = []
        monitor_release = asyncio.Event()
        gluetun_environment_by_name_map: dict[str, str] = {}

        class EmptyOutput:
            """Represent one child output stream that immediately closes."""

            def __aiter__(self) -> "EmptyOutput":
                """Return this empty asynchronous iterator.

                Returns:
                    The this empty asynchronous iterator.
                """

                return self

            async def __anext__(self) -> bytes:
                """End the empty asynchronous iterator.

                Returns:
                    Resulting byte payload.
                """

                raise StopAsyncIteration

        class ExitedProcess:
            """Represent one already-exited child after startup capture."""

            pid = 10001
            returncode = 0
            stdout = EmptyOutput()

        async def process_create(*args: object, **kwargs: object) -> ExitedProcess:
            """Capture the curated Gluetun environment without exposing secret bytes.

            Args:
                *args: Additional positional arguments.
                **kwargs: Provider keyword arguments.

            Returns:
                Resulting exited process.
            """

            environment = kwargs.get("env")
            if environment is not None:
                assert isinstance(environment, dict)
                gluetun_environment_by_name_map.update(environment)
            return ExitedProcess()

        async def readiness_wait(timeout_seconds: int | None = None) -> None:
            """Represent immediate provider or SOCKS readiness.

            Args:
                timeout_seconds: Timeout in seconds.
            """

        async def dnsmasq_start(connection_deadline: float) -> None:
            """Represent an immediately available tunnel-bound DNS forwarder.

            Args:
                connection_deadline: Connection deadline.
            """

        async def health_monitor(generation: int) -> None:
            """Keep one synthetic monitor alive until stop cancels it.

            Args:
                generation: Generation.
            """

            await monitor_release.wait()

        def path_chown(path: Path, user_id: int, group_id: int) -> None:
            """Capture ownership intent without requiring elevated host permissions.

            Args:
                path: Exact filesystem path.
                user_id: Exact user identity.
                group_id: Exact group identity.
            """

            chown_call_list.append((Path(path), user_id, group_id))

        monkeypatch.setattr(asyncio, "create_subprocess_exec", process_create)
        monkeypatch.setattr(gateway, "_dnsmasq_start", dnsmasq_start)
        monkeypatch.setattr(gateway, "_gluetun_ready_wait", readiness_wait)
        monkeypatch.setattr(gateway, "_proxy_dns_redirect_set", lambda *, enabled: None)
        monkeypatch.setattr(gateway, "_socks_ready_wait", readiness_wait)
        monkeypatch.setattr(gateway, "_health_monitor", health_monitor)
        monkeypatch.setattr(os, "chown", path_chown)

        await gateway.activate(generation=9)

        attempt_root_path = tmp_path / "runtime" / "generation_9"
        provider_attempt_root_path = attempt_root_path / "provider_attempt_1"
        authentication_path = provider_attempt_root_path / "private" / "openvpn-auth.txt"
        gluetun_authentication_path = tmp_path / "gluetun" / "auth.conf"
        assert gateway.status.state is GatewayState.READY
        assert gateway.status.generation == 9
        assert authentication_path.is_file()
        assert gluetun_authentication_path.is_symlink()
        assert gluetun_authentication_path.resolve() == authentication_path
        assert "OPENVPN_USER" not in gluetun_environment_by_name_map
        assert "OPENVPN_PASSWORD" not in gluetun_environment_by_name_map
        assert gluetun_environment_by_name_map["PGID"] == "0"
        assert gluetun_environment_by_name_map["PUID"] == "0"
        assert gluetun_environment_by_name_map["DNS_KEEP_NAMESERVER"] == "on"
        assert gluetun_environment_by_name_map["DNS_SERVER"] == "off"
        assert gluetun_environment_by_name_map["FIREWALL_OUTBOUND_SUBNETS"] == "10.96.0.10/32"
        assert gluetun_environment_by_name_map["OPENVPN_USER_SECRETFILE"] == str(
            provider_attempt_root_path / "private" / "openvpn-user.txt"
        )
        assert gluetun_environment_by_name_map["OPENVPN_PASSWORD_SECRETFILE"] == str(
            provider_attempt_root_path / "private" / "openvpn-password.txt"
        )
        assert os.stat(tmp_path / "runtime").st_mode & 0o777 == 0o710
        assert os.stat(attempt_root_path).st_mode & 0o777 == 0o710
        proxy_runtime_root_path = attempt_root_path / "proxy"
        assert os.stat(proxy_runtime_root_path).st_mode & 0o777 == 0o770
        assert (proxy_runtime_root_path, -1, 1000) in chown_call_list

        await gateway.stop()

        assert gateway.status.state is GatewayState.STOPPED
        assert not attempt_root_path.exists()
        assert not gluetun_authentication_path.exists()
        assert not gluetun_authentication_path.is_symlink()
        assert not gateway.have_owned_processes()

    asyncio.run(run())


def test_gateway_failure_redacts_credentials_and_erases_attempt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Keep secrets out of both raised diagnostics and persistent status.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Inject one provider failure and prove diagnostics redact credentials."""

        gateway = _gateway_get(tmp_path)

        async def process_start(openvpn_attempt: object) -> None:
            """Raise one provider failure containing both raw credentials.

            Args:
                openvpn_attempt: Openvpn attempt.
            """

            raise RuntimeError("provider rejected vpn-user and vpn-password")

        monkeypatch.setattr(gateway, "_gluetun_start", process_start)

        with pytest.raises(RuntimeError) as exception_info:
            await gateway.activate(generation=3)

        diagnostic = str(exception_info.value)
        assert "vpn-user" not in diagnostic
        assert "vpn-password" not in diagnostic
        assert diagnostic.count("[REDACTED]") == 2
        assert gateway.status.state is GatewayState.FAILED
        assert gateway.status.diagnostic == diagnostic
        assert not (tmp_path / "runtime" / "generation_3").exists()

    asyncio.run(run())


def test_gateway_proxy_dns_uses_tunnel_forwarder_and_uid_scoped_redirect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Bind upstream DNS to tun0 and redirect only the dedicated SOCKS identity.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Prove proxy DNS uses the tunnel forwarder and UID-scoped redirect."""

        gateway = _gateway_get(tmp_path)
        process_command_list: list[list[str]] = []
        iptables_command_list: list[list[str]] = []

        class EmptyOutput:
            """Represent one child output stream that immediately closes."""

            def __aiter__(self) -> "EmptyOutput":
                """Return this empty asynchronous iterator.

                Returns:
                    The this empty asynchronous iterator.
                """

                return self

            async def __anext__(self) -> bytes:
                """End the empty asynchronous iterator.

                Returns:
                    Resulting byte payload.
                """

                raise StopAsyncIteration

        class RunningProcess:
            """Represent one running DNS forwarder."""

            pid = 10002
            returncode = None
            stdout = EmptyOutput()

        async def process_create(*args: object, **kwargs: object) -> RunningProcess:
            """Capture one process command.

            Args:
                *args: Additional positional arguments.
                **kwargs: Provider keyword arguments.

            Returns:
                Resulting running process.
            """

            process_command_list.append([str(argument) for argument in args])
            return RunningProcess()

        def command_run(
            command: list[str],
            *,
            capture_output: bool,
            check: bool,
            text: bool,
        ) -> subprocess.CompletedProcess[str]:
            """Capture firewall inspection and mutation commands.

            Args:
                command: Command.
                capture_output: Capture output.
                check: Whether a nonzero command exit raises an error.
                text: Text.

            Returns:
                Completed text-mode subprocess result.
            """

            assert capture_output
            assert not check
            assert text
            iptables_command_list.append(command)
            return subprocess.CompletedProcess(command, 1 if "-C" in command else 0, "", "")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", process_create)
        monkeypatch.setattr(subprocess, "run", command_run)
        monkeypatch.setattr(gateway, "_dnsmasq_ready_wait", lambda connection_deadline: asyncio.sleep(0))

        await gateway._dnsmasq_start(asyncio.get_running_loop().time() + 10)
        gateway._proxy_dns_redirect_set(enabled=True)

        dnsmasq_command = process_command_list[0]
        assert "--no-resolv" in dnsmasq_command
        assert "--server=1.1.1.1@tun0" in dnsmasq_command
        assert "--server=1.0.0.1@tun0" in dnsmasq_command
        assert "--user=vpndns" in dnsmasq_command
        assert len(iptables_command_list) == 8
        assert all("--uid-owner" in command and "1000" in command for command in iptables_command_list)
        assert {command[command.index("-p") + 1] for command in iptables_command_list} == {"tcp", "udp"}
        assert any("DNAT" in command and "127.0.0.1:5353" in command for command in iptables_command_list)
        assert any("ACCEPT" in command and "5353" in command for command in iptables_command_list)

    asyncio.run(run())


def test_gateway_dnsmasq_readiness_rejects_an_early_process_exit(tmp_path: Path) -> None:
    """Surface a concrete target-DNS startup failure before opening SOCKS egress.

    Args:
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Prove DNS readiness rejects a helper that exits during startup."""

        gateway = _gateway_get(tmp_path)

        class ExitedProcess:
            """Represent a target-DNS process that failed during startup."""

            returncode = 5

        gateway._dnsmasq_process = ExitedProcess()

        with pytest.raises(RuntimeError, match="dnsmasq exited before target DNS readiness"):
            await gateway._dnsmasq_ready_wait(asyncio.get_running_loop().time() + 10)

    asyncio.run(run())


def test_gateway_health_monitor_restarts_the_complete_user_plane(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Stop the surviving listener before replacing a failed DNS or SOCKS child.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Fail one user-plane helper and prove the complete plane restarts."""

        gateway = _gateway_get(tmp_path)
        event_list: list[str] = []
        user_plane_started = asyncio.Event()

        class RunningProcess:
            """Represent one still-running owned child."""

            returncode = None

        class ExitedProcess:
            """Represent one failed owned child."""

            returncode = 1

        async def health_server_is_ready() -> bool:
            """Keep the provider tunnel ready while one user-plane child fails.

            Returns:
                True while the provider tunnel remains ready.
            """

            return True

        async def user_plane_stop(process_stop_deadline: float) -> None:
            """Capture complete user-plane shutdown.

            Args:
                process_stop_deadline: Process stop deadline.
            """

            event_list.append("stop")

        async def user_plane_start(connection_deadline: float) -> None:
            """Capture replacement after the shutdown boundary.

            Args:
                connection_deadline: Connection deadline.
            """

            event_list.append("start")
            user_plane_started.set()

        gateway._gluetun_process = RunningProcess()
        gateway._dante_process = RunningProcess()
        gateway._dnsmasq_process = ExitedProcess()
        gateway._status_set(generation=7, state=GatewayState.READY)
        monkeypatch.setattr(gateway, "_health_server_is_ready", health_server_is_ready)
        monkeypatch.setattr(gateway, "_user_plane_stop", user_plane_stop)
        monkeypatch.setattr(gateway, "_user_plane_start", user_plane_start)

        monitor_task = asyncio.create_task(gateway._health_monitor(generation=7))
        await asyncio.wait_for(user_plane_started.wait(), timeout=1)
        monitor_task.cancel()
        await asyncio.gather(monitor_task, return_exceptions=True)

        assert event_list[:2] == ["stop", "start"]

    asyncio.run(run())


def test_gateway_resolves_remote_hostname_again_and_rotates_provider_addresses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Use standard DNS for every provider attempt and rotate multiple current addresses.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Rotate resolved provider addresses on the replacement attempt."""

        config_root_path = _config_root_create(tmp_path)
        config_root_path.joinpath("provider.ovpn").write_text(
            "client\nremote vpn.example.test 1194\nauth-user-pass\n",
            encoding="utf-8",
        )
        gluetun_root_path = tmp_path / "gluetun"
        gluetun_root_path.mkdir()
        system_resolv_conf_path = tmp_path / "resolv.conf"
        system_resolv_conf_path.write_text("nameserver 10.96.0.10\n", encoding="utf-8")
        gateway = GatewayRuntime(
            GatewayConfig(
                config_root_path=config_root_path,
                gluetun_authentication_path=gluetun_root_path / "auth.conf",
                protocol=VpnProtocol.OPENVPN,
                runtime_root_path=tmp_path / "runtime",
                system_resolv_conf_path=system_resolv_conf_path,
            )
        )
        resolver_call_list: list[str] = []

        def address_info_get(
            hostname: str,
            port: object,
            *,
            family: socket.AddressFamily,
            type: socket.SocketKind,
        ) -> list[tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str, int]]]:
            """Return two current provider addresses in stable resolver order.

            Args:
                hostname: Hostname.
                port: TCP port.
                family: Family.
                type: Type.

            Returns:
                The two current provider addresses in stable resolver order.
            """

            assert port is None
            assert family is socket.AF_UNSPEC
            assert type is socket.SOCK_STREAM
            resolver_call_list.append(hostname)
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.20", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.21", 0)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", address_info_get)

        gateway._provider_attempt_number = 1
        first_remote_ip_by_hostname_map = await gateway._remote_ip_by_hostname_map_get()
        gateway._provider_attempt_number = 2
        second_remote_ip_by_hostname_map = await gateway._remote_ip_by_hostname_map_get()

        assert resolver_call_list == ["vpn.example.test", "vpn.example.test"]
        assert first_remote_ip_by_hostname_map == {"vpn.example.test": "203.0.113.20"}
        assert second_remote_ip_by_hostname_map == {"vpn.example.test": "203.0.113.21"}

    asyncio.run(run())


def test_gateway_config_rejects_overlapping_source_and_runtime_roots(tmp_path: Path) -> None:
    """Prevent generated credentials from being written under an immutable source root.

    Args:
        tmp_path: Temporary directory path.
    """

    config_root_path = _config_root_create(tmp_path)

    with pytest.raises(ValueError, match="must be disjoint"):
        GatewayConfig(
            config_root_path=config_root_path,
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=config_root_path / "runtime",
        )


def test_gateway_process_sessions_receive_parallel_term_then_bounded_kill(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Signal every owned session before waiting and prove stubborn wrappers after SIGKILL.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Prove every process session receives parallel TERM and bounded KILL."""

        gateway = _gateway_get(tmp_path)
        signal_call_list: list[tuple[int, signal.Signals]] = []

        class StubbornProcess:
            """Represent one wrapper that exits only after its process session receives SIGKILL."""

            def __init__(self, pid: int) -> None:
                """Initialize the stubborn process dependencies.

                Args:
                    pid: Operating-system process identity.
                """

                self.pid = pid
                self.returncode: int | None = None
                self._exit_event = asyncio.Event()

            async def wait(self) -> int:
                """Wait until the synthetic kernel reaps this process.

                Returns:
                    Synthetic process exit status after the reap event.
                """

                await self._exit_event.wait()
                return self.returncode or 0

        process_by_pid_map = {pid: StubbornProcess(pid) for pid in [101, 102]}

        def process_signal(pid: int, signal_number: signal.Signals) -> None:
            """Capture session-member ordering and reap a process after its kill fallback.

            Args:
                pid: Operating-system process identity.
                signal_number: POSIX signal number.
            """

            signal_call_list.append((pid, signal_number))
            if signal_number is signal.SIGKILL:
                process = process_by_pid_map[pid]
                process.returncode = -signal.SIGKILL
                process._exit_event.set()

        monkeypatch.setattr(os, "kill", process_signal)
        monkeypatch.setattr(
            gateway._process_session_supervisor,
            "_session_member_pid_list_get",
            lambda session_id: [session_id] if process_by_pid_map[session_id].returncode is None else [],
        )

        await gateway._process_list_stop(
            list(process_by_pid_map.values()),
            asyncio.get_running_loop().time(),
        )

        assert set(signal_call_list[:2]) == {(101, signal.SIGTERM), (102, signal.SIGTERM)}
        assert set(signal_call_list[2:]) == {(101, signal.SIGKILL), (102, signal.SIGKILL)}

    asyncio.run(run())


def test_gateway_full_cleanup_stops_every_process_under_one_common_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Full cleanup must not give each process family a sequential grace period.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Stop every gateway process under one shared cleanup deadline."""

        gateway = _gateway_get(tmp_path)
        process_list = [object(), object(), object()]
        gateway._dante_process = process_list[0]
        gateway._dnsmasq_process = process_list[1]
        gateway._gluetun_process = process_list[2]
        observed_call_list: list[tuple[list[object], float]] = []

        async def process_list_stop(
            selected_process_list: list[object],
            process_stop_deadline: float,
        ) -> None:
            """Record the exact process group and shared cleanup deadline.

            Args:
                selected_process_list: Ordered selected process values.
                process_stop_deadline: Process stop deadline.
            """

            observed_call_list.append((selected_process_list, process_stop_deadline))

        monkeypatch.setattr(gateway, "_process_list_stop", process_list_stop)
        deadline = asyncio.get_running_loop().time() + 30

        await gateway._process_cleanup(deadline)

        assert observed_call_list == [(process_list, deadline)]
        assert gateway._dante_process is None
        assert gateway._dnsmasq_process is None
        assert gateway._gluetun_process is None

    asyncio.run(run())


def test_gateway_provider_restart_never_starts_after_unproved_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not create a second provider attempt when old ownership is not proven absent.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Prevent a replacement provider from starting before proven cleanup."""

        gateway = _gateway_get(tmp_path)
        provider_start_count = 0

        async def process_list_stop(
            process_list: list[object],
            process_stop_deadline: float,
        ) -> None:
            """Represent a supervisor failure before old provider cleanup completes.

            Args:
                process_list: Ordered process values.
                process_stop_deadline: Process stop deadline.
            """

            raise RuntimeError("synthetic cleanup proof failure")

        async def provider_attempt_start() -> float:
            """Fail the test if restart opens another provider attempt.

            Returns:
                Resulting float.
            """

            nonlocal provider_start_count
            provider_start_count += 1
            return 0.0

        monkeypatch.setattr(gateway, "_process_list_stop", process_list_stop)
        monkeypatch.setattr(gateway, "_provider_attempt_start", provider_attempt_start)

        with pytest.raises(GatewaySupervisorFailure, match="cleanup could not be proven"):
            await gateway._provider_attempt_restart()

        assert provider_start_count == 0

    asyncio.run(run())


def test_gateway_provider_restart_reaps_previous_attempt_output_tasks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not retain one output-reader task per indefinite provider retry.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Reap output tasks from the provider attempt before replacement."""

        gateway = _gateway_get(tmp_path)
        output_task = asyncio.create_task(asyncio.Event().wait())
        gateway._output_task_list.append(output_task)

        async def all_processes_stop(_deadline: float) -> None:
            """Represent one already-proven process-session cleanup.

            Args:
                _deadline: Deadline.
            """

        async def provider_attempt_start() -> float:
            """Represent immediate replacement-process start.

            Returns:
                Resulting float.
            """

            return asyncio.get_running_loop().time()

        async def readiness_wait(_deadline: float) -> None:
            """Represent immediate replacement readiness.

            Args:
                _deadline: Deadline.
            """

        monkeypatch.setattr(gateway, "_all_processes_stop", all_processes_stop)
        monkeypatch.setattr(gateway, "_provider_attempt_start", provider_attempt_start)
        monkeypatch.setattr(gateway, "_gluetun_ready_wait", readiness_wait)
        monkeypatch.setattr(gateway, "_user_plane_start", readiness_wait)

        await gateway._provider_attempt_restart()

        assert output_task.cancelled()
        assert gateway._output_task_list == []

    asyncio.run(run())


def test_gateway_monitor_publishes_fatal_cleanup_failure_for_pod_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Wake the daemon replacement boundary instead of retrying unsafe cleanup.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Publish fatal cleanup failure so Kubernetes can replace the Pod."""

        gateway = _gateway_get(tmp_path)

        class ExitedProcess:
            """Represent one provider that requires a replacement attempt."""

            returncode = 1

        async def health_server_is_ready() -> bool:
            """Report the provider unavailable.

            Returns:
                False, reporting the provider unavailable.
            """

            return False

        async def user_plane_stop(process_stop_deadline: float) -> None:
            """Represent an already fail-closed user plane.

            Args:
                process_stop_deadline: Process stop deadline.
            """

        async def provider_attempt_restart() -> None:
            """Fail with the exact unproved-cleanup class."""

            raise GatewaySupervisorFailure("owned process remains after SIGKILL")

        async def process_cleanup(process_stop_deadline: float) -> None:
            """Preserve the original fatal cause while attempting final cleanup.

            Args:
                process_stop_deadline: Process stop deadline.
            """

        gateway._gluetun_process = ExitedProcess()
        gateway._status_set(generation=12, state=GatewayState.READY)
        monkeypatch.setattr(gateway, "_health_server_is_ready", health_server_is_ready)
        monkeypatch.setattr(gateway, "_user_plane_stop", user_plane_stop)
        monkeypatch.setattr(gateway, "_provider_attempt_restart", provider_attempt_restart)
        monkeypatch.setattr(gateway, "_process_cleanup", process_cleanup)

        await gateway._health_monitor(generation=12)

        assert await asyncio.wait_for(gateway.fatal_failure_wait(), timeout=1) == (
            "owned process remains after SIGKILL"
        )
        assert gateway.status.state is GatewayState.FAILED

    asyncio.run(run())
