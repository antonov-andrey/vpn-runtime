"""Behavior tests for prepared gateway lifecycle, cleanup, and redaction."""

import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from vpn_runtime.config import VpnProtocol
from vpn_runtime.gateway import GatewayConfig, GatewayRuntime, GatewayState


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
    """Perform static validation without creating any child process."""

    async def process_create(*args: object, **kwargs: object) -> None:
        """Fail if prepared construction attempts process startup."""

        raise AssertionError("prepared construction must not create a process")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", process_create)

    gateway = _gateway_get(tmp_path)

    assert gateway.status.state is GatewayState.PREPARED
    assert gateway.status.generation == 0
    assert not gateway.have_owned_processes()
    assert not (tmp_path / "runtime").exists()


def test_gateway_activation_reaches_ready_and_stop_removes_generated_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Materialize one generation, report readiness, and erase its whole attempt root."""

    async def run() -> None:
        gateway = _gateway_get(tmp_path)
        chown_call_list: list[tuple[Path, int, int]] = []
        monitor_release = asyncio.Event()
        gluetun_environment_by_name_map: dict[str, str] = {}

        class EmptyOutput:
            """Represent one child output stream that immediately closes."""

            def __aiter__(self) -> "EmptyOutput":
                """Return this empty asynchronous iterator."""

                return self

            async def __anext__(self) -> bytes:
                """End the empty asynchronous iterator."""

                raise StopAsyncIteration

        class ExitedProcess:
            """Represent one already-exited child after startup capture."""

            returncode = 0
            stdout = EmptyOutput()

        async def process_create(*args: object, **kwargs: object) -> ExitedProcess:
            """Capture the curated Gluetun environment without exposing secret bytes."""

            environment = kwargs.get("env")
            if environment is not None:
                assert isinstance(environment, dict)
                gluetun_environment_by_name_map.update(environment)
            return ExitedProcess()

        async def readiness_wait(timeout_seconds: int | None = None) -> None:
            """Represent immediate provider or SOCKS readiness."""

        async def dnsmasq_start() -> None:
            """Represent an immediately available tunnel-bound DNS forwarder."""

        async def health_monitor(generation: int) -> None:
            """Keep one synthetic monitor alive until stop cancels it."""

            await monitor_release.wait()

        def path_chown(path: Path, user_id: int, group_id: int) -> None:
            """Capture ownership intent without requiring elevated host permissions."""

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
    """Keep secrets out of both raised diagnostics and persistent status."""

    async def run() -> None:
        gateway = _gateway_get(tmp_path)

        async def process_start(openvpn_attempt: object) -> None:
            """Raise one provider failure containing both raw credentials."""

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
    """Bind upstream DNS to tun0 and redirect only the dedicated SOCKS identity."""

    async def run() -> None:
        gateway = _gateway_get(tmp_path)
        process_command_list: list[list[str]] = []
        iptables_command_list: list[list[str]] = []

        class EmptyOutput:
            """Represent one child output stream that immediately closes."""

            def __aiter__(self) -> "EmptyOutput":
                """Return this empty asynchronous iterator."""

                return self

            async def __anext__(self) -> bytes:
                """End the empty asynchronous iterator."""

                raise StopAsyncIteration

        class RunningProcess:
            """Represent one running DNS forwarder."""

            returncode = None
            stdout = EmptyOutput()

        async def process_create(*args: object, **kwargs: object) -> RunningProcess:
            """Capture one process command."""

            process_command_list.append([str(argument) for argument in args])
            return RunningProcess()

        def command_run(
            command: list[str],
            *,
            capture_output: bool,
            check: bool,
            text: bool,
        ) -> subprocess.CompletedProcess[str]:
            """Capture firewall inspection and mutation commands."""

            assert capture_output
            assert not check
            assert text
            iptables_command_list.append(command)
            return subprocess.CompletedProcess(command, 1 if "-C" in command else 0, "", "")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", process_create)
        monkeypatch.setattr(subprocess, "run", command_run)

        await gateway._dnsmasq_start()
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


def test_gateway_resolves_remote_hostname_again_and_rotates_provider_addresses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Use standard DNS for every provider attempt and rotate multiple current addresses."""

    async def run() -> None:
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
            """Return two current provider addresses in stable resolver order."""

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
    """Prevent generated credentials from being written under an immutable source root."""

    config_root_path = _config_root_create(tmp_path)

    with pytest.raises(ValueError, match="must be disjoint"):
        GatewayConfig(
            config_root_path=config_root_path,
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=config_root_path / "runtime",
        )
