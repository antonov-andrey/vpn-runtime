"""Behavior tests for private generation fencing and durable local control."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vpn_runtime.config import VpnProtocol
from vpn_runtime.control import (
    ControlCommand,
    ControlDaemon,
    ControlRequest,
    _control_request_send,
)
from vpn_runtime.gateway import GatewayConfig, GatewayState, GatewayStatus


class FakeGatewayRuntime:
    """Deterministic prepared lifecycle used to verify control semantics."""

    instance_list: list["FakeGatewayRuntime"] = []

    def __init__(self, config: GatewayConfig, status_callback: object = None) -> None:
        """Create one prepared fake and publish its initial status.

        Args:
            config: Validated runtime configuration.
            status_callback: Status callback.
        """

        self.activate_count = 0
        self.config = config
        self.stop_count = 0
        self.status = _fake_gateway_status_get(0, GatewayState.PREPARED)
        self._status_callback = status_callback
        self._fatal_failure_event = asyncio.Event()
        self.instance_list.append(self)
        self._notify()

    async def activate(self, generation: int) -> None:
        """Publish activating then ready without opening a provider connection.

        Args:
            generation: Generation.
        """

        self.activate_count += 1
        self.status = _fake_gateway_status_get(generation, GatewayState.ACTIVATING)
        self._notify()
        await asyncio.sleep(0)
        self.status = _fake_gateway_status_get(generation, GatewayState.READY)
        self._notify()

    async def stop(self) -> None:
        """Publish an idempotent stopped state."""

        self.stop_count += 1
        self.status = _fake_gateway_status_get(self.status.generation, GatewayState.STOPPED)
        self._notify()

    async def fatal_failure_wait(self) -> str:
        """Wait for the synthetic fatal supervisor boundary.

        Returns:
            Resulting text value.
        """

        await self._fatal_failure_event.wait()
        return "synthetic fatal failure"

    def _notify(self) -> None:
        """Invoke the real daemon persistence callback when configured."""

        if self._status_callback is not None:
            self._status_callback(self.status)


def _fake_gateway_status_get(generation: int, state: GatewayState) -> GatewayStatus:
    """Build one immutable fake status.

    Args:
        generation: Generation.
        state: Exact runtime state.

    Returns:
        One immutable fake status.
    """

    return GatewayStatus(
        diagnostic="",
        generation=generation,
        state=state,
        t_update=datetime.now(timezone.utc),
    )


def _daemon_get(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ControlDaemon:
    """Create one control daemon with the deterministic gateway fake.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.

    Returns:
        One control daemon with the deterministic gateway fake.
    """

    from vpn_runtime import control

    FakeGatewayRuntime.instance_list.clear()
    monkeypatch.setattr(control, "GatewayRuntime", FakeGatewayRuntime)
    return ControlDaemon(
        gateway_config=GatewayConfig(
            config_root_path=tmp_path / "config",
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=tmp_path / "runtime",
        ),
        socket_path=tmp_path / "runtime" / "control.sock",
        state_path=tmp_path / "runtime" / "status.json",
    )


def test_control_activation_is_idempotent_and_rejects_smaller_generation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Start one generation once and fence every older command.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Prove activation is idempotent and rejects an older generation."""

        daemon = _daemon_get(monkeypatch, tmp_path)
        fake_runtime = FakeGatewayRuntime.instance_list[-1]

        first_response = await daemon.request_handle(ControlRequest(command=ControlCommand.ACTIVATE, generation=8))
        await asyncio.sleep(0)
        repeated_response = await daemon.request_handle(ControlRequest(command=ControlCommand.ACTIVATE, generation=8))
        fenced_response = await daemon.request_handle(ControlRequest(command=ControlCommand.STOP, generation=7))

        assert first_response.ok
        assert repeated_response.ok
        assert fake_runtime.activate_count == 1
        assert fenced_response.ok is False
        assert fenced_response.error == "generation 7 is fenced by generation 8"
        assert daemon.status.generation == 8
        assert daemon.status.state is GatewayState.READY
        await daemon.close()

    asyncio.run(run())


def test_control_newer_stop_fences_generation_without_waiting_for_provider_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Advance the fence and expose stopped state through one idempotent command.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Fence a newer stop generation without awaiting provider cleanup."""

        daemon = _daemon_get(monkeypatch, tmp_path)
        fake_runtime = FakeGatewayRuntime.instance_list[-1]
        await daemon.request_handle(ControlRequest(command=ControlCommand.ACTIVATE, generation=2))
        await asyncio.sleep(0)

        stop_response = await daemon.request_handle(ControlRequest(command=ControlCommand.STOP, generation=5))
        repeated_response = await daemon.request_handle(ControlRequest(command=ControlCommand.STOP, generation=5))

        assert stop_response.ok
        assert repeated_response.ok
        assert stop_response.status.generation == 5
        assert repeated_response.status.state is GatewayState.STOPPED
        assert fake_runtime.stop_count >= 2
        await daemon.close()

    asyncio.run(run())


def test_control_same_generation_activate_does_not_interrupt_internal_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Repeated orchestration observes reconnecting state without restarting its provider attempt.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Keep same-generation activation from interrupting internal recovery."""

        daemon = _daemon_get(monkeypatch, tmp_path)
        fake_runtime = FakeGatewayRuntime.instance_list[-1]
        await daemon.request_handle(ControlRequest(command=ControlCommand.ACTIVATE, generation=3))
        await asyncio.sleep(0)
        fake_runtime.status = _fake_gateway_status_get(3, GatewayState.RECONNECTING)
        fake_runtime._notify()
        stop_count_before_retry = fake_runtime.stop_count

        response = await daemon.request_handle(ControlRequest(command=ControlCommand.ACTIVATE, generation=3))

        assert response.ok
        assert response.status.state is GatewayState.RECONNECTING
        assert fake_runtime.activate_count == 1
        assert fake_runtime.stop_count == stop_count_before_retry
        await daemon.close()

    asyncio.run(run())


def test_control_unix_socket_returns_exact_redacted_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Serve the shell-free JSON command protocol only on the private Unix socket.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Serve exact redacted gateway status over the Unix control socket."""

        daemon = _daemon_get(monkeypatch, tmp_path)
        socket_path = tmp_path / "runtime" / "control.sock"
        await daemon.serve_start()

        response = await _control_request_send(
            socket_path,
            ControlRequest(command=ControlCommand.ACTIVATE, generation=4),
        )
        await asyncio.sleep(0)
        status_response = await _control_request_send(
            socket_path,
            ControlRequest(command=ControlCommand.STATUS, generation=4),
        )

        assert response.ok
        assert status_response.ok
        assert status_response.status.generation == 4
        assert status_response.status.state is GatewayState.READY
        assert socket_path.stat().st_mode & 0o777 == 0o600
        await daemon.close()

    asyncio.run(run())


def test_control_daemon_does_not_steal_a_live_socket(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A concurrent daemon cannot unlink or later remove the live owner's socket.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Refuse to replace a control socket owned by a live daemon."""

        first_daemon = _daemon_get(monkeypatch, tmp_path)
        await first_daemon.serve_start()
        second_daemon = _daemon_get(monkeypatch, tmp_path)

        with pytest.raises(ValueError, match="owned by a live process"):
            await second_daemon.serve_start()
        await second_daemon.close()

        response = await _control_request_send(
            tmp_path / "runtime" / "control.sock",
            ControlRequest(command=ControlCommand.ACTIVATE, generation=4),
        )
        assert response.ok
        await first_daemon.close()

    asyncio.run(run())


def test_control_restores_highest_generation_fence_as_prepared(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Preserve fencing across daemon restart without claiming stale process readiness.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Restore the persisted highest-generation fence in prepared state."""

        first_daemon = _daemon_get(monkeypatch, tmp_path)
        await first_daemon.request_handle(ControlRequest(command=ControlCommand.ACTIVATE, generation=11))
        await asyncio.sleep(0)
        await first_daemon.close()

        second_daemon = _daemon_get(monkeypatch, tmp_path)
        stale_response = await second_daemon.request_handle(
            ControlRequest(command=ControlCommand.ACTIVATE, generation=10)
        )

        assert stale_response.ok is False
        assert second_daemon.status.generation == 11
        assert second_daemon.status.state is GatewayState.PREPARED
        await second_daemon.close()

    asyncio.run(run())
