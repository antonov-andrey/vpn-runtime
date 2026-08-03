"""Behavior tests for the credentialless stable fail-closed proxy."""

import asyncio
from pathlib import Path
import socket

import pytest

import vpn_runtime.stable_proxy as stable_proxy_module
from vpn_runtime.stable_proxy import (
    StableProxyCommand,
    StableProxyRequest,
    StableProxyRuntime,
    StableProxyState,
    stable_proxy_request_send,
)


def _available_port_get() -> int:
    """Reserve and release one loopback port for the next local listener."""

    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        return port_socket.getsockname()[1]


def test_stable_proxy_starts_disabled_and_fences_control_identity(tmp_path: Path) -> None:
    """Require exact Pod and runtime identities before any mutation."""

    async def run() -> None:
        """Exercise the private control protocol against one real Unix socket."""

        runtime = StableProxyRuntime(
            control_socket_path=tmp_path / "control.sock",
            listen_host="127.0.0.1",
            listen_port=_available_port_get(),
            pod_uid="pod-uid-one",
            status_path=tmp_path / "status.json",
        )
        await runtime.start()
        try:
            status = runtime.status
            assert status.state is StableProxyState.DISABLED
            assert status.generation == 0
            assert len(status.runtime_instance_identity) == 32
            mismatch_response = await stable_proxy_request_send(
                tmp_path / "control.sock",
                StableProxyRequest(
                    command=StableProxyCommand.DISABLE,
                    expected_pod_uid="pod-uid-other",
                    expected_runtime_instance_identity=status.runtime_instance_identity,
                    expected_mutation_revision=0,
                    generation=1,
                ),
            )
            assert not mismatch_response.ok
            assert mismatch_response.status.generation == 0
            instance_mismatch_response = await runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.DISABLE,
                    expected_pod_uid=status.pod_uid,
                    expected_runtime_instance_identity="0" * 32,
                    expected_mutation_revision=0,
                    generation=1,
                )
            )
            assert not instance_mismatch_response.ok
            assert runtime.status.state is StableProxyState.DISABLED
        finally:
            await runtime.close()
        assert not (tmp_path / "control.sock").exists()

    asyncio.run(run())


def test_stable_proxy_restart_reclaims_only_a_stale_socket(tmp_path: Path) -> None:
    """A same-Pod process restart rotates its fence and starts fail-closed."""

    async def run() -> None:
        """Leave the kernel socket path as a crashed process would, then restart."""

        control_socket_path = tmp_path / "control.sock"
        status_path = tmp_path / "status.json"
        listen_port = _available_port_get()
        first_runtime = StableProxyRuntime(
            control_socket_path=control_socket_path,
            listen_host="127.0.0.1",
            listen_port=listen_port,
            pod_uid="pod-uid-one",
            status_path=status_path,
        )
        first_identity = first_runtime.status.runtime_instance_identity
        first_runtime._status_write()
        with socket.socket(socket.AF_UNIX) as crashed_socket:
            crashed_socket.bind(str(control_socket_path))
        assert control_socket_path.is_socket()

        second_runtime = StableProxyRuntime(
            control_socket_path=control_socket_path,
            listen_host="127.0.0.1",
            listen_port=listen_port,
            pod_uid="pod-uid-one",
            status_path=status_path,
        )
        await second_runtime.start()
        try:
            assert second_runtime.status.runtime_instance_identity != first_identity
            assert second_runtime.status.state is StableProxyState.DISABLED
            response = await stable_proxy_request_send(
                control_socket_path,
                StableProxyRequest(
                    command=StableProxyCommand.STATUS,
                    expected_pod_uid=second_runtime.status.pod_uid,
                    expected_runtime_instance_identity=second_runtime.status.runtime_instance_identity,
                    expected_mutation_revision=0,
                    generation=0,
                ),
            )
            assert response.ok
            assert response.status.state is StableProxyState.DISABLED
        finally:
            await second_runtime.close()

    asyncio.run(run())


def test_stable_proxy_restart_does_not_steal_a_live_socket(tmp_path: Path) -> None:
    """A concurrent runtime cannot unlink or replace the live control owner."""

    async def run() -> None:
        """Attempt a second startup and prove the first endpoint remains usable."""

        control_socket_path = tmp_path / "control.sock"
        first_runtime = StableProxyRuntime(
            control_socket_path=control_socket_path,
            listen_host="127.0.0.1",
            listen_port=_available_port_get(),
            pod_uid="pod-uid-one",
            status_path=tmp_path / "first-status.json",
        )
        await first_runtime.start()
        second_runtime = StableProxyRuntime(
            control_socket_path=control_socket_path,
            listen_host="127.0.0.1",
            listen_port=_available_port_get(),
            pod_uid="pod-uid-one",
            status_path=tmp_path / "second-status.json",
        )
        try:
            with pytest.raises(ValueError, match="live process"):
                await second_runtime.start()
            response = await stable_proxy_request_send(
                control_socket_path,
                StableProxyRequest(
                    command=StableProxyCommand.STATUS,
                    expected_pod_uid=first_runtime.status.pod_uid,
                    expected_runtime_instance_identity=first_runtime.status.runtime_instance_identity,
                    expected_mutation_revision=0,
                    generation=0,
                ),
            )
            assert response.ok
        finally:
            await second_runtime.close()
            await first_runtime.close()

    asyncio.run(run())


def test_stable_proxy_switches_one_exact_upstream_and_disables_active_traffic(tmp_path: Path) -> None:
    """Relay only through the selected generation and close traffic on disable."""

    async def echo_handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Echo one bounded test payload."""

        payload = await reader.read(1024)
        writer.write(payload)
        await writer.drain()
        await reader.read()
        writer.close()
        await writer.wait_closed()

    async def run() -> None:
        """Exercise atomic set, idempotence, stale rejection, and fail-closed disable."""

        echo_server = await asyncio.start_server(echo_handle, host="127.0.0.1", port=0)
        echo_port = echo_server.sockets[0].getsockname()[1]
        proxy_port = _available_port_get()
        runtime = StableProxyRuntime(
            control_socket_path=tmp_path / "control.sock",
            listen_host="127.0.0.1",
            listen_port=proxy_port,
            pod_uid="pod-uid-one",
            status_path=tmp_path / "status.json",
        )
        await runtime.start()
        status = runtime.status
        request = StableProxyRequest(
            command=StableProxyCommand.SET_UPSTREAM,
            expected_pod_uid=status.pod_uid,
            expected_runtime_instance_identity=status.runtime_instance_identity,
            expected_mutation_revision=0,
            generation=7,
            upstream_host="127.0.0.1",
            upstream_port=echo_port,
        )
        try:
            set_response = await runtime.request_handle(request)
            assert set_response.ok
            assert set_response.status.state is StableProxyState.READY
            assert set_response.status.mutation_revision == 1
            repeated_request = request.model_copy(update={"expected_mutation_revision": 1})
            assert (await runtime.request_handle(repeated_request)).ok
            stale_revision_response = await runtime.request_handle(request)
            assert not stale_revision_response.ok
            assert "mutation revision" in stale_revision_response.diagnostic
            different_equal_response = await runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.SET_UPSTREAM,
                    expected_pod_uid=status.pod_uid,
                    expected_runtime_instance_identity=status.runtime_instance_identity,
                    expected_mutation_revision=1,
                    generation=7,
                    upstream_host="127.0.0.1",
                    upstream_port=_available_port_get(),
                )
            )
            assert not different_equal_response.ok
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            writer.write(b"through-vpn")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(11), timeout=2) == b"through-vpn"
            stale_response = await runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.DISABLE,
                    expected_pod_uid=status.pod_uid,
                    expected_runtime_instance_identity=status.runtime_instance_identity,
                    expected_mutation_revision=1,
                    generation=6,
                )
            )
            assert not stale_response.ok
            disable_response = await runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.DISABLE,
                    expected_pod_uid=status.pod_uid,
                    expected_runtime_instance_identity=status.runtime_instance_identity,
                    expected_mutation_revision=1,
                    generation=8,
                )
            )
            assert disable_response.ok
            assert disable_response.status.state is StableProxyState.DISABLED
            assert disable_response.status.mutation_revision == 2
            delayed_set_response = await runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.SET_UPSTREAM,
                    expected_pod_uid=status.pod_uid,
                    expected_runtime_instance_identity=status.runtime_instance_identity,
                    expected_mutation_revision=1,
                    generation=8,
                    upstream_host="127.0.0.1",
                    upstream_port=echo_port,
                )
            )
            assert not delayed_set_response.ok
            assert "mutation revision" in delayed_set_response.diagnostic
            reconnect_response = await runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.SET_UPSTREAM,
                    expected_pod_uid=status.pod_uid,
                    expected_runtime_instance_identity=status.runtime_instance_identity,
                    expected_mutation_revision=2,
                    generation=8,
                    upstream_host="127.0.0.1",
                    upstream_port=echo_port,
                )
            )
            assert reconnect_response.ok
            assert reconnect_response.status.mutation_revision == 3
            final_disable_response = await runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.DISABLE,
                    expected_pod_uid=status.pod_uid,
                    expected_runtime_instance_identity=status.runtime_instance_identity,
                    expected_mutation_revision=3,
                    generation=9,
                )
            )
            assert final_disable_response.ok
            assert await asyncio.wait_for(reader.read(), timeout=2) == b""
            writer.close()
            await writer.wait_closed()
            disabled_reader, disabled_writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            assert await asyncio.wait_for(disabled_reader.read(), timeout=2) == b""
            disabled_writer.close()
            await disabled_writer.wait_closed()
        finally:
            await runtime.close()
            echo_server.close()
            await echo_server.wait_closed()

    asyncio.run(run())


def test_stable_proxy_generation_switch_closes_the_previous_upstream_relay(tmp_path: Path) -> None:
    """A routing-state change cannot leave an established old-generation relay alive."""

    async def echo_handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Echo until the proxy closes this upstream connection."""

        try:
            while payload := await reader.read(1024):
                writer.write(payload)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def run() -> None:
        """Open one relay, switch generation, and prove immediate EOF."""

        echo_server = await asyncio.start_server(echo_handle, host="127.0.0.1", port=0)
        echo_port = echo_server.sockets[0].getsockname()[1]
        proxy_port = _available_port_get()
        runtime = StableProxyRuntime(
            control_socket_path=tmp_path / "control.sock",
            listen_host="127.0.0.1",
            listen_port=proxy_port,
            pod_uid="pod-uid-one",
            status_path=tmp_path / "status.json",
        )
        await runtime.start()
        status = runtime.status
        try:
            first_response = await runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.SET_UPSTREAM,
                    expected_pod_uid=status.pod_uid,
                    expected_runtime_instance_identity=status.runtime_instance_identity,
                    expected_mutation_revision=0,
                    generation=1,
                    upstream_host="127.0.0.1",
                    upstream_port=echo_port,
                )
            )
            assert first_response.ok
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            writer.write(b"first-generation")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(16), timeout=2) == b"first-generation"

            second_response = await runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.SET_UPSTREAM,
                    expected_pod_uid=status.pod_uid,
                    expected_runtime_instance_identity=status.runtime_instance_identity,
                    expected_mutation_revision=1,
                    generation=2,
                    upstream_host="127.0.0.1",
                    upstream_port=echo_port,
                )
            )

            assert second_response.ok
            assert second_response.status.generation == 2
            assert await asyncio.wait_for(reader.read(), timeout=2) == b""
            writer.close()
            await writer.wait_closed()
        finally:
            await runtime.close()
            echo_server.close()
            await echo_server.wait_closed()

    asyncio.run(run())


def test_stable_proxy_disable_overtakes_an_inflight_upstream_proof(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Never publish an upstream whose readiness proof began before fail-close."""

    async def echo_handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Hold a reachable proof endpoint until the test closes it."""

        await reader.read()
        writer.close()
        await writer.wait_closed()

    async def run() -> None:
        """Interleave one set request with a later disable mutation."""

        echo_server = await asyncio.start_server(echo_handle, host="127.0.0.1", port=0)
        echo_port = echo_server.sockets[0].getsockname()[1]
        runtime = StableProxyRuntime(
            control_socket_path=tmp_path / "control.sock",
            listen_host="127.0.0.1",
            listen_port=_available_port_get(),
            pod_uid="pod-uid-one",
            status_path=tmp_path / "status.json",
        )
        await runtime.start()
        proof_started = asyncio.Event()
        proof_release = asyncio.Event()
        real_open_connection = asyncio.open_connection

        async def delayed_open_connection(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            """Pause the proof outside the mutation lock."""

            proof_started.set()
            await proof_release.wait()
            return await real_open_connection(host, port)

        monkeypatch.setattr(stable_proxy_module.asyncio, "open_connection", delayed_open_connection)
        status = runtime.status
        set_task = asyncio.create_task(
            runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.SET_UPSTREAM,
                    expected_pod_uid=status.pod_uid,
                    expected_runtime_instance_identity=status.runtime_instance_identity,
                    expected_mutation_revision=0,
                    generation=4,
                    upstream_host="127.0.0.1",
                    upstream_port=echo_port,
                )
            )
        )
        await proof_started.wait()
        disable_response = await runtime.request_handle(
            StableProxyRequest(
                command=StableProxyCommand.DISABLE,
                expected_pod_uid=status.pod_uid,
                expected_runtime_instance_identity=status.runtime_instance_identity,
                expected_mutation_revision=0,
                generation=4,
            )
        )
        proof_release.set()
        set_response = await set_task

        assert disable_response.ok
        assert not set_response.ok
        assert "overtaken" in set_response.diagnostic
        assert runtime.status.state is StableProxyState.DISABLED
        await runtime.close()
        echo_server.close()
        await echo_server.wait_closed()

    asyncio.run(run())
