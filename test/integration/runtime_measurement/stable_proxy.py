"""Real stable fail-closed proxy switch and restart measurement."""

import asyncio
from pathlib import Path
import socket
import time

from vpn_runtime.stable_proxy import StableProxyCommand, StableProxyRequest, StableProxyRuntime

from runtime_measurement.model import MeasurementSample


async def stable_proxy_switch_restart_get(*, runtime_root_path: Path) -> MeasurementSample:
    """Prove disabled start, atomic upstream switch, and disabled restart."""

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        payload = await reader.read(1024)
        if payload:
            writer.write(payload)
            await writer.drain()
        writer.close()
        await writer.wait_closed()

    upstream_server_list = [
        await asyncio.start_server(echo, host="127.0.0.1", port=0),
        await asyncio.start_server(echo, host="127.0.0.1", port=0),
    ]
    listen_port = _free_port_get()
    control_socket_path = runtime_root_path / "control.sock"
    status_path = runtime_root_path / "status.json"
    runtime = StableProxyRuntime(
        control_socket_path=control_socket_path,
        listen_host="127.0.0.1",
        listen_port=listen_port,
        pod_uid="measurement-pod-uid",
        status_path=status_path,
    )
    t_start = time.monotonic()
    try:
        await runtime.start()
        first_identity = runtime.status.runtime_instance_identity
        await _fail_closed_prove(port=listen_port)
        for generation, server in enumerate(upstream_server_list, start=1):
            upstream_port = server.sockets[0].getsockname()[1]
            response = await runtime.request_handle(
                StableProxyRequest(
                    command=StableProxyCommand.SET_UPSTREAM,
                    expected_pod_uid=runtime.status.pod_uid,
                    expected_runtime_instance_identity=runtime.status.runtime_instance_identity,
                    generation=generation,
                    upstream_host="127.0.0.1",
                    upstream_port=upstream_port,
                )
            )
            if not response.ok:
                raise RuntimeError("stable proxy rejected a ready exact upstream")
            await _round_trip_prove(port=listen_port, payload=f"generation-{generation}".encode())
        await runtime.close()
        runtime = StableProxyRuntime(
            control_socket_path=control_socket_path,
            listen_host="127.0.0.1",
            listen_port=listen_port,
            pod_uid="measurement-pod-uid",
            status_path=status_path,
        )
        await runtime.start()
        await _fail_closed_prove(port=listen_port)
        if runtime.status.runtime_instance_identity == first_identity:
            raise RuntimeError("stable proxy restart reused its runtime instance fence")
        return MeasurementSample(
            detail_by_name_map={
                "atomic_switch_proven": True,
                "disabled_restart_proven": True,
                "runtime_instance_fence_rotated": True,
            },
            duration_seconds=time.monotonic() - t_start,
            name="stable_proxy_switch_restart",
        )
    finally:
        await runtime.close()
        for server in upstream_server_list:
            server.close()
            await server.wait_closed()


async def _fail_closed_prove(*, port: int) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"blocked")
    await writer.drain()
    payload = await asyncio.wait_for(reader.read(1), timeout=2)
    writer.close()
    await writer.wait_closed()
    if payload:
        raise RuntimeError("disabled stable proxy forwarded traffic")


def _free_port_get() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


async def _round_trip_prove(*, port: int, payload: bytes) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    response = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=2)
    writer.close()
    await writer.wait_closed()
    if response != payload:
        raise RuntimeError("stable proxy switched to the wrong upstream")
