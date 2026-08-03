"""Shared exact gateway construction and readiness helpers for measurements."""

import asyncio
from collections.abc import Callable
from pathlib import Path
import time

from vpn_runtime.config import VpnProtocol
from vpn_runtime.gateway import GatewayConfig, GatewayRuntime, GatewayState
from vpn_runtime.validation import _socks_https_get


def gateway_get(
    *,
    config_root_path: Path,
    connection_attempt_timeout_seconds: int,
    process_stop_timeout_seconds: int,
    provider_recovery_grace_seconds: int,
    runtime_root_path: Path,
) -> GatewayRuntime:
    """Construct one production gateway with explicit measured timing inputs.

    Args:
        config_root_path: Exact filesystem path for config root.
        connection_attempt_timeout_seconds: Connection attempt timeout in seconds.
        process_stop_timeout_seconds: Process stop timeout in seconds.
        provider_recovery_grace_seconds: Provider recovery grace in seconds.
        runtime_root_path: Exact filesystem path for runtime root.

    Returns:
        Resulting gateway runtime.
    """

    return GatewayRuntime(
        GatewayConfig(
            config_root_path=config_root_path,
            connection_attempt_timeout_seconds=connection_attempt_timeout_seconds,
            process_stop_timeout_seconds=process_stop_timeout_seconds,
            protocol=VpnProtocol.OPENVPN,
            provider_recovery_grace_seconds=provider_recovery_grace_seconds,
            runtime_root_path=runtime_root_path,
        )
    )


async def nonce_probe(*, expected_nonce: bytes, https_url: str, timeout_seconds: int = 15) -> None:
    """Prove one HTTPS nonce through production SOCKS and proxy-side DNS.

    Args:
        expected_nonce: Exact private nonce bytes.
        https_url: Presigned HTTPS URL.
        timeout_seconds: Timeout in seconds.
    """

    response = await asyncio.to_thread(
        _socks_https_get,
        https_url=https_url,
        socks_host="127.0.0.1",
        socks_port=1080,
        timeout_seconds=timeout_seconds,
    )
    if not 200 <= response.status_code < 300 or response.body != expected_nonce:
        raise RuntimeError("SOCKS HTTPS nonce proof failed")


async def state_wait(
    *,
    predicate: Callable[[], bool],
    timeout_seconds: float,
) -> float:
    """Wait for one cheap local proof and return its monotonic duration.

    Args:
        predicate: Readiness predicate.
        timeout_seconds: Timeout in seconds.

    Returns:
        Resulting float.
    """

    t_start = time.monotonic()
    while time.monotonic() - t_start < timeout_seconds:
        if predicate():
            return time.monotonic() - t_start
        await asyncio.sleep(0.1)
    raise TimeoutError("runtime state proof timed out")


def runtime_is_ready(runtime: GatewayRuntime) -> bool:
    """Return whether one production gateway currently reports ready.

    Args:
        runtime: Runtime under observation.

    Returns:
        Whether one production gateway currently reports ready.
    """

    return runtime.status.state is GatewayState.READY
