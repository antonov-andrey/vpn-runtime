"""Real provider activation, recovery, DNS-change, and authentication measurements."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from typing import Any

from vpn_runtime.gateway import GatewayConfigurationError, GatewayRuntime, GatewayState
from vpn_runtime.timing import (
    HEALTH_POLL_INTERVAL_SECONDS,
    PROVIDER_RETRY_INITIAL_SECONDS,
)

from runtime_measurement.common import gateway_get, nonce_probe, runtime_is_ready, state_wait
from runtime_measurement.model import MeasurementSample


class GatewayMeasurement:
    """Run sequential real-tunnel scenarios that share the fixed gateway ports."""

    def __init__(
        self,
        *,
        config_root_path: Path,
        connection_attempt_timeout_seconds: int,
        expected_nonce: bytes,
        https_url: str,
        process_stop_timeout_seconds: int,
        provider_recovery_grace_seconds: int,
        runtime_root_path: Path,
    ) -> None:
        self._config_root_path = config_root_path
        self._connection_attempt_timeout_seconds = connection_attempt_timeout_seconds
        self._expected_nonce = expected_nonce
        self._https_url = https_url
        self._process_stop_timeout_seconds = process_stop_timeout_seconds
        self._provider_recovery_grace_seconds = provider_recovery_grace_seconds
        self._runtime_root_path = runtime_root_path

    async def activation_sample_list_get(self, *, round_count: int) -> list[MeasurementSample]:
        """Measure one cold and repeated warm provider starts plus graceful stops."""

        sample_list: list[MeasurementSample] = []
        for round_number in range(1, round_count + 1):
            runtime = self._gateway_get(suffix=f"activation-{round_number}")
            activation_start = time.monotonic()
            try:
                await runtime.activate(generation=round_number)
                activation_duration = time.monotonic() - activation_start
                await nonce_probe(expected_nonce=self._expected_nonce, https_url=self._https_url)
            finally:
                stop_start = time.monotonic()
                await runtime.stop()
                stop_duration = time.monotonic() - stop_start
            sample_list.extend(
                [
                    MeasurementSample(
                        detail_by_name_map={"round": round_number},
                        duration_seconds=activation_duration,
                        name="cold_activation" if round_number == 1 else "warm_activation",
                    ),
                    MeasurementSample(
                        detail_by_name_map={"clean_shutdown_proven": not runtime.have_owned_processes()},
                        duration_seconds=stop_duration,
                        name="graceful_stop",
                    ),
                ]
            )
        return sample_list

    async def provider_blackhole_recovery_get(self) -> MeasurementSample:
        """Block tunnel traffic, prove fail-closed, then prove same-attempt recovery."""

        runtime = self._gateway_get(suffix="blackhole-recovery")
        rule_argument_list = [
            "OUTPUT",
            "-o",
            "tun0",
            "-m",
            "comment",
            "--comment",
            "vpn-runtime-measurement-blackhole",
            "-j",
            "DROP",
        ]
        rule_is_installed = False
        try:
            await runtime.activate(generation=1)
            initial_attempt_number = runtime._provider_attempt_number
            self._iptables_run(["-I", *rule_argument_list])
            rule_is_installed = True
            t_start = time.monotonic()
            await state_wait(
                predicate=lambda: runtime.status.state is GatewayState.RECONNECTING,
                timeout_seconds=(self._provider_recovery_grace_seconds + 2 * HEALTH_POLL_INTERVAL_SECONDS),
            )
            fail_closed_proven = await _socks_failure_prove()
            self._iptables_run(["-D", *rule_argument_list])
            rule_is_installed = False
            await state_wait(
                predicate=lambda: runtime_is_ready(runtime),
                timeout_seconds=(
                    self._provider_recovery_grace_seconds
                    + self._connection_attempt_timeout_seconds
                    + 2 * HEALTH_POLL_INTERVAL_SECONDS
                ),
            )
            duration_seconds = time.monotonic() - t_start
            await nonce_probe(expected_nonce=self._expected_nonce, https_url=self._https_url)
            return MeasurementSample(
                detail_by_name_map={
                    "fail_closed_proven": fail_closed_proven,
                    "same_attempt_recovered": runtime._provider_attempt_number == initial_attempt_number,
                },
                duration_seconds=duration_seconds,
                name="provider_blackhole_recovery",
            )
        finally:
            if rule_is_installed:
                self._iptables_run(["-D", *rule_argument_list], check=False)
            await runtime.stop()

    async def provider_dns_change_replacement_get(self) -> MeasurementSample:
        """Inject one changed unreachable DNS answer, then prove a fresh successful attempt."""

        runtime = gateway_get(
            config_root_path=self._config_root_path,
            connection_attempt_timeout_seconds=self._connection_attempt_timeout_seconds,
            process_stop_timeout_seconds=self._process_stop_timeout_seconds,
            provider_recovery_grace_seconds=self._provider_recovery_grace_seconds,
            runtime_root_path=self._scenario_root_get("dns-change-replacement"),
        )
        original_resolver = runtime._remote_ip_by_hostname_map_get
        resolver_call_count = 0

        async def changing_resolver() -> dict[str, str]:
            nonlocal resolver_call_count
            resolver_call_count += 1
            if resolver_call_count == 2:
                return {hostname: "192.0.2.1" for hostname in runtime._snapshot.remote_hostname_list}
            return await original_resolver()

        runtime._remote_ip_by_hostname_map_get = changing_resolver  # type: ignore[method-assign]
        try:
            await runtime.activate(generation=1)
            gluetun_process = runtime._gluetun_process
            if gluetun_process is None or gluetun_process.returncode is not None:
                raise RuntimeError("provider process is unavailable for replacement injection")
            t_start = time.monotonic()
            os.killpg(gluetun_process.pid, signal.SIGKILL)
            await state_wait(
                predicate=lambda: resolver_call_count >= 3 and runtime_is_ready(runtime),
                timeout_seconds=self._attempt_replacement_observation_timeout_seconds_get(),
            )
            duration_seconds = time.monotonic() - t_start
            await nonce_probe(expected_nonce=self._expected_nonce, https_url=self._https_url)
            return MeasurementSample(
                detail_by_name_map={
                    "fresh_dns_resolution_count": resolver_call_count,
                    "unreachable_attempt_replaced": resolver_call_count >= 3,
                },
                duration_seconds=duration_seconds,
                name="dns_change_attempt_replacement",
            )
        finally:
            await runtime.stop()

    async def invalid_authentication_get(self) -> MeasurementSample:
        """Measure deterministic invalid-auth rejection using a private snapshot copy."""

        scenario_root_path = self._scenario_root_get("invalid-authentication")
        config_root_path = scenario_root_path / "input"
        shutil.copytree(self._config_root_path, config_root_path)
        config_path = config_root_path / "config.json"
        config_document: dict[str, Any] = json.loads(config_path.read_text(encoding="utf-8"))
        if not config_document.get("login"):
            raise RuntimeError("accepted measurement snapshot does not use provider authentication")
        config_document["password"] = "invalid-measurement-password"
        os.chmod(config_path, 0o600)
        config_path.write_text(json.dumps(config_document, separators=(",", ":")) + "\n", encoding="utf-8")
        os.chmod(config_path, 0o400)
        runtime = gateway_get(
            config_root_path=config_root_path,
            connection_attempt_timeout_seconds=30,
            process_stop_timeout_seconds=self._process_stop_timeout_seconds,
            provider_recovery_grace_seconds=self._provider_recovery_grace_seconds,
            runtime_root_path=scenario_root_path / "runtime",
        )
        t_start = time.monotonic()
        deterministic_failure_proven = False
        try:
            await runtime.activate(generation=1)
        except GatewayConfigurationError:
            deterministic_failure_proven = True
        finally:
            await runtime.stop()
        if not deterministic_failure_proven:
            raise RuntimeError("invalid provider authentication was not classified deterministically")
        return MeasurementSample(
            detail_by_name_map={"deterministic_failure_proven": True},
            duration_seconds=time.monotonic() - t_start,
            name="invalid_authentication_rejection",
        )

    def _gateway_get(self, *, suffix: str) -> GatewayRuntime:
        return gateway_get(
            config_root_path=self._config_root_path,
            connection_attempt_timeout_seconds=self._connection_attempt_timeout_seconds,
            process_stop_timeout_seconds=self._process_stop_timeout_seconds,
            provider_recovery_grace_seconds=self._provider_recovery_grace_seconds,
            runtime_root_path=self._scenario_root_get(suffix),
        )

    def _iptables_run(self, argument_list: list[str], *, check: bool = True) -> None:
        result = subprocess.run(
            ["/usr/sbin/iptables", *argument_list],
            capture_output=True,
            check=False,
            text=True,
        )
        if check and result.returncode != 0:
            raise RuntimeError("failed to apply the measurement network fault")

    def _scenario_root_get(self, suffix: str) -> Path:
        return self._runtime_root_path / suffix

    def _attempt_replacement_observation_timeout_seconds_get(self) -> float:
        """Cover one unreachable attempt and the following successful attempt."""

        return (
            2 * self._connection_attempt_timeout_seconds
            + 2 * self._process_stop_timeout_seconds
            + 3 * HEALTH_POLL_INTERVAL_SECONDS
            + 3 * PROVIDER_RETRY_INITIAL_SECONDS
        )


async def _socks_failure_prove() -> bool:
    """Prove that SOCKS cannot establish an upstream TCP connection."""

    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", 1080), timeout=3)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        method_response = await asyncio.wait_for(reader.readexactly(2), timeout=3)
        if method_response != b"\x05\x00":
            return True
        writer.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x01\xbb")
        await writer.drain()
        connect_response = await asyncio.wait_for(reader.readexactly(4), timeout=3)
        return connect_response[1] != 0
    except OSError, TimeoutError, asyncio.IncompleteReadError:
        return True
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
