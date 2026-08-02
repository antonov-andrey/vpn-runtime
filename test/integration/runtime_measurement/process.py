"""Real process-group stop deadline measurement."""

import asyncio
from pathlib import Path
import sys
import time

from runtime_measurement.common import gateway_get
from runtime_measurement.model import MeasurementSample


async def forced_process_stop_get(
    *,
    config_root_path: Path,
    process_stop_timeout_seconds: int,
    runtime_root_path: Path,
) -> MeasurementSample:
    """Prove SIGKILL fallback for one process group that ignores SIGTERM."""

    runtime = gateway_get(
        config_root_path=config_root_path,
        connection_attempt_timeout_seconds=180,
        process_stop_timeout_seconds=process_stop_timeout_seconds,
        provider_recovery_grace_seconds=180,
        runtime_root_path=runtime_root_path,
    )
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)",
        start_new_session=True,
    )
    await asyncio.sleep(0.2)
    t_start = time.monotonic()
    await runtime._process_list_stop(
        [process],
        asyncio.get_running_loop().time() + process_stop_timeout_seconds,
    )
    duration_seconds = time.monotonic() - t_start
    if process.returncode is None:
        raise RuntimeError("forced process stop did not prove wrapper exit")
    return MeasurementSample(
        detail_by_name_map={"sigkill_fallback_proven": True},
        duration_seconds=duration_seconds,
        name="forced_process_stop",
    )
