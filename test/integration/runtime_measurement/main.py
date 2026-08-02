"""Run and atomically report the complete real VPN runtime measurement suite."""

import argparse
import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
import platform

from runtime_measurement.gateway import GatewayMeasurement
from runtime_measurement.model import RuntimeMeasurementReport
from runtime_measurement.process import forced_process_stop_get
from runtime_measurement.stable_proxy import stable_proxy_switch_restart_get
from vpn_runtime.timing import (
    CONNECTION_ATTEMPT_TIMEOUT_SECONDS_DEFAULT,
    PROCESS_STOP_TIMEOUT_SECONDS_DEFAULT,
    PROVIDER_RECOVERY_GRACE_SECONDS_DEFAULT,
    connection_attempt_timeout_seconds_parse,
    process_stop_timeout_seconds_parse,
    provider_recovery_grace_seconds_parse,
)


def _args_parse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Measure the production VPN runtime on one real target node.")
    parser.add_argument("--config-root-path", required=True, type=Path)
    parser.add_argument(
        "--connection-attempt-timeout-seconds",
        default=CONNECTION_ATTEMPT_TIMEOUT_SECONDS_DEFAULT,
        type=connection_attempt_timeout_seconds_parse,
    )
    parser.add_argument("--expected-nonce-path", required=True, type=Path)
    parser.add_argument("--https-url-path", required=True, type=Path)
    parser.add_argument("--image-identity", required=True)
    parser.add_argument(
        "--process-stop-timeout-seconds",
        default=PROCESS_STOP_TIMEOUT_SECONDS_DEFAULT,
        type=process_stop_timeout_seconds_parse,
    )
    parser.add_argument(
        "--provider-recovery-grace-seconds",
        default=PROVIDER_RECOVERY_GRACE_SECONDS_DEFAULT,
        type=provider_recovery_grace_seconds_parse,
    )
    parser.add_argument("--report-path", required=True, type=Path)
    parser.add_argument("--round-count", default=3, type=int)
    parser.add_argument("--runtime-root-path", required=True, type=Path)
    return parser.parse_args()


async def _run(argument_by_name_map: dict[str, object]) -> RuntimeMeasurementReport:
    t_start = datetime.now(timezone.utc)
    image_identity = str(argument_by_name_map.pop("image_identity"))
    report_path = Path(argument_by_name_map.pop("report_path"))
    round_count = int(argument_by_name_map.pop("round_count"))
    runtime_root_path = Path(argument_by_name_map["runtime_root_path"])
    measurement = GatewayMeasurement(**argument_by_name_map)
    sample_list = []
    diagnostic = ""
    status = "passed"
    scenario_name = "activation"
    try:
        sample_list.extend(await measurement.activation_sample_list_get(round_count=round_count))
        scenario_name = "provider_blackhole_recovery"
        sample_list.append(await measurement.provider_blackhole_recovery_get())
        scenario_name = "provider_dns_change_replacement"
        sample_list.append(await measurement.provider_dns_change_replacement_get())
        scenario_name = "invalid_authentication"
        sample_list.append(await measurement.invalid_authentication_get())
        scenario_name = "forced_process_stop"
        sample_list.append(
            await forced_process_stop_get(
                config_root_path=Path(argument_by_name_map["config_root_path"]),
                process_stop_timeout_seconds=int(argument_by_name_map["process_stop_timeout_seconds"]),
                runtime_root_path=runtime_root_path / "forced-process-stop",
            )
        )
        scenario_name = "stable_proxy_switch_restart"
        sample_list.append(await stable_proxy_switch_restart_get(runtime_root_path=runtime_root_path / "stable-proxy"))
    except Exception as exc:
        status = "failed"
        diagnostic = f"{type(exc).__name__}: {scenario_name} measurement failed"
    report = RuntimeMeasurementReport(
        architecture=platform.machine(),
        diagnostic=diagnostic,
        image_identity=image_identity,
        sample_list=sample_list,
        status=status,
        t_complete=datetime.now(timezone.utc),
        t_start=t_start,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_report_path = report_path.with_name(f".{report_path.name}.{os.getpid()}.tmp")
    with temporary_report_path.open("w", encoding="utf-8") as report_file:
        report_file.write(report.model_dump_json() + "\n")
        report_file.flush()
        os.fsync(report_file.fileno())
    os.chmod(temporary_report_path, 0o600)
    os.replace(temporary_report_path, report_path)
    return report


def main() -> None:
    argument_by_name_map = vars(_args_parse())
    argument_by_name_map["expected_nonce"] = argument_by_name_map.pop("expected_nonce_path").read_bytes()
    argument_by_name_map["https_url"] = argument_by_name_map.pop("https_url_path").read_text(encoding="utf-8").strip()
    report = asyncio.run(_run(argument_by_name_map))
    print(report.model_dump_json(), flush=True)
    if report.status != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
