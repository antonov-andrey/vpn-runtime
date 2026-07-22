"""Platform-owned real gateway validation using the production runtime lifecycle."""

import argparse
import asyncio
from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from vpn_runtime.config import VpnProtocol
from vpn_runtime.gateway import GatewayConfig, GatewayConfigurationError, GatewayRuntime


class ValidationFailureKind(StrEnum):
    """Stable retry classification for one unsuccessful validation."""

    CONFIGURATION = "configuration"
    INFRASTRUCTURE = "infrastructure"
    TEST = "test"


class ValidationPhase(StrEnum):
    """Current or final platform-owned validation phase."""

    ACTIVATION = "activation"
    CLEANUP = "cleanup"
    FAIL_CLOSED = "fail_closed"
    PROXY_HTTPS = "proxy_https"
    STATIC = "static"


class ValidationStatus(StrEnum):
    """Final result of one exact image and snapshot validation."""

    FAILED = "failed"
    PASSED = "passed"


class ValidationReport(BaseModel):
    """Redacted exact-snapshot validation evidence returned to the platform."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    clean_shutdown_proven: bool
    diagnostic: str
    failure_kind: str
    fail_closed_proven: bool
    observed_exit_ip: str
    phase: ValidationPhase
    proxy_side_dns_proven: bool
    status: ValidationStatus
    t_complete: datetime
    t_start: datetime


class SocksHttpsResponse(BaseModel):
    """Bounded HTTPS response observed through an exact SOCKS5 listener."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    body: bytes
    status_code: int


def _bytes_exact_receive(connection: socket.socket, byte_count: int) -> bytes:
    """Receive exactly the requested byte count or fail on early EOF.

    Args:
        connection: Connected blocking socket.
        byte_count: Exact required byte count.

    Returns:
        Received bytes.
    """

    payload = bytearray()
    while len(payload) < byte_count:
        chunk = connection.recv(byte_count - len(payload))
        if not chunk:
            raise ConnectionError("SOCKS5 connection closed before the response completed")
        payload.extend(chunk)
    return bytes(payload)


def _observed_exit_ip_get(body: bytes) -> str:
    """Extract one valid observed client IP from a controlled endpoint response.

    Args:
        body: Bounded response body.

    Returns:
        Canonical observed IP address.
    """

    body_text = body.decode(encoding="utf-8").strip()
    candidate_list: list[str] = []
    try:
        payload = json.loads(body_text)
    except json.JSONDecodeError:
        candidate_list.append(body_text)
    else:
        if isinstance(payload, dict):
            for field_name in ["ip", "origin"]:
                field_value = payload.get(field_name)
                if isinstance(field_value, str):
                    candidate_list.extend(value.strip() for value in field_value.split(","))
    for candidate in candidate_list:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    raise ValueError("controlled HTTPS endpoint did not return one valid observed IP address")


def _socks_https_get(*, https_url: str, socks_host: str, socks_port: int, timeout_seconds: int) -> SocksHttpsResponse:
    """Perform one HTTPS request using SOCKS5 domain-name target addressing.

    Args:
        https_url: Controlled HTTPS observation URL.
        socks_host: Run-local SOCKS listener host.
        socks_port: Run-local SOCKS listener port.
        timeout_seconds: Socket and TLS operation timeout.

    Returns:
        Bounded response status and body.
    """

    split_url = urlsplit(https_url)
    if (
        split_url.scheme != "https"
        or split_url.hostname is None
        or split_url.username is not None
        or split_url.password is not None
        or split_url.fragment
    ):
        raise ValueError("validation URL must be one credential-free HTTPS URL")
    target_hostname = split_url.hostname
    target_hostname_bytes = target_hostname.encode("idna")
    if len(target_hostname_bytes) > 255:
        raise ValueError("validation HTTPS hostname is too long for SOCKS5")
    target_port = split_url.port or 443
    request_path = split_url.path or "/"
    if split_url.query:
        request_path += f"?{split_url.query}"
    with socket.create_connection((socks_host, socks_port), timeout=timeout_seconds) as connection:
        connection.settimeout(timeout_seconds)
        connection.sendall(b"\x05\x01\x00")
        if _bytes_exact_receive(connection, 2) != b"\x05\x00":
            raise ConnectionError("SOCKS5 listener rejected unauthenticated negotiation")
        connection.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(target_hostname_bytes)])
            + target_hostname_bytes
            + target_port.to_bytes(2, byteorder="big")
        )
        response_header = _bytes_exact_receive(connection, 4)
        if response_header[:2] != b"\x05\x00":
            raise ConnectionError(f"SOCKS5 target connection failed with reply code {response_header[1]}")
        address_type = response_header[3]
        if address_type == 1:
            _bytes_exact_receive(connection, 4)
        elif address_type == 3:
            _bytes_exact_receive(connection, _bytes_exact_receive(connection, 1)[0])
        elif address_type == 4:
            _bytes_exact_receive(connection, 16)
        else:
            raise ConnectionError(f"SOCKS5 listener returned unsupported address type {address_type}")
        _bytes_exact_receive(connection, 2)
        tls_context = ssl.create_default_context()
        with tls_context.wrap_socket(connection, server_hostname=target_hostname) as tls_connection:
            tls_connection.sendall(
                (
                    f"GET {request_path} HTTP/1.1\r\n"
                    f"Host: {target_hostname}\r\n"
                    "Accept: application/json,text/plain\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
            )
            response_bytes = bytearray()
            while len(response_bytes) <= 1024 * 1024:
                response_chunk = tls_connection.recv(64 * 1024)
                if not response_chunk:
                    break
                response_bytes.extend(response_chunk)
            if len(response_bytes) > 1024 * 1024:
                raise ValueError("validation HTTPS response exceeds 1 MiB")
    response_head, separator, response_body = bytes(response_bytes).partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("validation HTTPS endpoint returned an invalid response")
    status_line = response_head.split(b"\r\n", maxsplit=1)[0]
    status_part_list = status_line.split(b" ", maxsplit=2)
    if len(status_part_list) < 2 or not status_part_list[1].isdigit():
        raise ValueError("validation HTTPS endpoint returned an invalid status line")
    return SocksHttpsResponse(body=response_body, status_code=int(status_part_list[1]))


async def validation_run(
    *,
    config_root_path: Path,
    https_url: str,
    protocol: VpnProtocol,
    runtime_root_path: Path,
) -> ValidationReport:
    """Validate one exact snapshot through the same gateway used in production.

    Args:
        config_root_path: Exact immutable VPN source snapshot.
        https_url: Platform-owned HTTPS observation endpoint.
        protocol: Exact protocol adapter.
        runtime_root_path: Private validation runtime root.

    Returns:
        Complete redacted validation report.
    """

    t_start = datetime.now(timezone.utc)
    phase = ValidationPhase.STATIC
    gateway: GatewayRuntime | None = None
    clean_shutdown_proven = False
    fail_closed_proven = False
    observed_exit_ip = ""
    proxy_side_dns_proven = False
    try:
        gateway = GatewayRuntime(
            GatewayConfig(
                config_root_path=config_root_path,
                protocol=protocol,
                runtime_root_path=runtime_root_path,
            )
        )
        phase = ValidationPhase.ACTIVATION
        await gateway.activate(generation=1)
        phase = ValidationPhase.PROXY_HTTPS
        https_response = await asyncio.to_thread(
            _socks_https_get,
            https_url=https_url,
            socks_host="127.0.0.1",
            socks_port=gateway.config.socks_port,
            timeout_seconds=15,
        )
        if not 200 <= https_response.status_code < 300:
            raise ValueError(f"controlled HTTPS endpoint returned status {https_response.status_code}")
        observed_exit_ip = _observed_exit_ip_get(https_response.body)
        proxy_side_dns_proven = True
        phase = ValidationPhase.FAIL_CLOSED
        await gateway.provider_interrupt_for_validation()
        await asyncio.sleep(gateway.config.reconnect_poll_seconds * 2)
        try:
            await asyncio.to_thread(
                _socks_https_get,
                https_url=https_url,
                socks_host="127.0.0.1",
                socks_port=gateway.config.socks_port,
                timeout_seconds=3,
            )
        except OSError, TimeoutError, ConnectionError:
            fail_closed_proven = True
        if not fail_closed_proven:
            raise ValueError("SOCKS5 target request succeeded while provider transport was unavailable")
        phase = ValidationPhase.CLEANUP
        await gateway.stop()
        clean_shutdown_proven = not gateway.have_owned_processes() and not any(runtime_root_path.glob("generation_*"))
        if not clean_shutdown_proven:
            raise RuntimeError("gateway cleanup left an owned process or generated attempt root")
        return ValidationReport(
            clean_shutdown_proven=True,
            diagnostic="",
            failure_kind="",
            fail_closed_proven=True,
            observed_exit_ip=observed_exit_ip,
            phase=phase,
            proxy_side_dns_proven=True,
            status=ValidationStatus.PASSED,
            t_complete=datetime.now(timezone.utc),
            t_start=t_start,
        )
    except Exception as exc:
        diagnostic = str(exc)
        failure_kind = ValidationFailureKind.TEST
        if phase is ValidationPhase.STATIC:
            failure_kind = ValidationFailureKind.CONFIGURATION
        elif phase is ValidationPhase.ACTIVATION:
            failure_kind = (
                ValidationFailureKind.CONFIGURATION
                if isinstance(exc, GatewayConfigurationError)
                else ValidationFailureKind.INFRASTRUCTURE
            )
        elif phase is ValidationPhase.PROXY_HTTPS:
            failure_kind = ValidationFailureKind.INFRASTRUCTURE
        if gateway is not None:
            try:
                await gateway.stop()
            except Exception as cleanup_exc:
                diagnostic = f"{diagnostic}; cleanup failed: {cleanup_exc}"
            clean_shutdown_proven = not gateway.have_owned_processes() and not any(
                runtime_root_path.glob("generation_*")
            )
        return ValidationReport(
            clean_shutdown_proven=clean_shutdown_proven,
            diagnostic=diagnostic,
            failure_kind=failure_kind,
            fail_closed_proven=fail_closed_proven,
            observed_exit_ip=observed_exit_ip,
            phase=phase,
            proxy_side_dns_proven=proxy_side_dns_proven,
            status=ValidationStatus.FAILED,
            t_complete=datetime.now(timezone.utc),
            t_start=t_start,
        )


def _args_parse() -> argparse.Namespace:
    """Parse exact validation input and report paths."""

    parser = argparse.ArgumentParser(description="Validate one exact VPN snapshot with the production gateway image.")
    parser.add_argument("--config-root-path", required=True, type=Path)
    parser.add_argument("--https-url", required=True)
    parser.add_argument("--protocol", choices=list(VpnProtocol), required=True, type=VpnProtocol)
    parser.add_argument("--report-path", required=True, type=Path)
    parser.add_argument("--runtime-root-path", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    """Run validation, atomically persist its report, and fail for a rejected Version."""

    argument_by_name_map = vars(_args_parse())
    report_path = argument_by_name_map.pop("report_path")
    report = asyncio.run(validation_run(**argument_by_name_map))
    report_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_report_path = report_path.with_name(f".{report_path.name}.{os.getpid()}.tmp")
    temporary_report_path.write_text(report.model_dump_json() + "\n", encoding="utf-8")
    os.chmod(temporary_report_path, 0o600)
    os.replace(temporary_report_path, report_path)
    print(report.model_dump_json(), flush=True)
    if report.status is not ValidationStatus.PASSED:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
