"""Contract tests for VPN Version timing defaults, ranges, and CLI parsing."""

import argparse
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from vpn_runtime.config import VpnProtocol
from vpn_runtime.gateway import GatewayConfig
from vpn_runtime.timing import (
    CONNECTION_ATTEMPT_TIMEOUT_SECONDS_DEFAULT,
    CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MAXIMUM,
    CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MINIMUM,
    PROCESS_STOP_TIMEOUT_SECONDS_DEFAULT,
    PROCESS_STOP_TIMEOUT_SECONDS_MAXIMUM,
    PROCESS_STOP_TIMEOUT_SECONDS_MINIMUM,
    PROVIDER_RECOVERY_GRACE_SECONDS_DEFAULT,
    PROVIDER_RECOVERY_GRACE_SECONDS_MAXIMUM,
    PROVIDER_RECOVERY_GRACE_SECONDS_MINIMUM,
    connection_attempt_timeout_seconds_parse,
    process_stop_timeout_seconds_parse,
    provider_recovery_grace_seconds_parse,
)


def _gateway_config_get(tmp_path: Path, **overrides: int) -> GatewayConfig:
    """Build one configuration at the exact production validation boundary.

    Args:
        tmp_path: Temporary directory path.
        **overrides: Additional keyword arguments.

    Returns:
        One configuration at the exact production validation boundary.
    """

    return GatewayConfig(
        config_root_path=tmp_path / "config",
        protocol=VpnProtocol.OPENVPN,
        runtime_root_path=tmp_path / "runtime",
        **overrides,
    )


def test_timing_defaults_and_range_edges_are_accepted(tmp_path: Path) -> None:
    """Materialize approved defaults and both edges of every safety range.

    Args:
        tmp_path: Temporary directory path.
    """

    default_config = _gateway_config_get(tmp_path)
    assert default_config.connection_attempt_timeout_seconds == CONNECTION_ATTEMPT_TIMEOUT_SECONDS_DEFAULT
    assert default_config.provider_recovery_grace_seconds == PROVIDER_RECOVERY_GRACE_SECONDS_DEFAULT
    assert default_config.process_stop_timeout_seconds == PROCESS_STOP_TIMEOUT_SECONDS_DEFAULT

    minimum_config = _gateway_config_get(
        tmp_path,
        connection_attempt_timeout_seconds=CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MINIMUM,
        process_stop_timeout_seconds=PROCESS_STOP_TIMEOUT_SECONDS_MINIMUM,
        provider_recovery_grace_seconds=PROVIDER_RECOVERY_GRACE_SECONDS_MINIMUM,
    )
    maximum_config = _gateway_config_get(
        tmp_path,
        connection_attempt_timeout_seconds=CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MAXIMUM,
        process_stop_timeout_seconds=PROCESS_STOP_TIMEOUT_SECONDS_MAXIMUM,
        provider_recovery_grace_seconds=PROVIDER_RECOVERY_GRACE_SECONDS_MAXIMUM,
    )
    assert minimum_config.connection_attempt_timeout_seconds == CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MINIMUM
    assert maximum_config.connection_attempt_timeout_seconds == CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MAXIMUM


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("connection_attempt_timeout_seconds", CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MINIMUM - 1),
        ("connection_attempt_timeout_seconds", CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MAXIMUM + 1),
        ("provider_recovery_grace_seconds", PROVIDER_RECOVERY_GRACE_SECONDS_MINIMUM - 1),
        ("provider_recovery_grace_seconds", PROVIDER_RECOVERY_GRACE_SECONDS_MAXIMUM + 1),
        ("process_stop_timeout_seconds", PROCESS_STOP_TIMEOUT_SECONDS_MINIMUM - 1),
        ("process_stop_timeout_seconds", PROCESS_STOP_TIMEOUT_SECONDS_MAXIMUM + 1),
    ],
)
def test_gateway_config_rejects_timing_outside_safety_range(
    field_name: str,
    tmp_path: Path,
    value: int,
) -> None:
    """Reject resource-ownership deadlines outside the platform contract.

    Args:
        field_name: Field name.
        tmp_path: Temporary directory path.
        value: Candidate value.
    """

    with pytest.raises(ValidationError):
        _gateway_config_get(tmp_path, **{field_name: value})


@pytest.mark.parametrize(
    ("parser", "minimum", "maximum"),
    [
        (
            connection_attempt_timeout_seconds_parse,
            CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MINIMUM,
            CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MAXIMUM,
        ),
        (
            provider_recovery_grace_seconds_parse,
            PROVIDER_RECOVERY_GRACE_SECONDS_MINIMUM,
            PROVIDER_RECOVERY_GRACE_SECONDS_MAXIMUM,
        ),
        (
            process_stop_timeout_seconds_parse,
            PROCESS_STOP_TIMEOUT_SECONDS_MINIMUM,
            PROCESS_STOP_TIMEOUT_SECONDS_MAXIMUM,
        ),
    ],
)
def test_cli_timing_parser_uses_same_range(
    parser: Callable[[str], int],
    minimum: int,
    maximum: int,
) -> None:
    """Keep shell entrypoints on the same strict bounds as the runtime model.

    Args:
        parser: Parser.
        minimum: Minimum.
        maximum: Maximum.
    """

    assert parser(str(minimum)) == minimum
    assert parser(str(maximum)) == maximum
    with pytest.raises(argparse.ArgumentTypeError):
        parser(str(minimum - 1))
    with pytest.raises(argparse.ArgumentTypeError):
        parser(str(maximum + 1))
