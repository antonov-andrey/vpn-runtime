"""Canonical validated timing contract for one VPN configuration Version."""

import argparse

CONNECTION_ATTEMPT_TIMEOUT_SECONDS_DEFAULT = 180
CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MINIMUM = 30
CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MAXIMUM = 900

PROVIDER_RECOVERY_GRACE_SECONDS_DEFAULT = 180
PROVIDER_RECOVERY_GRACE_SECONDS_MINIMUM = 90
PROVIDER_RECOVERY_GRACE_SECONDS_MAXIMUM = 900

PROCESS_STOP_TIMEOUT_SECONDS_DEFAULT = 30
PROCESS_STOP_TIMEOUT_SECONDS_MINIMUM = 30
PROCESS_STOP_TIMEOUT_SECONDS_MAXIMUM = 300

HEALTH_POLL_INTERVAL_SECONDS = 5.0
PROVIDER_RETRY_INITIAL_SECONDS = 1.0
PROVIDER_RETRY_MAXIMUM_SECONDS = 300.0


def _bounded_integer_parse(*, maximum: int, minimum: int, name: str, value: str) -> int:
    """Parse one CLI integer and enforce its platform safety range."""

    try:
        parsed_value = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name} must be an integer") from exc
    if not minimum <= parsed_value <= maximum:
        raise argparse.ArgumentTypeError(f"{name} must be between {minimum} and {maximum}")
    return parsed_value


def connection_attempt_timeout_seconds_parse(value: str) -> int:
    """Parse one provider-attempt deadline from the CLI."""

    return _bounded_integer_parse(
        maximum=CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MAXIMUM,
        minimum=CONNECTION_ATTEMPT_TIMEOUT_SECONDS_MINIMUM,
        name="connection_attempt_timeout_seconds",
        value=value,
    )


def process_stop_timeout_seconds_parse(value: str) -> int:
    """Parse one common graceful process-session deadline from the CLI."""

    return _bounded_integer_parse(
        maximum=PROCESS_STOP_TIMEOUT_SECONDS_MAXIMUM,
        minimum=PROCESS_STOP_TIMEOUT_SECONDS_MINIMUM,
        name="process_stop_timeout_seconds",
        value=value,
    )


def provider_recovery_grace_seconds_parse(value: str) -> int:
    """Parse one current-provider recovery grace from the CLI."""

    return _bounded_integer_parse(
        maximum=PROVIDER_RECOVERY_GRACE_SECONDS_MAXIMUM,
        minimum=PROVIDER_RECOVERY_GRACE_SECONDS_MINIMUM,
        name="provider_recovery_grace_seconds",
        value=value,
    )
