"""Behavior tests for platform-owned production-image validation reports."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vpn_runtime.config import VpnProtocol
from vpn_runtime.gateway import GatewayConfigurationError, GatewayState, GatewayStatus
from vpn_runtime.validation import (
    SocksHttpsResponse,
    ValidationFailureKind,
    ValidationPhase,
    ValidationStatus,
    validation_run,
)


class FakeValidationGateway:
    """Successful exact gateway lifecycle used by validation behavior tests."""

    def __init__(self, config: object) -> None:
        """Store runtime config and start prepared."""

        self.config = config
        self._have_owned_processes = False
        self.status = GatewayStatus(
            diagnostic="",
            generation=0,
            state=GatewayState.PREPARED,
            t_update=datetime.now(timezone.utc),
        )

    async def activate(self, generation: int) -> None:
        """Represent successful production gateway activation."""

        self._have_owned_processes = True

    def have_owned_processes(self) -> bool:
        """Return synthetic child ownership state."""

        return self._have_owned_processes

    async def provider_interrupt_for_validation(self) -> None:
        """Represent exact provider transport loss."""

    async def stop(self) -> None:
        """Prove synthetic child cleanup."""

        self._have_owned_processes = False


def test_validation_passes_only_after_https_dns_fail_closed_and_cleanup_proofs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Require every platform-owned proof before returning a passed report."""

    from vpn_runtime import validation

    call_count = 0

    def socks_https_get(**kwargs: object) -> SocksHttpsResponse:
        """Return observed egress once, then fail after provider interruption."""

        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return SocksHttpsResponse(body=b'{"ip":"198.51.100.20"}', status_code=200)
        raise ConnectionError("provider transport unavailable")

    monkeypatch.setattr(validation, "GatewayRuntime", FakeValidationGateway)
    monkeypatch.setattr(validation, "_socks_https_get", socks_https_get)

    report = asyncio.run(
        validation_run(
            config_root_path=tmp_path / "config",
            https_url="https://validation.example.test/ip",
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=tmp_path / "runtime",
        )
    )

    assert report.status is ValidationStatus.PASSED
    assert report.phase is ValidationPhase.CLEANUP
    assert report.failure_kind == ""
    assert report.observed_exit_ip == "198.51.100.20"
    assert report.proxy_side_dns_proven
    assert report.fail_closed_proven
    assert report.clean_shutdown_proven


def test_validation_classifies_static_rejection_as_deterministic_configuration_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Separate an unsafe snapshot from retryable provider infrastructure failure."""

    from vpn_runtime import validation

    class RejectedGateway:
        """Reject one snapshot during static prepared construction."""

        def __init__(self, config: object) -> None:
            """Raise the deterministic parser result."""

            raise ValueError("unsafe OpenVPN directive: plugin")

    monkeypatch.setattr(validation, "GatewayRuntime", RejectedGateway)

    report = asyncio.run(
        validation_run(
            config_root_path=tmp_path / "config",
            https_url="https://validation.example.test/ip",
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=tmp_path / "runtime",
        )
    )

    assert report.status is ValidationStatus.FAILED
    assert report.phase is ValidationPhase.STATIC
    assert report.failure_kind == ValidationFailureKind.CONFIGURATION
    assert report.diagnostic == "unsafe OpenVPN directive: plugin"
    assert not report.clean_shutdown_proven


def test_validation_classifies_proven_provider_rejection_as_configuration_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not retry forever when provider output proves the exact snapshot is invalid."""

    from vpn_runtime import validation

    class ProviderRejectedGateway(FakeValidationGateway):
        """Fail exact activation with the runtime's deterministic error type."""

        async def activate(self, generation: int) -> None:
            """Raise one already-redacted provider rejection."""

            raise GatewayConfigurationError("AUTH_FAILED")

    monkeypatch.setattr(validation, "GatewayRuntime", ProviderRejectedGateway)

    report = asyncio.run(
        validation_run(
            config_root_path=tmp_path / "config",
            https_url="https://validation.example.test/ip",
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=tmp_path / "runtime",
        )
    )

    assert report.status is ValidationStatus.FAILED
    assert report.phase is ValidationPhase.ACTIVATION
    assert report.failure_kind == ValidationFailureKind.CONFIGURATION
    assert report.diagnostic == "AUTH_FAILED"
    assert report.clean_shutdown_proven
