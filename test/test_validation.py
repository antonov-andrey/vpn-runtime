"""Behavior tests for platform-owned production-image validation reports."""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from vpn_runtime.config import VpnProtocol
from vpn_runtime.gateway import (
    GatewayConfigurationError,
    GatewayState,
    GatewayStatus,
    GatewaySupervisorFailure,
)
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
        """Store runtime config and start prepared.

        Args:
            config: Validated runtime configuration.
        """

        self.config = config
        self._have_owned_processes = False
        self.status = GatewayStatus(
            diagnostic="",
            generation=0,
            state=GatewayState.PREPARED,
            t_update=datetime.now(timezone.utc),
        )

    async def activate(self, generation: int) -> None:
        """Represent successful production gateway activation.

        Args:
            generation: Generation.
        """

        self._have_owned_processes = True

    def have_owned_processes(self) -> bool:
        """Return synthetic child ownership state.

        Returns:
            The synthetic child ownership state.
        """

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
    """Require every platform-owned proof before returning a passed report.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    from vpn_runtime import validation

    call_count = 0
    timeout_second_list: list[int] = []

    def socks_https_get(**kwargs: object) -> SocksHttpsResponse:
        """Return exact nonce once, then fail after provider interruption.

        Args:
            **kwargs: Provider keyword arguments.

        Returns:
            The exact nonce once, then fail after provider interruption.
        """

        nonlocal call_count
        call_count += 1
        timeout_second_list.append(int(kwargs["timeout_seconds"]))
        if call_count == 1:
            return SocksHttpsResponse(body=b"private-nonce", status_code=200)
        raise ConnectionError("provider transport unavailable")

    monkeypatch.setattr(validation, "GatewayRuntime", FakeValidationGateway)
    monkeypatch.setattr(validation, "_socks_https_get", socks_https_get)

    report = asyncio.run(
        validation_run(
            config_root_path=tmp_path / "config",
            expected_nonce=b"private-nonce",
            fail_closed_probe_timeout_seconds=7,
            https_url="https://validation.example.test/nonce",
            nonce_https_timeout_seconds=23,
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=tmp_path / "runtime",
        )
    )

    assert report.status is ValidationStatus.PASSED
    assert report.phase is ValidationPhase.CLEANUP
    assert report.failure_kind == ""
    assert report.nonce_proven
    assert report.proxy_side_dns_proven
    assert report.fail_closed_proven
    assert report.clean_shutdown_proven
    assert timeout_second_list == [23, 7]


@pytest.mark.parametrize("field_name", ["fail_closed_probe_timeout_seconds", "nonce_https_timeout_seconds"])
def test_validation_rejects_nonpositive_probe_timeout(
    field_name: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Reject an invalid platform probe deadline before gateway activation.

    Args:
        field_name: Field name.
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    from vpn_runtime import validation

    monkeypatch.setattr(validation, "GatewayRuntime", FakeValidationGateway)
    argument_by_name_map = {
        "config_root_path": tmp_path / "config",
        "expected_nonce": b"private-nonce",
        "https_url": "https://validation.example.test/nonce",
        "protocol": VpnProtocol.OPENVPN,
        "runtime_root_path": tmp_path / "runtime",
        field_name: 0,
    }

    report = asyncio.run(validation_run(**argument_by_name_map))

    assert report.status is ValidationStatus.FAILED
    assert report.phase is ValidationPhase.STATIC
    assert report.failure_kind == ValidationFailureKind.CONFIGURATION
    assert report.diagnostic == "validation probe timeouts must be positive"


def test_validation_classifies_static_rejection_as_deterministic_configuration_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Separate an unsafe snapshot from retryable provider infrastructure failure.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    from vpn_runtime import validation

    class RejectedGateway:
        """Reject one snapshot during static prepared construction."""

        def __init__(self, config: object) -> None:
            """Raise the deterministic parser result.

            Args:
                config: Validated runtime configuration.
            """

            raise ValueError("unsafe OpenVPN directive: plugin")

    monkeypatch.setattr(validation, "GatewayRuntime", RejectedGateway)

    report = asyncio.run(
        validation_run(
            config_root_path=tmp_path / "config",
            expected_nonce=b"private-nonce",
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


def test_validation_static_report_excludes_invalid_document_credentials(tmp_path: Path) -> None:
    """Keep raw invalid document values out of the persisted validation diagnostic.

    Args:
        tmp_path: Temporary directory path.
    """

    config_root_path = tmp_path / "config"
    config_root_path.mkdir()
    config_root_path.joinpath("config.json").write_text(
        json.dumps(
            {
                "config_path": "provider.ovpn",
                "login": "sensitive-login\nline",
                "password": "sensitive-password",
            }
        ),
        encoding="utf-8",
    )

    report = asyncio.run(
        validation_run(
            config_root_path=config_root_path,
            expected_nonce=b"private-nonce",
            https_url="https://validation.example.test/ip",
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=tmp_path / "runtime",
        )
    )

    assert report.status is ValidationStatus.FAILED
    assert report.phase is ValidationPhase.STATIC
    assert report.failure_kind == ValidationFailureKind.CONFIGURATION
    assert report.diagnostic.startswith("invalid VPN config document: document:")
    assert "sensitive-login" not in report.diagnostic
    assert "sensitive-password" not in report.diagnostic
    assert not report.clean_shutdown_proven


def test_validation_classifies_proven_provider_rejection_as_configuration_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not retry forever when provider output proves the exact snapshot is invalid.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    from vpn_runtime import validation

    class ProviderRejectedGateway(FakeValidationGateway):
        """Fail exact activation with the runtime's deterministic error type."""

        async def activate(self, generation: int) -> None:
            """Raise one already-redacted provider rejection.

            Args:
                generation: Generation.
            """

            raise GatewayConfigurationError("AUTH_FAILED")

    monkeypatch.setattr(validation, "GatewayRuntime", ProviderRejectedGateway)

    report = asyncio.run(
        validation_run(
            config_root_path=tmp_path / "config",
            expected_nonce=b"private-nonce",
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


def test_validation_classifies_fail_closed_supervisor_failure_as_infrastructure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Retry a runtime supervisor failure instead of rejecting the immutable Version.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    from vpn_runtime import validation

    class SupervisorFailedGateway(FakeValidationGateway):
        """Fail while stopping the provider for the fail-closed proof."""

        async def provider_interrupt_for_validation(self) -> None:
            """Expose one already-redacted supervisor failure."""

            raise GatewaySupervisorFailure("owned process absence cannot be proved")

    monkeypatch.setattr(validation, "GatewayRuntime", SupervisorFailedGateway)
    monkeypatch.setattr(
        validation,
        "_socks_https_get",
        lambda **_kwargs: SocksHttpsResponse(body=b"private-nonce", status_code=200),
    )

    report = asyncio.run(
        validation_run(
            config_root_path=tmp_path / "config",
            expected_nonce=b"private-nonce",
            https_url="https://validation.example.test/nonce",
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=tmp_path / "runtime",
        )
    )

    assert report.status is ValidationStatus.FAILED
    assert report.phase is ValidationPhase.FAIL_CLOSED
    assert report.failure_kind == ValidationFailureKind.INFRASTRUCTURE
    assert report.diagnostic == "owned process absence cannot be proved"


def test_validation_cleanup_failure_overrides_deterministic_test_classification(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Treat an unproved cleanup as retryable even after a deterministic test failure.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    from vpn_runtime import validation

    class CleanupFailedGateway(FakeValidationGateway):
        """Fail the cleanup that follows a fail-closed assertion failure."""

        async def stop(self) -> None:
            """Expose one already-redacted cleanup failure."""

            raise GatewaySupervisorFailure("cleanup absence cannot be proved")

    call_count = 0

    def socks_https_get(**_kwargs: object) -> SocksHttpsResponse:
        """Return the nonce and then incorrectly remain reachable.

        Args:
            **_kwargs: Additional keyword arguments.

        Returns:
            A nonce that incorrectly remains reachable after validation.
        """

        nonlocal call_count
        call_count += 1
        return SocksHttpsResponse(body=b"private-nonce", status_code=200)

    monkeypatch.setattr(validation, "GatewayRuntime", CleanupFailedGateway)
    monkeypatch.setattr(validation, "_socks_https_get", socks_https_get)

    report = asyncio.run(
        validation_run(
            config_root_path=tmp_path / "config",
            expected_nonce=b"private-nonce",
            https_url="https://validation.example.test/nonce",
            protocol=VpnProtocol.OPENVPN,
            runtime_root_path=tmp_path / "runtime",
        )
    )

    assert report.status is ValidationStatus.FAILED
    assert report.phase is ValidationPhase.FAIL_CLOSED
    assert report.failure_kind == ValidationFailureKind.INFRASTRUCTURE
    assert "cleanup failed: cleanup absence cannot be proved" in report.diagnostic
