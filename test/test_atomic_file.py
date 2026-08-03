"""Behavior tests for crash-safe private runtime file replacement."""

import os
from pathlib import Path

import pytest

import vpn_runtime.atomic_file as atomic_file_module
from vpn_runtime.atomic_file import atomic_bytes_write


def test_atomic_bytes_write_does_not_follow_a_predictable_legacy_temporary_symlink(tmp_path: Path) -> None:
    """Random exclusive staging must not reuse the former PID-only path.

    Args:
        tmp_path: Temporary directory path.
    """

    target_path = tmp_path / "status.json"
    victim_path = tmp_path / "victim"
    victim_path.write_bytes(b"unchanged")
    target_path.with_name(f".{target_path.name}.{os.getpid()}.tmp").symlink_to(victim_path)

    atomic_bytes_write(target_path, b"current\n")

    assert target_path.read_bytes() == b"current\n"
    assert victim_path.read_bytes() == b"unchanged"
    assert target_path.stat().st_mode & 0o777 == 0o600


def test_atomic_bytes_write_removes_staging_file_after_failed_replace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A failed publication must not leave an ambiguous candidate behind.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    target_path = tmp_path / "status.json"

    def replace_fail(_source: Path, _target: Path) -> None:
        """Inject the exact atomic-rename failure under test.

        Args:
            _source: Source filesystem path.
            _target: Target filesystem path.
        """

        raise OSError("simulated replace failure")

    monkeypatch.setattr(atomic_file_module.os, "replace", replace_fail)

    with pytest.raises(OSError, match="simulated replace failure"):
        atomic_bytes_write(target_path, b"candidate\n")

    assert not target_path.exists()
    assert [path.name for path in tmp_path.iterdir()] == []
