"""Behavior tests for exact OpenVPN snapshot validation and materialization."""

import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from vpn_runtime.config import OpenvpnSnapshot


def _snapshot_create(
    tmp_path: Path,
    *,
    config_text: str = "client\nremote 203.0.113.10 1194\nca ca.crt\nauth-user-pass\n",
    login: str = "vpn-user",
    password: str = "vpn-password",
) -> Path:
    """Create one minimal exact OpenVPN snapshot.

    Args:
        tmp_path: Temporary test root.
        config_text: OpenVPN source text.
        login: Optional provider login.
        password: Optional provider password.

    Returns:
        Snapshot root path.
    """

    config_root_path = tmp_path / "vpn-config"
    config_root_path.mkdir()
    config_root_path.joinpath("config.json").write_text(
        json.dumps(
            {
                "config_path": "provider.ovpn",
                "login": login,
                "password": password,
            }
        ),
        encoding="utf-8",
    )
    config_root_path.joinpath("provider.ovpn").write_text(config_text, encoding="utf-8")
    config_root_path.joinpath("ca.crt").write_text("certificate\n", encoding="utf-8")
    return config_root_path


def test_openvpn_snapshot_materializes_private_attempt_without_mutating_source(tmp_path: Path) -> None:
    """Rewrite contained paths and credentials only in a mode-0600 attempt copy."""

    config_root_path = _snapshot_create(tmp_path)
    source_config_text = config_root_path.joinpath("provider.ovpn").read_text(encoding="utf-8")
    snapshot = OpenvpnSnapshot.from_root(config_root_path)

    openvpn_attempt = snapshot.attempt_materialize(tmp_path / "runtime" / "generation_7")

    materialized_config_path = openvpn_attempt.config_path
    materialized_config_text = materialized_config_path.read_text(encoding="utf-8")
    authentication_path = openvpn_attempt.authentication_path
    assert authentication_path is not None
    assert openvpn_attempt.password_path is not None
    assert openvpn_attempt.user_path is not None
    assert config_root_path.joinpath("provider.ovpn").read_text(encoding="utf-8") == source_config_text
    assert f"ca {materialized_config_path.parent / 'ca.crt'}" in materialized_config_text
    assert f"auth-user-pass {authentication_path}" in materialized_config_text
    assert "auth-nocache" in materialized_config_text
    assert authentication_path.read_text(encoding="utf-8") == "vpn-user\nvpn-password"
    assert openvpn_attempt.password_path.read_text(encoding="utf-8") == "vpn-password"
    assert openvpn_attempt.user_path.read_text(encoding="utf-8") == "vpn-user"
    assert stat_mode_get(authentication_path) == 0o600
    assert stat_mode_get(materialized_config_path) == 0o600
    assert stat_mode_get(openvpn_attempt.password_path) == 0o600
    assert stat_mode_get(openvpn_attempt.user_path) == 0o600


def stat_mode_get(path: Path) -> int:
    """Return only Unix permission bits for one path.

    Args:
        path: Filesystem path to inspect.

    Returns:
        Permission bits.
    """

    return os.stat(path).st_mode & 0o777


@pytest.mark.parametrize(
    "document_payload",
    [
        {"config_path": "/provider.ovpn", "login": "", "password": ""},
        {"config_path": "../provider.ovpn", "login": "", "password": ""},
        {"config_path": "provider.ovpn", "login": "only-login", "password": ""},
        {"config_path": "provider.ovpn", "login": "", "password": "only-password"},
        {"config_path": "provider.ovpn", "login": "vpn-user\nother", "password": "vpn-password"},
        {"config_path": "provider.ovpn", "login": "vpn-user", "password": "vpn-password\r\nother"},
        {"config_path": "provider.ovpn", "login": None, "password": None},
    ],
)
def test_openvpn_snapshot_rejects_invalid_protocol_neutral_document(
    tmp_path: Path,
    document_payload: dict[str, object],
) -> None:
    """Reject path escape, null credentials, and incomplete credential pairs."""

    config_root_path = _snapshot_create(tmp_path)
    config_root_path.joinpath("config.json").write_text(json.dumps(document_payload), encoding="utf-8")

    with pytest.raises((ValidationError, ValueError)):
        OpenvpnSnapshot.from_root(config_root_path)


@pytest.mark.parametrize(
    "unsafe_directive",
    [
        "up /tmp/hook.sh",
        "down /tmp/hook.sh",
        "plugin /tmp/plugin.so",
        "script-security 2",
        "management 0.0.0.0 7505",
        "config other.conf",
        "log /tmp/openvpn.log",
    ],
)
def test_openvpn_snapshot_rejects_executable_and_external_control_directives(
    tmp_path: Path,
    unsafe_directive: str,
) -> None:
    """Reject provider directives that execute code or create an external control surface."""

    config_root_path = _snapshot_create(
        tmp_path,
        config_text=f"client\nremote 203.0.113.10 1194\n{unsafe_directive}\n",
        login="",
        password="",
    )

    with pytest.raises(ValueError, match="unsafe OpenVPN directive"):
        OpenvpnSnapshot.from_root(config_root_path)


@pytest.mark.parametrize(
    "config_text",
    [
        "client\nremote vpn.example.test 1194\n",
        "client\nremote 203.0.113.10 1194\nca /outside/ca.crt\n",
        "client\nremote 203.0.113.10 1194\nca ../ca.crt\n",
        "client\nremote 203.0.113.10 1194\nauth-user-pass credentials.txt\n",
        "client\nremote 203.0.113.10 1194\n<connection>\nremote 203.0.113.11 1194\n</connection>\n",
    ],
)
def test_openvpn_snapshot_rejects_leaky_bootstrap_and_escaping_references(
    tmp_path: Path,
    config_text: str,
) -> None:
    """Reject DNS bootstrap leaks, escaping paths, credential files, and unsupported blocks."""

    config_root_path = _snapshot_create(tmp_path, config_text=config_text)

    with pytest.raises(ValueError):
        OpenvpnSnapshot.from_root(config_root_path)


def test_openvpn_snapshot_rejects_symlink_anywhere_in_source_tree(tmp_path: Path) -> None:
    """Reject symlinks even when the OpenVPN file does not reference them."""

    config_root_path = _snapshot_create(tmp_path)
    config_root_path.joinpath("linked-ca.crt").symlink_to(config_root_path / "ca.crt")

    with pytest.raises(ValueError, match="unsafe filesystem entry"):
        OpenvpnSnapshot.from_root(config_root_path)


def test_openvpn_snapshot_detects_source_mutation_before_attempt(tmp_path: Path) -> None:
    """Refuse materialization if any exact source byte changes after validation."""

    config_root_path = _snapshot_create(tmp_path)
    snapshot = OpenvpnSnapshot.from_root(config_root_path)
    config_root_path.joinpath("ca.crt").write_text("changed\n", encoding="utf-8")

    with pytest.raises(ValueError, match="changed after validation"):
        snapshot.attempt_materialize(tmp_path / "runtime" / "generation_1")


def test_openvpn_snapshot_accepts_inline_certificate_and_certificate_only_authentication(tmp_path: Path) -> None:
    """Allow contained inline material and a provider that needs no login pair."""

    config_root_path = _snapshot_create(
        tmp_path,
        config_text=(
            "client\n"
            "remote 203.0.113.10 1194\n"
            "<ca>\n"
            "-----BEGIN CERTIFICATE-----\n"
            "certificate\n"
            "-----END CERTIFICATE-----\n"
            "</ca>\n"
        ),
        login="",
        password="",
    )

    snapshot = OpenvpnSnapshot.from_root(config_root_path)
    openvpn_attempt = snapshot.attempt_materialize(tmp_path / "runtime" / "generation_1")

    assert "<ca>" in openvpn_attempt.config_path.read_text(encoding="utf-8")
    assert openvpn_attempt.authentication_path is None
    assert openvpn_attempt.password_path is None
    assert openvpn_attempt.user_path is None
    assert not openvpn_attempt.config_path.parents[1].joinpath("private/openvpn-auth.txt").exists()
