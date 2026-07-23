"""Strict immutable VPN snapshot parsing and attempt-local materialization."""

from enum import StrEnum
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import stat
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator, model_validator

_OPENVPN_DANGEROUS_DIRECTIVE_SET = {
    "askpass",
    "auth-gen-token-secret",
    "auth-user-pass-verify",
    "cd",
    "chroot",
    "client-connect",
    "client-disconnect",
    "config",
    "daemon",
    "down",
    "down-pre",
    "ipchange",
    "learn-address",
    "log",
    "log-append",
    "management",
    "management-client",
    "management-external-cert",
    "management-external-key",
    "management-hold",
    "management-query-passwords",
    "plugin",
    "route-pre-down",
    "route-up",
    "script-security",
    "secret",
    "status",
    "syslog",
    "tls-export-cert",
    "tls-verify",
    "up",
    "up-delay",
    "up-restart",
    "writepid",
}
_OPENVPN_FILE_DIRECTIVE_SET = {
    "ca",
    "cert",
    "crl-verify",
    "dh",
    "extra-certs",
    "key",
    "pkcs12",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
}
_OPENVPN_INLINE_BLOCK_SET = {
    "ca",
    "cert",
    "extra-certs",
    "key",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
}


class VpnProtocol(StrEnum):
    """Protocols implemented by exact runtime adapters."""

    OPENVPN = "openvpn"


class VpnSnapshotDocument(BaseModel):
    """Protocol-neutral fields stored in one immutable VPN snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)

    config_path: str
    login: SecretStr = Field(default=SecretStr(""), repr=False)
    password: SecretStr = Field(default=SecretStr(""), repr=False)

    @field_validator("config_path")
    @classmethod
    def config_path_validate(cls, config_path: str) -> str:
        """Require one contained relative POSIX file path.

        Args:
            config_path: Candidate configuration path.

        Returns:
            Validated unchanged path.
        """

        relative_path = PurePosixPath(config_path)
        if (
            not config_path
            or relative_path.is_absolute()
            or "\\" in config_path
            or any(path_part in {"", ".", ".."} for path_part in relative_path.parts)
        ):
            raise ValueError("config_path must be one contained relative POSIX file path")
        return config_path

    @model_validator(mode="after")
    def credential_pair_validate(self) -> Self:
        """Require both credentials to be present or both to be empty.

        Returns:
            Validated document.
        """

        login = self.login.get_secret_value()
        password = self.password.get_secret_value()
        if bool(login) != bool(password):
            raise ValueError("login and password must both be non-empty or both be empty")
        if any(character in login or character in password for character in ["\0", "\n", "\r"]):
            raise ValueError("login and password must each fit on one credential-file line")
        return self


class OpenvpnAttempt(BaseModel):
    """Attempt-local OpenVPN configuration and credential file paths."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    authentication_path: Path | None
    config_path: Path
    password_path: Path | None
    user_path: Path | None


class OpenvpnSnapshot(BaseModel):
    """Validated exact OpenVPN source tree with mutation-detection digests."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    config_relative_path: Path
    config_root_path: Path
    document: VpnSnapshotDocument = Field(repr=False)
    file_sha256_by_relative_path_map: dict[str, str] = Field(repr=False)
    remote_hostname_list: list[str]

    @classmethod
    def from_root(cls, config_root_path: Path) -> Self:
        """Validate and fingerprint one complete read-only snapshot root.

        Args:
            config_root_path: Directory containing `config.json` and referenced files.

        Returns:
            Validated exact snapshot.

        Raises:
            ValueError: If the tree, document, or OpenVPN configuration is unsafe.
        """

        if config_root_path.is_symlink() or not config_root_path.is_dir():
            raise ValueError("VPN config root must be one real directory")
        file_sha256_by_relative_path_map = _snapshot_file_sha256_by_relative_path_map_get(config_root_path)
        if "config.json" not in file_sha256_by_relative_path_map:
            raise ValueError("VPN config root must contain config.json")
        try:
            document_payload = json.loads(config_root_path.joinpath("config.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"failed to parse VPN config document: {exc}") from exc
        try:
            document = VpnSnapshotDocument.model_validate(document_payload)
        except ValidationError as exc:
            diagnostic_list = []
            for error in exc.errors(include_context=False, include_input=False, include_url=False):
                location = error["loc"]
                field_name = (
                    location[0] if location and location[0] in {"config_path", "login", "password"} else "document"
                )
                diagnostic_list.append(f"{field_name}:{error['type']}")
            raise ValueError(f"invalid VPN config document: {'; '.join(diagnostic_list)}") from None
        config_relative_path = Path(document.config_path)
        config_path = config_root_path / config_relative_path
        if config_relative_path.suffix.lower() not in {".conf", ".ovpn"}:
            raise ValueError("OpenVPN config_path must end with .conf or .ovpn")
        if document.config_path not in file_sha256_by_relative_path_map:
            raise ValueError(f"OpenVPN config file is missing: {document.config_path}")
        config_line_list = _openvpn_config_line_list_get(
            config_path=config_path,
            materialized_root_path=None,
            document=document,
            remote_ip_by_hostname_map=None,
        )
        return cls(
            config_relative_path=config_relative_path,
            config_root_path=config_root_path,
            document=document,
            file_sha256_by_relative_path_map=file_sha256_by_relative_path_map,
            remote_hostname_list=_openvpn_remote_hostname_list_get(config_line_list),
        )

    def attempt_materialize(
        self,
        attempt_root_path: Path,
        remote_ip_by_hostname_map: dict[str, str] | None = None,
    ) -> OpenvpnAttempt:
        """Copy and rewrite the validated snapshot into one private attempt root.

        Args:
            attempt_root_path: New private runtime directory for one provider attempt.
            remote_ip_by_hostname_map: Runtime-resolved IP address for every remote hostname.

        Returns:
            Absolute rewritten OpenVPN configuration and credential paths.

        Raises:
            ValueError: If source bytes changed after validation.
        """

        current_file_sha256_by_relative_path_map = _snapshot_file_sha256_by_relative_path_map_get(self.config_root_path)
        if current_file_sha256_by_relative_path_map != self.file_sha256_by_relative_path_map:
            raise ValueError("VPN source snapshot changed after validation")
        if attempt_root_path.exists():
            raise ValueError(f"attempt root already exists: {attempt_root_path}")
        snapshot_root_path = attempt_root_path / "snapshot"
        shutil.copytree(self.config_root_path, snapshot_root_path, symlinks=False)
        os.chmod(attempt_root_path, 0o700)
        for directory_path, directory_name_list, filename_list in os.walk(snapshot_root_path):
            os.chmod(directory_path, 0o700)
            for directory_name in directory_name_list:
                os.chmod(Path(directory_path) / directory_name, 0o700)
            for filename in filename_list:
                os.chmod(Path(directory_path) / filename, 0o600)
        private_root_path = attempt_root_path / "private"
        private_root_path.mkdir(mode=0o700)
        config_path = snapshot_root_path / self.config_relative_path
        config_line_list = _openvpn_config_line_list_get(
            config_path=config_path,
            materialized_root_path=snapshot_root_path,
            document=self.document,
            remote_ip_by_hostname_map=remote_ip_by_hostname_map,
        )
        config_path.write_text("\n".join(config_line_list) + "\n", encoding="utf-8")
        os.chmod(config_path, 0o600)
        authentication_path: Path | None = None
        password_path: Path | None = None
        user_path: Path | None = None
        if self.document.login.get_secret_value():
            authentication_path = private_root_path / "openvpn-auth.txt"
            password_path = private_root_path / "openvpn-password.txt"
            user_path = private_root_path / "openvpn-user.txt"
        return OpenvpnAttempt(
            authentication_path=authentication_path,
            config_path=config_path,
            password_path=password_path,
            user_path=user_path,
        )


def _openvpn_config_line_list_get(
    *,
    config_path: Path,
    materialized_root_path: Path | None,
    document: VpnSnapshotDocument,
    remote_ip_by_hostname_map: dict[str, str] | None,
) -> list[str]:
    """Validate OpenVPN directives and optionally render attempt-local paths.

    Args:
        config_path: Exact source or copied OpenVPN configuration file.
        materialized_root_path: Attempt-local snapshot root, or `None` for static validation.
        document: Protocol-neutral snapshot document.
        remote_ip_by_hostname_map: Runtime-resolved IP address for every remote hostname.

    Returns:
        Validated source lines or materialized rewritten lines.
    """

    try:
        source_line_list = config_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"failed to read OpenVPN config: {exc}") from exc
    config_root_path = config_path.parents[len(Path(document.config_path).parts) - 1]
    rendered_line_list: list[str] = []
    inline_block_name: str | None = None
    auth_user_pass_count = 0
    for line_number, source_line in enumerate(source_line_list, start=1):
        stripped_line = source_line.strip()
        if inline_block_name is not None:
            rendered_line_list.append(source_line)
            if stripped_line == f"</{inline_block_name}>":
                inline_block_name = None
            elif stripped_line.startswith("<"):
                raise ValueError(f"nested OpenVPN inline block at line {line_number}")
            continue
        if stripped_line.startswith("<"):
            if not stripped_line.endswith(">") or stripped_line.startswith("</"):
                raise ValueError(f"invalid OpenVPN inline block at line {line_number}")
            inline_block_name = stripped_line[1:-1].lower()
            if inline_block_name not in _OPENVPN_INLINE_BLOCK_SET:
                raise ValueError(f"unsupported OpenVPN inline block at line {line_number}: {inline_block_name}")
            rendered_line_list.append(source_line)
            continue
        if not stripped_line or stripped_line.startswith(("#", ";")):
            rendered_line_list.append(source_line)
            continue
        try:
            token_list = shlex.split(source_line, comments=True, posix=True)
        except ValueError as exc:
            raise ValueError(f"invalid OpenVPN syntax at line {line_number}: {exc}") from exc
        if not token_list:
            rendered_line_list.append(source_line)
            continue
        directive_name = token_list[0].lower()
        argument_list = token_list[1:]
        if directive_name in _OPENVPN_DANGEROUS_DIRECTIVE_SET:
            raise ValueError(f"unsafe OpenVPN directive at line {line_number}: {directive_name}")
        if directive_name == "auth-user-pass":
            auth_user_pass_count += 1
            if argument_list:
                raise ValueError("OpenVPN auth-user-pass must not reference an external credential path")
            if not document.login.get_secret_value():
                raise ValueError("OpenVPN auth-user-pass requires login and password in config.json")
            if materialized_root_path is None:
                rendered_line_list.append(source_line)
            continue
        if directive_name == "remote":
            if not argument_list:
                raise ValueError(f"OpenVPN remote is missing a host at line {line_number}")
            try:
                ipaddress.ip_address(argument_list[0])
            except ValueError:
                _openvpn_remote_hostname_validate(argument_list[0], line_number)
                if materialized_root_path is not None:
                    if remote_ip_by_hostname_map is None or argument_list[0] not in remote_ip_by_hostname_map:
                        raise ValueError(
                            f"OpenVPN remote hostname has no runtime-resolved IP address at line {line_number}"
                        )
                    resolved_ip = remote_ip_by_hostname_map[argument_list[0]]
                    try:
                        ipaddress.ip_address(resolved_ip)
                    except ValueError as exc:
                        raise ValueError(
                            f"OpenVPN remote hostname has an invalid runtime-resolved IP address at line {line_number}"
                        ) from exc
                    token_list[1] = resolved_ip
                    source_line = shlex.join(token_list)
        if directive_name in _OPENVPN_FILE_DIRECTIVE_SET:
            if not argument_list:
                raise ValueError(f"OpenVPN {directive_name} is missing a file path at line {line_number}")
            source_reference = argument_list[0]
            if source_reference != "[inline]":
                reference_relative_path = PurePosixPath(source_reference)
                if (
                    reference_relative_path.is_absolute()
                    or "\\" in source_reference
                    or any(path_part in {"", ".", ".."} for path_part in reference_relative_path.parts)
                ):
                    raise ValueError(
                        f"OpenVPN {directive_name} path must stay relative to the snapshot at line {line_number}"
                    )
                reference_path = config_root_path / Path(source_reference)
                if reference_path.is_symlink() or not reference_path.is_file():
                    raise ValueError(f"OpenVPN referenced file is missing or unsafe at line {line_number}")
                if materialized_root_path is not None:
                    token_list[1] = str(materialized_root_path / Path(source_reference))
                    source_line = shlex.join(token_list)
        rendered_line_list.append(source_line)
    if inline_block_name is not None:
        raise ValueError(f"unterminated OpenVPN inline block: {inline_block_name}")
    if auth_user_pass_count > 1:
        raise ValueError("OpenVPN config must not declare auth-user-pass more than once")
    if materialized_root_path is not None and document.login.get_secret_value():
        authentication_path = materialized_root_path.parent / "private" / "openvpn-auth.txt"
        password_path = materialized_root_path.parent / "private" / "openvpn-password.txt"
        user_path = materialized_root_path.parent / "private" / "openvpn-user.txt"
        authentication_path.write_text(
            f"{document.login.get_secret_value()}\n{document.password.get_secret_value()}",
            encoding="utf-8",
        )
        password_path.write_text(document.password.get_secret_value(), encoding="utf-8")
        user_path.write_text(document.login.get_secret_value(), encoding="utf-8")
        for credential_path in [authentication_path, password_path, user_path]:
            os.chmod(credential_path, 0o600)
        rendered_line_list.append(f"auth-user-pass {shlex.quote(str(authentication_path))}")
        rendered_line_list.append("auth-nocache")
    return rendered_line_list


def _openvpn_remote_hostname_list_get(config_line_list: list[str]) -> list[str]:
    """Return unique remote hostnames in source order from validated lines.

    Args:
        config_line_list: Validated OpenVPN source lines.

    Returns:
        Unique remote hostnames.
    """

    remote_hostname_list: list[str] = []
    inline_block_name: str | None = None
    for config_line in config_line_list:
        stripped_line = config_line.strip()
        if inline_block_name is not None:
            if stripped_line == f"</{inline_block_name}>":
                inline_block_name = None
            continue
        if stripped_line.startswith("<") and stripped_line.endswith(">") and not stripped_line.startswith("</"):
            inline_block_name = stripped_line[1:-1].lower()
            continue
        token_list = shlex.split(config_line, comments=True, posix=True)
        if not token_list or token_list[0].lower() != "remote":
            continue
        remote_host = token_list[1]
        try:
            ipaddress.ip_address(remote_host)
        except ValueError:
            if remote_host not in remote_hostname_list:
                remote_hostname_list.append(remote_host)
    return remote_hostname_list


def _openvpn_remote_hostname_validate(remote_hostname: str, line_number: int) -> None:
    """Require one syntactically valid DNS hostname without resolving it.

    Args:
        remote_hostname: Candidate OpenVPN remote hostname.
        line_number: One-based source line number for diagnostics.
    """

    normalized_hostname = remote_hostname.removesuffix(".")
    try:
        encoded_hostname = normalized_hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"OpenVPN remote hostname is invalid at line {line_number}") from exc
    label_list = encoded_hostname.split(".")
    if (
        not normalized_hostname
        or len(encoded_hostname) > 253
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in label_list
        )
    ):
        raise ValueError(f"OpenVPN remote hostname is invalid at line {line_number}")


def _snapshot_file_sha256_by_relative_path_map_get(config_root_path: Path) -> dict[str, str]:
    """Validate a real-file-only tree and return deterministic content digests.

    Args:
        config_root_path: Exact snapshot root.

    Returns:
        SHA-256 digest by transparent POSIX relative path.
    """

    file_sha256_by_relative_path_map: dict[str, str] = {}
    for directory_path, directory_name_list, filename_list in os.walk(config_root_path, followlinks=False):
        directory_name_list.sort()
        filename_list.sort()
        for entry_name in [*directory_name_list, *filename_list]:
            entry_path = Path(directory_path) / entry_name
            entry_mode = entry_path.lstat().st_mode
            if stat.S_ISLNK(entry_mode) or not (stat.S_ISDIR(entry_mode) or stat.S_ISREG(entry_mode)):
                raise ValueError(f"VPN snapshot contains an unsafe filesystem entry: {entry_name}")
        for filename in filename_list:
            file_path = Path(directory_path) / filename
            relative_path = file_path.relative_to(config_root_path).as_posix()
            file_sha256_by_relative_path_map[relative_path] = hashlib.sha256(file_path.read_bytes()).hexdigest()
    return file_sha256_by_relative_path_map
