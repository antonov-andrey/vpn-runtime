"""Crash-safe atomic replacement for private runtime state files."""

from __future__ import annotations

import os
from pathlib import Path
import secrets


def atomic_bytes_write(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    """Replace one file after syncing its bytes and containing directory."""

    temporary_path = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    open_flag = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        open_flag |= os.O_NOFOLLOW
    descriptor = os.open(temporary_path, open_flag, mode)
    try:
        with os.fdopen(descriptor, "wb") as temporary_file:
            descriptor = -1
            temporary_file.write(payload)
            temporary_file.flush()
            os.fchmod(temporary_file.fileno(), mode)
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
