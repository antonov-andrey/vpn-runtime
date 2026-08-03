"""Safe lifecycle primitives for private Unix control sockets."""

import asyncio
from pathlib import Path
import stat


async def stale_control_socket_remove(*, socket_path: Path, owner_name: str) -> None:
    """Remove a dead prior socket without unlinking another live owner."""

    try:
        socket_stat = socket_path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(socket_stat.st_mode):
        raise ValueError(f"{owner_name} control socket path is not a Unix socket")
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(socket_path),
            timeout=1,
        )
        writer.write(b"\n")
        await writer.drain()
        response_line = await asyncio.wait_for(reader.readline(), timeout=1)
        if not response_line:
            raise OSError("live socket returned no ownership response")
    except ConnectionRefusedError, FileNotFoundError:
        socket_path.unlink(missing_ok=True)
        return
    except (OSError, TimeoutError) as error:
        raise ValueError(f"{owner_name} control socket ownership cannot be proven") from error
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
    raise ValueError(f"{owner_name} control socket is owned by a live process")
