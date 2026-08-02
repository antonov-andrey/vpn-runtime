"""Credentialless fail-closed TCP relay for stable run-local SOCKS endpoints."""

import argparse
import asyncio
from enum import StrEnum
import os
from pathlib import Path
import secrets
import signal
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StableProxyCommand(StrEnum):
    """Operations accepted by the private stable-proxy control socket."""

    DISABLE = "disable"
    SET_UPSTREAM = "set_upstream"
    STATUS = "status"


class StableProxyState(StrEnum):
    """User-plane state exposed through the private control protocol."""

    DISABLED = "disabled"
    READY = "ready"


class StableProxyStatus(BaseModel):
    """Exact runtime fence and current upstream state."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    generation: int = Field(ge=0)
    pod_uid: str = Field(min_length=1)
    runtime_instance_identity: str = Field(min_length=32, max_length=64)
    state: StableProxyState
    upstream_host: str = ""
    upstream_port: int = Field(default=0, ge=0, le=65535)


class StableProxyRequest(BaseModel):
    """Generation-fenced private control request."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    command: StableProxyCommand
    expected_pod_uid: str = Field(min_length=1)
    expected_runtime_instance_identity: str = Field(min_length=32, max_length=64)
    generation: int = Field(ge=0)
    upstream_host: str = ""
    upstream_port: int = Field(default=0, ge=0, le=65535)

    @model_validator(mode="after")
    def command_shape_validate(self) -> Self:
        """Require upstream fields only for exact-upstream mutation.

        Returns:
            Validated request.
        """

        have_upstream = bool(self.upstream_host) and self.upstream_port > 0
        if self.command is StableProxyCommand.SET_UPSTREAM and not have_upstream:
            raise ValueError("set_upstream requires one non-empty host and positive port")
        if self.command is not StableProxyCommand.SET_UPSTREAM and (self.upstream_host or self.upstream_port):
            raise ValueError("upstream fields are valid only for set_upstream")
        return self


class StableProxyResponse(BaseModel):
    """Closed response returned by the private control protocol."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    diagnostic: str = ""
    ok: bool
    status: StableProxyStatus


class StableProxyRuntime:
    """Own one disabled-by-default listener and atomic upstream fence."""

    def __init__(
        self,
        *,
        control_socket_path: Path,
        listen_host: str,
        listen_port: int,
        pod_uid: str,
        status_path: Path,
    ) -> None:
        """Bind immutable listener identity and create a new runtime fence.

        Args:
            control_socket_path: Private Unix control socket path.
            listen_host: TCP address exposed to exact run consumers.
            listen_port: TCP port exposed to exact run consumers.
            pod_uid: Exact Kubernetes Pod UID supplied through Downward API.
            status_path: Private non-secret bootstrap and current-status file.
        """

        if not pod_uid:
            raise ValueError("pod_uid must not be empty")
        if not 1 <= listen_port <= 65535:
            raise ValueError("listen_port must be within 1..65535")
        self._connection_writer_pair_by_identity_map: dict[int, list[asyncio.StreamWriter]] = {}
        self._control_server: asyncio.Server | None = None
        self._control_socket_path = control_socket_path
        self._generation = 0
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._listener_server: asyncio.Server | None = None
        self._mutation_lock = asyncio.Lock()
        self._mutation_epoch = 0
        self._next_connection_identity = 0
        self._pod_uid = pod_uid
        self._runtime_instance_identity = secrets.token_hex(16)
        self._status_path = status_path
        self._upstream_host = ""
        self._upstream_port = 0

    @property
    def status(self) -> StableProxyStatus:
        """Return the current immutable runtime fence and upstream state.

        Returns:
            Current stable-proxy status.
        """

        state = StableProxyState.READY if self._upstream_host else StableProxyState.DISABLED
        return StableProxyStatus(
            generation=self._generation,
            pod_uid=self._pod_uid,
            runtime_instance_identity=self._runtime_instance_identity,
            state=state,
            upstream_host=self._upstream_host,
            upstream_port=self._upstream_port,
        )

    async def close(self) -> None:
        """Disable traffic, close listeners, and remove the owned socket."""

        async with self._mutation_lock:
            writer_list = self._disable(generation=self._generation)
        await self._writer_list_close(writer_list)
        for server in [self._listener_server, self._control_server]:
            if server is not None:
                server.close()
                await server.wait_closed()
        self._listener_server = None
        self._control_server = None
        if self._control_socket_path.is_socket():
            self._control_socket_path.unlink()
        self._status_path.unlink(missing_ok=True)

    async def request_handle(self, request: StableProxyRequest) -> StableProxyResponse:
        """Apply one identity and generation-fenced control request.

        Args:
            request: Validated private control request.

        Returns:
            Exact operation result and current status.
        """

        async with self._mutation_lock:
            if request.expected_pod_uid != self._pod_uid:
                return StableProxyResponse(diagnostic="Pod UID fence mismatch", ok=False, status=self.status)
            if request.expected_runtime_instance_identity != self._runtime_instance_identity:
                return StableProxyResponse(
                    diagnostic="runtime instance fence mismatch",
                    ok=False,
                    status=self.status,
                )
            if request.generation < self._generation:
                return StableProxyResponse(
                    diagnostic="generation fence rejected stale request", ok=False, status=self.status
                )
            if request.command is StableProxyCommand.STATUS:
                if request.generation != self._generation:
                    return StableProxyResponse(
                        diagnostic="status generation does not match current generation",
                        ok=False,
                        status=self.status,
                    )
                return StableProxyResponse(ok=True, status=self.status)
            if request.command is StableProxyCommand.DISABLE:
                writer_list = self._disable(generation=request.generation)
                response = StableProxyResponse(ok=True, status=self.status)
            else:
                if request.generation == self._generation and self._upstream_host:
                    if (request.upstream_host, request.upstream_port) == (
                        self._upstream_host,
                        self._upstream_port,
                    ):
                        return StableProxyResponse(ok=True, status=self.status)
                    return StableProxyResponse(
                        diagnostic="equal generation cannot select a different upstream",
                        ok=False,
                        status=self.status,
                    )
                mutation_epoch = self._mutation_epoch
                writer_list = []
                response = None
        if response is not None:
            await self._writer_list_close(writer_list)
            return response
        return await self._upstream_set(request=request, expected_mutation_epoch=mutation_epoch)

    async def start(self) -> None:
        """Start the TCP listener and private mode-0600 control socket."""

        self._control_socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._control_socket_path.parent, 0o700)
        if self._control_socket_path.exists() or self._control_socket_path.is_symlink():
            raise ValueError("stable-proxy control socket path is not clean")
        self._listener_server = await asyncio.start_server(
            self._connection_handle,
            host=self._listen_host,
            port=self._listen_port,
        )
        self._control_server = await asyncio.start_unix_server(
            self._control_connection_handle,
            path=self._control_socket_path,
        )
        os.chmod(self._control_socket_path, 0o600)
        self._status_write()

    def _status_write(self) -> None:
        """Atomically persist the current non-secret runtime fence for controller discovery."""

        self._status_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._status_path.parent, 0o700)
        temporary_path = self._status_path.with_name(f".{self._status_path.name}.{os.getpid()}.tmp")
        with temporary_path.open("w", encoding="utf-8") as status_file:
            status_file.write(self.status.model_dump_json() + "\n")
            status_file.flush()
            os.fsync(status_file.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, self._status_path)
        directory_descriptor = os.open(self._status_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    async def _connection_handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Relay one accepted connection through the currently fenced upstream."""

        async with self._mutation_lock:
            upstream_host = self._upstream_host
            upstream_port = self._upstream_port
            mutation_epoch = self._mutation_epoch
        if not upstream_host:
            writer.close()
            await writer.wait_closed()
            return
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(upstream_host, upstream_port),
                timeout=5,
            )
        except OSError, TimeoutError:
            writer.close()
            await writer.wait_closed()
            return
        async with self._mutation_lock:
            is_overtaken = (
                mutation_epoch != self._mutation_epoch
                or upstream_host != self._upstream_host
                or upstream_port != self._upstream_port
            )
            if not is_overtaken:
                self._next_connection_identity += 1
                connection_identity = self._next_connection_identity
                self._connection_writer_pair_by_identity_map[connection_identity] = [writer, upstream_writer]
        if is_overtaken:
            writer.close()
            upstream_writer.close()
            await self._writer_list_close([writer, upstream_writer])
            return

        async def relay(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
            """Copy bounded chunks until one side closes."""

            while payload := await source.read(65536):
                destination.write(payload)
                await destination.drain()

        try:
            relay_task_list = [
                asyncio.create_task(relay(reader, upstream_writer)),
                asyncio.create_task(relay(upstream_reader, writer)),
            ]
            _, pending_task_set = await asyncio.wait(relay_task_list, return_when=asyncio.FIRST_COMPLETED)
            for pending_task in pending_task_set:
                pending_task.cancel()
            await asyncio.gather(*pending_task_set, return_exceptions=True)
        finally:
            self._connection_writer_pair_by_identity_map.pop(connection_identity, None)
            for connection_writer in [writer, upstream_writer]:
                connection_writer.close()
            await asyncio.gather(
                writer.wait_closed(),
                upstream_writer.wait_closed(),
                return_exceptions=True,
            )

    async def _control_connection_handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle one bounded newline-delimited JSON control request."""

        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            if not request_line or len(request_line) > 65536 or not request_line.endswith(b"\n"):
                raise ValueError("control request must be one bounded newline-terminated JSON document")
            request = StableProxyRequest.model_validate_json(request_line)
            response = await self.request_handle(request)
        except Exception as exc:
            response = StableProxyResponse(diagnostic=str(exc), ok=False, status=self.status)
        writer.write(response.model_dump_json().encode() + b"\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    def _disable(self, *, generation: int) -> list[asyncio.StreamWriter]:
        """Atomically clear upstream state and return every active relay writer."""

        self._mutation_epoch += 1
        self._generation = generation
        self._upstream_host = ""
        self._upstream_port = 0
        self._status_write()
        writer_list = [
            writer for writer_pair in self._connection_writer_pair_by_identity_map.values() for writer in writer_pair
        ]
        self._connection_writer_pair_by_identity_map.clear()
        for writer in writer_list:
            writer.close()
        return writer_list

    async def _upstream_set(
        self,
        *,
        expected_mutation_epoch: int,
        request: StableProxyRequest,
    ) -> StableProxyResponse:
        """Prove one exact upstream reachable before atomically publishing it."""

        try:
            _, proof_writer = await asyncio.wait_for(
                asyncio.open_connection(request.upstream_host, request.upstream_port),
                timeout=5,
            )
        except OSError, TimeoutError:
            return StableProxyResponse(diagnostic="upstream readiness proof failed", ok=False, status=self.status)
        proof_writer.close()
        await proof_writer.wait_closed()
        async with self._mutation_lock:
            if request.expected_pod_uid != self._pod_uid:
                return StableProxyResponse(diagnostic="Pod UID fence mismatch", ok=False, status=self.status)
            if request.expected_runtime_instance_identity != self._runtime_instance_identity:
                return StableProxyResponse(
                    diagnostic="runtime instance fence mismatch",
                    ok=False,
                    status=self.status,
                )
            if request.generation < self._generation:
                return StableProxyResponse(
                    diagnostic="generation fence rejected stale request", ok=False, status=self.status
                )
            if expected_mutation_epoch != self._mutation_epoch:
                return StableProxyResponse(
                    diagnostic="upstream proof was overtaken by another mutation",
                    ok=False,
                    status=self.status,
                )
            if request.generation == self._generation and self._upstream_host:
                if (request.upstream_host, request.upstream_port) == (
                    self._upstream_host,
                    self._upstream_port,
                ):
                    return StableProxyResponse(ok=True, status=self.status)
                return StableProxyResponse(
                    diagnostic="equal generation cannot select a different upstream",
                    ok=False,
                    status=self.status,
                )
            self._mutation_epoch += 1
            self._generation = request.generation
            self._upstream_host = request.upstream_host
            self._upstream_port = request.upstream_port
            self._status_write()
            return StableProxyResponse(ok=True, status=self.status)

    @staticmethod
    async def _writer_list_close(writer_list: list[asyncio.StreamWriter]) -> None:
        """Bound cleanup waiting after traffic has already been disabled atomically."""

        if not writer_list:
            return
        try:
            await asyncio.wait_for(
                asyncio.gather(*(writer.wait_closed() for writer in writer_list), return_exceptions=True),
                timeout=5,
            )
        except TimeoutError:
            return


async def stable_proxy_request_send(
    socket_path: Path,
    request: StableProxyRequest,
) -> StableProxyResponse:
    """Send one exact request to a private stable-proxy control socket.

    Args:
        socket_path: Private Unix socket path.
        request: Validated request payload.

    Returns:
        Validated stable-proxy response.
    """

    reader, writer = await asyncio.open_unix_connection(socket_path)
    writer.write(request.model_dump_json().encode() + b"\n")
    await writer.drain()
    response_line = await asyncio.wait_for(reader.readline(), timeout=10)
    writer.close()
    await writer.wait_closed()
    return StableProxyResponse.model_validate_json(response_line)


def _control_args_parse() -> argparse.Namespace:
    """Parse one stable-proxy control request."""

    parser = argparse.ArgumentParser(description="Control one exact stable fail-closed proxy runtime.")
    parser.add_argument("--expected-pod-uid", required=True)
    parser.add_argument("--expected-runtime-instance-identity", required=True)
    parser.add_argument("--generation", required=True, type=int)
    parser.add_argument("--socket-path", required=True, type=Path)
    parser.add_argument("--upstream-host", default="")
    parser.add_argument("--upstream-port", default=0, type=int)
    parser.add_argument("command", choices=list(StableProxyCommand), type=StableProxyCommand)
    return parser.parse_args()


def _daemon_args_parse() -> argparse.Namespace:
    """Parse stable-proxy listener and identity paths."""

    parser = argparse.ArgumentParser(description="Run one credentialless stable fail-closed SOCKS relay.")
    parser.add_argument("--control-socket-path", required=True, type=Path)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", default=1080, type=int)
    parser.add_argument("--pod-uid-path", required=True, type=Path)
    parser.add_argument("--status-path", required=True, type=Path)
    return parser.parse_args()


def _readiness_args_parse() -> argparse.Namespace:
    """Parse one private stable-proxy status-file path."""

    parser = argparse.ArgumentParser(description="Read one stable-proxy runtime fence.")
    parser.add_argument("--status-path", required=True, type=Path)
    return parser.parse_args()


def stable_proxy_control_main() -> None:
    """Send one control request and print its redacted response."""

    argument_by_name_map = vars(_control_args_parse())
    socket_path = argument_by_name_map.pop("socket_path")
    response = asyncio.run(stable_proxy_request_send(socket_path, StableProxyRequest(**argument_by_name_map)))
    print(response.model_dump_json(), flush=True)
    if not response.ok:
        raise SystemExit(1)


def stable_proxy_daemon_main() -> None:
    """Run a disabled-by-default stable proxy until operating-system stop."""

    argument_by_name_map = vars(_daemon_args_parse())
    pod_uid_path = argument_by_name_map.pop("pod_uid_path")
    pod_uid = pod_uid_path.read_text(encoding="utf-8").strip()

    async def run() -> None:
        """Own listener startup, signal handling, and final fail-closed cleanup."""

        runtime = StableProxyRuntime(pod_uid=pod_uid, **argument_by_name_map)
        await runtime.start()
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signal_number in [signal.SIGINT, signal.SIGTERM]:
            loop.add_signal_handler(signal_number, stop_event.set)
        try:
            await stop_event.wait()
        finally:
            await runtime.close()

    asyncio.run(run())


def stable_proxy_readiness_main() -> None:
    """Validate and print the current non-secret stable-proxy runtime fence."""

    status_path = _readiness_args_parse().status_path
    status = StableProxyStatus.model_validate_json(status_path.read_bytes())
    print(status.model_dump_json(), flush=True)
