"""Generation-fenced Unix-socket control daemon and shell-free CLI."""

import argparse
import asyncio
from enum import StrEnum
import os
from pathlib import Path
import signal
import stat
import sys

from pydantic import BaseModel, ConfigDict, Field

from vpn_runtime.config import VpnProtocol
from vpn_runtime.gateway import GatewayConfig, GatewayRuntime, GatewayState, GatewayStatus


class ControlCommand(StrEnum):
    """Commands accepted by the private exact-Pod control socket."""

    ACTIVATE = "activate"
    STATUS = "status"
    STOP = "stop"


class ControlRequest(BaseModel):
    """One exact generation-fenced local control request."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    command: ControlCommand
    generation: int = Field(ge=1)


class ControlResponse(BaseModel):
    """Redacted response returned by the local control daemon."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    error: str = ""
    ok: bool
    status: GatewayStatus


class ControlDaemon:
    """Own generation fencing, durable status, and one prepared gateway runtime."""

    def __init__(
        self,
        *,
        gateway_config: GatewayConfig,
        socket_path: Path,
        state_path: Path,
    ) -> None:
        """Load the highest durable generation without opening a provider connection.

        Args:
            gateway_config: Exact gateway process and snapshot configuration.
            socket_path: Private Unix socket path.
            state_path: Atomic redacted status document path.
        """

        self._activation_task: asyncio.Task[None] | None = None
        self._command_lock = asyncio.Lock()
        self._server: asyncio.Server | None = None
        self._socket_path = socket_path
        self._state_path = state_path
        stored_status = self._stored_status_get()
        self._highest_generation = 0 if stored_status is None else stored_status.generation
        self._runtime = GatewayRuntime(gateway_config, status_callback=self._runtime_status_handle)

    @property
    def status(self) -> GatewayStatus:
        """Return runtime state projected onto the highest fenced generation."""

        status_payload = self._runtime.status.model_dump(mode="python")
        status_payload["generation"] = self._highest_generation
        return GatewayStatus(**status_payload)

    async def close(self) -> None:
        """Stop accepting commands and cleanly close the provider lifecycle."""

        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._activation_task is not None:
            self._activation_task.cancel()
            await asyncio.gather(self._activation_task, return_exceptions=True)
            self._activation_task = None
        await self._runtime.stop()
        self._socket_path.unlink(missing_ok=True)

    async def fatal_failure_wait(self) -> str:
        """Wait for a runtime failure that requires Kubernetes to replace this Pod."""

        return await self._runtime.fatal_failure_wait()

    async def request_handle(self, request: ControlRequest) -> ControlResponse:
        """Apply one idempotent command under the generation fence.

        Args:
            request: Validated command and exact generation.

        Returns:
            Concrete status or fenced error.
        """

        async with self._command_lock:
            if request.generation < self._highest_generation:
                return ControlResponse(
                    error=(f"generation {request.generation} is fenced by generation {self._highest_generation}"),
                    ok=False,
                    status=self.status,
                )
            if request.command is ControlCommand.STATUS:
                if request.generation > self._highest_generation:
                    return ControlResponse(
                        error=f"generation {request.generation} has not been activated",
                        ok=False,
                        status=self.status,
                    )
                return ControlResponse(ok=True, status=self.status)
            if request.command is ControlCommand.ACTIVATE:
                return await self._activate(request.generation)
            return await self._stop(request.generation)

    async def serve_start(self) -> None:
        """Create the private mode-0600 Unix socket and begin accepting requests."""

        self._socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self._socket_path.exists() or self._socket_path.is_symlink():
            socket_mode = self._socket_path.lstat().st_mode
            if not stat.S_ISSOCK(socket_mode):
                raise ValueError(f"control socket path is occupied by a non-socket: {self._socket_path}")
            self._socket_path.unlink()
        self._server = await asyncio.start_unix_server(self._connection_handle, path=self._socket_path)
        os.chmod(self._socket_path, 0o600)

    async def _activate(self, generation: int) -> ControlResponse:
        """Start or recover the exact latest generation without awaiting readiness."""

        if generation > self._highest_generation:
            await self._activation_cancel_and_stop()
            self._highest_generation = generation
        elif self._activation_task is not None and not self._activation_task.done():
            return ControlResponse(ok=True, status=self.status)
        elif self._runtime.status.state is GatewayState.READY:
            return ControlResponse(ok=True, status=self.status)
        self._state_write(
            GatewayStatus(
                diagnostic="",
                generation=self._highest_generation,
                state=GatewayState.ACTIVATING,
                t_update=self._runtime.status.t_update,
            )
        )
        self._activation_task = asyncio.create_task(self._runtime.activate(generation))
        self._activation_task.add_done_callback(self._activation_task_done)
        await asyncio.sleep(0)
        return ControlResponse(ok=True, status=self.status)

    async def _activation_cancel_and_stop(self) -> None:
        """Cancel one unfinished activation and prove owned processes stopped."""

        if self._activation_task is not None and not self._activation_task.done():
            self._activation_task.cancel()
            await asyncio.gather(self._activation_task, return_exceptions=True)
        self._activation_task = None
        await self._runtime.stop()

    def _activation_task_done(self, activation_task: asyncio.Task[None]) -> None:
        """Consume one task exception because status already carries the redacted failure."""

        if not activation_task.cancelled():
            activation_task.exception()

    async def _connection_handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Read exactly one bounded JSON request and write one JSON response."""

        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            if not request_line or len(request_line) > 65536 or not request_line.endswith(b"\n"):
                raise ValueError("control request must be one bounded newline-terminated JSON document")
            request = ControlRequest.model_validate_json(request_line)
            response = await self.request_handle(request)
        except Exception as exc:
            response = ControlResponse(error=str(exc), ok=False, status=self.status)
        writer.write(response.model_dump_json().encode() + b"\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    def _runtime_status_handle(self, runtime_status: GatewayStatus) -> None:
        """Persist each redacted runtime transition under the current fence."""

        status_payload = runtime_status.model_dump(mode="python")
        status_payload["generation"] = self._highest_generation
        self._state_write(GatewayStatus(**status_payload))

    def _state_write(self, status: GatewayStatus) -> None:
        """Atomically replace the redacted durable status document."""

        self._state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary_path = self._state_path.with_name(f".{self._state_path.name}.{os.getpid()}.tmp")
        temporary_path.write_text(status.model_dump_json() + "\n", encoding="utf-8")
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, self._state_path)

    def _stored_status_get(self) -> GatewayStatus | None:
        """Load a previous redacted status only to preserve its generation fence."""

        if not self._state_path.is_file():
            return None
        try:
            return GatewayStatus.model_validate_json(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"failed to load durable gateway status: {exc}") from exc

    async def _stop(self, generation: int) -> ControlResponse:
        """Fence through the requested generation and idempotently stop provider work."""

        if generation > self._highest_generation:
            self._highest_generation = generation
        await self._activation_cancel_and_stop()
        return ControlResponse(ok=True, status=self.status)


async def _control_request_send(socket_path: Path, request: ControlRequest) -> ControlResponse:
    """Send one exact local control request.

    Args:
        socket_path: Private daemon Unix socket.
        request: Validated command.

    Returns:
        Validated daemon response.
    """

    reader, writer = await asyncio.open_unix_connection(socket_path)
    writer.write(request.model_dump_json().encode() + b"\n")
    await writer.drain()
    response_line = await asyncio.wait_for(reader.readline(), timeout=10)
    writer.close()
    await writer.wait_closed()
    return ControlResponse.model_validate_json(response_line)


def _control_args_parse() -> argparse.Namespace:
    """Parse one shell-free local control command."""

    parser = argparse.ArgumentParser(description="Control one exact fenced vpn-runtime gateway generation.")
    parser.add_argument("--socket-path", required=True, type=Path)
    parser.add_argument("command", choices=list(ControlCommand), type=ControlCommand)
    parser.add_argument("generation", type=int)
    return parser.parse_args()


def _daemon_args_parse() -> argparse.Namespace:
    """Parse prepared gateway daemon configuration."""

    parser = argparse.ArgumentParser(description="Run one prepared generation-fenced VPN gateway daemon.")
    parser.add_argument("--activate-generation", default=None, type=int)
    parser.add_argument("--connection-attempt-timeout-seconds", default=180, type=int)
    parser.add_argument("--config-root-path", required=True, type=Path)
    parser.add_argument("--control-socket-path", required=True, type=Path)
    parser.add_argument("--protocol", choices=list(VpnProtocol), required=True, type=VpnProtocol)
    parser.add_argument("--process-stop-timeout-seconds", default=30, type=int)
    parser.add_argument("--provider-recovery-grace-seconds", default=180, type=int)
    parser.add_argument("--runtime-root-path", required=True, type=Path)
    parser.add_argument("--state-path", required=True, type=Path)
    return parser.parse_args()


def _readiness_args_parse() -> argparse.Namespace:
    """Parse one local readiness state path."""

    parser = argparse.ArgumentParser(description="Exit successfully only for a ready vpn-runtime gateway.")
    parser.add_argument("--state-path", required=True, type=Path)
    return parser.parse_args()


def control_main() -> None:
    """Send one control command and print the exact redacted JSON response."""

    argument_by_name_map = vars(_control_args_parse())
    socket_path = argument_by_name_map.pop("socket_path")
    response = asyncio.run(
        _control_request_send(
            socket_path,
            ControlRequest(**argument_by_name_map),
        )
    )
    print(response.model_dump_json(), flush=True)
    if not response.ok:
        raise SystemExit(1)


def daemon_main() -> None:
    """Run the prepared private control daemon until an operating-system stop signal."""

    argument_by_name_map = vars(_daemon_args_parse())

    async def run() -> None:
        """Own daemon startup, signal waiting, and cleanup."""

        activate_generation = argument_by_name_map.pop("activate_generation")
        control_socket_path = argument_by_name_map.pop("control_socket_path")
        state_path = argument_by_name_map.pop("state_path")
        daemon = ControlDaemon(
            gateway_config=GatewayConfig(**argument_by_name_map),
            socket_path=control_socket_path,
            state_path=state_path,
        )
        await daemon.serve_start()
        if activate_generation is not None:
            activation_response = await daemon.request_handle(
                ControlRequest(command=ControlCommand.ACTIVATE, generation=activate_generation)
            )
            if not activation_response.ok:
                raise RuntimeError(activation_response.error)
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signal_number in [signal.SIGINT, signal.SIGTERM]:
            loop.add_signal_handler(signal_number, stop_event.set)
        stop_task = asyncio.create_task(stop_event.wait())
        fatal_failure_task = asyncio.create_task(daemon.fatal_failure_wait())
        try:
            completed_task_set, _ = await asyncio.wait(
                {stop_task, fatal_failure_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if fatal_failure_task in completed_task_set:
                raise RuntimeError(await fatal_failure_task)
        finally:
            for task in [stop_task, fatal_failure_task]:
                if not task.done():
                    task.cancel()
            await asyncio.gather(stop_task, fatal_failure_task, return_exceptions=True)
            await daemon.close()

    asyncio.run(run())


def readiness_main() -> None:
    """Read one redacted status file without opening a management API."""

    state_path = _readiness_args_parse().state_path
    try:
        status = GatewayStatus.model_validate_json(state_path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        raise SystemExit(1) from None
    if status.state is not GatewayState.READY:
        raise SystemExit(1)


if __name__ == "__main__":
    if Path(sys.argv[0]).name == "vpn-runtime-daemon":
        daemon_main()
    elif Path(sys.argv[0]).name == "vpn-runtime-readiness":
        readiness_main()
    else:
        control_main()
