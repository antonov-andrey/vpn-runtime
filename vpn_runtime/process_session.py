"""Linux process-session ownership and bounded termination."""

import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import signal
from typing import Protocol

PROCESS_EXIT_PROOF_TIMEOUT_SECONDS = 5.0
PROCESS_EXIT_POLL_SECONDS = 0.05


class ProcessSessionError(RuntimeError):
    """Raised when absence of an owned process session cannot be proved."""


class WaitableProcess(Protocol):
    """Structural process surface used by the session supervisor."""

    pid: int
    returncode: int | None

    async def wait(self) -> int:
        """Wait for the direct process wrapper to exit."""


@dataclass(frozen=True, slots=True)
class OwnedProcessSession:
    """Bind one direct wrapper to the Linux session created for its process tree."""

    process: WaitableProcess
    session_id: int


class ProcessSessionSupervisor:
    """Track and terminate complete Linux sessions, including orphaned descendants."""

    def __init__(self, *, proc_root_path: Path = Path("/proc")) -> None:
        self._owned_session_by_process_id_map: dict[int, OwnedProcessSession] = {}
        self._proc_root_path = proc_root_path

    def register(self, process: WaitableProcess) -> None:
        """Register a process started with ``start_new_session=True``."""

        process_id = id(process)
        if process_id in self._owned_session_by_process_id_map:
            raise ProcessSessionError("process session is already registered")
        self._owned_session_by_process_id_map[process_id] = OwnedProcessSession(
            process=process,
            session_id=process.pid,
        )

    def have_processes(self, process_list: list[WaitableProcess | None]) -> bool:
        """Return whether a direct wrapper or any member of its owned session exists."""

        for process in process_list:
            if process is None:
                continue
            if process.returncode is None:
                return True
            owned_session = self._owned_session_get(process)
            if self._session_member_pid_list_get(owned_session.session_id):
                return True
        return False

    async def stop(
        self,
        process_list: list[WaitableProcess | None],
        process_stop_deadline: float,
    ) -> None:
        """Signal complete sessions and prove direct wrappers and descendants absent."""

        owned_session_list = [self._owned_session_get(process) for process in process_list if process is not None]
        if not owned_session_list:
            return
        await self._signal_and_wait(
            owned_session_list=owned_session_list,
            process_stop_deadline=process_stop_deadline,
        )
        for owned_session in owned_session_list:
            self._owned_session_by_process_id_map.pop(id(owned_session.process), None)

    async def _signal_and_wait(
        self,
        *,
        owned_session_list: list[OwnedProcessSession],
        process_stop_deadline: float,
    ) -> None:
        self._signal_send(owned_session_list, signal.SIGTERM)
        if await self._absence_wait(owned_session_list, process_stop_deadline):
            return
        self._signal_send(owned_session_list, signal.SIGKILL)
        proof_deadline = asyncio.get_running_loop().time() + PROCESS_EXIT_PROOF_TIMEOUT_SECONDS
        if not await self._absence_wait(owned_session_list, proof_deadline):
            raise ProcessSessionError("owned process-session exit could not be proved after SIGKILL")

    async def _absence_wait(
        self,
        owned_session_list: list[OwnedProcessSession],
        deadline: float,
    ) -> bool:
        wait_task_list = [
            asyncio.create_task(owned_session.process.wait())
            for owned_session in owned_session_list
            if owned_session.process.returncode is None
        ]
        try:
            while True:
                wrapper_is_running = any(
                    owned_session.process.returncode is None for owned_session in owned_session_list
                )
                session_has_members = any(
                    self._session_member_pid_list_get(owned_session.session_id) for owned_session in owned_session_list
                )
                if not wrapper_is_running and not session_has_members:
                    return True
                remaining_seconds = deadline - asyncio.get_running_loop().time()
                if remaining_seconds <= 0:
                    return False
                await asyncio.sleep(min(PROCESS_EXIT_POLL_SECONDS, remaining_seconds))
        finally:
            for wait_task in wait_task_list:
                if not wait_task.done():
                    wait_task.cancel()
            await asyncio.gather(*wait_task_list, return_exceptions=True)

    def _owned_session_get(self, process: WaitableProcess) -> OwnedProcessSession:
        return self._owned_session_by_process_id_map.get(
            id(process),
            OwnedProcessSession(process=process, session_id=process.pid),
        )

    def _signal_send(
        self,
        owned_session_list: list[OwnedProcessSession],
        signal_number: signal.Signals,
    ) -> None:
        target_pid_set: set[int] = set()
        for owned_session in owned_session_list:
            target_pid_set.update(self._session_member_pid_list_get(owned_session.session_id))
            if owned_session.process.returncode is None:
                target_pid_set.add(owned_session.process.pid)
        target_pid_set.discard(os.getpid())
        for target_pid in sorted(target_pid_set, reverse=True):
            try:
                os.kill(target_pid, signal_number)
            except ProcessLookupError:
                continue
            except PermissionError as exc:
                raise ProcessSessionError("owned process session could not be signalled") from exc

    def _session_member_pid_list_get(self, session_id: int) -> list[int]:
        try:
            process_path_list = list(self._proc_root_path.iterdir())
        except OSError as exc:
            raise ProcessSessionError("process-session membership could not be inspected") from exc
        member_pid_list: list[int] = []
        for process_path in process_path_list:
            if not process_path.name.isdecimal():
                continue
            try:
                stat_text = process_path.joinpath("stat").read_text(encoding="utf-8")
            except OSError as exc:
                if isinstance(exc, (FileNotFoundError, ProcessLookupError)):
                    continue
                raise ProcessSessionError("process-session membership could not be inspected") from exc
            command_end_index = stat_text.rfind(")")
            if command_end_index < 0:
                raise ProcessSessionError("kernel process metadata has an invalid shape")
            stat_field_list = stat_text[command_end_index + 2 :].split()
            if len(stat_field_list) < 4:
                raise ProcessSessionError("kernel process metadata has an invalid shape")
            if stat_field_list[0] == "Z":
                continue
            try:
                process_session_id = int(stat_field_list[3])
            except ValueError as exc:
                raise ProcessSessionError("kernel process session is invalid") from exc
            if process_session_id == session_id:
                member_pid_list.append(int(process_path.name))
        return member_pid_list
