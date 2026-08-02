"""Behavior tests for complete Linux process-session ownership."""

import asyncio
import os
from pathlib import Path
import signal

import pytest

from vpn_runtime.process_session import ProcessSessionSupervisor


class _ExitedProcess:
    """Represent an exited session leader whose descendant remains alive."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.returncode: int | None = -signal.SIGKILL

    async def wait(self) -> int:
        """Return the already observed leader exit."""

        return self.returncode


def _proc_stat_write(proc_root_path: Path, *, pid: int, session_id: int) -> None:
    """Write the minimum Linux stat shape consumed by the supervisor."""

    process_root_path = proc_root_path / str(pid)
    process_root_path.mkdir()
    process_root_path.joinpath("stat").write_text(
        f"{pid} (openvpn worker) S 1 {pid} {session_id} 0\n",
        encoding="utf-8",
    )


def test_process_session_stop_terminates_orphan_after_direct_leader_exit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not mistake an exited Gluetun wrapper for an empty provider process tree."""

    async def run() -> None:
        proc_root_path = tmp_path / "proc"
        proc_root_path.mkdir()
        leader_pid = 201
        orphan_pid = 202
        _proc_stat_write(proc_root_path, pid=orphan_pid, session_id=leader_pid)
        process = _ExitedProcess(leader_pid)
        supervisor = ProcessSessionSupervisor(proc_root_path=proc_root_path)
        supervisor.register(process)
        signal_call_list: list[tuple[int, signal.Signals]] = []

        def process_signal(pid: int, signal_number: signal.Signals) -> None:
            signal_call_list.append((pid, signal_number))
            proc_root_path.joinpath(str(pid), "stat").unlink()
            proc_root_path.joinpath(str(pid)).rmdir()

        monkeypatch.setattr(os, "kill", process_signal)

        assert supervisor.have_processes([process])
        await supervisor.stop([process], asyncio.get_running_loop().time() + 1)

        assert signal_call_list == [(orphan_pid, signal.SIGTERM)]
        assert not supervisor.have_processes([process])

    asyncio.run(run())
