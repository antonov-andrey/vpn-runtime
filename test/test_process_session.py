"""Behavior tests for complete Linux process-session ownership."""

import asyncio
import os
from pathlib import Path
import signal

import pytest

from vpn_runtime.process_session import ProcessSessionError, ProcessSessionSupervisor


class _ExitedProcess:
    """Represent an exited session leader whose descendant remains alive."""

    def __init__(self, pid: int) -> None:
        """Initialize the exited process dependencies.

        Args:
            pid: Operating-system process identity.
        """

        self.pid = pid
        self.returncode: int | None = -signal.SIGKILL

    async def wait(self) -> int:
        """Return the already observed leader exit.

        Returns:
            The already observed leader exit.
        """

        return self.returncode


def _proc_stat_write(
    proc_root_path: Path,
    *,
    pid: int,
    session_id: int,
    state: str = "S",
) -> None:
    """Write the minimum Linux stat shape consumed by the supervisor.

    Args:
        proc_root_path: Exact filesystem path for proc root.
        pid: Operating-system process identity.
        session_id: Exact session identity.
        state: Exact runtime state.
    """

    process_root_path = proc_root_path / str(pid)
    process_root_path.mkdir()
    process_root_path.joinpath("stat").write_text(
        f"{pid} (openvpn worker) {state} 1 {pid} {session_id} 0\n",
        encoding="utf-8",
    )


def test_process_session_stop_terminates_orphan_after_direct_leader_exit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not mistake an exited Gluetun wrapper for an empty provider process tree.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    async def run() -> None:
        """Terminate an orphaned session member after its direct leader exits."""

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
            """Record the delivered signal and remove the emulated process.

            Args:
                pid: Operating-system process identity.
                signal_number: POSIX signal number.
            """

            signal_call_list.append((pid, signal_number))
            proc_root_path.joinpath(str(pid), "stat").unlink()
            proc_root_path.joinpath(str(pid)).rmdir()

        monkeypatch.setattr(os, "kill", process_signal)

        assert supervisor.have_processes([process])
        await supervisor.stop([process], asyncio.get_running_loop().time() + 1)

        assert signal_call_list == [(orphan_pid, signal.SIGTERM)]
        assert not supervisor.have_processes([process])

    asyncio.run(run())


def test_process_session_ignores_resource_free_descendant_zombie(tmp_path: Path) -> None:
    """Require wrapper reaping but do not wait on a descendant that has already exited.

    Args:
        tmp_path: Temporary directory path.
    """

    proc_root_path = tmp_path / "proc"
    proc_root_path.mkdir()
    leader_pid = 301
    _proc_stat_write(proc_root_path, pid=302, session_id=leader_pid, state="Z")
    process = _ExitedProcess(leader_pid)
    supervisor = ProcessSessionSupervisor(proc_root_path=proc_root_path)
    supervisor.register(process)

    assert not supervisor.have_processes([process])


def test_process_session_ignores_process_that_disappears_while_stat_is_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Accept the normal procfs race after one enumerated process exits.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    proc_root_path = tmp_path / "proc"
    proc_root_path.mkdir()
    disappearing_process_path = proc_root_path / "302"
    disappearing_process_path.mkdir()
    process = _ExitedProcess(301)
    supervisor = ProcessSessionSupervisor(proc_root_path=proc_root_path)
    supervisor.register(process)
    original_read_text = Path.read_text

    def stat_read(path: Path, *args: object, **kwargs: object) -> str:
        """Inject disappearance while delegating every other procfs read.

        Args:
            path: Exact filesystem path.
            *args: Additional positional arguments.
            **kwargs: Provider keyword arguments.

        Returns:
            Original procfs text for every retained process.
        """

        if path == disappearing_process_path / "stat":
            raise ProcessLookupError("process exited during procfs inspection")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", stat_read)

    assert not supervisor.have_processes([process])


def test_process_session_rejects_unreadable_process_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Keep inspection failures fail-closed when the process did not disappear.

    Args:
        monkeypatch: Pytest mutation fixture.
        tmp_path: Temporary directory path.
    """

    proc_root_path = tmp_path / "proc"
    proc_root_path.mkdir()
    unreadable_process_path = proc_root_path / "402"
    unreadable_process_path.mkdir()
    process = _ExitedProcess(401)
    supervisor = ProcessSessionSupervisor(proc_root_path=proc_root_path)
    supervisor.register(process)
    original_read_text = Path.read_text

    def stat_read(path: Path, *args: object, **kwargs: object) -> str:
        """Inject an unreadable process while delegating every other procfs read.

        Args:
            path: Exact filesystem path.
            *args: Additional positional arguments.
            **kwargs: Provider keyword arguments.

        Returns:
            Original procfs text for every other process.
        """

        if path == unreadable_process_path / "stat":
            raise PermissionError("process metadata is unreadable")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", stat_read)

    with pytest.raises(ProcessSessionError, match="membership could not be inspected"):
        supervisor.have_processes([process])
