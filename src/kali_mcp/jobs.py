from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import signal
import time
import uuid
from pathlib import Path

from .inventory import Inventory
from .workspace import Workspace, now, write_json

TERMINAL = {
    "completed",
    "failed",
    "cancelled",
    "timed_out",
    "output_limit",
    "artifact_limit",
    "interrupted",
}


def directory_bytes(root: Path) -> int:
    total = 0
    for directory, _, filenames in os.walk(root, followlinks=False):
        for filename in filenames:
            path = Path(directory) / filename
            try:
                if not path.is_symlink():
                    total += path.stat().st_size
            except FileNotFoundError:
                pass
    return total


class JobManager:
    def __init__(self, workspace: Workspace, inventory: Inventory | None = None):
        self.workspace = workspace
        self.config = workspace.config
        self.inventory = inventory or Inventory(self.config)
        self.tasks: dict[str, asyncio.Task] = {}
        self.active: dict[str, dict] = {}
        self.cancel_requested: set[str] = set()
        self.slots = asyncio.Semaphore(self.config.max_concurrent)
        self.closing = False
        for data in workspace.catalog.unfinished_jobs():
            path = workspace.engagement_path(data["engagement_id"]) / "jobs" / data["id"]
            # Recover a sidecar committed just before an interrupted index update.
            if (path / "job.json").is_file():
                data = json.loads((path / "job.json").read_text(encoding="utf-8"))
            if data["status"] not in TERMINAL:
                data.update(
                    status="interrupted",
                    finished_at=now(),
                    error="Server restarted; previous process state is unknown",
                )
            self.save(path, data)

    def save(self, path: Path, data: dict) -> None:
        with self.workspace.mutations:
            self._save(path, data)

    def _save(self, path: Path, data: dict) -> None:
        write_json(path / "job.json", data)
        self.workspace.catalog.put("job", data, data["engagement_id"])
        try:
            self.workspace.reports.observe_job(data)
        except (OSError, ValueError) as error:
            data["report_error"] = str(error)
            if data["status"] == "queued":
                data.update(
                    status="failed", finished_at=now(), error="Report unavailable; not executed"
                )
            write_json(path / "job.json", data)
            self.workspace.catalog.put("job", data, data["engagement_id"])
            if (
                data["status"] == "failed"
                and data.get("error") == "Report unavailable; not executed"
            ):
                raise ValueError(f"Report unavailable; command not executed: {error}") from error

    async def persist(self, path: Path, data: dict) -> None:
        saving = asyncio.create_task(asyncio.to_thread(self.save, path, data.copy()))
        try:
            await asyncio.shield(saving)
        except asyncio.CancelledError:
            await saving
            raise

    def path(self, engagement_id: str, job_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise ValueError("Invalid job ID")
        path = self.workspace.engagement_path(engagement_id) / "jobs" / job_id
        # DrvFS can briefly hide an overwritten sidecar during Windows/Linux rename.
        # The stable job directory and indexed/in-memory metadata define job identity.
        if not path.is_dir():
            raise ValueError("Job not found")
        return path

    def get(self, engagement_id: str, job_id: str) -> dict:
        self.path(engagement_id, job_id)
        if data := self.active.get(job_id):
            if data["engagement_id"] != engagement_id:
                raise ValueError("Job belongs to another engagement")
            return data.copy()
        data = self.workspace.catalog.get("job", job_id, engagement_id)
        if data is None:
            raise ValueError("Job metadata not found")
        return data

    def list(self, engagement_id: str) -> list[dict]:
        self.workspace.engagement_path(engagement_id)
        return self.workspace.catalog.all("job", engagement_id)

    def preflight(
        self, engagement_id: str, tool: str, args: list[str], target: str, timeout: int = 300
    ) -> str:
        try:
            return self._preflight(engagement_id, tool, args, target, timeout)
        except ValueError as error:
            try:
                self.workspace.engagement_path(engagement_id)
            except ValueError:
                raise error from None
            command = (
                shlex.join([tool, *args])
                if isinstance(args, list) and all(isinstance(arg, str) for arg in args)
                else f"{tool} {args!r}"
            )
            self.workspace.reports.blocked(engagement_id, target, command, str(error))
            raise

    def _preflight(
        self, engagement_id: str, tool: str, args: list[str], target: str, timeout: int = 300
    ) -> str:
        if self.closing:
            raise ValueError("Server is shutting down")
        self.workspace.check_target(engagement_id, target)
        if type(timeout) is not int or not 1 <= timeout <= self.config.max_timeout:
            raise ValueError(f"timeout must be 1..{self.config.max_timeout} seconds")
        if (
            not isinstance(args, list)
            or len(args) > 256
            or any(not isinstance(arg, str) or "\x00" in arg or len(arg) > 8192 for arg in args)
        ):
            raise ValueError("Invalid argument list")
        return self.inventory.resolve(tool)

    def check_capacity(self, count: int = 1) -> None:
        pending = sum(not task.done() for task in self.tasks.values())
        if pending + count > self.config.max_concurrent + self.config.max_queued:
            raise ValueError("Concurrent job / queue limit reached; poll or cancel existing jobs")

    def start(
        self,
        engagement_id: str,
        tool: str,
        args: list[str],
        target: str,
        timeout: int = 300,
        profile: str | None = None,
        batch_id: str | None = None,
    ) -> dict:
        executable = self.preflight(engagement_id, tool, args, target, timeout)
        try:
            self.check_capacity()
        except ValueError as error:
            self.workspace.reports.blocked(
                engagement_id, target, shlex.join([executable, *args]), str(error)
            )
            raise
        job_id = uuid.uuid4().hex
        path = self.workspace.engagement_path(engagement_id) / "jobs" / job_id
        path.mkdir(mode=0o700)
        data = {
            "id": job_id,
            "engagement_id": engagement_id,
            "tool": tool,
            "argv": [executable, *args],
            "target": target,
            "timeout": timeout,
            "profile": profile,
            "batch_id": batch_id,
            "status": "queued",
            "created_at": now(),
            "finished_at": None,
            "exit_code": None,
            "output_bytes": 0,
            "stdout": f"jobs/{job_id}/stdout.txt",
            "stderr": f"jobs/{job_id}/stderr.txt",
        }
        self.save(path, data)
        self.active[job_id] = data
        task = asyncio.create_task(self._run(path, data), name=f"kali-job-{job_id}")
        self.tasks[job_id] = task

        def finished(_):
            self.tasks.pop(job_id, None)
            self.active.pop(job_id, None)
            self.cancel_requested.discard(job_id)

        task.add_done_callback(finished)
        return data.copy()

    async def _stop(self, process: asyncio.subprocess.Process) -> None:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
                until = time.monotonic() + self.config.terminate_grace_seconds
                while process.returncode is None and time.monotonic() < until:
                    await asyncio.sleep(0.05)
            except ProcessLookupError:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.returncode is None:
            process.kill()
        try:
            await asyncio.wait_for(process.wait(), 5)
        except TimeoutError:
            pass  # Detached descendants holding pipes have bounded drain cleanup too.

    async def _run(self, path: Path, data: dict) -> None:
        process = launch = collector = watcher = quota_waiter = None
        acquired = False
        started = None
        queued_at = time.monotonic()
        output_limit = asyncio.Event()
        reason = "failed"

        async def drain(stream: asyncio.StreamReader, destination: Path) -> None:
            with destination.open("wb", buffering=0) as output:
                while chunk := await stream.read(65536):
                    remaining = self.config.max_output_bytes - data["output_bytes"]
                    if remaining > 0:
                        written = chunk[:remaining]
                        data["output_bytes"] += len(written)
                        writing = asyncio.create_task(asyncio.to_thread(output.write, written))
                        try:
                            await asyncio.shield(writing)
                        except asyncio.CancelledError:
                            await writing
                            raise
                    if len(chunk) > remaining:
                        output_limit.set()

        async def watch() -> str:
            deadline = started + data["timeout"]
            next_quota_check = time.monotonic() + 1
            while process.returncode is None:
                if time.monotonic() >= deadline:
                    return "timed_out"
                if time.monotonic() >= next_quota_check:
                    size = await asyncio.to_thread(directory_bytes, path)
                    if size > self.config.max_artifact_bytes:
                        return "artifact_limit"
                    next_quota_check = time.monotonic() + 1
                await asyncio.sleep(0.1)
            return "completed" if process.returncode == 0 else "failed"

        try:
            await self.slots.acquire()
            acquired = True
            started = time.monotonic()
            data["queue_seconds"] = round(started - queued_at, 3)
            env = {
                key: os.environ[key]
                for key in ("PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
                if key in os.environ
            }
            env.update(NO_COLOR="1", PYTHONUNBUFFERED="1")
            launch = asyncio.create_task(
                asyncio.create_subprocess_exec(
                    *data["argv"],
                    cwd=path,
                    env=env,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=os.name == "posix",
                )
            )
            process = await asyncio.shield(launch)
            data.update(status="running", started_at=now(), pid=process.pid)
            collector = asyncio.gather(
                drain(process.stdout, path / "stdout.txt"),
                drain(process.stderr, path / "stderr.txt"),
            )
            await self.persist(path, data)
            watcher = asyncio.create_task(watch())
            quota_waiter = asyncio.create_task(output_limit.wait())
            done, _ = await asyncio.wait(
                {watcher, quota_waiter, collector}, return_when=asyncio.FIRST_COMPLETED
            )
            if output_limit.is_set():
                reason = "output_limit"
            elif watcher in done:
                reason = watcher.result()
            else:
                await collector
                done, _ = await asyncio.wait(
                    {watcher, quota_waiter}, return_when=asyncio.FIRST_COMPLETED
                )
                reason = "output_limit" if quota_waiter in done else watcher.result()
        except asyncio.CancelledError:
            reason = "cancelled"
            if process is None and launch is not None:
                try:
                    process = await launch
                except Exception as error:
                    data["error"] = str(error)
        except Exception as error:
            data["error"] = str(error)
        finally:
            try:
                if process is not None:
                    await self._stop(process)
                    data["exit_code"] = process.returncode
                if collector is not None:
                    try:
                        await asyncio.wait_for(asyncio.shield(collector), 5)
                    except (asyncio.CancelledError, Exception):
                        collector.cancel()
                        await asyncio.gather(collector, return_exceptions=True)
                for task in (watcher, quota_waiter):
                    if task is not None:
                        task.cancel()
                await asyncio.gather(
                    *[t for t in (watcher, quota_waiter) if t is not None], return_exceptions=True
                )
                data["artifact_bytes"] = await asyncio.to_thread(directory_bytes, path)
                if reason in {"completed", "failed"} and output_limit.is_set():
                    reason = "output_limit"
                if (
                    reason == "completed"
                    and data["artifact_bytes"] > self.config.max_artifact_bytes
                ):
                    reason = "artifact_limit"
            except Exception as error:
                data["error"] = f"Cleanup failed: {error}"
                reason = "failed"
            finally:
                data.update(
                    status=reason,
                    finished_at=now(),
                    duration_seconds=round(time.monotonic() - started, 3) if started else 0,
                )
                try:
                    await self.persist(path, data)
                finally:
                    if acquired:
                        self.slots.release()

    async def wait(self, engagement_id: str, job_id: str, seconds: int = 10) -> dict:
        self.path(engagement_id, job_id)
        if not 0 <= seconds <= 30:
            raise ValueError("wait seconds must be 0..30")
        if (task := self.tasks.get(job_id)) is not None and seconds:
            await asyncio.wait({task}, timeout=seconds)
        return self.get(engagement_id, job_id)

    async def cancel(self, engagement_id: str, job_id: str) -> dict:
        self.path(engagement_id, job_id)
        if (task := self.tasks.get(job_id)) is not None:
            await asyncio.sleep(0)
            if job_id not in self.cancel_requested:
                self.cancel_requested.add(job_id)
                task.cancel()
            await asyncio.shield(asyncio.gather(task, return_exceptions=True))
        return self.get(engagement_id, job_id)

    async def wait_many(self, engagement_id: str, job_ids: list[str], seconds: int = 10) -> dict:
        if not 1 <= len(job_ids) <= 100 or not 0 <= seconds <= 30:
            raise ValueError("Provide 1..100 job IDs and wait seconds 0..30")
        for job_id in job_ids:
            self.path(engagement_id, job_id)
        tasks = {self.tasks[job_id] for job_id in job_ids if job_id in self.tasks}
        if tasks and seconds:
            await asyncio.wait(tasks, timeout=seconds)
        items = [self.get(engagement_id, job_id) for job_id in job_ids]
        return {"jobs": items, "all_finished": all(item["status"] in TERMINAL for item in items)}

    async def close(self) -> None:
        self.closing = True
        await asyncio.sleep(0)
        tasks = list(self.tasks.items())
        for job_id, task in tasks:
            if job_id not in self.cancel_requested:
                self.cancel_requested.add(job_id)
                task.cancel()
        await asyncio.gather(*[task for _, task in tasks], return_exceptions=True)
