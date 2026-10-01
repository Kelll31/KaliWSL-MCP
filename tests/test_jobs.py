import asyncio
import os
import sys
from pathlib import Path

import pytest

from kali_mcp.config import Config
from kali_mcp.jobs import JobManager
from kali_mcp.workspace import Workspace


def setup_jobs(tmp_path, **kwargs):
    name = Path(sys.executable).name
    config = Config(workspace=tmp_path, allowed_tools=(name,), **kwargs)
    workspace = Workspace(config)
    eid = workspace.create("lab", ["127.0.0.1"])["id"]
    return workspace, JobManager(workspace), eid, name


def test_literal_argv_and_exit_code(tmp_path):
    async def check():
        ws, jobs, eid, name = setup_jobs(tmp_path)
        literal = "$(echo injected); & | `whoami`"
        data = jobs.start(
            eid,
            name,
            ["-c", "import sys; print(sys.argv[1]); print('err', file=sys.stderr)", literal],
            "127.0.0.1",
        )
        result = await jobs.wait(eid, data["id"], 10)
        assert result["status"] == "completed"
        assert result["exit_code"] == 0
        assert literal in ws.read(eid, result["stdout"])["text"]
        assert ws.read(eid, result["stderr"])["text"].strip() == "err"
        failed = jobs.start(eid, name, ["-c", "raise SystemExit(7)"], "127.0.0.1")
        result = await jobs.wait(eid, failed["id"], 10)
        assert result["status"] == "failed" and result["exit_code"] == 7
        await jobs.close()

    asyncio.run(check())


def test_timeout_and_cancel(tmp_path):
    async def check():
        _, jobs, eid, name = setup_jobs(tmp_path)
        data = jobs.start(eid, name, ["-c", "import time; time.sleep(60)"], "127.0.0.1", 1)
        result = await jobs.wait(eid, data["id"], 10)
        assert result["status"] == "timed_out"
        data = jobs.start(eid, name, ["-c", "import time; time.sleep(60)"], "127.0.0.1")
        result = await jobs.cancel(eid, data["id"])
        assert result["status"] == "cancelled"
        await jobs.close()

    asyncio.run(check())


def test_output_quota_and_concurrency(tmp_path):
    async def check():
        _, jobs, eid, name = setup_jobs(
            tmp_path, max_output_bytes=1024, max_concurrent=1, max_queued=0
        )
        data = jobs.start(eid, name, ["-c", "print('x'*100000)"], "127.0.0.1")
        with pytest.raises(ValueError, match="Concurrent"):
            jobs.start(eid, name, ["-c", "pass"], "127.0.0.1")
        result = await jobs.wait(eid, data["id"], 10)
        assert result["status"] == "output_limit"
        assert result["output_bytes"] == 1024
        await jobs.close()

    asyncio.run(check())


def test_rejects_disallowed_execution(tmp_path):
    _, jobs, eid, name = setup_jobs(tmp_path)
    with pytest.raises(ValueError, match="allowlist"):
        jobs.start(eid, "bash", ["-c", "id"], "127.0.0.1")
    with pytest.raises(ValueError, match="outside"):
        jobs.start(eid, name, ["-c", "pass"], "example.com")
    with pytest.raises(ValueError, match="timeout"):
        jobs.start(eid, name, [], "127.0.0.1", 0)


def test_shutdown_cancels_active_jobs(tmp_path):
    async def check():
        _, jobs, eid, name = setup_jobs(tmp_path)
        job = jobs.start(eid, name, ["-c", "import time; time.sleep(60)"], "127.0.0.1")
        await jobs.close()
        assert jobs.get(eid, job["id"])["status"] == "cancelled"
        with pytest.raises(ValueError, match="shutting down"):
            jobs.start(eid, name, ["-c", "pass"], "127.0.0.1")

    asyncio.run(check())


def test_queue_limits_cancel_and_execution_order(tmp_path):
    async def check():
        _, jobs, eid, name = setup_jobs(tmp_path, max_concurrent=1, max_queued=2)
        first = jobs.start(eid, name, ["-c", "import time; time.sleep(60)"], "127.0.0.1")
        second = jobs.start(eid, name, ["-c", "print('second')"], "127.0.0.1", timeout=1)
        third = jobs.start(eid, name, ["-c", "print('third')"], "127.0.0.1", timeout=1)
        with pytest.raises(ValueError, match="queue"):
            jobs.start(eid, name, ["-c", "pass"], "127.0.0.1")
        await asyncio.sleep(0.2)
        assert jobs.get(eid, second["id"])["status"] == "queued"
        cancelled = await jobs.cancel(eid, second["id"])
        assert cancelled["status"] == "cancelled" and "started_at" not in cancelled
        await jobs.cancel(eid, first["id"])
        final = await jobs.wait(eid, third["id"], 10)
        assert final["status"] == "completed" and final["queue_seconds"] >= 0.2
        await jobs.close()

    asyncio.run(check())


def test_artifact_quota(tmp_path):
    async def check():
        _, jobs, eid, name = setup_jobs(tmp_path, max_artifact_bytes=10000)
        code = "open('large.bin','wb').write(b'a'*50000); import time; time.sleep(60)"
        job = jobs.start(eid, name, ["-c", code], "127.0.0.1")
        final = await jobs.wait(eid, job["id"], 10)
        assert final["status"] == "artifact_limit"
        assert final["artifact_bytes"] >= 50000
        await jobs.close()

    asyncio.run(check())


def test_poll_survives_sidecar_replacement_visibility_gap(tmp_path):
    async def check():
        _, jobs, eid, name = setup_jobs(tmp_path)
        job = jobs.start(eid, name, ["-c", "import time; time.sleep(60)"], "127.0.0.1")
        (jobs.path(eid, job["id"]) / "job.json").unlink()
        result = await jobs.wait(eid, job["id"], 0)
        assert result["id"] == job["id"]
        final = await jobs.cancel(eid, job["id"])
        assert final["status"] == "cancelled"
        assert (jobs.path(eid, job["id"]) / "job.json").is_file()
        await jobs.close()

    asyncio.run(check())


@pytest.mark.skipif(os.name != "posix", reason="Linux descendant pipes")
def test_exited_leader_does_not_leave_job_waiting_on_child_pipes(tmp_path):
    async def check():
        _, jobs, eid, name = setup_jobs(tmp_path)
        code = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])"
        )
        job = jobs.start(eid, name, ["-c", code], "127.0.0.1", timeout=3)
        final = await jobs.wait(eid, job["id"], 10)
        assert final["status"] == "completed"
        await jobs.close()

    asyncio.run(check())


def test_restart_marks_interrupted(tmp_path):
    ws, jobs, eid, _ = setup_jobs(tmp_path)
    path = ws.engagement_path(eid) / "jobs" / ("a" * 32)
    path.mkdir()
    jobs.save(path, {"id": "a" * 32, "status": "running", "engagement_id": eid})
    recovered = JobManager(ws)
    assert recovered.get(eid, "a" * 32)["status"] == "interrupted"


@pytest.mark.skipif(os.name != "posix", reason="Linux process group semantics")
def test_cancel_kills_descendants(tmp_path):
    async def check():
        ws, jobs, eid, name = setup_jobs(tmp_path)
        code = (
            "import subprocess,sys,time; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            "open('child.pid','w').write(str(p.pid)); time.sleep(60)"
        )
        data = jobs.start(eid, name, ["-c", code], "127.0.0.1")
        pid_path = jobs.path(eid, data["id"]) / "child.pid"
        for _ in range(100):
            if pid_path.exists():
                break
            await asyncio.sleep(0.02)
        assert pid_path.exists()
        child_pid = int(pid_path.read_text())
        await jobs.cancel(eid, data["id"])
        for _ in range(100):
            proc_stat = Path(f"/proc/{child_pid}/stat")
            if not proc_stat.exists() or proc_stat.read_text().split()[2] == "Z":
                break
            await asyncio.sleep(0.02)
        else:
            pytest.fail("Child process survived cancellation")
        await jobs.close()

    asyncio.run(check())
