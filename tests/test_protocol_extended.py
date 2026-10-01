import asyncio
import sys
from pathlib import Path

from mcp import Client

from kali_mcp.config import Config
from kali_mcp.server import create_server


def test_batch_queue_outputs_notes_and_findings_over_mcp(tmp_path, monkeypatch):
    name = Path(sys.executable).name
    config = Config(workspace=tmp_path, allowed_tools=(name,), max_concurrent=1, max_queued=4)
    monkeypatch.setattr(
        "kali_mcp.workflows.build",
        lambda profile, target, options, ceiling: (
            name,
            ["-c", "import time; print('batch works'); time.sleep(.15)"],
        ),
    )

    async def check():
        async with Client(create_server(config)) as client:

            async def call(tool, **arguments):
                result = await client.call_tool(tool, arguments)
                assert not result.is_error, result.content
                return result.structured_content

            engagement = await call("engagement_create", name="batch", targets=["127.0.0.1"])
            eid = engagement["id"]
            batch = await call(
                "scan_batch",
                engagement_id=eid,
                scans=[
                    {"profile": "ports", "target": "127.0.0.1"},
                    {"profile": "ports", "target": "127.0.0.1"},
                ],
            )
            job_ids = [job["id"] for job in batch["jobs"]]
            result = await call("jobs_wait", engagement_id=eid, job_ids=job_ids, wait_seconds=10)
            assert result["all_finished"]
            assert all(item["status"] == "completed" for item in result["jobs"])
            output = await call("job_output", engagement_id=eid, job_id=job_ids[0])
            assert "batch works" in output["stdout"]["text"]
            assert "argv" not in output["job"]
            evidence = output["job"]["stdout"]
            found = await call(
                "finding_add",
                engagement_id=eid,
                title="test",
                severity="low",
                target="127.0.0.1",
                description="details",
                evidence=[evidence],
            )
            await call(
                "finding_update",
                engagement_id=eid,
                finding_id=found["id"],
                status="false_positive",
                verification_note="reviewed",
            )
            listed = await call("finding_list", engagement_id=eid, status="false_positive")
            assert listed["total"] == 1 and "description" not in listed["findings"][0]
            await call("note_add", engagement_id=eid, text="handoff")
            assert (await call("note_list", engagement_id=eid))["notes"][0]["text"] == "handoff"
            report = await call("report_generate", engagement_id=eid)
            assert report["json_path"] == "report.json"
            summary = await call("engagement_get", engagement_id=eid)
            assert summary["jobs_count"] == 2

    asyncio.run(check())


def test_response_budget_returns_actionable_mcp_error(tmp_path):
    config = Config(workspace=tmp_path, max_response_bytes=4096)

    async def check():
        async with Client(create_server(config)) as client:
            created = await client.call_tool(
                "engagement_create", {"name": "lab", "targets": ["127.0.0.1"]}
            )
            eid = created.structured_content["id"]
            uploaded = await client.call_tool(
                "input_write", {"engagement_id": eid, "name": "large.txt", "text": "a" * 10000}
            )
            assert not uploaded.is_error
            large = await client.call_tool(
                "artifact_read", {"engagement_id": eid, "path": "inputs/large.txt"}
            )
            assert large.is_error and "response budget" in large.content[0].text
            small = await client.call_tool(
                "artifact_read", {"engagement_id": eid, "path": "inputs/large.txt", "limit": 1000}
            )
            assert not small.is_error and small.structured_content["next_offset"] == 1000

    asyncio.run(check())
