import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_stdio_agent_workflow(tmp_path, mode):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {"workspace": str(tmp_path / "state"), "allowed_tools": [Path(sys.executable).name]}
        )
    )
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}

    async def check():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "kali_mcp", "--config", str(config)], env=env
        )
        async with Client(params, mode=mode) as client:
            tools = await client.list_tools()
            names = {tool.name for tool in tools.tools}
            assert {"scan_start", "job_status", "artifact_read", "report_generate"} <= names
            resources = await client.list_resources()
            assert "kali://profiles" in {str(resource.uri) for resource in resources.resources}
            prompts = await client.list_prompts()
            assert "pentest_workflow" in {prompt.name for prompt in prompts.prompts}
            created = await client.call_tool(
                "engagement_create", {"name": "protocol lab", "targets": ["127.0.0.1"]}
            )
            assert not created.is_error
            eid = created.structured_content["id"]
            input_file = await client.call_tool(
                "input_write", {"engagement_id": eid, "name": "words.txt", "text": "admin\nhealth"}
            )
            assert input_file.structured_content["path"] == "inputs/words.txt"
            started = await client.call_tool(
                "run_tool",
                {
                    "engagement_id": eid,
                    "tool": Path(sys.executable).name,
                    "args": ["-c", "print('protocol works')"],
                    "target": "127.0.0.1",
                },
            )
            assert not started.is_error
            job_id = started.structured_content["id"]
            status = await client.call_tool(
                "job_status", {"engagement_id": eid, "job_id": job_id, "wait_seconds": 10}
            )
            assert status.structured_content["status"] == "completed"
            output = await client.call_tool(
                "artifact_read", {"engagement_id": eid, "path": status.structured_content["stdout"]}
            )
            assert "protocol works" in output.structured_content["text"]
            report = await client.call_tool("report_generate", {"engagement_id": eid})
            assert report.structured_content["path"] == "report.md"
            rejected = await client.call_tool(
                "scan_start", {"engagement_id": eid, "profile": "ports", "target": "example.com"}
            )
            assert rejected.is_error
            assert "outside" in rejected.content[0].text

    asyncio.run(check())
