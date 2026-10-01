import asyncio
import sys
from pathlib import Path

import httpx2
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from kali_mcp.config import Config
from kali_mcp.server import create_server
from kali_mcp.transport import http_app


def test_http_auth_and_shared_runtime(tmp_path):
    name = Path(sys.executable).name
    server = create_server(Config(workspace=tmp_path, allowed_tools=(name,)))
    app = http_app(server, token="a" * 64)

    async def check():
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1:8765"
            ) as http:
                assert (await http.post("/mcp", json={})).status_code == 401
                http.headers["Authorization"] = "Bearer " + "a" * 64
                async with streamable_http_client(
                    "http://127.0.0.1:8765/mcp", http_client=http
                ) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        await session.initialize()
                        created = await session.call_tool(
                            "engagement_create", {"name": "shared", "targets": ["127.0.0.1"]}
                        )
                        assert not created.is_error
                        eid = created.structured_content["id"]
                        job = await session.call_tool(
                            "run_tool",
                            {
                                "engagement_id": eid,
                                "target": "127.0.0.1",
                                "tool": name,
                                "args": ["-c", "import time; print('shared'); time.sleep(.2)"],
                            },
                        )
                        assert not job.is_error
                        job_id = job.structured_content["id"]
                # Disconnecting one HTTP client must not close the common job runtime.
                async with streamable_http_client(
                    "http://127.0.0.1:8765/mcp", http_client=http
                ) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        await session.initialize()
                        result = await session.call_tool(
                            "job_status",
                            {"engagement_id": eid, "job_id": job_id, "wait_seconds": 10},
                        )
                        assert result.structured_content["status"] == "completed"

    asyncio.run(check())


@pytest.mark.parametrize(("token", "host"), [("short", "127.0.0.1"), ("a" * 64, "0.0.0.0")])
def test_http_rejects_invalid_transport_settings(tmp_path, token, host):
    with pytest.raises(ValueError):
        http_app(create_server(Config(workspace=tmp_path)), token, host)
