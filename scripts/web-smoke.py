"""Exercise real curl, WhatWeb and ffuf against a temporary loopback HTTP fixture in Kali."""

import asyncio
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from mcp import Client, StdioServerParameters


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status = 200 if self.path in {"/", "/health", "/admin"} else 404
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><title>Kali MCP fixture</title><body>ready</body></html>")

    def log_message(self, *args):
        pass


async def check(url: str):
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "kali_mcp",
            "--config",
            "config.local.json",
            "--workspace",
            ".kali-mcp/smoke-web",
        ],
    )
    async with Client(params) as client:

        async def call(tool_name, **arguments):
            result = await client.call_tool(tool_name, arguments)
            if result.is_error:
                raise RuntimeError(f"{tool_name}: {result.content}")
            return result.structured_content

        engagement = await call(
            "engagement_create", name="Loopback web integration", targets=["127.0.0.1"]
        )
        eid = engagement["id"]
        wordlist = await call(
            "input_write", engagement_id=eid, name="paths.txt", text="health\nadmin\nmissing\n"
        )
        batch = await call(
            "scan_batch",
            engagement_id=eid,
            scans=[
                {"profile": "http_probe", "target": url},
                {"profile": "web_fingerprint", "target": url},
                {
                    "profile": "web_content",
                    "target": url,
                    "options": {"wordlist": wordlist["absolute_path"]},
                },
            ],
        )
        ids = [job["id"] for job in batch["jobs"]]
        result = await call("jobs_wait", engagement_id=eid, job_ids=ids, wait_seconds=30)
        for job in result["jobs"]:
            if job["status"] != "completed":
                output = await call("job_output", engagement_id=eid, job_id=job["id"])
                raise RuntimeError(f"{job['profile']}: {output}")
        by_profile = {job["profile"]: job for job in result["jobs"]}
        probe = by_profile["http_probe"]
        metadata = await call(
            "artifact_parse", engagement_id=eid, path=probe["stdout"], format="json"
        )
        assert metadata["data"]["http_code"] == 200
        ffuf = await call(
            "artifact_parse",
            engagement_id=eid,
            path=f"jobs/{by_profile['web_content']['id']}/ffuf.json",
            format="ffuf",
        )
        assert sorted(item["status"] for item in ffuf["records"]) == [200, 200]
        whatweb = await call(
            "artifact_parse",
            engagement_id=eid,
            path=f"jobs/{by_profile['web_fingerprint']['id']}/whatweb.json",
            format="whatweb",
        )
        assert whatweb["records"]
        report = await call("report_generate", engagement_id=eid)
        print(
            json.dumps(
                {
                    "engagement": eid,
                    "profiles": list(by_profile),
                    "http_status": 200,
                    "content_matches": len(ffuf["records"]),
                    "report": report,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    fixture_thread = Thread(target=fixture.serve_forever, daemon=True)
    fixture_thread.start()
    try:
        asyncio.run(check(f"http://127.0.0.1:{fixture.server_port}"))
    finally:
        fixture.shutdown()
        fixture.server_close()
        fixture_thread.join()
