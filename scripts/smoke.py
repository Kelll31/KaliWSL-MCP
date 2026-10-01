"""Real MCP -> Kali -> Nmap -> XML -> finding -> report round trip, loopback only."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from mcp import Client, StdioServerParameters


async def smoke(wsl: bool, distro: str, workspace: str) -> None:
    if wsl:
        root = Path(__file__).resolve().parents[1]
        drive = root.drive[0].lower()
        linux_root = "/mnt/" + drive + root.as_posix()[2:]
        command = "wsl.exe"
        args = [
            "-d",
            distro,
            "--cd",
            linux_root,
            "--exec",
            f"{linux_root}/.venv-kali/bin/python",
            "-m",
            "kali_mcp",
            "--config",
            "config.local.json",
        ]
    else:
        command = sys.executable
        args = ["-m", "kali_mcp", "--config", "config.local.json"]
    args.extend(["--workspace", workspace])
    async with Client(StdioServerParameters(command=command, args=args)) as client:

        async def call(tool_name, **arguments):
            result = await client.call_tool(tool_name, arguments)
            if result.is_error:
                raise RuntimeError(f"{tool_name}: {result.content}")
            return result.structured_content

        info = await call("system_info")
        assert info["platform"] == "Linux"
        engagement = await call(
            "engagement_create", name="Loopback MCP smoke", targets=["127.0.0.1"]
        )
        eid = engagement["id"]
        job = await call(
            "scan_start",
            engagement_id=eid,
            profile="ports",
            target="127.0.0.1",
            options={"ports": "1"},
            timeout=30,
        )
        for _ in range(4):
            job = await call("job_status", engagement_id=eid, job_id=job["id"], wait_seconds=10)
            if job["status"] not in {"queued", "running"}:
                break
        if job["status"] != "completed":
            error = await call("artifact_read", engagement_id=eid, path=job["stderr"])
            raise RuntimeError(f"Nmap status: {job['status']}; {error['text']}")
        evidence = f"jobs/{job['id']}/nmap.xml"
        parsed = await call("artifact_parse", engagement_id=eid, path=evidence, format="nmap")
        assert parsed["hosts"] and parsed["hosts"][0]["ports"][0]["port"] == 1
        await call(
            "finding_add",
            engagement_id=eid,
            title="MCP loopback scan verified",
            severity="info",
            target="127.0.0.1",
            evidence=[evidence],
            description="Integration smoke check; not a vulnerability.",
        )
        report = await call("report_generate", engagement_id=eid)
        summary = await call("artifact_summary", engagement_id=eid, path=evidence, format="nmap")
        assert summary["hosts"] == 1
        print(
            json.dumps(
                {
                    "platform": info["platform"],
                    "wsl": info["wsl"],
                    "engagement": eid,
                    "job_status": job["status"],
                    "ports": parsed["hosts"][0]["ports"],
                    "version": info["version"],
                    "report_json": report["json_path"],
                    "report": f"{info['workspace']}/engagements/{eid}/{report['path']}",
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wsl", action="store_true")
    parser.add_argument("--distro", default="kali-linux")
    parser.add_argument("--workspace", default=".kali-mcp/smoke-nmap")
    options = parser.parse_args()
    asyncio.run(smoke(options.wsl, options.distro, options.workspace))
