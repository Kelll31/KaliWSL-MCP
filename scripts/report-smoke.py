"""Exercise target report bundles against loopback fixtures inside Kali; no external scans."""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import Client, StdioServerParameters


async def check(report_root: str):
    workspace = Path(".kali-mcp/smoke-reporting").resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    config = workspace / "config.json"
    secret = "report-smoke-fixture-not-a-real-secret"
    config.write_text(
        json.dumps(
            {
                "workspace": str(workspace),
                "report_root": report_root,
                "report_secret_env": ["REPORT_SMOKE_SECRET"],
                "allowed_targets": ["127.0.0.0/8", "::1", "localhost"],
                "allowed_tools": [Path(sys.executable).name, "nmap"],
            }
        ),
        encoding="utf-8",
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "kali_mcp", "--config", str(config)],
        env={**os.environ, "REPORT_SMOKE_SECRET": secret},
    )
    async with Client(params) as client:

        async def call(tool_name, **arguments):
            response = await client.call_tool(tool_name, arguments)
            if response.is_error:
                raise RuntimeError(f"{tool_name}: {response.content}")
            return response.structured_content

        engagement = await call(
            "engagement_create",
            name="Reporting smoke: loopback fixtures",
            targets=["127.0.0.1"],
            roe="Local fixtures only. No external scans, load testing or DoS.",
        )
        eid = engagement["id"]
        jobs = []
        for code, timeout in (
            (
                f"import sys; print({secret!r}); print('stderr fixture',file=sys.stderr)",
                30,
            ),
            ("import sys; print('intentional fixture failure',file=sys.stderr); sys.exit(7)", 30),
            ("import time; print('timeout fixture',flush=True); time.sleep(60)", 1),
        ):
            job = await call(
                "run_tool",
                engagement_id=eid,
                tool=Path(sys.executable).name,
                args=["-c", code],
                target="127.0.0.1",
                timeout=timeout,
            )
            jobs.append(job["id"])
        scan = await call(
            "scan_start",
            engagement_id=eid,
            profile="ports_quick",
            target="127.0.0.1",
            options={"ports": "1"},
        )
        jobs.append(scan["id"])
        results = await call("jobs_wait", engagement_id=eid, job_ids=jobs, wait_seconds=30)
        assert results["all_finished"], results
        expected = ["completed", "failed", "timed_out", "completed"]
        assert [job["status"] for job in results["jobs"]] == expected, results
        refusal = await client.call_tool(
            "run_tool",
            {
                "engagement_id": eid,
                "tool": Path(sys.executable).name,
                "args": ["-c", "raise SystemExit(99)"],
                "target": "192.0.2.1",
            },
        )
        assert refusal.is_error
        await call(
            "report_step_add",
            engagement_id=eid,
            target="127.0.0.1",
            command="Proposed load test (not executed)",
            status="blocked",
            reason="Fixture RoE prohibits load testing / DoS.",
            service="fixture",
        )
        await call(
            "report_summary_update",
            engagement_id=eid,
            confirmed_facts=[
                "MCP captured loopback fixture output and Nmap completed with exit code 0.",
                "Intentional failure returned exit code 7; the sleeping fixture timed out.",
                "Out-of-scope execution was refused before starting a process.",
            ],
            hypotheses=[],
            limitations=["Smoke fixtures only; no vulnerability assessment was performed."],
            next_steps=["Review raw stdout/stderr and verify report links."],
        )
        report = await call("report_generate", engagement_id=eid)
        directory = Path(report["directory"])
        data = json.loads((directory / "report.json").read_text(encoding="utf-8"))
        assert len(data["steps"]) == 6
        for path in directory.rglob("*"):
            if path.is_file():
                assert secret.encode() not in path.read_bytes(), path
        original = workspace / "engagements" / eid / "jobs" / jobs[0] / "stdout.txt"
        assert secret in original.read_text(encoding="utf-8")
        statuses = {}
        for step in data["steps"]:
            statuses[step["status"]] = statuses.get(step["status"], 0) + 1
            for raw in step["raw"].values():
                assert (directory / raw["path"]).is_file()
        print(
            json.dumps(
                {
                    "engagement_id": eid,
                    "directory": report["directory"],
                    "windows_report_file": report["windows_report_file"],
                    "statuses": statuses,
                    "private_original_preserved": True,
                    "report_secret_masked": True,
                },
                indent=2,
            )
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report-root", default=str(Path(".kali-mcp/smoke-report-bundles").resolve())
    )
    args = parser.parse_args()
    asyncio.run(check(args.report_root))


if __name__ == "__main__":
    main()
