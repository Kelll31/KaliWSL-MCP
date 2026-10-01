from __future__ import annotations

import json
import uuid
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from .artifacts import Artifacts, encoded_size
from .config import target_host
from .inventory import Inventory
from .jobs import JobManager
from .profiles import build
from .workspace import Workspace


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: str
    target: str
    options: dict = Field(default_factory=dict)
    timeout: int = Field(default=300, ge=1)


class Workflows:
    def __init__(self, workspace: Workspace, inventory: Inventory):
        self.workspace = workspace
        self.inventory = inventory
        self.artifacts = Artifacts(workspace)

    def batch(self, jobs: JobManager, engagement_id: str, requests: list[ScanRequest]) -> dict:
        if not 1 <= len(requests) <= 50:
            raise ValueError("Batch must contain 1..50 scans")
        prepared = []
        # Validate every request before starting any process or creating any job directory.
        for request in requests:
            try:
                tool, args = build(
                    request.profile,
                    request.target,
                    request.options,
                    self.workspace.config.profile_rate_limit,
                )
            except ValueError as error:
                self.workspace.reports.blocked(
                    engagement_id,
                    request.target,
                    "MCP scan_batch " + json.dumps(request.model_dump(), ensure_ascii=False),
                    "Batch rejected; no scans started. " + str(error),
                )
                raise
            jobs.preflight(engagement_id, tool, args, request.target, request.timeout)
            prepared.append((request, tool, args))
        try:
            jobs.check_capacity(len(prepared))
        except ValueError as error:
            self.workspace.reports.blocked(
                engagement_id,
                requests[0].target,
                "MCP scan_batch " + json.dumps([r.model_dump() for r in requests]),
                str(error),
            )
            raise
        estimated = [
            {"target": request.target, "tool": tool, "profile": request.profile, "argv": args}
            for request, tool, args in prepared
        ]
        estimated_bytes = encoded_size(estimated) + 1024 * len(prepared)
        if estimated_bytes > self.workspace.config.max_response_bytes:
            raise ValueError("Batch exceeds response budget; submit fewer scans")
        batch_id = uuid.uuid4().hex
        started = [
            jobs.start(
                engagement_id,
                tool,
                args,
                request.target,
                request.timeout,
                request.profile,
                batch_id,
            )
            for request, tool, args in prepared
        ]
        return {
            "batch_id": batch_id,
            "jobs": [
                {key: value for key, value in item.items() if key != "argv"} for item in started
            ],
            "count": len(started),
        }

    def recon_plan(self, engagement_id: str, target: str) -> dict:
        self.workspace.check_target(engagement_id, target)
        host = target_host(target)
        if "/" in host:
            selected = ["discovery", "ports_quick"]
        elif "://" in target:
            selected = ["http_probe", "web_fingerprint"]
            if urlsplit(target).scheme == "https":
                selected.append("tls")
        else:
            selected = ["ports_quick"]
            if not any(c in host for c in ":/") and not host.replace(".", "").isdigit():
                selected.append("dns")
        self.inventory.refresh()
        available, unavailable = [], []
        for profile in selected:
            tool, args = build(profile, target, rate_limit=self.workspace.config.profile_rate_limit)
            item = {
                "profile": profile,
                "target": target,
                "tool": tool,
                "argv": [tool, *args],
                "timeout": 300,
            }
            (available if self.inventory.paths.get(tool) else unavailable).append(item)
        return {
            "scans": available,
            "unavailable": unavailable,
            "next_step": "Inspect discovered services before choosing deeper scan profiles",
        }

    def import_nuclei(
        self, engagement_id: str, path: str, cursor: int = 0, limit: int = 100
    ) -> dict:
        page = self.artifacts.parse(engagement_id, path, "nuclei", limit=limit, cursor=cursor)
        findings, skipped = [], []
        for record in page["records"]:
            if not isinstance(record, dict) or record.get("parse_error"):
                skipped.append("Malformed JSONL record")
                continue
            target = record.get("matched-at") or record.get("host")
            info = record.get("info", {})
            if not isinstance(info, dict) or not isinstance(target, str):
                skipped.append("Record has no target or template info")
                continue
            try:
                self.workspace.check_target(engagement_id, target)
            except ValueError:
                skipped.append(f"Out-of-scope result: {target[:200]}")
                continue
            title = str(info.get("name", record.get("template-id", "Nuclei result")))[:300]
            severity = str(info.get("severity", "info"))
            classification = info.get("classification", {})
            description = str(info.get("description", "Template match; verify manually."))[:95000]
            if classification:
                description += "\n\nClassification: " + json.dumps(classification)[:4000]
            fingerprint = json.dumps(
                [record.get("template-id"), target, record.get("matcher-name")], sort_keys=True
            )
            try:
                finding = self.workspace.add_finding(
                    engagement_id,
                    title,
                    severity,
                    target,
                    description,
                    [path],
                    str(info.get("remediation", ""))[:100000],
                    fingerprint,
                )
                findings.append(
                    {
                        "id": finding["id"],
                        "severity": finding["severity"],
                        "deduplicated": finding["deduplicated"],
                    }
                )
            except ValueError as error:
                skipped.append(str(error))
        return {
            "findings": findings,
            "skipped": skipped,
            "next_cursor": page["next_cursor"],
            "eof": page["eof"],
            "verified": False,
            "untrusted": True,
        }
