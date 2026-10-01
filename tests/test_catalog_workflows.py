import asyncio
import json
import shutil
import sys
from pathlib import Path

import pytest

from kali_mcp.config import Config
from kali_mcp.inventory import Inventory
from kali_mcp.jobs import JobManager
from kali_mcp.workflows import ScanRequest, Workflows
from kali_mcp.workspace import Workspace, write_json


def test_legacy_workspace_import_preserves_artifacts(tmp_path):
    eid = "a" * 32
    root = tmp_path / "engagements" / eid
    (root / "findings").mkdir(parents=True)
    (root / "jobs").mkdir()
    write_json(root / "engagement.json", {"id": eid, "name": "old", "targets": ["127.0.0.1"]})
    write_json(
        root / "findings" / "one.json",
        {"id": "b" * 32, "title": "old finding", "severity": "low", "verified": False},
    )
    evidence = root / "evidence.txt"
    evidence.write_text("preserved")
    workspace = Workspace(Config(workspace=tmp_path))
    assert workspace.get(eid)["name"] == "old"
    assert workspace.catalog.page("finding", eid, status="open")["total"] == 1
    assert evidence.read_text() == "preserved"
    reopened = Workspace(Config(workspace=tmp_path))
    assert reopened.catalog.page("finding", eid)["total"] == 1


def test_inventory_caches_path_lookups(tmp_path, monkeypatch):
    config = Config(workspace=tmp_path, allowed_tools=("nmap", "curl"))
    calls = []
    monkeypatch.setattr(shutil, "which", lambda name: calls.append(name) or f"/usr/bin/{name}")
    inventory = Inventory(config)
    inventory.inspect()
    inventory.inspect()
    assert calls == ["nmap", "curl"]
    inventory.inspect(refresh=True)
    assert calls == ["nmap", "curl", "nmap", "curl"]


def test_batch_preflight_prevents_partial_execution(tmp_path):
    async def check():
        name = Path(sys.executable).name
        workspace = Workspace(Config(workspace=tmp_path, allowed_tools=(name,)))
        eid = workspace.create("lab", ["127.0.0.1"])["id"]
        inventory = Inventory(workspace.config)
        jobs = JobManager(workspace, inventory)
        workflows = Workflows(workspace, inventory)
        with pytest.raises(ValueError):
            workflows.batch(
                jobs,
                eid,
                [
                    ScanRequest(profile="ports", target="127.0.0.1"),
                    ScanRequest(profile="ports", target="example.com"),
                ],
            )
        assert workspace.catalog.page("job", eid)["total"] == 0
        assert not list((workspace.engagement_path(eid) / "jobs").iterdir())
        await jobs.close()

    asyncio.run(check())


def test_findings_dedupe_state_and_nuclei_import(tmp_path):
    workspace = Workspace(Config(workspace=tmp_path))
    eid = workspace.create("lab", ["127.0.0.1"])["id"]
    path = workspace.engagement_path(eid) / "nuclei.jsonl"
    matching = {
        "template-id": "test",
        "matched-at": "http://127.0.0.1/a",
        "info": {"name": "Test finding", "severity": "high"},
    }
    outside = {**matching, "matched-at": "https://example.com"}
    path.write_text("\n".join(json.dumps(item) for item in [matching, matching, outside]))
    workflows = Workflows(workspace, Inventory(workspace.config))
    result = workflows.import_nuclei(eid, path.name)
    assert len(result["findings"]) == 2 and len(result["skipped"]) == 1
    assert result["findings"][1]["deduplicated"]
    findings = workspace.findings(eid)
    assert len(findings) == 1 and findings[0]["occurrences"] == 2
    confirmed = workspace.update_finding(
        eid, findings[0]["id"], "confirmed", verification_note="manually reproduced"
    )
    assert confirmed["verified"]
    assert workspace.catalog.page("finding", eid, status="confirmed")["total"] == 1
    workspace.note_add(eid, "Agent handoff")
    report = workspace.report(eid)
    data = json.loads(workspace.artifact(eid, report["json_path"]).read_text(encoding="utf-8"))
    assert data["findings"][0]["status"] == "confirmed"
    assert data["notes"][0]["text"] == "Agent handoff"


def test_catalog_pages_respect_response_budget(tmp_path):
    workspace = Workspace(Config(workspace=tmp_path, max_response_bytes=4096))
    eid = workspace.create("lab", ["127.0.0.1"])["id"]
    for _ in range(5):
        workspace.note_add(eid, "a" * 1500)
    page = workspace.catalog.page("note", eid)
    assert 0 < len(page["items"]) < 5
    assert page["total"] == 5 and page["next_offset"] == len(page["items"])
    remainder = workspace.catalog.page("note", eid, offset=page["next_offset"])
    assert remainder["items"][0]["id"] != page["items"][0]["id"]
