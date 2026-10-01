import json

import pytest

from kali_mcp.config import Config
from kali_mcp.workspace import Workspace


@pytest.fixture
def workspace(tmp_path):
    return Workspace(Config(workspace=tmp_path))


def test_artifacts_findings_report(workspace):
    engagement = workspace.create("Проверка Kali", ["127.0.0.1"])
    eid = engagement["id"]
    path = workspace.engagement_path(eid) / "evidence.txt"
    path.write_text("abcdef", encoding="utf-8")
    page = workspace.read(eid, "evidence.txt", offset=2, limit=3)
    assert page["text"] == "cde"
    assert page["next_offset"] == 5
    assert not page["eof"]
    finding = workspace.add_finding(
        eid, "Заголовок", "low", "127.0.0.1", "Описание", ["evidence.txt"], "Исправление"
    )
    assert not finding["verified"]
    assert workspace.get(eid)["name"] == "Проверка Kali"
    assert workspace.findings(eid)[0]["title"] == "Заголовок"
    workspace.report(eid)
    assert "Заголовок" in workspace.read(eid, "report.md")["text"]
    assert json.loads((path.parent / "engagement.json").read_text(encoding="utf-8"))


def test_path_escape(workspace, tmp_path):
    eid = workspace.create("lab", ["127.0.0.1"])["id"]
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    for value in (str(outside), "../../../secret.txt"):
        with pytest.raises(ValueError):
            workspace.read(eid, value)
    link = workspace.engagement_path(eid) / "link"
    try:
        link.symlink_to(outside)
    except OSError:
        return  # Windows may require a privilege to create symlinks.
    with pytest.raises(ValueError):
        workspace.read(eid, "link")


def test_evidence_and_target_required(workspace):
    eid = workspace.create("lab", ["127.0.0.1"])["id"]
    with pytest.raises(ValueError):
        workspace.add_finding(eid, "x", "high", "127.0.0.2", "x", [], "")
    with pytest.raises(ValueError):
        workspace.add_finding(eid, "x", "high", "127.0.0.1", "x", ["missing"], "")


def test_input_files(workspace):
    eid = workspace.create("lab", ["127.0.0.1"])["id"]
    data = workspace.write_input(eid, "wordlist.txt", "admin\nhealth\n")
    assert workspace.read(eid, data["path"])["text"] == "admin\nhealth\n"
    with pytest.raises(FileExistsError):
        workspace.write_input(eid, "wordlist.txt", "replacement")
    with pytest.raises(ValueError):
        workspace.write_input(eid, "../../escape", "payload")
    with pytest.raises(ValueError):
        workspace.write_input(eid, "big.txt", "x" * 65537)


def test_engagement_exclusions(workspace):
    eid = workspace.create("lab", ["127.0.0.0/8"], ["127.0.0.2"])["id"]
    workspace.check_target(eid, "127.0.0.1")
    with pytest.raises(ValueError, match="excluded"):
        workspace.check_target(eid, "127.0.0.2")
    with pytest.raises(ValueError, match="excluded"):
        workspace.check_target(eid, "127.0.0.0/8")
