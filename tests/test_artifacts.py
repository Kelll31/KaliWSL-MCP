import base64
import hashlib
import json

import pytest

from kali_mcp.artifacts import Artifacts, encoded_size
from kali_mcp.config import Config
from kali_mcp.workspace import Workspace


@pytest.fixture
def lab(tmp_path):
    workspace = Workspace(Config(workspace=tmp_path))
    eid = workspace.create("lab", ["127.0.0.1"])["id"]
    return workspace, Artifacts(workspace), eid, workspace.engagement_path(eid)


def test_jsonl_cursor_pages_do_not_drop_records(lab):
    _, artifacts, eid, root = lab
    path = root / "records.jsonl"
    records = [{"index": i, "text": "Проверка" * 1000} for i in range(30)]
    path.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in records), encoding="utf-8"
    )
    cursor, received = 0, []
    while True:
        page = artifacts.parse(eid, path.name, "jsonl", limit=30, cursor=cursor)
        assert encoded_size(page) < artifacts.response_limit
        received.extend(page["records"])
        if page["eof"]:
            break
        assert page["next_cursor"] > cursor
        cursor = page["next_cursor"]
    assert received == records


def test_jsonl_invalid_cursor_and_large_record(lab):
    _, artifacts, eid, root = lab
    (root / "a.jsonl").write_text('{"id":1}\ninvalid\n{"id":2}\n')
    with pytest.raises(ValueError, match="boundary"):
        artifacts.parse(eid, "a.jsonl", "jsonl", cursor=2)
    page = artifacts.parse(eid, "a.jsonl", "jsonl", offset=1, limit=1)
    assert page["records"][0]["parse_error"]
    (root / "big.jsonl").write_text(json.dumps({"text": "a" * 200000}))
    with pytest.raises(ValueError, match="budget"):
        artifacts.parse(eid, "big.jsonl", "jsonl")


def test_nmap_stream_pagination_and_summary(lab):
    _, artifacts, eid, root = lab
    host = (
        '<host><status state="up"/><address addr="127.0.0.1"/>'
        '<ports><port portid="80" protocol="tcp"><state state="open"/>'
        '<service name="http"/></port></ports></host>'
    )
    (root / "nmap.xml").write_text("<nmaprun>" + host * 20 + "</nmaprun>")
    page = artifacts.parse(eid, "nmap.xml", "nmap", offset=3, limit=5)
    assert len(page["hosts"]) == 5 and page["total"] == 20 and page["next_offset"] == 8
    summary = artifacts.summary(eid, "nmap.xml", "nmap")
    assert summary["open_ports"] == 20 and summary["services"] == {"http": 20}


def test_tail_search_checksum_and_binary(lab):
    workspace, artifacts, eid, root = lab
    data = b"first\nTARGET middle\nlast\n"
    (root / "a.txt").write_bytes(data)
    assert artifacts.tail(eid, "a.txt", lines=1)["text"] == "last\n"
    matched = artifacts.search(eid, "a.txt", "target", limit=1)
    assert matched["matches"][0]["offset"] == 6
    assert artifacts.info(eid, "a.txt", checksum=True)["sha256"] == hashlib.sha256(data).hexdigest()
    (root / "binary").write_bytes(bytes(range(256)))
    result = workspace.read(eid, "binary", encoding="base64")
    assert base64.b64decode(result["data"]) == bytes(range(256))


def test_utf8_byte_pages_preserve_text(lab):
    workspace, _, eid, root = lab
    expected = "Привет 🌍 — проверка"
    (root / "utf8").write_text(expected, encoding="utf-8")
    text, offset = "", 0
    for _ in range(100):
        page = workspace.read(eid, "utf8", offset, limit=1)
        text += page["text"]
        if page["eof"]:
            break
        assert page["next_offset"] > offset
        offset = page["next_offset"]
    assert text == expected


def test_ffuf_and_whatweb_records(lab):
    _, artifacts, eid, root = lab
    (root / "ffuf.json").write_text(json.dumps({"results": [{"status": 200}, {"status": 403}]}))
    page = artifacts.parse(eid, "ffuf.json", "ffuf", limit=1)
    assert page["records"] == [{"status": 200}] and page["total"] == 2
    (root / "whatweb.json").write_text('[{"target":"http://localhost"}]')
    assert artifacts.parse(eid, "whatweb.json", "whatweb")["eof"]


def test_prefix_listing(lab):
    _, artifacts, eid, root = lab
    (root / "a").mkdir()
    (root / "a" / "one.txt").write_text("1")
    (root / "a" / "two.txt").write_text("2")
    page = artifacts.list(eid, limit=1, prefix="a/")
    assert page["total"] == 2 and page["artifacts"][0]["path"] == "a/one.txt"
