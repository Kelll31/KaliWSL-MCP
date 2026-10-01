"""Reproducible parser benchmark against the v0.1 whole-file implementations."""

import argparse
import gc
import json
import tempfile
import time
import tracemalloc
from pathlib import Path

from kali_mcp.artifacts import Artifacts
from kali_mcp.config import Config
from kali_mcp.parsers import parse_jsonl, parse_nmap
from kali_mcp.workspace import Workspace


def measure(function) -> dict:
    gc.collect()
    tracemalloc.start()
    start = time.perf_counter()
    result = function()
    elapsed = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    count = len(result.get("records", result.get("hosts", [])))
    return {
        "seconds": round(elapsed, 4),
        "peak_mib": round(peak / 1024**2, 3),
        "returned_records": count,
    }


def benchmark(records: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="kali-mcp-benchmark-") as temporary:
        workspace = Workspace(Config(workspace=Path(temporary)))
        eid = workspace.create("benchmark", ["127.0.0.1"])["id"]
        root = workspace.engagement_path(eid)
        jsonl = root / "results.jsonl"
        with jsonl.open("w", encoding="utf-8") as stream:
            for i in range(records):
                stream.write(json.dumps({"index": i, "text": "a" * 500}) + "\n")
        xml = root / "nmap.xml"
        with xml.open("w", encoding="utf-8") as stream:
            stream.write("<nmaprun>")
            for i in range(records):
                stream.write(
                    f'<host><status state="up"/><address addr="127.0.0.1"/>'
                    f'<ports><port portid="80" protocol="tcp"><state state="open"/>'
                    f'<service name="http" product="fixture-{i}"/></port></ports></host>'
                )
            stream.write("</nmaprun>")
        artifacts = Artifacts(workspace)
        return {
            "records": records,
            "page_size": 100,
            "jsonl_bytes": jsonl.stat().st_size,
            "jsonl_legacy": measure(lambda: parse_jsonl(jsonl.read_text(), limit=100)),
            "jsonl_stream": measure(lambda: artifacts.parse(eid, jsonl.name, "jsonl", cursor=0)),
            "xml_bytes": xml.stat().st_size,
            "xml_legacy": measure(lambda: {"hosts": parse_nmap(xml.read_text())["hosts"][:100]}),
            "xml_stream": measure(lambda: artifacts.parse(eid, xml.name, "nmap")),
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=20000)
    options = parser.parse_args()
    if not 100 <= options.records <= 100000:
        parser.error("--records must be within 100..100000")
    print(json.dumps(benchmark(options.records), indent=2))
