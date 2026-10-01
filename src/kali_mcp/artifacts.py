from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .parsers import iter_nmap
from .workspace import Workspace


def encoded_size(value) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


class Artifacts:
    def __init__(self, workspace: Workspace):
        self.workspace = workspace
        self.response_limit = workspace.config.max_response_bytes

    def list(self, engagement_id: str, offset: int = 0, limit: int = 100, prefix: str = "") -> dict:
        if offset < 0 or not 1 <= limit <= 500:
            raise ValueError("offset >= 0; limit must be 1..500")
        root = self.workspace.engagement_path(engagement_id).resolve()
        items, total = [], 0
        # Sort directory entries per directory, rather than constructing a list of every path.
        for directory, directories, files in os.walk(root, followlinks=False):
            directories[:] = sorted(
                d for d in directories if not (Path(directory) / d).is_symlink()
            )
            for name in sorted(files):
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                if not relative.startswith(prefix) or path.is_symlink() or name.endswith(".tmp"):
                    continue
                if offset <= total < offset + limit:
                    items.append({"path": relative, "size": path.stat().st_size})
                total += 1
        return {"artifacts": items, "total": total, "next_offset": min(offset + len(items), total)}

    def info(self, engagement_id: str, relative: str, checksum: bool = False) -> dict:
        path = self.workspace.artifact(engagement_id, relative)
        stat = path.stat()
        result = {
            "path": relative,
            "size": stat.st_size,
            "modified_ns": stat.st_mtime_ns,
            "absolute_path": str(path),
            "untrusted": True,
        }
        if checksum:
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            result["sha256"] = digest.hexdigest()
            after = path.stat()
            result["stable"] = (
                stat.st_size == after.st_size and stat.st_mtime_ns == after.st_mtime_ns
            )
        return result

    def tail(
        self, engagement_id: str, relative: str, lines: int = 50, max_bytes: int = 32768
    ) -> dict:
        if not 1 <= lines <= 500 or not 1 <= max_bytes <= 65536:
            raise ValueError("lines must be 1..500; max_bytes must be 1..65536")
        path = self.workspace.artifact(engagement_id, relative)
        size = path.stat().st_size
        start = max(0, size - max_bytes)
        with path.open("rb") as stream:
            stream.seek(start)
            content = stream.read(max_bytes)
        selected = content.splitlines(keepends=True)[-lines:]
        text = b"".join(selected)
        return {
            "path": relative,
            "text": text.decode("utf-8", errors="replace"),
            "offset": size - len(text),
            "size": size,
            "untrusted": True,
        }

    def search(
        self,
        engagement_id: str,
        relative: str,
        query: str,
        cursor: int = 0,
        limit: int = 50,
        case_sensitive: bool = False,
    ) -> dict:
        if not query or len(query) > 500 or cursor < 0 or not 1 <= limit <= 200:
            raise ValueError("query 1..500 chars; cursor >= 0; limit 1..200")
        path = self.workspace.artifact(engagement_id, relative)
        matches, budget = [], 0
        needle = query if case_sensitive else query.casefold()
        with path.open("rb") as stream:
            if cursor > path.stat().st_size:
                raise ValueError("Cursor exceeds file size")
            stream.seek(cursor)
            scan_end = cursor + 8 * 1024 * 1024
            while stream.tell() < scan_end and len(matches) < limit:
                offset = stream.tell()
                raw = stream.readline(65537)
                if not raw:
                    break
                text = raw.decode("utf-8", errors="replace")
                if needle in (text if case_sensitive else text.casefold()):
                    item = {"offset": offset, "text": text.rstrip()[:2000]}
                    size = encoded_size(item)
                    if budget + size > self.response_limit - 1024:
                        stream.seek(offset)
                        break
                    matches.append(item)
                    budget += size
            next_cursor = stream.tell()
        return {
            "matches": matches,
            "next_cursor": next_cursor,
            "eof": next_cursor >= path.stat().st_size,
            "untrusted": True,
        }

    def parse(
        self,
        engagement_id: str,
        relative: str,
        format: str,
        offset: int = 0,
        limit: int = 100,
        cursor: int | None = None,
    ) -> dict:
        if offset < 0 or not 1 <= limit <= 500 or (cursor is not None and cursor < 0):
            raise ValueError("offset/cursor >= 0; limit must be 1..500")
        path = self.workspace.artifact(engagement_id, relative)
        if path.stat().st_size > self.workspace.config.max_artifact_bytes:
            raise ValueError("Artifact exceeds parser input limit")
        if format in {"jsonl", "nuclei", "httpx"}:
            return self.jsonl(path, offset, limit, cursor)
        if format == "nmap":
            return self.nmap(path, offset, limit)
        if format in {"ffuf", "whatweb", "json"}:
            if path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("JSON input exceeds 16 MiB; prefer JSONL for large results")
            data = json.loads(path.read_text(encoding="utf-8"))
            if format == "json":
                if encoded_size(data) > self.response_limit - 1024:
                    raise ValueError(
                        "JSON exceeds response budget; use a paginated format or artifact_read"
                    )
                return {"data": data, "untrusted": True}
            items = data.get("results", []) if format == "ffuf" else data
            if not isinstance(items, list):
                raise ValueError(f"Expected {format} records array")
            return self.record_page(items, offset, limit)
        raise ValueError("format must be nmap, json, jsonl, nuclei, httpx, ffuf, or whatweb")

    def record_page(self, items: list, offset: int, limit: int) -> dict:
        selected, budget = [], 0
        for item in items[offset : offset + limit]:
            size = encoded_size(item)
            if size > self.response_limit - 1024:
                raise ValueError("Single record exceeds response budget; use artifact_read")
            if budget + size > self.response_limit - 1024:
                break
            selected.append(item)
            budget += size
        return {
            "records": selected,
            "total": len(items),
            "next_offset": offset + len(selected),
            "eof": offset + len(selected) >= len(items),
            "untrusted": True,
        }

    def jsonl(self, path: Path, offset: int, limit: int, cursor: int | None) -> dict:
        records, skipped, budget = [], 0, 0
        with path.open("rb") as stream:
            if cursor is not None:
                if cursor > path.stat().st_size:
                    raise ValueError("Cursor exceeds file size")
                if cursor:
                    stream.seek(cursor - 1)
                    if stream.read(1) != b"\n":
                        raise ValueError("Cursor must point to a JSONL line boundary")
                stream.seek(cursor)
            while len(records) < limit:
                position = stream.tell()
                raw = stream.readline(self.response_limit + 1)
                if not raw:
                    break
                if len(raw) > self.response_limit:
                    raise ValueError("Single JSONL line exceeds response budget; use artifact_read")
                if not raw.strip():
                    continue
                if cursor is None and skipped < offset:
                    skipped += 1
                    continue
                try:
                    item = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    item = {
                        "parse_error": True,
                        "byte_offset": position,
                        "raw": raw.decode("utf-8", errors="replace")[:1000],
                    }
                size = encoded_size(item)
                if size > self.response_limit - 1024:
                    raise ValueError("Single JSONL record exceeds response budget")
                if budget + size > self.response_limit - 1024:
                    stream.seek(position)
                    break
                records.append(item)
                budget += size
            next_cursor = stream.tell()
        return {
            "records": records,
            "next_cursor": next_cursor,
            "next_offset": offset + len(records),
            "total": None,
            "eof": next_cursor >= path.stat().st_size,
            "untrusted": True,
        }

    def nmap(self, path: Path, offset: int, limit: int) -> dict:
        hosts, total, budget = [], 0, 0
        for host in iter_nmap(path):
            if offset <= total < offset + limit:
                size = encoded_size(host)
                if size > self.response_limit - 1024:
                    raise ValueError("Nmap host exceeds response budget; use artifact_read")
                if budget + size <= self.response_limit - 1024:
                    hosts.append(host)
                    budget += size
                else:
                    limit = total - offset
            total += 1
        return {
            "hosts": hosts,
            "total": total,
            "next_offset": min(offset + len(hosts), total),
            "eof": offset + len(hosts) >= total,
            "untrusted": True,
        }

    def summary(self, engagement_id: str, relative: str, format: str) -> dict:
        from collections import Counter

        path = self.workspace.artifact(engagement_id, relative)
        if path.stat().st_size > self.workspace.config.max_artifact_bytes:
            raise ValueError("Artifact exceeds summary input limit")
        if format == "nmap":
            hosts, ports = 0, 0
            services, states = Counter(), Counter()
            examples = []
            for host in iter_nmap(path):
                hosts += 1
                states[host["status"] or "unknown"] += 1
                for port in host["ports"]:
                    if port["state"] == "open":
                        ports += 1
                        services[port["service"].get("name", "unknown")] += 1
                        if len(examples) < 50:
                            examples.append(
                                {
                                    "addresses": host["addresses"],
                                    "port": port["port"],
                                    "protocol": port["protocol"],
                                    "service": port["service"].get("name"),
                                }
                            )
            return {
                "hosts": hosts,
                "host_states": dict(states),
                "open_ports": ports,
                "services": dict(services.most_common(50)),
                "examples": examples,
                "untrusted": True,
            }
        if format not in {"jsonl", "nuclei", "httpx"}:
            raise ValueError("summary format must be nmap, jsonl, nuclei, or httpx")
        records, malformed = 0, 0
        severities, status_codes = Counter(), Counter()
        cursor = 0
        while True:
            page = self.jsonl(path, 0, 100, cursor)
            for item in page["records"]:
                if not isinstance(item, dict) or item.get("parse_error"):
                    malformed += 1
                    continue
                records += 1
                info = item.get("info", {})
                if isinstance(info, dict) and "severity" in info:
                    severities[str(info["severity"])[:50]] += 1
                if "status_code" in item:
                    status_codes[str(item["status_code"])[:50]] += 1
            if page["eof"]:
                break
            cursor = page["next_cursor"]
        return {
            "records": records,
            "malformed": malformed,
            "severity_counts": dict(severities.most_common(50)),
            "http_status_counts": dict(status_codes.most_common(50)),
            "untrusted": True,
        }
