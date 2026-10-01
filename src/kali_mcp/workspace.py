from __future__ import annotations

import base64
import codecs
import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock

from .catalog import Catalog
from .config import Config, denied, target_host

SEVERITIES = ("info", "low", "medium", "high", "critical")
FINDING_STATES = ("open", "confirmed", "false_positive", "resolved")


def now() -> str:
    return datetime.now(UTC).isoformat()


def write_json(path: Path, data: dict) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2))


def write_text(path: Path, text: str) -> None:
    temporary = path.with_name(f".{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


class Workspace:
    def __init__(self, config: Config):
        self.config = config
        self.root = config.workspace.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.root / "engagements").mkdir(exist_ok=True, mode=0o700)
        self.catalog = Catalog(self.root, config.max_response_bytes)
        self.mutations = RLock()
        from .reporting import Reports

        self.reports = Reports(self)

    def engagement_path(self, engagement_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", engagement_id):
            raise ValueError("Invalid engagement ID")
        path = self.root / "engagements" / engagement_id
        if not (path / "engagement.json").is_file():
            raise ValueError("Engagement not found")
        return path

    def create(
        self,
        name: str,
        targets: list[str],
        excluded_targets: list[str] | None = None,
        roe: str = "",
    ) -> dict:
        if not name.strip() or len(name) > 200 or not targets or len(targets) > 100:
            raise ValueError("Provide a name (1..200 chars) and 1..100 targets")
        if len(roe.encode("utf-8")) > 32768:
            raise ValueError("RoE text is limited to 32 KiB")
        for target in targets:
            self.config.check_rule(target)
        excluded_targets = excluded_targets or []
        if len(excluded_targets) > 100:
            raise ValueError("Provide at most 100 exclusion rules")
        for rule in excluded_targets:
            target_host(rule[2:] if rule.startswith("*.") else rule)
        engagement_id = uuid.uuid4().hex
        path = self.root / "engagements" / engagement_id
        path.mkdir(mode=0o700)
        (path / "jobs").mkdir(mode=0o700)
        (path / "findings").mkdir(mode=0o700)
        data = {
            "id": engagement_id,
            "name": name,
            "targets": targets,
            "excluded_targets": excluded_targets,
            "created_at": now(),
            "roe": roe,
        }
        write_json(path / "engagement.json", data)
        self.catalog.put("engagement", data, engagement_id)
        self.reports.generate(engagement_id)
        return self.get(engagement_id)

    def get(self, engagement_id: str) -> dict:
        self.engagement_path(engagement_id)
        data = self.catalog.get("engagement", engagement_id)
        if data is None:
            raise ValueError("Engagement metadata not found")
        return data

    def list(self) -> list[dict]:
        return self.catalog.all("engagement")

    def check_target(self, engagement_id: str, target: str) -> None:
        engagement = self.get(engagement_id)
        self.config.check_target(target, engagement["targets"])
        if any(denied(target, rule) for rule in engagement.get("excluded_targets", [])):
            raise ValueError(f"Target {target!r} intersects engagement-excluded scope")

    def artifact(self, engagement_id: str, relative: str) -> Path:
        root = self.engagement_path(engagement_id).resolve()
        path = (root / relative).resolve()
        if path == root or not path.is_relative_to(root):
            raise ValueError("Artifact path escapes engagement")
        if path.is_symlink() or not path.is_file():
            raise ValueError("Artifact not found")
        return path

    def read(
        self,
        engagement_id: str,
        relative: str,
        offset: int = 0,
        limit: int = 32768,
        encoding: str = "utf-8",
    ) -> dict:
        if offset < 0 or not 1 <= limit <= 65536:
            raise ValueError("offset >= 0; limit must be 1..65536 bytes")
        path = self.artifact(engagement_id, relative)
        if encoding not in {"utf-8", "base64"}:
            raise ValueError("encoding must be utf-8 or base64")
        size = path.stat().st_size
        with path.open("rb") as stream:
            stream.seek(offset)
            content = stream.read(limit)
            if encoding == "utf-8":
                decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
                text = decoder.decode(content, final=offset + len(content) >= size)
                pending = decoder.getstate()[0]
                if pending and not text:
                    extra = stream.read(3)
                    content += extra
                    text += decoder.decode(extra, final=offset + len(content) >= size)
                    pending = decoder.getstate()[0]
                if pending:
                    content = content[: -len(pending)]
                payload = {"text": text}
            else:
                payload = {"data": base64.b64encode(content).decode("ascii")}
        return {
            "path": relative,
            **payload,
            "encoding": encoding,
            "offset": offset,
            "next_offset": offset + len(content),
            "size": size,
            "eof": offset + len(content) >= size,
            "untrusted": True,
        }

    def write_input(self, engagement_id: str, name: str, text: str) -> dict:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}", name):
            raise ValueError("Input name must be a basename with 1..100 characters")
        content = text.encode("utf-8")
        if len(content) > 65536:
            raise ValueError("Input exceeds 64 KiB")
        root = self.engagement_path(engagement_id).resolve()
        directory = root / "inputs"
        if directory.is_symlink():
            raise ValueError("Inputs directory must not be a symlink")
        directory.mkdir(exist_ok=True, mode=0o700)
        destination = directory / name
        if destination.is_symlink() or not destination.resolve().is_relative_to(root):
            raise ValueError("Input path escapes engagement")
        # Inputs are immutable; reuse requires choosing a new filename.
        with destination.open("xb") as stream:
            stream.write(content)
        return {"path": f"inputs/{name}", "absolute_path": str(destination), "size": len(content)}

    def findings(self, engagement_id: str) -> list[dict]:
        self.engagement_path(engagement_id)
        return self.catalog.all("finding", engagement_id)

    def add_finding(
        self,
        engagement_id: str,
        title: str,
        severity: str,
        target: str,
        description: str,
        evidence: list[str],
        remediation: str,
        fingerprint: str | None = None,
    ) -> dict:
        self.check_target(engagement_id, target)
        if severity not in SEVERITIES:
            raise ValueError("Invalid severity")
        if not title.strip() or len(title) > 300 or len(description) > 100000:
            raise ValueError("Invalid finding title or description length")
        for relative in evidence:
            self.artifact(engagement_id, relative)
        key = fingerprint or json.dumps([target, title.strip().casefold()], ensure_ascii=False)
        identifier = hashlib.sha256(f"{engagement_id}\0{key}".encode()).hexdigest()[:32]
        with self.mutations:
            existing = self.catalog.get("finding", identifier, engagement_id)
            if existing is not None:
                existing["evidence"] = sorted(set(existing["evidence"]) | set(evidence))
                existing["last_seen_at"] = now()
                existing["occurrences"] = existing.get("occurrences", 1) + 1
                write_json(
                    self.engagement_path(engagement_id) / "findings" / f"{identifier}.json",
                    existing,
                )
                self.catalog.put("finding", existing, engagement_id)
                self.reports.generate(engagement_id)
                return {**existing, "deduplicated": True}
            data = {
                "id": identifier,
                "title": title,
                "severity": severity,
                "target": target,
                "description": description,
                "evidence": evidence,
                "remediation": remediation,
                "created_at": now(),
                "verified": False,
                "status": "open",
                "occurrences": 1,
            }
            destination = self.engagement_path(engagement_id) / "findings" / f"{identifier}.json"
            write_json(destination, data)
            self.catalog.put("finding", data, engagement_id)
            self.reports.generate(engagement_id)
            return {**data, "deduplicated": False}

    def update_finding(
        self,
        engagement_id: str,
        finding_id: str,
        status: str,
        severity: str | None = None,
        remediation: str | None = None,
        verification_note: str = "",
    ) -> dict:
        self.engagement_path(engagement_id)
        if status not in FINDING_STATES or (severity is not None and severity not in SEVERITIES):
            raise ValueError("Invalid finding state or severity")
        if len(verification_note) > 10000 or (
            remediation is not None and len(remediation) > 100000
        ):
            raise ValueError("Finding update text is too large")
        with self.mutations:
            data = self.catalog.get("finding", finding_id, engagement_id)
            if data is None:
                raise ValueError("Finding not found")
            data.update(
                status=status,
                verified=status == "confirmed",
                updated_at=now(),
                verification_note=verification_note,
            )
            if severity is not None:
                data["severity"] = severity
            if remediation is not None:
                data["remediation"] = remediation
            destination = self.engagement_path(engagement_id) / "findings" / f"{data['id']}.json"
            write_json(destination, data)
            self.catalog.put("finding", data, engagement_id)
            self.reports.generate(engagement_id)
            return data

    def note_add(self, engagement_id: str, text: str) -> dict:
        if not text.strip() or len(text.encode("utf-8")) > 32768:
            raise ValueError("Note must contain 1..32768 UTF-8 bytes")
        root = self.engagement_path(engagement_id) / "notes"
        root.mkdir(exist_ok=True, mode=0o700)
        data = {"id": uuid.uuid4().hex, "text": text, "created_at": now()}
        write_json(root / f"{data['id']}.json", data)
        self.catalog.put("note", data, engagement_id)
        self.reports.generate(engagement_id)
        return data

    def report(self, engagement_id: str) -> dict:
        return self.reports.generate(engagement_id)
