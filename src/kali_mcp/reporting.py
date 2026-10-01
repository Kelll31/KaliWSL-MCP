"""Durable per-engagement reports with redacted, complete stdout/stderr copies."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from .config import target_host
from .redaction import Redactor
from .workspace import now, write_json, write_text

if TYPE_CHECKING:
    from .workspace import Workspace

FINAL_STATES = {
    "completed": "success",
    "failed": "fail",
    "timed_out": "timeout",
    "cancelled": "blocked",
    "output_limit": "blocked",
    "artifact_limit": "blocked",
    "interrupted": "fail",
}
SUMMARY_KEYS = ("confirmed_facts", "hypotheses", "limitations", "next_steps")


def slug(value: str, length: int = 70) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")[:length] or "target"


def write_bytes(path: Path, content: bytes) -> None:
    if path.is_symlink():
        raise ValueError("Report files must not be symlinks")
    temporary = path.with_name(f".{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(content)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def windows_path(path: Path) -> str | None:
    if os.name == "nt":
        return str(path)
    if not (converter := shutil.which("wslpath")):
        return None
    result = subprocess.run(
        [converter, "-w", str(path)], capture_output=True, text=True, timeout=5, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else None


def utc_timestamp(value: str | None = None) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if value else datetime.now(UTC)
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("timestamp_utc must include the UTC timezone")
    return parsed.isoformat()


def fenced(text: str) -> list[str]:
    # Tool output may contain Markdown fences; it must remain literal in the report.
    fence = "~" * max(3, max((len(m[0]) + 1 for m in re.finditer(r"~+", text)), default=3))
    return [fence + "text", text, fence]


class Reports:
    def __init__(self, workspace: Workspace):
        self.workspace = workspace
        self.redactor = Redactor(workspace.config.report_secret_env)
        self.secret_registry = workspace.root / ".report-secrets.json"
        if self.secret_registry.is_symlink():
            raise ValueError("Private report redaction registry must not be a symlink")
        stored = (
            json.loads(self.secret_registry.read_text(encoding="utf-8"))
            if (self.secret_registry.exists())
            else {"values": []}
        )
        if (
            not isinstance(stored, dict)
            or not isinstance(stored.get("values"), list)
            or any(not isinstance(value, str) or not value for value in stored["values"])
        ):
            raise ValueError("Invalid private report redaction registry")
        self.remembered = {value.encode("utf-8") for value in stored["values"]}
        self.redactor.values = sorted(
            set(self.redactor.values) | self.remembered, key=lambda value: (-len(value), value)
        )
        self.root = (workspace.config.report_root or workspace.root / "reports").resolve()
        self.evidence_cache: dict[tuple, tuple] = {}

    @property
    def redaction_id(self) -> str:
        return hashlib.sha256(b"v2\0" + b"\0".join(self.redactor.values)).hexdigest()

    def remember(self, values) -> None:
        remembered = self.remembered | set(values)
        if remembered != self.remembered:
            if self.secret_registry.is_symlink():
                raise ValueError("Private report redaction registry must not be a symlink")
            write_json(
                self.secret_registry,
                {
                    "values": [value.decode("utf-8") for value in sorted(remembered)],
                    "private": True,
                },
            )
            self.remembered = remembered
            self.redactor.values = sorted(
                set(self.redactor.values) | self.remembered, key=lambda value: (-len(value), value)
            )

    def remember_metadata(self, value) -> None:
        if isinstance(value, str):
            content = value.encode("utf-8")
            self.remember(secret for secret in self.redactor.values if secret in content)
        elif isinstance(value, list):
            for item in value:
                self.remember_metadata(item)
        elif isinstance(value, dict):
            for item in value.values():
                self.remember_metadata(item)

    def directory(self, engagement_id: str, create: bool = False) -> Path | None:
        engagement = self.workspace.get(engagement_id)
        folder = engagement.get("report_folder")
        if folder is None:
            if not create:
                return None
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = target_host(engagement["targets"][0].removeprefix("*."))
            if len(engagement["targets"]) > 1:
                target += f"_and_{len(engagement['targets']) - 1}_more"
            timestamp = datetime.fromisoformat(engagement.get("created_at") or now()).astimezone(
                UTC
            )
            base = f"pentest_{slug(target)}_{timestamp:%Y%m%d_%H%M}"
            folder = base
            try:
                (self.root / folder).mkdir(mode=0o700)
            except FileExistsError:
                folder = f"{base}_{engagement_id[:8]}"
                try:
                    (self.root / folder).mkdir(mode=0o700)
                except FileExistsError:
                    folder = f"{base}_{engagement_id}"
                    (self.root / folder).mkdir(mode=0o700)
            engagement.update(
                report_folder=folder,
                report_directory=str(self.root / folder),
                report_windows_directory=windows_path(self.root / folder),
            )
            write_json(
                self.workspace.engagement_path(engagement_id) / "engagement.json", engagement
            )
            self.workspace.catalog.put("engagement", engagement, engagement_id)
        if not re.fullmatch(r"pentest_[A-Za-z0-9._-]{1,150}", folder):
            raise ValueError("Invalid report folder metadata")
        directory = self.root / folder
        if directory.is_symlink() or not directory.resolve().is_relative_to(self.root):
            raise ValueError("Report directory escapes report_root")
        if create:
            manifest = directory / "report.json"
            if engagement.get("report_directory") != str(directory) and manifest.exists():
                if manifest.is_symlink():
                    raise ValueError("Report manifest must not be a symlink")
                owner = json.loads(manifest.read_text(encoding="utf-8"))["engagement"]["id"]
                if owner != engagement_id:
                    if folder.endswith((engagement_id, engagement_id[:8])):
                        raise ValueError("Destination report belongs to another engagement")
                    folder = f"{folder}_{engagement_id[:8]}"
                    directory = self.root / folder
                    if directory.exists() or directory.is_symlink():
                        raise ValueError("Destination report collision; choose another report_root")
                    engagement["report_folder"] = folder
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            raw = directory / "raw"
            if raw.is_symlink():
                raise ValueError("Raw report directory must not be a symlink")
            raw.mkdir(exist_ok=True, mode=0o700)
            if engagement.get("report_directory") != str(directory):
                engagement.update(
                    report_directory=str(directory),
                    report_windows_directory=windows_path(directory),
                )
                write_json(
                    self.workspace.engagement_path(engagement_id) / "engagement.json", engagement
                )
                self.workspace.catalog.put("engagement", engagement, engagement_id)
        return directory

    def status(self, engagement_id: str) -> dict:
        directory = self.directory(engagement_id)
        engagement = self.workspace.get(engagement_id)
        win = engagement.get("report_windows_directory")
        return {
            "directory": str(directory) if directory else None,
            "windows_directory": win,
            "report_file": str(directory / "report.md") if directory else None,
            "windows_report_file": str(PureWindowsPath(win) / "report.md") if win else None,
            "raw_directory": str(directory / "raw") if directory else None,
            "exists": bool(directory and (directory / "report.md").is_file()),
            "steps": sum(self.workspace.catalog.counts("step", engagement_id).values()),
            "redacted": True,
            "export_errors": [
                {"job_id": job["id"], "error": self.redactor.text(job["report_error"])}
                for job in self.workspace.catalog.all("job", engagement_id)
                if job.get("report_error")
            ][-10:],
        }

    def _save_step(self, engagement_id: str, step: dict) -> None:
        root = self.workspace.engagement_path(engagement_id) / "steps"
        root.mkdir(exist_ok=True, mode=0o700)
        write_json(root / f"{step['id']}.json", step)
        self.workspace.catalog.put("step", step, engagement_id)

    def _capture(self, engagement_id: str, step: dict, sources: dict[str, Path | None]) -> None:
        directory = self.directory(engagement_id, create=True)
        timestamp = datetime.fromisoformat(step["created_at"]).astimezone(UTC)
        prefix = f"{slug(step.get('tool') or 'step', 30)}_{timestamp:%Y%m%d_%H%M%S}_{step['id']}"
        step["raw"] = {}
        step["_redaction_id"] = self.redaction_id
        total = 0
        for channel, source in sources.items():
            captured = bool(source and source.is_file())
            if captured:
                if source.is_symlink():
                    raise ValueError("Raw source must not be a symlink")
                if not source.resolve().is_relative_to(
                    self.workspace.engagement_path(engagement_id).resolve()
                ):
                    raise ValueError("Raw source escapes engagement")
                with source.open("rb") as stream:
                    content = stream.read(self.workspace.config.max_output_bytes - total + 1)
                total += len(content)
                if total > self.workspace.config.max_output_bytes:
                    raise ValueError("Manual raw evidence exceeds max_output_bytes")
            else:
                content = b""
            exported = self.redactor.bytes(content)
            self.remember(value for value in self.redactor.values if value in content)
            relative = f"raw/{prefix}.{channel}.txt"
            write_bytes(directory / relative, exported)
            step["raw"][channel] = {
                "path": relative,
                "captured": captured,
                "source_bytes": len(content),
                "bytes": len(exported),
                "sha256": hashlib.sha256(exported).hexdigest(),
                "redacted": content != exported,
            }

    def observe_job(self, job: dict, refresh_report: bool = True) -> None:
        eid = job["engagement_id"]
        with self.workspace.mutations:
            self.remember(
                set(self.redactor.scoped(job.get("argv", [])).values) - set(self.redactor.values)
            )
            previous = self.workspace.catalog.get("step", job["id"], eid)
            step = {
                "id": job["id"],
                "created_at": job.get("created_at", now()),
                "timestamp_utc": job.get("started_at") or job.get("created_at", now()),
                "finished_at": job.get("finished_at"),
                "target": job.get("target") or self.workspace.get(eid)["targets"][0],
                "port": None,
                "service": {
                    "dig": "dns",
                    "smbclient": "smb",
                    "sslscan": "tls",
                    "testssl.sh": "tls",
                }.get(job.get("tool"), ""),
                "profile": job.get("profile"),
                "tool": job.get("tool", "unknown"),
                "argv": job.get("argv", []),
                "command": shlex.join(self.redactor.argv(job.get("argv", []))),
                "status": FINAL_STATES.get(job["status"], "pending"),
                "job_status": job["status"],
                "exit_code": job.get("exit_code"),
                "executed": bool(job.get("started_at")),
                "provenance": "mcp_observed",
                "reason": job.get("error")
                or {
                    "timed_out": (
                        f"Execution exceeded the {job.get('timeout', 'configured')}s timeout."
                    ),
                    "cancelled": "Execution was cancelled.",
                    "output_limit": "Capture stopped at the stdout/stderr output quota.",
                    "artifact_limit": "Execution stopped at the job artifact quota.",
                    "interrupted": "Server restarted; final process state was not observed.",
                }.get(job["status"], ""),
                "summary": "",
                "job_id": job["id"],
                "output_incomplete": job["status"]
                in {"output_limit", "artifact_limit", "cancelled", "timed_out", "interrupted"},
            }
            if "://" in step["target"]:
                parsed = urlsplit(step["target"])
                step["port"] = parsed.port or (443 if parsed.scheme == "https" else 80)
                step["service"] = parsed.scheme
            elif job.get("tool") == "nmap" and "-p" in step["argv"]:
                index = step["argv"].index("-p") + 1
                if index < len(step["argv"]) and step["argv"][index].isdigit():
                    step["port"] = int(step["argv"][index])
                elif index < len(step["argv"]):
                    step["ports"] = step["argv"][index]
            if previous:
                step["created_at"] = previous["created_at"]
                step["raw"] = previous["raw"]
                step["_redaction_id"] = previous.get("_redaction_id")
            if (
                not previous
                or job["status"] in FINAL_STATES
                or any(
                    not (self.directory(eid, create=True) / raw["path"]).is_file()
                    for raw in previous["raw"].values()
                )
            ):
                sources = {
                    channel: (
                        self.workspace.engagement_path(eid) / job[channel]
                        if job.get(channel) and job["status"] in FINAL_STATES
                        else None
                    )
                    for channel in ("stdout", "stderr")
                }
                self._capture(eid, step, sources)
                if job["status"] in FINAL_STATES:
                    step["summary"] = self.preview(eid, step)
            self._save_step(eid, step)
            if refresh_report:
                self.generate(eid)

    def preview(self, engagement_id: str, step: dict) -> str:
        previews = []
        for raw in step["raw"].values():
            if raw["captured"]:
                exported = self.directory(engagement_id) / raw["path"]
                with exported.open("rb") as stream:
                    content = stream.read(2048).decode("utf-8", errors="replace")
                previews.extend(line[:300] for line in content.splitlines() if line.strip())
        return "\n".join(previews[:2])

    def add_step(
        self,
        engagement_id: str,
        target: str,
        command: str,
        status: str,
        stdout: str = "",
        stderr: str = "",
        exit_code: int | None = None,
        summary: str = "",
        reason: str = "",
        port: int | None = None,
        service: str = "",
        stdout_path: str | None = None,
        stderr_path: str | None = None,
        timestamp_utc: str | None = None,
        _observed: bool = False,
    ) -> dict:
        self.workspace.engagement_path(engagement_id)
        if status not in {"success", "fail", "timeout", "blocked"}:
            raise ValueError("status must be success, fail, timeout or blocked")
        if status != "blocked":
            self.workspace.check_target(engagement_id, target)
        if not command.strip() or (not _observed and len(command.encode()) > 32768):
            raise ValueError("Provide an exact command/request up to 32 KiB")
        if len(summary) > 2000 or len(reason) > 10000 or len(service) > 100:
            raise ValueError("Step summary, reason or service is too long")
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError("port must be 1..65535")
        if exit_code is not None and type(exit_code) is not int:
            raise ValueError("exit_code must be an integer or null")
        if status == "success" and exit_code not in (None, 0):
            raise ValueError("success cannot have a nonzero exit_code")
        if status == "blocked" and (
            stdout or stderr or stdout_path or stderr_path or exit_code is not None
        ):
            raise ValueError("blocked means not executed; do not supply output or exit_code")
        if status == "blocked" and not reason.strip():
            raise ValueError("blocked steps require a reason")
        timestamp = utc_timestamp(timestamp_utc)
        sources = {}
        total = 0
        for channel, text, source in (
            ("stdout", stdout, stdout_path),
            ("stderr", stderr, stderr_path),
        ):
            if source is not None and text:
                raise ValueError(f"Provide {channel} text or {channel}_path, not both")
            if len(text.encode("utf-8")) > 65536:
                raise ValueError(
                    "Inline output is limited to 64 KiB per stream; use artifact paths"
                )
            sources[channel] = self.workspace.artifact(engagement_id, source) if source else None
            total += sources[channel].stat().st_size if source else len(text.encode("utf-8"))
        if total > self.workspace.config.max_output_bytes:
            raise ValueError("Manual raw evidence exceeds max_output_bytes")
        with self.workspace.mutations:
            try:
                requested_argv = shlex.split(command)
            except ValueError:
                requested_argv = []
            self.remember(
                set(self.redactor.scoped(requested_argv).values) - set(self.redactor.values)
            )
            identifier = uuid.uuid4().hex
            root = self.workspace.engagement_path(engagement_id) / "steps" / identifier
            root.mkdir(parents=True, mode=0o700)
            for channel, text in (("stdout", stdout), ("stderr", stderr)):
                if status != "blocked":
                    destination = root / f"{channel}.txt"
                    content = sources[channel].read_bytes() if sources[channel] else text.encode()
                    if len(content) > self.workspace.config.max_output_bytes:
                        raise ValueError("Manual raw evidence changed beyond max_output_bytes")
                    write_bytes(destination, content)
                    sources[channel] = destination
            step = {
                "id": identifier,
                "created_at": timestamp,
                "timestamp_utc": timestamp,
                "target": target,
                "port": port,
                "service": service,
                "command": command,
                "status": status,
                "exit_code": exit_code,
                "summary": "\n".join(summary.splitlines()[:2]),
                "reason": reason,
                "executed": status != "blocked",
                "provenance": "mcp_observed" if _observed else "agent_supplied",
                "source_paths": {
                    key: value.relative_to(self.workspace.engagement_path(engagement_id)).as_posix()
                    if value
                    else None
                    for key, value in sources.items()
                },
            }
            self._capture(engagement_id, step, sources)
            if not step["summary"]:
                step["summary"] = self.preview(engagement_id, step)
            self._save_step(engagement_id, step)
            self.generate(engagement_id)
            return self.redactor.object(step)

    def blocked(self, engagement_id: str, target: str, command: str, reason: str) -> None:
        self.add_step(engagement_id, target, command, "blocked", reason=reason, _observed=True)

    def summary_update(self, engagement_id: str, **sections: list[str] | None) -> dict:
        with self.workspace.mutations:
            data = self.workspace.catalog.get("summary", engagement_id, engagement_id) or {
                "id": engagement_id,
                "created_at": now(),
                **{key: [] for key in SUMMARY_KEYS},
            }
            for key, value in sections.items():
                if key not in SUMMARY_KEYS:
                    raise ValueError("Unknown summary section")
                if value is not None:
                    if len(value) > 100 or any(not v.strip() or len(v) > 2000 for v in value):
                        raise ValueError(
                            "Each summary section allows 100 non-empty items up to 2000 chars"
                        )
                    data[key] = value
            data["updated_at"] = now()
            self.workspace.engagement_path(engagement_id)
            write_json(self.workspace.engagement_path(engagement_id) / "summary.json", data)
            self.workspace.catalog.put("summary", data, engagement_id)
            self.generate(engagement_id)
            return self.redactor.object(data)

    def export_evidence(self, engagement_id: str, findings: list[dict], steps: list[dict]) -> dict:
        directory = self.directory(engagement_id, create=True)
        destination_root = directory / "evidence"
        if destination_root.is_symlink():
            raise ValueError("Evidence directory must not be a symlink")
        source_map = {}
        for step in steps:
            if step.get("job_id"):
                for channel, raw in step["raw"].items():
                    source_map[f"jobs/{step['job_id']}/{channel}.txt"] = raw
        exports = {}
        for relative in sorted({p for finding in findings for p in finding["evidence"]}):
            if relative in source_map:
                exports[relative] = source_map[relative]
                continue
            try:
                source = self.workspace.artifact(engagement_id, relative)
                stat = source.stat()
                prefix = hashlib.sha256(relative.encode()).hexdigest()[:16]
                destination = destination_root / f"{prefix}_{slug(source.name)}"
                fingerprint = (stat.st_size, stat.st_mtime_ns, self.redaction_id)
                key = (engagement_id, relative, str(directory))
                cached = self.evidence_cache.get(key)
                if (
                    cached
                    and cached[0] == fingerprint
                    and destination.is_file()
                    and not destination.is_symlink()
                ):
                    exports[relative] = cached[1]
                    continue
                with source.open("rb") as stream:
                    content = stream.read(self.workspace.config.max_output_bytes + 1)
                if len(content) > self.workspace.config.max_output_bytes:
                    exports[relative] = {
                        "omitted_reason": "Evidence exceeds max_output_bytes export cap"
                    }
                    continue
                try:
                    content.decode("utf-8")
                    if b"\x00" in content:
                        raise UnicodeError("binary content")
                except UnicodeError:
                    exports[relative] = {
                        "omitted_reason": "Binary evidence remains in private workspace"
                    }
                    continue
                destination_root.mkdir(exist_ok=True, mode=0o700)
                exported = self.redactor.bytes(content)
                self.remember(value for value in self.redactor.values if value in content)
                write_bytes(destination, exported)
                item = {
                    "path": destination.relative_to(directory).as_posix(),
                    "bytes": len(exported),
                    "redacted": content != exported,
                    "sha256": hashlib.sha256(exported).hexdigest(),
                }
                exports[relative] = item
                self.evidence_cache[key] = (fingerprint, item)
            except (OSError, ValueError) as error:
                exports[relative] = {"omitted_reason": str(error)}
        return exports

    def generate(self, engagement_id: str) -> dict:
        with self.workspace.mutations:
            directory = self.directory(engagement_id, create=True)
            engagement = self.workspace.get(engagement_id)
            rank = {
                severity: index
                for index, severity in enumerate(("critical", "high", "medium", "low", "info"))
            }
            findings = sorted(
                self.workspace.findings(engagement_id),
                key=lambda item: rank.get(item["severity"], len(rank)),
            )
            jobs = self.workspace.catalog.all("job", engagement_id)
            indexed = {
                step["id"]: step for step in self.workspace.catalog.all("step", engagement_id)
            }
            for job in jobs:
                previous = indexed.get(job["id"])
                if (
                    previous is None
                    or previous.get("job_status") != job["status"]
                    or previous.get("_redaction_id") != self.redaction_id
                    or any(
                        not (directory / raw["path"]).is_file() for raw in previous["raw"].values()
                    )
                    or job.get("report_error")
                ):
                    self.observe_job(job, refresh_report=False)
                    if job.pop("report_error", None) is not None:
                        write_json(
                            self.workspace.engagement_path(engagement_id)
                            / "jobs"
                            / job["id"]
                            / "job.json",
                            job,
                        )
                        self.workspace.catalog.put("job", job, engagement_id)
            for step in indexed.values():
                if step.get("job_id"):
                    continue
                if step.get("_redaction_id") != self.redaction_id or any(
                    not (directory / raw["path"]).is_file() for raw in step["raw"].values()
                ):
                    sources = {
                        channel: self.workspace.artifact(engagement_id, relative)
                        if relative
                        else None
                        for channel, relative in step["source_paths"].items()
                    }
                    self._capture(engagement_id, step, sources)
                    self._save_step(engagement_id, step)
            steps = self.workspace.catalog.all("step", engagement_id)
            evidence = self.export_evidence(engagement_id, findings, steps)
            notes = self.workspace.catalog.all("note", engagement_id)
            summary = self.workspace.catalog.get("summary", engagement_id, engagement_id) or {
                key: [] for key in SUMMARY_KEYS
            }
            raw_data = {
                "engagement": engagement,
                "generated_at": now(),
                "steps": steps,
                "findings": findings,
                "jobs": jobs,
                "notes": notes,
                "summary": summary,
                "untrusted": True,
                "redacted": True,
                "evidence_exports": evidence,
            }
            self.remember_metadata(raw_data)
            data = self.redactor.object(raw_data)
            for step in data["steps"]:
                step.pop("_redaction_id", None)
                step.pop("source_paths", None)
            if not data["summary"]["confirmed_facts"]:
                data["summary"]["confirmed_facts"] = [
                    f"Observed execution: {step.get('tool', 'manual step')} "
                    f"on {step['target']}, exit code {step['exit_code']}."
                    for step in data["steps"]
                    if step["status"] == "success" and step["provenance"] == "mcp_observed"
                ]
            automatic_limits = [
                f"{step['timestamp_utc']}: {step['status']} on {step['target']}"
                + (f" — {step['reason']}" if step.get("reason") else "")
                for step in data["steps"]
                if step["status"] in {"blocked", "timeout", "pending"}
                or step.get("output_incomplete")
            ]
            data["summary"]["limitations"] = list(
                dict.fromkeys(data["summary"]["limitations"] + automatic_limits)
            )
            lines = [
                f"# {data['engagement']['name']}",
                "",
                f"Generated UTC: {data['generated_at']}",
                "",
                "## Scope",
                "",
                *[f"- {value}" for value in data["engagement"]["targets"]],
                "",
                "## Rules of engagement",
                "",
                data["engagement"].get("roe")
                or "No additional RoE supplied. Operator/engagement scope applies.",
                "",
                "Excluded targets:",
                "",
                *[
                    f"- {value}"
                    for value in self.redactor.object(
                        sorted(
                            set(engagement.get("excluded_targets", []))
                            | set(self.workspace.config.excluded_targets)
                        )
                    )
                ],
                "",
                "## Steps",
                "",
                "Raw copies preserve stdout/stderr separately; "
                "recognized secrets are replaced with <REDACTED>.",
                "Empty output and unexecuted steps are recorded explicitly. "
                "Agent-supplied steps are not independently verified.",
                "",
            ]
            for step in data["steps"]:
                lines.extend(
                    [
                        f"### {step['timestamp_utc']} — {step.get('tool', 'manual step')}",
                        "",
                        f"- Target: {step['target']}; "
                        f"port: {step.get('port') or step.get('ports') or 'not specified'}; "
                        f"service: {step.get('service') or 'not specified'}",
                        f"- Status: {step['status']}"
                        + (f" ({step['job_status']})" if step.get("job_status") else ""),
                        f"- Executed: {step['executed']}; provenance: {step['provenance']}",
                        "- Exit code: "
                        + (
                            str(step["exit_code"])
                            if step["exit_code"] is not None
                            else "not available"
                        ),
                        "",
                        "Command / request (secret values redacted):",
                        "",
                        *fenced(step["command"]),
                        "",
                    ]
                )
                if step.get("argv"):
                    lines.extend(
                        [
                            "Literal argv:",
                            "",
                            *fenced(json.dumps(step["argv"], ensure_ascii=False)),
                            "",
                        ]
                    )
                for channel, raw in step["raw"].items():
                    description = (
                        "empty"
                        if raw["captured"] and raw["source_bytes"] == 0
                        else f"{raw['source_bytes']} source bytes"
                        if raw["captured"]
                        else "not captured; command has not produced a saved stream"
                    )
                    lines.append(
                        f"- [{channel}](<{raw['path']}>) — {description}; SHA-256: {raw['sha256']}"
                    )
                if step.get("output_incomplete"):
                    lines.append(
                        "- Output may be incomplete because execution was stopped "
                        "or a quota was reached."
                    )
                if step.get("reason"):
                    lines.extend(["", "Reason:", "", *fenced(step["reason"])])
                if step.get("summary"):
                    lines.extend(
                        [
                            "",
                            "Preview / agent conclusion (does not replace raw):",
                            "",
                            *fenced(step["summary"]),
                        ]
                    )
                else:
                    lines.append("- No output preview or agent conclusion supplied.")
                lines.append("")
            lines.extend(
                [
                    "## Findings",
                    "",
                    "Findings require verification; confirmed reflects agent/operator assessment.",
                    "",
                    "Severity totals: "
                    + ", ".join(
                        f"{severity}: {sum(item['severity'] == severity for item in findings)}"
                        for severity in rank
                    ),
                    "",
                ]
            )
            for item in data["findings"]:
                lines.extend(
                    [
                        f"### [{item['severity'].upper()}] {item['title']}",
                        "",
                        f"Target: {item['target']}; status: {item.get('status', 'open')}",
                        "",
                        item["description"],
                        "",
                        "Remediation: " + item["remediation"],
                        "",
                        "Evidence:",
                        "",
                        *[
                            f"- [{p}](<{data['evidence_exports'][p]['path']}>)"
                            if data["evidence_exports"][p].get("path")
                            else f"- {p}: {data['evidence_exports'][p]['omitted_reason']}"
                            for p in item["evidence"]
                        ],
                        "",
                    ]
                )
            if notes:
                lines.extend(["## Notes", ""])
                for note in data["notes"]:
                    lines.extend([f"{note['created_at']}:", "", *fenced(note["text"]), ""])
            lines.extend(["## Summary", ""])
            for key, title in (
                ("confirmed_facts", "Confirmed facts"),
                ("hypotheses", "Hypotheses"),
                ("limitations", "Limitations"),
                ("next_steps", "Next steps"),
            ):
                items = data["summary"][key]
                if key == "confirmed_facts" and not items:
                    items = [
                        f"Observed execution: {step.get('tool', 'manual step')} "
                        f"on {step['target']}, "
                        f"exit code {step['exit_code']}."
                        for step in data["steps"]
                        if step["status"] == "success" and step["provenance"] == "mcp_observed"
                    ]
                lines.extend(
                    [
                        f"### {title}",
                        "",
                        *([f"- {item}" for item in items] if items else ["- Not supplied."]),
                    ]
                )
                lines.append("")
            markdown = "\n".join(lines) + "\n"
            for filename in ("report.md", "report.json"):
                if (directory / filename).is_symlink():
                    raise ValueError("Report files must not be symlinks")
            write_text(directory / "report.md", markdown)
            public_data = {
                **data,
                "steps": [
                    {key: value for key, value in step.items() if key != "source_paths"}
                    for step in data["steps"]
                ],
            }
            write_json(directory / "report.json", public_data)
            private = self.workspace.engagement_path(engagement_id)
            internal = markdown
            for step in data["steps"]:
                for raw in step["raw"].values():
                    internal = internal.replace(
                        f"(<{raw['path']}>)", f"(<{directory / raw['path']}>)"
                    )
            for exported in data["evidence_exports"].values():
                if exported.get("path"):
                    internal = internal.replace(
                        f"(<{exported['path']}>)", f"(<{directory / exported['path']}>)"
                    )
            write_text(private / "report.md", internal)
            write_json(private / "report.json", public_data)
            return {
                "path": "report.md",
                "json_path": "report.json",
                "findings": len(findings),
                **self.status(engagement_id),
            }
