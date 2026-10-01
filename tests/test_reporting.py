import asyncio
import json
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import Client

from kali_mcp.config import Config
from kali_mcp.jobs import JobManager
from kali_mcp.redaction import Redactor
from kali_mcp.server import create_server
from kali_mcp.workspace import Workspace


def make_workspace(tmp_path, **settings):
    return Workspace(
        Config(workspace=tmp_path / "state", report_root=tmp_path / "pentests", **settings)
    )


def bundle(workspace, eid):
    path = Path(workspace.reports.status(eid)["directory"])
    return path, json.loads((path / "report.json").read_text(encoding="utf-8"))


def test_target_utc_folder_collision_and_initial_summary(tmp_path, monkeypatch):
    monkeypatch.setattr("kali_mcp.workspace.now", lambda: "2026-10-01T09:07:00+00:00")
    workspace = make_workspace(tmp_path)
    first = workspace.create("first", ["127.0.0.1"], roe="Loopback only; no DoS")
    second = workspace.create("second", ["127.0.0.1"])
    assert first["report_folder"] == "pentest_127.0.0.1_20261001_0907"
    assert second["report_folder"] != first["report_folder"]
    path, data = bundle(workspace, first["id"])
    assert (path / "raw").is_dir()
    text = (path / "report.md").read_text(encoding="utf-8")
    assert "Loopback only; no DoS" in text and "## Summary" in text
    assert data["steps"] == [] and data["summary"]["hypotheses"] == []


def test_job_automatically_preserves_full_bytes_redacts_export_and_records_failure(
    tmp_path, monkeypatch
):
    secret = "unique-local-fixture-value"
    monkeypatch.setenv("REPORT_TEST_SECRET", secret)
    executable = Path(sys.executable).name
    workspace = make_workspace(
        tmp_path, allowed_tools=(executable,), report_secret_env=("REPORT_TEST_SECRET",)
    )
    eid = workspace.create("audit", ["127.0.0.1"])["id"]
    stdout = b"\xffbegin\r\n" + secret.encode() + b"\n" + b"x" * 200000 + b"\r\n"
    stderr = b"Authorization: Bearer laboratory-only-token\r\n"

    async def check():
        jobs = JobManager(workspace)
        # Keep individual argv entries below the execution validator's 8 KiB ceiling.
        code = (
            "import sys; "
            f"sys.stdout.buffer.write(b'\\xffbegin\\r\\n'+{secret.encode()!r}"
            "+b'\\n'+b'x'*200000+b'\\r\\n'); "
            f"sys.stderr.buffer.write({stderr!r}); raise SystemExit(7)"
        )
        job = jobs.start(eid, executable, ["-c", code], "127.0.0.1")
        final = await jobs.wait(eid, job["id"], 10)
        assert final["status"] == "failed" and final["exit_code"] == 7
        assert workspace.artifact(eid, final["stdout"]).read_bytes() == stdout
        assert workspace.artifact(eid, final["stderr"]).read_bytes() == stderr
        directory, data = bundle(workspace, eid)
        step = data["steps"][0]
        assert step["status"] == "fail" and step["exit_code"] == 7
        assert step["provenance"] == "mcp_observed" and step["executed"]
        assert (directory / step["raw"]["stdout"]["path"]).read_bytes() == stdout.replace(
            secret.encode(), b"<REDACTED>"
        )
        exported = (directory / step["raw"]["stderr"]["path"]).read_bytes()
        assert exported == b"Authorization: Bearer <REDACTED>\r\n"
        assert secret not in (directory / "report.md").read_text()
        assert secret not in (directory / "report.json").read_text()
        assert "_redaction_id" not in step
        await jobs.close()

    asyncio.run(check())


def test_empty_stdout_timeout_and_scope_rejection_are_truthful(tmp_path):
    executable = Path(sys.executable).name
    workspace = make_workspace(tmp_path, allowed_tools=(executable,))
    eid = workspace.create("audit", ["127.0.0.1"])["id"]

    async def check():
        jobs = JobManager(workspace)
        empty = jobs.start(eid, executable, ["-c", "pass"], "127.0.0.1")
        await jobs.wait(eid, empty["id"], 10)
        timed = jobs.start(eid, executable, ["-c", "import time; time.sleep(60)"], "127.0.0.1", 1)
        await jobs.wait(eid, timed["id"], 10)
        with pytest.raises(ValueError, match="outside"):
            jobs.start(eid, executable, ["-c", "print('must not run')"], "example.com")
        directory, data = bundle(workspace, eid)
        by_id = {step["id"]: step for step in data["steps"]}
        assert by_id[empty["id"]]["status"] == "success"
        assert by_id[empty["id"]]["raw"]["stdout"]["captured"]
        assert by_id[empty["id"]]["raw"]["stdout"]["bytes"] == 0
        assert by_id[timed["id"]]["status"] == "timeout"
        blocked = next(step for step in data["steps"] if step["status"] == "blocked")
        assert not blocked["executed"] and blocked["exit_code"] is None
        assert not blocked["raw"]["stdout"]["captured"]
        assert "outside" in blocked["reason"]
        assert len(workspace.catalog.all("job", eid)) == 2
        text = (directory / "report.md").read_text(encoding="utf-8")
        assert "empty" in text and "not captured" in text and "timeout" in text
        await jobs.close()

    asyncio.run(check())


def test_manual_snapshot_recovery_summary_and_portable_evidence(tmp_path):
    workspace = make_workspace(tmp_path)
    eid = workspace.create("manual", ["127.0.0.1"])["id"]
    artifact = workspace.write_input(eid, "response.txt", "unaltered response\r\n")
    step = workspace.reports.add_step(
        eid,
        "127.0.0.1",
        "GET / HTTP/1.1",
        "success",
        stdout_path=artifact["path"],
        exit_code=None,
        port=8080,
        service="http",
        summary="HTTP response received",
        timestamp_utc="2026-10-01T09:08:00Z",
    )
    original = workspace.artifact(eid, artifact["path"])
    original.write_text("changed later")
    directory, _ = bundle(workspace, eid)
    (directory / step["raw"]["stdout"]["path"]).unlink()
    workspace.reports.summary_update(
        eid,
        confirmed_facts=["Received an HTTP response"],
        hypotheses=["Version needs review"],
        limitations=["Loopback fixture only"],
        next_steps=["Review server configuration"],
    )
    data = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    assert (directory / step["raw"]["stdout"]["path"]).read_bytes() == b"unaltered response\r\n"
    assert data["steps"][0]["provenance"] == "agent_supplied"
    assert data["summary"]["confirmed_facts"] == ["Received an HTTP response"]
    assert "source_paths" not in data["steps"][0]
    evidence = workspace.engagement_path(eid) / "evidence.txt"
    evidence.write_text("password=fixture-secret\n")
    workspace.add_finding(eid, "Needs review", "low", "127.0.0.1", "Manual", ["evidence.txt"], "")
    _, data = bundle(workspace, eid)
    exported = data["evidence_exports"]["evidence.txt"]
    assert (directory / exported["path"]).read_text() == "password=<REDACTED>\n"
    assert evidence.read_text() == "password=fixture-secret\n"
    workspace.catalog.path.unlink()
    recovered = Workspace(workspace.config)
    recovered.report(eid)
    assert recovered.catalog.all("step", eid)[0]["id"] == step["id"]
    assert recovered.catalog.get("summary", eid)["hypotheses"] == ["Version needs review"]


def test_report_failure_prevents_execution_and_retries_on_recovery(tmp_path, monkeypatch):
    executable = Path(sys.executable).name
    workspace = make_workspace(tmp_path, allowed_tools=(executable,))
    eid = workspace.create("offline destination", ["127.0.0.1"])["id"]
    observe = workspace.reports.observe_job
    monkeypatch.setattr(
        workspace.reports, "observe_job", lambda *_: (_ for _ in ()).throw(OSError("disk offline"))
    )
    jobs = JobManager(workspace)
    with pytest.raises(ValueError, match="not executed"):
        jobs.start(eid, executable, ["-c", "raise SystemExit(0)"], "127.0.0.1")
    assert not jobs.tasks
    failed = workspace.catalog.all("job", eid)[0]
    assert failed["status"] == "failed" and failed["exit_code"] is None
    assert workspace.reports.status(eid)["export_errors"]
    monkeypatch.setattr(workspace.reports, "observe_job", observe)
    workspace.report(eid)
    assert not workspace.reports.status(eid)["export_errors"]
    _, data = bundle(workspace, eid)
    assert not data["steps"][0]["executed"]


def test_manual_validation_does_not_claim_blocked_commands_ran(tmp_path):
    workspace = make_workspace(tmp_path)
    eid = workspace.create("blocked", ["127.0.0.1"])["id"]
    with pytest.raises(ValueError, match="outside"):
        workspace.reports.add_step(eid, "example.com", "GET /", "success")
    with pytest.raises(ValueError, match="not executed"):
        workspace.reports.add_step(eid, "example.com", "GET /", "blocked", stdout="invented")
    with pytest.raises(ValueError, match="UTC"):
        workspace.reports.add_step(
            eid, "127.0.0.1", "GET /", "success", timestamp_utc="2026-10-01T09:00:00"
        )
    recorded = workspace.reports.add_step(
        eid, "example.com", "High load request", "blocked", reason="Outside RoE; DoS risk"
    )
    assert recorded["status"] == "blocked" and not recorded["executed"]
    assert workspace.reports.status(eid)["steps"] == 1


def test_report_folder_escape_is_rejected(tmp_path):
    workspace = make_workspace(tmp_path)
    engagement = workspace.create("scope", ["127.0.0.1"])
    engagement["report_folder"] = "../../outside"
    workspace.catalog.put("engagement", engagement, engagement["id"])
    with pytest.raises(ValueError, match="folder metadata"):
        workspace.report(engagement["id"])


def test_changing_report_root_restores_snapshots_without_overwriting_another_report(tmp_path):
    from dataclasses import replace

    workspace = make_workspace(tmp_path)
    eid = workspace.create("move", ["127.0.0.1"])["id"]
    step = workspace.reports.add_step(eid, "127.0.0.1", "GET /", "success", stdout="snapshot")
    destination = tmp_path / "different"
    foreign = destination / workspace.get(eid)["report_folder"]
    foreign.mkdir(parents=True)
    manifest = foreign / "report.json"
    manifest.write_text(json.dumps({"engagement": {"id": "f" * 32}}))
    moved = Workspace(replace(workspace.config, report_root=destination))
    moved.report(eid)
    assert json.loads(manifest.read_text())["engagement"]["id"] == "f" * 32
    directory, data = bundle(moved, eid)
    assert directory != foreign
    assert (directory / step["raw"]["stdout"]["path"]).read_text() == "snapshot"
    assert data["steps"][0]["provenance"] == "agent_supplied"


def test_registering_new_secret_remasks_existing_manual_raw(tmp_path, monkeypatch):
    from dataclasses import replace

    workspace = make_workspace(tmp_path)
    eid = workspace.create("secret rotation", ["127.0.0.1"])["id"]
    step = workspace.reports.add_step(
        eid, "127.0.0.1", "GET /", "success", stdout="bare-local-fixture"
    )
    monkeypatch.setenv("NEW_REDACTION_SECRET", "bare-local-fixture")
    refreshed = Workspace(replace(workspace.config, report_secret_env=("NEW_REDACTION_SECRET",)))
    refreshed.report(eid)
    directory, _ = bundle(refreshed, eid)
    assert (directory / step["raw"]["stdout"]["path"]).read_text() == "<REDACTED>"
    assert (
        refreshed.artifact(eid, f"steps/{step['id']}/stdout.txt").read_text()
        == "bare-local-fixture"
    )


def test_rotating_secrets_preserves_redaction_of_raw_notes_and_evidence(tmp_path, monkeypatch):
    old = "old-raw-fixture-value"
    note_secret = "old-note-fixture-value"
    evidence_secret = "old-evidence-fixture-value"
    for name, value in (
        ("ROTATING_RAW", old),
        ("ROTATING_NOTE", note_secret),
        ("ROTATING_EVIDENCE", evidence_secret),
        ("UNUSED_SECRET", "unused-value"),
    ):
        monkeypatch.setenv(name, value)
    workspace = make_workspace(
        tmp_path,
        report_secret_env=("ROTATING_RAW", "ROTATING_NOTE", "ROTATING_EVIDENCE", "UNUSED_SECRET"),
    )
    eid = workspace.create("rotation", ["127.0.0.1"])["id"]
    step = workspace.reports.add_step(eid, "127.0.0.1", "GET /", "success", stdout=old)
    assert step["summary"] == "<REDACTED>"
    workspace.note_add(eid, note_secret)
    evidence = workspace.engagement_path(eid) / "rotation.txt"
    evidence.write_text(evidence_secret)
    workspace.add_finding(eid, "Review", "low", "127.0.0.1", "Fixture", ["rotation.txt"], "")
    registry = json.loads(workspace.reports.secret_registry.read_text())
    assert set(registry["values"]) == {old, note_secret, evidence_secret}
    for name in ("ROTATING_RAW", "ROTATING_NOTE", "ROTATING_EVIDENCE"):
        monkeypatch.setenv(name, "new-fixture-value")
    refreshed = Workspace(workspace.config)
    refreshed.report(eid)
    directory, data = bundle(refreshed, eid)
    assert (directory / step["raw"]["stdout"]["path"]).read_text() == "<REDACTED>"
    assert data["notes"][0]["text"] == "<REDACTED>"
    assert (
        directory / data["evidence_exports"]["rotation.txt"]["path"]
    ).read_text() == "<REDACTED>"
    assert not (directory / ".report-secrets.json").exists()
    for path in directory.rglob("*"):
        if path.is_file():
            assert all(
                value.encode() not in path.read_bytes()
                for value in (old, note_secret, evidence_secret)
            )
    assert refreshed.artifact(eid, f"steps/{step['id']}/stdout.txt").read_text() == old


def test_cli_credential_reflected_in_output_stays_masked_after_restart(tmp_path):
    executable = Path(sys.executable).name
    workspace = make_workspace(tmp_path, allowed_tools=(executable,))
    eid = workspace.create("CLI credentials", ["127.0.0.1"])["id"]

    async def check():
        jobs = JobManager(workspace)
        job = jobs.start(
            eid,
            executable,
            ["-c", "import sys; print(sys.argv[-1])", "--password", "cli-fixture-value"],
            "127.0.0.1",
        )
        final = await jobs.wait(eid, job["id"], 10)
        assert final["status"] == "completed"
        assert workspace.artifact(eid, final["stdout"]).read_text().strip() == "cli-fixture-value"
        await jobs.close()

    asyncio.run(check())
    refreshed = Workspace(workspace.config)
    refreshed.report(eid)
    directory, data = bundle(refreshed, eid)
    step = data["steps"][0]
    assert (directory / step["raw"]["stdout"]["path"]).read_text().strip() == "<REDACTED>"
    assert "cli-fixture-value" not in (directory / "report.md").read_text()


def test_tool_credential_flags_preserve_port_and_wordlist_arguments():
    redactor = Redactor().scoped(["/usr/bin/nxc", "smb", "127.0.0.1", "-p", "pass"])
    assert redactor.argv(["nxc", "smb", "127.0.0.1", "-p", "pass"])[-1] == "<REDACTED>"
    assert redactor.bytes(b"password: pass\r\ncompass") == b"password: <REDACTED>\r\ncompass"
    assert Redactor().scoped(["nmap", "-p", "80"]).values == []
    assert Redactor().scoped(["hydra", "-P", "wordlist.txt"]).values == []
    assert (
        Redactor().scoped(["curl", "--password=inline-fixture"]).bytes(b"inline-fixture")
        == b"<REDACTED>"
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (b'{"password": "lab-only"}', b'{"password": "<REDACTED>"}'),
        (b"token=lab-only&public=yes", b"token=<REDACTED>&public=yes"),
        (b"https://user:lab-only@example.com", b"https://user:<REDACTED>@example.com"),
        (b"Cookie: session=lab-only\r\n", b"Cookie: session=<REDACTED>\r\n"),
        (
            b"Set-Cookie: session=lab-only; HttpOnly; Secure; SameSite=Lax\r\n",
            b"Set-Cookie: session=<REDACTED>; HttpOnly; Secure; SameSite=Lax\r\n",
        ),
        (b"--password 'lab-only'", b"--password '<REDACTED>'"),
        (b"print('password=lab-only')", b"print('password=<REDACTED>')"),
    ],
)
def test_redaction_preserves_nonsecret_bytes(source, expected):
    assert Redactor().bytes(source) == expected


def test_redaction_key_blocks_and_credential_argv():
    prefix = b"-----BEGIN " + b"PRIVATE KEY-----"
    assert Redactor().bytes(prefix + b"\ntruncated-fixture") == b"<REDACTED>"
    assert Redactor().argv(["curl", "-u", "user:fixture", "--token", "fixture"]) == [
        "curl",
        "-u",
        "user:<REDACTED>",
        "--token",
        "<REDACTED>",
    ]
    assert Redactor().argv(["nuclei", "-u", "http://127.0.0.1:8080"]) == [
        "nuclei",
        "-u",
        "http://127.0.0.1:8080",
    ]


def test_config_relative_report_root_and_env_validation(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"report_root": "pentests", "report_secret_env": ["TEST_TOKEN"]}))
    loaded = Config.load(str(config))
    assert loaded.report_root == tmp_path / "pentests"
    assert loaded.report_secret_env == ("TEST_TOKEN",)
    with pytest.raises(ValueError, match="variable names"):
        Config(report_secret_env=("not a variable",))


@pytest.mark.skipif(os.name == "nt", reason="Windows paths use native pathlib on Windows")
def test_config_windows_report_root_is_translated_in_wsl(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"report_root": r"G:\pentests"}))
    calls = []
    monkeypatch.setattr("kali_mcp.config.shutil.which", lambda _: "/usr/bin/wslpath")
    monkeypatch.setattr(
        "kali_mcp.config.subprocess.run",
        lambda arguments, **_: (
            calls.append(arguments) or SimpleNamespace(returncode=0, stdout="/mnt/g/pentests\n")
        ),
    )
    assert Config.load(str(config)).report_root == Path("/mnt/g/pentests")
    assert calls[0] == ["/usr/bin/wslpath", "-u", r"G:\pentests"]


def test_reporting_tools_over_mcp(tmp_path):
    async def check():
        config = Config(workspace=tmp_path / "state", report_root=tmp_path / "pentests")
        async with Client(create_server(config)) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert {"report_status", "report_step_add", "report_summary_update"} <= names

            async def call(name, arguments):
                result = await client.call_tool(name, arguments)
                assert not result.is_error, result.content
                return result.structured_content

            engagement = await call(
                "engagement_create",
                {"name": "report protocol", "targets": ["127.0.0.1"], "roe": "No DoS"},
            )
            eid = engagement["id"]
            assert re.match(r"pentest_127\.0\.0\.1_", engagement["report_folder"])
            await call(
                "report_step_add",
                {
                    "engagement_id": eid,
                    "target": "127.0.0.1",
                    "command": "GET /health",
                    "status": "success",
                    "stdout": "HTTP/1.1 200 OK",
                    "service": "http",
                    "port": 8080,
                },
            )
            await call(
                "report_summary_update",
                {
                    "engagement_id": eid,
                    "confirmed_facts": ["HTTP 200 observed"],
                    "hypotheses": ["Version unknown"],
                    "limitations": ["No load test"],
                    "next_steps": ["Review headers"],
                },
            )
            blocked = await client.call_tool(
                "scan_start", {"engagement_id": eid, "profile": "ports", "target": "example.com"}
            )
            assert blocked.is_error
            status = await call("report_status", {"engagement_id": eid})
            assert status["steps"] == 2 and status["exists"]
            report = await call("report_generate", {"engagement_id": eid})
            text = Path(report["report_file"]).read_text(encoding="utf-8")
            assert "HTTP 200 observed" in text and "blocked" in text
            assert "No DoS" in text and "Next steps" in text

    asyncio.run(check())
