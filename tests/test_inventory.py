from pathlib import Path

import pytest

from kali_mcp.config import Config
from kali_mcp.inventory import Inventory


def mock_paths(monkeypatch, paths):
    monkeypatch.setattr("kali_mcp.inventory.shutil.which", paths.get)


def test_kali_httpx_uses_projectdiscovery_binary(tmp_path, monkeypatch):
    mock_paths(monkeypatch, {"httpx": "/usr/bin/httpx", "httpx-toolkit": "/usr/bin/httpx-toolkit"})
    inventory = Inventory(Config(workspace=tmp_path, allowed_tools=("httpx",)))
    assert inventory.resolve("httpx") == "/usr/bin/httpx-toolkit"
    tool = inventory.inspect()["tools"][0]
    assert tool["executable"] == "httpx-toolkit"


def test_python_httpx_is_not_reported_as_projectdiscovery(tmp_path, monkeypatch):
    path = tmp_path / "httpx"
    path.write_text("#!/usr/bin/python3\nfrom httpx import main\nmain()\n")
    mock_paths(monkeypatch, {"httpx": str(path)})
    inventory = Inventory(Config(workspace=tmp_path, allowed_tools=("httpx",)))
    assert not inventory.inspect()["tools"][0]["installed"]
    with pytest.raises(ValueError, match="not installed"):
        inventory.resolve("httpx")


def test_upstream_httpx_binary_works_without_kali_alias(tmp_path, monkeypatch):
    path = tmp_path / "httpx"
    path.write_bytes(b"\x7fELF")
    mock_paths(monkeypatch, {"httpx": str(path)})
    assert Inventory(Config(workspace=tmp_path, allowed_tools=("httpx",))).resolve("httpx") == str(
        path
    )


@pytest.mark.parametrize(
    ("logical", "executable"),
    [
        ("testssl.sh", "testssl"),
        ("testssl", "testssl.sh"),
        ("httpie", "http"),
        ("enum4linux-ng", "enum4linux-ng.py"),
        ("netexec", "nxc"),
        ("netcat", "nc"),
    ],
)
def test_distribution_aliases(tmp_path, monkeypatch, logical, executable):
    path = f"/usr/bin/{executable}"
    mock_paths(monkeypatch, {executable: path})
    inventory = Inventory(Config(workspace=tmp_path, allowed_tools=(logical,)))
    assert inventory.resolve(logical) == path
    if logical == "testssl.sh":
        assert inventory.inspect()["profiles"]["tls_audit"]["available"]


def test_alias_does_not_extend_operator_allowlist(tmp_path, monkeypatch):
    mock_paths(monkeypatch, {"testssl": "/usr/bin/testssl"})
    inventory = Inventory(Config(workspace=tmp_path, allowed_tools=("testssl.sh",)))
    assert Path(inventory.resolve("testssl.sh")).name == "testssl"
    with pytest.raises(ValueError, match="allowlist"):
        inventory.resolve("testssl")
