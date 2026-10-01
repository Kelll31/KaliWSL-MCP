from __future__ import annotations

import shutil
import time
from pathlib import Path

from .config import Config
from .profiles import PROFILES

EXECUTABLE_ALIASES = {
    "httpx": ("httpx-toolkit", "httpx"),
    "testssl.sh": ("testssl.sh", "testssl"),
    "testssl": ("testssl", "testssl.sh"),
    "httpie": ("http", "httpie"),
    "enum4linux-ng": ("enum4linux-ng", "enum4linux-ng.py"),
    "netexec": ("netexec", "nxc"),
    "nxc": ("nxc", "netexec"),
    "netcat": ("netcat", "nc"),
    "nc": ("nc", "netcat"),
}


def executable_path(name: str) -> str | None:
    for candidate in EXECUTABLE_ALIASES.get(name, (name,)):
        if path := shutil.which(candidate):
            if name == "httpx" and candidate == "httpx":
                # Kali's python3-httpx installs a different CLI with this basename.
                try:
                    with Path(path).open("rb") as stream:
                        header = stream.read(4096)
                    if (
                        b"from httpx import main" in header
                        or b"from httpx._main import main" in header
                    ):
                        continue
                except OSError:
                    continue
            return path
    return None


class Inventory:
    def __init__(self, config: Config):
        self.config = config
        self.checked_at = 0.0
        self.paths: dict[str, str | None] = {}

    def refresh(self, force: bool = False) -> None:
        if force or not self.paths or time.monotonic() - self.checked_at >= 30:
            self.paths = {tool: executable_path(tool) for tool in self.config.allowed_tools}
            self.checked_at = time.monotonic()

    def resolve(self, name: str) -> str:
        self.refresh()
        if name not in self.config.allowed_tools:
            raise ValueError(f"Executable {name!r} is not in the operator allowlist")
        if not self.paths.get(name):
            self.refresh(force=True)
        if not (path := self.paths.get(name)):
            raise ValueError(f"{name} is not installed or is missing from PATH")
        return path

    def inspect(self, refresh: bool = False) -> dict:
        self.refresh(force=refresh)
        return {
            "tools": [
                {
                    "name": name,
                    "installed": path is not None,
                    "path": path,
                    "executable": Path(path).name if path else None,
                    "candidates": list(EXECUTABLE_ALIASES.get(name, (name,))),
                }
                for name, path in self.paths.items()
            ],
            "profiles": {
                name: {
                    **spec,
                    "available": bool(self.paths.get(spec["tool"])),
                    "executable": self.paths.get(spec["tool"]),
                }
                for name, spec in PROFILES.items()
            },
            "cache_ttl_seconds": 30,
        }
