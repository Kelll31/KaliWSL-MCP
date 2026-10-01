from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

from .inventory import Inventory
from .workspace import Workspace


def environment_check(workspace: Workspace, inventory: Inventory) -> dict:
    capabilities = {}
    if platform.system() == "Linux":
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith(("CapEff:", "CapBnd:")):
                key, value = line.split(":", 1)
                capabilities[key] = value.strip()
    installed = inventory.inspect(refresh=True)
    disk = shutil.disk_usage(workspace.root)
    linux_distribution = {}
    if platform.system() == "Linux":
        try:
            linux_distribution = platform.freedesktop_os_release()
        except OSError:
            pass
    effective = int(capabilities.get("CapEff", "0"), 16)
    return {
        "platform": platform.system(),
        "linux_distribution": {
            key: linux_distribution[key]
            for key in ("ID", "VERSION_ID", "PRETTY_NAME")
            if key in linux_distribution
        },
        "wsl_distro": os.environ.get("WSL_DISTRO_NAME"),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "capabilities": capabilities,
        "network_capabilities": {
            "net_raw": bool(effective & (1 << 13)),
            "net_admin": bool(effective & (1 << 12)),
        },
        "workspace": str(workspace.root),
        "workspace_on_windows_mount": str(workspace.root).startswith("/mnt/"),
        "disk_free_bytes": disk.free,
        "catalog": str(workspace.catalog.path),
        "available_profiles": [
            name for name, spec in installed["profiles"].items() if spec["available"]
        ],
        "unavailable_profiles": [
            name for name, spec in installed["profiles"].items() if not spec["available"]
        ],
        "missing_tools": [tool["name"] for tool in installed["tools"] if not tool["installed"]],
        "limits": {
            name: getattr(workspace.config, name)
            for name in (
                "max_concurrent",
                "max_queued",
                "max_timeout",
                "max_output_bytes",
                "max_artifact_bytes",
                "max_response_bytes",
                "profile_rate_limit",
            )
        },
    }
