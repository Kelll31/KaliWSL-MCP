"""Verify Kali package status, executable aliases and profile CLI flags without scans."""

import argparse
import json
import os
import platform
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from kali_mcp.config import Config
from kali_mcp.inventory import Inventory

# These commands display local help only; no target or update flags are passed.
HELP_CHECKS = {
    "nmap": (["-h"], ["-oX", "--max-rate"]),
    "curl": (["--help", "all"], ["--proto", "--dump-header", "--write-out"]),
    "whatweb": (["--help"], ["--log-json", "--follow-redirect", "--max-threads"]),
    "ffuf": (["-h"], ["-of", "-rate", "-noninteractive"]),
    "sslscan": (["--help"], ["--xml", "--connect-timeout", "--timeout"]),
    "testssl.sh": (["--help"], ["--jsonfile", "--warnings", "--color"]),
    "nuclei": (["-h"], ["-jsonl", "-duc", "-ni", "-dr"]),
    "nikto": (["-Help"], ["-Format", "-output", "-nointeractive", "-nocheck"]),
    "subfinder": (["-h"], ["-json", "-silent"]),
    "smbclient": (["--help"], ["--list", "--no-pass", "--timeout"]),
    "httpx": (["-h"], ["-json", "-target"]),
}


def help_check(item: tuple[str, str, list[str], list[str]]) -> dict:
    name, path, arguments, flags = item
    try:
        result = subprocess.run([path, *arguments], capture_output=True, timeout=15, check=False)
        text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        missing = [flag for flag in flags if flag not in text]
        return {
            "tool": name,
            "executable": path,
            "ok": not missing and result.returncode in (0, 1),
            "returncode": result.returncode,
            "missing_flags": missing,
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"tool": name, "executable": path, "ok": False, "error": str(error)}


def package_status() -> dict:
    if not (dpkg := shutil.which("dpkg-query")):
        return {"installed": False, "status": "dpkg-query not available"}
    try:
        result = subprocess.run(
            [dpkg, "-W", "-f=${Status}\n${Version}", "kali-linux-large"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"installed": False, "error": str(error)}
    lines = result.stdout.splitlines()
    return {
        "installed": result.returncode == 0 and bool(lines) and lines[0] == "install ok installed",
        "status": lines[0] if lines else "not installed",
        "version": lines[1] if len(lines) > 1 else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="Operator config; defaults to built-in tool allowlist")
    parser.add_argument("--output", type=Path, help="Write a JSON report as well as stdout")
    parser.add_argument(
        "--strict", action="store_true", help="Fail when any profile is unavailable"
    )
    args = parser.parse_args()
    inventory = Inventory(Config.load(args.config)).inspect(refresh=True)
    paths = {tool["name"]: tool["path"] for tool in inventory["tools"]}
    items = [
        (tool, paths[tool], arguments, flags)
        for tool, (arguments, flags) in HELP_CHECKS.items()
        if paths.get(tool)
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        checks = list(pool.map(help_check, items))
    missing_profiles = [
        name for name, spec in inventory["profiles"].items() if not spec["available"]
    ]
    report = {
        "platform": platform.system(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "wsl_distro": os.environ.get("WSL_DISTRO_NAME"),
        "kali_linux_large": package_status(),
        "installed_tools": sum(tool["installed"] for tool in inventory["tools"]),
        "configured_tools": len(inventory["tools"]),
        "available_profiles": [
            name for name, spec in inventory["profiles"].items() if spec["available"]
        ],
        "unavailable_profiles": missing_profiles,
        "tools": inventory["tools"],
        "cli_checks": checks,
        "ok": all(check["ok"] for check in checks),
    }
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    raise SystemExit(0 if report["ok"] and not (args.strict and missing_profiles) else 1)


if __name__ == "__main__":
    main()
