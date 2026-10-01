from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_TOOLS = (
    "nmap",
    "curl",
    "dig",
    "whois",
    "whatweb",
    "nikto",
    "nuclei",
    "ffuf",
    "gobuster",
    "feroxbuster",
    "testssl",
    "testssl.sh",
    "sslscan",
    "openssl",
    "httpx",
    "httpx-toolkit",
    "subfinder",
    "amass",
    "dnsrecon",
    "dnsenum",
    "traceroute",
    "ping",
    "tcpdump",
    "tshark",
    "searchsploit",
    "sqlmap",
    "smbclient",
    "enum4linux-ng",
    "rpcclient",
    "snmpwalk",
    "wpscan",
    "netcat",
    "nc",
    "jq",
    "naabu",
    "dnsx",
    "katana",
    "arjun",
    "dalfox",
    "httpie",
    "socat",
    "ldapsearch",
    "smbmap",
    "netexec",
    "nxc",
    "nbtscan",
    "fping",
    "arp-scan",
    "rustscan",
    "exiftool",
    "binwalk",
    "strings",
    "file",
    "xxd",
    "sha256sum",
    "hashid",
)


def report_path(value: str, base: Path | None = None) -> Path:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError("report_root must be a non-empty path or null")
    if os.name != "nt" and re.match(r"^[A-Za-z]:[\\/]", value):
        if not (converter := shutil.which("wslpath")):
            raise ValueError("Windows report_root requires WSL; use a native Linux path")
        result = subprocess.run(
            [converter, "-u", value], capture_output=True, text=True, timeout=5, check=False
        )
        if result.returncode or not result.stdout.strip().startswith("/"):
            raise ValueError("Cannot convert Windows report_root with wslpath")
        value = result.stdout.strip()
    destination = Path(value).expanduser()
    if not destination.is_absolute() and base is not None:
        destination = base / destination
    return destination.resolve()


def target_host(value: str) -> str:
    value = value.strip()
    if not value or any(c.isspace() for c in value) or value.startswith("-"):
        raise ValueError("Target must be a host, IP, CIDR, or HTTP(S) URL")
    if "://" in value:
        url = urlsplit(value)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username:
            raise ValueError("Only HTTP(S) URLs without credentials are accepted")
        # Validate malformed or out-of-range ports too.
        _ = url.port
        value = url.hostname
    value = value.rstrip(".").lower()
    try:
        return (
            str(ipaddress.ip_network(value, strict=False))
            if "/" in value
            else str(ipaddress.ip_address(value))
        )
    except ValueError:
        if "/" in value or not all(c.isalnum() or c in ".-" for c in value):
            raise ValueError("Invalid target") from None
        labels = value.split(".")
        if len(value) > 253 or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in labels
        ):
            raise ValueError("Invalid hostname") from None
        return value.encode("idna").decode("ascii")


def matches(target: str, rule: str) -> bool:
    host = target_host(target)
    if rule.startswith("*."):
        domain = target_host(rule[2:])
        return host.endswith("." + domain) and host != domain
    scope = target_host(rule)
    try:
        candidate = ipaddress.ip_network(host, strict=False)
        network = ipaddress.ip_network(scope, strict=False)
        return candidate.version == network.version and candidate.subnet_of(network)
    except ValueError:
        return host == scope


def denied(target: str, rule: str) -> bool:
    if matches(target, rule):
        return True
    try:
        a = ipaddress.ip_network(target_host(target), strict=False)
        b = ipaddress.ip_network(target_host(rule), strict=False)
        return a.version == b.version and a.overlaps(b)
    except ValueError:
        return False


@dataclass(frozen=True)
class Config:
    workspace: Path = field(default_factory=lambda: Path(".kali-mcp").resolve())
    report_root: Path | None = None
    report_secret_env: tuple[str, ...] = ()
    allowed_targets: tuple[str, ...] = ("127.0.0.0/8", "::1", "localhost")
    excluded_targets: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = DEFAULT_TOOLS
    max_concurrent: int = 4
    max_queued: int = 64
    max_timeout: int = 3600
    max_output_bytes: int = 16 * 1024 * 1024
    max_artifact_bytes: int = 256 * 1024 * 1024
    max_response_bytes: int = 128 * 1024
    terminate_grace_seconds: float = 2.0
    profile_rate_limit: int = 50

    def __post_init__(self) -> None:
        if self.report_root is not None and not isinstance(self.report_root, Path):
            raise ValueError("report_root must be a Path; use Config.load for JSON paths")
        if any(
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", v) for v in self.report_secret_env
        ):
            raise ValueError("report_secret_env must contain environment variable names")
        for name in (
            "max_concurrent",
            "max_queued",
            "max_timeout",
            "max_output_bytes",
            "max_artifact_bytes",
            "max_response_bytes",
            "profile_rate_limit",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < (0 if name == "max_queued" else 1):
                raise ValueError(f"{name} must be a positive integer (max_queued may be zero)")
        if self.max_output_bytes < 1024 or self.max_response_bytes < 4096:
            raise ValueError("Output limit must be >= 1024 and response limit >= 4096 bytes")
        if not 0 <= self.terminate_grace_seconds <= 10:
            raise ValueError("terminate_grace_seconds must be within 0..10")
        for rule in (*self.allowed_targets, *self.excluded_targets):
            target_host(rule[2:] if rule.startswith("*.") else rule)
        for tool in self.allowed_tools:
            if not tool or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for c in tool):
                raise ValueError("Executable allowlist accepts basenames only")

    @classmethod
    def load(cls, path: str | None = None) -> Config:
        path = path or os.environ.get("KALI_MCP_CONFIG")
        raw = json.loads(Path(path).read_text(encoding="utf-8")) if path else {}
        unknown = set(raw) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"Unknown config keys: {sorted(unknown)}")
        if "workspace" in raw:
            root = Path(raw["workspace"]).expanduser()
            if not root.is_absolute() and path:
                root = Path(path).resolve().parent / root
            raw["workspace"] = root.resolve()
        if raw.get("report_root") is not None:
            raw["report_root"] = report_path(
                raw["report_root"], Path(path).resolve().parent if path else None
            )
        for key in ("allowed_targets", "excluded_targets", "allowed_tools", "report_secret_env"):
            if key in raw:
                if not isinstance(raw[key], list):
                    raise ValueError(f"{key} must be an array")
                raw[key] = tuple(raw[key])
        return cls(**raw)

    def check_target(self, target: str, scope: list[str] | None = None) -> None:
        if any(denied(target, rule) for rule in self.excluded_targets):
            raise ValueError(f"Target {target!r} intersects operator-excluded scope")
        if not any(matches(target, rule) for rule in self.allowed_targets):
            raise ValueError(f"Target {target!r} is outside operator-configured scope")
        if scope is not None and not any(matches(target, rule) for rule in scope):
            raise ValueError(f"Target {target!r} is outside engagement scope")

    def check_rule(self, rule: str) -> None:
        if not rule.startswith("*."):
            self.check_target(rule)
            return
        domain = target_host(rule[2:])
        if not any(
            allowed.startswith("*.")
            and (domain == target_host(allowed[2:]) or matches(domain, allowed))
            for allowed in self.allowed_targets
        ):
            raise ValueError(f"Wildcard {rule!r} is outside operator-configured scope")
