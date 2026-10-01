from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from .config import target_host

NETWORK_OPTIONS = {
    "ports": "Numeric ranges, e.g. 22,80,443 or 1-1000",
    "rate": "Maximum packets/requests per second (operator ceiling applies)",
    "timing": "Nmap timing level 2..4; default 3",
}
WEB_OPTIONS = {
    "rate": "Maximum requests per second (operator ceiling applies)",
    "threads": "Concurrency 1..8; default 2",
}
PROFILES = {
    "ports": {
        "tool": "nmap",
        "description": "TCP connect scan, service detection, XML output",
        "options": NETWORK_OPTIONS,
    },
    "ports_quick": {
        "tool": "nmap",
        "description": "Top 100 TCP ports, no version probing",
        "options": NETWORK_OPTIONS,
    },
    "ports_full": {
        "tool": "nmap",
        "description": "All 65535 TCP ports, XML output",
        "options": NETWORK_OPTIONS,
    },
    "ports_udp": {
        "tool": "nmap",
        "description": "Top 20 UDP ports; raw socket privileges needed",
        "options": NETWORK_OPTIONS,
    },
    "service_audit": {
        "tool": "nmap",
        "description": "Banners, SSH keys, TLS certificates, HTTP",
        "options": NETWORK_OPTIONS,
    },
    "discovery": {
        "tool": "nmap",
        "description": "Host discovery without port scanning",
        "options": {},
    },
    "http_headers": {
        "tool": "curl",
        "description": "HTTP headers, no redirect following",
        "options": {},
    },
    "http_probe": {
        "tool": "curl",
        "description": "GET response body, headers and timings",
        "options": {},
    },
    "web_fingerprint": {
        "tool": "whatweb",
        "description": "Passive web fingerprint, JSON",
        "options": {},
    },
    "dns": {
        "tool": "dig",
        "description": "DNS record lookup",
        "options": {"record": "A, AAAA, MX, NS, TXT, SOA, CAA"},
    },
    "tls": {
        "tool": "sslscan",
        "description": "TLS protocol and cipher checks",
        "options": {"port": "1..65535; default 443"},
    },
    "tls_audit": {
        "tool": "testssl.sh",
        "description": "TLS and certificate audit, JSON output",
        "options": {"port": "1..65535; default 443"},
    },
    "nuclei": {
        "tool": "nuclei",
        "description": "Template checks with bounded concurrency",
        "options": {**WEB_OPTIONS, "severity": "Comma-separated info,low,medium,high,critical"},
    },
    "web_audit": {
        "tool": "nikto",
        "description": "Nikto web audit with JSON evidence",
        "options": {},
    },
    "subdomains": {
        "tool": "subfinder",
        "description": "Passive subdomain discovery, JSONL",
        "options": {},
    },
    "smb_shares": {
        "tool": "smbclient",
        "description": "List SMB shares without credentials",
        "options": {},
    },
    "whois": {"tool": "whois", "description": "WHOIS lookup", "options": {}},
    "web_content": {
        "tool": "ffuf",
        "description": "Content discovery with JSON output",
        "options": {
            **WEB_OPTIONS,
            "wordlist": "Absolute Linux wordlist path",
            "extensions": "Comma-separated extensions, e.g. .php,.txt",
        },
    },
}


def integer(options: dict, key: str, default: int, minimum: int, maximum: int) -> int:
    value = options.get(key, default)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{key} must be an integer within {minimum}..{maximum}")
    return value


def port_ranges(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9,-]{1,1000}", value):
        raise ValueError("ports must be numeric port ranges")
    for part in value.split(","):
        bounds = part.split("-")
        if len(bounds) > 2 or any(not p or not 1 <= int(p) <= 65535 for p in bounds):
            raise ValueError("ports must be within 1..65535")
        if len(bounds) == 2 and int(bounds[0]) > int(bounds[1]):
            raise ValueError("Port range is reversed")
    return value


def build(
    profile: str, target: str, options: dict | None = None, rate_limit: int = 50
) -> tuple[str, list[str]]:
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile; choose from {sorted(PROFILES)}")
    if options is not None and not isinstance(options, dict):
        raise ValueError("options must be an object")
    options = options or {}
    unknown = set(options) - set(PROFILES[profile]["options"])
    if unknown:
        raise ValueError(f"Unsupported options: {sorted(unknown)}")
    host = target_host(target)
    url = target if "://" in target else f"https://{f'[{host}]' if ':' in host else host}"
    if profile in {
        "http_headers",
        "http_probe",
        "web_fingerprint",
        "nuclei",
        "web_content",
        "web_audit",
    }:
        if "/" in host or not urlsplit(url).hostname:
            raise ValueError("Web profiles require a single host or URL")
    if profile in {"ports", "ports_quick", "ports_full", "ports_udp", "service_audit"}:
        rate = integer(options, "rate", min(50, rate_limit), 1, rate_limit)
        timing = integer(options, "timing", 3, 2, 4)
        args = [
            "-sU" if profile == "ports_udp" else "-sT",
            "-Pn",
            "-n",
            f"-T{timing}",
            "--max-rate",
            str(rate),
            "--max-retries",
            "2",
            "--stats-every",
            "5s",
            "--no-stylesheet",
            "-oX",
            "nmap.xml",
        ]
        if profile not in {"ports_quick", "ports_udp", "ports_full"}:
            args.extend(["-sV", "--version-light"])
        if profile == "service_audit":
            args.extend(["--script", "banner,ssh-hostkey,ssl-cert,http-title,http-headers"])
        if ":" in host:
            args.append("-6")
        if ports := options.get("ports"):
            args.extend(["-p", port_ranges(ports)])
        elif profile == "ports_full":
            args.extend(["-p", "1-65535"])
        elif profile in {"ports_quick", "ports_udp"}:
            args.extend(["--top-ports", "20" if profile == "ports_udp" else "100"])
        args.extend(["--", host])
    elif profile == "discovery":
        args = ["-sn", "-oX", "nmap.xml", *(["-6"] if ":" in host else []), "--", host]
    elif profile == "http_headers":
        args = [
            "--head",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            "--connect-timeout",
            "10",
            "--proto",
            "=http,https",
            "--",
            url,
        ]
    elif profile == "http_probe":
        args = [
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            "--connect-timeout",
            "10",
            "--proto",
            "=http,https",
            "--dump-header",
            "headers.txt",
            "--output",
            "body.txt",
            "--write-out",
            "%{json}",
            "--",
            url,
        ]
    elif profile == "web_fingerprint":
        args = [
            "--aggression=1",
            "--follow-redirect=never",
            "--max-threads=2",
            "--open-timeout=10",
            "--read-timeout=15",
            "--colour=never",
            "--log-json=whatweb.json",
            url,
        ]
    elif profile == "dns":
        record = options.get("record", "A")
        if record not in {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"} or "/" in host:
            raise ValueError("Invalid DNS record type or target")
        args = ["+time=5", "+tries=1", host, record]
    elif profile in {"tls", "tls_audit"}:
        default_port = urlsplit(target).port or 443 if "://" in target else 443
        port = integer(options, "port", default_port, 1, 65535)
        if not 1 <= port <= 65535 or "/" in host:
            raise ValueError("TLS needs a single host and port 1..65535")
        destination = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        args = (
            ["--no-colour", "--connect-timeout=10", "--timeout=5", "--xml=sslscan.xml", destination]
            if profile == "tls"
            else [
                "--quiet",
                "--color",
                "0",
                "--warnings",
                "batch",
                "--jsonfile",
                "testssl.json",
                destination,
            ]
        )
    elif profile == "nuclei":
        severity = options.get("severity", "medium,high,critical")
        if not isinstance(severity, str) or not set(severity.split(",")) <= {
            "info",
            "low",
            "medium",
            "high",
            "critical",
        }:
            raise ValueError("Invalid nuclei severity")
        rate = integer(options, "rate", min(10, rate_limit), 1, rate_limit)
        threads = integer(options, "threads", 2, 1, 8)
        args = [
            "-u",
            url,
            "-severity",
            severity,
            "-rl",
            str(rate),
            "-c",
            str(threads),
            "-jsonl",
            "-o",
            "nuclei.jsonl",
            "-duc",
            "-ni",
            "-dr",
        ]
    elif profile == "web_audit":
        args = [
            "-h",
            url,
            "-maxtime",
            "300s",
            "-timeout",
            "10",
            "-nointeractive",
            "-nocheck",
            "-Tuning",
            "x6",
            "-Format",
            "json",
            "-output",
            "nikto.json",
        ]
    elif profile == "subdomains":
        if "/" in host or ":" in host or re.fullmatch(r"[0-9.]+", host):
            raise ValueError("Subdomain discovery needs a domain")
        args = ["-d", host, "-silent", "-json", "-o", "subfinder.jsonl"]
    elif profile == "smb_shares":
        if "/" in host:
            raise ValueError("SMB requires a single host")
        args = ["-L", host, "-N", "-g", "--timeout=10"]
    elif profile == "whois":
        if "/" in host:
            raise ValueError("WHOIS requires a host or IP")
        args = [host]
    else:
        value = options.get("wordlist", "")
        if not isinstance(value, str):
            raise ValueError("wordlist must be a file path string")
        wordlist = Path(value)
        if not wordlist.is_absolute() or not wordlist.is_file():
            raise ValueError("Provide an existing absolute wordlist path")
        parsed = urlsplit(url)
        fuzz_url = parsed._replace(
            path=parsed.path.rstrip("/") + "/FUZZ", query="", fragment=""
        ).geturl()
        rate = integer(options, "rate", min(10, rate_limit), 1, rate_limit)
        threads = integer(options, "threads", 2, 1, 8)
        args = [
            "-u",
            fuzz_url,
            "-w",
            str(wordlist),
            "-rate",
            str(rate),
            "-t",
            str(threads),
            "-maxtime",
            "300",
            "-timeout",
            "10",
            "-of",
            "json",
            "-o",
            "ffuf.json",
            "-noninteractive",
        ]
        if extensions := options.get("extensions"):
            if not isinstance(extensions, str) or not re.fullmatch(
                r"[.a-zA-Z0-9,]{1,100}", extensions
            ):
                raise ValueError("Invalid extensions")
            args.extend(["-e", extensions])
    return PROFILES[profile]["tool"], args
