from __future__ import annotations

import json

from defusedxml import ElementTree


def parse_nmap(text: str) -> dict:
    root = ElementTree.fromstring(text)
    return {"hosts": [nmap_host(host) for host in root.findall("host")], "untrusted": True}


def nmap_host(host) -> dict:
    status = host.find("status")
    ports = []
    for port in host.findall("ports/port"):
        state = port.find("state")
        service = port.find("service")
        ports.append(
            {
                "port": int(port.get("portid", "0")),
                "protocol": port.get("protocol"),
                "state": state.get("state") if state is not None else None,
                "service": dict(service.attrib) if service is not None else {},
                "scripts": [dict(s.attrib) for s in port.findall("script")],
            }
        )
    return {
        "addresses": [dict(a.attrib) for a in host.findall("address")],
        "hostnames": [h.get("name") for h in host.findall("hostnames/hostname")],
        "status": status.get("state") if status is not None else None,
        "ports": ports,
    }


def iter_nmap(path):
    with path.open("rb") as stream:
        events = ElementTree.iterparse(stream, events=("start", "end"))
        _, root = next(events)
        for event, element in events:
            if event == "end" and element.tag == "host":
                yield nmap_host(element)
                root.remove(element)
                element.clear()


def parse_jsonl(text: str, offset: int = 0, limit: int = 100) -> dict:
    if offset < 0 or not 1 <= limit <= 500:
        raise ValueError("offset >= 0; limit must be 1..500 records")
    lines = [line for line in text.splitlines() if line.strip()]
    records = []
    for number, line in enumerate(lines[offset : offset + limit], start=offset):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append({"parse_error": True, "line": number, "raw": line[:1000]})
    return {
        "records": records,
        "next_offset": offset + len(records),
        "total": len(lines),
        "untrusted": True,
    }
