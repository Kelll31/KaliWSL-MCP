import pytest
from defusedxml.common import DefusedXmlException

from kali_mcp.parsers import parse_jsonl, parse_nmap
from kali_mcp.profiles import build


def test_ports_and_url_normalization():
    tool, args = build("ports", "https://localhost:8443/a", {"ports": "22,80,443"})
    assert tool == "nmap" and args[-1] == "localhost"
    assert "22,80,443" in args
    assert "-sT" in args
    assert build("http_headers", "::1")[1][-1] == "https://[::1]"


@pytest.mark.parametrize("ports", ["0", "65536", "80;id", "90-80", "1--3", "1,"])
def test_invalid_ports(ports):
    with pytest.raises(ValueError):
        build("ports", "localhost", {"ports": ports})


def test_unknown_options():
    with pytest.raises(ValueError):
        build("ports", "localhost", {"args": "--script=all"})


@pytest.mark.parametrize(
    "profile", ["ports", "ports_quick", "ports_full", "ports_udp", "service_audit"]
)
def test_network_profiles_obey_rate_ceiling(profile):
    _, args = build(profile, "::1", {"rate": 20}, rate_limit=25)
    assert "-6" in args and args[args.index("--max-rate") + 1] == "20"
    with pytest.raises(ValueError, match="rate"):
        build(profile, "localhost", {"rate": 26}, rate_limit=25)


@pytest.mark.parametrize("port", [True, "443", 0, 65536, 3.5])
def test_tls_port_types(port):
    with pytest.raises(ValueError, match="port"):
        build("tls", "localhost", {"port": port})


def test_tls_uses_explicit_url_port():
    assert build("tls", "https://localhost:8443/path")[1][-1] == "localhost:8443"


def test_nmap_parser():
    data = parse_nmap("""<nmaprun><host><status state="up"/>
      <address addr="127.0.0.1" addrtype="ipv4"/><ports>
      <port protocol="tcp" portid="80"><state state="open"/>
      <service name="http" product="nginx"/></port></ports></host></nmaprun>""")
    assert data["hosts"][0]["ports"][0]["service"]["name"] == "http"
    assert data["untrusted"]


def test_xml_entities_rejected():
    with pytest.raises(DefusedXmlException):
        parse_nmap('<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>')


def test_jsonl_paging_and_malformed_line():
    result = parse_jsonl('{"id":1}\ninvalid\n{"id":2}\n', offset=1, limit=1)
    assert result["records"][0]["parse_error"]
    assert result["total"] == 3 and result["next_offset"] == 2
