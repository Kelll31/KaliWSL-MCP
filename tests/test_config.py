import pytest

from kali_mcp.config import Config, matches, target_host


@pytest.mark.parametrize(
    ("target", "rule", "expected"),
    [
        ("https://app.example.com:8443/path", "*.example.com", True),
        ("example.com", "*.example.com", False),
        ("evil-example.com", "*.example.com", False),
        ("EXAMPLE.COM.", "example.com", True),
        ("10.2.3.4", "10.0.0.0/8", True),
        ("10.2.0.0/16", "10.0.0.0/8", True),
        ("10.0.0.0/8", "10.2.0.0/16", False),
        ("2001:db8::1", "2001:db8::/32", True),
        ("127.0.0.1", "::1", False),
    ],
)
def test_scope(target, rule, expected):
    assert matches(target, rule) is expected


@pytest.mark.parametrize(
    "target",
    [
        "-oX",
        "host name",
        "file:///etc/passwd",
        "https://user:pass@example.com",
        "https://x:99999",
        "example.com/path",
        "x..com",
        "foo;id",
    ],
)
def test_invalid_target(target):
    with pytest.raises(ValueError):
        target_host(target)


def test_outside_scope():
    with pytest.raises(ValueError, match="outside"):
        Config().check_target("example.com")


def test_executable_paths_rejected():
    with pytest.raises(ValueError):
        Config(allowed_tools=("/usr/bin/python3",))


def test_scope_exclusions_reject_overlapping_networks():
    config = Config(allowed_targets=("10.0.0.0/8",), excluded_targets=("10.5.0.0/16",))
    config.check_target("10.4.0.1")
    for target in ("10.5.1.1", "10.0.0.0/8"):
        with pytest.raises(ValueError, match="excluded"):
            config.check_target(target)


def test_wildcard_scope_can_be_narrowed():
    config = Config(allowed_targets=("*.example.com",))
    config.check_rule("*.app.example.com")
    config.check_rule("*.example.com")
    with pytest.raises(ValueError):
        config.check_rule("*.com")
    with pytest.raises(ValueError):
        Config(allowed_targets=("example.com",)).check_rule("*.example.com")
