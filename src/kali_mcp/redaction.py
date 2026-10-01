"""Redact report copies while keeping private evidence byte-for-byte unchanged."""

from __future__ import annotations

import os
import re
from pathlib import Path

MARKER = b"<REDACTED>"
SECRET_NAMES = (
    rb"password|passwd|pwd|passphrase|token|access[_-]?token|refresh[_-]?token|"
    rb"api[_-]?key|client[_-]?secret|secret|private[_-]?key"
)
INLINE_ASSIGNMENT = re.compile(
    rb"""(?i)(["'])((?:""" + SECRET_NAMES + rb""")[ \t]*=[ \t]*)(?:\\.|(?!\1)[^\\])*\1"""
)
ASSIGNMENT = re.compile(
    rb"""(?i)(["']?(?:""" + SECRET_NAMES + rb""")["']?\s*[:=]\s*)"""
    rb"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s&,;]+)"""
)
AUTHORIZATION = re.compile(
    rb"(?i)((?:proxy-)?authorization[ \t]*:[ \t]*(?:basic|bearer)[ \t]+)[^\r\n]+"
)
COOKIE = re.compile(rb"(?im)^((?:set-)?cookie[ \t]*:[ \t]*)([^\r\n]+)")
COOKIE_VALUE = re.compile(rb"""([^=;]+=[ \t]*)("(?:[^"\\]|\\.)*"|[^;\r\n]*)""")
TOKEN = re.compile(rb"(?i)\b((?:bearer|basic)[ \t]+)[A-Za-z0-9._~+/=-]+")
URL_PASSWORD = re.compile(rb"(://[^/\s:@]+:)[^@\s/]+(@)")
PRIVATE_KEY = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    rb".*?(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
KNOWN_TOKEN = re.compile(
    rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}|"
    rb"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}|(?:AKIA|ASIA)[A-Z0-9]{16}|"
    rb"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b"
)
SECRET_FLAGS = {
    "--password",
    "-password",
    "--passwd",
    "-passwd",
    "--passphrase",
    "--token",
    "-token",
    "--api-key",
    "-api-key",
    "--apikey",
    "-apikey",
    "--client-secret",
    "--secret",
    "--private-key",
    "--key",
    "-key",
    "--pwd",
    "--pass",
}
TOOL_SECRET_FLAGS = {
    "netexec": {"-p"},
    "nxc": {"-p"},
    "smbmap": {"-p"},
    "ldapsearch": {"-w"},
    "hydra": {"-p"},
    "medusa": {"-p"},
}
CLI_SECRET = re.compile(
    rb"""(?i)(--?(?:""" + SECRET_NAMES + rb""")[ \t]+)"""
    rb"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s]+)"""
)


class Redactor:
    def __init__(self, secret_env: tuple[str, ...] = ()):
        self.values = sorted(
            {os.environ[name].encode("utf-8") for name in secret_env if os.environ.get(name)},
            key=lambda value: (-len(value), value),
        )

    def bytes(self, value: bytes) -> bytes:
        for secret in self.values:
            if len(secret) < 8:
                value = re.sub(
                    rb"(?<![A-Za-z0-9_])" + re.escape(secret) + rb"(?![A-Za-z0-9_])",
                    MARKER,
                    value,
                )
            else:
                value = value.replace(secret, MARKER)
        value = PRIVATE_KEY.sub(MARKER, value)
        value = AUTHORIZATION.sub(lambda m: m[1] + MARKER, value)

        def replace_cookie(match):
            def cookie_value(pair):
                previous = pair[2]
                marker = b'"' + MARKER + b'"' if previous[:1] == b'"' else MARKER
                return pair[1] + marker

            count = 1 if match[1].lower().startswith(b"set-cookie") else 0
            return match[1] + COOKIE_VALUE.sub(cookie_value, match[2], count=count)

        value = COOKIE.sub(replace_cookie, value)
        value = TOKEN.sub(lambda m: m[1] + MARKER, value)
        value = URL_PASSWORD.sub(lambda m: m[1] + MARKER + m[2], value)
        value = INLINE_ASSIGNMENT.sub(lambda m: m[1] + m[2] + MARKER + m[1], value)

        def replace_assignment(match):
            previous = match[2]
            prefix_quote = match[1][:1]
            if prefix_quote in (b'"', b"'") and match[1].count(prefix_quote) == 1:
                closing = previous.find(prefix_quote)
                if closing >= 0:
                    return match[1] + MARKER + previous[closing:]
            marker = (
                previous[:1] + MARKER + previous[-1:] if previous[:1] in (b'"', b"'") else MARKER
            )
            return match[1] + marker

        value = ASSIGNMENT.sub(replace_assignment, value)
        value = CLI_SECRET.sub(replace_assignment, value)
        return KNOWN_TOKEN.sub(MARKER, value)

    def text(self, value: str) -> str:
        return self.bytes(value.encode("utf-8")).decode("utf-8")

    def argv(self, arguments: list[str]) -> list[str]:
        tool = Path(arguments[0]).name.removesuffix(".exe") if arguments else ""
        tool_flags = TOOL_SECRET_FLAGS.get(tool, set())
        result, hide_next, credential_next = [], False, False
        for argument in arguments:
            if hide_next:
                result.append("<REDACTED>")
                hide_next = False
            elif credential_next:
                sanitized = self.text(argument)
                if "://" not in argument:
                    sanitized = re.sub(r"([:%]).+", r"\1<REDACTED>", sanitized)
                result.append(sanitized)
                credential_next = False
            else:
                result.append(self.text(argument))
                hide_next = argument.lower() in SECRET_FLAGS or argument in tool_flags
                credential_next = argument in ("-u", "--user", "-U", "--username")
        return result

    def scoped(self, arguments: list[str]) -> Redactor:
        """Learn explicit credential arguments so their reflected output is masked too."""
        tool = Path(arguments[0]).name.removesuffix(".exe") if arguments else ""
        tool_flags = TOOL_SECRET_FLAGS.get(tool, set())
        secrets = set(self.values)
        for index, argument in enumerate(arguments):
            option, separator, inline_value = argument.partition("=")
            if separator and (option.lower() in SECRET_FLAGS or option in tool_flags):
                if inline_value:
                    secrets.add(inline_value.encode("utf-8"))
            if (argument.lower() in SECRET_FLAGS or argument in tool_flags) and index + 1 < len(
                arguments
            ):
                value = arguments[index + 1]
                if value:
                    secrets.add(value.encode("utf-8"))
            if argument in ("-u", "--user", "-U", "--username") and index + 1 < len(arguments):
                value = arguments[index + 1]
                if "://" not in value:
                    parts = re.split(r"[:%]", value, maxsplit=1)
                    if len(parts) == 2 and parts[1]:
                        secrets.add(parts[1].encode("utf-8"))
        result = Redactor()
        result.values = sorted(secrets, key=lambda value: (-len(value), value))
        return result

    def object(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.object(item) for item in value]
        if isinstance(value, dict):
            return {
                key: (
                    "<REDACTED>"
                    if isinstance(item, str)
                    and re.fullmatch(SECRET_NAMES.decode(), key, flags=re.IGNORECASE)
                    else self.argv(item)
                    if key == "argv" and isinstance(item, list)
                    else self.object(item)
                )
                for key, item in value.items()
            }
        return value
