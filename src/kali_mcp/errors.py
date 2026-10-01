import inspect
import json
from functools import wraps
from xml.etree.ElementTree import ParseError

from defusedxml.common import DefusedXmlException
from mcp.server.mcpserver.exceptions import ToolError

EXPECTED = (ValueError, OSError, ParseError, DefusedXmlException)


def tool_errors(function):
    """Expose actionable validation errors through MCP instead of generic crash messages."""
    if inspect.iscoroutinefunction(function):

        @wraps(function)
        async def async_wrapper(*args, **kwargs):
            try:
                return await function(*args, **kwargs)
            except EXPECTED as error:
                raise ToolError(str(error)) from error

        return async_wrapper

    @wraps(function)
    def sync_wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except EXPECTED as error:
            raise ToolError(str(error)) from error

    return sync_wrapper


def response_budget(max_bytes: int):
    """Reject oversized results before MCP serializes both text and structured content."""

    def decorate(function):
        def check(result):
            if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > max_bytes:
                raise ToolError(
                    "Result exceeds response budget; reduce limit, use compact lists, "
                    "or read the saved artifact in pages"
                )
            return result

        if inspect.iscoroutinefunction(function):

            @wraps(function)
            async def async_wrapper(*args, **kwargs):
                return check(await function(*args, **kwargs))

            return async_wrapper

        @wraps(function)
        def sync_wrapper(*args, **kwargs):
            return check(function(*args, **kwargs))

        return sync_wrapper

    return decorate
