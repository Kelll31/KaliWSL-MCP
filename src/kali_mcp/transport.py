from __future__ import annotations

import hmac

from mcp.server import MCPServer
from starlette.responses import JSONResponse


class BearerMiddleware:
    def __init__(self, app, token: str):
        self.app = app
        self.expected = b"Bearer " + token.encode("utf-8")

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = [
                value
                for name, value in scope.get("headers", [])
                if name.lower() == b"authorization"
            ]
            if len(headers) != 1 or not hmac.compare_digest(headers[0], self.expected):
                response = JSONResponse(
                    {"error": "Bearer token required"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def http_app(server: MCPServer, token: str, host: str = "127.0.0.1"):
    """One persistent runtime shared by multiple local MCP clients."""
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("HTTP transport binds to loopback only")
    if len(token) < 32 or any(c.isspace() for c in token):
        raise ValueError("HTTP token must contain at least 32 non-whitespace characters")
    app = server.streamable_http_app(
        host=host,
        json_response=True,
        stateless_http=True,
        max_request_body_size=1024 * 1024,
        max_sessions=100,
    )
    app.add_middleware(BearerMiddleware, token=token)
    return app
