from __future__ import annotations

from urllib.parse import urlencode

from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.requests import Request

from cozy_network_manager.app.services.head_auth import (
    SESSION_COOKIE,
    AuthStateCorrupt,
    HeadAuthStore,
    same_origin,
)


PUBLIC_AUTH_PATHS = {"/auth/login", "/auth/setup"}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class HeadAuthMiddleware:
    def __init__(self, app, store: HeadAuthStore):
        self.app = app
        self.store = store

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        path = request.url.path
        if path == "/health" or path.startswith("/static/"):
            await self.app(scope, receive, send)
            return

        try:
            configured = self.store.configured()
            authenticated = configured and self.store.session_valid(
                request.cookies.get(SESSION_COOKIE)
            )
        except AuthStateCorrupt:
            response = self._service_unavailable(path)
            await response(scope, receive, send)
            return

        scope.setdefault("state", {})["auth_configured"] = configured
        scope["state"]["authenticated"] = authenticated

        if not configured:
            await self.app(scope, receive, send)
            return

        if path in PUBLIC_AUTH_PATHS:
            await self.app(scope, receive, send)
            return

        if not authenticated:
            response = self._unauthorized(request)
            await response(scope, receive, send)
            return

        if request.method in UNSAFE_METHODS and not same_origin(request):
            if path.startswith("/api/"):
                response = JSONResponse(
                    {"detail": "Same-origin request required."}, status_code=403
                )
            else:
                response = PlainTextResponse("Same-origin request required.", status_code=403)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

    @staticmethod
    def _service_unavailable(path: str):
        detail = "Head authentication is unavailable because its state file is invalid."
        if path.startswith("/api/"):
            return JSONResponse({"detail": detail}, status_code=503)
        return PlainTextResponse(detail, status_code=503)

    @staticmethod
    def _unauthorized(request: Request):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Authentication required."}, status_code=401)
        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"
        return RedirectResponse(
            f"/auth/login?{urlencode({'next': target})}",
            status_code=303,
        )
