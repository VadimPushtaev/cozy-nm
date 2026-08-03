from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from cozy_network_manager.app.api import auth
from cozy_network_manager.app.middleware.head_auth import HeadAuthMiddleware
from cozy_network_manager.app.services.head_auth import HeadAuthStore, LoginThrottle


def _app(auth_file: Path) -> FastAPI:
    app = FastAPI()
    store = HeadAuthStore(auth_file)
    app.state.head_auth_store = store
    app.state.head_auth_throttle = LoginThrottle(max_delay_seconds=0)
    app.state.head_auth_cookie_secure = False
    app.add_middleware(HeadAuthMiddleware, store=store)
    app.include_router(auth.router)

    @app.get("/")
    async def home():
        return {"page": "home"}

    @app.get("/api/private")
    async def private_api():
        return {"private": True}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
        follow_redirects=False,
    )


@pytest.mark.asyncio
async def test_setup_login_change_and_disable_flow(tmp_path: Path):
    auth_file = tmp_path / "head-auth.json"
    app = _app(auth_file)
    origin = {"origin": "http://testserver"}

    async with _client(app) as owner:
        assert (await owner.get("/")).status_code == 200
        assert (await owner.get("/auth/setup")).status_code == 200
        assert (
            await owner.post(
                "/auth/setup",
                data={"password": "first password", "confirm_password": "first password"},
            )
        ).status_code == 403

        setup = await owner.post(
            "/auth/setup",
            data={"password": "first password", "confirm_password": "first password"},
            headers=origin,
        )
        assert setup.status_code == 303
        assert "cnm_head_session" in owner.cookies
        assert "HttpOnly" in setup.headers["set-cookie"]
        assert "SameSite=lax" in setup.headers["set-cookie"]
        assert "Max-Age=2592000" in setup.headers["set-cookie"]
        assert (await owner.get("/")).status_code == 200

        async with _client(app) as second_browser:
            redirect = await second_browser.get("/nodes")
            assert redirect.status_code == 303
            assert redirect.headers["location"].startswith("/auth/login?")
            api_response = await second_browser.get("/api/private")
            assert api_response.status_code == 401
            assert (await second_browser.get("/health")).status_code == 200

            wrong = await second_browser.post(
                "/auth/login", data={"password": "wrong password"}, headers=origin
            )
            assert wrong.status_code == 401
            login = await second_browser.post(
                "/auth/login", data={"password": "first password"}, headers=origin
            )
            assert login.status_code == 303
            assert (await second_browser.get("/")).status_code == 200

            no_origin = await owner.post(
                "/auth/change",
                data={
                    "current_password": "first password",
                    "new_password": "second password",
                    "confirm_password": "second password",
                },
            )
            assert no_origin.status_code == 403
            changed = await owner.post(
                "/auth/change",
                data={
                    "current_password": "first password",
                    "new_password": "second password",
                    "confirm_password": "second password",
                },
                headers=origin,
            )
            assert changed.status_code == 303
            assert (await owner.get("/")).status_code == 200
            assert (await second_browser.get("/")).status_code == 303

            bad_disable = await owner.post(
                "/auth/disable",
                data={"current_password": "wrong password"},
                headers=origin,
            )
            assert bad_disable.status_code == 401
            disabled = await owner.post(
                "/auth/disable",
                data={"current_password": "second password"},
                headers=origin,
            )
            assert disabled.status_code == 303
            assert not auth_file.exists()
            assert (await second_browser.get("/")).status_code == 200


@pytest.mark.asyncio
async def test_external_removal_and_invalid_file_behavior(tmp_path: Path):
    auth_file = tmp_path / "head-auth.json"
    app = _app(auth_file)
    app.state.head_auth_store.setup("test password")

    async with _client(app) as client:
        assert (await client.get("/")).status_code == 303
        auth_file.unlink()
        assert (await client.get("/")).status_code == 200

        auth_file.write_text("invalid", encoding="utf-8")
        assert (await client.get("/")).status_code == 503
        assert (await client.get("/api/private")).status_code == 503
        assert (await client.get("/health")).status_code == 200
