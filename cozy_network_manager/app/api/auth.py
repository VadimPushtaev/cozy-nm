from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cozy_network_manager.app.services.head_auth import (
    MIN_PASSWORD_LENGTH,
    SESSION_COOKIE,
    AuthAlreadyConfigured,
    HeadAuthStore,
    InvalidPassword,
    LoginThrottle,
    PasswordValidationError,
    safe_next_url,
    same_origin,
)
from cozy_network_manager.app.ui.templates import templates


router = APIRouter(prefix="/auth")


def _store(request: Request) -> HeadAuthStore:
    return request.app.state.head_auth_store


def _throttle(request: Request) -> LoginThrottle:
    return request.app.state.head_auth_throttle


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _require_same_origin(request: Request) -> None:
    if not same_origin(request):
        raise HTTPException(status_code=403, detail="Same-origin form submission required.")


def _set_session_cookie(response: RedirectResponse, request: Request, token: str) -> None:
    store = _store(request)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=store.session_seconds,
        httponly=True,
        secure=request.app.state.head_auth_cookie_secure,
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: RedirectResponse, request: Request) -> None:
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=request.app.state.head_auth_cookie_secure,
        samesite="lax",
        path="/",
    )


def _render_setup(request: Request, error: str | None = None, status_code: int = 200):
    return templates.TemplateResponse(
        request,
        "auth_setup.html",
        {"error": error, "minimum_length": MIN_PASSWORD_LENGTH},
        status_code=status_code,
    )


def _render_login(
    request: Request,
    next_url: str,
    error: str | None = None,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request,
        "auth_login.html",
        {"error": error, "next_url": next_url},
        status_code=status_code,
    )


def _render_settings(
    request: Request,
    *,
    message: str | None = None,
    change_error: str | None = None,
    disable_error: str | None = None,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request,
        "auth_settings.html",
        {
            "message": message,
            "change_error": change_error,
            "disable_error": disable_error,
            "minimum_length": MIN_PASSWORD_LENGTH,
        },
        status_code=status_code,
    )


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if request.state.auth_configured:
        destination = "/" if request.state.authenticated else "/auth/login"
        return RedirectResponse(destination, status_code=303)
    return _render_setup(request)


@router.post("/setup")
async def setup_password(
    request: Request,
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    _require_same_origin(request)
    if request.state.auth_configured:
        return RedirectResponse("/auth/login", status_code=303)
    if password != confirm_password:
        return _render_setup(request, "Passwords do not match.", 400)
    try:
        token = _store(request).setup(password)
    except PasswordValidationError as exc:
        return _render_setup(request, str(exc), 400)
    except AuthAlreadyConfigured:
        return RedirectResponse("/auth/login", status_code=303)
    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, request, token)
    return response


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str | None = None):
    next_url = safe_next_url(next)
    if not request.state.auth_configured:
        return RedirectResponse("/auth/setup", status_code=303)
    if request.state.authenticated:
        return RedirectResponse(next_url, status_code=303)
    return _render_login(request, next_url)


@router.post("/login")
async def login(
    request: Request,
    password: str = Form(...),
    next: str | None = Form(None),
):
    _require_same_origin(request)
    next_url = safe_next_url(next)
    if not request.state.auth_configured:
        return RedirectResponse("/auth/setup", status_code=303)
    key = _client_key(request)
    try:
        token = _store(request).login(password)
    except InvalidPassword:
        await _throttle(request).failed(key)
        return _render_login(request, next_url, "Incorrect password.", 401)
    await _throttle(request).succeeded(key)
    response = RedirectResponse(next_url, status_code=303)
    _set_session_cookie(response, request, token)
    return response


@router.get("/settings", response_class=HTMLResponse)
async def auth_settings(request: Request, message: str | None = None):
    return _render_settings(request, message=message)


@router.post("/change")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    if new_password != confirm_password:
        return _render_settings(request, change_error="New passwords do not match.", status_code=400)
    key = _client_key(request)
    try:
        token = _store(request).change_password(current_password, new_password)
    except PasswordValidationError as exc:
        return _render_settings(request, change_error=str(exc), status_code=400)
    except InvalidPassword:
        await _throttle(request).failed(key)
        return _render_settings(
            request,
            change_error="Incorrect current password.",
            status_code=401,
        )
    await _throttle(request).succeeded(key)
    response = RedirectResponse("/auth/settings?message=Password+changed.", status_code=303)
    _set_session_cookie(response, request, token)
    return response


@router.post("/disable")
async def disable_password(request: Request, current_password: str = Form(...)):
    key = _client_key(request)
    try:
        _store(request).disable(current_password)
    except InvalidPassword:
        await _throttle(request).failed(key)
        return _render_settings(
            request,
            disable_error="Incorrect current password.",
            status_code=401,
        )
    await _throttle(request).succeeded(key)
    response = RedirectResponse("/", status_code=303)
    _clear_session_cookie(response, request)
    return response


@router.post("/logout")
async def logout(request: Request):
    _store(request).logout(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse("/auth/login", status_code=303)
    _clear_session_cookie(response, request)
    return response
