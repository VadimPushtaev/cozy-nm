from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from cozy_network_manager.app.services.head_auth import (
    AuthStateCorrupt,
    HeadAuthStore,
    InvalidPassword,
    PasswordValidationError,
    safe_next_url,
)


def test_password_and_sessions_are_hashed_and_persisted(tmp_path: Path):
    auth_file = tmp_path / "auth" / "head-auth.json"
    store = HeadAuthStore(auth_file, session_days=30)

    token = store.setup("correct horse battery staple")
    contents = auth_file.read_text(encoding="utf-8")
    data = json.loads(contents)

    assert "correct horse battery staple" not in contents
    assert token not in contents
    assert data["password"]["algorithm"] == "scrypt"
    assert len(data["sessions"][0]["token_hash"]) == 64
    assert stat.S_IMODE(auth_file.stat().st_mode) == 0o600
    assert HeadAuthStore(auth_file, session_days=30).session_valid(token)


def test_login_change_logout_and_disable(tmp_path: Path):
    auth_file = tmp_path / "head-auth.json"
    store = HeadAuthStore(auth_file)
    original_token = store.setup("first password")
    second_token = store.login("first password")

    with pytest.raises(InvalidPassword):
        store.login("wrong password")

    changed_token = store.change_password("first password", "second password")
    assert not store.session_valid(original_token)
    assert not store.session_valid(second_token)
    assert store.session_valid(changed_token)

    with pytest.raises(InvalidPassword):
        store.login("first password")
    login_token = store.login("second password")
    store.logout(login_token)
    assert not store.session_valid(login_token)

    with pytest.raises(InvalidPassword):
        store.disable("wrong password")
    store.disable("second password")
    assert not auth_file.exists()
    assert not store.configured()


def test_password_validation_and_corrupt_file(tmp_path: Path):
    auth_file = tmp_path / "head-auth.json"
    store = HeadAuthStore(auth_file)

    with pytest.raises(PasswordValidationError, match="at least 8"):
        store.setup("short")

    auth_file.write_text("not json", encoding="utf-8")
    with pytest.raises(AuthStateCorrupt):
        store.configured()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "/"),
        ("", "/"),
        ("/nodes?view=all", "/nodes?view=all"),
        ("//evil.example/path", "/"),
        ("https://evil.example/path", "/"),
        ("nodes", "/"),
    ],
)
def test_safe_next_url(value: str | None, expected: str):
    assert safe_next_url(value) == expected
