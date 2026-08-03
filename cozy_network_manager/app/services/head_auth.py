from __future__ import annotations

import asyncio
import base64
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError


SESSION_COOKIE = "cnm_head_session"
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 1024
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024
MAX_SESSIONS = 32


class HeadAuthError(Exception):
    pass


class AuthStateCorrupt(HeadAuthError):
    pass


class AuthAlreadyConfigured(HeadAuthError):
    pass


class InvalidPassword(HeadAuthError):
    pass


class PasswordValidationError(HeadAuthError):
    pass


class PasswordHash(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    algorithm: Literal["scrypt"] = "scrypt"
    salt: str
    digest: str
    n: int = SCRYPT_N
    r: int = SCRYPT_R
    p: int = SCRYPT_P
    dklen: int = SCRYPT_DKLEN


class SessionHash(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: int


class AuthState(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[1] = 1
    password: PasswordHash
    sessions: list[SessionHash] = Field(default_factory=list)


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordValidationError(
            f"Password must contain at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordValidationError("Password is too long.")


def safe_next_url(value: str | None, default: str = "/") -> str:
    if not value or not value.startswith("/") or value.startswith("//"):
        return default
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        return default
    return value


def same_origin(request) -> bool:
    expected_host = request.headers.get("host", "")
    supplied = request.headers.get("origin") or request.headers.get("referer")
    if not expected_host or not supplied:
        return False
    return urlsplit(supplied).netloc == expected_host


class HeadAuthStore:
    def __init__(self, path: str | Path, session_days: int = 30):
        self.path = Path(path)
        self.lock_path = self.path.with_name(f".{self.path.name}.lock")
        self.session_seconds = session_days * 24 * 60 * 60

    def configured(self) -> bool:
        return self._read() is not None

    def session_valid(self, token: str | None) -> bool:
        if not token:
            return False
        state = self._read()
        if state is None:
            return False
        token_hash = self._token_hash(token)
        now = int(time.time())
        return any(
            session.expires_at > now
            and hmac.compare_digest(session.token_hash, token_hash)
            for session in state.sessions
        )

    def setup(self, password: str) -> str:
        validate_password(password)
        with self._locked():
            if self._read() is not None:
                raise AuthAlreadyConfigured("A password is already configured.")
            token, session = self._new_session()
            state = AuthState(password=self._hash_password(password), sessions=[session])
            self._write(state)
        return token

    def login(self, password: str) -> str:
        with self._locked():
            state = self._read()
            if state is None or not self._verify_password(password, state.password):
                raise InvalidPassword("Invalid password.")
            token, session = self._new_session()
            state.sessions = self._active_sessions(state.sessions)[-(MAX_SESSIONS - 1) :]
            state.sessions.append(session)
            self._write(state)
        return token

    def change_password(self, current_password: str, new_password: str) -> str:
        validate_password(new_password)
        with self._locked():
            state = self._read()
            if state is None or not self._verify_password(current_password, state.password):
                raise InvalidPassword("Invalid current password.")
            token, session = self._new_session()
            state.password = self._hash_password(new_password)
            state.sessions = [session]
            self._write(state)
        return token

    def disable(self, current_password: str) -> None:
        with self._locked():
            state = self._read()
            if state is None or not self._verify_password(current_password, state.password):
                raise InvalidPassword("Invalid current password.")
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            self._sync_parent()

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with self._locked():
            state = self._read()
            if state is None:
                return
            token_hash = self._token_hash(token)
            state.sessions = [
                session
                for session in self._active_sessions(state.sessions)
                if not hmac.compare_digest(session.token_hash, token_hash)
            ]
            self._write(state)

    def _read(self) -> AuthState | None:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError) as exc:
            raise AuthStateCorrupt("The head authentication file cannot be read.") from exc
        try:
            state = AuthState.model_validate_json(raw)
            self._validate_hash(state.password)
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise AuthStateCorrupt("The head authentication file is invalid.") from exc
        return state

    @staticmethod
    def _validate_hash(password_hash: PasswordHash) -> None:
        if (
            password_hash.n != SCRYPT_N
            or password_hash.r != SCRYPT_R
            or password_hash.p != SCRYPT_P
            or password_hash.dklen != SCRYPT_DKLEN
        ):
            raise ValueError("Unsupported password hashing parameters")
        salt = base64.b64decode(password_hash.salt, validate=True)
        digest = base64.b64decode(password_hash.digest, validate=True)
        if len(salt) != 16 or len(digest) != SCRYPT_DKLEN:
            raise ValueError("Invalid password hash")

    @staticmethod
    def _hash_password(password: str) -> PasswordHash:
        salt = secrets.token_bytes(16)
        digest = HeadAuthStore._scrypt(password, salt)
        return PasswordHash(
            salt=base64.b64encode(salt).decode("ascii"),
            digest=base64.b64encode(digest).decode("ascii"),
        )

    @staticmethod
    def _verify_password(password: str, password_hash: PasswordHash) -> bool:
        if len(password) > MAX_PASSWORD_LENGTH:
            return False
        try:
            salt = base64.b64decode(password_hash.salt, validate=True)
            expected = base64.b64decode(password_hash.digest, validate=True)
            actual = HeadAuthStore._scrypt(password, salt)
        except (ValueError, UnicodeError):
            return False
        return hmac.compare_digest(actual, expected)

    @staticmethod
    def _scrypt(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
            maxmem=SCRYPT_MAXMEM,
        )

    def _new_session(self) -> tuple[str, SessionHash]:
        token = secrets.token_urlsafe(32)
        return token, SessionHash(
            token_hash=self._token_hash(token),
            expires_at=int(time.time()) + self.session_seconds,
        )

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _active_sessions(sessions: list[SessionHash]) -> list[SessionHash]:
        now = int(time.time())
        return [session for session in sessions if session.expires_at > now]

    def _ensure_parent(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._ensure_parent()
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _write(self, state: AuthState) -> None:
        self._ensure_parent()
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(state.model_dump_json(indent=2))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.path)
            self._sync_parent()
        finally:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass

    def _sync_parent(self) -> None:
        try:
            descriptor = os.open(self.path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class LoginThrottle:
    def __init__(self, max_delay_seconds: float = 30, reset_after_seconds: int = 15 * 60):
        self.max_delay_seconds = max_delay_seconds
        self.reset_after_seconds = reset_after_seconds
        self._failures: dict[str, tuple[int, float]] = {}
        self._lock = asyncio.Lock()

    async def failed(self, key: str) -> None:
        now = time.monotonic()
        async with self._lock:
            count, previous = self._failures.get(key, (0, 0))
            if now - previous > self.reset_after_seconds:
                count = 0
            count += 1
            self._failures[key] = (count, now)
            delay = min(float(2 ** (count - 1)), self.max_delay_seconds)
        if delay:
            await asyncio.sleep(delay)

    async def succeeded(self, key: str) -> None:
        async with self._lock:
            self._failures.pop(key, None)
