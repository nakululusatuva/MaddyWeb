"""Durable authentication metadata and second-factor state.

The store is intentionally synchronous so the privileged helper can own it.
Production callers should place the database in a root-owned, owner-only
directory and provide the 32-byte master key from a separate protected file.
Passwords remain outside this module; a caller creates a pending challenge only
after it has verified the primary credential.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import struct
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final
from urllib.parse import quote, urlencode, urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers import (
    options_to_json,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

TOTP_PERIOD_SECONDS: Final[int] = 30
TOTP_WINDOW: Final[int] = 1
TOTP_SECRET_BYTES: Final[int] = 20
RECOVERY_CODE_COUNT: Final[int] = 10
CHALLENGE_LIFETIME_SECONDS: Final[int] = 5 * 60
CHALLENGE_FAILURE_LIMIT: Final[int] = 5
SESSION_IDLE_SECONDS: Final[int] = 72 * 60 * 60
SESSION_ABSOLUTE_SECONDS: Final[int] = 30 * 24 * 60 * 60
STEP_UP_SECONDS: Final[int] = 5 * 60
_LEGACY_SESSION_IDLE_SECONDS: Final[int] = 30 * 60
MAX_SESSIONS_PER_ACCOUNT: Final[int] = 5
MAX_PASSKEYS_PER_ACCOUNT: Final[int] = 10

_TOKEN_BYTES: Final[int] = 32
_ACCOUNT_ID_BYTES: Final[int] = 16
_SESSION_ID_BYTES: Final[int] = 16
_AES_GCM_NONCE_BYTES: Final[int] = 12
_SCHEMA_VERSION: Final[int] = 4
_PASSKEY_SESSION_EXTENSION_VERSION: Final[int] = 1
_PASSKEY_SESSION_EXTENSION_KEY: Final[str] = "passkey_session_extension_version"
_MAX_CHALLENGES_PER_ACCOUNT: Final[int] = 5
_MAX_PASSKEY_CHALLENGES_PER_ACCOUNT: Final[int] = 5
_MAX_ANONYMOUS_PASSKEY_LOGIN_CHALLENGES: Final[int] = 256
_MAX_RATE_LIMIT_ROWS: Final[int] = 1024
_MAX_CREDENTIAL_ID_BYTES: Final[int] = 1024
_MAX_PASSKEY_NAME_LENGTH: Final[int] = 100
_MAX_USER_AGENT_LENGTH: Final[int] = 512
_EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+")
_DOMAIN_LABEL_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9-]+")
_ACCOUNT_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{32}")
_OPAQUE_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_-]{43}")
_RECOVERY_CODE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{32}")
_SESSION_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{32}")
_RATE_POLICIES: Final[tuple[tuple[str, int, int], ...]] = (
    ("global", 120, 5 * 60),
    ("ip", 30, 5 * 60),
    ("account", 15, 15 * 60),
    ("pair", 10, 15 * 60),
)
_PASSKEY_LOGIN_RATE_POLICIES: Final[tuple[tuple[str, int, int], ...]] = (
    ("global", 120, 5 * 60),
    ("ip", 30, 5 * 60),
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_metadata (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS auth_accounts (
    account_id TEXT PRIMARY KEY
        CHECK(length(account_id) = 32),
    canonical_email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL
        CHECK(role IN ('admin', 'user')),
    password_change_required INTEGER NOT NULL
        CHECK(password_change_required IN (0, 1)),
    enrollment_state TEXT NOT NULL
        CHECK(enrollment_state IN ('required', 'pending', 'active')),
    totp_nonce BLOB,
    totp_ciphertext BLOB,
    enrollment_challenge_digest BLOB
        CHECK(
            enrollment_challenge_digest IS NULL
            OR length(enrollment_challenge_digest) = 32
        ),
    totp_last_counter INTEGER NOT NULL DEFAULT -1
        CHECK(totp_last_counter >= -1),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK(
        (
            enrollment_state = 'required'
            AND totp_nonce IS NULL
            AND totp_ciphertext IS NULL
            AND enrollment_challenge_digest IS NULL
            AND totp_last_counter = -1
        )
        OR (
            enrollment_state = 'pending'
            AND length(totp_nonce) = 12
            AND totp_ciphertext IS NOT NULL
            AND length(enrollment_challenge_digest) = 32
        )
        OR (
            enrollment_state = 'active'
            AND length(totp_nonce) = 12
            AND totp_ciphertext IS NOT NULL
            AND enrollment_challenge_digest IS NULL
        )
    )
) STRICT;

CREATE TABLE IF NOT EXISTS auth_recovery_codes (
    account_id TEXT NOT NULL
        REFERENCES auth_accounts(account_id) ON DELETE CASCADE,
    code_digest BLOB NOT NULL
        CHECK(length(code_digest) = 32),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(account_id, code_digest)
) STRICT;

CREATE TABLE IF NOT EXISTS auth_pending_challenges (
    challenge_digest BLOB PRIMARY KEY
        CHECK(length(challenge_digest) = 32),
    account_id TEXT NOT NULL
        REFERENCES auth_accounts(account_id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    failure_count INTEGER NOT NULL DEFAULT 0
        CHECK(failure_count BETWEEN 0 AND 5)
) STRICT;

CREATE INDEX IF NOT EXISTS auth_pending_challenges_account_idx
    ON auth_pending_challenges(account_id, created_at);
CREATE INDEX IF NOT EXISTS auth_pending_challenges_expiry_idx
    ON auth_pending_challenges(expires_at);

CREATE TABLE IF NOT EXISTS auth_sessions (
    session_digest BLOB PRIMARY KEY
        CHECK(length(session_digest) = 32),
    account_id TEXT NOT NULL
        REFERENCES auth_accounts(account_id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    step_up_until INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX IF NOT EXISTS auth_sessions_account_idx
    ON auth_sessions(account_id, last_seen_at, created_at);
CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx
    ON auth_sessions(absolute_expires_at);

CREATE TABLE IF NOT EXISTS auth_login_rate_limits (
    scope TEXT NOT NULL
        CHECK(scope IN ('global', 'ip', 'account', 'pair')),
    identity_digest BLOB NOT NULL
        CHECK(length(identity_digest) = 32),
    account_id TEXT
        REFERENCES auth_accounts(account_id) ON DELETE CASCADE,
    account_identity_digest BLOB
        CHECK(
            account_identity_digest IS NULL
            OR length(account_identity_digest) = 32
        ),
    window_started_at INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL
        CHECK(attempt_count > 0),
    PRIMARY KEY(scope, identity_digest)
) STRICT;
"""

_PASSKEY_SCHEMA = """
CREATE UNIQUE INDEX IF NOT EXISTS auth_sessions_public_id_idx
    ON auth_sessions(session_id)
    WHERE session_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS auth_passkey_credentials (
    credential_id BLOB PRIMARY KEY
        CHECK(length(credential_id) BETWEEN 1 AND 1024),
    public_id TEXT NOT NULL UNIQUE
        CHECK(length(public_id) = 32),
    account_id TEXT NOT NULL
        REFERENCES auth_accounts(account_id) ON DELETE CASCADE,
    public_key BLOB NOT NULL
        CHECK(length(public_key) > 0),
    sign_count INTEGER NOT NULL
        CHECK(sign_count >= 0),
    name TEXT NOT NULL
        CHECK(length(name) BETWEEN 1 AND 100),
    device_type TEXT NOT NULL
        CHECK(device_type IN ('single_device', 'multi_device')),
    backed_up INTEGER NOT NULL
        CHECK(backed_up IN (0, 1)),
    transports TEXT,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS auth_passkey_credentials_account_idx
    ON auth_passkey_credentials(account_id, created_at, credential_id);

CREATE TABLE IF NOT EXISTS auth_passkey_challenges (
    challenge_digest BLOB PRIMARY KEY
        CHECK(length(challenge_digest) = 32),
    purpose TEXT NOT NULL
        CHECK(purpose IN ('registration', 'login', 'step_up')),
    account_id TEXT
        REFERENCES auth_accounts(account_id) ON DELETE CASCADE,
    session_digest BLOB
        REFERENCES auth_sessions(session_digest) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    failure_count INTEGER NOT NULL DEFAULT 0
        CHECK(failure_count BETWEEN 0 AND 5),
    CHECK(
        (purpose = 'login' AND account_id IS NULL AND session_digest IS NULL)
        OR (
            purpose IN ('registration', 'step_up')
            AND account_id IS NOT NULL
            AND session_digest IS NOT NULL
        )
    )
) STRICT;

CREATE INDEX IF NOT EXISTS auth_passkey_challenges_account_idx
    ON auth_passkey_challenges(account_id, created_at, challenge_digest);
CREATE INDEX IF NOT EXISTS auth_passkey_challenges_expiry_idx
    ON auth_passkey_challenges(expires_at);
"""


class Role(StrEnum):
    ADMIN = "admin"
    USER = "user"


class EnrollmentState(StrEnum):
    REQUIRED = "required"
    PENDING = "pending"
    ACTIVE = "active"


@dataclass(frozen=True, slots=True)
class Account:
    account_id: str
    email: str
    role: Role
    password_change_required: bool
    enrollment_state: EnrollmentState
    created_at: int
    updated_at: int


@dataclass(frozen=True, slots=True)
class TotpEnrollment:
    secret: str
    provisioning_uri: str


@dataclass(frozen=True, slots=True)
class AccountBootstrap:
    email: str
    role: Role | str
    totp_secret: str
    recovery_codes: tuple[str, ...]
    password_change_required: bool


@dataclass(frozen=True, slots=True)
class SessionPrincipal:
    account_id: str
    email: str
    role: Role
    password_change_required: bool
    enrollment_state: EnrollmentState
    created_at: int
    idle_expires_at: int
    absolute_expires_at: int
    step_up_until: int
    session_id: str | None = None
    client_ip: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True, slots=True)
class IssuedSession:
    token: str
    principal: SessionPrincipal


@dataclass(frozen=True, slots=True)
class VerifiedPasskeyIdentity:
    account_id: str
    email: str


@dataclass(frozen=True, slots=True)
class EnrollmentResult:
    session: IssuedSession
    recovery_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SessionInfo:
    session_id: str
    account_id: str
    created_at: int
    last_seen_at: int
    idle_expires_at: int
    absolute_expires_at: int
    step_up_until: int
    client_ip: str | None
    user_agent: str | None
    current: bool


@dataclass(frozen=True, slots=True)
class PasskeyCredential:
    public_id: str
    account_id: str
    name: str
    sign_count: int
    device_type: str
    backed_up: bool
    transports: tuple[str, ...]
    created_at: int
    last_used_at: int | None


@dataclass(frozen=True, slots=True)
class PasskeyCeremony:
    challenge_token: str
    options: dict[str, object]


class AuthenticationError(RuntimeError):
    """Base class for authentication-store failures."""


class DatabaseSecurityError(AuthenticationError):
    pass


class MasterKeyError(AuthenticationError):
    pass


class AccountExistsError(AuthenticationError):
    pass


class AccountNotFoundError(AuthenticationError):
    pass


class EnrollmentStateError(AuthenticationError):
    pass


class InvalidChallengeError(AuthenticationError):
    pass


class InvalidSecondFactorError(AuthenticationError):
    pass


class InvalidPasskeyError(InvalidSecondFactorError):
    pass


class StepUpRequiredError(InvalidSecondFactorError):
    pass


class InvalidSessionError(AuthenticationError):
    pass


class AuthenticationDataError(AuthenticationError):
    pass


class LoginRateLimitedError(AuthenticationError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("login rate limit exceeded")
        self.retry_after = max(1, retry_after)


class PasskeyLimitError(AuthenticationError):
    pass


def canonicalize_email(value: str) -> str:
    """Return the canonical ASCII mailbox identity used by the metadata store."""

    if not isinstance(value, str):
        raise ValueError("email identity must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > 254 or not normalized.isascii():
        raise ValueError("email identity must be a valid ASCII address")
    if normalized.count("@") != 1:
        raise ValueError("email identity must contain one at sign")
    local, domain = normalized.rsplit("@", 1)
    if (
        not local
        or len(local) > 64
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or _EMAIL_PATTERN.fullmatch(local) is None
    ):
        raise ValueError("email identity has an invalid local part")
    if not domain or len(domain) > 253 or domain.startswith(".") or domain.endswith("."):
        raise ValueError("email identity has an invalid domain")
    labels = domain.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or _DOMAIN_LABEL_PATTERN.fullmatch(label) is None
        for label in labels
    ):
        raise ValueError("email identity has an invalid domain")
    return f"{local.lower()}@{domain.lower()}"


def decode_totp_secret(value: str) -> bytes:
    """Decode an exact 20-byte Base32 TOTP secret."""

    if not isinstance(value, str) or not value:
        raise ValueError("TOTP secret must be Base32 text")
    normalized = "".join(value.upper().split())
    if not normalized.isascii() or len(normalized) != 32:
        raise ValueError("TOTP secret must encode exactly 20 bytes")
    try:
        decoded = base64.b32decode(normalized, casefold=False)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("TOTP secret must be valid Base32") from exc
    if len(decoded) != TOTP_SECRET_BYTES:
        raise ValueError("TOTP secret must encode exactly 20 bytes")
    return decoded


def totp_code(secret: str | bytes, *, timestamp: float | int | None = None) -> str:
    """Generate the RFC 6238 SHA-1, six-digit, 30-second TOTP value."""

    key = decode_totp_secret(secret) if isinstance(secret, str) else secret
    if not isinstance(key, bytes) or len(key) != TOTP_SECRET_BYTES:
        raise ValueError("TOTP key must contain exactly 20 bytes")
    moment = time.time() if timestamp is None else timestamp
    if not isinstance(moment, int | float) or not math.isfinite(moment) or moment < 0:
        raise ValueError("TOTP timestamp must be a finite non-negative number")
    return _totp_for_counter(key, int(moment // TOTP_PERIOD_SECONDS))


def totp_provisioning_uri(issuer: str, email: str, secret: str) -> str:
    """Build the canonical Google Authenticator-compatible provisioning URI."""

    normalized_issuer = _validate_issuer(issuer)
    canonical = canonicalize_email(email)
    normalized_secret = _encode_totp_secret(decode_totp_secret(secret))
    label = quote(f"{normalized_issuer}:{canonical}", safe="")
    query = urlencode(
        {
            "secret": normalized_secret,
            "issuer": normalized_issuer,
            "algorithm": "SHA1",
            "digits": "6",
            "period": str(TOTP_PERIOD_SECONDS),
        }
    )
    return f"otpauth://totp/{label}?{query}"


class AuthStore:
    """Own durable authentication metadata in a private SQLite database."""

    def __init__(
        self,
        db_path: str | Path,
        master_key: bytes,
        issuer: str,
        *,
        clock: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        webauthn_rp_id: str | None = None,
        webauthn_origin: str | None = None,
    ) -> None:
        if not isinstance(master_key, bytes) or len(master_key) != 32:
            raise ValueError("authentication master key must contain exactly 32 bytes")
        self.issuer = _validate_issuer(issuer)
        self.webauthn_rp_id, self.webauthn_origin = _validate_webauthn_configuration(
            webauthn_rp_id,
            webauthn_origin,
        )
        self._clock = clock
        self._random_bytes_source = random_bytes
        self._lock = threading.RLock()
        self._closed = False
        self._path = Path(db_path)
        if not self._path.is_absolute():
            raise ValueError("authentication database path must be absolute")
        _prepare_private_database(self._path)

        self._encryption_key = _derive_key(master_key, b"totp-encryption")
        self._challenge_digest_key = _derive_key(master_key, b"challenge-digest")
        self._passkey_challenge_digest_key = _derive_key(
            master_key,
            b"passkey-challenge-digest",
        )
        self._session_digest_key = _derive_key(master_key, b"session-digest")
        self._recovery_digest_key = _derive_key(master_key, b"recovery-digest")
        self._rate_digest_key = _derive_key(master_key, b"rate-digest")
        self._key_verifier = _derive_key(master_key, b"master-verifier")

        self._connection = sqlite3.connect(
            self._path,
            timeout=5.0,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._configure_connection()
            self._initialize_schema()
        except Exception:
            self._connection.close()
            self._closed = True
            raise

    def __enter__(self) -> AuthStore:
        self._require_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def create_account(
        self,
        email: str,
        *,
        role: Role | str = Role.USER,
        password_change_required: bool = True,
    ) -> Account:
        canonical = canonicalize_email(email)
        normalized_role = _coerce_role(role)
        required = _coerce_bool(password_change_required, "password_change_required")
        now = self._now()
        with self._transaction():
            if self._account_row_by_email_locked(canonical) is not None:
                raise AccountExistsError("account metadata already exists")
            account_id = self._new_account_id_locked()
            self._connection.execute(
                """
                INSERT INTO auth_accounts(
                    account_id, canonical_email, role, password_change_required,
                    enrollment_state, totp_nonce, totp_ciphertext,
                    totp_last_counter, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'required', NULL, NULL, -1, ?, ?)
                """,
                (account_id, canonical, normalized_role.value, int(required), now, now),
            )
            row = self._account_row_by_id_locked(account_id)
        return _account_from_row(_required_row(row))

    def get_account(self, email: str) -> Account | None:
        canonical = canonicalize_email(email)
        with self._lock:
            self._require_open()
            row = self._account_row_by_email_locked(canonical)
        return _account_from_row(row) if row is not None else None

    def resolve_account_id(self, account_id: str) -> Account:
        normalized = _validate_account_id(account_id)
        with self._lock:
            self._require_open()
            row = self._account_row_by_id_locked(normalized)
        if row is None:
            raise AccountNotFoundError("account metadata does not exist")
        return _account_from_row(row)

    def list_accounts(self) -> tuple[Account, ...]:
        with self._lock:
            self._require_open()
            rows = self._connection.execute(
                "SELECT * FROM auth_accounts ORDER BY canonical_email"
            ).fetchall()
        return tuple(_account_from_row(row) for row in rows)

    def sync_accounts(
        self,
        emails: Iterable[str],
        *,
        default_role: Role | str = Role.USER,
        password_change_required: bool = True,
    ) -> tuple[Account, ...]:
        canonical_emails = sorted({canonicalize_email(email) for email in emails})
        role = _coerce_role(default_role)
        required = _coerce_bool(password_change_required, "password_change_required")
        now = self._now()
        accounts: list[Account] = []
        with self._transaction():
            for canonical in canonical_emails:
                row = self._account_row_by_email_locked(canonical)
                if row is None:
                    account_id = self._new_account_id_locked()
                    self._connection.execute(
                        """
                        INSERT INTO auth_accounts(
                            account_id, canonical_email, role, password_change_required,
                            enrollment_state, totp_nonce, totp_ciphertext,
                            totp_last_counter, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, 'required', NULL, NULL, -1, ?, ?)
                        """,
                        (account_id, canonical, role.value, int(required), now, now),
                    )
                    row = self._account_row_by_id_locked(account_id)
                accounts.append(_account_from_row(_required_row(row)))
        return tuple(accounts)

    def set_role(
        self,
        account_id: str,
        role: Role | str,
        *,
        revoke_sessions: bool = True,
    ) -> Account:
        normalized_id = _validate_account_id(account_id)
        normalized_role = _coerce_role(role)
        now = self._now()
        with self._transaction():
            self._require_account_by_id_locked(normalized_id)
            self._connection.execute(
                "UPDATE auth_accounts SET role = ?, updated_at = ? WHERE account_id = ?",
                (normalized_role.value, now, normalized_id),
            )
            if revoke_sessions:
                self._revoke_account_authentication_locked(normalized_id)
            else:
                self._revoke_pending_challenges_locked(normalized_id)
            row = self._account_row_by_id_locked(normalized_id)
        return _account_from_row(_required_row(row))

    def set_password_change_required(
        self,
        account_id: str,
        required: bool,
        *,
        revoke_sessions: bool = True,
    ) -> Account:
        normalized_id = _validate_account_id(account_id)
        normalized_required = _coerce_bool(required, "required")
        now = self._now()
        with self._transaction():
            self._require_account_by_id_locked(normalized_id)
            self._connection.execute(
                """
                UPDATE auth_accounts
                SET password_change_required = ?, updated_at = ?
                WHERE account_id = ?
                """,
                (int(normalized_required), now, normalized_id),
            )
            if revoke_sessions:
                self._revoke_account_authentication_locked(normalized_id)
            else:
                self._revoke_pending_challenges_locked(normalized_id)
            row = self._account_row_by_id_locked(normalized_id)
        return _account_from_row(_required_row(row))

    def reset_totp(self, account_id: str) -> Account:
        normalized_id = _validate_account_id(account_id)
        now = self._now()
        with self._transaction():
            self._require_account_by_id_locked(normalized_id)
            self._connection.execute(
                """
                UPDATE auth_accounts
                SET enrollment_state = 'required',
                    totp_nonce = NULL,
                    totp_ciphertext = NULL,
                    enrollment_challenge_digest = NULL,
                    totp_last_counter = -1,
                    updated_at = ?
                WHERE account_id = ?
                """,
                (now, normalized_id),
            )
            self._connection.execute(
                "DELETE FROM auth_recovery_codes WHERE account_id = ?", (normalized_id,)
            )
            self._connection.execute(
                "DELETE FROM auth_pending_challenges WHERE account_id = ?", (normalized_id,)
            )
            self._connection.execute(
                "DELETE FROM auth_passkey_challenges WHERE account_id = ?", (normalized_id,)
            )
            self._connection.execute(
                "DELETE FROM auth_sessions WHERE account_id = ?", (normalized_id,)
            )
            row = self._account_row_by_id_locked(normalized_id)
        return _account_from_row(_required_row(row))

    def rotate_totp(
        self,
        account_id: str,
    ) -> tuple[TotpEnrollment, tuple[str, ...]]:
        """Replace an account's TOTP factor under a privileged helper workflow."""

        normalized_id = _validate_account_id(account_id)
        now = self._now()
        with self._transaction():
            row = self._require_account_by_id_locked(normalized_id)
            canonical = str(row["canonical_email"])
            secret_bytes = self._random_bytes(TOTP_SECRET_BYTES)
            secret = _encode_totp_secret(secret_bytes)
            nonce, ciphertext = self._encrypt_totp(normalized_id, canonical, secret_bytes)
            recovery_codes = self._generate_recovery_codes()
            self._connection.execute(
                """
                UPDATE auth_accounts
                SET enrollment_state = 'active',
                    totp_nonce = ?,
                    totp_ciphertext = ?,
                    enrollment_challenge_digest = NULL,
                    totp_last_counter = -1,
                    updated_at = ?
                WHERE account_id = ?
                """,
                (nonce, ciphertext, now, normalized_id),
            )
            self._connection.execute(
                "DELETE FROM auth_recovery_codes WHERE account_id = ?", (normalized_id,)
            )
            self._store_recovery_codes_locked(normalized_id, recovery_codes, now)
            self._connection.execute(
                "DELETE FROM auth_pending_challenges WHERE account_id = ?", (normalized_id,)
            )
            self._connection.execute(
                "DELETE FROM auth_passkey_challenges WHERE account_id = ?", (normalized_id,)
            )
            self._connection.execute(
                "DELETE FROM auth_sessions WHERE account_id = ?", (normalized_id,)
            )
        return self._enrollment(canonical, secret), recovery_codes

    def regenerate_recovery_codes(
        self,
        account_id: str,
        code: str,
    ) -> tuple[str, ...]:
        """Consume a fresh TOTP step and replace all recovery codes."""

        normalized_id = _validate_account_id(account_id)
        now = self._now()
        with self._transaction():
            row = self._require_account_by_id_locked(normalized_id)
            if not self._consume_totp_locked(row, code, now):
                raise InvalidSecondFactorError("second-factor verification failed")
            recovery_codes = self._generate_recovery_codes()
            self._connection.execute(
                "DELETE FROM auth_recovery_codes WHERE account_id = ?", (normalized_id,)
            )
            self._store_recovery_codes_locked(normalized_id, recovery_codes, now)
            self._connection.execute(
                "DELETE FROM auth_pending_challenges WHERE account_id = ?", (normalized_id,)
            )
            self._connection.execute(
                "DELETE FROM auth_passkey_challenges WHERE account_id = ?", (normalized_id,)
            )
            self._connection.execute(
                "DELETE FROM auth_sessions WHERE account_id = ?", (normalized_id,)
            )
        return recovery_codes

    def recovery_code_count(self, account_id: str) -> int:
        """Return the number of unused recovery codes for an active account."""

        normalized_id = _validate_account_id(account_id)
        with self._lock:
            self._require_open()
            self._require_account_by_id_locked(normalized_id)
            row = self._connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM auth_recovery_codes
                WHERE account_id = ?
                """,
                (normalized_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError("recovery code count query returned no row")
        return int(row["count"])

    def verify_totp(self, account_id: str, code: str) -> None:
        """Consume one current TOTP value without issuing a session."""

        normalized_id = _validate_account_id(account_id)
        now = self._now()
        with self._transaction():
            row = self._require_account_by_id_locked(normalized_id)
            if not self._consume_totp_locked(row, code, now):
                raise InvalidSecondFactorError("second-factor verification failed")

    def delete_account(self, account_id: str) -> None:
        """Delete only authentication metadata for an already-removed mailbox."""

        normalized_id = _validate_account_id(account_id)
        with self._transaction():
            row = self._require_account_by_id_locked(normalized_id)
            canonical = str(row["canonical_email"])
            account_digest = self._rate_digest(b"account", canonical.encode("ascii"))
            self._connection.execute(
                """
                DELETE FROM auth_login_rate_limits
                WHERE account_id = ?
                   OR account_identity_digest = ?
                """,
                (normalized_id, account_digest),
            )
            deleted = self._connection.execute(
                "DELETE FROM auth_accounts WHERE account_id = ?", (normalized_id,)
            )
            if deleted.rowcount != 1:
                raise AccountNotFoundError("account metadata does not exist")

    def provision_active_account(
        self,
        email: str,
        *,
        role: Role | str = Role.USER,
        password_change_required: bool = False,
    ) -> tuple[Account, TotpEnrollment, tuple[str, ...]]:
        canonical = canonicalize_email(email)
        normalized_role = _coerce_role(role)
        required = _coerce_bool(password_change_required, "password_change_required")
        now = self._now()
        with self._transaction():
            if self._account_row_by_email_locked(canonical) is not None:
                raise AccountExistsError("account metadata already exists")
            account_id = self._new_account_id_locked()
            secret_bytes = self._random_bytes(TOTP_SECRET_BYTES)
            secret = _encode_totp_secret(secret_bytes)
            nonce, ciphertext = self._encrypt_totp(account_id, canonical, secret_bytes)
            recovery_codes = self._generate_recovery_codes()
            self._connection.execute(
                """
                INSERT INTO auth_accounts(
                    account_id, canonical_email, role, password_change_required,
                    enrollment_state, totp_nonce, totp_ciphertext,
                    totp_last_counter, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'active', ?, ?, -1, ?, ?)
                """,
                (
                    account_id,
                    canonical,
                    normalized_role.value,
                    int(required),
                    nonce,
                    ciphertext,
                    now,
                    now,
                ),
            )
            self._store_recovery_codes_locked(account_id, recovery_codes, now)
            row = self._account_row_by_id_locked(account_id)
        account = _account_from_row(_required_row(row))
        return account, self._enrollment(canonical, secret), recovery_codes

    def bootstrap_active_account(
        self,
        email: str,
        *,
        role: Role | str,
        totp_secret: str,
        recovery_codes: Sequence[str],
        password_change_required: bool,
    ) -> Account:
        return self.bootstrap_active_accounts(
            (
                AccountBootstrap(
                    email=email,
                    role=role,
                    totp_secret=totp_secret,
                    recovery_codes=tuple(recovery_codes),
                    password_change_required=password_change_required,
                ),
            )
        )[0]

    def bootstrap_active_accounts(
        self,
        records: Iterable[AccountBootstrap],
    ) -> tuple[Account, ...]:
        """Atomically import a reviewed batch of active account factors."""

        prepared: list[tuple[str, Role, bytes, tuple[str, ...], bool]] = []
        seen: set[str] = set()
        for record in records:
            if not isinstance(record, AccountBootstrap):
                raise TypeError("bootstrap records must use AccountBootstrap")
            canonical = canonicalize_email(record.email)
            if canonical in seen:
                raise ValueError("bootstrap records contain a duplicate account")
            seen.add(canonical)
            prepared.append(
                (
                    canonical,
                    _coerce_role(record.role),
                    decode_totp_secret(record.totp_secret),
                    _validate_recovery_code_set(record.recovery_codes),
                    _coerce_bool(
                        record.password_change_required,
                        "password_change_required",
                    ),
                )
            )
        if not prepared:
            raise ValueError("bootstrap records must not be empty")

        now = self._now()
        imported: list[Account] = []
        with self._transaction():
            for canonical, role, secret_bytes, recovery_codes, required in prepared:
                existing = self._account_row_by_email_locked(canonical)
                if existing is None:
                    account_id = self._new_account_id_locked()
                    created_at = now
                else:
                    account_id = str(existing["account_id"])
                    created_at = int(existing["created_at"])
                nonce, ciphertext = self._encrypt_totp(
                    account_id,
                    canonical,
                    secret_bytes,
                )
                self._connection.execute(
                    """
                    INSERT INTO auth_accounts(
                        account_id, canonical_email, role, password_change_required,
                        enrollment_state, totp_nonce, totp_ciphertext,
                        totp_last_counter, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'active', ?, ?, -1, ?, ?)
                    ON CONFLICT(canonical_email) DO UPDATE SET
                        role = excluded.role,
                        password_change_required = excluded.password_change_required,
                        enrollment_state = 'active',
                        totp_nonce = excluded.totp_nonce,
                        totp_ciphertext = excluded.totp_ciphertext,
                        enrollment_challenge_digest = NULL,
                        totp_last_counter = -1,
                        updated_at = excluded.updated_at
                    """,
                    (
                        account_id,
                        canonical,
                        role.value,
                        int(required),
                        nonce,
                        ciphertext,
                        created_at,
                        now,
                    ),
                )
                self._connection.execute(
                    "DELETE FROM auth_recovery_codes WHERE account_id = ?",
                    (account_id,),
                )
                self._store_recovery_codes_locked(account_id, recovery_codes, now)
                self._connection.execute(
                    "DELETE FROM auth_pending_challenges WHERE account_id = ?",
                    (account_id,),
                )
                self._connection.execute(
                    "DELETE FROM auth_passkey_challenges WHERE account_id = ?",
                    (account_id,),
                )
                self._connection.execute(
                    "DELETE FROM auth_sessions WHERE account_id = ?",
                    (account_id,),
                )
                row = self._account_row_by_id_locked(account_id)
                imported.append(_account_from_row(_required_row(row)))
        return tuple(imported)

    def create_pending_challenge(self, email: str) -> str:
        canonical = canonicalize_email(email)
        now = self._now()
        with self._transaction():
            row = self._account_row_by_email_locked(canonical)
            if row is None:
                raise AccountNotFoundError("account metadata does not exist")
            account_id = str(row["account_id"])
            self._delete_expired_challenges_locked(now)
            challenge_count = int(
                self._connection.execute(
                    """
                    SELECT COUNT(*) FROM auth_pending_challenges
                    WHERE account_id = ?
                    """,
                    (account_id,),
                ).fetchone()[0]
            )
            if challenge_count >= _MAX_CHALLENGES_PER_ACCOUNT:
                remove_count = challenge_count - _MAX_CHALLENGES_PER_ACCOUNT + 1
                self._connection.execute(
                    """
                    DELETE FROM auth_pending_challenges
                    WHERE challenge_digest IN (
                        SELECT challenge_digest
                        FROM auth_pending_challenges
                        WHERE account_id = ?
                          AND challenge_digest NOT IN (
                              SELECT enrollment_challenge_digest
                              FROM auth_accounts
                              WHERE account_id = ?
                                AND enrollment_state = 'pending'
                                AND enrollment_challenge_digest IS NOT NULL
                          )
                        ORDER BY created_at, challenge_digest
                        LIMIT ?
                    )
                    """,
                    (account_id, account_id, remove_count),
                )
            token, digest = self._new_unique_token_locked(
                self._challenge_digest_key,
                table="auth_pending_challenges",
                digest_column="challenge_digest",
            )
            self._connection.execute(
                """
                INSERT INTO auth_pending_challenges(
                    challenge_digest, account_id, created_at, expires_at, failure_count
                ) VALUES (?, ?, ?, ?, 0)
                """,
                (digest, account_id, now, now + CHALLENGE_LIFETIME_SECONDS),
            )
        return token

    def begin_totp_enrollment(self, challenge_token: str) -> TotpEnrollment:
        digest = self._opaque_digest(self._challenge_digest_key, challenge_token)
        now = self._now()
        with self._transaction():
            challenge = self._challenge_row_locked(digest, now)
            state = EnrollmentState(str(challenge["enrollment_state"]))
            if state is EnrollmentState.ACTIVE:
                raise EnrollmentStateError("TOTP is already active")
            account_id = str(challenge["account_id"])
            canonical = str(challenge["canonical_email"])
            if state is EnrollmentState.PENDING:
                owner = challenge["enrollment_challenge_digest"]
                if not isinstance(owner, bytes) or len(owner) != 32:
                    raise AuthenticationDataError("TOTP enrollment owner is invalid")
                if not hmac.compare_digest(owner, digest):
                    raise EnrollmentStateError("TOTP enrollment belongs to another challenge")
                secret_bytes = self._decrypt_totp(challenge)
            else:
                secret_bytes = self._random_bytes(TOTP_SECRET_BYTES)
                nonce, ciphertext = self._encrypt_totp(account_id, canonical, secret_bytes)
                updated = self._connection.execute(
                    """
                    UPDATE auth_accounts
                    SET enrollment_state = 'pending',
                        totp_nonce = ?,
                        totp_ciphertext = ?,
                        enrollment_challenge_digest = ?,
                        totp_last_counter = -1,
                        updated_at = ?
                    WHERE account_id = ?
                      AND enrollment_state = 'required'
                    """,
                    (nonce, ciphertext, digest, now, account_id),
                )
                if updated.rowcount != 1:
                    raise EnrollmentStateError("TOTP enrollment state changed")
                self._connection.execute(
                    "DELETE FROM auth_recovery_codes WHERE account_id = ?", (account_id,)
                )
                self._connection.execute(
                    "DELETE FROM auth_passkey_challenges WHERE account_id = ?", (account_id,)
                )
                self._connection.execute(
                    "DELETE FROM auth_sessions WHERE account_id = ?", (account_id,)
                )
            secret = _encode_totp_secret(secret_bytes)
        return self._enrollment(canonical, secret)

    def confirm_totp_enrollment(
        self,
        challenge_token: str,
        code: str,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> EnrollmentResult:
        digest = self._opaque_digest(self._challenge_digest_key, challenge_token)
        now = self._now()
        failure = False
        result: EnrollmentResult | None = None
        with self._transaction():
            challenge = self._challenge_row_locked(digest, now)
            if EnrollmentState(str(challenge["enrollment_state"])) is not EnrollmentState.PENDING:
                raise EnrollmentStateError("TOTP enrollment is not pending")
            account_id = str(challenge["account_id"])
            owner = challenge["enrollment_challenge_digest"]
            if (
                not isinstance(owner, bytes)
                or len(owner) != 32
                or not hmac.compare_digest(owner, digest)
            ):
                raise EnrollmentStateError("TOTP enrollment belongs to another challenge")
            secret = self._decrypt_totp(challenge)
            matching_counter = _matching_totp_counter(secret, code, now)
            last_counter = int(challenge["totp_last_counter"])
            if matching_counter is None or matching_counter <= last_counter:
                self._record_challenge_failure_locked(digest, int(challenge["failure_count"]))
                failure = True
            else:
                updated = self._connection.execute(
                    """
                    UPDATE auth_accounts
                    SET enrollment_state = 'active',
                        enrollment_challenge_digest = NULL,
                        totp_last_counter = ?,
                        updated_at = ?
                    WHERE account_id = ?
                      AND enrollment_state = 'pending'
                      AND enrollment_challenge_digest = ?
                      AND totp_last_counter < ?
                    """,
                    (matching_counter, now, account_id, digest, matching_counter),
                )
                if updated.rowcount != 1:
                    self._record_challenge_failure_locked(digest, int(challenge["failure_count"]))
                    failure = True
                else:
                    recovery_codes = self._generate_recovery_codes()
                    self._store_recovery_codes_locked(account_id, recovery_codes, now)
                    self._connection.execute(
                        """
                        DELETE FROM auth_pending_challenges
                        WHERE account_id = ?
                        """,
                        (account_id,),
                    )
                    account_row = self._account_row_by_id_locked(account_id)
                    session = self._issue_session_locked(
                        _required_row(account_row),
                        now,
                        client_ip=client_ip,
                        user_agent=user_agent,
                    )
                    result = EnrollmentResult(
                        session=session,
                        recovery_codes=recovery_codes,
                    )
        if failure:
            raise InvalidSecondFactorError("second-factor verification failed")
        return _required_result(result)

    def complete_totp_challenge(
        self,
        challenge_token: str,
        code: str,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedSession:
        digest = self._opaque_digest(self._challenge_digest_key, challenge_token)
        now = self._now()
        failure = False
        issued: IssuedSession | None = None
        with self._transaction():
            challenge = self._challenge_row_locked(digest, now)
            if EnrollmentState(str(challenge["enrollment_state"])) is not EnrollmentState.ACTIVE:
                raise EnrollmentStateError("TOTP enrollment is not active")
            secret = self._decrypt_totp(challenge)
            matching_counter = _matching_totp_counter(secret, code, now)
            last_counter = int(challenge["totp_last_counter"])
            if matching_counter is None or matching_counter <= last_counter:
                self._record_challenge_failure_locked(digest, int(challenge["failure_count"]))
                failure = True
            else:
                account_id = str(challenge["account_id"])
                updated = self._connection.execute(
                    """
                    UPDATE auth_accounts
                    SET totp_last_counter = ?, updated_at = ?
                    WHERE account_id = ?
                      AND enrollment_state = 'active'
                      AND totp_last_counter < ?
                    """,
                    (matching_counter, now, account_id, matching_counter),
                )
                if updated.rowcount != 1:
                    self._record_challenge_failure_locked(digest, int(challenge["failure_count"]))
                    failure = True
                else:
                    self._connection.execute(
                        """
                        DELETE FROM auth_pending_challenges
                        WHERE challenge_digest = ?
                        """,
                        (digest,),
                    )
                    account_row = self._account_row_by_id_locked(account_id)
                    issued = self._issue_session_locked(
                        _required_row(account_row),
                        now,
                        client_ip=client_ip,
                        user_agent=user_agent,
                    )
        if failure:
            raise InvalidSecondFactorError("second-factor verification failed")
        return _required_session(issued)

    def complete_recovery_challenge(
        self,
        challenge_token: str,
        recovery_code: str,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedSession:
        digest = self._opaque_digest(self._challenge_digest_key, challenge_token)
        normalized_code = _normalize_recovery_code(recovery_code)
        now = self._now()
        failure = False
        issued: IssuedSession | None = None
        with self._transaction():
            challenge = self._challenge_row_locked(digest, now)
            if EnrollmentState(str(challenge["enrollment_state"])) is not EnrollmentState.ACTIVE:
                raise EnrollmentStateError("TOTP enrollment is not active")
            account_id = str(challenge["account_id"])
            code_digest = self._recovery_digest(account_id, normalized_code)
            consumed = self._connection.execute(
                """
                DELETE FROM auth_recovery_codes
                WHERE account_id = ? AND code_digest = ?
                """,
                (account_id, code_digest),
            )
            if consumed.rowcount != 1:
                self._record_challenge_failure_locked(digest, int(challenge["failure_count"]))
                failure = True
            else:
                self._connection.execute(
                    """
                    DELETE FROM auth_pending_challenges
                    WHERE account_id = ?
                    """,
                    (account_id,),
                )
                self._connection.execute(
                    "DELETE FROM auth_passkey_challenges WHERE account_id = ?",
                    (account_id,),
                )
                self._connection.execute(
                    """
                    DELETE FROM auth_sessions
                    WHERE account_id = ?
                    """,
                    (account_id,),
                )
                account_row = self._account_row_by_id_locked(account_id)
                issued = self._issue_session_locked(
                    _required_row(account_row),
                    now,
                    client_ip=client_ip,
                    user_agent=user_agent,
                )
        if failure:
            raise InvalidSecondFactorError("second-factor verification failed")
        return _required_session(issued)

    def authenticate_session(
        self,
        token: str,
        *,
        touch: bool = True,
    ) -> SessionPrincipal:
        digest = self._opaque_digest(self._session_digest_key, token)
        now = self._now()
        principal: SessionPrincipal | None = None
        with self._transaction():
            loaded = self._valid_session_row_locked(digest, now, touch=touch)
            if loaded is not None:
                row, effective_last_seen = loaded
                principal = _principal_from_session_row(row, effective_last_seen)
        if principal is None:
            raise InvalidSessionError("session is invalid")
        return principal

    def mark_step_up(self, session_token: str) -> SessionPrincipal:
        """Mark a valid session as helper-verified for five minutes."""

        digest = self._opaque_digest(self._session_digest_key, session_token)
        now = self._now()
        principal: SessionPrincipal | None = None
        with self._transaction():
            loaded = self._valid_session_row_locked(digest, now, touch=True)
            if loaded is not None:
                row, effective_last_seen = loaded
                step_up_until = min(
                    now + STEP_UP_SECONDS,
                    int(row["absolute_expires_at"]),
                )
                self._connection.execute(
                    """
                    UPDATE auth_sessions
                    SET step_up_until = ?
                    WHERE session_digest = ?
                    """,
                    (step_up_until, digest),
                )
                principal = _principal_from_session_row(
                    row,
                    effective_last_seen,
                    step_up_until=step_up_until,
                )
        if principal is None:
            raise InvalidSessionError("session is invalid")
        return principal

    def require_step_up(self, session_token: str) -> SessionPrincipal:
        """Return a valid principal only while its helper step-up is current."""

        digest = self._opaque_digest(self._session_digest_key, session_token)
        now = self._now()
        principal: SessionPrincipal | None = None
        step_up_missing = False
        with self._transaction():
            loaded = self._valid_session_row_locked(digest, now, touch=True)
            if loaded is not None:
                row, effective_last_seen = loaded
                if now >= int(row["step_up_until"]):
                    step_up_missing = True
                else:
                    principal = _principal_from_session_row(row, effective_last_seen)
        if principal is not None:
            return principal
        if step_up_missing:
            raise StepUpRequiredError("recent second-factor verification is required")
        raise InvalidSessionError("session is invalid")

    def revoke_session(self, token: str) -> bool:
        digest = self._opaque_digest(self._session_digest_key, token)
        with self._transaction():
            deleted = self._connection.execute(
                "DELETE FROM auth_sessions WHERE session_digest = ?", (digest,)
            )
        return deleted.rowcount == 1

    def list_sessions(
        self,
        account_id: str,
        *,
        current_session_token: str | None = None,
    ) -> tuple[SessionInfo, ...]:
        """List active sessions using non-secret public identifiers."""

        normalized_id = _validate_account_id(account_id)
        current_digest = (
            self._opaque_digest(self._session_digest_key, current_session_token)
            if current_session_token is not None
            else None
        )
        now = self._now()
        with self._transaction():
            self._require_account_by_id_locked(normalized_id)
            self._delete_expired_sessions_locked(now)
            rows = self._connection.execute(
                """
                SELECT
                    session_digest, session_id, account_id, created_at, last_seen_at,
                    absolute_expires_at, step_up_until, client_ip, user_agent
                FROM auth_sessions
                WHERE account_id = ?
                ORDER BY last_seen_at DESC, created_at DESC, session_id
                """,
                (normalized_id,),
            ).fetchall()
        return tuple(
            _session_info_from_row(
                row,
                current=(
                    current_digest is not None
                    and hmac.compare_digest(bytes(row["session_digest"]), current_digest)
                ),
            )
            for row in rows
        )

    def revoke_session_by_id(self, account_id: str, session_id: str) -> bool:
        """Revoke one account session without accepting or exposing its bearer token."""

        normalized_account_id = _validate_account_id(account_id)
        normalized_session_id = _validate_session_id(session_id)
        with self._transaction():
            self._require_account_by_id_locked(normalized_account_id)
            deleted = self._connection.execute(
                """
                DELETE FROM auth_sessions
                WHERE account_id = ? AND session_id = ?
                """,
                (normalized_account_id, normalized_session_id),
            )
        return deleted.rowcount == 1

    def revoke_sessions(self, account_id: str) -> int:
        """Revoke sessions and incomplete login challenges for one account."""

        normalized_id = _validate_account_id(account_id)
        with self._transaction():
            self._require_account_by_id_locked(normalized_id)
            session_count = self._revoke_account_authentication_locked(normalized_id)
        return session_count

    def begin_passkey_registration(self, session_token: str) -> PasskeyCeremony:
        """Begin a user-verified registration bound to one stepped-up session."""

        rp_id, _origin = self._require_passkey_configuration()
        session_digest = self._opaque_digest(self._session_digest_key, session_token)
        now = self._now()
        ceremony: PasskeyCeremony | None = None
        invalid_session = False
        step_up_missing = False
        with self._transaction():
            loaded = self._valid_session_row_locked(session_digest, now, touch=True)
            if loaded is None:
                invalid_session = True
            else:
                session_row, _effective_last_seen = loaded
                if now >= int(session_row["step_up_until"]):
                    step_up_missing = True
                else:
                    account_id = str(session_row["account_id"])
                    credentials = self._connection.execute(
                        """
                        SELECT credential_id
                        FROM auth_passkey_credentials
                        WHERE account_id = ?
                        ORDER BY created_at, credential_id
                        """,
                        (account_id,),
                    ).fetchall()
                    if len(credentials) >= MAX_PASSKEYS_PER_ACCOUNT:
                        raise PasskeyLimitError("passkey credential limit reached")
                    challenge, challenge_token = self._create_passkey_challenge_locked(
                        purpose="registration",
                        account_id=account_id,
                        session_digest=session_digest,
                        now=now,
                    )
                    options = generate_registration_options(
                        rp_id=rp_id,
                        rp_name=self.issuer,
                        user_id=bytes.fromhex(account_id),
                        user_name=str(session_row["canonical_email"]),
                        user_display_name=str(session_row["canonical_email"]),
                        challenge=challenge,
                        timeout=CHALLENGE_LIFETIME_SECONDS * 1000,
                        attestation=AttestationConveyancePreference.NONE,
                        authenticator_selection=AuthenticatorSelectionCriteria(
                            authenticator_attachment=None,
                            resident_key=ResidentKeyRequirement.REQUIRED,
                            require_resident_key=True,
                            user_verification=UserVerificationRequirement.REQUIRED,
                        ),
                        exclude_credentials=[
                            PublicKeyCredentialDescriptor(id=bytes(row["credential_id"]))
                            for row in credentials
                        ],
                    )
                    ceremony = PasskeyCeremony(
                        challenge_token=challenge_token,
                        options=_options_to_payload(options),
                    )
        if ceremony is not None:
            return ceremony
        if step_up_missing:
            raise StepUpRequiredError("recent second-factor verification is required")
        if invalid_session:
            raise InvalidSessionError("session is invalid")
        raise AuthenticationDataError("passkey registration challenge was not issued")

    def complete_passkey_registration(
        self,
        session_token: str,
        challenge_token: str,
        credential: object,
        *,
        name: str = "Passkey",
    ) -> PasskeyCredential:
        """Verify and store a passkey registration as one atomic operation."""

        rp_id, origin = self._require_passkey_configuration()
        normalized_name = _normalize_passkey_name(name)
        challenge = _decode_opaque_token(challenge_token)
        if challenge is None:
            raise InvalidChallengeError("passkey challenge is invalid")
        challenge_digest = self._passkey_challenge_digest(challenge)
        session_digest = self._opaque_digest(self._session_digest_key, session_token)
        now = self._now()
        result: PasskeyCredential | None = None
        invalid_session = False
        step_up_missing = False
        verification_failed = False
        with self._transaction():
            loaded = self._valid_session_row_locked(session_digest, now, touch=True)
            if loaded is None:
                invalid_session = True
            else:
                session_row, _effective_last_seen = loaded
                if now >= int(session_row["step_up_until"]):
                    step_up_missing = True
                else:
                    account_id = str(session_row["account_id"])
                    challenge_row = self._passkey_challenge_row_locked(
                        challenge_digest,
                        now,
                        purpose="registration",
                        account_id=account_id,
                        session_digest=session_digest,
                    )
                    credential_count = int(
                        self._connection.execute(
                            """
                            SELECT COUNT(*) FROM auth_passkey_credentials
                            WHERE account_id = ?
                            """,
                            (account_id,),
                        ).fetchone()[0]
                    )
                    if credential_count >= MAX_PASSKEYS_PER_ACCOUNT:
                        raise PasskeyLimitError("passkey credential limit reached")
                    try:
                        parsed = _parse_registration_credential(credential)
                        verified = verify_registration_response(
                            credential=parsed,
                            expected_challenge=challenge,
                            expected_rp_id=rp_id,
                            expected_origin=origin,
                            require_user_presence=True,
                            require_user_verification=True,
                        )
                        self._validate_registration_result(parsed, verified)
                    except TypeError, ValueError, WebAuthnException, InvalidPasskeyError:
                        self._record_passkey_challenge_failure_locked(
                            challenge_digest,
                            int(challenge_row["failure_count"]),
                        )
                        verification_failed = True
                    else:
                        transports = tuple(
                            transport.value for transport in (parsed.response.transports or [])
                        )
                        try:
                            self._connection.execute(
                                """
                                INSERT INTO auth_passkey_credentials(
                                    credential_id, public_id, account_id, public_key, sign_count,
                                    name, device_type, backed_up, transports,
                                    created_at, last_used_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                                """,
                                (
                                    verified.credential_id,
                                    self._new_passkey_public_id_locked(),
                                    account_id,
                                    verified.credential_public_key,
                                    verified.sign_count,
                                    normalized_name,
                                    verified.credential_device_type.value,
                                    int(verified.credential_backed_up),
                                    json.dumps(transports, separators=(",", ":")),
                                    now,
                                ),
                            )
                        except sqlite3.IntegrityError:
                            self._record_passkey_challenge_failure_locked(
                                challenge_digest,
                                int(challenge_row["failure_count"]),
                            )
                            verification_failed = True
                        else:
                            self._connection.execute(
                                """
                                DELETE FROM auth_passkey_challenges
                                WHERE challenge_digest = ?
                                """,
                                (challenge_digest,),
                            )
                            stored = self._passkey_credential_row_locked(
                                verified.credential_id,
                                account_id=account_id,
                            )
                            result = _passkey_credential_from_row(_required_row(stored))
        if result is not None:
            return result
        if step_up_missing:
            raise StepUpRequiredError("recent second-factor verification is required")
        if invalid_session:
            raise InvalidSessionError("session is invalid")
        if verification_failed:
            raise InvalidPasskeyError("passkey registration failed")
        raise AuthenticationDataError("passkey registration did not complete")

    def list_passkeys(self, account_id: str) -> tuple[PasskeyCredential, ...]:
        normalized_id = _validate_account_id(account_id)
        with self._transaction():
            self._require_account_by_id_locked(normalized_id)
            rows = self._connection.execute(
                """
                SELECT * FROM auth_passkey_credentials
                WHERE account_id = ?
                ORDER BY created_at, credential_id
                """,
                (normalized_id,),
            ).fetchall()
        return tuple(_passkey_credential_from_row(row) for row in rows)

    def delete_passkey(self, account_id: str, public_id: str) -> bool:
        normalized_account_id = _validate_account_id(account_id)
        normalized_public_id = _validate_passkey_public_id(public_id)
        with self._transaction():
            self._require_account_by_id_locked(normalized_account_id)
            deleted = self._connection.execute(
                """
                DELETE FROM auth_passkey_credentials
                WHERE account_id = ? AND public_id = ?
                """,
                (normalized_account_id, normalized_public_id),
            )
        return deleted.rowcount == 1

    def begin_passkey_login(self) -> PasskeyCeremony:
        """Begin an account-unbound, user-verified discoverable passkey login."""

        rp_id, _origin = self._require_passkey_configuration()
        now = self._now()
        with self._transaction():
            challenge, challenge_token = self._create_passkey_challenge_locked(
                purpose="login",
                account_id=None,
                session_digest=None,
                now=now,
            )
            options = generate_authentication_options(
                rp_id=rp_id,
                challenge=challenge,
                timeout=CHALLENGE_LIFETIME_SECONDS * 1000,
                allow_credentials=[],
                user_verification=UserVerificationRequirement.REQUIRED,
            )
        return PasskeyCeremony(
            challenge_token=challenge_token,
            options=_options_to_payload(options),
        )

    def complete_passkey_login(
        self,
        challenge_token: str,
        credential: object,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedSession:
        """Verify a discoverable assertion and issue one ordinary session."""

        identity = self.verify_passkey_login(challenge_token, credential)
        return self.issue_verified_passkey_session(
            identity,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def verify_passkey_login(
        self,
        challenge_token: str,
        credential: object,
    ) -> VerifiedPasskeyIdentity:
        """Verify a discoverable assertion without changing active sessions."""

        rp_id, origin = self._require_passkey_configuration()
        challenge = _decode_opaque_token(challenge_token)
        if challenge is None:
            raise InvalidChallengeError("passkey challenge is invalid")
        challenge_digest = self._passkey_challenge_digest(challenge)
        now = self._now()
        identity: VerifiedPasskeyIdentity | None = None
        verification_failed = False
        with self._transaction():
            challenge_row = self._passkey_challenge_row_locked(
                challenge_digest,
                now,
                purpose="login",
                account_id=None,
                session_digest=None,
            )
            try:
                parsed = _parse_authentication_credential(credential)
                credential_id = bytes(parsed.raw_id)
                if not 1 <= len(credential_id) <= _MAX_CREDENTIAL_ID_BYTES:
                    raise InvalidPasskeyError("passkey authentication failed")
                credential_row = self._passkey_credential_row_by_id_locked(credential_id)
                if credential_row is None:
                    raise InvalidPasskeyError("passkey authentication failed")
                account_id = str(credential_row["account_id"])
                user_handle = parsed.response.user_handle
                if user_handle is None or not hmac.compare_digest(
                    bytes(user_handle),
                    bytes.fromhex(account_id),
                ):
                    raise InvalidPasskeyError("passkey authentication failed")
                self._verify_passkey_assertion_locked(
                    parsed,
                    challenge=challenge,
                    account_id=account_id,
                    rp_id=rp_id,
                    origin=origin,
                    now=now,
                )
            except TypeError, ValueError, WebAuthnException, InvalidPasskeyError:
                self._record_passkey_challenge_failure_locked(
                    challenge_digest,
                    int(challenge_row["failure_count"]),
                )
                verification_failed = True
            else:
                self._connection.execute(
                    "DELETE FROM auth_passkey_challenges WHERE challenge_digest = ?",
                    (challenge_digest,),
                )
                account_row = _required_row(self._account_row_by_id_locked(account_id))
                identity = VerifiedPasskeyIdentity(
                    account_id=account_id,
                    email=str(account_row["canonical_email"]),
                )
        if identity is not None:
            return identity
        if verification_failed:
            raise InvalidPasskeyError("passkey authentication failed")
        raise AuthenticationDataError("passkey identity was not verified")

    def issue_verified_passkey_session(
        self,
        identity: VerifiedPasskeyIdentity,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedSession:
        """Issue a session after the caller validates the verified live identity."""

        if not isinstance(identity, VerifiedPasskeyIdentity):
            raise TypeError("verified passkey identity is required")
        account_id = _validate_account_id(identity.account_id)
        email = canonicalize_email(identity.email)
        now = self._now()
        issued: IssuedSession | None = None
        with self._transaction():
            account_row = self._account_row_by_id_locked(account_id)
            if account_row is None or str(account_row["canonical_email"]) != email:
                raise AccountNotFoundError(email)
            issued = self._issue_session_locked(
                account_row,
                now,
                client_ip=client_ip,
                user_agent=user_agent,
            )
        return _required_session(issued)

    def begin_passkey_step_up(self, session_token: str) -> PasskeyCeremony:
        """Begin a user-verified assertion bound to one valid session."""

        rp_id, _origin = self._require_passkey_configuration()
        session_digest = self._opaque_digest(self._session_digest_key, session_token)
        now = self._now()
        ceremony: PasskeyCeremony | None = None
        with self._transaction():
            loaded = self._valid_session_row_locked(session_digest, now, touch=True)
            if loaded is not None:
                session_row, _effective_last_seen = loaded
                account_id = str(session_row["account_id"])
                credentials = self._connection.execute(
                    """
                    SELECT credential_id FROM auth_passkey_credentials
                    WHERE account_id = ?
                    ORDER BY created_at, credential_id
                    """,
                    (account_id,),
                ).fetchall()
                if not credentials:
                    raise InvalidPasskeyError("account has no registered passkey")
                challenge, challenge_token = self._create_passkey_challenge_locked(
                    purpose="step_up",
                    account_id=account_id,
                    session_digest=session_digest,
                    now=now,
                )
                options = generate_authentication_options(
                    rp_id=rp_id,
                    challenge=challenge,
                    timeout=CHALLENGE_LIFETIME_SECONDS * 1000,
                    allow_credentials=[
                        PublicKeyCredentialDescriptor(id=bytes(row["credential_id"]))
                        for row in credentials
                    ],
                    user_verification=UserVerificationRequirement.REQUIRED,
                )
                ceremony = PasskeyCeremony(
                    challenge_token=challenge_token,
                    options=_options_to_payload(options),
                )
        if ceremony is None:
            raise InvalidSessionError("session is invalid")
        return ceremony

    def complete_passkey_step_up(
        self,
        session_token: str,
        challenge_token: str,
        credential: object,
    ) -> SessionPrincipal:
        """Verify a session-bound assertion and grant five minutes of step-up."""

        rp_id, origin = self._require_passkey_configuration()
        challenge = _decode_opaque_token(challenge_token)
        if challenge is None:
            raise InvalidChallengeError("passkey challenge is invalid")
        challenge_digest = self._passkey_challenge_digest(challenge)
        session_digest = self._opaque_digest(self._session_digest_key, session_token)
        now = self._now()
        principal: SessionPrincipal | None = None
        invalid_session = False
        verification_failed = False
        with self._transaction():
            loaded = self._valid_session_row_locked(session_digest, now, touch=True)
            if loaded is None:
                invalid_session = True
            else:
                session_row, effective_last_seen = loaded
                account_id = str(session_row["account_id"])
                challenge_row = self._passkey_challenge_row_locked(
                    challenge_digest,
                    now,
                    purpose="step_up",
                    account_id=account_id,
                    session_digest=session_digest,
                )
                try:
                    self._verify_passkey_assertion_locked(
                        credential,
                        challenge=challenge,
                        account_id=account_id,
                        rp_id=rp_id,
                        origin=origin,
                        now=now,
                    )
                except TypeError, ValueError, WebAuthnException, InvalidPasskeyError:
                    self._record_passkey_challenge_failure_locked(
                        challenge_digest,
                        int(challenge_row["failure_count"]),
                    )
                    verification_failed = True
                else:
                    step_up_until = min(
                        now + STEP_UP_SECONDS,
                        int(session_row["absolute_expires_at"]),
                    )
                    self._connection.execute(
                        """
                        UPDATE auth_sessions
                        SET step_up_until = ?
                        WHERE session_digest = ?
                        """,
                        (step_up_until, session_digest),
                    )
                    self._connection.execute(
                        "DELETE FROM auth_passkey_challenges WHERE challenge_digest = ?",
                        (challenge_digest,),
                    )
                    principal = _principal_from_session_row(
                        session_row,
                        effective_last_seen,
                        step_up_until=step_up_until,
                    )
        if principal is not None:
            return principal
        if invalid_session:
            raise InvalidSessionError("session is invalid")
        if verification_failed:
            raise InvalidPasskeyError("passkey authentication failed")
        raise AuthenticationDataError("passkey step-up did not complete")

    def check_login_rate(self, email: str, client_ip: str) -> None:
        """Atomically reserve one login attempt or raise with a retry delay."""

        canonical = canonicalize_email(email)
        normalized_ip = _canonical_ip(client_ip)
        now = self._now()
        identities = self._rate_identities(canonical, normalized_ip)
        retry_after = 0
        with self._transaction():
            account_row = self._account_row_by_email_locked(canonical)
            account_id = str(account_row["account_id"]) if account_row is not None else None
            for scope, _limit, window_seconds in _RATE_POLICIES:
                self._connection.execute(
                    """
                    DELETE FROM auth_login_rate_limits
                    WHERE scope = ?
                      AND window_started_at <= ?
                    """,
                    (scope, now - window_seconds),
                )
            retained_rows = int(
                self._connection.execute("SELECT COUNT(*) FROM auth_login_rate_limits").fetchone()[
                    0
                ]
            )
            if retained_rows > _MAX_RATE_LIMIT_ROWS:
                self._connection.execute(
                    """
                    DELETE FROM auth_login_rate_limits
                    WHERE rowid IN (
                        SELECT rowid
                        FROM auth_login_rate_limits
                        ORDER BY (scope = 'global'), window_started_at, rowid
                        LIMIT ?
                    )
                    """,
                    (retained_rows - _MAX_RATE_LIMIT_ROWS,),
                )
                retry_after = max(window for _scope, _limit, window in _RATE_POLICIES)
            rows_by_scope: dict[str, sqlite3.Row | None] = {}
            for scope, limit, window_seconds in _RATE_POLICIES:
                digest = identities[scope]
                row = self._connection.execute(
                    """
                    SELECT window_started_at, attempt_count
                    FROM auth_login_rate_limits
                    WHERE scope = ? AND identity_digest = ?
                    """,
                    (scope, digest),
                ).fetchone()
                rows_by_scope[scope] = row
                if row is None:
                    continue
                window_started = int(row["window_started_at"])
                count = int(row["attempt_count"])
                elapsed = max(0, now - window_started)
                if count >= limit:
                    retry_after = max(retry_after, window_seconds - elapsed)
            if retry_after == 0:
                current_rows = int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM auth_login_rate_limits"
                    ).fetchone()[0]
                )
                new_rows = sum(row is None for row in rows_by_scope.values())
                if current_rows + new_rows > _MAX_RATE_LIMIT_ROWS:
                    retry_after = max(window for _scope, _limit, window in _RATE_POLICIES)
            if retry_after == 0:
                for scope, _limit, _window_seconds in _RATE_POLICIES:
                    digest = identities[scope]
                    linked_account_id = account_id if scope in {"account", "pair"} else None
                    self._connection.execute(
                        """
                        INSERT INTO auth_login_rate_limits(
                            scope, identity_digest, account_id, account_identity_digest,
                            window_started_at, attempt_count
                        ) VALUES (?, ?, ?, ?, ?, 1)
                        ON CONFLICT(scope, identity_digest) DO UPDATE SET
                            account_id = COALESCE(
                                excluded.account_id,
                                auth_login_rate_limits.account_id
                            ),
                            account_identity_digest = COALESCE(
                                excluded.account_identity_digest,
                                auth_login_rate_limits.account_identity_digest
                            ),
                            attempt_count = auth_login_rate_limits.attempt_count + 1
                        """,
                        (
                            scope,
                            digest,
                            linked_account_id,
                            (identities["account"] if scope in {"account", "pair"} else None),
                            now,
                        ),
                    )
        if retry_after:
            raise LoginRateLimitedError(retry_after)

    def record_login_result(
        self,
        email: str,
        client_ip: str,
        *,
        success: bool,
    ) -> None:
        """Record completion; a full success clears only the account/IP bucket."""

        if not isinstance(success, bool):
            raise ValueError("success must be a boolean")
        canonical = canonicalize_email(email)
        normalized_ip = _canonical_ip(client_ip)
        if not success:
            return
        pair_digest = self._rate_identities(canonical, normalized_ip)["pair"]
        with self._transaction():
            self._connection.execute(
                """
                DELETE FROM auth_login_rate_limits
                WHERE scope = 'pair' AND identity_digest = ?
                """,
                (pair_digest,),
            )

    def check_passkey_login_rate(self, client_ip: str) -> None:
        """Reserve one account-unbound passkey attempt for the global and IP buckets."""

        normalized_ip = _canonical_ip(client_ip)
        now = self._now()
        identities = self._passkey_login_rate_identities(normalized_ip)
        retry_after = 0
        with self._transaction():
            for scope, _limit, window_seconds in _PASSKEY_LOGIN_RATE_POLICIES:
                self._connection.execute(
                    """
                    DELETE FROM auth_login_rate_limits
                    WHERE scope = ? AND window_started_at <= ?
                    """,
                    (scope, now - window_seconds),
                )
            retained_rows = int(
                self._connection.execute("SELECT COUNT(*) FROM auth_login_rate_limits").fetchone()[
                    0
                ]
            )
            if retained_rows > _MAX_RATE_LIMIT_ROWS:
                self._connection.execute(
                    """
                    DELETE FROM auth_login_rate_limits
                    WHERE rowid IN (
                        SELECT rowid
                        FROM auth_login_rate_limits
                        ORDER BY (scope = 'global'), window_started_at, rowid
                        LIMIT ?
                    )
                    """,
                    (retained_rows - _MAX_RATE_LIMIT_ROWS,),
                )
                retry_after = max(window for _scope, _limit, window in _PASSKEY_LOGIN_RATE_POLICIES)
            rows_by_scope: dict[str, sqlite3.Row | None] = {}
            for scope, limit, window_seconds in _PASSKEY_LOGIN_RATE_POLICIES:
                row = self._connection.execute(
                    """
                    SELECT window_started_at, attempt_count
                    FROM auth_login_rate_limits
                    WHERE scope = ? AND identity_digest = ?
                    """,
                    (scope, identities[scope]),
                ).fetchone()
                rows_by_scope[scope] = row
                if row is None:
                    continue
                elapsed = max(0, now - int(row["window_started_at"]))
                if int(row["attempt_count"]) >= limit:
                    retry_after = max(retry_after, window_seconds - elapsed)
            if retry_after == 0:
                current_rows = int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM auth_login_rate_limits"
                    ).fetchone()[0]
                )
                if current_rows + sum(row is None for row in rows_by_scope.values()) > (
                    _MAX_RATE_LIMIT_ROWS
                ):
                    retry_after = max(
                        window for _scope, _limit, window in _PASSKEY_LOGIN_RATE_POLICIES
                    )
            if retry_after == 0:
                for scope, _limit, _window_seconds in _PASSKEY_LOGIN_RATE_POLICIES:
                    self._connection.execute(
                        """
                        INSERT INTO auth_login_rate_limits(
                            scope, identity_digest, account_id, account_identity_digest,
                            window_started_at, attempt_count
                        ) VALUES (?, ?, NULL, NULL, ?, 1)
                        ON CONFLICT(scope, identity_digest) DO UPDATE SET
                            attempt_count = auth_login_rate_limits.attempt_count + 1
                        """,
                        (scope, identities[scope], now),
                    )
        if retry_after:
            raise LoginRateLimitedError(retry_after)

    def record_passkey_login_result(self, client_ip: str, *, success: bool) -> None:
        """Clear only the account-unbound IP bucket after a completed login."""

        if not isinstance(success, bool):
            raise ValueError("success must be a boolean")
        normalized_ip = _canonical_ip(client_ip)
        if not success:
            return
        digest = self._passkey_login_rate_identities(normalized_ip)["ip"]
        with self._transaction():
            self._connection.execute(
                """
                DELETE FROM auth_login_rate_limits
                WHERE scope = 'ip' AND identity_digest = ?
                """,
                (digest,),
            )

    def _configure_connection(self) -> None:
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA trusted_schema = OFF")
        self._connection.execute("PRAGMA secure_delete = ON")
        self._connection.execute("PRAGMA journal_mode = DELETE")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.execute("PRAGMA busy_timeout = 5000")

    def _initialize_schema(self) -> None:
        enrollment_owner_added = False
        with self._lock:
            self._require_open()
            self._connection.executescript(_SCHEMA)
            account_columns = {
                str(row["name"])
                for row in self._connection.execute("PRAGMA table_info(auth_accounts)").fetchall()
            }
            if "enrollment_challenge_digest" not in account_columns:
                self._connection.execute(
                    """
                    ALTER TABLE auth_accounts
                    ADD COLUMN enrollment_challenge_digest BLOB
                        CHECK(
                            enrollment_challenge_digest IS NULL
                            OR length(enrollment_challenge_digest) = 32
                        )
                    """
                )
                enrollment_owner_added = True
            session_columns = {
                str(row["name"])
                for row in self._connection.execute("PRAGMA table_info(auth_sessions)").fetchall()
            }
            if "step_up_until" not in session_columns:
                self._connection.execute(
                    """
                    ALTER TABLE auth_sessions
                    ADD COLUMN step_up_until INTEGER NOT NULL DEFAULT 0
                    """
                )
            if "session_id" not in session_columns:
                self._connection.execute(
                    """
                    ALTER TABLE auth_sessions
                    ADD COLUMN session_id TEXT
                        CHECK(session_id IS NULL OR length(session_id) = 32)
                    """
                )
            if "client_ip" not in session_columns:
                self._connection.execute(
                    """
                    ALTER TABLE auth_sessions
                    ADD COLUMN client_ip TEXT
                    """
                )
            if "user_agent" not in session_columns:
                self._connection.execute(
                    """
                    ALTER TABLE auth_sessions
                    ADD COLUMN user_agent TEXT
                        CHECK(user_agent IS NULL OR length(user_agent) <= 512)
                    """
                )
            rate_columns = {
                str(row["name"])
                for row in self._connection.execute(
                    "PRAGMA table_info(auth_login_rate_limits)"
                ).fetchall()
            }
            if "account_id" not in rate_columns:
                self._connection.execute(
                    """
                    ALTER TABLE auth_login_rate_limits
                    ADD COLUMN account_id TEXT
                        REFERENCES auth_accounts(account_id) ON DELETE CASCADE
                    """
                )
            if "account_identity_digest" not in rate_columns:
                self._connection.execute(
                    """
                    ALTER TABLE auth_login_rate_limits
                    ADD COLUMN account_identity_digest BLOB
                        CHECK(
                            account_identity_digest IS NULL
                            OR length(account_identity_digest) = 32
                        )
                    """
                )
            self._connection.executescript(_PASSKEY_SCHEMA)
        with self._transaction():
            version = self._connection.execute(
                "SELECT value FROM auth_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version is None:
                self._connection.execute(
                    "INSERT INTO auth_metadata(key, value) VALUES ('schema_version', ?)",
                    (str(_SCHEMA_VERSION).encode("ascii"),),
                )
                stored_version = _SCHEMA_VERSION
            else:
                try:
                    stored_version = int(bytes(version["value"]).decode("ascii"))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise AuthenticationDataError("invalid authentication schema version") from exc
                if not 1 <= stored_version <= _SCHEMA_VERSION:
                    raise AuthenticationDataError("unsupported authentication schema version")
            if stored_version < 4 or enrollment_owner_added:
                self._connection.execute(
                    """
                    DELETE FROM auth_recovery_codes
                    WHERE account_id IN (
                        SELECT account_id
                        FROM auth_accounts
                        WHERE enrollment_state = 'pending'
                    )
                    """
                )
                self._connection.execute(
                    """
                    DELETE FROM auth_sessions
                    WHERE account_id IN (
                        SELECT account_id
                        FROM auth_accounts
                        WHERE enrollment_state = 'pending'
                    )
                    """
                )
                self._connection.execute(
                    """
                    DELETE FROM auth_pending_challenges
                    WHERE account_id IN (
                        SELECT account_id
                        FROM auth_accounts
                        WHERE enrollment_state = 'pending'
                    )
                    """
                )
                self._connection.execute(
                    """
                    UPDATE auth_accounts
                    SET enrollment_state = 'required',
                        totp_nonce = NULL,
                        totp_ciphertext = NULL,
                        enrollment_challenge_digest = NULL,
                        totp_last_counter = -1
                    WHERE enrollment_state = 'pending'
                    """
                )
            invalid_owner = self._connection.execute(
                """
                SELECT 1
                FROM auth_accounts
                WHERE (
                    enrollment_state = 'pending'
                    AND (
                        enrollment_challenge_digest IS NULL
                        OR length(enrollment_challenge_digest) != 32
                    )
                )
                OR (
                    enrollment_state != 'pending'
                    AND enrollment_challenge_digest IS NOT NULL
                )
                LIMIT 1
                """
            ).fetchone()
            if invalid_owner is not None:
                raise AuthenticationDataError("invalid TOTP enrollment ownership state")
            if stored_version != _SCHEMA_VERSION:
                self._connection.execute(
                    """
                    UPDATE auth_metadata
                    SET value = ?
                    WHERE key = 'schema_version'
                    """,
                    (str(_SCHEMA_VERSION).encode("ascii"),),
                )
            extension = self._connection.execute(
                "SELECT value FROM auth_metadata WHERE key = ?",
                (_PASSKEY_SESSION_EXTENSION_KEY,),
            ).fetchone()
            if extension is None:
                migration_now = self._now()
                self._connection.execute(
                    """
                    DELETE FROM auth_sessions
                    WHERE absolute_expires_at <= ?
                       OR last_seen_at + ? <= ?
                    """,
                    (migration_now, _LEGACY_SESSION_IDLE_SECONDS, migration_now),
                )
                self._connection.execute(
                    "INSERT INTO auth_metadata(key, value) VALUES (?, ?)",
                    (
                        _PASSKEY_SESSION_EXTENSION_KEY,
                        str(_PASSKEY_SESSION_EXTENSION_VERSION).encode("ascii"),
                    ),
                )
            else:
                try:
                    extension_version = int(bytes(extension["value"]).decode("ascii"))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise AuthenticationDataError(
                        "invalid passkey/session extension schema version"
                    ) from exc
                if extension_version != _PASSKEY_SESSION_EXTENSION_VERSION:
                    raise AuthenticationDataError(
                        "unsupported passkey/session extension schema version"
                    )
            legacy_sessions = self._connection.execute(
                "SELECT session_digest FROM auth_sessions WHERE session_id IS NULL"
            ).fetchall()
            for legacy_session in legacy_sessions:
                self._connection.execute(
                    "UPDATE auth_sessions SET session_id = ? WHERE session_digest = ?",
                    (
                        self._new_session_id_locked(),
                        bytes(legacy_session["session_digest"]),
                    ),
                )
            verifier = self._connection.execute(
                "SELECT value FROM auth_metadata WHERE key = 'master_key_verifier'"
            ).fetchone()
            if verifier is None:
                self._connection.execute(
                    """
                    INSERT INTO auth_metadata(key, value)
                    VALUES ('master_key_verifier', ?)
                    """,
                    (self._key_verifier,),
                )
            elif not hmac.compare_digest(bytes(verifier["value"]), self._key_verifier):
                raise MasterKeyError("authentication master key does not match the database")

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._require_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("authentication store is closed")

    def _now(self) -> int:
        value = self._clock()
        if not isinstance(value, int | float) or not math.isfinite(value) or value < 0:
            raise ValueError("authentication clock must return a finite non-negative value")
        return int(value)

    def _random_bytes(self, length: int) -> bytes:
        value = self._random_bytes_source(length)
        if not isinstance(value, bytes) or len(value) != length:
            raise ValueError("random byte source returned an invalid value")
        return value

    def _new_account_id_locked(self) -> str:
        for _ in range(8):
            account_id = self._random_bytes(_ACCOUNT_ID_BYTES).hex()
            exists = self._connection.execute(
                "SELECT 1 FROM auth_accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
            if exists is None:
                return account_id
        raise AuthenticationError("unable to allocate a unique account identifier")

    def _new_session_id_locked(self) -> str:
        for _ in range(8):
            session_id = self._random_bytes(_SESSION_ID_BYTES).hex()
            exists = self._connection.execute(
                "SELECT 1 FROM auth_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if exists is None:
                return session_id
        raise AuthenticationError("unable to allocate a unique session identifier")

    def _new_passkey_public_id_locked(self) -> str:
        for _ in range(8):
            public_id = self._random_bytes(_SESSION_ID_BYTES).hex()
            exists = self._connection.execute(
                "SELECT 1 FROM auth_passkey_credentials WHERE public_id = ?",
                (public_id,),
            ).fetchone()
            if exists is None:
                return public_id
        raise AuthenticationError("unable to allocate a unique passkey identifier")

    def _require_passkey_configuration(self) -> tuple[str, str]:
        if self.webauthn_rp_id is None or self.webauthn_origin is None:
            raise AuthenticationError("passkey authentication is not configured")
        return self.webauthn_rp_id, self.webauthn_origin

    def _passkey_challenge_digest(self, challenge: bytes) -> bytes:
        return hmac.digest(self._passkey_challenge_digest_key, challenge, "sha256")

    def _create_passkey_challenge_locked(
        self,
        *,
        purpose: str,
        account_id: str | None,
        session_digest: bytes | None,
        now: int,
    ) -> tuple[bytes, str]:
        self._delete_expired_passkey_challenges_locked(now)
        if purpose == "login":
            if account_id is not None or session_digest is not None:
                raise ValueError("login passkey challenges must not bind an account or session")
            challenge_count = int(
                self._connection.execute(
                    """
                    SELECT COUNT(*) FROM auth_passkey_challenges
                    WHERE purpose = 'login'
                    """
                ).fetchone()[0]
            )
            if challenge_count >= _MAX_ANONYMOUS_PASSKEY_LOGIN_CHALLENGES:
                remove_count = challenge_count - _MAX_ANONYMOUS_PASSKEY_LOGIN_CHALLENGES + 1
                self._connection.execute(
                    """
                    DELETE FROM auth_passkey_challenges
                    WHERE challenge_digest IN (
                        SELECT challenge_digest
                        FROM auth_passkey_challenges
                        WHERE purpose = 'login'
                        ORDER BY created_at, challenge_digest
                        LIMIT ?
                    )
                    """,
                    (remove_count,),
                )
        else:
            if purpose not in {"registration", "step_up"}:
                raise ValueError("invalid passkey challenge purpose")
            if account_id is None or session_digest is None:
                raise ValueError("authenticated passkey challenges require an account and session")
            challenge_count = int(
                self._connection.execute(
                    """
                    SELECT COUNT(*) FROM auth_passkey_challenges
                    WHERE purpose != 'login' AND account_id = ?
                    """,
                    (account_id,),
                ).fetchone()[0]
            )
            if challenge_count >= _MAX_PASSKEY_CHALLENGES_PER_ACCOUNT:
                remove_count = challenge_count - _MAX_PASSKEY_CHALLENGES_PER_ACCOUNT + 1
                self._connection.execute(
                    """
                    DELETE FROM auth_passkey_challenges
                    WHERE challenge_digest IN (
                        SELECT challenge_digest
                        FROM auth_passkey_challenges
                        WHERE purpose != 'login' AND account_id = ?
                        ORDER BY created_at, challenge_digest
                        LIMIT ?
                    )
                    """,
                    (account_id, remove_count),
                )
        for _ in range(8):
            challenge = self._random_bytes(_TOKEN_BYTES)
            challenge_digest = self._passkey_challenge_digest(challenge)
            exists = self._connection.execute(
                """
                SELECT 1 FROM auth_passkey_challenges
                WHERE challenge_digest = ?
                """,
                (challenge_digest,),
            ).fetchone()
            if exists is not None:
                continue
            self._connection.execute(
                """
                INSERT INTO auth_passkey_challenges(
                    challenge_digest, purpose, account_id, session_digest,
                    created_at, expires_at, failure_count
                ) VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    challenge_digest,
                    purpose,
                    account_id,
                    session_digest,
                    now,
                    now + CHALLENGE_LIFETIME_SECONDS,
                ),
            )
            return challenge, _encode_opaque_token(challenge)
        raise AuthenticationError("unable to allocate a unique passkey challenge")

    def _passkey_challenge_row_locked(
        self,
        challenge_digest: bytes,
        now: int,
        *,
        purpose: str,
        account_id: str | None,
        session_digest: bytes | None,
    ) -> sqlite3.Row:
        row = self._connection.execute(
            """
            SELECT * FROM auth_passkey_challenges
            WHERE challenge_digest = ?
            """,
            (challenge_digest,),
        ).fetchone()
        if row is None or now >= int(row["expires_at"]):
            raise InvalidChallengeError("passkey challenge is invalid")
        if not hmac.compare_digest(str(row["purpose"]), purpose):
            raise InvalidChallengeError("passkey challenge is invalid")
        stored_account_id = row["account_id"]
        if account_id is None:
            if stored_account_id is not None:
                raise InvalidChallengeError("passkey challenge is invalid")
        elif not isinstance(stored_account_id, str) or not hmac.compare_digest(
            stored_account_id,
            account_id,
        ):
            raise InvalidChallengeError("passkey challenge is invalid")
        stored_session_digest = row["session_digest"]
        if session_digest is None:
            if stored_session_digest is not None:
                raise InvalidChallengeError("passkey challenge is invalid")
        elif not isinstance(stored_session_digest, bytes) or not hmac.compare_digest(
            stored_session_digest,
            session_digest,
        ):
            raise InvalidChallengeError("passkey challenge is invalid")
        return row

    def _record_passkey_challenge_failure_locked(
        self,
        challenge_digest: bytes,
        failure_count: int,
    ) -> None:
        next_count = failure_count + 1
        if next_count >= CHALLENGE_FAILURE_LIMIT:
            self._connection.execute(
                "DELETE FROM auth_passkey_challenges WHERE challenge_digest = ?",
                (challenge_digest,),
            )
        else:
            self._connection.execute(
                """
                UPDATE auth_passkey_challenges
                SET failure_count = ?
                WHERE challenge_digest = ?
                """,
                (next_count, challenge_digest),
            )

    def _delete_expired_passkey_challenges_locked(self, now: int) -> None:
        self._connection.execute(
            "DELETE FROM auth_passkey_challenges WHERE expires_at <= ?",
            (now,),
        )

    def _passkey_credential_row_locked(
        self,
        credential_id: bytes,
        *,
        account_id: str,
    ) -> sqlite3.Row | None:
        return self._connection.execute(
            """
            SELECT * FROM auth_passkey_credentials
            WHERE credential_id = ? AND account_id = ?
            """,
            (credential_id, account_id),
        ).fetchone()

    def _passkey_credential_row_by_id_locked(
        self,
        credential_id: bytes,
    ) -> sqlite3.Row | None:
        return self._connection.execute(
            """
            SELECT * FROM auth_passkey_credentials
            WHERE credential_id = ?
            """,
            (credential_id,),
        ).fetchone()

    @staticmethod
    def _validate_registration_result(
        credential: RegistrationCredential,
        verified: VerifiedRegistration,
    ) -> None:
        credential_id = bytes(verified.credential_id)
        public_key = bytes(verified.credential_public_key)
        if (
            not verified.user_verified
            or credential.raw_id != credential_id
            or not 1 <= len(credential_id) <= _MAX_CREDENTIAL_ID_BYTES
            or not public_key
            or verified.sign_count < 0
            or verified.credential_device_type.value not in {"single_device", "multi_device"}
        ):
            raise InvalidPasskeyError("passkey registration failed")

    def _verify_passkey_assertion_locked(
        self,
        credential: object,
        *,
        challenge: bytes,
        account_id: str,
        rp_id: str,
        origin: str,
        now: int,
    ) -> VerifiedAuthentication:
        parsed = _parse_authentication_credential(credential)
        credential_id = bytes(parsed.raw_id)
        if not 1 <= len(credential_id) <= _MAX_CREDENTIAL_ID_BYTES:
            raise InvalidPasskeyError("passkey authentication failed")
        credential_row = self._passkey_credential_row_locked(
            credential_id,
            account_id=account_id,
        )
        if credential_row is None:
            raise InvalidPasskeyError("passkey authentication failed")
        user_handle = parsed.response.user_handle
        if user_handle is not None and bytes(user_handle) != bytes.fromhex(account_id):
            raise InvalidPasskeyError("passkey authentication failed")
        current_sign_count = int(credential_row["sign_count"])
        verified = verify_authentication_response(
            credential=parsed,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=bytes(credential_row["public_key"]),
            credential_current_sign_count=current_sign_count,
            require_user_verification=True,
        )
        new_sign_count = int(verified.new_sign_count)
        if (
            not verified.user_verified
            or bytes(verified.credential_id) != credential_id
            or new_sign_count < 0
            or (
                (new_sign_count > 0 or current_sign_count > 0)
                and new_sign_count <= current_sign_count
            )
            or verified.credential_device_type.value not in {"single_device", "multi_device"}
        ):
            raise InvalidPasskeyError("passkey authentication failed")
        updated = self._connection.execute(
            """
            UPDATE auth_passkey_credentials
            SET sign_count = ?, device_type = ?, backed_up = ?, last_used_at = ?
            WHERE credential_id = ? AND account_id = ? AND sign_count = ?
            """,
            (
                new_sign_count,
                verified.credential_device_type.value,
                int(verified.credential_backed_up),
                now,
                credential_id,
                account_id,
                current_sign_count,
            ),
        )
        if updated.rowcount != 1:
            raise InvalidPasskeyError("passkey authentication failed")
        return verified

    def _new_unique_token_locked(
        self,
        key: bytes,
        *,
        table: str,
        digest_column: str,
    ) -> tuple[str, bytes]:
        if (table, digest_column) not in {
            ("auth_pending_challenges", "challenge_digest"),
            ("auth_sessions", "session_digest"),
        }:
            raise ValueError("invalid token table")
        query = (
            "SELECT 1 FROM auth_pending_challenges WHERE challenge_digest = ?"
            if table == "auth_pending_challenges"
            else "SELECT 1 FROM auth_sessions WHERE session_digest = ?"
        )
        for _ in range(8):
            token = _encode_opaque_token(self._random_bytes(_TOKEN_BYTES))
            digest = self._opaque_digest(key, token)
            row = self._connection.execute(query, (digest,)).fetchone()
            if row is None:
                return token, digest
        raise AuthenticationError("unable to allocate a unique opaque token")

    @staticmethod
    def _account_row_query() -> str:
        return "SELECT * FROM auth_accounts"

    def _account_row_by_email_locked(self, canonical: str) -> sqlite3.Row | None:
        return self._connection.execute(
            f"{self._account_row_query()} WHERE canonical_email = ?",
            (canonical,),
        ).fetchone()

    def _account_row_by_id_locked(self, account_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            f"{self._account_row_query()} WHERE account_id = ?",
            (account_id,),
        ).fetchone()

    def _require_account_by_id_locked(self, account_id: str) -> sqlite3.Row:
        row = self._account_row_by_id_locked(account_id)
        if row is None:
            raise AccountNotFoundError("account metadata does not exist")
        return row

    def _challenge_row_locked(self, digest: bytes, now: int) -> sqlite3.Row:
        row = self._connection.execute(
            """
            SELECT
                c.challenge_digest,
                c.account_id,
                c.created_at AS challenge_created_at,
                c.expires_at,
                c.failure_count,
                a.*
            FROM auth_pending_challenges AS c
            JOIN auth_accounts AS a ON a.account_id = c.account_id
            WHERE c.challenge_digest = ?
            """,
            (digest,),
        ).fetchone()
        if row is None:
            raise InvalidChallengeError("pending challenge is invalid")
        if now >= int(row["expires_at"]):
            raise InvalidChallengeError("pending challenge is invalid")
        return row

    def _record_challenge_failure_locked(self, digest: bytes, failure_count: int) -> None:
        next_count = failure_count + 1
        if next_count >= CHALLENGE_FAILURE_LIMIT:
            self._release_pending_enrollment_locked(digest, self._now())
            self._connection.execute(
                "DELETE FROM auth_pending_challenges WHERE challenge_digest = ?",
                (digest,),
            )
        else:
            self._connection.execute(
                """
                UPDATE auth_pending_challenges
                SET failure_count = ?
                WHERE challenge_digest = ?
                """,
                (next_count, digest),
            )

    def _delete_expired_challenges_locked(self, now: int) -> None:
        self._connection.execute(
            """
            UPDATE auth_accounts
            SET enrollment_state = 'required',
                totp_nonce = NULL,
                totp_ciphertext = NULL,
                enrollment_challenge_digest = NULL,
                totp_last_counter = -1,
                updated_at = ?
            WHERE enrollment_state = 'pending'
              AND enrollment_challenge_digest IN (
                  SELECT challenge_digest
                  FROM auth_pending_challenges
                  WHERE expires_at <= ?
              )
            """,
            (now, now),
        )
        self._connection.execute(
            "DELETE FROM auth_pending_challenges WHERE expires_at <= ?",
            (now,),
        )

    def _release_pending_enrollment_locked(self, digest: bytes, now: int) -> None:
        self._connection.execute(
            """
            UPDATE auth_accounts
            SET enrollment_state = 'required',
                totp_nonce = NULL,
                totp_ciphertext = NULL,
                enrollment_challenge_digest = NULL,
                totp_last_counter = -1,
                updated_at = ?
            WHERE enrollment_state = 'pending'
              AND enrollment_challenge_digest = ?
            """,
            (now, digest),
        )

    def _revoke_account_authentication_locked(self, account_id: str) -> int:
        self._revoke_pending_challenges_locked(account_id)
        deleted = self._connection.execute(
            "DELETE FROM auth_sessions WHERE account_id = ?",
            (account_id,),
        )
        return max(0, deleted.rowcount)

    def _revoke_pending_challenges_locked(self, account_id: str) -> None:
        now = self._now()
        self._connection.execute(
            """
            UPDATE auth_accounts
            SET enrollment_state = 'required',
                totp_nonce = NULL,
                totp_ciphertext = NULL,
                enrollment_challenge_digest = NULL,
                totp_last_counter = -1,
                updated_at = ?
            WHERE account_id = ?
              AND enrollment_state = 'pending'
            """,
            (now, account_id),
        )
        self._connection.execute(
            "DELETE FROM auth_pending_challenges WHERE account_id = ?",
            (account_id,),
        )
        self._connection.execute(
            "DELETE FROM auth_passkey_challenges WHERE account_id = ?",
            (account_id,),
        )

    def _consume_totp_locked(self, row: sqlite3.Row, code: str, now: int) -> bool:
        if EnrollmentState(str(row["enrollment_state"])) is not EnrollmentState.ACTIVE:
            raise EnrollmentStateError("TOTP enrollment is not active")
        secret = self._decrypt_totp(row)
        matching_counter = _matching_totp_counter(secret, code, now)
        if matching_counter is None or matching_counter <= int(row["totp_last_counter"]):
            return False
        consumed = self._connection.execute(
            """
            UPDATE auth_accounts
            SET totp_last_counter = ?, updated_at = ?
            WHERE account_id = ?
              AND enrollment_state = 'active'
              AND totp_last_counter < ?
            """,
            (matching_counter, now, str(row["account_id"]), matching_counter),
        )
        return consumed.rowcount == 1

    def _valid_session_row_locked(
        self,
        digest: bytes,
        now: int,
        *,
        touch: bool,
    ) -> tuple[sqlite3.Row, int] | None:
        row = self._connection.execute(
            """
            SELECT
                s.created_at AS session_created_at,
                s.last_seen_at,
                s.absolute_expires_at,
                s.step_up_until,
                s.session_id,
                s.client_ip,
                s.user_agent,
                a.*
            FROM auth_sessions AS s
            JOIN auth_accounts AS a ON a.account_id = s.account_id
            WHERE s.session_digest = ?
            """,
            (digest,),
        ).fetchone()
        if row is None:
            return None
        last_seen = int(row["last_seen_at"])
        absolute_expires = int(row["absolute_expires_at"])
        if now >= absolute_expires or now - last_seen >= SESSION_IDLE_SECONDS:
            self._connection.execute(
                "DELETE FROM auth_sessions WHERE session_digest = ?", (digest,)
            )
            return None
        effective_last_seen = max(last_seen, now) if touch else last_seen
        if touch and effective_last_seen != last_seen:
            self._connection.execute(
                """
                UPDATE auth_sessions
                SET last_seen_at = ?
                WHERE session_digest = ?
                """,
                (effective_last_seen, digest),
            )
        return row, effective_last_seen

    def _delete_expired_sessions_locked(self, now: int) -> None:
        self._connection.execute(
            """
            DELETE FROM auth_sessions
            WHERE absolute_expires_at <= ?
               OR last_seen_at + ? <= ?
            """,
            (now, SESSION_IDLE_SECONDS, now),
        )

    def _encrypt_totp(
        self,
        account_id: str,
        canonical_email: str,
        secret: bytes,
    ) -> tuple[bytes, bytes]:
        nonce = self._random_bytes(_AES_GCM_NONCE_BYTES)
        ciphertext = AESGCM(self._encryption_key).encrypt(
            nonce,
            secret,
            _totp_aad(account_id, canonical_email),
        )
        return nonce, ciphertext

    def _decrypt_totp(self, row: sqlite3.Row) -> bytes:
        nonce = row["totp_nonce"]
        ciphertext = row["totp_ciphertext"]
        if not isinstance(nonce, bytes) or not isinstance(ciphertext, bytes):
            raise AuthenticationDataError("TOTP enrollment data is incomplete")
        try:
            secret = AESGCM(self._encryption_key).decrypt(
                nonce,
                ciphertext,
                _totp_aad(str(row["account_id"]), str(row["canonical_email"])),
            )
        except InvalidTag as exc:
            raise AuthenticationDataError("TOTP enrollment data failed authentication") from exc
        if len(secret) != TOTP_SECRET_BYTES:
            raise AuthenticationDataError("TOTP enrollment data has an invalid length")
        return secret

    def _generate_recovery_codes(self) -> tuple[str, ...]:
        codes: list[str] = []
        seen: set[str] = set()
        while len(codes) < RECOVERY_CODE_COUNT:
            raw = self._random_bytes(16).hex()
            if raw in seen:
                continue
            seen.add(raw)
            codes.append("-".join(raw[index : index + 4] for index in range(0, 32, 4)))
        return tuple(codes)

    def _store_recovery_codes_locked(
        self,
        account_id: str,
        recovery_codes: Sequence[str],
        now: int,
    ) -> None:
        for code in recovery_codes:
            normalized = _normalize_recovery_code(code)
            self._connection.execute(
                """
                INSERT INTO auth_recovery_codes(account_id, code_digest, created_at)
                VALUES (?, ?, ?)
                """,
                (account_id, self._recovery_digest(account_id, normalized), now),
            )

    def _recovery_digest(self, account_id: str, normalized_code: str) -> bytes:
        return hmac.digest(
            self._recovery_digest_key,
            account_id.encode("ascii") + b"\0" + normalized_code.encode("ascii"),
            "sha256",
        )

    @staticmethod
    def _opaque_digest(key: bytes, token: str) -> bytes:
        bounded = (
            token
            if isinstance(token, str) and _OPAQUE_TOKEN_PATTERN.fullmatch(token) is not None
            else ""
        )
        return hmac.digest(key, bounded.encode("ascii"), "sha256")

    def _issue_session_locked(
        self,
        account_row: sqlite3.Row,
        now: int,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedSession:
        account_id = str(account_row["account_id"])
        normalized_ip, normalized_user_agent = _normalize_session_metadata(
            client_ip,
            user_agent,
        )
        self._delete_expired_sessions_locked(now)
        session_count = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM auth_sessions WHERE account_id = ?",
                (account_id,),
            ).fetchone()[0]
        )
        if session_count >= MAX_SESSIONS_PER_ACCOUNT:
            remove_count = session_count - MAX_SESSIONS_PER_ACCOUNT + 1
            self._connection.execute(
                """
                DELETE FROM auth_sessions
                WHERE session_digest IN (
                    SELECT session_digest
                    FROM auth_sessions
                    WHERE account_id = ?
                    ORDER BY last_seen_at, created_at, session_digest
                    LIMIT ?
                )
                """,
                (account_id, remove_count),
            )
        token, digest = self._new_unique_token_locked(
            self._session_digest_key,
            table="auth_sessions",
            digest_column="session_digest",
        )
        session_id = self._new_session_id_locked()
        absolute_expires = now + SESSION_ABSOLUTE_SECONDS
        self._connection.execute(
            """
            INSERT INTO auth_sessions(
                session_digest, account_id, created_at, last_seen_at,
                absolute_expires_at, step_up_until, session_id, client_ip, user_agent
            ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
            """,
            (
                digest,
                account_id,
                now,
                now,
                absolute_expires,
                session_id,
                normalized_ip,
                normalized_user_agent,
            ),
        )
        principal = SessionPrincipal(
            account_id=account_id,
            email=str(account_row["canonical_email"]),
            role=Role(str(account_row["role"])),
            password_change_required=bool(account_row["password_change_required"]),
            enrollment_state=EnrollmentState(str(account_row["enrollment_state"])),
            created_at=now,
            idle_expires_at=min(now + SESSION_IDLE_SECONDS, absolute_expires),
            absolute_expires_at=absolute_expires,
            step_up_until=0,
            session_id=session_id,
            client_ip=normalized_ip,
            user_agent=normalized_user_agent,
        )
        return IssuedSession(token=token, principal=principal)

    def _enrollment(self, canonical_email: str, secret: str) -> TotpEnrollment:
        return TotpEnrollment(
            secret=secret,
            provisioning_uri=totp_provisioning_uri(
                self.issuer,
                canonical_email,
                secret,
            ),
        )

    def _rate_identities(self, canonical_email: str, normalized_ip: str) -> dict[str, bytes]:
        email_bytes = canonical_email.encode("ascii")
        ip_bytes = normalized_ip.encode("ascii")
        return {
            "global": self._rate_digest(b"global", b"all"),
            "ip": self._rate_digest(b"ip", ip_bytes),
            "account": self._rate_digest(b"account", email_bytes),
            "pair": self._rate_digest(b"pair", email_bytes + b"\0" + ip_bytes),
        }

    def _passkey_login_rate_identities(self, normalized_ip: str) -> dict[str, bytes]:
        ip_bytes = normalized_ip.encode("ascii")
        return {
            "global": self._rate_digest(b"passkey-global", b"all"),
            "ip": self._rate_digest(b"passkey-ip", ip_bytes),
        }

    def _rate_digest(self, scope: bytes, value: bytes) -> bytes:
        return hmac.digest(
            self._rate_digest_key,
            b"maddyweb-login-rate-v1\0" + scope + b"\0" + value,
            "sha256",
        )


def _validate_issuer(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("TOTP issuer must be text")
    issuer = value.strip()
    if (
        not issuer
        or len(issuer) > 64
        or not issuer.isascii()
        or ":" in issuer
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in issuer)
    ):
        raise ValueError("TOTP issuer must be printable ASCII without a colon")
    return issuer


def _validate_webauthn_configuration(
    rp_id: str | None,
    origin: str | None,
) -> tuple[str | None, str | None]:
    if rp_id is None and origin is None:
        return None, None
    if not isinstance(rp_id, str) or not isinstance(origin, str):
        raise ValueError("WebAuthn RP ID and origin must be configured together")
    normalized_rp_id = rp_id.strip().lower()
    if (
        not normalized_rp_id
        or len(normalized_rp_id) > 253
        or not normalized_rp_id.isascii()
        or normalized_rp_id.endswith(".")
    ):
        raise ValueError("WebAuthn RP ID must be an ASCII host name or IP address")
    try:
        ipaddress.ip_address(normalized_rp_id)
        rp_is_ip = True
    except ValueError:
        rp_is_ip = False
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or _DOMAIN_LABEL_PATTERN.fullmatch(label) is None
            for label in normalized_rp_id.split(".")
        ):
            raise ValueError("WebAuthn RP ID must be an ASCII host name or IP address") from None

    configured_origin = origin.strip()
    parsed = urlsplit(configured_origin)
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("WebAuthn origin must contain a valid port") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("WebAuthn origin must be an exact HTTPS origin without a path")
    origin_host = parsed.hostname.lower()
    if not origin_host.isascii():
        raise ValueError("WebAuthn origin host must be ASCII")
    if rp_is_ip:
        rp_matches_origin = origin_host == normalized_rp_id
    else:
        rp_matches_origin = origin_host == normalized_rp_id or origin_host.endswith(
            f".{normalized_rp_id}"
        )
    if not rp_matches_origin:
        raise ValueError("WebAuthn RP ID must equal or be a parent of the origin host")
    try:
        origin_ip = ipaddress.ip_address(origin_host)
    except ValueError:
        origin_host_text = origin_host
    else:
        origin_host_text = f"[{origin_ip}]" if origin_ip.version == 6 else str(origin_ip)
    normalized_origin = f"https://{origin_host_text}"
    if parsed_port is not None:
        normalized_origin = f"{normalized_origin}:{parsed_port}"
    return normalized_rp_id, normalized_origin


def _coerce_role(value: Role | str) -> Role:
    try:
        return Role(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("role must be admin or user") from exc


def _coerce_bool(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _validate_account_id(value: str) -> str:
    if not isinstance(value, str) or _ACCOUNT_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("account identifier must be 32 lowercase hexadecimal characters")
    return value


def _validate_session_id(value: str) -> str:
    if not isinstance(value, str) or _SESSION_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("session identifier must be 32 lowercase hexadecimal characters")
    return value


def _validate_passkey_public_id(value: str) -> str:
    if not isinstance(value, str) or _SESSION_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("passkey identifier must be 32 lowercase hexadecimal characters")
    return value


def _normalize_passkey_name(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("passkey name must be text")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > _MAX_PASSKEY_NAME_LENGTH
        or any(character in "\r\n\0" for character in normalized)
    ):
        raise ValueError("passkey name must contain 1 to 100 safe characters")
    return normalized


def _normalize_session_metadata(
    client_ip: str | None,
    user_agent: str | None,
) -> tuple[str | None, str | None]:
    normalized_ip = None if client_ip is None else _canonical_ip(client_ip)
    if user_agent is None:
        return normalized_ip, None
    if not isinstance(user_agent, str):
        raise ValueError("user agent must be text")
    normalized_user_agent = user_agent.strip()
    if not normalized_user_agent:
        return normalized_ip, None
    if len(normalized_user_agent) > _MAX_USER_AGENT_LENGTH or any(
        character in "\r\n\0" for character in normalized_user_agent
    ):
        raise ValueError("user agent must contain at most 512 safe characters")
    return normalized_ip, normalized_user_agent


def _encode_totp_secret(value: bytes) -> str:
    return base64.b32encode(value).decode("ascii").rstrip("=")


def _encode_opaque_token(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_opaque_token(value: str) -> bytes | None:
    if not isinstance(value, str) or _OPAQUE_TOKEN_PATTERN.fullmatch(value) is None:
        return None
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except ValueError, base64.binascii.Error:
        return None
    return decoded if len(decoded) == _TOKEN_BYTES else None


def _options_to_payload(options: object) -> dict[str, object]:
    payload = json.loads(options_to_json(options))  # type: ignore[arg-type]
    if not isinstance(payload, dict):
        raise AuthenticationDataError("WebAuthn options did not serialize to an object")
    return payload


def _parse_registration_credential(value: object) -> RegistrationCredential:
    if isinstance(value, RegistrationCredential):
        return value
    if isinstance(value, str | dict):
        return parse_registration_credential_json(value)
    raise ValueError("passkey registration credential must be a WebAuthn response")


def _parse_authentication_credential(value: object) -> AuthenticationCredential:
    if isinstance(value, AuthenticationCredential):
        return value
    if isinstance(value, str | dict):
        return parse_authentication_credential_json(value)
    raise ValueError("passkey authentication credential must be a WebAuthn response")


def _normalize_recovery_code(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("recovery code must be text")
    normalized = value.strip().lower().replace("-", "")
    if _RECOVERY_CODE_PATTERN.fullmatch(normalized) is None:
        raise ValueError("recovery code must contain 32 hexadecimal characters")
    return normalized


def _validate_recovery_code_set(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, str) or len(values) != RECOVERY_CODE_COUNT:
        raise ValueError("exactly 10 recovery codes are required")
    normalized = tuple(_normalize_recovery_code(value) for value in values)
    if len(set(normalized)) != RECOVERY_CODE_COUNT:
        raise ValueError("recovery codes must be unique")
    return normalized


def _derive_key(master_key: bytes, label: bytes) -> bytes:
    return hmac.digest(master_key, b"maddyweb-auth-v1\0" + label, "sha256")


def _totp_aad(account_id: str, canonical_email: str) -> bytes:
    return (
        b"maddyweb-totp-seed-v1\0"
        + account_id.encode("ascii")
        + b"\0"
        + canonical_email.encode("ascii")
    )


def _sha1(data: bytes = b"") -> hashlib._Hash:
    # RFC 6238 interoperability requires HMAC-SHA1 here.
    return hashlib.sha1(data, usedforsecurity=False)


def _totp_for_counter(secret: bytes, counter: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", counter), _sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"


def _matching_totp_counter(secret: bytes, code: str, now: int) -> int | None:
    bounded = code if isinstance(code, str) and len(code) == 6 and code.isascii() else ""
    current = now // TOTP_PERIOD_SECONDS
    matching: int | None = None
    for candidate in range(max(0, current - TOTP_WINDOW), current + TOTP_WINDOW + 1):
        if hmac.compare_digest(_totp_for_counter(secret, candidate), bounded):
            matching = candidate
    return matching


def _canonical_ip(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("client IP must be text")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("client IP must be an explicit IP address") from exc


def _prepare_private_database(path: Path) -> None:
    parent = path.parent
    if not parent.exists() or not parent.is_dir():
        raise DatabaseSecurityError("authentication database directory does not exist")
    if os.name != "posix":
        return
    effective_uid = os.geteuid()
    parent_stat = os.stat(parent, follow_symlinks=False)
    if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
        raise DatabaseSecurityError("authentication database directory must not be a symlink")
    if parent_stat.st_uid != effective_uid or stat.S_IMODE(parent_stat.st_mode) & 0o022:
        raise DatabaseSecurityError("authentication database directory must be owner-controlled")
    try:
        file_stat = os.lstat(path)
    except FileNotFoundError:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        os.close(descriptor)
        file_stat = os.lstat(path)
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or stat.S_ISLNK(file_stat.st_mode)
        or file_stat.st_uid != effective_uid
        or stat.S_IMODE(file_stat.st_mode) & 0o077
        or file_stat.st_nlink != 1
    ):
        raise DatabaseSecurityError(
            "authentication database must be an owner-only single-link regular file"
        )


def _account_from_row(row: sqlite3.Row) -> Account:
    return Account(
        account_id=str(row["account_id"]),
        email=str(row["canonical_email"]),
        role=Role(str(row["role"])),
        password_change_required=bool(row["password_change_required"]),
        enrollment_state=EnrollmentState(str(row["enrollment_state"])),
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
    )


def _session_info_from_row(row: sqlite3.Row, *, current: bool) -> SessionInfo:
    session_id = row["session_id"]
    if not isinstance(session_id, str) or _SESSION_ID_PATTERN.fullmatch(session_id) is None:
        raise AuthenticationDataError("session has an invalid public identifier")
    last_seen = int(row["last_seen_at"])
    absolute_expires = int(row["absolute_expires_at"])
    return SessionInfo(
        session_id=session_id,
        account_id=str(row["account_id"]),
        created_at=int(row["created_at"]),
        last_seen_at=last_seen,
        idle_expires_at=min(last_seen + SESSION_IDLE_SECONDS, absolute_expires),
        absolute_expires_at=absolute_expires,
        step_up_until=int(row["step_up_until"]),
        client_ip=(None if row["client_ip"] is None else str(row["client_ip"])),
        user_agent=(None if row["user_agent"] is None else str(row["user_agent"])),
        current=current,
    )


def _passkey_credential_from_row(row: sqlite3.Row) -> PasskeyCredential:
    try:
        raw_transports = json.loads(str(row["transports"])) if row["transports"] else []
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AuthenticationDataError("passkey transports are invalid") from exc
    if not isinstance(raw_transports, list) or any(
        not isinstance(transport, str) for transport in raw_transports
    ):
        raise AuthenticationDataError("passkey transports are invalid")
    public_id = row["public_id"]
    if not isinstance(public_id, str) or _SESSION_ID_PATTERN.fullmatch(public_id) is None:
        raise AuthenticationDataError("passkey has an invalid public identifier")
    return PasskeyCredential(
        public_id=public_id,
        account_id=str(row["account_id"]),
        name=str(row["name"]),
        sign_count=int(row["sign_count"]),
        device_type=str(row["device_type"]),
        backed_up=bool(row["backed_up"]),
        transports=tuple(raw_transports),
        created_at=int(row["created_at"]),
        last_used_at=(None if row["last_used_at"] is None else int(row["last_used_at"])),
    )


def _principal_from_session_row(
    row: sqlite3.Row,
    last_seen: int,
    *,
    step_up_until: int | None = None,
) -> SessionPrincipal:
    absolute_expires = int(row["absolute_expires_at"])
    return SessionPrincipal(
        account_id=str(row["account_id"]),
        email=str(row["canonical_email"]),
        role=Role(str(row["role"])),
        password_change_required=bool(row["password_change_required"]),
        enrollment_state=EnrollmentState(str(row["enrollment_state"])),
        created_at=int(row["session_created_at"]),
        idle_expires_at=min(last_seen + SESSION_IDLE_SECONDS, absolute_expires),
        absolute_expires_at=absolute_expires,
        step_up_until=(int(row["step_up_until"]) if step_up_until is None else step_up_until),
        session_id=(None if row["session_id"] is None else str(row["session_id"])),
        client_ip=(None if row["client_ip"] is None else str(row["client_ip"])),
        user_agent=(None if row["user_agent"] is None else str(row["user_agent"])),
    )


def _required_row(value: sqlite3.Row | None) -> sqlite3.Row:
    if value is None:
        raise AuthenticationDataError("authentication row disappeared")
    return value


def _required_session(value: IssuedSession | None) -> IssuedSession:
    if value is None:
        raise AuthenticationDataError("authentication session was not issued")
    return value


def _required_result(value: EnrollmentResult | None) -> EnrollmentResult:
    if value is None:
        raise AuthenticationDataError("TOTP enrollment result was not issued")
    return value


__all__ = [
    "CHALLENGE_FAILURE_LIMIT",
    "CHALLENGE_LIFETIME_SECONDS",
    "MAX_PASSKEYS_PER_ACCOUNT",
    "MAX_SESSIONS_PER_ACCOUNT",
    "RECOVERY_CODE_COUNT",
    "SESSION_ABSOLUTE_SECONDS",
    "SESSION_IDLE_SECONDS",
    "STEP_UP_SECONDS",
    "TOTP_PERIOD_SECONDS",
    "TOTP_SECRET_BYTES",
    "TOTP_WINDOW",
    "Account",
    "AccountBootstrap",
    "AccountExistsError",
    "AccountNotFoundError",
    "AuthStore",
    "AuthenticationDataError",
    "AuthenticationError",
    "DatabaseSecurityError",
    "EnrollmentResult",
    "EnrollmentState",
    "EnrollmentStateError",
    "InvalidChallengeError",
    "InvalidPasskeyError",
    "InvalidSecondFactorError",
    "InvalidSessionError",
    "IssuedSession",
    "LoginRateLimitedError",
    "MasterKeyError",
    "PasskeyCeremony",
    "PasskeyCredential",
    "PasskeyLimitError",
    "Role",
    "SessionInfo",
    "SessionPrincipal",
    "StepUpRequiredError",
    "TotpEnrollment",
    "VerifiedPasskeyIdentity",
    "canonicalize_email",
    "decode_totp_secret",
    "totp_code",
    "totp_provisioning_uri",
]
