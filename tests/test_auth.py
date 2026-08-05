from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers.structs import (
    AttestationFormat,
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorTransport,
    CredentialDeviceType,
    PublicKeyCredentialType,
    RegistrationCredential,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

import maddyweb.auth as auth_module
from maddyweb.auth import (
    CHALLENGE_FAILURE_LIMIT,
    CHALLENGE_LIFETIME_SECONDS,
    MAX_PASSKEYS_PER_ACCOUNT,
    MAX_SESSIONS_PER_ACCOUNT,
    RECOVERY_CODE_COUNT,
    SESSION_ABSOLUTE_SECONDS,
    SESSION_IDLE_SECONDS,
    STEP_UP_SECONDS,
    AccountExistsError,
    AccountNotFoundError,
    AuthStore,
    DatabaseSecurityError,
    EnrollmentState,
    EnrollmentStateError,
    InvalidChallengeError,
    InvalidPasskeyError,
    InvalidSecondFactorError,
    InvalidSessionError,
    LoginRateLimitedError,
    MasterKeyError,
    PasskeyLimitError,
    Role,
    StepUpRequiredError,
    canonicalize_email,
    decode_totp_secret,
    totp_code,
    totp_provisioning_uri,
)

MASTER_KEY = b"maddyweb-auth-test-master-key-01"
OTHER_MASTER_KEY = b"maddyweb-auth-test-master-key-02"
START_TIME = 1_800_000_000


class FakeClock:
    def __init__(self, value: int = START_TIME) -> None:
        self.value = value

    def __call__(self) -> float:
        return float(self.value)

    def advance(self, seconds: int) -> None:
        self.value += seconds


class DeterministicRandom:
    def __init__(self, seed: bytes = b"auth-tests") -> None:
        self.seed = seed
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        output = bytearray()
        while len(output) < length:
            output.extend(hashlib.sha256(self.seed + self.counter.to_bytes(8, "big")).digest())
            self.counter += 1
        return bytes(output[:length])


class StoreFactory:
    def __init__(self, tmp_path: Path, clock: FakeClock) -> None:
        self.tmp_path = tmp_path
        self.clock = clock
        self.stores: list[AuthStore] = []
        self.counter = 0
        if os.name == "posix":
            tmp_path.chmod(0o700)

    def __call__(
        self,
        *,
        name: str = "auth.db",
        master_key: bytes = MASTER_KEY,
        seed: bytes | None = None,
        webauthn_rp_id: str | None = None,
        webauthn_origin: str | None = None,
    ) -> AuthStore:
        random_seed = seed or f"store-{self.counter}".encode("ascii")
        self.counter += 1
        store = AuthStore(
            self.tmp_path / name,
            master_key,
            "MaddyWeb",
            clock=self.clock,
            random_bytes=DeterministicRandom(random_seed),
            webauthn_rp_id=webauthn_rp_id,
            webauthn_origin=webauthn_origin,
        )
        self.stores.append(store)
        return store

    def close(self) -> None:
        for store in self.stores:
            store.close()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store_factory(tmp_path: Path, clock: FakeClock) -> Iterator[StoreFactory]:
    factory = StoreFactory(tmp_path, clock)
    yield factory
    factory.close()


def _wrong_code(correct: str) -> str:
    return "999999" if correct != "999999" else "000000"


def _login(
    store: AuthStore,
    email: str,
    secret: str,
    clock: FakeClock,
) -> str:
    challenge = store.create_pending_challenge(email)
    issued = store.complete_totp_challenge(
        challenge,
        totp_code(secret, timestamp=clock.value),
    )
    return issued.token


def _bootstrap_codes(prefix: int = 0) -> tuple[str, ...]:
    return tuple(f"{prefix + index:032x}" for index in range(RECOVERY_CODE_COUNT))


def _decode_token(token: str) -> bytes:
    return base64.urlsafe_b64decode(token + "=" * ((4 - len(token) % 4) % 4))


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _registration_credential(credential_id: bytes) -> RegistrationCredential:
    return RegistrationCredential(
        id=_encode_base64url(credential_id),
        raw_id=credential_id,
        response=AuthenticatorAttestationResponse(
            client_data_json=b"test-client-data",
            attestation_object=b"test-attestation",
            transports=[AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID],
        ),
    )


def _verified_registration(
    credential_id: bytes,
    *,
    sign_count: int = 0,
) -> VerifiedRegistration:
    return VerifiedRegistration(
        credential_id=credential_id,
        credential_public_key=b"test-cose-public-key",
        sign_count=sign_count,
        aaguid="00000000-0000-0000-0000-000000000000",
        fmt=AttestationFormat.NONE,
        credential_type=PublicKeyCredentialType.PUBLIC_KEY,
        user_verified=True,
        attestation_object=b"test-attestation",
        credential_device_type=CredentialDeviceType.MULTI_DEVICE,
        credential_backed_up=True,
    )


def _authentication_credential(
    credential_id: bytes,
    account_id: str,
) -> AuthenticationCredential:
    return AuthenticationCredential(
        id=_encode_base64url(credential_id),
        raw_id=credential_id,
        response=AuthenticatorAssertionResponse(
            client_data_json=b"test-client-data",
            authenticator_data=b"test-authenticator-data",
            signature=b"test-signature",
            user_handle=bytes.fromhex(account_id),
        ),
    )


def _verified_authentication(
    credential_id: bytes,
    sign_count: int,
) -> VerifiedAuthentication:
    return VerifiedAuthentication(
        credential_id=credential_id,
        new_sign_count=sign_count,
        credential_device_type=CredentialDeviceType.MULTI_DEVICE,
        credential_backed_up=True,
        user_verified=True,
    )


def _create_schema_v3_pending_database(path: Path) -> None:
    account_id = "1" * 32
    challenge_digest = b"c" * 32
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE auth_metadata (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            ) STRICT;

            CREATE TABLE auth_accounts (
                account_id TEXT PRIMARY KEY CHECK(length(account_id) = 32),
                canonical_email TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                password_change_required INTEGER NOT NULL
                    CHECK(password_change_required IN (0, 1)),
                enrollment_state TEXT NOT NULL
                    CHECK(enrollment_state IN ('required', 'pending', 'active')),
                totp_nonce BLOB,
                totp_ciphertext BLOB,
                totp_last_counter INTEGER NOT NULL DEFAULT -1
                    CHECK(totp_last_counter >= -1),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                CHECK(
                    (
                        enrollment_state = 'required'
                        AND totp_nonce IS NULL
                        AND totp_ciphertext IS NULL
                        AND totp_last_counter = -1
                    )
                    OR (
                        enrollment_state IN ('pending', 'active')
                        AND length(totp_nonce) = 12
                        AND totp_ciphertext IS NOT NULL
                    )
                )
            ) STRICT;

            CREATE TABLE auth_pending_challenges (
                challenge_digest BLOB PRIMARY KEY CHECK(length(challenge_digest) = 32),
                account_id TEXT NOT NULL
                    REFERENCES auth_accounts(account_id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                failure_count INTEGER NOT NULL DEFAULT 0
                    CHECK(failure_count BETWEEN 0 AND 5)
            ) STRICT;
            """
        )
        connection.execute(
            "INSERT INTO auth_metadata(key, value) VALUES ('schema_version', ?)",
            (b"3",),
        )
        connection.execute(
            """
            INSERT INTO auth_accounts(
                account_id, canonical_email, role, password_change_required,
                enrollment_state, totp_nonce, totp_ciphertext,
                totp_last_counter, created_at, updated_at
            ) VALUES (?, 'user@example.test', 'user', 1, 'pending', ?, ?, -1, ?, ?)
            """,
            (account_id, b"n" * 12, b"legacy-ciphertext", START_TIME, START_TIME),
        )
        connection.execute(
            """
            INSERT INTO auth_pending_challenges(
                challenge_digest, account_id, created_at, expires_at, failure_count
            ) VALUES (?, ?, ?, ?, 0)
            """,
            (challenge_digest, account_id, START_TIME, START_TIME + 300),
        )
    if os.name == "posix":
        path.chmod(0o600)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("User@Example.COM", "user@example.com"),
        (" user.name+tag@MAIL.Example ", "user.name+tag@mail.example"),
        ("A@localhost", "a@localhost"),
    ],
)
def test_canonicalize_email(raw: str, expected: str) -> None:
    assert canonicalize_email(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "missing-at.example",
        "two@@example.test",
        ".leading@example.test",
        "trailing.@example.test",
        "double..dot@example.test",
        "quoted local@example.test",
        "user@-example.test",
        "user@example-.test",
        "user@example..test",
        "nonascii-\N{LATIN SMALL LETTER E WITH ACUTE}@example.test",
    ],
)
def test_canonicalize_email_rejects_ambiguous_or_invalid_values(raw: str) -> None:
    with pytest.raises(ValueError):
        canonicalize_email(raw)


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (59, "287082"),
        (1_111_111_109, "081804"),
        (1_111_111_111, "050471"),
        (1_234_567_890, "005924"),
        (2_000_000_000, "279037"),
        (20_000_000_000, "353130"),
    ],
)
def test_totp_matches_rfc_6238_sha1_vectors_at_six_digits(
    timestamp: int,
    expected: str,
) -> None:
    assert totp_code(b"12345678901234567890", timestamp=timestamp) == expected


def test_totp_provisioning_uri_is_google_authenticator_compatible() -> None:
    uri = totp_provisioning_uri(
        "MaddyWeb Example",
        "Owner@Example.TEST",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    )

    assert uri == (
        "otpauth://totp/MaddyWeb%20Example%3Aowner%40example.test"
        "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        "&issuer=MaddyWeb+Example&algorithm=SHA1&digits=6&period=30"
    )


def test_account_ids_are_stable_and_sync_is_create_only(
    store_factory: StoreFactory,
) -> None:
    store = store_factory()
    created = store.create_account(
        "Owner@Example.test",
        role=Role.ADMIN,
        password_change_required=False,
    )

    assert len(created.account_id) == 32
    assert int(created.account_id, 16) >= 0
    assert created.email == "owner@example.test"
    assert created.role is Role.ADMIN
    assert created.enrollment_state is EnrollmentState.REQUIRED
    assert store.resolve_account_id(created.account_id) == created
    assert store.get_account("OWNER@example.test") == created

    synced = store.sync_accounts(["new@example.test", "OWNER@EXAMPLE.TEST", "New@Example.Test"])
    assert [account.email for account in synced] == [
        "new@example.test",
        "owner@example.test",
    ]
    assert synced[1] == created
    assert synced[1].role is Role.ADMIN

    with pytest.raises(AccountExistsError):
        store.create_account("owner@example.test")
    with pytest.raises(AccountNotFoundError):
        store.resolve_account_id("0" * 32)


def test_provisioning_returns_secrets_once_and_persists_only_protected_values(
    store_factory: StoreFactory,
) -> None:
    store = store_factory()
    account, enrollment, recovery_codes = store.provision_active_account(
        "User@Example.test",
        role=Role.USER,
        password_change_required=True,
    )

    assert account.enrollment_state is EnrollmentState.ACTIVE
    assert account.password_change_required is True
    assert len(decode_totp_secret(enrollment.secret)) == 20
    assert enrollment.secret in enrollment.provisioning_uri
    assert "issuer=MaddyWeb" in enrollment.provisioning_uri
    assert len(recovery_codes) == RECOVERY_CODE_COUNT
    assert len(set(recovery_codes)) == RECOVERY_CODE_COUNT
    assert store.recovery_code_count(account.account_id) == RECOVERY_CODE_COUNT

    database_bytes = (store_factory.tmp_path / "auth.db").read_bytes()
    assert enrollment.secret.encode("ascii") not in database_bytes
    assert decode_totp_secret(enrollment.secret) not in database_bytes
    for code in recovery_codes:
        assert code.encode("ascii") not in database_bytes

    with pytest.raises(AccountExistsError):
        store.provision_active_account("USER@example.test")

    with pytest.raises(AccountNotFoundError):
        store.recovery_code_count("0" * 32)


def test_pending_enrollment_confirms_then_issues_session_and_recovery_codes(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account = store.create_account("user@example.test")
    challenge = store.create_pending_challenge(account.email)
    enrollment = store.begin_totp_enrollment(challenge)
    correct = totp_code(enrollment.secret, timestamp=clock.value)

    for _ in range(CHALLENGE_FAILURE_LIMIT - 1):
        with pytest.raises(InvalidSecondFactorError):
            store.confirm_totp_enrollment(challenge, _wrong_code(correct))

    result = store.confirm_totp_enrollment(challenge, correct)
    assert len(result.recovery_codes) == RECOVERY_CODE_COUNT
    assert result.session.principal.account_id == account.account_id
    assert result.session.principal.password_change_required is True
    assert result.session.principal.enrollment_state is EnrollmentState.ACTIVE
    assert store.authenticate_session(result.session.token).email == account.email
    assert store.resolve_account_id(account.account_id).enrollment_state is EnrollmentState.ACTIVE

    with pytest.raises(InvalidChallengeError):
        store.confirm_totp_enrollment(challenge, correct)


def test_pending_enrollment_is_bound_to_one_challenge_across_store_instances(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    first = store_factory(seed=b"enrollment-first")
    account = first.create_account("user@example.test")
    second = store_factory(seed=b"enrollment-second")
    owner_challenge = first.create_pending_challenge(account.email)
    competing_challenge = second.create_pending_challenge(account.email)

    enrollment = first.begin_totp_enrollment(owner_challenge)
    assert first.begin_totp_enrollment(owner_challenge) == enrollment

    with pytest.raises(EnrollmentStateError, match="another challenge"):
        second.begin_totp_enrollment(competing_challenge)
    with pytest.raises(EnrollmentStateError, match="another challenge"):
        second.confirm_totp_enrollment(
            competing_challenge,
            totp_code(enrollment.secret, timestamp=clock.value),
        )

    result = first.confirm_totp_enrollment(
        owner_challenge,
        totp_code(enrollment.secret, timestamp=clock.value),
    )
    assert result.session.principal.enrollment_state is EnrollmentState.ACTIVE
    with pytest.raises(InvalidChallengeError):
        second.confirm_totp_enrollment(
            competing_challenge,
            totp_code(enrollment.secret, timestamp=clock.value),
        )


def test_failed_or_expired_enrollment_owner_can_be_replaced(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account = store.create_account("user@example.test")
    failed_challenge = store.create_pending_challenge(account.email)
    failed_enrollment = store.begin_totp_enrollment(failed_challenge)
    correct = totp_code(failed_enrollment.secret, timestamp=clock.value)

    for _ in range(CHALLENGE_FAILURE_LIMIT):
        with pytest.raises(InvalidSecondFactorError):
            store.confirm_totp_enrollment(failed_challenge, _wrong_code(correct))
    assert store.resolve_account_id(account.account_id).enrollment_state is EnrollmentState.REQUIRED

    expired_challenge = store.create_pending_challenge(account.email)
    store.begin_totp_enrollment(expired_challenge)
    clock.advance(5 * 60)
    with pytest.raises(InvalidChallengeError):
        store.begin_totp_enrollment(expired_challenge)

    replacement = store.create_pending_challenge(account.email)
    assert store.resolve_account_id(account.account_id).enrollment_state is EnrollmentState.REQUIRED
    assert store.begin_totp_enrollment(replacement).secret != failed_enrollment.secret


def test_challenge_expires_and_five_failures_invalidate_it(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, _codes = store.provision_active_account("user@example.test")

    expired = store.create_pending_challenge(account.email)
    clock.advance(5 * 60)
    with pytest.raises(InvalidChallengeError):
        store.complete_totp_challenge(
            expired,
            totp_code(enrollment.secret, timestamp=clock.value),
        )

    challenge = store.create_pending_challenge(account.email)
    correct = totp_code(enrollment.secret, timestamp=clock.value)
    for _ in range(CHALLENGE_FAILURE_LIMIT):
        with pytest.raises(InvalidSecondFactorError):
            store.complete_totp_challenge(challenge, _wrong_code(correct))
    with pytest.raises(InvalidChallengeError):
        store.complete_totp_challenge(challenge, correct)


def test_totp_window_and_replay_counter_are_durable_across_store_instances(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    first = store_factory(seed=b"first")
    account, enrollment, _codes = first.provision_active_account("user@example.test")
    second = store_factory(seed=b"second")

    previous_code = totp_code(enrollment.secret, timestamp=clock.value - 30)
    previous_challenge = first.create_pending_challenge(account.email)
    first.complete_totp_challenge(previous_challenge, previous_code)

    current = totp_code(enrollment.secret, timestamp=clock.value)
    challenge_one = first.create_pending_challenge(account.email)
    challenge_two = second.create_pending_challenge(account.email)
    first.complete_totp_challenge(challenge_one, current)
    with pytest.raises(InvalidSecondFactorError):
        second.complete_totp_challenge(challenge_two, current)

    future = totp_code(enrollment.secret, timestamp=clock.value + 30)
    future_challenge = second.create_pending_challenge(account.email)
    second.complete_totp_challenge(future_challenge, future)


def test_recovery_codes_are_keyed_one_use_credentials(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, codes = store.provision_active_account("user@example.test")
    existing_session = _login(store, account.email, enrollment.secret, clock)
    other_pending_challenge = store.create_pending_challenge(account.email)

    challenge = store.create_pending_challenge(account.email)
    session = store.complete_recovery_challenge(challenge, codes[0].upper())
    assert store.authenticate_session(session.token).account_id == account.account_id
    assert store.recovery_code_count(account.account_id) == RECOVERY_CODE_COUNT - 1
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(existing_session)
    with pytest.raises(InvalidChallengeError):
        store.complete_recovery_challenge(other_pending_challenge, codes[2])

    replay = store.create_pending_challenge(account.email)
    with pytest.raises(InvalidSecondFactorError):
        store.complete_recovery_challenge(replay, codes[0])

    unused = store.create_pending_challenge(account.email)
    assert store.complete_recovery_challenge(unused, codes[1]).principal.email == account.email
    assert store.recovery_code_count(account.account_id) == RECOVERY_CODE_COUNT - 2


def test_helper_totp_verification_and_recovery_regeneration_are_replay_safe(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, old_codes = store.provision_active_account("user@example.test")

    first_code = totp_code(enrollment.secret, timestamp=clock.value)
    store.verify_totp(account.account_id, first_code)
    with pytest.raises(InvalidSecondFactorError):
        store.verify_totp(account.account_id, first_code)

    clock.advance(30)
    session_token = _login(store, account.email, enrollment.secret, clock)
    clock.advance(30)
    replacement_codes = store.regenerate_recovery_codes(
        account.account_id,
        totp_code(enrollment.secret, timestamp=clock.value),
    )
    assert len(replacement_codes) == RECOVERY_CODE_COUNT
    assert set(replacement_codes).isdisjoint(old_codes)
    assert store.recovery_code_count(account.account_id) == RECOVERY_CODE_COUNT
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(session_token)

    old_challenge = store.create_pending_challenge(account.email)
    with pytest.raises(InvalidSecondFactorError):
        store.complete_recovery_challenge(old_challenge, old_codes[0])
    new_challenge = store.create_pending_challenge(account.email)
    store.complete_recovery_challenge(new_challenge, replacement_codes[0])


def test_totp_rotation_preserves_identity_and_revokes_existing_sessions(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, original, original_codes = store.provision_active_account(
        "admin@example.test",
        role=Role.ADMIN,
    )
    old_session = _login(store, account.email, original.secret, clock)

    rotated, rotated_codes = store.rotate_totp(account.account_id)
    assert rotated.secret != original.secret
    assert set(rotated_codes).isdisjoint(original_codes)
    assert store.resolve_account_id(account.account_id).role is Role.ADMIN
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(old_session)

    old_factor = store.create_pending_challenge(account.email)
    with pytest.raises(InvalidSecondFactorError):
        store.complete_totp_challenge(
            old_factor,
            totp_code(original.secret, timestamp=clock.value),
        )
    new_factor = store.create_pending_challenge(account.email)
    store.complete_totp_challenge(
        new_factor,
        totp_code(rotated.secret, timestamp=clock.value),
    )


def test_bootstrap_upsert_preserves_account_id_and_revokes_sessions(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    first_secret = base64.b32encode(b"a" * 20).decode("ascii")
    first_codes = _bootstrap_codes()
    account = store.bootstrap_active_account(
        "Root@Example.test",
        role=Role.ADMIN,
        totp_secret=first_secret,
        recovery_codes=first_codes,
        password_change_required=True,
    )
    session = _login(store, account.email, first_secret, clock)

    second_secret = base64.b32encode(b"b" * 20).decode("ascii")
    updated = store.bootstrap_active_account(
        "ROOT@example.test",
        role=Role.USER,
        totp_secret=second_secret,
        recovery_codes=_bootstrap_codes(100),
        password_change_required=False,
    )
    assert updated.account_id == account.account_id
    assert updated.created_at == account.created_at
    assert updated.role is Role.USER
    assert updated.password_change_required is False
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(session)

    with pytest.raises(ValueError, match="exactly 10"):
        store.bootstrap_active_account(
            "other@example.test",
            role=Role.USER,
            totp_secret=second_secret,
            recovery_codes=("0" * 32,),
            password_change_required=False,
        )
    with pytest.raises(ValueError, match="unique"):
        store.bootstrap_active_account(
            "other@example.test",
            role=Role.USER,
            totp_secret=second_secret,
            recovery_codes=("0" * 32,) * RECOVERY_CODE_COUNT,
            password_change_required=False,
        )


def test_session_tokens_are_256_bit_keyed_digests_and_revocable(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    challenge = store.create_pending_challenge(account.email)
    token = store.complete_totp_challenge(
        challenge,
        totp_code(enrollment.secret, timestamp=clock.value),
    ).token
    pending_token = store.create_pending_challenge(account.email)

    assert len(_decode_token(token)) == 32
    assert len(_decode_token(pending_token)) == 32
    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        stored_session = connection.execute("SELECT session_digest FROM auth_sessions").fetchone()[
            0
        ]
        assert isinstance(stored_session, bytes)
        assert len(stored_session) == 32
        assert stored_session != token.encode("ascii")
        stored_challenges = connection.execute(
            "SELECT challenge_digest FROM auth_pending_challenges"
        ).fetchall()
        assert len(stored_challenges) == 1
        assert len(stored_challenges[0][0]) == 32
        assert stored_challenges[0][0] != pending_token.encode("ascii")

    database_bytes = (store_factory.tmp_path / "auth.db").read_bytes()
    assert token.encode("ascii") not in database_bytes
    assert pending_token.encode("ascii") not in database_bytes
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(token + "\u00e9")
    assert store.revoke_session(token) is True
    assert store.revoke_session(token) is False
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(token)


def test_session_idle_absolute_and_per_account_limit(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    idle_token = _login(store, account.email, enrollment.secret, clock)
    clock.advance(SESSION_IDLE_SECONDS)
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(idle_token)

    clock.advance(30)
    absolute_token = _login(store, account.email, enrollment.secret, clock)
    issued_at = clock.value
    for delta in range(1_700, SESSION_ABSOLUTE_SECONDS, 1_700):
        clock.value = issued_at + delta
        store.authenticate_session(absolute_token)
    clock.value = issued_at + SESSION_ABSOLUTE_SECONDS
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(absolute_token)

    tokens: list[str] = []
    for _ in range(MAX_SESSIONS_PER_ACCOUNT + 1):
        clock.advance(30)
        tokens.append(_login(store, account.email, enrollment.secret, clock))
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(tokens[0])
    for token in tokens[1:]:
        store.authenticate_session(token)
    assert store.revoke_sessions(account.account_id) == MAX_SESSIONS_PER_ACCOUNT


def test_role_and_password_state_changes_revoke_sessions_by_default(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    token = _login(store, account.email, enrollment.secret, clock)

    promoted = store.set_role(account.account_id, Role.ADMIN)
    assert promoted.role is Role.ADMIN
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(token)

    clock.advance(30)
    next_token = _login(store, account.email, enrollment.secret, clock)
    changed = store.set_password_change_required(account.account_id, True)
    assert changed.password_change_required is True
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(next_token)


def test_role_and_password_state_changes_revoke_preexisting_challenges(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    role_challenge = store.create_pending_challenge(account.email)

    store.set_role(account.account_id, Role.ADMIN)
    with pytest.raises(InvalidChallengeError):
        store.complete_totp_challenge(
            role_challenge,
            totp_code(enrollment.secret, timestamp=clock.value),
        )

    password_challenge = store.create_pending_challenge(account.email)
    store.set_password_change_required(account.account_id, True)
    with pytest.raises(InvalidChallengeError):
        store.complete_totp_challenge(
            password_challenge,
            totp_code(enrollment.secret, timestamp=clock.value),
        )

    preserved_session = _login(store, account.email, enrollment.secret, clock)
    challenge_without_session_revocation = store.create_pending_challenge(account.email)
    store.set_password_change_required(
        account.account_id,
        False,
        revoke_sessions=False,
    )
    assert store.authenticate_session(preserved_session).account_id == account.account_id
    with pytest.raises(InvalidChallengeError):
        store.complete_totp_challenge(
            challenge_without_session_revocation,
            totp_code(enrollment.secret, timestamp=clock.value),
        )

    pending_account = store.create_account("pending@example.test")
    enrollment_challenge = store.create_pending_challenge(pending_account.email)
    store.begin_totp_enrollment(enrollment_challenge)
    store.set_role(pending_account.account_id, Role.ADMIN)
    assert (
        store.resolve_account_id(pending_account.account_id).enrollment_state
        is EnrollmentState.REQUIRED
    )
    with pytest.raises(InvalidChallengeError):
        store.begin_totp_enrollment(enrollment_challenge)


def test_session_step_up_is_bounded_to_five_minutes(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, _codes = store.provision_active_account("admin@example.test")
    token = _login(store, account.email, enrollment.secret, clock)

    with pytest.raises(StepUpRequiredError):
        store.require_step_up(token)
    marked = store.mark_step_up(token)
    assert marked.step_up_until == clock.value + STEP_UP_SECONDS
    clock.advance(STEP_UP_SECONDS - 1)
    assert store.require_step_up(token).account_id == account.account_id
    clock.advance(1)
    with pytest.raises(StepUpRequiredError):
        store.require_step_up(token)
    assert store.authenticate_session(token).account_id == account.account_id


def test_step_up_column_migrates_from_schema_version_one(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    token = _login(store, account.email, enrollment.secret, clock)
    store.close()

    path = store_factory.tmp_path / "auth.db"
    with sqlite3.connect(path) as connection:
        connection.execute("ALTER TABLE auth_sessions DROP COLUMN step_up_until")
        connection.execute("ALTER TABLE auth_login_rate_limits DROP COLUMN account_identity_digest")
        connection.execute("ALTER TABLE auth_login_rate_limits DROP COLUMN account_id")
        connection.execute(
            "UPDATE auth_metadata SET value = ? WHERE key = 'schema_version'",
            (b"1",),
        )

    reopened = store_factory(seed=b"migration")
    principal = reopened.authenticate_session(token)
    assert principal.step_up_until == 0
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(auth_sessions)")}
        assert "step_up_until" in columns
        rate_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(auth_login_rate_limits)")
        }
        assert {"account_id", "account_identity_digest"} <= rate_columns
        account_columns = {row[1] for row in connection.execute("PRAGMA table_info(auth_accounts)")}
        assert "enrollment_challenge_digest" in account_columns
        assert (
            connection.execute(
                "SELECT value FROM auth_metadata WHERE key = 'schema_version'"
            ).fetchone()[0]
            == b"4"
        )


def test_schema_version_three_pending_enrollment_migrates_to_required(
    store_factory: StoreFactory,
) -> None:
    path = store_factory.tmp_path / "legacy-v3.db"
    _create_schema_v3_pending_database(path)

    store = store_factory(name="legacy-v3.db", seed=b"migration-v3")
    account = store.get_account("user@example.test")
    assert account is not None
    assert account.enrollment_state is EnrollmentState.REQUIRED

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            """
            SELECT
                enrollment_challenge_digest,
                totp_nonce,
                totp_ciphertext,
                totp_last_counter
            FROM auth_accounts
            """
        ).fetchone()
        assert row == (None, None, None, -1)
        assert connection.execute("SELECT COUNT(*) FROM auth_pending_challenges").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT value FROM auth_metadata WHERE key = 'schema_version'"
            ).fetchone()[0]
            == b"4"
        )

    challenge = store.create_pending_challenge(account.email)
    assert store.begin_totp_enrollment(challenge).secret


def test_session_metadata_listing_current_and_targeted_revoke(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    challenge = store.create_pending_challenge(account.email)
    issued = store.complete_totp_challenge(
        challenge,
        totp_code(enrollment.secret, timestamp=clock.value),
        client_ip="2001:0db8::1",
        user_agent="  MaddyWeb Test Browser  ",
    )

    assert SESSION_IDLE_SECONDS == 72 * 60 * 60
    assert SESSION_ABSOLUTE_SECONDS == 30 * 24 * 60 * 60
    assert issued.principal.session_id is not None
    assert issued.principal.client_ip == "2001:db8::1"
    assert issued.principal.user_agent == "MaddyWeb Test Browser"
    sessions = store.list_sessions(
        account.account_id,
        current_session_token=issued.token,
    )
    assert len(sessions) == 1
    assert sessions[0].session_id == issued.principal.session_id
    assert sessions[0].current is True
    assert sessions[0].client_ip == "2001:db8::1"
    assert sessions[0].user_agent == "MaddyWeb Test Browser"
    assert issued.token not in repr(sessions[0])

    assert store.revoke_session_by_id(account.account_id, sessions[0].session_id) is True
    assert store.revoke_session_by_id(account.account_id, sessions[0].session_id) is False
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(issued.token)


def test_passkey_session_extension_migrates_additively_from_schema_v4(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory(name="legacy-v4.db")
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    token = _login(store, account.email, enrollment.secret, clock)
    store.close()
    path = store_factory.tmp_path / "legacy-v4.db"

    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE auth_passkey_challenges")
        connection.execute("DROP TABLE auth_passkey_credentials")
        connection.execute("DROP INDEX auth_sessions_public_id_idx")
        connection.execute("ALTER TABLE auth_sessions DROP COLUMN user_agent")
        connection.execute("ALTER TABLE auth_sessions DROP COLUMN client_ip")
        connection.execute("ALTER TABLE auth_sessions DROP COLUMN session_id")
        connection.execute(
            "DELETE FROM auth_metadata WHERE key = 'passkey_session_extension_version'"
        )
        assert (
            connection.execute(
                "SELECT value FROM auth_metadata WHERE key = 'schema_version'"
            ).fetchone()[0]
            == b"4"
        )

    reopened = store_factory(name="legacy-v4.db", seed=b"extension-migration")
    principal = reopened.authenticate_session(token)
    assert principal.session_id is not None
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT value FROM auth_metadata WHERE key = 'schema_version'"
            ).fetchone()[0]
            == b"4"
        )
        assert (
            connection.execute(
                """
            SELECT value FROM auth_metadata
            WHERE key = 'passkey_session_extension_version'
            """
            ).fetchone()[0]
            == b"1"
        )
        columns = {row[1]: row for row in connection.execute("PRAGMA table_info(auth_sessions)")}
        assert {"session_id", "client_ip", "user_agent"} <= columns.keys()
        assert all(columns[name][3] == 0 for name in ("session_id", "client_ip", "user_agent"))
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert {"auth_passkey_credentials", "auth_passkey_challenges"} <= tables
        challenge_columns = {
            row[1]: row for row in connection.execute("PRAGMA table_info(auth_passkey_challenges)")
        }
        assert challenge_columns["account_id"][3] == 0


def test_passkey_session_extension_does_not_revive_legacy_idle_session(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory(name="legacy-idle-v4.db")
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    token = _login(store, account.email, enrollment.secret, clock)
    store.close()
    path = store_factory.tmp_path / "legacy-idle-v4.db"

    with sqlite3.connect(path) as connection:
        connection.execute(
            "DELETE FROM auth_metadata WHERE key = 'passkey_session_extension_version'"
        )
    clock.advance(30 * 60)

    reopened = store_factory(name="legacy-idle-v4.db", seed=b"idle-migration")
    with pytest.raises(InvalidSessionError):
        reopened.authenticate_session(token)


def test_passkey_registration_login_and_session_bound_step_up(
    store_factory: StoreFactory,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = store_factory(
        webauthn_rp_id="example.test",
        webauthn_origin="https://admin.example.test",
    )
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    totp_session = _login(store, account.email, enrollment.secret, clock)
    store.mark_step_up(totp_session)
    credential_id = b"synced-platform-passkey"

    registration = store.begin_passkey_registration(totp_session)
    assert len(_decode_token(registration.challenge_token)) == 32
    assert registration.options["rp"] == {"id": "example.test", "name": "MaddyWeb"}
    assert registration.options["attestation"] == "none"
    assert registration.options["authenticatorSelection"] == {
        "requireResidentKey": True,
        "residentKey": "required",
        "userVerification": "required",
    }
    registration_call: dict[str, object] = {}

    def verify_registration(**kwargs: object) -> VerifiedRegistration:
        registration_call.update(kwargs)
        return _verified_registration(credential_id)

    monkeypatch.setattr(auth_module, "verify_registration_response", verify_registration)
    passkey = store.complete_passkey_registration(
        totp_session,
        registration.challenge_token,
        _registration_credential(credential_id),
        name="Laptop passkey",
    )
    assert registration_call["expected_rp_id"] == "example.test"
    assert registration_call["expected_origin"] == "https://admin.example.test"
    assert registration_call["require_user_verification"] is True
    assert len(passkey.public_id) == 32
    assert not hasattr(passkey, "credential_id")
    assert store.list_passkeys(account.account_id) == (passkey,)

    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        stored_challenge_count = connection.execute(
            "SELECT COUNT(*) FROM auth_passkey_challenges"
        ).fetchone()[0]
        stored_credential_id = connection.execute(
            "SELECT credential_id FROM auth_passkey_credentials"
        ).fetchone()[0]
    assert stored_challenge_count == 0
    assert stored_credential_id == credential_id
    assert credential_id not in bytes.fromhex(passkey.public_id)

    login = store.begin_passkey_login()
    assert login.options["rpId"] == "example.test"
    assert login.options["userVerification"] == "required"
    assert login.options["allowCredentials"] == []
    authentication_calls: list[dict[str, object]] = []

    def verify_authentication(**kwargs: object) -> VerifiedAuthentication:
        authentication_calls.append(dict(kwargs))
        return _verified_authentication(credential_id, len(authentication_calls))

    monkeypatch.setattr(auth_module, "verify_authentication_response", verify_authentication)
    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        session_count_before = connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[
            0
        ]
    identity = store.verify_passkey_login(
        login.challenge_token,
        _authentication_credential(credential_id, account.account_id),
    )
    assert identity.account_id == account.account_id
    assert identity.email == account.email
    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0]
            == session_count_before
        )
    passkey_session = store.issue_verified_passkey_session(
        identity,
        client_ip="203.0.113.20",
        user_agent="Passkey Browser",
    )
    assert passkey_session.principal.step_up_until == 0
    assert passkey_session.principal.client_ip == "203.0.113.20"
    assert authentication_calls[0]["expected_origin"] == "https://admin.example.test"
    assert authentication_calls[0]["require_user_verification"] is True
    with pytest.raises(InvalidChallengeError):
        store.complete_passkey_login(
            login.challenge_token,
            _authentication_credential(credential_id, account.account_id),
        )

    step_up = store.begin_passkey_step_up(passkey_session.token)
    with pytest.raises(InvalidChallengeError):
        store.complete_passkey_step_up(
            totp_session,
            step_up.challenge_token,
            _authentication_credential(credential_id, account.account_id),
        )
    elevated = store.complete_passkey_step_up(
        passkey_session.token,
        step_up.challenge_token,
        _authentication_credential(credential_id, account.account_id),
    )
    assert elevated.step_up_until == clock.value + STEP_UP_SECONDS
    assert store.require_step_up(passkey_session.token).account_id == account.account_id


def test_passkey_counter_rollback_failure_limit_and_expiry(
    store_factory: StoreFactory,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = store_factory(
        webauthn_rp_id="example.test",
        webauthn_origin="https://example.test",
    )
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    session = _login(store, account.email, enrollment.secret, clock)
    store.mark_step_up(session)
    credential_id = b"counter-passkey"
    registration = store.begin_passkey_registration(session)
    monkeypatch.setattr(
        auth_module,
        "verify_registration_response",
        lambda **_kwargs: _verified_registration(credential_id, sign_count=7),
    )
    store.complete_passkey_registration(
        session,
        registration.challenge_token,
        _registration_credential(credential_id),
    )

    login = store.begin_passkey_login()
    monkeypatch.setattr(
        auth_module,
        "verify_authentication_response",
        lambda **_kwargs: _verified_authentication(credential_id, 7),
    )
    assertion = _authentication_credential(credential_id, account.account_id)
    for _ in range(CHALLENGE_FAILURE_LIMIT):
        with pytest.raises(InvalidPasskeyError):
            store.complete_passkey_login(login.challenge_token, assertion)
    with pytest.raises(InvalidChallengeError):
        store.complete_passkey_login(login.challenge_token, assertion)
    assert store.list_passkeys(account.account_id)[0].sign_count == 7

    expired = store.begin_passkey_login()
    clock.advance(CHALLENGE_LIFETIME_SECONDS)
    with pytest.raises(InvalidChallengeError):
        store.complete_passkey_login(expired.challenge_token, assertion)


def test_discoverable_passkey_login_is_account_unbound_and_requires_user_handle(
    store_factory: StoreFactory,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = store_factory(
        webauthn_rp_id="example.test",
        webauthn_origin="https://example.test",
    )
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    session = _login(store, account.email, enrollment.secret, clock)
    store.mark_step_up(session)
    credential_id = b"discoverable-passkey"
    registration = store.begin_passkey_registration(session)
    monkeypatch.setattr(
        auth_module,
        "verify_registration_response",
        lambda **_kwargs: _verified_registration(credential_id),
    )
    store.complete_passkey_registration(
        session,
        registration.challenge_token,
        _registration_credential(credential_id),
    )

    login = store.begin_passkey_login()
    assert login.options["allowCredentials"] == []
    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        stored = connection.execute(
            """
            SELECT purpose, account_id, session_digest
            FROM auth_passkey_challenges
            WHERE purpose = 'login'
            """
        ).fetchone()
    assert stored == ("login", None, None)

    missing_handle = AuthenticationCredential(
        id=_encode_base64url(credential_id),
        raw_id=credential_id,
        response=AuthenticatorAssertionResponse(
            client_data_json=b"test-client-data",
            authenticator_data=b"test-authenticator-data",
            signature=b"test-signature",
            user_handle=None,
        ),
    )
    with pytest.raises(InvalidPasskeyError):
        store.complete_passkey_login(login.challenge_token, missing_handle)


def test_anonymous_login_challenge_eviction_is_isolated_from_session_ceremonies(
    store_factory: StoreFactory,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = store_factory(
        webauthn_rp_id="example.test",
        webauthn_origin="https://example.test",
    )
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    session = _login(store, account.email, enrollment.secret, clock)
    store.mark_step_up(session)
    registration = store.begin_passkey_registration(session)

    for _ in range(auth_module._MAX_ANONYMOUS_PASSKEY_LOGIN_CHALLENGES + 1):
        store.begin_passkey_login()

    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        counts = dict(
            connection.execute(
                """
                SELECT purpose, COUNT(*)
                FROM auth_passkey_challenges
                GROUP BY purpose
                """
            ).fetchall()
        )
    assert counts == {
        "login": auth_module._MAX_ANONYMOUS_PASSKEY_LOGIN_CHALLENGES,
        "registration": 1,
    }

    credential_id = b"registration-survives-login-pressure"
    monkeypatch.setattr(
        auth_module,
        "verify_registration_response",
        lambda **_kwargs: _verified_registration(credential_id),
    )
    registered = store.complete_passkey_registration(
        session,
        registration.challenge_token,
        _registration_credential(credential_id),
    )
    assert registered.account_id == account.account_id


def test_account_unbound_passkey_login_has_dedicated_global_and_ip_rate_buckets(
    store_factory: StoreFactory,
) -> None:
    store = store_factory()
    client_ip = "203.0.113.77"
    for _ in range(30):
        store.check_passkey_login_rate(client_ip)
    with pytest.raises(LoginRateLimitedError):
        store.check_passkey_login_rate(client_ip)

    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        rows = connection.execute(
            """
            SELECT scope, account_id, account_identity_digest
            FROM auth_login_rate_limits
            ORDER BY scope
            """
        ).fetchall()
    assert rows == [("global", None, None), ("ip", None, None)]

    store.record_passkey_login_result(client_ip, success=True)
    store.check_passkey_login_rate(client_ip)


def test_passkey_limit_and_https_configuration(
    store_factory: StoreFactory,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        store_factory(
            name="bad-origin.db",
            webauthn_rp_id="example.test",
            webauthn_origin="http://example.test",
        )
    store = store_factory(
        webauthn_rp_id="example.test",
        webauthn_origin="https://example.test",
    )
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    session = _login(store, account.email, enrollment.secret, clock)
    store.mark_step_up(session)
    for index in range(MAX_PASSKEYS_PER_ACCOUNT):
        credential_id = f"credential-{index}".encode()
        verified_registration = _verified_registration(credential_id)
        registration = store.begin_passkey_registration(session)
        monkeypatch.setattr(
            auth_module,
            "verify_registration_response",
            lambda value=verified_registration, **_kwargs: value,
        )
        store.complete_passkey_registration(
            session,
            registration.challenge_token,
            _registration_credential(credential_id),
            name=f"Passkey {index}",
        )
    with pytest.raises(PasskeyLimitError):
        store.begin_passkey_registration(session)


def test_rate_limit_pair_is_atomic_and_success_clears_only_pair(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    email = "user@example.test"
    client_ip = "203.0.113.9"

    for _ in range(10):
        store.check_login_rate(email, client_ip)
        store.record_login_result(email, client_ip, success=False)
    with pytest.raises(LoginRateLimitedError) as caught:
        store.check_login_rate(email, client_ip)
    assert caught.value.retry_after == 15 * 60

    store.record_login_result(email, client_ip, success=True)
    store.check_login_rate(email, client_ip)
    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        assert (
            connection.execute(
                """
            SELECT COUNT(*) FROM auth_login_rate_limits
            WHERE scope = 'global'
            """
            ).fetchone()[0]
            == 1
        )

    database_bytes = (store_factory.tmp_path / "auth.db").read_bytes()
    assert client_ip.encode("ascii") not in database_bytes


def test_rate_limit_account_ip_and_global_layers(
    store_factory: StoreFactory,
) -> None:
    account_store = store_factory(name="account.db")
    for index in range(15):
        account_store.check_login_rate(
            "same@example.test",
            f"203.0.113.{index + 1}",
        )
    with pytest.raises(LoginRateLimitedError):
        account_store.check_login_rate("same@example.test", "203.0.113.200")

    ip_store = store_factory(name="ip.db")
    for index in range(30):
        ip_store.check_login_rate(f"user{index}@example.test", "198.51.100.4")
    with pytest.raises(LoginRateLimitedError):
        ip_store.check_login_rate("user30@example.test", "198.51.100.4")

    global_store = store_factory(name="global.db")
    for index in range(120):
        global_store.check_login_rate(
            f"user{index}@example.test",
            f"198.18.{index // 250}.{index % 250 + 1}",
        )
    with pytest.raises(LoginRateLimitedError) as caught:
        global_store.check_login_rate("last@example.test", "198.19.0.1")
    assert caught.value.retry_after == 5 * 60


def test_rate_limits_persist_and_expire_on_fixed_window(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    first = store_factory(seed=b"rate-first")
    for _ in range(10):
        first.check_login_rate("user@example.test", "203.0.113.10")
    first.close()

    second = store_factory(seed=b"rate-second")
    with pytest.raises(LoginRateLimitedError) as caught:
        second.check_login_rate("USER@example.test", "203.0.113.10")
    assert caught.value.retry_after == 15 * 60
    clock.advance(15 * 60)
    second.check_login_rate("user@example.test", "203.0.113.10")


def test_rate_limit_check_prunes_all_expired_identity_rows(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    for index in range(20):
        store.check_login_rate(
            f"expired-{index}@example.test",
            f"2001:db8::{index + 1}",
        )
    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM auth_login_rate_limits").fetchone()[0] == 61

    clock.advance(15 * 60)
    store.check_login_rate("current@example.test", "2001:db8::ffff")
    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM auth_login_rate_limits").fetchone()[0] == 4


def test_rate_limit_table_is_trimmed_and_fails_closed_at_capacity(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    path = store_factory.tmp_path / "auth.db"
    with sqlite3.connect(path) as connection:
        connection.executemany(
            """
            INSERT INTO auth_login_rate_limits(
                scope, identity_digest, window_started_at, attempt_count
            ) VALUES ('ip', ?, ?, 1)
            """,
            (
                (hashlib.sha256(f"identity-{index}".encode("ascii")).digest(), clock.value)
                for index in range(1030)
            ),
        )

    with pytest.raises(LoginRateLimitedError):
        store.check_login_rate("current@example.test", "203.0.113.250")
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM auth_login_rate_limits").fetchone()[0] == 1024
        )


def test_delete_account_removes_only_linked_authentication_metadata(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    store.check_login_rate("user@example.test", "203.0.113.10")
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    _login(store, account.email, enrollment.secret, clock)
    store.create_pending_challenge(account.email)
    store.check_login_rate(account.email, "203.0.113.11")

    store.delete_account(account.account_id)
    assert store.get_account(account.email) is None
    with sqlite3.connect(store_factory.tmp_path / "auth.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM auth_pending_challenges").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM auth_recovery_codes").fetchone()[0] == 0
        assert (
            connection.execute(
                """
            SELECT COUNT(*) FROM auth_login_rate_limits
            WHERE account_id = ?
            """,
                (account.account_id,),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                """
            SELECT COUNT(*) FROM auth_login_rate_limits
            WHERE scope IN ('account', 'pair')
            """
            ).fetchone()[0]
            == 0
        )

    with pytest.raises(AccountNotFoundError):
        store.delete_account(account.account_id)


def test_reset_totp_clears_factors_challenges_and_sessions(
    store_factory: StoreFactory,
    clock: FakeClock,
) -> None:
    store = store_factory()
    account, enrollment, _codes = store.provision_active_account("user@example.test")
    token = _login(store, account.email, enrollment.secret, clock)
    store.create_pending_challenge(account.email)

    reset = store.reset_totp(account.account_id)
    assert reset.enrollment_state is EnrollmentState.REQUIRED
    with pytest.raises(InvalidSessionError):
        store.authenticate_session(token)
    challenge = store.create_pending_challenge(account.email)
    with pytest.raises(EnrollmentStateError):
        store.complete_totp_challenge(
            challenge,
            totp_code(enrollment.secret, timestamp=clock.value),
        )


def test_private_database_and_master_key_invariants(
    store_factory: StoreFactory,
) -> None:
    store = store_factory()
    store.create_account("user@example.test")
    store.close()
    path = store_factory.tmp_path / "auth.db"

    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(MasterKeyError):
        store_factory(master_key=OTHER_MASTER_KEY, seed=b"wrong-key")


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership semantics")
def test_database_rejects_symlinks_and_writable_parent(
    tmp_path: Path,
    clock: FakeClock,
) -> None:
    tmp_path.chmod(0o700)
    target = tmp_path / "target.db"
    store = AuthStore(
        target,
        MASTER_KEY,
        "MaddyWeb",
        clock=clock,
        random_bytes=DeterministicRandom(),
    )
    store.close()
    link = tmp_path / "link.db"
    link.symlink_to(target)
    with pytest.raises(DatabaseSecurityError):
        AuthStore(link, MASTER_KEY, "MaddyWeb")

    insecure = tmp_path / "insecure"
    insecure.mkdir(mode=0o700)
    insecure.chmod(0o777)
    with pytest.raises(DatabaseSecurityError):
        AuthStore(insecure / "auth.db", MASTER_KEY, "MaddyWeb")


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link semantics")
def test_database_rejects_hard_links(
    tmp_path: Path,
    clock: FakeClock,
) -> None:
    tmp_path.chmod(0o700)
    target = tmp_path / "target.db"
    store = AuthStore(
        target,
        MASTER_KEY,
        "MaddyWeb",
        clock=clock,
        random_bytes=DeterministicRandom(),
    )
    store.close()
    hard_link = tmp_path / "linked.db"
    os.link(target, hard_link)

    with pytest.raises(DatabaseSecurityError, match="single-link"):
        AuthStore(target, MASTER_KEY, "MaddyWeb")


def test_store_rejects_bad_inputs_and_use_after_close(
    store_factory: StoreFactory,
) -> None:
    store = store_factory()
    account = store.create_account("user@example.test")

    with pytest.raises(ValueError):
        store.set_role(account.account_id, "owner")
    with pytest.raises(ValueError):
        store.resolve_account_id(account.account_id.upper())
    with pytest.raises(ValueError):
        store.check_login_rate(account.email, "not-an-ip")
    with pytest.raises(ValueError):
        decode_totp_secret("ABC")

    store.close()
    with pytest.raises(RuntimeError, match="closed"):
        store.list_accounts()
