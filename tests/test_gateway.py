from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path
from typing import Any, BinaryIO

import pytest

import maddyweb.gateway as gateway_module
from maddyweb.config import AppConfig
from maddyweb.gateway import HelperCallError, HelperGateway
from maddyweb.mail import DeliveryRejected, DeliveryUncertain, PreparedMessage
from maddyweb.protocol import Request, Response

FIXTURE_CREDENTIAL = "-".join(("account", "credential"))


class FakeClient:
    def __init__(self, responses: dict[str, Response], *, download: bytes = b"") -> None:
        self.responses = responses
        self.download = download
        self.requests: list[Request] = []
        self.uploads: list[bytes] = []

    def _response(self, request: Request) -> Response:
        self.requests.append(request)
        response = self.responses[request.operation]
        return Response(
            request.request_id,
            response.ok,
            response.result,
            response.error,
            response.stream_length,
        )

    def call(self, request: Request) -> Response:
        return self._response(request)

    def call_with_stream(self, request: Request, source: BinaryIO) -> Response:
        self.uploads.append(source.read())
        return self._response(request)

    def call_to_stream(self, request: Request, destination: BinaryIO) -> Response:
        destination.write(self.download)
        return self._response(request)


def config(*, certificates: bool = False) -> AppConfig:
    document: dict[str, Any] = {
        "maddy": {
            "mode": "docker",
            "helper_socket": "/tmp/maddyweb-test-helper.sock",  # noqa: S108
        },
    }
    if certificates:
        document["certificates"] = {
            "enabled": True,
            "names": ["mx.example.test"],
        }
    return AppConfig.from_dict(document)


def gateway_with(client: FakeClient, *, certificates: bool = False) -> HelperGateway:
    gateway = HelperGateway(config(certificates=certificates))
    gateway._client = client  # type: ignore[attr-defined]  # test seam
    gateway._certificate_client = client  # type: ignore[attr-defined]  # test seam
    return gateway


@pytest.mark.asyncio
async def test_health_has_fixed_schema_discards_accounts_and_is_cached() -> None:
    client = FakeClient(
        {
            "maddy.version": Response.success(
                "template",
                {"version": "0.9.5", "writes_enabled": True, "mode": "docker"},
            ),
            "accounts.list": Response.success(
                "template",
                [{"username": "must-not-leak@example.test"}],
            ),
            "certificates.health": Response.success(
                "template",
                {"certbot_available": True, "source_readable": True},
            ),
        }
    )
    gateway = gateway_with(client, certificates=True)
    first = await gateway.health()
    second = await gateway.health()
    accounts = await gateway.list_accounts()
    assert first == second
    assert set(first) == {
        "status",
        "version",
        "maddy_version",
        "maddy_write_enabled",
        "storage_available",
        "certbot_available",
        "certificate_management_enabled",
    }
    assert first["status"] == "ok"
    assert first["maddy_version"] == "0.9.5"
    assert first["storage_available"] is True
    assert first["certbot_available"] is True
    assert "must-not-leak" not in repr(first)
    assert accounts == ({"username": "must-not-leak@example.test"},)
    assert [request.operation for request in client.requests] == [
        "maddy.version",
        "accounts.list",
        "certificates.health",
        "accounts.list",
    ]
    account_probe = client.requests[1]
    assert account_probe.params == {"include_append_limits": False}


@pytest.mark.asyncio
async def test_health_cache_ttl_starts_after_slow_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]

    class SlowVersionClient(FakeClient):
        def call(self, request: Request) -> Response:
            response = super().call(request)
            if request.operation == "maddy.version":
                clock[0] += 6.0
            return response

    client = SlowVersionClient(
        {
            "maddy.version": Response.success(
                "template",
                {"version": "0.9.5", "writes_enabled": True, "mode": "docker"},
            ),
            "accounts.list": Response.success("template", []),
        }
    )
    monkeypatch.setattr(gateway_module.time, "monotonic", lambda: clock[0])
    gateway = gateway_with(client)
    first = await gateway.health()
    clock[0] = 11.0
    second = await gateway.health()
    assert second == first
    assert [request.operation for request in client.requests].count("maddy.version") == 1


@pytest.mark.asyncio
async def test_account_list_coalesces_and_returns_independent_snapshots() -> None:
    client = FakeClient(
        {
            "accounts.list": Response.success(
                "template",
                [
                    {
                        "username": "user@example.test",
                        "has_credentials": True,
                        "extension": {"roles": ["mail"]},
                    }
                ],
            ),
        }
    )
    gateway = gateway_with(client)
    results = await asyncio.gather(*(gateway.list_accounts() for _ in range(8)))
    assert [request.operation for request in client.requests] == ["accounts.list"]
    assert all(result == results[0] for result in results)
    first = results[0][0]
    assert isinstance(first, dict)
    first["username"] = "mutated@example.test"
    first["extension"]["roles"].append("poison")
    cached = await gateway.list_accounts()
    assert cached[0]["username"] == "user@example.test"  # type: ignore[index]
    assert cached[0]["extension"] == {"roles": ["mail"]}  # type: ignore[index]


@pytest.mark.asyncio
async def test_account_list_failure_is_single_flight() -> None:
    client = FakeClient(
        {
            "accounts.list": Response.failure(
                "template",
                "maddy_failed",
                "unavailable",
            ),
        }
    )
    gateway = gateway_with(client)
    results = await asyncio.gather(
        *(gateway.list_accounts() for _ in range(8)),
        return_exceptions=True,
    )
    assert len(client.requests) == 1
    assert all(isinstance(result, HelperCallError) for result in results)


@pytest.mark.asyncio
async def test_cancelled_account_list_waiter_does_not_cancel_shared_read() -> None:
    read_started = threading.Event()
    release_read = threading.Event()

    class BlockingClient(FakeClient):
        def call(self, request: Request) -> Response:
            self.requests.append(request)
            read_started.set()
            assert release_read.wait(timeout=2.0)
            return Response.success(
                request.request_id,
                [{"username": "user@example.test"}],
            )

    client = BlockingClient({})
    gateway = gateway_with(client)
    cancelled = asyncio.create_task(gateway.list_accounts())
    survivor = asyncio.create_task(gateway.list_accounts())
    try:
        assert await asyncio.to_thread(read_started.wait, 1.0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        release_read.set()
        assert await survivor == ({"username": "user@example.test"},)
        assert len(client.requests) == 1
    finally:
        release_read.set()


@pytest.mark.asyncio
async def test_cancelled_account_waiter_late_failure_has_no_loop_error() -> None:
    read_started = threading.Event()
    release_read = threading.Event()
    read_finished = threading.Event()

    class LateFailureClient(FakeClient):
        def call(self, request: Request) -> Response:
            self.requests.append(request)
            read_started.set()
            assert release_read.wait(timeout=2.0)
            read_finished.set()
            return Response.failure(
                request.request_id,
                "maddy_failed",
                "late read failure",
            )

    contexts: list[dict[str, Any]] = []
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))
    gateway = gateway_with(LateFailureClient({}))
    try:
        waiter = asyncio.create_task(gateway.list_accounts())
        assert await asyncio.to_thread(read_started.wait, 1.0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        release_read.set()
        assert await asyncio.to_thread(read_finished.wait, 1.0)
        for _attempt in range(100):
            if not gateway._account_read_tasks:  # type: ignore[attr-defined]
                break
            await asyncio.sleep(0.01)
        assert not gateway._account_read_tasks  # type: ignore[attr-defined]
        await asyncio.sleep(0)
        assert contexts == []
    finally:
        release_read.set()
        loop.set_exception_handler(previous_handler)


@pytest.mark.asyncio
@pytest.mark.parametrize("write_succeeds", (True, False))
async def test_account_mutation_always_invalidates_cached_list(write_succeeds: bool) -> None:
    mutation = (
        Response.success("template", {"created": True})
        if write_succeeds
        else Response.failure("template", "maddy_failed", "ambiguous")
    )
    client = FakeClient(
        {
            "accounts.list": Response.success("template", []),
            "accounts.create": mutation,
        }
    )
    gateway = gateway_with(client)
    await gateway.list_accounts()
    if write_succeeds:
        await gateway.create_account("user@example.test", "secret-value")
    else:
        with pytest.raises(HelperCallError):
            await gateway.create_account("user@example.test", "secret-value")
    await gateway.list_accounts()
    assert [request.operation for request in client.requests] == [
        "accounts.list",
        "accounts.create",
        "accounts.list",
    ]


@pytest.mark.asyncio
async def test_transport_failure_quarantines_cache_until_fresh_read() -> None:
    class TransportFailureClient(FakeClient):
        account_calls = 0

        def call(self, request: Request) -> Response:
            self.requests.append(request)
            if request.operation == "accounts.create":
                raise OSError("connection outcome is unknown")
            self.account_calls += 1
            return Response.success(
                request.request_id,
                [{"username": "user@example.test"}],
            )

    client = TransportFailureClient({})
    gateway = gateway_with(client)
    await gateway.list_accounts()
    with pytest.raises(OSError):
        await gateway.create_account("user@example.test", "secret-value")
    assert gateway._account_cache_quarantined is True  # type: ignore[attr-defined]
    await gateway.list_accounts()
    assert client.account_calls == 2
    assert gateway._account_cache_quarantined is False  # type: ignore[attr-defined]
    await gateway.list_accounts()
    assert client.account_calls == 2


@pytest.mark.asyncio
async def test_account_read_crossing_write_generation_cannot_repopulate_cache() -> None:
    read_started = threading.Event()
    release_read = threading.Event()

    class RacingClient(FakeClient):
        list_calls = 0

        def call(self, request: Request) -> Response:
            if request.operation != "accounts.list":
                return super().call(request)
            self.requests.append(request)
            self.list_calls += 1
            if self.list_calls == 1:
                read_started.set()
                assert release_read.wait(timeout=2.0)
                username = "old@example.test"
            else:
                username = "new@example.test"
            return Response.success(request.request_id, [{"username": username}])

    client = RacingClient(
        {
            "accounts.create": Response.success("template", {"created": True}),
        }
    )
    gateway = gateway_with(client)
    read_task = asyncio.create_task(gateway.list_accounts())
    assert await asyncio.to_thread(read_started.wait, 1.0)
    await gateway.create_account("new@example.test", "secret-value")
    release_read.set()
    first = await read_task
    assert first[0]["username"] == "new@example.test"  # type: ignore[index]
    second = await gateway.list_accounts()
    assert second[0]["username"] == "new@example.test"  # type: ignore[index]
    assert client.list_calls == 2


@pytest.mark.asyncio
async def test_cancelled_account_mutation_invalidates_after_helper_settles() -> None:
    mutation_started = threading.Event()
    finish_mutation = threading.Event()
    mutation_finished = threading.Event()
    read_captured = threading.Event()
    release_read = threading.Event()
    state = {"username": "old@example.test", "list_calls": 0}

    class CancellationClient(FakeClient):
        def call(self, request: Request) -> Response:
            self.requests.append(request)
            if request.operation == "accounts.create":
                mutation_started.set()
                assert finish_mutation.wait(timeout=2.0)
                state["username"] = "new@example.test"
                mutation_finished.set()
                return Response.success(request.request_id, {"created": True})
            if request.operation == "accounts.list":
                state["list_calls"] += 1
                username = state["username"]
                if state["list_calls"] == 1:
                    read_captured.set()
                    assert release_read.wait(timeout=2.0)
                return Response.success(request.request_id, [{"username": username}])
            raise AssertionError(f"unexpected operation: {request.operation}")

    client = CancellationClient({})
    gateway = gateway_with(client)
    try:
        mutation = asyncio.create_task(
            gateway.create_account("new@example.test", "secret-value")
        )
        assert await asyncio.to_thread(mutation_started.wait, 1.0)
        mutation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await mutation

        account_read = asyncio.create_task(gateway.list_accounts())
        await asyncio.sleep(0.05)
        assert account_read.done() is False
        assert state["list_calls"] == 0
        finish_mutation.set()
        assert await asyncio.to_thread(mutation_finished.wait, 1.0)
        for _attempt in range(100):
            if gateway._account_mutations_inflight == 0:  # type: ignore[attr-defined]
                break
            await asyncio.sleep(0.01)
        assert gateway._account_mutations_inflight == 0  # type: ignore[attr-defined]
        assert await asyncio.to_thread(read_captured.wait, 1.0)
        release_read.set()
        accounts = await asyncio.wait_for(account_read, timeout=1.0)
        assert accounts[0]["username"] == "new@example.test"  # type: ignore[index]
        assert state["list_calls"] == 1
    finally:
        finish_mutation.set()
        release_read.set()


@pytest.mark.asyncio
async def test_cancelled_account_mutation_late_failure_has_no_loop_error() -> None:
    mutation_started = threading.Event()
    release_mutation = threading.Event()
    mutation_finished = threading.Event()

    class LateTransportFailureClient(FakeClient):
        def call(self, request: Request) -> Response:
            self.requests.append(request)
            mutation_started.set()
            assert release_mutation.wait(timeout=2.0)
            mutation_finished.set()
            raise OSError("late transport failure")

    contexts: list[dict[str, Any]] = []
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))
    gateway = gateway_with(LateTransportFailureClient({}))
    try:
        mutation = asyncio.create_task(
            gateway.create_account("new@example.test", "secret-value")
        )
        assert await asyncio.to_thread(mutation_started.wait, 1.0)
        mutation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await mutation
        release_mutation.set()
        assert await asyncio.to_thread(mutation_finished.wait, 1.0)
        for _attempt in range(100):
            if not gateway._account_mutation_tasks:  # type: ignore[attr-defined]
                break
            await asyncio.sleep(0.01)
        assert not gateway._account_mutation_tasks  # type: ignore[attr-defined]
        assert gateway._account_cache_quarantined is True  # type: ignore[attr-defined]
        await asyncio.sleep(0)
        assert contexts == []
    finally:
        release_mutation.set()
        loop.set_exception_handler(previous_handler)


@pytest.mark.asyncio
async def test_health_storage_probe_bypasses_account_page_cache() -> None:
    class FailingSecondAccountRead(FakeClient):
        account_calls = 0

        def call(self, request: Request) -> Response:
            if request.operation != "accounts.list":
                return super().call(request)
            self.requests.append(request)
            self.account_calls += 1
            if self.account_calls == 1:
                return Response.success(
                    request.request_id,
                    [{"username": "cached@example.test"}],
                )
            return Response.failure(
                request.request_id,
                "maddy_failed",
                "storage unavailable",
            )

    client = FailingSecondAccountRead(
        {
            "maddy.version": Response.success(
                "template",
                {"version": "0.9.5", "writes_enabled": True, "mode": "docker"},
            ),
        }
    )
    gateway = gateway_with(client)
    assert await gateway.list_accounts()
    health = await gateway.health()
    assert health["status"] == "degraded"
    assert health["storage_available"] is False
    assert client.account_calls == 2


@pytest.mark.asyncio
async def test_health_preserves_version_when_storage_probe_fails() -> None:
    client = FakeClient(
        {
            "maddy.version": Response.success(
                "template",
                {"version": "0.8.2", "writes_enabled": True, "mode": "docker"},
            ),
            "accounts.list": Response.failure("template", "maddy_failed", "unavailable"),
        }
    )
    health = await gateway_with(client).health()
    assert health["maddy_version"] == "0.8.2"
    assert health["storage_available"] is False
    assert health["status"] == "degraded"


@pytest.mark.asyncio
async def test_message_page_preserves_authoritative_continuation() -> None:
    payload = {
        "items": [{"uid": 90, "subject": "one"}],
        "offset": 100,
        "limit": 50,
        "total": None,
        "next_offset": 90,
    }
    client = FakeClient({"messages.list": Response.success("template", payload)})
    gateway = gateway_with(client)
    result = await gateway.list_messages(
        "user@example.test",
        "INBOX",
        limit=50,
        offset=100,
    )
    assert result == payload
    assert client.requests[0].params["limit"] == 50
    assert client.requests[0].params["offset"] == 100


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="POSIX private-file mode and ownership contract")
async def test_raw_message_is_streamed_into_private_existing_file(tmp_path: Path) -> None:
    raw = b"From: sender@example.test\r\n\r\nbody\r\n"
    client = FakeClient(
        {
            "messages.get": Response.success(
                "template",
                {"stream": True},
                stream_length=len(raw),
            )
        },
        download=raw,
    )
    gateway = gateway_with(client)
    destination = tmp_path / "message.eml"
    destination.touch(mode=0o600)
    os.chmod(destination, 0o600)
    size = await gateway.spool_message(
        "user@example.test",
        "INBOX",
        "42",
        destination,
        max_bytes=1024,
    )
    assert size == len(raw)
    assert destination.read_bytes() == raw
    assert client.requests[0].params == {
        "username": "user@example.test",
        "mailbox": "INBOX",
        "uid": "42",
    }


def prepared(tmp_path: Path) -> PreparedMessage:
    path = tmp_path / "outgoing.eml"
    path.write_bytes(b"From: user@example.test\r\n\r\nbody\r\n")
    os.chmod(path, 0o600)
    return PreparedMessage(
        path=path,
        envelope_from="user@example.test",
        recipients=("recipient@example.test",),
        message_id="<message@example.test>",
        size=path.stat().st_size,
    )


@pytest.mark.asyncio
async def test_submission_and_sent_are_two_distinct_stream_operations(tmp_path: Path) -> None:
    client = FakeClient(
        {
            "messages.send": Response.success("template", {"accepted": True}),
            "messages.append": Response.success("template", {"uid": 7}),
        }
    )
    gateway = gateway_with(client)
    message = prepared(tmp_path)
    assert (
        await gateway.deliver_message(
            message,
            message.envelope_from,
            message.recipients,
            FIXTURE_CREDENTIAL,
        )
        == message.message_id
    )
    await gateway.save_sent(message)
    assert [request.operation for request in client.requests] == [
        "messages.send",
        "messages.append",
    ]
    assert client.requests[1].params["mailbox_special"] == "sent"
    assert client.uploads == [message.path.read_bytes(), message.path.read_bytes()]
    assert client.requests[0].params["password"] == FIXTURE_CREDENTIAL


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("code", "error_type"),
    [
        ("smtp_permanent_rejection", DeliveryRejected),
        ("smtp_temporary_rejection", DeliveryRejected),
        ("smtp_transport", DeliveryRejected),
        ("smtp_outcome_unknown", DeliveryUncertain),
        ("writes_disabled", DeliveryRejected),
        ("unsupported_maddy", DeliveryRejected),
        ("invalid_request", DeliveryRejected),
    ],
)
async def test_smtp_helper_codes_preserve_retry_semantics(
    tmp_path: Path,
    code: str,
    error_type: type[Exception],
) -> None:
    client = FakeClient({"messages.send": Response.failure("template", code, "safe failure")})
    gateway = gateway_with(client)
    message = prepared(tmp_path)
    with pytest.raises(error_type):
        await gateway.deliver_message(
            message,
            message.envelope_from,
            message.recipients,
            FIXTURE_CREDENTIAL,
        )


@pytest.mark.asyncio
async def test_certificate_status_flattens_source_and_deployed_fingerprints() -> None:
    client = FakeClient(
        {
            "certificates.list": Response.success(
                "template",
                [
                    {
                        "name": "mx.example.test",
                        "source": {
                            "not_after": "2030-01-01T00:00:00+00:00",
                            "sha256_fingerprint": "AA:BB",
                            "private_key_path": "/must/not/reach/browser.pem",
                        },
                        "deployed": {
                            "sha256_fingerprint": "AA:BB",
                            "certificate_path": "/must/not/reach/browser.crt",
                        },
                        "fingerprints_match": True,
                        "automation_safe": True,
                        "timer_enable_safe": True,
                        "timer": {"enabled": True, "active": True, "active_state": "active"},
                    }
                ],
            )
        }
    )
    gateway = gateway_with(client, certificates=True)
    result = await gateway.certificate_status()
    assert isinstance(result, dict)
    record = result["certificates"][0]
    assert record["source_fingerprint"] == "AA:BB"
    assert record["deployed_fingerprint"] == "AA:BB"
    assert "path" not in repr(record)
    assert result["timer_enabled"] is True
    assert result["timer_active"] is True
    assert result["timer_enable_safe"] is True
    assert record["automation_safe"] is True


@pytest.mark.asyncio
async def test_certificate_status_preserves_active_timer_when_disabled() -> None:
    client = FakeClient(
        {
            "certificates.list": Response.success(
                "template",
                [
                    {
                        "name": "mx.example.test",
                        "source": {},
                        "deployed": {},
                        "timer_enable_safe": False,
                        "timer": {
                            "enabled": False,
                            "active": True,
                            "active_state": "active",
                        },
                    }
                ],
            )
        }
    )
    gateway = gateway_with(client, certificates=True)
    result = await gateway.certificate_status()
    assert isinstance(result, dict)
    assert result["timer_enabled"] is False
    assert result["timer_active"] is True
    assert result["timer_state"] == "active"
