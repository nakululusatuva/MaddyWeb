from __future__ import annotations

import os
from pathlib import Path
from typing import Any, BinaryIO

import pytest

from maddyweb.config import AppConfig
from maddyweb.gateway import HelperGateway
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
    assert [request.operation for request in client.requests] == [
        "maddy.version",
        "accounts.list",
        "certificates.health",
    ]
    account_probe = client.requests[1]
    assert account_probe.params == {"include_append_limits": False}


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
                        "timer": {"enabled": True, "active_state": "active"},
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
