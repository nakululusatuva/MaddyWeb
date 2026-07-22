from __future__ import annotations

import io
import socket
import struct
import threading

import pytest

from maddyweb.protocol import (
    DEFAULT_MAX_FRAME_BYTES,
    FrameTooLarge,
    ProtocolError,
    Request,
    Response,
    StreamError,
    StreamTooLarge,
    StreamTruncated,
    decode_payload,
    encode_frame,
    read_frame,
    receive_stream_frame,
    send_stream_frame,
)


class OneByteReader(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        return super().read(1 if size != 0 else 0)


class OverReadingSource(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        return super().read(-1 if size > 0 else size)


def test_json_frame_is_network_length_prefixed_and_partial_read_safe() -> None:
    message = {"version": 1, "text": "message", "ok": True}
    frame = encode_frame(message)
    assert struct.unpack("!I", frame[:4])[0] == len(frame) - 4
    assert read_frame(OneByteReader(frame)) == message


def test_control_frame_is_small_and_strict_json_object() -> None:
    assert DEFAULT_MAX_FRAME_BYTES == 64 * 1024
    with pytest.raises(FrameTooLarge):
        encode_frame({"value": "x" * DEFAULT_MAX_FRAME_BYTES})
    with pytest.raises(ProtocolError, match="object"):
        decode_payload(b"[]")
    with pytest.raises(ProtocolError):
        decode_payload(b'{"value":NaN}')
    with pytest.raises(ProtocolError):
        decode_payload(b"\xff")


def test_decode_converts_excessive_json_nesting_to_protocol_error() -> None:
    payload = b'{"nested":' + (b"[" * 2000) + b"0" + (b"]" * 2000) + b"}"
    with pytest.raises(ProtocolError):
        decode_payload(payload)


def test_request_and_response_are_versioned_and_closed() -> None:
    request = Request.create(
        "messages.append",
        {"username": "user@example.test", "mailbox": "Sent"},
        request_id="req-1",
        stream_length=123,
    )
    assert Request.from_payload(request.to_payload()) == request
    with pytest.raises(ProtocolError, match="unknown"):
        Request.from_payload({**request.to_payload(), "surprise": True})
    with pytest.raises(ProtocolError, match="version"):
        Request.from_payload({**request.to_payload(), "version": 2})
    response = Response.success("req-1", {"stream": True}, stream_length=55)
    assert Response.from_payload(response.to_payload()) == response
    with pytest.raises(ProtocolError):
        Response.from_payload(
            Response.failure("req-1", "failed", "safe").to_payload() | {"stream_length": 1}
        )
    with pytest.raises(ProtocolError, match="marker"):
        Response.from_payload(
            Response.success("req-1", {"value": "not-a-stream"}).to_payload() | {"stream_length": 1}
        )
    with pytest.raises(ProtocolError, match="marker"):
        Response.success("req-1", {"stream": True})


def _receive_in_thread(
    sock: socket.socket,
    destination: io.BytesIO,
    result: list[object],
    *,
    maximum: int = 1024,
) -> None:
    try:
        result.append(receive_stream_frame(sock, destination, max_stream_bytes=maximum))
    except BaseException as exc:
        result.append(exc)


def test_exact_binary_stream_round_trip() -> None:
    left, right = socket.socketpair()
    destination = io.BytesIO()
    result: list[object] = []
    thread = threading.Thread(
        target=_receive_in_thread,
        args=(right, destination, result),
    )
    thread.start()
    try:
        send_stream_frame(left, {"stream_length": 7, "kind": "message"}, io.BytesIO(b"payload"))
        left.shutdown(socket.SHUT_WR)
        thread.join(timeout=2)
        assert result == [({"stream_length": 7, "kind": "message"}, 7)]
        assert destination.getvalue() == b"payload"
    finally:
        left.close()
        right.close()


def test_declared_stream_too_long_is_truncated() -> None:
    left, right = socket.socketpair()
    try:
        left.sendall(encode_frame({"stream_length": 5}) + b"abc")
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(StreamTruncated):
            receive_stream_frame(right, io.BytesIO(), max_stream_bytes=10)
    finally:
        left.close()
        right.close()


def test_declared_stream_too_short_rejects_extra_wire_bytes() -> None:
    left, right = socket.socketpair()
    try:
        left.sendall(encode_frame({"stream_length": 3}) + b"abcd")
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(StreamError, match="beyond"):
            receive_stream_frame(right, io.BytesIO(), max_stream_bytes=10)
    finally:
        left.close()
        right.close()


def test_zero_and_oversized_stream_declarations_are_rejected() -> None:
    for length, error in ((0, StreamError), (11, StreamTooLarge)):
        left, right = socket.socketpair()
        try:
            left.sendall(encode_frame({"stream_length": length}))
            left.shutdown(socket.SHUT_WR)
            with pytest.raises(error):
                receive_stream_frame(right, io.BytesIO(), max_stream_bytes=10)
        finally:
            left.close()
            right.close()


def test_stream_sender_rejects_source_length_mismatch() -> None:
    left, right = socket.socketpair()
    try:
        with pytest.raises(StreamTruncated):
            send_stream_frame(left, {"stream_length": 5}, io.BytesIO(b"abc"))
        with pytest.raises(StreamError, match="beyond"):
            send_stream_frame(left, {"stream_length": 3}, io.BytesIO(b"abcd"))
        with pytest.raises(StreamError, match="more bytes"):
            send_stream_frame(left, {"stream_length": 3}, OverReadingSource(b"abcd"))
    finally:
        left.close()
        right.close()
