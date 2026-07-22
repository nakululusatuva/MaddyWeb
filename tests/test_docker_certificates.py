from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from maddyweb.certificates import CertificateCommandError, UnknownCertificate
from maddyweb.docker_certificates import DockerCertificateAdapter
from maddyweb.maddy import CommandResult

CERTIFICATE = b"""-----BEGIN CERTIFICATE-----
MIIDMTCCAhmgAwIBAgIUOv7Joo15bMp5xH6bEU3jbnLtiCcwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPbXguZXhhbXBsZS50ZXN0MB4XDTI2MDcyMjEwMTA1OFoX
DTM2MDcxOTEwMTA1OFowGjEYMBYGA1UEAwwPbXguZXhhbXBsZS50ZXN0MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA03v2aepQH4fz+ePF4r1SnUEHML2e
DmdaMi2dUrk+jdAKiXnU1uYCdWoOUYUP6feLHzdY5IsBqwzEx8cmNUeAaKWSna3e
K6udl+3wQHeub5MN1TSEm317jeCQTIITYmB6foFTXD+2B4fPdhaR4mD0Bb1rpdn3
6p2cz6LAWWADQdPw3haV1TeUDMvNUvEMNpIvJllcNYvkmUadjBwHjWNaM8R1qqD+
lcTPUakuaqU2BpZY2r01NteiggGTrLTHbGBvKjik8QBlCI1oVvRB/UEHKARnwJI9
jSy8/0zidmaICPWqJmdk/46EFIbl3fPZ1spyUbfNZUlydNPYy0Yrxky4VwIDAQAB
o28wbTAdBgNVHQ4EFgQUIEUNH96E4842XbA270G+2I5xxkwwHwYDVR0jBBgwFoAU
IEUNH96E4842XbA270G+2I5xxkwwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzAR
gg9teC5leGFtcGxlLnRlc3QwDQYJKoZIhvcNAQELBQADggEBAGP2Oo3oRd3ZfakS
u3BjaIsG1GO+gt9sypXSo73k3wqpDB5FS9r8nCBV+4cKq5UDaXm5jhO7NsJ5c/hu
q1MJY6+nvCti3xXnaw4KRyfcV05VgxG6n60ypu5UQDyoRmziodqxc2Q8CtDiqIKZ
hAhg93NO1dZ7udN4S9aIaUVp99olEFEwm9Eb/n7TZI6RyD6wn0Y1jAE6lb0RZJST
WsYqLF/wRZRWe4/a6Zf2aCA6HJVROe9msRFrpNlldjLicNPeJzKmn1Y1LB2IC4X4
PZN+92iFMQ+xCdzGQUzU/0+WhRYkTkpYk1p27QpXDYHT1TXsrVTPuLEWAUaAlKum
kykNVXM=
-----END CERTIFICATE-----
"""

PRIVATE_KEY = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDTe/Zp6lAfh/P5
48XivVKdQQcwvZ4OZ1oyLZ1SuT6N0AqJedTW5gJ1ag5RhQ/p94sfN1jkiwGrDMTH
xyY1R4BopZKdrd4rq52X7fBAd65vkw3VNISbfXuN4JBMghNiYHp+gVNcP7YHh892
FpHiYPQFvWul2ffqnZzPosBZYANB0/DeFpXVN5QMy81S8Qw2ki8mWVw1i+SZRp2M
HAeNY1ozxHWqoP6VxM9RqS5qpTYGlljavTU216KCAZOstMdsYG8qOKTxAGUIjWhW
9EH9QQcoBGfAkj2NLLz/TOJ2ZogI9aomZ2T/joQUhuXd89nWynJRt81lSXJ009jL
RivGTLhXAgMBAAECggEAXm1FEvmKGOoNJ5Bp9Nlvn8M/QKYJgojnHux7CEqqAYvY
iJWbUPCWPHLEPeXZuy/KMH/38uOWNReYbVMgXj20ugTjt/+/6WPRE9sroL1PZ4YT
cRTn+L1Ig4q3I1IY8Z3+U6nO3KudzTL4kNN3A8siacWv4Pe32EvTjmou1DkoeyUk
3CFzM0Ajs+08+Nquc9huKH82NGyHrEPhkHyCFpPuNZyIKQqWXGQyMeWuABaROpwM
d/DkvFCkaWRG9ZA2cYnFyuns9TrimXbSMs0bj7wCq/41MsWjLXpdLyPeHW1GwP+w
442cc4T3BxWlj/d/NBxIcez6igMFHbQZg0ufG8p1MQKBgQDttzkxjpVTT2Yl6p80
9ka+sktq3mScntKBuz7d6WnpmvR0qsD+xHcuyhQDsrKsy5PvtsZ5IbXkWingwA5v
hcc6l6/gFZWTklUYP49RUEJXojbRr4z+gkWZENoXTI8BF2zmLPijwy6QHxHznHn+
uaGw3L9i4K+UMf7eIstFEtmhKwKBgQDjwDlhOayaUwqgTYjgEKjtHK3ykYRvUoU0
blrJahx/Q3SH9VXP/U21nOCz5dZarY09oBOHbFe//hamgLwlCfVMZb6A8NXHibMF
3zwUzMX5V8cr/ZLrsbTq+5RcC6osTl60F/Xv9e/GOJHdBIY7zmjFz9Z8Muk1Ka2Q
pgVDwXN3hQKBgQDUzOzaPDXY+n8K+lnDY6Q5GgsBhEy1GEiB8kl5BnbVtO2ZczKJ
3v6CWExKczIYFbY9JXXPAip+XWiX1dYWZ7/N5/R9uVTJYnni1yNJO3voT0Kbu3eQ
brY3LCrQKKzr4TiPZTq//v4z7lx3pGBhc3QXi8WYkmMbWxY5bRRipVlFOQKBgQDE
AH0hODJcCdVeSfve4VeP4BuvYx53c6whiEtnhYOK3rGeBDxaqCNFhgI3sDg+h5fD
Dk1gQZRvLauulaHVunE502IUs683b0D7b7fUKrrCMJG/QRY88w3BIMv4Py2vva5x
DSHh5mT40VxuumMPez7d5lUvQ91BnGG717U2L3lAxQKBgEX86gr4T1aQAyEHai3m
rhbEpF32s4KH+ALH9Bg7TvoaUNhOvvDPy/lfnXAGH3tSI1T1cS1jg9R5gT0HL5sS
j5Y0nYcPqVD4B0RlW/igBSt4q4AJtV/KsVX83uG+5wE0jpkAqa5zto4En/QEHpEg
w5sTL9NKppYM/R9y80E7F7el
-----END PRIVATE KEY-----
"""


class FakeDockerRunner:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = dict(files)
        self.owners = dict.fromkeys(files, "1001:1002")
        self.modes = dict.fromkeys(files, "0600")
        self.calls: list[tuple[str, ...]] = []
        self.fail_key_move_once = False
        self.resolved_parents: dict[str, str] = {}

    @staticmethod
    def _result(argv: tuple[str, ...], returncode: int = 0, stdout: bytes = b"") -> CommandResult:
        return CommandResult(argv, returncode, stdout, b"", 0.001)

    def run(
        self,
        argv: Sequence[str],
        *,
        max_output_bytes: int,
        **_kwargs: Any,
    ) -> CommandResult:
        call = tuple(argv)
        self.calls.append(call)
        assert call[0] == "/usr/bin/docker"
        if call[1] == "cp":
            assert len(call) == 4
            container, destination = call[3].split(":", 1)
            assert container == "maddy-test"
            self.files[destination] = Path(call[2]).read_bytes()
            self.owners[destination] = "0:0"
            self.modes[destination] = "0600"
            return self._result(call)

        assert call[1:5] == ("exec", "--user", "0:0", "maddy-test")
        executable = call[5]
        arguments = call[6:]
        if executable == "/bin/true":
            return self._result(call)
        if executable == "/bin/cat":
            value = self.files.get(arguments[0])
            if value is None:
                return self._result(call, 1)
            assert len(value) <= max_output_bytes
            return self._result(call, stdout=value)
        if executable == "/bin/stat":
            owner = self.owners.get(arguments[2])
            return (
                self._result(call, 1)
                if owner is None
                else self._result(call, stdout=f"{owner}\n".encode())
            )
        if executable == "/usr/bin/readlink":
            _canonical, path = arguments
            resolved = self.resolved_parents.get(path, path)
            return self._result(call, stdout=f"{resolved}\n".encode())
        if executable == "/bin/chmod":
            mode, path = arguments
            if path not in self.files:
                return self._result(call, 1)
            self.modes[path] = mode
            return self._result(call)
        if executable == "/bin/chown":
            owner, path = arguments
            if path not in self.files:
                return self._result(call, 1)
            self.owners[path] = owner
            return self._result(call)
        if executable == "/bin/mv":
            _force, source, destination = arguments
            if self.fail_key_move_once and destination == "/data/tls/private-key.pem":
                self.fail_key_move_once = False
                return self._result(call, 1)
            if source not in self.files:
                return self._result(call, 1)
            self.files[destination] = self.files.pop(source)
            self.owners[destination] = self.owners.pop(source)
            self.modes[destination] = self.modes.pop(source)
            return self._result(call)
        if executable == "/bin/rm":
            for path in arguments[1:]:
                self.files.pop(path, None)
                self.owners.pop(path, None)
                self.modes.pop(path, None)
            return self._result(call)
        raise AssertionError(f"unexpected fixed command: {call!r}")


def make_adapter(
    tmp_path: Path,
) -> tuple[DockerCertificateAdapter, FakeDockerRunner, Path]:
    name = "mx.example.test"
    live = tmp_path / "live"
    source = live / name
    spool = tmp_path / "spool"
    source.mkdir(parents=True)
    spool.mkdir()
    (source / "fullchain.pem").write_bytes(CERTIFICATE + b"\n")
    (source / "privkey.pem").write_bytes(PRIVATE_KEY + b"\n")
    certificate_path = "/data/tls/fullchain.pem"
    private_key_path = "/data/tls/private-key.pem"
    runner = FakeDockerRunner(
        {
            certificate_path: CERTIFICATE,
            private_key_path: PRIVATE_KEY,
        }
    )
    runner.owners[certificate_path] = "1001:1002"
    runner.owners[private_key_path] = "1003:1004"
    adapter = DockerCertificateAdapter.from_config(
        SimpleNamespace(mode="docker", container="maddy-test", data_dir="/data"),
        SimpleNamespace(
            names=(name,),
            live_dir=live,
            deployed_cert_path=certificate_path,
            deployed_key_path=private_key_path,
        ),
        runner,
        spool,
        300.0,
    )
    return adapter, runner, spool


def test_status_reads_with_cat_without_exposing_paths_or_key(tmp_path: Path) -> None:
    adapter, runner, _spool = make_adapter(tmp_path)

    status = adapter.status()

    assert status.error is None
    assert status.exists is True and status.private_key_exists is True
    assert status.sha256_fingerprint
    assert status.certificate_path == ""
    assert status.private_key_path == ""
    encoded = json.dumps(status.to_dict())
    assert "/data/tls" not in encoded
    assert PRIVATE_KEY[:32].decode() not in encoded
    assert [call[5] for call in runner.calls if call[1] == "exec"] == [
        "/usr/bin/readlink",
        "/bin/true",
        "/bin/cat",
        "/bin/cat",
    ]


def test_successful_atomic_deployment_uses_fixed_argv_and_preserves_owner(
    tmp_path: Path,
) -> None:
    adapter, runner, spool = make_adapter(tmp_path)

    adapter.deploy("mx.example.test")

    assert runner.files["/data/tls/fullchain.pem"] == CERTIFICATE + b"\n"
    assert runner.files["/data/tls/private-key.pem"] == PRIVATE_KEY + b"\n"
    assert runner.owners["/data/tls/fullchain.pem"] == "1001:1002"
    assert runner.owners["/data/tls/private-key.pem"] == "1003:1004"
    assert runner.modes["/data/tls/fullchain.pem"] == "0644"
    assert runner.modes["/data/tls/private-key.pem"] == "0600"
    assert not tuple(spool.iterdir())
    assert not [path for path in runner.files if ".maddyweb-" in path]

    allowed_inner = {
        "/bin/true",
        "/bin/cat",
        "/bin/stat",
        "/usr/bin/readlink",
        "/bin/chmod",
        "/bin/chown",
        "/bin/mv",
        "/bin/rm",
    }
    for call in runner.calls:
        assert call[0] == "/usr/bin/docker"
        assert call[1] in {"cp", "exec"}
        if call[1] == "exec":
            assert call[2:5] == ("--user", "0:0", "maddy-test")
            assert call[5] in allowed_inner
        assert "/bin/sh" not in call


def test_successful_deployment_returns_one_shot_verified_rollback(tmp_path: Path) -> None:
    adapter, runner, _spool = make_adapter(tmp_path)
    old_files = dict(runner.files)
    old_owners = dict(runner.owners)

    rollback = adapter.deploy("mx.example.test")
    rollback()

    assert runner.files == old_files
    assert runner.owners == old_owners
    with pytest.raises(CertificateCommandError, match="already been used"):
        rollback()


def test_failed_second_move_restores_prior_pair_and_owner(tmp_path: Path) -> None:
    adapter, runner, spool = make_adapter(tmp_path)
    old_files = dict(runner.files)
    old_owners = dict(runner.owners)
    runner.fail_key_move_once = True

    with pytest.raises(CertificateCommandError, match="prior material was restored") as raised:
        adapter.deploy("mx.example.test")

    assert runner.files == old_files
    assert runner.owners == old_owners
    assert not tuple(spool.iterdir())
    assert "/data/tls/private-key.pem" not in str(raised.value)
    assert PRIVATE_KEY[:32].decode() not in str(raised.value)


def test_unknown_name_and_unsafe_paths_fail_before_docker(tmp_path: Path) -> None:
    adapter, runner, _spool = make_adapter(tmp_path)
    with pytest.raises(UnknownCertificate):
        adapter.deploy("attacker.example.test")
    assert runner.calls == []

    with pytest.raises(ValueError, match="private-key path"):
        DockerCertificateAdapter(
            container="maddy-test",
            allowed_names=("mx.example.test",),
            live_dir=tmp_path,
            data_dir="/data",
            deployed_certificate_path="/data/certificate.pem",
            deployed_private_key_path="/proc/self/environ",
            runner=runner,
            spool_dir=tmp_path,
        )


def test_target_must_be_under_data_dir_and_parent_must_be_canonical(
    tmp_path: Path,
) -> None:
    adapter, runner, _spool = make_adapter(tmp_path)
    runner.resolved_parents["/data/tls"] = "/outside/tls"

    with pytest.raises(CertificateCommandError, match="symbolic link"):
        adapter.deploy("mx.example.test")
    assert not [call for call in runner.calls if call[1] == "cp"]

    with pytest.raises(ValueError, match="inside the Maddy data directory"):
        DockerCertificateAdapter(
            container="maddy-test",
            allowed_names=("mx.example.test",),
            live_dir=tmp_path,
            data_dir="/data",
            deployed_certificate_path="/etc/certificate.pem",
            deployed_private_key_path="/data/private-key.pem",
            runner=runner,
            spool_dir=tmp_path,
        )
