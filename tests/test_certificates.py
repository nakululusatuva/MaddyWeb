from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from maddyweb.certificates import (
    CertificateCommandError,
    CertificateError,
    CertificateManager,
    UnknownCertificate,
)
from maddyweb.maddy import (
    CliFingerprint,
    CommandResult,
    LegacyLDAPUnsafe,
    MaddyService,
    MaddyTarget,
    SemVer,
)

CERTIFICATE_1 = b"""-----BEGIN CERTIFICATE-----
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

PRIVATE_KEY_1 = b"""-----BEGIN PRIVATE KEY-----
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

CERTIFICATE_2 = b"""-----BEGIN CERTIFICATE-----
MIIDMTCCAhmgAwIBAgIUclZMhexGmUffTWYNW6Cu5X0Ce2swDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPbXguZXhhbXBsZS50ZXN0MB4XDTI2MDcyMjEwMTEzOVoX
DTM2MDcxOTEwMTEzOVowGjEYMBYGA1UEAwwPbXguZXhhbXBsZS50ZXN0MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtA+93ng342ROauRMxXcICGpvf1t6
GcJak1cvEREdY1EZ3WwuEWrk70Weowm1CgQ9E6QC9Scfm7MYaB6WgUoWod58B7Aj
qMUHUY/IO64AI2JIf1dMc5DouZanK/mMgCCgdIuqT/6U4hgQ+991W3oinNP+FbnZ
Wyqtjm0NexGDRRiWUjNJ2UI7JnkrN2/9hoJX5Yr1Rbbi5jX6xc/pZJGjRRSnbF0E
DymJU/b5LRLFLPErCpCfFoasNkHW30Gp/1BmXjQYYpgvaTwIIGxsjNyvWSzZBTM1
1oooQSarUG2+qYcqqn3WB4GyiyxtwjVEMGyS5x6QHSavDcYFj8WoCTm5NQIDAQAB
o28wbTAdBgNVHQ4EFgQUqkfH66SxXnfXLJNmxi4IdTrLQE4wHwYDVR0jBBgwFoAU
qkfH66SxXnfXLJNmxi4IdTrLQE4wDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzAR
gg9teC5leGFtcGxlLnRlc3QwDQYJKoZIhvcNAQELBQADggEBAKXaWqG1uc/Ub7hw
ibLkZmeusubu7xRZlCEUYXCQkQSIpLqSQwfgT+ELmanPZwSOUfkFo3xkn7f37hWC
lbnJexWxW3FNVCGkDB9DMwDQdifNKdmPM2dFtnQ0noqOZYpaqtmfx1QRTGHx7T3U
xYHWXGg+P+3M5snE6iiH8XWU3MbyzZBQ9gAfsmOkgA6jy5uedBnBNhK1mEVGfu0y
aiifYfrr9O5osJfkW+rQhHbK2ILKbfnU81x6Cj/tgzJaL3w5jEpc8WPhJUcl2RWr
p9X3mK1emBBirIdexkWuNG9w8kf3C3wWAyHVjXQgT5hE0lq3o8me88v8oau7yA7j
jg2hLMQ=
-----END CERTIFICATE-----
"""

PRIVATE_KEY_2 = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0D73eeDfjZE5q
5EzFdwgIam9/W3oZwlqTVy8RER1jURndbC4RauTvRZ6jCbUKBD0TpAL1Jx+bsxho
HpaBShah3nwHsCOoxQdRj8g7rgAjYkh/V0xzkOi5lqcr+YyAIKB0i6pP/pTiGBD7
33VbeiKc0/4VudlbKq2ObQ17EYNFGJZSM0nZQjsmeSs3b/2GglflivVFtuLmNfrF
z+lkkaNFFKdsXQQPKYlT9vktEsUs8SsKkJ8Whqw2QdbfQan/UGZeNBhimC9pPAgg
bGyM3K9ZLNkFMzXWiihBJqtQbb6phyqqfdYHgbKLLG3CNUQwbJLnHpAdJq8NxgWP
xagJObk1AgMBAAECggEAI6nkhO5Rv3+sCn7qd8gCNsyCBfsj3XtBvmIrx9kYdYXo
NhOJslh2PLAQ4iD3kyLQyBWZol3b5FZeNK0uSTBX+DqdXVZ1UaWos+5jDfMCQv/h
9Rrg4RjoB24/8TVNr0kHDt5k3tBBQ+DZaFHTqEkyFtbkQgBb/TMgSg/udhw7YFFP
khKwxV0WgL/8PW6sl/eCQavsrY9UyKiFo7WO6blHYYaj9UDChAuzycOIo0RmWLJl
kRaPXf9VA8dtHyLrNLPWGFwTDIfNhBztI/gkcJzhXmlwt8Ay3pMz15LEzN83Fjf0
rWoeQARi6kd/O/08uWpzHWjcjXq7vZh6y3Y0s7Wp4QKBgQDoE8DchjuyizMeS86P
lOs3GA5kBwBuTvVyOkYY0leZzXLUXBIMnzfxivE+TPRL+Bm3q0ZhTodnarKI+qdy
zH9+TVk3K5tqNYlLGS68VgXN3MkUfED1hydp58e56ZedAEYl0rF1OFYFa6NYFOZW
G+Z23igzERGfbFl4xNrty1WPcQKBgQDGn1rudlIUuVH2cu8uuO/r6jU8ewgtGWQL
8Ab/PMwsk30m5MWuQ1afH1k+iGpAqW7AdyQhMXdELnxnHbTS1NckgnMicWCAxMYI
AMvTZyRPLuLukYHakb+bD6sAwJ67x3eSXCVozccL8Vk6r3Vkschk6QDlTIwoPzHe
oTmNfA6sBQKBgE6L6Pl6QRgzvrBhTd8Qsu9pp+045W9wL+hiSrk578YxX8z6AG3f
MYsB0JaaaxCPPv0H7gEfF/rrhNORqjzTc88mlKx0iNxQlFAjjMrXfo1nTXMufrna
7X8NoG6O3e6YWiWRAti+oXaiMJ2uLSs1tDHFDOwDuegwPrP+RG65JBMxAoGBAKOo
SlSSSa+pw08+BLaKy6WnpZXgCiye70Cm1h0ZC2LvY//YIMol0gnq2q4b2PDOquML
SEnRaGRVqUuNvqC5n0wF8LhAkzOG72VIwqm+Irzb9UB9xHFEBozNrClCjYhMIsoG
Aw0IASpmAw/H4wLFOklrc8F8AUBoUb8POUzLG4vBAoGAAb/3TjtNATgFl3HX8VfK
UKxa8IKLBlPqHSRnTcTm7yBdwrV9ERZaoB0gImsivCjXdS6lr13+GnSbYb6w19qs
IEY3Xfjclp+ctt2Kb5ApDjWssl5y/Mi6mqnVHaIHCgfxRIJ31BDwtMZwuQ6/37XX
jTsRZrHutHb6NETtXXwk6sw=
-----END PRIVATE KEY-----
"""


class CertRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.enabled = True
        self.active = True
        self.nginx_ok = True
        self.on_renew: Any = None

    def run(self, argv: Sequence[str], **_kwargs: Any) -> CommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        returncode = 0
        stdout = b""
        if argv[1:2] == ("is-enabled",):
            stdout = b"enabled\n" if self.enabled else b"disabled\n"
            returncode = 0 if self.enabled else 1
        elif argv[1:2] == ("is-active",):
            stdout = b"active\n" if self.active else b"inactive\n"
            returncode = 0 if self.active else 3
        elif argv[1:2] == ("enable",):
            self.enabled = self.active = True
        elif argv[1:2] == ("disable",):
            self.enabled = self.active = False
        elif argv[1:] == ("-t",):
            returncode = 0 if self.nginx_ok else 1
        elif "renew" in argv and "--dry-run" not in argv and self.on_renew is not None:
            self.on_renew()
        elif argv[1:] == ("--version",):
            stdout = b"certbot 4.0\n"
        return CommandResult(argv, returncode, stdout, b"", 0.001)


def make_manager(
    tmp_path: Path,
    *,
    runner: CertRunner | None = None,
    reload_callback: Any = None,
    deployment_mode: str = "native",
) -> tuple[CertificateManager, CertRunner, Path, Path]:
    runner = runner or CertRunner()
    name = "mx.example.test"
    live = tmp_path / "live"
    source = live / name
    deployed = tmp_path / "deployed"
    source.mkdir(parents=True)
    deployed.mkdir()
    (source / "fullchain.pem").write_bytes(CERTIFICATE_1)
    (source / "privkey.pem").write_bytes(PRIVATE_KEY_1)
    (deployed / "fullchain.pem").write_bytes(CERTIFICATE_1)
    (deployed / "privkey.pem").write_bytes(PRIVATE_KEY_1)
    os.chmod(source / "privkey.pem", 0o600)
    os.chmod(deployed / "privkey.pem", 0o600)
    manager = CertificateManager(
        allowed_names=(name,),
        live_dir=live,
        deployed_certificate_path=deployed / "fullchain.pem",
        deployed_private_key_path=deployed / "privkey.pem",
        timer_unit="certbot-renew.timer",
        runner=runner,
        reload_callback=reload_callback,
        deployment_mode=deployment_mode,
        audit=lambda *_args, **_kwargs: None,
    )
    return manager, runner, source, deployed


def test_status_has_timer_and_source_deployed_fingerprint(tmp_path: Path) -> None:
    manager, _runner, _source, _deployed = make_manager(tmp_path)
    status = manager.status("mx.example.test")
    assert status["error"] is None
    if os.name == "posix":
        assert status["private_key_permissions_safe"] is True
    assert status["fingerprints_match"] is True
    assert status["timer"]["enabled"] is True
    assert status["timer"]["active"] is True
    assert status["source"]["sha256_fingerprint"] == status["deployed"]["sha256_fingerprint"]
    with pytest.raises(UnknownCertificate):
        manager.status("attacker.example")
    assert not hasattr(manager, "install_pem")


def test_status_detects_a_mismatched_deployed_private_key(tmp_path: Path) -> None:
    manager, _runner, _source, deployed = make_manager(tmp_path)
    (deployed / "privkey.pem").write_bytes(PRIVATE_KEY_2)
    status = manager.status("mx.example.test")
    assert status["deployed"]["error"] is not None
    assert status["fingerprints_match"] is False


def test_timer_enable_disable_is_fixed_and_verified(tmp_path: Path) -> None:
    manager, runner, _source, _deployed = make_manager(tmp_path)
    disabled = manager.set_timer_enabled(False)
    assert disabled["enabled"] is False and disabled["active"] is False
    assert runner.calls[0] == ("/usr/bin/systemctl", "disable", "--now", "certbot-renew.timer")
    enabled = manager.set_timer_enabled(True)
    assert enabled["enabled"] is True and enabled["active"] is True


def test_dry_run_has_nginx_checks_and_no_force(tmp_path: Path) -> None:
    manager, runner, _source, _deployed = make_manager(tmp_path)
    manager.dry_run("mx.example.test")
    assert runner.calls[:3] == [
        ("/usr/sbin/nginx", "-t"),
        (
            "/usr/bin/certbot",
            "renew",
            "--dry-run",
            "--cert-name",
            "mx.example.test",
            "--non-interactive",
        ),
        ("/usr/sbin/nginx", "-t"),
    ]
    assert all("--force-renewal" not in call for call in runner.calls)


def test_nginx_failure_stops_before_certbot(tmp_path: Path) -> None:
    manager, runner, _source, _deployed = make_manager(tmp_path)
    runner.nginx_ok = False
    with pytest.raises(CertificateCommandError):
        manager.renew("mx.example.test")
    assert runner.calls == [("/usr/sbin/nginx", "-t")]


def test_not_due_reloads_to_repair_an_ambiguous_prior_reload(tmp_path: Path) -> None:
    reloaded: list[bool] = []
    manager, _runner, _source, deployed = make_manager(
        tmp_path, reload_callback=lambda: reloaded.append(True)
    )
    before = (deployed / "fullchain.pem").stat().st_mtime_ns
    result = manager.renew("mx.example.test")
    assert result["renewed"] is False
    assert result["renewal_result"] == "not_due"
    assert reloaded == [True]
    assert (deployed / "fullchain.pem").stat().st_mtime_ns == before


def test_not_due_synchronizes_a_stale_deployed_copy(tmp_path: Path) -> None:
    reloaded: list[bool] = []
    manager, _runner, source, deployed = make_manager(
        tmp_path, reload_callback=lambda: reloaded.append(True)
    )
    (source / "fullchain.pem").write_bytes(CERTIFICATE_2)
    (source / "privkey.pem").write_bytes(PRIVATE_KEY_2)
    result = manager.renew("mx.example.test")
    assert result["renewed"] is False
    assert result["renewal_result"] == "synchronized"
    assert result["fingerprints_match"] is True
    assert reloaded == [True]
    assert (deployed / "fullchain.pem").read_bytes() == CERTIFICATE_2


def test_reload_failure_restores_prior_native_material_and_reloads_it(tmp_path: Path) -> None:
    reload_attempts = 0

    def reload_with_first_failure() -> None:
        nonlocal reload_attempts
        reload_attempts += 1
        if reload_attempts == 1:
            raise RuntimeError("injected reload failure")

    manager, runner, source, deployed = make_manager(
        tmp_path, reload_callback=reload_with_first_failure
    )

    def rotate() -> None:
        (source / "fullchain.pem").write_bytes(CERTIFICATE_2)
        (source / "privkey.pem").write_bytes(PRIVATE_KEY_2)

    runner.on_renew = rotate
    with pytest.raises(CertificateCommandError, match="prior material was restored"):
        manager.renew("mx.example.test")
    assert reload_attempts == 2
    assert (deployed / "fullchain.pem").read_bytes() == CERTIFICATE_1
    assert (deployed / "privkey.pem").read_bytes() == PRIVATE_KEY_1


@pytest.mark.skipif(os.name != "posix", reason="POSIX dirfd safety contract")
def test_native_deploy_rejects_a_writable_or_symlinked_parent(tmp_path: Path) -> None:
    manager, _runner, source, deployed = make_manager(tmp_path, reload_callback=lambda: None)
    (source / "fullchain.pem").write_bytes(CERTIFICATE_2)
    (source / "privkey.pem").write_bytes(PRIVATE_KEY_2)
    deployed.chmod(0o777)
    with pytest.raises(CertificateError, match=r"trusted|writable"):
        manager.renew("mx.example.test")

    deployed.chmod(0o755)
    real_deployed = tmp_path / "real-deployed"
    deployed.rename(real_deployed)
    deployed.symlink_to(real_deployed, target_is_directory=True)
    with pytest.raises(CertificateError, match="safely"):
        manager.renew("mx.example.test")


def test_changed_renew_deploys_verifies_and_reloads(tmp_path: Path) -> None:
    reloaded: list[bool] = []
    manager, runner, source, deployed = make_manager(
        tmp_path, reload_callback=lambda: reloaded.append(True)
    )

    def rotate() -> None:
        (source / "fullchain.pem").write_bytes(CERTIFICATE_2)
        (source / "privkey.pem").write_bytes(PRIVATE_KEY_2)
        os.chmod(source / "privkey.pem", 0o600)

    runner.on_renew = rotate
    result = manager.renew("mx.example.test")
    assert result["renewed"] is True
    assert result["fingerprints_match"] is True
    assert reloaded == [True]
    assert (deployed / "fullchain.pem").read_bytes() == CERTIFICATE_2
    assert (deployed / "privkey.pem").read_bytes() == PRIVATE_KEY_2


def test_docker_deployment_paths_fail_closed_without_fixed_hooks(tmp_path: Path) -> None:
    reloaded: list[bool] = []
    manager, runner, _source, deployed = make_manager(
        tmp_path,
        reload_callback=lambda: reloaded.append(True),
        deployment_mode="docker",
    )
    original_certificate = (deployed / "fullchain.pem").read_bytes()
    status = manager.status("mx.example.test")
    assert status["deployed"]["error"] == (
        "deployed certificate status is unavailable in Docker mode"
    )
    assert status["fingerprints_match"] is False

    with pytest.raises(CertificateCommandError, match="fixed deployment and status hooks"):
        manager.renew("mx.example.test")

    assert runner.calls == [
        ("/usr/bin/systemctl", "is-enabled", "certbot-renew.timer"),
        ("/usr/bin/systemctl", "is-active", "certbot-renew.timer"),
    ]
    assert (deployed / "fullchain.pem").read_bytes() == original_certificate
    assert reloaded == []


def test_health_is_fixed_and_does_not_expose_paths(tmp_path: Path) -> None:
    manager, _runner, _source, _deployed = make_manager(tmp_path)
    health = manager.health()
    assert set(health) == {
        "certbot_available",
        "timer_enabled",
        "timer_active",
        "source_readable",
        "deployed_matches_source",
    }
    assert all(health.values())
    encoded = json.dumps(health)
    assert str(tmp_path) not in encoded


def test_health_keeps_fixed_schema_when_external_commands_fail(tmp_path: Path) -> None:
    class FailingRunner:
        @staticmethod
        def run(*_args: Any, **_kwargs: Any) -> Any:
            raise TimeoutError("unavailable")

    manager, _runner, _source, _deployed = make_manager(tmp_path)
    manager.runner = FailingRunner()
    health = manager.health()
    assert set(health) == {
        "certbot_available",
        "timer_enabled",
        "timer_active",
        "source_readable",
        "deployed_matches_source",
    }
    assert health["certbot_available"] is False
    assert health["timer_enabled"] is False
    assert health["timer_active"] is False


class OneResultRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], **_kwargs: Any) -> CommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        output = b"0.8.2 linux/amd64 go1.24\n" if argv[-1] == "version" else b""
        return CommandResult(argv, 0, output, b"", 0.001)


def test_legacy_ldap_blocks_account_writes_but_not_tls_reload(tmp_path: Path) -> None:
    config = tmp_path / "maddy.conf"
    config.write_text("auth.ldap local_authdb {}\n", encoding="utf-8")
    runner = OneResultRunner()
    service = MaddyService(
        MaddyTarget(mode="native", config_path=str(config), service_user=None),
        runner=runner,
        version=SemVer.parse("0.8.2"),
        cli_fingerprint=CliFingerprint("locked", ()),
    )
    with pytest.raises(LegacyLDAPUnsafe):
        service.change_password("user@example.test", "irrelevant")
    assert runner.calls == [("/usr/bin/maddy", "version")]
    service.reload()
    assert runner.calls[-1] == ("/usr/bin/systemctl", "reload", "maddy.service")
