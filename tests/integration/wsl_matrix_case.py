#!/usr/bin/env python3
"""One read-only Maddy CLI compatibility case, invoked inside WSL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from maddyweb.maddy import MaddyService, MaddyTarget


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()

    target = MaddyTarget(
        mode="native",
        maddy_executable=str(args.binary),
        config_path=str(args.config),
        service_user=None,
    )
    service = MaddyService(target)
    detected = str(service.probe_version(refresh=True))
    if detected != args.expected_version:
        raise SystemExit(f"detected {detected}, expected {args.expected_version}")
    capabilities = service.capabilities()
    if any(item.value == "verify_config" for item in capabilities):
        verification = service.verify_config()
        validation = "verify-config"
    else:
        safety = service.startup_safety_status()
        if safety.get("writes_enabled") is not True:
            raise SystemExit("legacy Maddy CLI help profile rejected writes")
        verification = ""
        validation = "help-profile-only"
    report = {
        "status": "ok",
        "version": detected,
        "capabilities": sorted(item.value for item in capabilities),
        "config_validation": validation,
        "verify_config_output_bytes": len(verification.encode("utf-8")),
    }
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
