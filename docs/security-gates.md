# MaddyWeb Security Gates and Upstream Maddy Findings

This document records MaddyWeb's own deployment gates and the upstream Maddy image scan reported separately.
`HIGH` or `CRITICAL` findings in MaddyWeb source code, Python production dependencies, secrets, or configuration
continue to block a release; this repository has no `.trivyignore` or automatic suppression rule for them.

Under the security scope explicitly set by the project owner on 2026-07-22, the official Maddy binary and image are
independent upstream components. Their scan results must remain visible, but do not block MaddyWeb builds, commits,
or deployments. This scope adjustment does not lower the security gates for MaddyWeb or its root helper, nor change
the requirement that the Maddy version, CLI capability fingerprint, and integration tests pass.

## Automated gates

`.github/workflows/security.yml` pins the full commit SHA of the Trivy action and explicitly selects
the Trivy version. It checks:

- repository contents, dependency locks, secrets, and configuration errors;
- known Python vulnerabilities in `requirements.lock`;
- high-severity static findings in Python source code;
- the JSON frame, Maddy CLI, configuration, and MIME parsers with 20,000 deterministic mutation inputs;
- the exact Maddy 0.9.5 image digest in `tests/integration/maddy-image-lock.json`
  as an informational item.

The first four items are mandatory MaddyWeb release gates. The last item still scans the exact pinned digest and retains
the Trivy log in the GitHub Actions summary. Vulnerabilities or scanner failures produce information or warnings,
but do not fail the MaddyWeb security workflow. A malformed image lock file or a reference that is not a full digest
remains a repository integrity error and continues to block.

## Scan results from 2026-07-22

The pinned image was checked locally with Trivy 0.72.0 after verifying the release tarball against official checksums,
using the vulnerability database current on that date:

```text
ghcr.io/foxcpp/maddy@sha256:de42151adff6388edb5e4ee88f60334fa1ab85e309485193ecb1c2db20203315
Alpine packages: 0 HIGH/CRITICAL
Maddy Go binary: 31 HIGH, 2 CRITICAL (including with ignore-unfixed enabled)
```

The two critical findings include:

- `CVE-2025-68121`: Go standard library v1.23.12 in the image, affecting certificate validation during TLS session
  resumption. Trivy reports fixed versions beginning with Go 1.24.13 and 1.25.7.
- `CVE-2026-33186`: an authorization path validation issue in `google.golang.org/grpc` v1.70.0.
  Trivy reports version 1.79.3 as fixed.

These findings come from the pinned official Maddy 0.9.5 build, not MaddyWeb's Python dependencies. At the same time,
the repository filesystem scan reported zero `HIGH/CRITICAL` findings, and `pip-audit` reported zero known vulnerabilities.

## Disposition

These upstream findings are known and remain documented, but no longer block a MaddyWeb release or deployment. To
remove the upstream risk in the future, either:

1. adopt a new immutable upstream image that is functionally compatible and passes scanning, update the digest, and
   rerun the complete seven-version matrix; or
2. build a reviewed patched image from the Maddy 0.9.5 tag, upgrade the Go toolchain and affected modules,
   pin all build materials and the resulting digest, and rerun the same CLI, SMTP/IMAP, certificate, fault-injection,
   and Trivy checks.

Do not delete, falsify, or conceal image scan results. Before deployment, record the digest of the Maddy binary or image actually running
on the target VPS and its scan results. They support informed upstream risk acceptance and remediation,
not MaddyWeb's own security gate. Matrix compatibility does not make production Maddy 0.8.2 vulnerability-free.
