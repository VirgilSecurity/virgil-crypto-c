# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Report vulnerabilities privately by email to **support@VirgilSecurity.com** with `SECURITY` in the subject line.

Please include the affected version or commit, a description of the issue and its impact, and steps or a proof of
concept to reproduce it. We will acknowledge your report, keep you informed while we investigate, and credit you in
the release notes unless you prefer otherwise.

## Supported versions

Security fixes are released for the latest `0.x` release line. Please make sure you can reproduce the issue on the
latest release or on the `develop` branch.

## Scope

This policy covers the C libraries in this repository (`library/`) and the language wrappers in `wrappers/`.
Vulnerabilities in bundled third-party code (`thirdparty/`) should also be reported upstream; we will update the
bundled copy once a fix is available.
