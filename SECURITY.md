# Security policy

## Supported versions

Security fixes are prepared for the latest published release only. QualityCI
is an engineering prototype, not a production service, and does not carry a
commercial support commitment.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature. Do not open a public
issue for a suspected vulnerability or include exploit details in an ordinary
GitHub issue.

Please include the affected version or commit, the smallest reproducible input,
the expected security boundary, the observed result, and whether the issue can
cause data disclosure, unauthorized persistence, approval bypass, or audit
tampering.

High-priority areas include:

- path traversal, symlink, hardlink, or Windows junction escapes;
- malicious structured files, duplicate JSON keys, and resource exhaustion;
- signature, authorization, approval, or source-provenance bypass;
- audit-chain or persistence-integrity tampering;
- Web Demo host, origin, request-size, timeout, and concurrency boundaries.

We aim to acknowledge a complete report within three business days and provide
an initial severity assessment within seven business days. These targets are
best-effort and do not create a warranty, bounty, or safe-harbor program.

## Scope boundary

QualityCI is an engineering prototype. It is not a factory safety certification,
a professional approval system, or an automatic product-release controller.
