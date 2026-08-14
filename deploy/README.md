# Static deployment

The public site in `site/` is deliberately static. It performs no uploads,
creates no cookies, calls no model, and exposes no QualityCI Python endpoint.

`nginx-qualityci.conf.example` is a hardened starting point, not a drop-in
certificate configuration. Replace certificate and document-root placeholders
for the target server, validate the configuration, and keep `/api/` disabled.

The richer Python demo remains loopback-only and must not be bound to a public
interface.

The active `.github/workflows/ci.yml` workflow is fail-closed across
Ubuntu/Windows and Python 3.11/3.13. `github-actions-ci.yml.example` is retained
as the deployment-readable copy of the same policy.
