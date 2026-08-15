# Public deployment

The main walkthrough in `site/` is deliberately static. It performs no uploads,
creates no cookies, calls no model, and never exposes the loopback-only
`qualityci.web_demo` service.

`experience.html` adds a constrained leadership Q&A surface. The browser can
submit only three reviewed synthetic scenario IDs and four reviewed question
IDs to the exact route `POST /api/v1/leader-answer`. `leader_gateway.py` binds
only to `127.0.0.1` and this reviewed build returns pre-approved
`static_fallback` answers. It deliberately refuses to start in live mode. A
real provider requires a separate security, retention, budget, and output-
validation review; no API key belongs in this repository or in static assets.

`nginx-qualityci.conf.example` is a hardened starting point, not a drop-in
certificate configuration. Install `nginx-qualityci-limits.conf.example` in
the Nginx `http` context, install the gateway as a sandboxed systemd service,
replace certificate placeholders, and run `nginx -t` before every reload. The
single exact leader route is proxied to loopback; every other `/api` path stays
404.

The richer Python demo remains loopback-only and must not be bound to a public
interface.

The active `.github/workflows/ci.yml` workflow is fail-closed across
Ubuntu/Windows and Python 3.11/3.13. `github-actions-ci.yml.example` is retained
as the deployment-readable copy of the same policy.
