# QualityCI

**Industrial quality regression infrastructure for engineering changes.**

QualityCI turns a manufacturing engineering change or quality event into a
repeatable, evidence-grounded regression across process flow, PFMEA, control
plan, SOP, and inspection records. Missing or conflicting evidence blocks the
gate; high-risk revisions must be explicitly approved and replayed before a
candidate baseline can be created.

> This repository is the curated public source distribution. It is separate
> from the byte-frozen competition archive, which remains unchanged and is
> identified independently by its SHA-256 digest.

## What it does

- Compiles one change event into an explicit cross-document impact plan.
- Evaluates seven deterministic rules with `PASS`, `CONTRADICTED`, and
  `UNVERIFIABLE` outcomes.
- Carries source, version, locator, and hash evidence with each finding.
- Keeps unbound serialized cases in evaluation-only mode.
- Requires exact approval bindings and a successful replay before baseline
  creation.
- Produces a four-role local deterministic collaboration trace. AgentTeams
  runtime integration is a next-stage adapter, not a current claim.

## Quick start

QualityCI requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

Run the source-rooted synthetic fixture:

```bash
QCI_TMP="$(mktemp -d)"
python -m qualityci.cli run \
  --case-source-manifest tests/fixtures/case_builder/manifest.json \
  --validation-manifest tests/fixtures/case_builder/validation_manifest.json \
  --output "$QCI_TMP/source-run.json" \
  --db "$QCI_TMP/audit.sqlite"
python -m qualityci.cli audit --db "$QCI_TMP/audit.sqlite"
```

## Demos

- `site/` is a static contract walkthrough assembled from public-entry fields
  for synthetic cases. It is not a raw run log; it uploads nothing, calls no
  model, and exposes no Python API.
- `apps/web_demo/` and `qualityci.web_demo` provide the richer local demo. The
  server deliberately binds only to loopback and must not be exposed directly
  to a LAN or the public Internet.

The local Web Demo is a repository-checkout demo and is not included as a
standalone wheel asset.

Start the local demo:

```bash
PYTHONPATH=src python3 -m qualityci.web_demo
```

Then open `http://127.0.0.1:8765`.

## Repository map

```text
src/qualityci/       Core engine, ingestion, workflow, store, and CLI
schemas/             Versioned exchange and audit contracts
datasets/            Clearly marked synthetic regression cases
tests/               Public contract and safety tests
apps/web_demo/       Loopback-only local application
site/                Static public landing page and contract walkthrough
docs/                Public architecture, benchmark, and threat-model notes
```

## Evidence and claim boundary

The included benchmark contains 30 synthetic mutations and 210 rule-state
expectations jointly developed with the implementation. It is an engineering
regression suite, not independent evidence of factory accuracy, product safety,
recall prevention, ROI, or production readiness. A `PASS` means the current
rules and supplied evidence agree; it never approves process parameters or
authorizes product release.

The public facts used to frame the synthetic scenario are cited, but official
documents, logos, screenshots, customer files, and supplier materials are not
redistributed. See [DATA_NOTICE.md](DATA_NOTICE.md) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Security

QualityCI treats path traversal, link/junction escapes, duplicate JSON keys,
non-finite numbers, signature or approval bypass, audit-chain tampering, and
unsafe demo exposure as security boundaries. See [SECURITY.md](SECURITY.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

Copyright 2026 上海擎鼎曜晶智能科技有限公司.

Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE),
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and
[DATA_NOTICE.md](DATA_NOTICE.md) for attribution and data-source boundaries.
