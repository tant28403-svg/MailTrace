# MailTrace Audit Notes

Date: 2026-11-04

This document records the correctness, privacy and reliability issues found
during a full audit of the project, together with the changes that were made.
It is intended to help future maintainers understand why the current code looks
the way it does.

## Scope

The audit covered the CLI, TUI, orchestrator, providers, reporting, schemas and
SQLite storage layers, and included a review of the build, lint and test
configuration.

## Fixed Issues

### Critical

- **Database schema was never created on a fresh install.** `Base.metadata`
  was imported but `create_all` was never called and the Alembic migration was
  not invoked automatically, so the CLI/TUI failed on a new machine. The
  database manager now bootstraps missing tables at initialization and is safe
  to call repeatedly.
- **Findings could be persisted before deduplication/correlation.** The old
  flow persisted raw provider output and then processed the in-memory copy, so
  the database and snapshots could disagree with the returned investigation.
  Processing now happens before persistence, and snapshot IDs match the stored
  findings.
- **Plaintext credentials could reach the database.** BreachDirectory returns
  plaintext passwords and password hashes. Only presence/type metadata is now
  stored; the original values are discarded before findings are created.
- **CLI confirmation did not satisfy the orchestrator guard.** `scan`
  confirmed externally and then called the orchestrator without
  `authorization_confirmed=True`, so the run failed whenever confirmation was
  enabled. Authorization is now passed through and domain scans confirm too.

### High

- **SQLite URL handling was broken on Windows.** The sync URL returned `None`
  for non-PostgreSQL URLs and paths were built with `:///` string assumptions.
  URL derivation and parent-directory creation are now handled explicitly for
  both async and sync engines.
- **Repository round trips lost relations.** History and report commands
  reconstructed investigations manually and the schema/database enumerations
  were not aligned. A mapper layer now converts models with eager-loaded
  relations, including evidence and correlations.
- **`Investigation` duplicated `target_email` into the database schema.** The
  field is transient (excluded from serialization); only the HMAC hash and
  masked target are persisted.
- **Duplicate SQLAlchemy indexes** referenced columns that did not exist on the
  models, so `create_all` crashed as soon as it was actually invoked.
- **TUI actions were placeholders.** History loaded hard-coded rows, export
  did nothing, settings were not persisted and provider toggles had no effect.
  These screens now use the real repositories, settings persistence and report
  generator.
- **Missing `ComposeResult` imports** broke the Textual screens at runtime.

### Medium

- GitHub search now searches both `author-email` and `committer-email`, merges
  results by SHA, and treats code search as best-effort so commit findings are
  not lost when code search is unavailable or unauthorized.
- Provider HTTP errors are chained (`raise ... from`) and rate-limit/auth
  responses preserve their specific status instead of being recorded as generic
  failures.
- HIBP, emailrep.io, Brave Search and VirusTotal no longer store unused state
  or send invalid parameters (for example Brave's `freshness=all`).
- Reporting honors `include_evidence` and `include_raw`, avoids duplicate
  terminal output, emits masked targets, and includes the target column in CSV
  exports.
- Configuration accepts both `MAILTRACE_GENERAL_*` and legacy `MAILTRACE_*`
  spellings, loads `.env` files, and exposes typed dataclass views for the CLI
  and TUI.
- Python 3.12 compatibility fixes (timezone-aware `utc_now`, `StrEnum`,
  forward references) replaced deprecated `datetime.utcnow()` usage.

## Verification

- `ruff check mailtrace tests` passes with the configured rule set.
- `mypy mailtrace` passes under strict settings.
- `pytest` covers schemas, configuration sources, database bootstrap and
  repository round trips, report masking, credential redaction, orchestrator
  deduplication/correlation, status derivation and end-to-end persistence.

## Known Limitations

- Live provider calls are not exercised by the test suite; tests use fakes and
  direct unit calls to avoid consuming API quotas.
- The Alembic migration in `mailtrace/storage/migrations` is retained for
  future controlled upgrades but is not run automatically. It predates the
  runtime schema bootstrap and may need a baseline revision before it is used
  against existing databases.
- PDF export requires the optional `report` extra and is not covered by tests.
- Cross-platform package builds (PyInstaller) are described in the project
  plan but are not automated in CI.
