# MailTrace

Cross-platform email exposure intelligence CLI/TUI.

MailTrace runs authorized, evidence-based investigations of an email address
against breach databases, public indexes and DNS records, then stores the
results locally with masked targets and an audit trail.

> **Use responsibly.** Only investigate addresses you own or are explicitly
> authorized to assess. External providers receive the target address; review
> `uv run mailtrace sources list` and the confirmation prompt before running a
> scan.

> **Bring your own keys.** MailTrace ships without credentials and refuses to
> start scans until you configure your own provider key. Keys are read from your
> per-user config (`~/.config/mailtrace/.env`) or the process environment, never
> from a bundled or project-local file by default. See
> [Bring your own API keys](#bring-your-own-api-keys).

## Features

- **Interactive TUI** — dashboard with live progress, sortable findings,
  evidence viewer, history and export screens
- **CLI mode** — scriptable commands for automation and CI/CD
- **Breach intelligence** — HIBP, BreachDirectory and emailrep.io
- **Public exposure search** — Brave Search and GitHub public metadata
- **Domain intelligence** — DNS, MX, SPF, DMARC, nameservers and VirusTotal
  reputation
- **Evidence-based** — every finding links to normalized evidence with
  verification status and a content hash
- **Privacy-first** — local SQLite storage, masked output, explicit
  authorization confirmation for external calls
- **Redaction by design** — plaintext passwords and password hashes returned by
  breach providers are never persisted; only presence/type metadata is stored
- **Cross-platform** — Windows, Linux and macOS

## Installation

### With uv (recommended, Python 3.12+)

```bash
git clone https://github.com/tant28403-svg/MailTrace.git
cd MailTrace
uv sync
uv run mailtrace
```

### With pip

```bash
git clone https://github.com/tant28403-svg/MailTrace.git
cd MailTrace
python -m venv .venv
.venv/Scripts/activate  # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -e ".[report]"  # omit the extra if you do not need PDF export
mailtrace
```

Pre-built binaries may be published on the GitHub Releases page in the future;
until then use one of the source installs above.

## Bring your own API keys

MailTrace never bundles or shares provider credentials. Scans are **blocked**
until you configure at least one key-requiring provider (HIBP, BreachDirectory,
GitHub, Brave Search or VirusTotal). This prevents anyone who clones or receives
the project from spending the maintainer's API quota.

1. Create your private configuration file:

   ```bash
   # Linux/macOS
   mkdir -p ~/.config/mailtrace
   cp .env.example ~/.config/mailtrace/.env

   # Windows PowerShell
   New-Item -ItemType Directory -Force "$HOME\.config\mailtrace"
   Copy-Item .env.example "$HOME\.config\mailtrace\.env"
   ```

2. Add **your own** keys to that file (or export them in your shell). See
   [`.env.example`](.env.example) for the full list. HIBP and GitHub are enabled
   by default; enable BreachDirectory, Brave Search or VirusTotal in the same
   file if you want those sources to count toward the scan gate.

3. Verify what MailTrace can see:

   ```bash
   uv run mailtrace config keys status
   ```

   The status table shows a short SHA-256 fingerprint and the key's source; it
   never prints the key itself.

4. If you previously kept keys in the project `.env`, move them with:

   ```bash
   uv run mailtrace config keys migrate
   ```

   A timestamped backup is written next to the per-user file, not in the project
   folder. The project copy is stripped of credentials and can then be deleted.
   Use `--all` to also move recognised non-secret settings.

A project-local `.env` is **ignored by default**, even if it contains keys. For
development you can explicitly opt in with `MAILTRACE_USE_PROJECT_ENV=1`; the
per-user file still wins when both define the same key.

If you understand the cost implications and want to allow keyless DNS/emailrep
runs, set `MAILTRACE_GENERAL_REQUIRE_KEYS=false`. This is an escape hatch, not
the default.

Key-requiring providers are only run when they are enabled **and** their key is
present. emailrep.io and DNS need no key, but they do not satisfy the scan gate.
See [SECURITY.md](SECURITY.md) for the credential-handling policy.

## Quick Start

```bash
# 1. Configure your own keys first (see the section above)
uv run mailtrace config keys status

# 2. Interactive TUI (default)
uv run mailtrace

# Full CLI scan
uv run mailtrace scan user@example.com --profile full

# Individual checks
uv run mailtrace breach check user@example.com --format json
uv run mailtrace exposure search user@example.com --format csv
uv run mailtrace domain inspect example.com

# Inventory and history
uv run mailtrace sources list
uv run mailtrace history list
uv run mailtrace report CASE-001 --format pdf --output report.pdf
```

Without a configured key these scan commands exit with code `2` and print setup
instructions instead of calling any provider.

> If you installed the console script (`pip install -e .` or
> `uv tool install mailtrace`), you can drop the `uv run` prefix and call
> `mailtrace` directly.

## Configuration

Credentials are read from the process environment and
`~/.config/mailtrace/.env` only:

```bash
export HIBP_API_KEY="your_hibp_key"                  # HIBP (paid subscription)
export BREACHDIRECTORY_API_KEY="your_rapidapi_key"   # BreachDirectory
export EMAILREP_API_KEY="optional"                   # emailrep.io (optional)
export GITHUB_TOKEN="ghp_..."                        # GitHub (public_repo scope)
export BRAVE_API_KEY="your_brave_key"                # Brave Search
export VIRUSTOTAL_API_KEY="your_vt_key"              # VirusTotal
```

A project-local `.env` is ignored unless `MAILTRACE_USE_PROJECT_ENV=1` is set.
When opted in, the load order is process environment → per-user `.env` →
project `.env`, so the per-user file always wins.

Non-secret settings can be written by the TUI or the per-user `.env` file:

```bash
MAILTRACE_GENERAL_DATA_DIR=~/.local/share/mailtrace
MAILTRACE_GENERAL_MASK_OUTPUT=true
MAILTRACE_GENERAL_CONFIRM_EXTERNAL=true
MAILTRACE_GENERAL_REQUIRE_KEYS=true
MAILTRACE_GENERAL_LOG_LEVEL=INFO
MAILTRACE_GENERAL_THEME=dark
```

Provider toggles are only applied when a provider is enabled **and** its key is
configured (emailrep.io and DNS need no key). The `MAILTRACE_` prefix is
optional for provider toggles, so both `MAILTRACE_BREACHDIRECTORY_ENABLED` and
`BREACHDIRECTORY_ENABLED` work. Providers without credentials or with the
toggle disabled are skipped in scans.

Provider toggles and timeouts can also be supplied in
`~/.config/mailtrace/providers.toml`. Copy
[`config/providers.example.toml`](config/providers.example.toml) as a starting
point. The legacy `MAILTRACE_DATA_DIR` spelling is also accepted.

See [`.env.example`](.env.example) for the complete environment reference.
Never commit or share `.env`, `.env.backup-*`, or copied configuration files.

## Profiles

| Profile | Checks |
|---------|--------|
| `breach` | HIBP, BreachDirectory and emailrep.io |
| `public` | Brave Search, GitHub and emailrep.io |
| `domain` | DNS, MX, SPF, DMARC and VirusTotal |
| `full` | All of the above (default) |

Providers without configured credentials are skipped. DNS and emailrep.io work
without keys, but the default scan gate still requires at least one configured
key-requiring provider (see `MAILTRACE_GENERAL_REQUIRE_KEYS`).

## Output Formats

| Format | Notes |
|--------|-------|
| `terminal` | Rich tables with colors (default) |
| `json` | Machine-readable report including evidence |
| `csv` | Spreadsheet-friendly one-row-per-finding export |
| `pdf` | Professional report (requires `uv sync --extra report`) |

## Privacy and Data Handling

- Email addresses are masked in output by default (`--show-target` to reveal).
- Only an HMAC-SHA256 hash and the masked form are persisted; the full address
  is never written to the database or reports.
- Breach credentials (plaintext passwords/hashes) are redacted before storage.
- External calls require explicit confirmation unless `--no-confirm` is used.
- Cases are stored in a local SQLite database under the configured data
  directory; delete them from the history screen or with
  `uv run mailtrace case delete <id>`.
- `uv run mailtrace report <case-id> --format json` exports a full case
  snapshot for inspection or archival.

## Development

```bash
uv sync --dev
uv run ruff check mailtrace tests
uv run mypy mailtrace
uv run pytest
```

The `report` extra adds ReportLab for PDF export; it is optional for tests.

Secret scanning is enforced in two places: CI runs gitleaks over the full
history, and `.pre-commit-config.yaml` blocks staged `.env` files and private
keys. Install the local hook with `pre-commit install` (the gitleaks pre-commit
hook requires the gitleaks binary on `PATH`).

## Requirements

- Python 3.12+
- SQLite (bundled with Python)
- Your own API key for at least one key-requiring provider (HIBP,
  BreachDirectory, GitHub, Brave Search or VirusTotal) — MailTrace will not run
  scans without one

## License

MIT — see [LICENSE](LICENSE).
