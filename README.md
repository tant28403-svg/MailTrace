# MailTrace

Cross-platform email exposure intelligence CLI/TUI.

MailTrace runs authorized, evidence-based investigations of an email address
against breach databases, public indexes and DNS records, then stores the
results locally with masked targets and an audit trail.

> **Use responsibly.** Only investigate addresses you own or are explicitly
> authorized to assess. External providers receive the target address; review
> `uv run mailtrace sources list` and the confirmation prompt before running a
> scan.

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

## Quick Start

```bash
# Interactive TUI (default)
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

> If you installed the console script (`pip install -e .` or
> `uv tool install mailtrace`), you can drop the `uv run` prefix and call
> `mailtrace` directly.

## Configuration

API keys are read from environment variables, a project `.env` file, or
`~/.config/mailtrace/.env`:

```bash
export HIBP_API_KEY="your_hibp_key"                  # HIBP (paid subscription)
export BREACHDIRECTORY_API_KEY="your_rapidapi_key"   # BreachDirectory
export EMAILREP_API_KEY="optional"                   # emailrep.io (optional)
export GITHUB_TOKEN="ghp_..."                        # GitHub (public_repo scope)
export BRAVE_API_KEY="your_brave_key"                # Brave Search
export VIRUSTOTAL_API_KEY="your_vt_key"              # VirusTotal
```

Non-secret settings can be written by the TUI or the `.env` file:

```bash
MAILTRACE_GENERAL_DATA_DIR=~/.local/share/mailtrace
MAILTRACE_GENERAL_MASK_OUTPUT=true
MAILTRACE_GENERAL_CONFIRM_EXTERNAL=true
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

## Profiles

| Profile | Checks |
|---------|--------|
| `breach` | HIBP, BreachDirectory and emailrep.io |
| `public` | Brave Search, GitHub and emailrep.io |
| `domain` | DNS, MX, SPF, DMARC and VirusTotal |
| `full` | All of the above (default) |

Providers without configured credentials are skipped; DNS and emailrep.io work
without API keys.

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

## Requirements

- Python 3.12+
- SQLite (bundled with Python)
- API keys for external providers (optional — DNS and emailrep.io work without)

## License

MIT — see [LICENSE](LICENSE).
