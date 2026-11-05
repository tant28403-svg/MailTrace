# Security Policy

## Credential Handling

MailTrace is bring-your-own-key software. The repository contains no provider
credentials, and the application does not read a project-local `.env` by
default.

- Credentials are loaded from the process environment and the per-user file
  `~/.config/mailtrace/.env`.
- A project-local `.env` is ignored unless `MAILTRACE_USE_PROJECT_ENV=1` is set.
  Even then, the per-user file takes precedence.
- Scans are blocked until at least one enabled provider has its own key.
  `MAILTRACE_GENERAL_REQUIRE_KEYS=false` is the explicit escape hatch.
- Status output (`mailtrace config keys status`) shows only the source and a
  short SHA-256 fingerprint. It never prints credential values.
- `mailtrace config keys migrate` moves project credentials into the per-user
  file, writes a timestamped backup next to that file (not in the project), and
  strips the project copy.
- Reports, exports and the SQLite database never include provider keys.

## Sharing the Project

Sharing the Git repository, a source archive, or the project folder does not
share credentials, provided you did not force-add a secret file. Before
sharing a folder copy, check for `.env`, `.env.backup-*`, `*.key`, `*.pem` and
`*.p12` files and remove them.

## Reporting a Vulnerability

Please do not paste API keys, passwords, or full target addresses into a public
issue. Report security issues privately through the repository's security
advisory feature, or open a minimal issue that describes the problem without
secrets and ask for a private channel.

## If a Key Leaks

1. Revoke the key in the provider dashboard immediately. Revocation is more
   important than rotating, because a leaked key may already have been used.
2. Create a replacement key and update only `~/.config/mailtrace/.env` or your
   shell environment.
3. Remove the leaked value from any file, archive, or shell history that
   contains it. If it was committed, rewrite history and treat the key as
   compromised even after cleanup.
4. Check the provider's usage/billing dashboard for unexpected activity and set
   a spending or usage limit where the provider supports it.

## Residual Risk

Software cannot protect credentials from someone who can already read your OS
account or an unencrypted copy of your per-user configuration. Keep that file
private, use full-disk encryption where possible, and set provider-side
spending limits as a second line of defense.
