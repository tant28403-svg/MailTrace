# MailTrace

## Detailed Technical Project Plan

**Project type:** Cross-platform email exposure intelligence CLI\
**Target platforms:** Windows 10/11, Linux (including Kali, Ubuntu,
Debian)\
**Primary interface:** Command-line interface (CLI), with optional
terminal UI (TUI)\
**Architecture:** Local-first, modular, provider-based\
**Initial language:** Python 3.12+\
**Document status:** Development specification

------------------------------------------------------------------------

## 1. Executive Summary

MailTrace is a cross-platform command-line application for investigating
the digital footprint of an email address. Its two primary investigation
scopes are:

1.  **Known breach intelligence:** Determine whether an email address
    appears in breach records reported by legitimate, authorized
    breach-intelligence providers.
2.  **Public internet exposure:** Discover publicly indexed or otherwise
    lawfully accessible pages that visibly contain or reference the
    email address, and identify the associated websites.

MailTrace collects findings from configured sources, normalizes them
into a common format, checks evidence where permitted, correlates
duplicate observations, assesses severity and confidence separately,
stores investigation history locally, and exports reports.

MailTrace is not intended to access private accounts, bypass
authentication, obtain stolen databases, retrieve passwords, or conduct
indiscriminate personal-data harvesting. Investigations should be
limited to email addresses the operator owns or is authorized to assess.
Provider terms, rate limits, privacy rules, and applicable laws must be
respected.

### Product principles

-   **CLI-first:** No website, web dashboard, or hosted control panel.
-   **Cross-platform:** Windows and Linux support through a shared
    Python codebase.
-   **Evidence-led:** Every finding should identify its source and
    verification state.
-   **Honest coverage:** A source failure or unavailable API must never
    be reported as "no exposure."
-   **Privacy-conscious:** Minimize collection and retention of personal
    information.
-   **Modular:** Providers can be added or removed without rewriting the
    orchestrator.
-   **Reproducible:** Investigations retain timestamps, source statuses,
    configuration versions, and report references.

------------------------------------------------------------------------

## 2. Goals and Non-Goals

### 2.1 Goals

MailTrace v1.0 should:

-   Accept and validate a target email address.
-   Check the address against supported breach-intelligence providers.
-   Search configured public search APIs for publicly indexed
    appearances, where the provider permits this use.
-   Inspect permitted public repository metadata for relevant matches.
-   Inspect the email domain's public DNS configuration.
-   Record the source, URL or provider reference, collection time, and
    verification status for each finding.
-   Deduplicate findings without incorrectly merging distinct exposures.
-   Assign severity and confidence as separate values.
-   Store investigations and historical snapshots in SQLite.
-   Export reports in JSON, CSV, and PDF.
-   Run from Windows PowerShell/CMD and Linux shells.
-   Handle missing credentials, rate limits, timeouts, and provider
    outages gracefully.

### 2.2 Non-goals for v1.0

The initial release will not:

-   Search private accounts, private groups, or authenticated content
    without explicit authorization and supported access.
-   Bypass CAPTCHAs, access controls, paywalls, or provider
    restrictions.
-   Download or store stolen databases or raw leaked credentials.
-   Retrieve, test, or display passwords.
-   Claim to find every occurrence of an email address on the internet.
-   Infer that an email account exists merely because its domain has MX
    records.
-   Automatically contact websites, account owners, or affected
    services.
-   Provide a web application or remote multi-user service.
-   Guarantee that a search result still exists or is currently
    accessible.

------------------------------------------------------------------------

## 3. Scope and Investigation Profiles

MailTrace should expose a small number of understandable investigation
profiles.

  -----------------------------------------------------------------------
  Profile                 Included checks         Intended use
  ----------------------- ----------------------- -----------------------
  `breach`                Configured              Known breach exposure
                          breach-intelligence
                          providers

  `public`                Permitted search        Publicly indexed
                          providers and public    appearances
                          repository metadata

  `domain`                DNS, MX, SPF, DMARC and Email-domain context
                          domain metadata

  `full`                  All enabled and         Combined investigation
                          applicable modules
  -----------------------------------------------------------------------

A profile only runs providers that are configured, supported, and
permitted for the target and query type. The report must list skipped
modules and explain why they were skipped.

### 3.1 Target authorization

Before transmitting an email address to an external service, MailTrace
should:

1.  Explain which configured providers may receive the address.
2.  Require an explicit confirmation for the investigation.
3.  Allow the operator to cancel.
4.  Record the authorization confirmation in the case audit log without
    storing unnecessary personal details.

A local-only validation or domain check may be offered separately, but
it must be clearly distinguished from external exposure checks.

------------------------------------------------------------------------

## 4. High-Level Architecture

MailTrace uses a central orchestrator and independent provider adapters.

``` text
User
 |
 v
CLI / Optional TUI
 |
 v
Input Validation and Authorization
 |
 v
Investigation Orchestrator
 |
 +---------------------+-----------------------+
 |                     |                       |
 v                     v                       v
Breach Providers   Public Search          Domain Intelligence
 |                 Providers               |
 v                     v                   v
Provider Adapters and Result Normalizers
 |
 v
Finding Deduplication and Correlation
 |
 v
Evidence Verification and Confidence Assessment
 |
 v
Severity Assessment
 |
 +---------------------+
 |                     |
 v                     v
SQLite Storage     Report Generator
                       |
                       v
                 JSON / CSV / PDF
```

### 4.1 Component responsibilities

  -----------------------------------------------------------------------
  Component                           Responsibility
  ----------------------------------- -----------------------------------
  CLI                                 Parse commands, validate options,
                                      present results

  Authorization layer                 Explain external data sharing and
                                      obtain confirmation

  Orchestrator                        Create cases, schedule modules,
                                      manage timeouts and cancellation

  Provider adapters                   Communicate with individual APIs or
                                      public sources

  Normalizers                         Convert provider-specific responses
                                      into common schemas

  Correlation engine                  Deduplicate and relate findings

  Evidence manager                    Preserve source references and
                                      integrity metadata

  Risk engine                         Assign severity and confidence

  Storage layer                       Persist cases, findings, evidence
                                      and snapshots

  Reporting layer                     Produce terminal and exportable
                                      reports

  Configuration layer                 Manage providers, keys, limits and
                                      privacy settings
  -----------------------------------------------------------------------

### 4.2 Failure isolation

A provider failure must not stop unrelated modules. Each provider run
should end with a structured status such as:

-   `completed_with_findings`
-   `completed_no_matches`
-   `unauthorized`
-   `rate_limited`
-   `unavailable`
-   `timeout`
-   `unsupported`
-   `configuration_error`
-   `partial`

The overall investigation should be marked `complete`, `partial`, or
`failed` based on the modules that actually ran. It must not be marked
clean merely because providers were unavailable.

------------------------------------------------------------------------

## 5. Functional Modules

### 5.1 Email Validation and Normalization

**Purpose:** Validate the input and derive safe comparison values.

Responsibilities:

-   Validate email syntax using a maintained validation library.
-   Normalize the domain using IDNA rules where applicable.
-   Preserve the original input for authorized provider queries when
    required.
-   Produce a comparison representation for deduplication.
-   Mask the email in ordinary logs and terminal output.
-   Reject malformed or unsupported input with a useful error.

Do not apply provider-specific transformations such as removing dots or
plus-tags unless a source explicitly documents that behavior. Such
transformations can cause false matches.

**Suggested library:** `email-validator`

### 5.2 Breach Intelligence

**Purpose:** Check whether the email appears in known breach records
through authorized providers.

Initial provider:

-   Have I Been Pwned (HIBP), subject to its current API terms,
    subscription requirements, and endpoint restrictions.

Potential future providers may be added only after their licensing, API
permissions, and data-handling terms have been reviewed.

Collect only fields the provider legitimately returns and MailTrace
needs, such as:

-   Breach or incident name.
-   Affected service or domain.
-   Reported breach date.
-   Provider-added or discovery date, if available.
-   Data categories exposed.
-   Provider verification or retirement status, if available.
-   Provider reference and retrieval timestamp.

Do not request, store, export, or display passwords or raw compromised
account data.

**Acceptance criteria:**

-   A valid provider response becomes normalized breach findings.
-   A successful response with no matches is recorded as
    `completed_no_matches`.
-   Missing or invalid credentials are recorded as `unauthorized`.
-   Provider errors and rate limits are visible in the report.
-   Provider-specific data is not presented as independently verified
    unless the provider supports that status.

### 5.3 Public Internet Exposure

**Purpose:** Discover public pages that may contain the target email
address.

Initial approach:

-   Use search APIs whose terms permit the intended query.
-   Record search results as leads.
-   Where access is permitted, verify the accessible page and whether
    the exact target is visibly present.
-   Respect robots policies, terms of service, rate limits, and access
    restrictions.
-   Do not use CAPTCHA bypass, session theft, or access-control
    circumvention.

For each lead, record:

-   Search provider.
-   Result title.
-   Result URL.
-   Snippet, only where retention is permitted and necessary.
-   Query and collection timestamp.
-   Page verification status.
-   Verification timestamp.
-   Reason verification could not be completed.

A search snippet alone is not proof of current exposure. Pages may be
stale, removed, inaccessible, or incorrectly indexed.

### 5.4 Public Repository Intelligence

**Purpose:** Identify relevant appearances in permitted public
repository metadata.

Initial integration:

-   GitHub REST API, subject to API authentication, search limitations,
    quotas, and acceptable-use terms.

Potential result categories:

-   Public commit author metadata.
-   Public repository metadata.
-   Publicly accessible documentation or files returned through
    supported APIs.

Keep collection narrow and tied to the authorized target. Do not
enumerate unrelated personal data or treat every repository author match
as proof of account ownership.

Record repository URL, commit or object reference where available,
timestamp, source type, and verification state.

### 5.5 Domain Intelligence

**Purpose:** Provide context about the domain portion of the email
address.

Checks:

-   DNS resolution.
-   MX records.
-   SPF record presence and syntax observations.
-   DMARC record presence and policy.
-   Nameserver information where useful.
-   Mail-provider classification when supported by reliable data.

Suggested library: `dnspython`

This module must not attempt SMTP recipient probing, mailbox
enumeration, or account-existence inference. A valid MX record only
indicates that a domain publishes mail-routing information; it does not
prove that a particular mailbox exists.

### 5.6 Metadata Intelligence (Post-MVP)

**Purpose:** Inspect files explicitly supplied by an authorized user to
identify email addresses or relevant metadata.

Potential file types:

-   PDF
-   DOCX
-   XLSX
-   JPEG and PNG
-   Other formats supported by the selected metadata backend

Suggested integration: ExifTool.

This module should be opt-in, process only user-supplied files, and
avoid uploading files to external services by default.

### 5.7 Source Management

Each source adapter should expose a common interface and report:

-   Source identifier and display name.
-   Whether it is enabled.
-   Whether required credentials are configured.
-   Last health-check result.
-   Rate-limit state, when available.
-   Request duration.
-   Result count.
-   Structured error code and safe error message.

Secrets must never be included in status output or logs.

### 5.8 Evidence Management

Evidence is the foundation of a credible report.

For each observation, preserve:

-   Source identifier.
-   Source URL or provider reference.
-   Collection timestamp in UTC.
-   Verification timestamp, if applicable.
-   Evidence type.
-   Verification status.
-   A hash of any retained evidence artifact.
-   Minimal notes explaining what was verified.

Do not archive full web pages by default. If an evidence artifact is
retained, ensure retention is permitted, minimize personal information,
and document its origin.

### 5.9 Correlation and Deduplication

The correlation engine should:

-   Detect duplicate results from the same source.
-   Identify likely duplicate URLs after safe URL normalization.
-   Group observations by service or domain where justified.
-   Preserve each source's attribution.
-   Link observations without assuming a common incident or common
    account owner.

A correlation is an analytical relationship, not automatically a
verified fact. The report should label inferred relationships
separately.

### 5.10 Severity and Confidence

Keep severity and confidence independent.

**Severity** describes potential impact:

-   `critical`
-   `high`
-   `medium`
-   `low`
-   `informational`

**Confidence** describes evidence strength:

-   `verified`
-   `high`
-   `medium`
-   `low`
-   `unverified`

Example: a verified public profile may have high confidence but low
severity. A provider-reported breach involving sensitive data categories
may have high severity, while confidence depends on the provider's
evidence and status.

Document the rules used for every severity assignment. Do not imply that
a numeric score is an objective probability of harm.

### 5.11 Historical Analysis

Allow users to compare authorized investigations over time.

Track:

-   Newly observed findings.
-   Previously observed findings.
-   Findings no longer returned by a source.
-   Changes in provider status.
-   Changes in verification state.

A result disappearing from a search index does not prove that the
information has been deleted from the original website or all copies.

### 5.12 Reporting

Supported outputs:

-   Terminal summary.
-   JSON.
-   CSV.
-   PDF.

Every report must include:

-   Case ID.
-   Masked target by default.
-   Investigation timestamp.
-   Enabled providers.
-   Provider run statuses.
-   Findings and source references.
-   Severity and confidence.
-   Verification status.
-   Coverage limitations.
-   Errors and unavailable sources.
-   Report-generation version.

------------------------------------------------------------------------

## 6. External APIs and Integrations

Provider access, pricing, authentication, endpoint availability, and
permitted use can change. Confirm current documentation and terms before
implementation.

  -----------------------------------------------------------------------
  Provider /        Intended use      Priority          Notes
  technology
  ----------------- ----------------- ----------------- -----------------
  Have I Been Pwned Breach            MVP               Review current
  API               intelligence                        subscription and
                                                        endpoint
                                                        requirements

  GitHub REST API   Public repository MVP               Search
                    and commit                          capabilities and
                    metadata                            quotas are
                                                        limited

  Brave Search API  Public page       MVP candidate     Confirm permitted
                    discovery                           query use and
                                                        current API terms

  Google            Alternative       Optional          Confirm current
  Programmable      public search                       product
  Search                                                availability and
                                                        quotas

  DNS via dnspython Domain records    MVP               No API key
                                                        normally required
                                                        for configured
                                                        DNS resolution

  ExifTool          Local document    Post-MVP          Process
                    metadata                            user-provided
                                                        files

  DeHashed API      Licensed exposure Optional          Requires
                    intelligence                        permitted
                                                        account/API
                                                        access

  VirusTotal API    Domain and URL    Optional          Not an email
                    reputation                          breach database
                    context
  -----------------------------------------------------------------------

### 6.1 Provider selection policy

Before enabling a provider, document:

1.  Official API documentation.
2.  Authentication requirements.
3.  Pricing or subscription requirements.
4.  Rate limits and quotas.
5.  Permitted query types.
6.  Data retention and redistribution rules.
7.  Whether personal email searches are permitted.
8.  Error and response semantics.

Do not scrape a service simply because it has a public website. Prefer
documented APIs and providers that explicitly permit the intended use.

### 6.2 Provider adapter contract

Every connector should implement a shared interface.

``` python
from abc import ABC, abstractmethod
from typing import Any

class IntelligenceProvider(ABC):
    name: str

    @abstractmethod
    async def health_check(self) -> dict[str, Any]:
        """Return a safe provider availability/configuration status."""
        raise NotImplementedError

    @abstractmethod
    async def check_email(self, email: str) -> list[dict[str, Any]]:
        """Return normalized observations permitted by the provider."""
        raise NotImplementedError
```

In production, replace generic dictionaries with Pydantic models and
typed result objects. Provider adapters should not write directly to the
database; they should return normalized results to the orchestrator.

### 6.3 Provider error handling

Map provider-specific errors to common internal statuses:

  Condition                             Internal status
  ------------------------------------- ---------------------------
  Successful response with findings     `completed_with_findings`
  Successful response with no matches   `completed_no_matches`
  Invalid/missing API key               `unauthorized`
  Quota exceeded                        `rate_limited`
  Connection failure                    `unavailable`
  Request timeout                       `timeout`
  Unsupported query                     `unsupported`
  Malformed response                    `partial` or `failed`

------------------------------------------------------------------------

## 7. CLI Command Design

The CLI should use consistent commands and predictable exit codes.

### 7.1 Proposed commands

``` text
mailtrace
├── scan
│   └── EMAIL
├── breach
│   └── check EMAIL
├── exposure
│   └── search EMAIL
├── domain
│   └── inspect DOMAIN
├── sources
│   ├── list
│   ├── status
│   └── test SOURCE
├── history
│   ├── list
│   └── compare CASE_A CASE_B
├── case
│   ├── show CASE_ID
│   └── delete CASE_ID
├── report
│   └── CASE_ID
└── config
    ├── show
    └── validate
```

### 7.2 Example usage

``` powershell
# Windows PowerShell
mailtrace scan person@example.com --profile full
mailtrace scan person@example.com --profile breach
mailtrace sources status
mailtrace history list
mailtrace report CASE-001 --format json
```

``` bash
# Linux / Kali
mailtrace scan person@example.com --profile full
mailtrace scan person@example.com --profile public
mailtrace sources status
mailtrace history compare CASE-001 CASE-002
mailtrace report CASE-001 --format pdf
```

### 7.3 CLI behavior

-   Show help and examples for every command.
-   Use a progress display for long investigations.
-   Allow cancellation without corrupting stored cases.
-   Mask the target in normal output.
-   Offer an explicit `--show-target` option for authorized local use.
-   Ask for confirmation before external transmission.
-   Provide a non-interactive mode only when authorization is explicitly
    supplied through a documented flag or configuration.
-   Never print API keys or sensitive headers.
-   Use meaningful exit codes for success, partial results, invalid
    input, and fatal errors.

------------------------------------------------------------------------

## 8. Data Model and SQLite Schema

SQLite is the recommended v1 database because it is portable and
requires no separate server.

### 8.1 Main entities

  Table              Purpose
  ------------------ -------------------------------------------------
  `investigations`   One record per investigation
  `provider_runs`    Status and timing for each source
  `findings`         Normalized observations
  `evidence`         Source references and verification metadata
  `breach_records`   Structured breach-specific details
  `snapshots`        Historical state for comparisons
  `audit_events`     Local record of significant application actions

### 8.2 Relationships

``` text
investigations
  ├── provider_runs
  ├── findings
  │     ├── evidence
  │     └── breach_records
  ├── snapshots
  └── audit_events
```

### 8.3 Suggested schema

``` sql
CREATE TABLE investigations (
    id TEXT PRIMARY KEY,
    target_hash TEXT NOT NULL,
    target_masked TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,
    authorization_confirmed INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE provider_runs (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    result_count INTEGER DEFAULT 0,
    error_code TEXT,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    title TEXT NOT NULL,
    service_name TEXT,
    domain TEXT,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    first_observed_at TEXT,
    collected_at TEXT NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
);

CREATE TABLE evidence (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    source_url TEXT,
    source_reference TEXT,
    evidence_type TEXT NOT NULL,
    evidence_hash TEXT,
    verification_status TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    verified_at TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE TABLE breach_records (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    breach_name TEXT NOT NULL,
    breach_domain TEXT,
    breach_date TEXT,
    discovery_date TEXT,
    data_classes_json TEXT,
    provider_status TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE TABLE snapshots (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    snapshot_date TEXT NOT NULL,
    findings_hash TEXT NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
);
```

Use parameterized SQL or SQLAlchemy. Enable SQLite foreign-key
enforcement. Add indexes on investigation IDs, provider names, and
timestamps. Use migrations rather than editing production schemas
manually.

### 8.4 Data protection

-   Encrypt sensitive target data at rest where practical.
-   Do not use a plain unsalted hash as the only protection for email
    addresses; email addresses have a guessable search space. Use keyed
    HMAC for matching when appropriate.
-   Keep encryption keys outside the database.
-   Apply restrictive file permissions to the database and reports.
-   Provide case deletion and retention settings.
-   Avoid saving raw API responses unless needed and permitted.
-   Store only the minimum evidence needed to support a finding.

------------------------------------------------------------------------

## 9. Normalized Data Contracts

All providers should return a common observation format.

### 9.1 Finding model

``` python
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, HttpUrl

Severity = Literal[
    "critical", "high", "medium", "low", "informational"
]

Confidence = Literal[
    "verified", "high", "medium", "low", "unverified"
]

class EvidenceRecord(BaseModel):
    provider: str
    source_url: HttpUrl | None = None
    source_reference: str | None = None
    evidence_type: str
    verification_status: str
    collected_at: datetime
    verified_at: datetime | None = None
    evidence_hash: str | None = None

class Finding(BaseModel):
    id: str
    finding_type: str
    title: str
    service_name: str | None = None
    domain: str | None = None
    severity: Severity
    confidence: Confidence
    verification_status: str
    collected_at: datetime
    evidence: list[EvidenceRecord]
```

### 9.2 Example finding

``` json
{
  "id": "FND-0001",
  "finding_type": "breach_exposure",
  "title": "Email listed in a provider-reported breach",
  "service_name": "Example Service",
  "domain": "example.com",
  "severity": "high",
  "confidence": "verified",
  "verification_status": "provider_verified",
  "collected_at": "2026-11-03T12:00:00Z",
  "evidence": [
    {
      "provider": "hibp",
      "source_reference": "provider-record-reference",
      "evidence_type": "breach_record",
      "verification_status": "provider_verified",
      "collected_at": "2026-11-03T12:00:00Z"
    }
  ]
}
```

All example values are illustrative.

------------------------------------------------------------------------

## 10. Correlation, Deduplication, and Risk Logic

### 10.1 Deduplication

Use conservative matching:

-   Same provider and same provider record ID: likely duplicate.
-   Same canonical URL and same observation type: possible duplicate.
-   Same service and same breach record: likely duplicate.
-   Similar title or domain only: insufficient to merge automatically.

Preserve all source references when findings are grouped.

### 10.2 Correlation

Correlation should produce relationships such as:

-   `same_service`
-   `same_domain`
-   `same_public_page`
-   `same_provider_record`
-   `possible_related_observation`

Do not infer that two appearances belong to the same person merely
because they contain the same email string. Do not infer that a public
appearance was caused by a breach without supporting evidence.

### 10.3 Severity

Severity should be determined using documented rules that consider:

-   Sensitivity of the reported data categories.
-   Exposure context.
-   Whether the information is currently accessible.
-   Recency, if reliably known.
-   Potential impact.

The rules should be configurable and reviewed. Avoid presenting severity
as a mathematically precise risk probability.

### 10.4 Confidence

Confidence should be based on evidence quality:

-   `verified`: exact match confirmed in an accessible source or by a
    provider's explicit verified record.
-   `high`: strong source evidence, but direct verification is
    incomplete.
-   `medium`: plausible match with partial evidence.
-   `low`: weak or ambiguous match.
-   `unverified`: insufficient evidence.

A provider's label and MailTrace's own verification status should be
stored separately.

------------------------------------------------------------------------

## 11. Privacy, Safety, and Compliance

MailTrace handles personal data. Privacy controls are core requirements,
not optional polish.

### Required safeguards

1.  Investigate only owned or authorized email addresses.
2.  Explain which external providers receive the target before sending
    requests.
3.  Do not collect passwords, authentication tokens, or raw stolen
    credentials.
4.  Do not access private accounts or bypass access controls.
5.  Respect provider terms, quotas, and applicable laws.
6.  Minimize the target and evidence data stored.
7.  Mask email addresses in terminal output and logs by default.
8.  Protect API credentials using environment variables or an OS
    credential store.
9.  Never include secrets in exception messages or reports.
10. Provide configurable retention and case deletion.
11. Document the limitations of each provider.
12. Keep a local audit trail of investigation actions.

### Reporting language

Prefer precise statements:

-   "The provider returned a breach record associated with this
    address."
-   "A public search result references a page that may contain this
    address."
-   "The page was accessible and the exact address was confirmed."
-   "The source could not be checked because authentication was
    unavailable."

Avoid unsupported statements such as:

-   "This email has been hacked."
-   "This email is exposed everywhere."
-   "This account definitely belongs to this person."
-   "No exposure exists" when source coverage is incomplete.

------------------------------------------------------------------------

## 12. Error Handling and Reliability

### 12.1 Network handling

Use HTTPX with:

-   Explicit connection and read timeouts.
-   Bounded retries for transient errors.
-   Exponential backoff with jitter.
-   Per-provider concurrency limits.
-   Rate-limit header handling where documented.
-   Cancellation support.
-   TLS certificate verification enabled.

Do not retry authentication failures or permanent validation errors
indefinitely.

### 12.2 Logging

Use structured logs with:

-   Timestamp.
-   Severity.
-   Module.
-   Provider.
-   Case ID.
-   Safe error code.
-   Duration.

Never log the full email address, API key, authorization header, or
sensitive provider response by default.

### 12.3 Exit codes

  Code   Meaning
  ------ --------------------------------------------------------
  `0`    Investigation completed successfully
  `1`    Fatal application error
  `2`    Invalid input or command usage
  `3`    Investigation completed with partial provider coverage
  `4`    Authorization or configuration requirement not met
  `5`    Report or storage operation failed

Document exact exit-code behavior and test it on both platforms.

------------------------------------------------------------------------

## 13. Recommended Technology Stack

  -----------------------------------------------------------------------
  Layer                   Technology              Reason
  ----------------------- ----------------------- -----------------------
  Language                Python 3.12+            Ecosystem and
                                                  cross-platform support

  CLI                     Typer                   Typed command structure

  Terminal output         Rich                    Tables, progress and
                                                  readable output

  HTTP                    HTTPX                   Async API communication

  Validation              Pydantic                Typed data contracts

  Email validation        email-validator         Email syntax and domain
                                                  validation

  DNS                     dnspython               DNS record inspection

  Database                SQLite                  Local portable storage

  ORM                     SQLAlchemy              Database abstraction

  Migrations              Alembic                 Versioned schema
                                                  changes

  Metadata                ExifTool                Optional local metadata
                                                  analysis

  Testing                 pytest                  Unit and integration
                                                  testing

  Linting                 Ruff                    Consistent code quality

  Type checking           mypy                    Static type checks

  Packaging               PyInstaller             Standalone executable
                                                  builds

  Dependency management   uv                      Reproducible
                                                  environments
  -----------------------------------------------------------------------

### Version policy

-   Start with Python 3.12 and 3.13.
-   Test Python 3.14 compatibility separately before claiming support.
-   Pin and audit dependencies for release builds.
-   Avoid unnecessary native dependencies in the MVP.

------------------------------------------------------------------------

## 14. Project Directory Structure

``` text
MailTrace/
│
├── mailtrace/
│   ├── __init__.py
│   ├── main.py
│   ├── cli.py
│   │
│   ├── core/
│   │   ├── orchestrator.py
│   │   ├── investigation.py
│   │   ├── configuration.py
│   │   ├── authorization.py
│   │   ├── exceptions.py
│   │   └── events.py
│   │
│   ├── modules/
│   │   ├── email_validator.py
│   │   ├── breach_intelligence.py
│   │   ├── public_exposure.py
│   │   ├── repository_intelligence.py
│   │   ├── domain_intelligence.py
│   │   ├── metadata_intelligence.py
│   │   ├── correlation.py
│   │   ├── severity.py
│   │   └── historical_analysis.py
│   │
│   ├── providers/
│   │   ├── base.py
│   │   ├── hibp.py
│   │   ├── github.py
│   │   ├── brave_search.py
│   │   ├── dns.py
│   │   └── virustotal.py
│   │
│   ├── schemas/
│   │   ├── finding.py
│   │   ├── evidence.py
│   │   ├── provider.py
│   │   └── investigation.py
│   │
│   ├── storage/
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── repositories.py
│   │   └── migrations/
│   │
│   ├── evidence/
│   │   ├── collector.py
│   │   ├── verifier.py
│   │   └── integrity.py
│   │
│   ├── reporting/
│   │   ├── terminal.py
│   │   ├── json_report.py
│   │   ├── csv_report.py
│   │   └── pdf_report.py
│   │
│   └── utils/
│       ├── masking.py
│       ├── hashing.py
│       ├── logging.py
│       ├── time.py
│       └── paths.py
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── providers/
│   ├── fixtures/
│   └── conftest.py
│
├── config/
│   └── providers.example.toml
│
├── docs/
│   ├── architecture.md
│   ├── provider-policy.md
│   ├── privacy.md
│   └── development.md
│
├── scripts/
├── reports/
├── pyproject.toml
├── README.md
├── LICENSE
└── .gitignore
```

The `reports/`, database, logs, and local secrets should live in an
application data directory rather than being committed into the source
repository. The directory above shows the logical project layout, not a
requirement to store runtime data in the repository.

------------------------------------------------------------------------

## 15. Development Roadmap

Estimated duration: **8--14 weeks** for one developer working
consistently. External API approval, subscription setup, provider
limitations, and testing can change this estimate.

### Phase 1 --- Foundation (Week 1--2)

**Tasks**

-   Initialize repository and `pyproject.toml`.
-   Configure uv and supported Python versions.
-   Create Typer CLI.
-   Implement configuration loading.
-   Implement email validation and masking.
-   Create SQLite database and initial migrations.
-   Add structured logging.
-   Add common Pydantic schemas.
-   Add unit tests and CI checks.

**Deliverable:** MailTrace starts, validates an input, creates a case,
and stores it locally.

### Phase 2 --- Breach Intelligence (Week 3--4)

**Tasks**

-   Review current HIBP API documentation and access requirements.
-   Implement provider adapter.
-   Add credential configuration.
-   Implement safe request and response handling.
-   Normalize breach records.
-   Add provider statuses and error handling.
-   Add mock-based tests and authorized integration tests.

**Deliverable:** MailTrace can perform an authorized breach check and
save provider-reported findings.

### Phase 3 --- Public Exposure Intelligence (Week 5--7)

**Tasks**

-   Select a search API whose terms permit the intended use.
-   Implement search provider adapter.
-   Add result normalization.
-   Add source URL and timestamp capture.
-   Add permitted page verification.
-   Add GitHub public metadata integration.
-   Implement conservative duplicate detection.
-   Add rate-limit and timeout handling.

**Deliverable:** MailTrace can discover public search leads and
repository observations, clearly distinguishing leads from verified page
contents.

### Phase 4 --- Intelligence Engine (Week 8--9)

**Tasks**

-   Implement correlation relationships.
-   Implement independent severity and confidence assessment.
-   Add finding grouping.
-   Add historical snapshots.
-   Add investigation comparison.
-   Add coverage summary.

**Deliverable:** MailTrace can produce a consolidated investigation with
explainable classifications.

### Phase 5 --- Reporting (Week 10--11)

**Tasks**

-   Create terminal report.
-   Implement JSON export.
-   Implement CSV export.
-   Implement PDF export.
-   Add evidence references.
-   Add provider coverage and limitations.
-   Add report tests.

**Deliverable:** Complete investigation reports with traceable evidence
and explicit limitations.

### Phase 6 --- Cross-Platform Release (Week 12--14)

**Tasks**

-   Test Windows PowerShell and CMD.
-   Test Kali Linux and Ubuntu.
-   Check filesystem path handling.
-   Check SQLite behavior and permissions.
-   Package Windows executable.
-   Package Linux executable.
-   Add installation and configuration documentation.
-   Run dependency and security audits.
-   Complete acceptance testing.

**Deliverable:** MailTrace v1.0 for Windows and Linux.

------------------------------------------------------------------------

## 16. Testing Strategy

### Unit tests

Test:

-   Email validation.
-   Domain normalization.
-   Email masking.
-   Finding normalization.
-   Severity classification.
-   Confidence classification.
-   URL normalization.
-   Deduplication.
-   Report serialization.
-   Database repositories.

### Provider tests

Use mocked HTTP responses to test:

-   Successful response with findings.
-   Successful response without matches.
-   Invalid credentials.
-   Rate limiting.
-   Timeout.
-   Server error.
-   Malformed response.
-   Missing optional fields.

Do not make ordinary unit tests depend on live third-party APIs.

### Integration tests

Use test credentials and authorized targets only. Keep live provider
tests opt-in so that normal test runs are repeatable and do not consume
API quotas.

### Cross-platform tests

Test at minimum:

-   Windows 10/11.
-   Kali Linux.
-   Ubuntu or Debian.

Check:

-   Path handling.
-   Environment variable handling.
-   Credential storage.
-   Unicode email/domain handling.
-   Terminal rendering.
-   Database file permissions.
-   Executable packaging.

------------------------------------------------------------------------

## 17. Deployment and Installation

Docker is not required for the core product.

### Developer installation

Windows PowerShell:

``` powershell
git clone <repository-url>
cd MailTrace

uv sync
uv run mailtrace --help
```

Linux:

``` bash
git clone <repository-url>
cd MailTrace

uv sync
uv run mailtrace --help
```

### API configuration

Use environment variables, an OS credential store, or a protected local
configuration file. Do not commit secrets.

Example environment variable names:

``` env
HIBP_API_KEY=
GITHUB_TOKEN=
BRAVE_API_KEY=
VIRUSTOTAL_API_KEY=
```

The application should run without optional credentials and clearly show
which modules are unavailable.

### Release packaging

Build separate platform artifacts:

``` text
dist/
├── windows/
│   └── mailtrace.exe
└── linux/
    └── mailtrace
```

Build and test each artifact on its target operating system. Do not
assume a Windows executable can be produced and run unchanged on Linux
or vice versa.

------------------------------------------------------------------------

## 18. MVP Definition and Release Acceptance Criteria

The MVP is complete when all of the following are true:

-   [ ] CLI starts on supported Windows and Linux systems.
-   [ ] Email input is validated and masked by default.
-   [ ] External transmission requires explicit authorization.
-   [ ] HIBP integration works with valid authorized credentials.
-   [ ] At least one permitted public search provider is integrated.
-   [ ] GitHub integration handles API limits and unsupported searches
    correctly.
-   [ ] Domain DNS checks work.
-   [ ] Findings use a common schema.
-   [ ] Provider runs have explicit statuses.
-   [ ] Provider errors do not silently become "no matches."
-   [ ] Findings retain source attribution and timestamps.
-   [ ] Search leads are distinguished from verified exposure.
-   [ ] Duplicate findings are handled conservatively.
-   [ ] Severity and confidence are independent.
-   [ ] SQLite investigations persist across restarts.
-   [ ] JSON and CSV exports work.
-   [ ] PDF export is tested before v1.0.
-   [ ] Secrets are not written to logs or reports.
-   [ ] Case deletion and retention controls work.
-   [ ] Unit and provider tests pass.
-   [ ] Windows and Linux packaging is verified.

------------------------------------------------------------------------

## 19. Risks and Mitigations

  -----------------------------------------------------------------------
  Risk                                Mitigation
  ----------------------------------- -----------------------------------
  Search APIs do not permit certain   Review provider terms and use only
  personal-data queries               permitted query types

  API cost or subscription changes    Make providers optional and expose
                                      configuration status

  Search results are stale            Verify pages where permitted and
                                      label unverified leads

  False-positive email matches        Require exact-match evidence and
                                      conservative normalization

  Provider downtime                   Isolate failures and report partial
                                      coverage

  API quotas are exhausted            Add per-provider rate limits and
                                      quota-aware scheduling

  Sensitive data is stored locally    Minimize collection, encrypt
                                      sensitive data, and provide
                                      retention controls

  Cross-platform packaging            Build and test native artifacts on
  differences                         each OS

  Provider response formats change    Version adapters, validate schemas,
                                      and test malformed responses
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 20. Future Enhancements (After v1.0)

These features should not delay the initial release:

-   Additional licensed breach-intelligence providers.
-   More public search integrations.
-   Optional local document metadata analysis.
-   Configurable source plugins.
-   Improved historical comparison.
-   Encrypted case export and import.
-   Additional report templates.
-   Optional TUI for interactive terminal navigation.
-   Organization-level exposure audits with explicit authorization.
-   Configurable retention policies and automated cleanup.

A future enhancement should be added only when its source access,
privacy impact, maintenance cost, and user value are understood.

------------------------------------------------------------------------

## 21. Recommended Build Order

Do not build every module at once. Follow this exact dependency order:

1.  Project setup, CLI, configuration, logging.
2.  Email validation, masking, and authorization confirmation.
3.  SQLite schema and migrations.
4.  Provider interface and normalized data models.
5.  HIBP breach provider.
6.  Search provider and public exposure leads.
7.  GitHub public metadata provider.
8.  DNS/domain intelligence.
9.  Evidence verification and storage.
10. Deduplication and correlation.
11. Severity and confidence assessment.
12. Historical snapshots.
13. JSON and CSV reporting.
14. PDF reporting.
15. Windows/Linux packaging and release testing.

This order delivers useful functionality early while keeping the
architecture extensible.

------------------------------------------------------------------------

## 22. Final Product Definition

**MailTrace v1.0** is a local-first, cross-platform email exposure
intelligence CLI.

An authorized operator supplies an email address. MailTrace validates
it, explains which configured external sources will receive it, and runs
the selected investigation profile. It checks supported
breach-intelligence providers, searches permitted public sources,
inspects relevant public repository metadata, and gathers domain
context.

It then normalizes the results, preserves evidence references,
distinguishes verified findings from unverified leads, assesses severity
and confidence separately, stores the investigation locally, and
generates a report.

### The most important product promise

MailTrace should never claim that an email address is completely safe or
completely exposed based on incomplete source coverage.

It should accurately answer:

-   Which configured sources were checked?
-   Which sources returned matches?
-   Which websites or services were associated with those matches?
-   What evidence supports each finding?
-   Which findings were independently verified?
-   Which sources could not be checked?
-   What changed since the previous investigation?

**Build a reliable evidence-based investigation tool first. Expand its
source coverage and analytical capabilities only after the core is
accurate, testable, and privacy-conscious.**
