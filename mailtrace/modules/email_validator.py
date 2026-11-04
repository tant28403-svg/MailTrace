"""Email validation and normalization module."""

from typing import ClassVar

from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel


class ValidationResult(BaseModel):
    """Result of email validation."""

    valid: bool
    normalized: str | None = None
    domain: str | None = None
    local_part: str | None = None
    error: str | None = None
    is_disposable: bool = False
    is_role_account: bool = False


class EmailValidator:
    """Email address validator and normalizer."""

    # Common role account prefixes
    ROLE_ACCOUNT_PREFIXES: ClassVar[set[str]] = {
        "admin",
        "administrator",
        "hostmaster",
        "postmaster",
        "webmaster",
        "info",
        "support",
        "help",
        "sales",
        "marketing",
        "abuse",
        "security",
        "noreply",
        "no-reply",
        "donotreply",
        "do-not-reply",
        "contact",
        "feedback",
        "billing",
        "accounts",
        "root",
        "system",
        "daemon",
        "mailer",
        "list",
        "newsletter",
    }

    # Known disposable email domains (subset)
    DISPOSABLE_DOMAINS: ClassVar[set[str]] = {
        "10minutemail.com",
        "guerrillamail.com",
        "mailinator.com",
        "tempmail.com",
        "throwawaymail.com",
        "yopmail.com",
        "maildrop.cc",
        "dispostable.com",
        "temp-mail.org",
        "fakeinbox.com",
        "trashmail.com",
        "getnada.com",
        "emailondeck.com",
    }

    def validate(self, email: str) -> ValidationResult:
        """Validate and normalize an email address."""
        try:
            # Validate using email-validator
            result = validate_email(email, check_deliverability=False)

            normalized = result.normalized
            local_part = result.local_part
            domain = result.domain

            # Check if role account
            is_role = local_part.lower() in self.ROLE_ACCOUNT_PREFIXES

            # Check if disposable domain
            is_disposable = domain.lower() in self.DISPOSABLE_DOMAINS

            return ValidationResult(
                valid=True,
                normalized=normalized,
                domain=domain,
                local_part=local_part,
                is_disposable=is_disposable,
                is_role_account=is_role,
            )

        except EmailNotValidError as e:
            return ValidationResult(
                valid=False,
                error=str(e),
            )

    def mask_email(self, email: str) -> str:
        """Mask email for display (preserves first and last char of local part)."""
        try:
            local, domain = email.split("@", 1)
            if len(local) <= 2:
                masked_local = local[0] + "*" * (len(local) - 1)
            else:
                masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
            return f"{masked_local}@{domain}"
        except ValueError:
            return "***@***"

    def extract_domain(self, email: str) -> str | None:
        """Extract domain from email."""
        try:
            return email.split("@", 1)[1].lower()
        except (ValueError, IndexError):
            return None

    def normalize_for_comparison(self, email: str) -> str:
        """Normalize email for comparison (lowercase, IDNA domain)."""
        try:
            result = validate_email(email, check_deliverability=False)
            return result.normalized.lower()
        except EmailNotValidError:
            return email.lower()


# Global validator instance
_validator: EmailValidator | None = None


def get_email_validator() -> EmailValidator:
    """Get global email validator instance."""
    global _validator
    if _validator is None:
        _validator = EmailValidator()
    return _validator
