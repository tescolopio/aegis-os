"""S1-4: Adversarial PII test suite for all five pattern classes.

Coverage targets (src/governance/guardrails.py):
  - Line coverage  : ≥ 95 % (hard gate) — this file pushes to 100 %
  - Branch coverage: 100 %               — already achieved; maintained here

Three test sections
-------------------
1. Adversarial matrix — 6 evasion variants × 5 PII classes (30 tests)
   Variants:
     standard        – canonical, well-formed PII
     zero_width      – invisible Unicode chars (U+200B) injected mid-token
     unicode_digit   – fullwidth digit substitution, collapsed by NFKC
     url_encoded     – key punctuation percent-encoded
     base64          – entire PII value base64-encoded (known: NOT detected)
     newline         – ASCII newline injected mid-token
2. False-positive matrix — ≥ 10 non-PII inputs per class (50 tests)
3. Performance test — 10 000-char prompt, 50 PII instances, < 50 ms
4. scrub() direct call — hits line 186 to reach 100 % line coverage
"""

from __future__ import annotations

import time

import pytest

from src.governance.guardrails import Guardrails

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GUARD = Guardrails()


def _found(text: str) -> list[str]:
    """Return the list of PII classes detected in *text*."""
    return _GUARD.mask_pii(text).found_types


def _scrubbed(text: str) -> str:
    """Return the scrubbed text (calls mask_pii which resets; same instance)."""
    return _GUARD.mask_pii(text).redacted


# ===========================================================================
# Section 1 — Adversarial Matrix
# ===========================================================================


class TestAdversarialEmail:
    """Email adversarial evasion variants."""

    def test_standard(self) -> None:
        assert "email" in _found("user@example.com")

    def test_zero_width(self) -> None:
        # U+200B zero-width space stripped by the normalization pipeline
        assert "email" in _found("user\u200bdoe@example.com")

    def test_unicode_digit_fullwidth(self) -> None:
        # Fullwidth Latin letters normalised to ASCII via NFKC
        assert "email" in _found("\uff55\uff53\uff45\uff52@example.com")

    def test_url_encoded_at(self) -> None:
        # %40 → @ after URL-decode step
        assert "email" in _found("user%40example.com")

    def test_base64_not_decoded(self) -> None:
        # Base64("user@example.com") — pipeline does NOT decode; known limitation
        assert "email" not in _found("dXNlckBleGFtcGxlLmNvbQ==")

    def test_newline_split(self) -> None:
        # Newline inside token — stripped/compacted during normalisation
        assert "email" in _found("user@example\n.com")


class TestAdversarialSSN:
    """SSN adversarial evasion variants."""

    def test_standard(self) -> None:
        assert "ssn" in _found("123-45-6789")

    def test_zero_width(self) -> None:
        assert "ssn" in _found("123\u200b-45-6789")

    def test_unicode_digit_fullwidth(self) -> None:
        # １２３-４５-６７８９
        assert "ssn" in _found("\uff11\uff12\uff13-\uff14\uff15-\uff16\uff17\uff18\uff19")

    def test_url_encoded_dash(self) -> None:
        # %2D → - after URL-decode
        assert "ssn" in _found("123%2D45%2D6789")

    def test_base64_not_decoded(self) -> None:
        # Base64("123-45-6789")
        assert "ssn" not in _found("MTIzLTQ1LTY3ODk=")

    def test_newline_split(self) -> None:
        assert "ssn" in _found("123-45\n-6789")


class TestAdversarialCreditCard:
    """Credit-card adversarial evasion variants."""

    def test_standard(self) -> None:
        assert "credit_card" in _found("4111 1111 1111 1111")

    def test_zero_width(self) -> None:
        assert "credit_card" in _found("4111\u200b1111 1111 1111")

    def test_unicode_digit_fullwidth(self) -> None:
        # ４１１１ 1111 1111 1111
        assert "credit_card" in _found("\uff14\uff11\uff11\uff11 1111 1111 1111")

    def test_url_encoded_space(self) -> None:
        # %20 → space after URL-decode
        assert "credit_card" in _found("4111%201111%201111%201111")

    def test_base64_not_decoded(self) -> None:
        # Base64("4111111111111111")
        assert "credit_card" not in _found("NDExMTExMTExMTExMTExMQ==")

    def test_newline_split(self) -> None:
        assert "credit_card" in _found("4111 1111\n1111 1111")


class TestAdversarialPhoneUS:
    """US phone adversarial evasion variants."""

    def test_standard(self) -> None:
        assert "phone_us" in _found("+1-555-867-5309")

    def test_zero_width(self) -> None:
        assert "phone_us" in _found("555\u200b-867-5309")

    def test_unicode_digit_fullwidth(self) -> None:
        # ５５５-867-5309
        assert "phone_us" in _found("\uff15\uff15\uff15-867-5309")

    def test_url_encoded_plus(self) -> None:
        # %2B → + after URL-decode
        assert "phone_us" in _found("%2B1-555-867-5309")

    def test_base64_not_decoded(self) -> None:
        # Base64("555-867-5309")
        assert "phone_us" not in _found("NTU1LTg2Ny01MzA5")

    def test_newline_split(self) -> None:
        assert "phone_us" in _found("555-867\n5309")


class TestAdversarialIPAddress:
    """IPv4 adversarial evasion variants."""

    def test_standard(self) -> None:
        assert "ip_address" in _found("192.168.1.1")

    def test_zero_width(self) -> None:
        assert "ip_address" in _found("192.168\u200b.1.1")

    def test_unicode_digit_fullwidth(self) -> None:
        # １９２.１６８.１.１
        assert "ip_address" in _found("\uff11\uff19\uff12.\uff11\uff16\uff18.\uff11.\uff11")

    def test_url_encoded_dot(self) -> None:
        # %2E → . after URL-decode
        assert "ip_address" in _found("192%2E168%2E1%2E1")

    def test_base64_not_decoded(self) -> None:
        # Base64("192.168.1.1")
        assert "ip_address" not in _found("MTkyLjE2OC4xLjE=")

    def test_newline_split(self) -> None:
        assert "ip_address" in _found("192.168.1\n.1")


# ===========================================================================
# Section 2 — False-Positive Matrix (≥ 10 per class)
# ===========================================================================


@pytest.mark.parametrize(
    "text",
    [
        "@mention no local part",
        "foo@",
        "@example.com",
        "not-an-email",
        "user@@double.at",
        "a @b",
        "price is 5.99@cost",
        "data=abc==",
        "file.txt",
        "v1.2@",
        "just-some-text@",
    ],
)
def test_email_false_positives(text: str) -> None:
    """Inputs that look or feel email-adjacent must not trigger email detection."""
    assert "email" not in _found(text), f"False-positive email detection on {text!r}"


@pytest.mark.parametrize(
    "text",
    [
        "000-45-6789",   # forbidden area code 000
        "666-12-3456",   # forbidden area code 666
        "900-12-3456",   # forbidden 9xx area code
        "123-00-6789",   # forbidden 00 middle group
        "123-45-0000",   # forbidden 0000 serial
        "12-345-6789",   # wrong group sizes (2-3-4)
        "1234-56-789",   # wrong group sizes (4-2-3)
        "123456789",     # unseparated 9-digit run
        "12-34-567",     # too few digits
        "product-code-ABC",
        "2024-01-15",    # ISO date looks like three groups
    ],
)
def test_ssn_false_positives(text: str) -> None:
    """Inputs structurally close to SSN must not trigger ssn detection."""
    assert "ssn" not in _found(text), f"False-positive SSN detection on {text!r}"


@pytest.mark.parametrize(
    "text",
    [
        "1234 5678 9012",          # only 12 digits (3 × 4)
        "1234",                    # 4-digit PIN
        "4111 1111 1111",          # 12 digits, not 16
        "1234-5678-9012",          # hyphen-separated 12 digits
        "12345",                   # too short
        "1234 5678 9012 345",      # 15 digits in 4 groups (wrong group split)
        "order-4111-9090",         # partial in mixed context
        "v4.11.11.1111",           # version string
        "987 654 3210 123",        # 12 digits wrong grouping
        "SKU-4111111111111111X",   # trailing non-digit breaks \b boundary
        "zip: 12345",              # 5-digit ZIP
    ],
)
def test_credit_card_false_positives(text: str) -> None:
    """Non-card numeric sequences must not trigger credit_card detection."""
    assert "credit_card" not in _found(text), f"False-positive CC detection on {text!r}"


@pytest.mark.parametrize(
    "text",
    [
        "867-5309",          # 7-digit local number (no area code)
        "ext 5309",          # 4-digit extension
        "1234",              # 4-digit
        "55-867-5309",       # 2-digit area code (not 3)
        "5555-867-5309",     # 4-digit area code (not 3)
        "+44 20 7946 0958",  # UK number, no US structure
        "fax-number-here",   # no digits
        "123",               # 3-digit
        "12-34-5678",        # 2-2-4 grouping
        "(555)",             # area code only, no subscriber
        "867.53.09",         # wrong grouping / too few digits
    ],
)
def test_phone_false_positives(text: str) -> None:
    """Non-US phone strings must not trigger phone_us detection."""
    assert "phone_us" not in _found(text), f"False-positive phone detection on {text!r}"


@pytest.mark.parametrize(
    "text",
    [
        "999.999.999.999",   # all octets > 255
        "256.0.0.1",         # first octet 256
        "1.256.3.4",         # second octet 256
        "v3.11.14.0",        # version with 'v' prefix
        "10.0.0",            # only 3 octets
        "1.2.3",             # 3 octets
        "...",               # no digits
        "a.b.c.d",           # non-digit groups
        "12.345.6789",       # 3-part decimal (3 groups)
        "rate: 12.345.678",  # 3 groups with context
        "999.0.0.1",         # first octet 999 (> 255)
    ],
)
def test_ip_false_positives(text: str) -> None:
    """Non-IP strings must not trigger ip_address detection."""
    assert "ip_address" not in _found(text), f"False-positive IP detection on {text!r}"


# ===========================================================================
# Section 3 — Performance test
# ===========================================================================


def test_pii_scrub_performance_50_instances_10k_chars() -> None:
    """Scrubbing a 10 000-char prompt containing 50 PII instances must complete in < 50 ms.

    The 50 instances are 10 of each class, interspersed with filler text so the
    total length reaches ≥ 10 000 characters.
    """
    pii_snippets = [
        # 10 emails
        "user1@example.com",
        "alice.bob@company.org",
        "support+tag@domain.net",
        "test.user@subdomain.example.co.uk",
        "no-reply@mail.example.io",
        "admin@internal.corp",
        "user2@example.com",
        "user3@example.com",
        "user4@example.com",
        "user5@example.com",
        # 10 SSNs
        "123-45-6789",
        "234-56-7890",
        "345-67-8901",
        "456-78-9012",
        "567-89-0123",
        "678-90-1234",
        "789-01-2345",
        "321-67-8901",
        "432-78-9012",
        "543-89-0123",
        # 10 credit cards
        "4111 1111 1111 1111",
        "5500 0000 0000 0004",
        "3714 496353 98431",
        "6011 1111 1111 1117",
        "3530 1113 3330 0000",
        "4111 1111 1111 1112",
        "4111 1111 1111 1113",
        "4111 1111 1111 1114",
        "4111 1111 1111 1115",
        "4111 1111 1111 1116",
        # 10 US phones
        "+1-555-867-5309",
        "(800) 555-1234",
        "212-555-6789",
        "+1 (415) 555-2671",
        "303-555-0100",
        "+1-555-867-5310",
        "+1-555-867-5311",
        "+1-555-867-5312",
        "+1-555-867-5313",
        "+1-555-867-5314",
        # 10 IP addresses
        "192.168.1.1",
        "10.0.0.1",
        "172.16.254.1",
        "203.0.113.42",
        "8.8.8.8",
        "1.2.3.4",
        "127.0.0.1",
        "255.255.255.0",
        "100.64.0.1",
        "198.51.100.7",
    ]
    filler = "The quick brown fox jumps over the lazy dog. " * 60  # ~2700 chars
    parts: list[str] = []
    for snippet in pii_snippets:
        parts.append(snippet)
        parts.append(filler[: len(filler) // len(pii_snippets)])
    prompt = " ".join(parts)
    # Pad to ≥ 10 000 characters
    while len(prompt) < 10_000:
        prompt += " " + filler

    assert len(prompt) >= 10_000, "Prompt must be at least 10 000 characters"

    guard = Guardrails()
    start = time.perf_counter()
    result = guard.mask_pii(prompt)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.05, f"PII scrub took {elapsed * 1000:.1f} ms (limit 50 ms)"

    # Sanity: at least several classes were detected
    assert len(result.found_types) >= 3, "Expected at least 3 PII classes detected"


# ===========================================================================
# Section 4 — scrub() direct call (hits line 186 → 100 % line coverage)
# ===========================================================================


def test_scrub_returns_mask_result_via_scrub_method() -> None:
    """Calling scrub() directly must apply PII masking and return a MaskResult."""
    guard = Guardrails()
    result = guard.scrub("Contact user@example.com or 192.168.1.1")
    assert "email" in result.found_types
    assert "ip_address" in result.found_types
    assert "REDACTED" in result.text


def test_scrub_clean_text_no_pii() -> None:
    """scrub() on PII-free text must return an empty found_types list."""
    guard = Guardrails()
    result = guard.scrub("The project deadline is next Monday.")
    assert result.found_types == []
    assert result.text == "The project deadline is next Monday."
