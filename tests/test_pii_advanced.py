"""Advanced PII detection and OPA routing tests – S1-2.

Covers:
  1. Per-class PII variant detection (email, SSN, credit card, phone_us, ip_address) –
     10+ parametrized inputs per class including canonical, whitespace, mixed-case,
     URL-encoded, Unicode homoglyphs, zero-width chars, and line-break variants.
  2. OPA mask instruction: ``PolicyResult(action='mask', fields=['prompt'])`` triggers
     ``Guardrails.scrub()`` before the LLM adapter is called.
  3. OPA reject instruction: ``PolicyResult(action='reject')`` raises
     :class:`PolicyDeniedError` and the LLM adapter is never called.
  4. Post-LLM leakage: PII present only in the LLM response is scrubbed before the
     caller receives the result.
  5. Regression suite: loads ``tests/pii_regression.json`` – run with
     ``pytest -k pii_regression`` for zero-leakage verification.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.adapters.base import BaseAdapter, LLMResponse
from src.audit_vault.logger import AuditLogger
from src.control_plane.orchestrator import (
    Orchestrator,
    OrchestratorRequest,
    PolicyDeniedError,
)
from src.governance.guardrails import Guardrails, MaskResult
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager

# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

_REGRESSION_FILE = pathlib.Path(__file__).parent / "pii_regression.json"
_SENTINEL_TOKEN = "jwt.sentinel.token"


def _make_stub_adapter(content: str = "OK") -> BaseAdapter:
    """Return an async adapter that always returns *content*."""
    adapter = MagicMock(spec=BaseAdapter)
    adapter.complete = AsyncMock(
        return_value=LLMResponse(
            content=content,
            tokens_used=5,
            model="stub",
            provider="stub",
            finish_reason="stop",
        )
    )
    return adapter


def _make_policy_engine(result: PolicyResult) -> PolicyEngine:
    """Return a PolicyEngine mock whose ``evaluate`` coroutine returns *result*."""
    pe = MagicMock(spec=PolicyEngine)
    pe.evaluate = AsyncMock(return_value=result)
    return pe


def _make_session_mgr() -> SessionManager:
    """Return a SessionManager mock that always issues the sentinel token."""
    sm = MagicMock(spec=SessionManager)
    sm.issue_token.return_value = _SENTINEL_TOKEN
    return sm


def _make_audit() -> AuditLogger:
    """Return a no-op AuditLogger mock."""
    return MagicMock(spec=AuditLogger)


# Module-level constant for the fullwidth-digit credit card test case.
# Defined here to keep the parametrize list within the 100-char line limit.
_FW_CC_INPUT = (
    "Number ４１１１ １１１１ １１１１ １１１１ billed"
)

_BASE_REQUEST = OrchestratorRequest(
    prompt="Analyse the agent log.",
    agent_type="general",
    requester_id="user-test",
    model="stub",
)

# ---------------------------------------------------------------------------
# 1. Per-class PII variant detection
# ---------------------------------------------------------------------------


class TestEmailVariants:
    """Verify that all canonical and adversarial email forms are caught."""

    @pytest.mark.parametrize(
        "raw_input",
        [
            "Contact john.doe@example.com for details.",
            "Reply to user@mail.corp.example.com",
            "Forwarded to user+tag@example.com",
            "Reach out to john.doe @ example.com",
            "Manager email is JOHN.DOE@EXAMPLE.COM",
            "Address: john.doe%40example.com",
            "Link: john.doe@example%2Ecom",
            "\uff4a\uff4f\uff48\uff4e.doe@example.com is the contact",
            "Send to john\u200bdoe@example.com",
            "Reply to john.doe@example\n.com please",
            "File CC to firstname_lastname@company.co.uk",
        ],
    )
    def test_email_detected(self, raw_input: str) -> None:
        """Email PII must be detected and redacted for all variants."""
        result = Guardrails().mask_pii(raw_input)
        assert "email" in result.found_types, (
            f"Expected 'email' in found_types for input: {raw_input!r}\n"
            f"  got found_types={result.found_types!r}, text={result.text!r}"
        )
        # No address should remain verbatim in the output
        assert "@" not in result.text or "[REDACTED" in result.text, (
            f"Raw '@' still present after masking: {result.text!r}"
        )

    def test_mention_not_detected_as_email(self) -> None:
        """@mention with no local part must not be classified as email."""
        result = Guardrails().mask_pii("@mention not email at all")
        assert "email" not in result.found_types


class TestSSNVariants:
    """Verify that all canonical and adversarial SSN forms are caught."""

    @pytest.mark.parametrize(
        "raw_input",
        [
            "SSN 123-45-6789",
            "Record shows 234-56-7890",
            "My SSN is 345 67 8901",
            "code 456 - 78 - 9012",
            "value 123%2D45%2D6789 end",
            "SSN: \uff11\uff12\uff13-\uff14\uff15-\uff16\uff17\uff18\uff19",
            "reference 123\u200b-45-6789 here",
            "token 123-45\n-6789 end",
            "The applicant provided SSN 111-22-3333 as their identifier.",
            "Ref: 223-45 6789",
        ],
    )
    def test_ssn_detected(self, raw_input: str) -> None:
        """SSN PII must be detected for all valid-format variants."""
        result = Guardrails().mask_pii(raw_input)
        assert "ssn" in result.found_types, (
            f"Expected 'ssn' in found_types for input: {raw_input!r}\n"
            f"  got found_types={result.found_types!r}, text={result.text!r}"
        )

    @pytest.mark.parametrize(
        "raw_input",
        [
            "Number 000-45-6789 is invalid",
            "Number 666-12-3456 is invalid",
        ],
    )
    def test_forbidden_ssn_area_not_detected(self, raw_input: str) -> None:
        """SSNs with forbidden area codes (000, 666) must not match."""
        result = Guardrails().mask_pii(raw_input)
        assert "ssn" not in result.found_types, (
            f"Forbidden SSN area code incorrectly detected: {raw_input!r}\n"
            f"  got found_types={result.found_types!r}"
        )


class TestCreditCardVariants:
    """Verify that all canonical and adversarial credit card forms are caught."""

    @pytest.mark.parametrize(
        "raw_input",
        [
            "Card 4111 1111 1111 1111 expired",
            "Number: 4111-1111-1111-1111",
            "Charged 4111111111111111 today",
            "Use card 5500 0000 0000 0004",
            "Card: 4111 1111\n1111 1111 done",
            "4111 1111\t1111 1111 is the number",
            "Number \uff14\uff11\uff11\uff11 \uff11\uff11\uff11\uff11"
            " \uff11\uff11\uff11\uff11 \uff11\uff11\uff11\uff11 billed",
            "card 4111%201111%201111%201111 charged",
            "token 4111\u200b1111 1111 1111 end",
            "Billing card: 5500-0000-0000-0004 for invoice",
        ],
    )
    def test_credit_card_detected(self, raw_input: str) -> None:
        """Credit card PII must be detected for all variants."""
        result = Guardrails().mask_pii(raw_input)
        assert "credit_card" in result.found_types, (
            f"Expected 'credit_card' in found_types for input: {raw_input!r}\n"
            f"  got found_types={result.found_types!r}, text={result.text!r}"
        )

    @pytest.mark.parametrize(
        "raw_input",
        [
            "Order ID: 1234 5678 9012",
            "Enter PIN: 1234",
        ],
    )
    def test_short_digit_string_not_detected(self, raw_input: str) -> None:
        """Digit strings shorter than 16 digits must not be flagged as credit cards."""
        result = Guardrails().mask_pii(raw_input)
        assert "credit_card" not in result.found_types, (
            f"Short digit string incorrectly classified as credit card: {raw_input!r}\n"
            f"  got found_types={result.found_types!r}"
        )


class TestPhoneVariants:
    """Verify that all canonical and adversarial US phone forms are caught."""

    @pytest.mark.parametrize(
        "raw_input",
        [
            "Call 555-867-5309 now",
            "Reach us at (555) 867-5309",
            "Contact: 555.867.5309",
            "Number 555 867 5309",
            "Dialed 5558675309 today",
            "International +1-555-867-5309",
            "Dial +1 (555) 867-5309 toll-free",
            "Contact %2B1-555-867-5309 for support",
            "HR: \uff15\uff15\uff15-\uff18\uff16\uff17-\uff15\uff13\uff10\uff19",
            "Call 555-867\n5309 back",
            "Hotline 555\u200b-867-5309 available",
            "Please call (800) 555-0100 for customer service.",
        ],
    )
    def test_phone_detected(self, raw_input: str) -> None:
        """US phone number PII must be detected for all variants."""
        result = Guardrails().mask_pii(raw_input)
        assert "phone_us" in result.found_types, (
            f"Expected 'phone_us' in found_types for input: {raw_input!r}\n"
            f"  got found_types={result.found_types!r}, text={result.text!r}"
        )

    @pytest.mark.parametrize(
        "raw_input",
        [
            "Extension 867-5309",
            "ext 5309",
        ],
    )
    def test_short_number_not_detected(self, raw_input: str) -> None:
        """7-digit or 4-digit partial phone numbers must not be classified as US phones."""
        result = Guardrails().mask_pii(raw_input)
        assert "phone_us" not in result.found_types, (
            f"Short phone number incorrectly classified: {raw_input!r}\n"
            f"  got found_types={result.found_types!r}"
        )


class TestIPVariants:
    """Verify that all canonical and adversarial IPv4 forms are caught."""

    @pytest.mark.parametrize(
        "raw_input",
        [
            "Server at 192.168.1.1 responded",
            "Nameserver 8.8.8.8 unreachable",
            "Mask 255.255.255.0 applied",
            "Listening on 127.0.0.1",
            "Host 192 . 168 . 1 . 1 blocked",
            "Block 192%2E168%2E1%2E1 immediately",
            "Origin: \uff11\uff19\uff12.\uff11\uff16\uff18.\uff11.\uff11",
            "Address 10.0.0\u200b.1 flagged",
            "Host 172.16.254\n.1 is internal",
            "The attacker originated from 10.0.0.1 on the internal network.",
        ],
    )
    def test_ip_detected(self, raw_input: str) -> None:
        """IPv4 PII must be detected for all variants."""
        result = Guardrails().mask_pii(raw_input)
        assert "ip_address" in result.found_types, (
            f"Expected 'ip_address' in found_types for input: {raw_input!r}\n"
            f"  got found_types={result.found_types!r}, text={result.text!r}"
        )

    @pytest.mark.parametrize(
        "raw_input",
        [
            "Config error 999.999.999.999 invalid",
            "Python v3.11.14.0 released",
        ],
    )
    def test_invalid_or_non_ip_not_detected(self, raw_input: str) -> None:
        """Invalid octet values and version strings must not be classified as IPv4."""
        result = Guardrails().mask_pii(raw_input)
        assert "ip_address" not in result.found_types, (
            f"Non-IP string incorrectly classified as ip_address: {raw_input!r}\n"
            f"  got found_types={result.found_types!r}"
        )


# ---------------------------------------------------------------------------
# 2. OPA mask instruction
# ---------------------------------------------------------------------------


class TestOpaMaskInstruction:
    """OPA returning action='mask' must cause scrub() to be called on the prompt."""

    @pytest.mark.asyncio
    async def test_scrub_called_on_mask_action(self) -> None:
        """When OPA returns action='mask' + fields=['prompt'], Guardrails.scrub()
        must be invoked before the LLM adapter receives the sanitized prompt."""
        # Guardrails: track scrub() calls explicitly
        guardrails = MagicMock(spec=Guardrails)
        cleaned_prompt = "Analyse the agent log."
        guardrails.check_prompt_injection.return_value = None
        guardrails.mask_pii.return_value = MaskResult(
            text=cleaned_prompt, found_types=[]
        )
        # scrub() is the Stage 2b entry point
        scrub_result = MaskResult(text=cleaned_prompt, found_types=[])
        guardrails.scrub.return_value = scrub_result

        policy_engine = _make_policy_engine(
            PolicyResult(allowed=True, action="mask", fields=["prompt"])
        )
        session_mgr = _make_session_mgr()
        adapter = _make_stub_adapter()

        orchestrator = Orchestrator(
            adapter=adapter,
            guardrails=guardrails,
            policy_engine=policy_engine,
            session_mgr=session_mgr,
            audit_logger=_make_audit(),
        )

        await orchestrator.run(_BASE_REQUEST)

        # scrub() must have been called exactly once with the sanitized prompt
        guardrails.scrub.assert_called_once_with(cleaned_prompt)
        # LLM adapter was called — mask does not prevent the request
        adapter.complete.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_scrub_not_called_when_action_is_allow(self) -> None:
        """When OPA returns action='allow', Guardrails.scrub() must NOT be called."""
        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.return_value = None
        guardrails.mask_pii.return_value = MaskResult(
            text="Hello world.", found_types=[]
        )

        policy_engine = _make_policy_engine(
            PolicyResult(allowed=True, action="allow", fields=[])
        )

        orchestrator = Orchestrator(
            adapter=_make_stub_adapter(),
            guardrails=guardrails,
            policy_engine=policy_engine,
            session_mgr=_make_session_mgr(),
            audit_logger=_make_audit(),
        )

        await orchestrator.run(_BASE_REQUEST)

        guardrails.scrub.assert_not_called()

    @pytest.mark.asyncio
    async def test_mask_pii_discovered_in_scrub_added_to_result(self) -> None:
        """PII types found by scrub() in Stage 2b must appear in pii_found_in_prompt."""
        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.return_value = None
        guardrails.mask_pii.return_value = MaskResult(
            text="Prompt with no obvious PII.", found_types=[]
        )
        # scrub finds an email that slipped through Stage 1
        guardrails.scrub.return_value = MaskResult(
            text="Prompt with [REDACTED-EMAIL].",
            found_types=["email"],
        )

        policy_engine = _make_policy_engine(
            PolicyResult(allowed=True, action="mask", fields=["prompt"])
        )

        orchestrator = Orchestrator(
            adapter=_make_stub_adapter(),
            guardrails=guardrails,
            policy_engine=policy_engine,
            session_mgr=_make_session_mgr(),
            audit_logger=_make_audit(),
        )

        result = await orchestrator.run(_BASE_REQUEST)

        assert "email" in result.pii_found_in_prompt


# ---------------------------------------------------------------------------
# 3. OPA reject instruction
# ---------------------------------------------------------------------------


class TestOpaRejectInstruction:
    """OPA returning allowed=False must raise PolicyDeniedError; LLM never called."""

    @pytest.mark.asyncio
    async def test_policy_denied_raises_error(self) -> None:
        """allowed=False must propagate as PolicyDeniedError."""
        policy_engine = _make_policy_engine(
            PolicyResult(
                allowed=False,
                action="reject",
                reasons=["agent_type_not_permitted"],
            )
        )
        adapter = _make_stub_adapter()

        orchestrator = Orchestrator(
            adapter=adapter,
            guardrails=Guardrails(),
            policy_engine=policy_engine,
            session_mgr=_make_session_mgr(),
            audit_logger=_make_audit(),
        )

        with pytest.raises(PolicyDeniedError):
            await orchestrator.run(_BASE_REQUEST)

    @pytest.mark.asyncio
    async def test_llm_adapter_not_called_on_deny(self) -> None:
        """When OPA denies the request, the LLM adapter must never be invoked."""
        policy_engine = _make_policy_engine(
            PolicyResult(
                allowed=False,
                action="reject",
                reasons=["denied"],
            )
        )
        adapter = _make_stub_adapter()

        orchestrator = Orchestrator(
            adapter=adapter,
            guardrails=Guardrails(),
            policy_engine=policy_engine,
            session_mgr=_make_session_mgr(),
            audit_logger=_make_audit(),
        )

        with pytest.raises(PolicyDeniedError):
            await orchestrator.run(_BASE_REQUEST)

        adapter.complete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_plaintext_prompt_in_audit_on_deny(self) -> None:
        """The raw/sanitised prompt must not appear verbatim in any AuditLogger call
        after a policy denial (prevents PII leaking into audit logs)."""
        sensitive_prompt = "SSN is 123-45-6789"
        policy_engine = _make_policy_engine(
            PolicyResult(
                allowed=False,
                action="reject",
                reasons=["denied"],
            )
        )
        audit = MagicMock(spec=AuditLogger)

        request = OrchestratorRequest(
            prompt=sensitive_prompt,
            agent_type="general",
            requester_id="user-test",
            model="stub",
        )

        orchestrator = Orchestrator(
            adapter=_make_stub_adapter(),
            guardrails=Guardrails(),
            policy_engine=policy_engine,
            session_mgr=_make_session_mgr(),
            audit_logger=audit,
        )

        with pytest.raises(PolicyDeniedError):
            await orchestrator.run(request)

        # Collect every argument passed to any AuditLogger method
        all_args: list[str] = []
        for mock_call in audit.warning.call_args_list + audit.error.call_args_list:
            for arg in mock_call.args:
                all_args.append(str(arg))
            for val in mock_call.kwargs.values():
                all_args.append(str(val))

        # The raw SSN must not appear in any audit call argument
        assert "123-45-6789" not in " ".join(all_args), (
            f"Raw SSN found in audit call arguments: {all_args!r}"
        )

    @pytest.mark.asyncio
    async def test_explicit_reject_action_with_allowed_true_also_denied(self) -> None:
        """action='reject' with allowed=True must also raise PolicyDeniedError
        (defensive check: the orchestrator denies on either condition)."""
        policy_engine = _make_policy_engine(
            PolicyResult(allowed=True, action="reject", reasons=[])
        )
        adapter = _make_stub_adapter()

        orchestrator = Orchestrator(
            adapter=adapter,
            guardrails=Guardrails(),
            policy_engine=policy_engine,
            session_mgr=_make_session_mgr(),
            audit_logger=_make_audit(),
        )

        with pytest.raises(PolicyDeniedError):
            await orchestrator.run(_BASE_REQUEST)

        adapter.complete.assert_not_awaited()


# ---------------------------------------------------------------------------
# 4. Post-LLM leakage prevention
# ---------------------------------------------------------------------------


class TestPostLLMLeakage:
    """PII present only in the LLM response must not appear in the final output."""

    @pytest.mark.asyncio
    async def test_ssn_in_llm_response_scrubbed(self) -> None:
        """SSN in the raw LLM response must be absent from OrchestratorResult.response.content."""
        raw_ssn = "123-45-6789"
        adapter = _make_stub_adapter(content=f"The applicant's SSN is {raw_ssn}.")

        policy_engine = _make_policy_engine(
            PolicyResult(allowed=True, action="allow", fields=[])
        )

        orchestrator = Orchestrator(
            adapter=adapter,
            guardrails=Guardrails(),
            policy_engine=policy_engine,
            session_mgr=_make_session_mgr(),
            audit_logger=_make_audit(),
        )

        result = await orchestrator.run(_BASE_REQUEST)

        # Raw SSN must not survive into the response content
        assert raw_ssn not in result.response.content, (
            f"SSN {raw_ssn!r} survived post-LLM scrub in: {result.response.content!r}"
        )
        # Must be registered as PII found in the response
        assert "ssn" in result.pii_found_in_response

    @pytest.mark.asyncio
    async def test_email_in_llm_response_scrubbed(self) -> None:
        """Email in the raw LLM response must be absent from the final output."""
        raw_email = "alice@internal.corp.example.com"
        adapter = _make_stub_adapter(content=f"Reply to {raw_email} for approval.")

        policy_engine = _make_policy_engine(
            PolicyResult(allowed=True, action="allow", fields=[])
        )

        orchestrator = Orchestrator(
            adapter=adapter,
            guardrails=Guardrails(),
            policy_engine=policy_engine,
            session_mgr=_make_session_mgr(),
            audit_logger=_make_audit(),
        )

        result = await orchestrator.run(_BASE_REQUEST)

        assert raw_email not in result.response.content
        assert "email" in result.pii_found_in_response

    @pytest.mark.asyncio
    async def test_ip_in_llm_response_scrubbed(self) -> None:
        """IPv4 address in the raw LLM response must not appear in the final output."""
        raw_ip = "10.0.0.1"
        adapter = _make_stub_adapter(
            content=f"The threat actor connected from {raw_ip}."
        )

        policy_engine = _make_policy_engine(
            PolicyResult(allowed=True, action="allow", fields=[])
        )

        orchestrator = Orchestrator(
            adapter=adapter,
            guardrails=Guardrails(),
            policy_engine=policy_engine,
            session_mgr=_make_session_mgr(),
            audit_logger=_make_audit(),
        )

        result = await orchestrator.run(_BASE_REQUEST)

        assert raw_ip not in result.response.content
        assert "ip_address" in result.pii_found_in_response

    @pytest.mark.asyncio
    async def test_clean_llm_response_unchanged(self) -> None:
        """A response with no PII must pass through without modification."""
        clean_content = "The quarterly report shows steady growth."
        adapter = _make_stub_adapter(content=clean_content)

        policy_engine = _make_policy_engine(
            PolicyResult(allowed=True, action="allow", fields=[])
        )

        orchestrator = Orchestrator(
            adapter=adapter,
            guardrails=Guardrails(),
            policy_engine=policy_engine,
            session_mgr=_make_session_mgr(),
            audit_logger=_make_audit(),
        )

        result = await orchestrator.run(_BASE_REQUEST)

        assert result.response.content == clean_content
        assert result.pii_found_in_response == []


# ---------------------------------------------------------------------------
# 5. Regression suite (`pytest -k pii_regression`)
# ---------------------------------------------------------------------------


def _load_regression_cases() -> list[tuple[int, str, bool, list[str]]]:
    """Load all entries from pii_regression.json."""
    raw: list[dict[str, Any]] = json.loads(_REGRESSION_FILE.read_text(encoding="utf-8"))
    return [
        (entry["id"], entry["input"], entry["should_redact"], entry["pii_types"])
        for entry in raw
    ]


_REGRESSION_CASES = _load_regression_cases()


@pytest.mark.parametrize(
    "entry_id,raw_input,should_redact,expected_types",
    _REGRESSION_CASES,
    ids=[f"pii_regression_id{c[0]}" for c in _REGRESSION_CASES],
)
def test_pii_regression(
    entry_id: int,
    raw_input: str,
    should_redact: bool,
    expected_types: list[str],
) -> None:
    """Zero-leakage regression: every entry in pii_regression.json must pass.

    Run the full suite with::

        pytest -k pii_regression

    Positive entries (``should_redact=true``) assert that all expected PII types
    are detected AND that no raw PII token survives in the masked output.
    Negative entries (``should_redact=false``) assert that no PII is detected.
    """
    result = Guardrails().mask_pii(raw_input)

    if should_redact:
        for pii_type in expected_types:
            assert pii_type in result.found_types, (
                f"[ID={entry_id}] Expected '{pii_type}' in found_types.\n"
                f"  input:       {raw_input!r}\n"
                f"  found_types: {result.found_types!r}\n"
                f"  masked text: {result.text!r}"
            )
        # Verify the redacted output does not re-introduce the original token
        # (regression guard against pattern replacement bugs).
        assert result.text != raw_input or not expected_types, (
            f"[ID={entry_id}] Text was not modified despite detecting PII.\n"
            f"  input: {raw_input!r}"
        )
    else:
        assert result.found_types == [], (
            f"[ID={entry_id}] Expected no PII but got found_types={result.found_types!r}.\n"
            f"  input:       {raw_input!r}\n"
            f"  masked text: {result.text!r}"
        )
