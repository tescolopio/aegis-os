"""Tests for the Governance Session Manager."""

from __future__ import annotations

import pytest
from jose import JWTError, jwt

from src.config import settings
from src.governance.session_mgr import (
    DPoPReplayError,
    SessionManager,
    TokenBindingError,
    TokenClaims,
)


@pytest.fixture()
def mgr() -> SessionManager:
    return SessionManager()


def _configure_es256(monkeypatch: pytest.MonkeyPatch) -> tuple[str, dict[str, str]]:
    """Configure ES256 signing settings for sender-constrained token tests."""
    private_key_pem, public_jwk = SessionManager.generate_dpop_key_pair()
    public_pem = SessionManager.public_pem_from_jwk(public_jwk)
    monkeypatch.setattr(settings, "token_algorithm", "ES256")
    monkeypatch.setattr(settings, "token_private_key", private_key_pem)
    monkeypatch.setattr(settings, "token_public_key", public_pem)
    return private_key_pem, public_jwk


def test_issue_token_returns_string(mgr: SessionManager) -> None:
    token = mgr.issue_token(agent_type="finance", requester_id="user-123")
    assert isinstance(token, str)
    assert len(token) > 0


def test_issued_token_contains_expected_claims(mgr: SessionManager) -> None:
    token = mgr.issue_token(agent_type="hr", requester_id="user-456")
    payload = jwt.decode(token, settings.token_secret_key, algorithms=[settings.token_algorithm])
    assert payload["agent_type"] == "hr"
    assert payload["sub"] == "user-456"
    assert "jti" in payload
    assert "exp" in payload
    assert "iat" in payload


def test_validate_token_returns_claims(mgr: SessionManager) -> None:
    token = mgr.issue_token(agent_type="it", requester_id="user-789", metadata={"foo": "bar"})
    claims = mgr.validate_token(token)
    assert isinstance(claims, TokenClaims)
    assert claims.agent_type == "it"
    assert claims.sub == "user-789"
    assert claims.metadata == {"foo": "bar"}


def test_token_not_expired_immediately(mgr: SessionManager) -> None:
    token = mgr.issue_token(agent_type="general", requester_id="user-111")
    claims = mgr.validate_token(token)
    assert not mgr.is_expired(claims)


def test_time_remaining_positive(mgr: SessionManager) -> None:
    token = mgr.issue_token(agent_type="general", requester_id="user-222")
    claims = mgr.validate_token(token)
    assert mgr.time_remaining(claims) > 0


def test_issue_token_raises_on_empty_agent_type(mgr: SessionManager) -> None:
    with pytest.raises(ValueError):
        mgr.issue_token(agent_type="", requester_id="user-333")


def test_issue_token_raises_on_empty_requester(mgr: SessionManager) -> None:
    with pytest.raises(ValueError):
        mgr.issue_token(agent_type="finance", requester_id="")


def test_invalid_token_raises_error(mgr: SessionManager) -> None:
    with pytest.raises(JWTError):
        mgr.validate_token("this.is.not.a.valid.token")


def test_sender_constrained_token_contains_cnf_thumbprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key_pem, public_jwk = _configure_es256(monkeypatch)
    manager = SessionManager()
    token = manager.issue_sender_constrained_token(
        agent_type="platform",
        requester_id="user-900",
        public_jwk=public_jwk,
        task_id="task-1",
    )

    payload = jwt.decode(token, settings.token_public_key, algorithms=["ES256"])
    assert private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert payload["task_id"] == "task-1"
    assert payload["cnf"]["jkt"] == manager.public_jwk_thumbprint(public_jwk)


def test_validate_sender_constrained_token_accepts_matching_dpop_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key_pem, public_jwk = _configure_es256(monkeypatch)
    manager = SessionManager()
    token = manager.issue_sender_constrained_token(
        agent_type="platform",
        requester_id="user-901",
        public_jwk=public_jwk,
        task_id="task-2",
    )
    proof = manager.issue_dpop_proof(
        private_key_pem,
        public_jwk,
        http_method="POST",
        http_url="https://api.example.test/v1/llm",
        access_token=token,
    )

    claims = manager.validate_sender_constrained_token(
        token,
        proof,
        http_method="POST",
        http_url="https://api.example.test/v1/llm",
    )
    assert claims.task_id == "task-2"
    assert claims.cnf is not None
    assert claims.cnf.jkt == manager.public_jwk_thumbprint(public_jwk)


def test_validate_sender_constrained_token_rejects_wrong_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key_pem, public_jwk = _configure_es256(monkeypatch)
    manager = SessionManager()
    token = manager.issue_sender_constrained_token(
        agent_type="platform",
        requester_id="user-902",
        public_jwk=public_jwk,
    )

    attacker_private_key, attacker_public_jwk = SessionManager.generate_dpop_key_pair()
    attacker_proof = manager.issue_dpop_proof(
        attacker_private_key,
        attacker_public_jwk,
        http_method="GET",
        http_url="https://api.example.test/v1/llm",
        access_token=token,
    )

    assert private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
    with pytest.raises(TokenBindingError):
        manager.validate_sender_constrained_token(
            token,
            attacker_proof,
            http_method="GET",
            http_url="https://api.example.test/v1/llm",
        )


def test_validate_sender_constrained_token_rejects_replayed_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key_pem, public_jwk = _configure_es256(monkeypatch)
    manager = SessionManager()
    token = manager.issue_sender_constrained_token(
        agent_type="platform",
        requester_id="user-903",
        public_jwk=public_jwk,
    )
    proof = manager.issue_dpop_proof(
        private_key_pem,
        public_jwk,
        http_method="POST",
        http_url="https://api.example.test/v1/llm",
        access_token=token,
        proof_jti="proof-123",
    )

    manager.validate_sender_constrained_token(
        token,
        proof,
        http_method="POST",
        http_url="https://api.example.test/v1/llm",
    )
    with pytest.raises(DPoPReplayError):
        manager.validate_sender_constrained_token(
            token,
            proof,
            http_method="POST",
            http_url="https://api.example.test/v1/llm",
        )
