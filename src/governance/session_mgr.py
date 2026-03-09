# Copyright 2026 Tim Escolopio / 3D Tech Solutions
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Session Manager - issues short-lived bearer and sender-constrained agent tokens.

This module preserves the existing short-lived JWT behaviour while adding a
forward-compatible path for asymmetric, sender-constrained tokens using DPoP.
The current public methods remain valid for HS256 bearer tokens, and new
methods allow the control plane to issue ES256 tokens that carry a
``cnf.jkt`` thumbprint and must be accompanied by a valid DPoP proof.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError
from pydantic import BaseModel, Field

from src.config import settings
from src.governance.replay_store import (
    DPoPReplayStore,
    InMemoryDPoPReplayStore,
    RedisDPoPReplayStore,
)


class TokenScopeError(PermissionError):
    """Raised when a presented JIT token is scoped to a different ``agent_type``
    than the one named in the current request.

    A token issued for ``agent_type="finance"`` must never be accepted for a
    request that declares ``agent_type="hr"``.  This prevents privilege
    escalation across agent-type boundaries.
    """


class TokenExpiredError(PermissionError):
    """Raised when a presented JIT token has passed its ``exp`` timestamp.

    The orchestrator must not forward the request to the LLM adapter after
    raising this error.  An audit event is emitted before the raise so the
    expiry is visible in the immutable audit trail.
    """


class TokenRevokedError(PermissionError):
    """Raised when a token's ``jti`` is present in the revocation list."""


class TokenActionError(PermissionError):
    """Raised when a token is used for an action outside ``allowed_actions``."""


class TokenBindingError(PermissionError):
    """Raised when a sender-constrained token is presented with the wrong key."""


class DPoPProofError(PermissionError):
    """Raised when a DPoP proof is malformed, expired, or otherwise invalid."""


class DPoPReplayError(DPoPProofError):
    """Raised when a DPoP proof ``jti`` is replayed inside the active TTL window."""


class ConfirmationClaims(BaseModel):
    """Confirmation claims for sender-constrained access tokens."""

    jkt: str


class TokenClaims(BaseModel):
    """Claims embedded in a JIT agent session token."""

    jti: str  # unique token ID
    sub: str  # requester / agent identity
    agent_type: str
    session_id: str | None = None
    task_id: str | None = None
    allowed_actions: list[str] = Field(default_factory=list)
    role: str | None = None
    issued_at: float
    expires_at: float
    metadata: dict[str, str] = Field(default_factory=dict)
    cnf: ConfirmationClaims | None = None


class DPoPProofClaims(BaseModel):
    """Claims embedded in a DPoP proof JWT."""

    jti: str
    htm: str
    htu: str
    iat: int
    ath: str | None = None
    nonce: str | None = None


def _b64url_encode(data: bytes) -> str:
    """Return URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(data: str) -> bytes:
    """Decode URL-safe base64 with optional omitted padding."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _curve_from_name(curve_name: str) -> ec.EllipticCurve:
    """Return the cryptography curve instance for a JWK ``crv`` name."""
    curves: dict[str, ec.EllipticCurve] = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }
    try:
        return curves[curve_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported JWK curve: {curve_name!r}") from exc


def _required_jwk_fields(jwk: Mapping[str, str]) -> dict[str, str]:
    """Return the RFC 7638 thumbprint fields for a supported public JWK."""
    kty = jwk.get("kty")
    if kty == "EC":
        return {
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"],
        }
    if kty == "RSA":
        return {
            "e": jwk["e"],
            "kty": jwk["kty"],
            "n": jwk["n"],
        }
    raise ValueError(f"Unsupported JWK key type: {kty!r}")


def _public_pem_from_jwk(jwk: Mapping[str, str]) -> str:
    """Convert a supported public JWK to PEM for JWT verification."""
    public_key: ec.EllipticCurvePublicKey | rsa.RSAPublicKey
    kty = jwk.get("kty")
    if kty == "EC":
        curve = _curve_from_name(jwk["crv"])
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_b64url_decode(jwk["x"]), "big"),
            int.from_bytes(_b64url_decode(jwk["y"]), "big"),
            curve,
        ).public_key()
    elif kty == "RSA":
        public_key = rsa.RSAPublicNumbers(
            e=int.from_bytes(_b64url_decode(jwk["e"]), "big"),
            n=int.from_bytes(_b64url_decode(jwk["n"]), "big"),
        ).public_key()
    else:
        raise ValueError(f"Unsupported JWK key type: {kty!r}")

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


class SessionManager:
    """Issues and validates short-lived scoped tokens for AI agents.

    Tokens expire after ``settings.token_expiry_seconds`` (default 15 minutes).
    Each token is scoped to a specific agent type, limiting the blast radius
    if a token is compromised.
    """

    def __init__(self, replay_store: DPoPReplayStore | None = None) -> None:
        """Initialise revocation, rotation, and DPoP replay-protection state."""
        self._revoked_jtis: dict[str, float] = {}
        self._rotation_index: dict[str, str] = {}
        self._replay_store = (
            replay_store if replay_store is not None else self._default_replay_store()
        )

    @staticmethod
    def _default_replay_store() -> DPoPReplayStore:
        """Create the configured replay store for DPoP proof ``jti`` values."""
        if settings.dpop_replay_store_url:
            return RedisDPoPReplayStore(settings.dpop_replay_store_url)
        if settings.aegis_env.lower() == "production":
            raise ValueError(
                "AEGIS_DPOP_REPLAY_STORE_URL must be configured in production for "
                "shared DPoP proof replay protection"
            )
        return InMemoryDPoPReplayStore()

    @staticmethod
    def public_jwk_thumbprint(public_jwk: Mapping[str, str]) -> str:
        """Compute the RFC 7638 SHA-256 thumbprint for a supported public JWK."""
        canonical = json.dumps(
            _required_jwk_fields(public_jwk),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return _b64url_encode(hashlib.sha256(canonical).digest())

    @staticmethod
    def public_pem_from_jwk(public_jwk: Mapping[str, str]) -> str:
        """Convert a supported public JWK to PEM for JWT verification."""
        return _public_pem_from_jwk(public_jwk)

    @staticmethod
    def generate_dpop_key_pair() -> tuple[str, dict[str, str]]:
        """Generate a P-256 key pair for DPoP clients.

        Returns:
            Tuple of ``(private_key_pem, public_jwk)``.
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_numbers = private_key.public_key().public_numbers()
        field_size = 32
        public_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url_encode(public_numbers.x.to_bytes(field_size, "big")),
            "y": _b64url_encode(public_numbers.y.to_bytes(field_size, "big")),
        }
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        return private_key_pem, public_jwk

    def _signing_algorithm(self) -> str:
        """Return the configured JWT algorithm name."""
        return settings.token_algorithm

    def _signing_key(self) -> str:
        """Return the configured JWT signing key material."""
        algorithm = self._signing_algorithm()
        if algorithm.startswith("HS"):
            return settings.token_secret_key
        if settings.token_private_key:
            return settings.token_private_key
        raise ValueError(
            "AEGIS_TOKEN_PRIVATE_KEY must be configured for asymmetric token signing"
        )

    def _verification_key(self) -> str:
        """Return the key material used to validate issued access tokens."""
        algorithm = self._signing_algorithm()
        if algorithm.startswith("HS"):
            return settings.token_secret_key
        if settings.token_public_key:
            return settings.token_public_key
        if settings.token_private_key:
            private_key = serialization.load_pem_private_key(
                settings.token_private_key.encode(),
                password=None,
            )
            public_key = private_key.public_key()
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        raise ValueError(
            "AEGIS_TOKEN_PUBLIC_KEY or AEGIS_TOKEN_PRIVATE_KEY must be configured "
            "for asymmetric token verification"
        )

    @staticmethod
    def _access_token_hash(access_token: str) -> str:
        """Return the DPoP access-token hash claim value for ``ath``."""
        return _b64url_encode(hashlib.sha256(access_token.encode()).digest())

    def issue_token(
        self,
        agent_type: str,
        requester_id: str,
        metadata: dict[str, str] | None = None,
        *,
        session_id: str | None = None,
        allowed_actions: Sequence[str] | None = None,
        role: str | None = None,
        expires_in_seconds: int | None = None,
        rotation_key: str | None = None,
        task_id: str | None = None,
        confirmation_jwk: Mapping[str, str] | None = None,
    ) -> str:
        """Create a signed JIT token for an agent session."""
        if not agent_type or not requester_id:
            raise ValueError("agent_type and requester_id must not be empty")

        now = time.time()
        expiry_seconds = (
            expires_in_seconds
            if expires_in_seconds is not None
            else settings.token_expiry_seconds
        )
        self._purge_expired_revocations(now)
        if rotation_key is not None and rotation_key in self._rotation_index:
            self.revoke_jti(self._rotation_index[rotation_key])

        claims: dict[str, Any] = {
            "jti": str(uuid4()),
            "sub": requester_id,
            "agent_type": agent_type,
            "session_id": session_id,
            "task_id": task_id,
            "allowed_actions": list(allowed_actions or []),
            "role": role,
            "iat": now,
            "exp": now + expiry_seconds,
            "metadata": metadata or {},
        }
        if confirmation_jwk is not None:
            claims["cnf"] = {"jkt": self.public_jwk_thumbprint(confirmation_jwk)}
        token: str = jwt.encode(
            claims,
            self._signing_key(),
            algorithm=self._signing_algorithm(),
        )
        if rotation_key is not None:
            self._rotation_index[rotation_key] = claims["jti"]
        return token

    def issue_sender_constrained_token(
        self,
        agent_type: str,
        requester_id: str,
        public_jwk: Mapping[str, str],
        metadata: dict[str, str] | None = None,
        *,
        session_id: str | None = None,
        task_id: str | None = None,
        allowed_actions: Sequence[str] | None = None,
        role: str | None = None,
        expires_in_seconds: int | None = None,
        rotation_key: str | None = None,
    ) -> str:
        """Create a sender-constrained token bound to a DPoP public key."""
        return self.issue_token(
            agent_type=agent_type,
            requester_id=requester_id,
            metadata=metadata,
            session_id=session_id,
            task_id=task_id,
            allowed_actions=allowed_actions,
            role=role,
            expires_in_seconds=expires_in_seconds,
            rotation_key=rotation_key,
            confirmation_jwk=public_jwk,
        )

    def validate_token(self, token: str) -> TokenClaims:
        """Decode and validate a JIT token, raising an error if invalid or expired."""
        try:
            payload = jwt.decode(
                token,
                self._verification_key(),
                algorithms=[self._signing_algorithm()],
            )
        except ExpiredSignatureError as exc:
            raise TokenExpiredError("Session token has expired") from exc

        jti = payload["jti"]
        self._purge_expired_revocations(time.time())
        if self.is_revoked(jti):
            raise TokenRevokedError(f"Session token jti={jti!r} has been revoked")

        return TokenClaims(
            jti=jti,
            sub=payload["sub"],
            agent_type=payload["agent_type"],
            session_id=payload.get("session_id"),
            task_id=payload.get("task_id"),
            allowed_actions=list(payload.get("allowed_actions", [])),
            role=payload.get("role"),
            issued_at=payload["iat"],
            expires_at=payload["exp"],
            metadata=payload.get("metadata", {}),
            cnf=ConfirmationClaims.model_validate(payload["cnf"])
            if payload.get("cnf") is not None
            else None,
        )

    def issue_dpop_proof(
        self,
        private_key_pem: str,
        public_jwk: Mapping[str, str],
        *,
        http_method: str,
        http_url: str,
        access_token: str | None = None,
        nonce: str | None = None,
        issued_at: int | None = None,
        proof_jti: str | None = None,
    ) -> str:
        """Create a DPoP proof JWT for a specific HTTP request."""
        now = issued_at if issued_at is not None else int(time.time())
        claims: dict[str, Any] = {
            "jti": proof_jti or str(uuid4()),
            "htm": http_method.upper(),
            "htu": http_url,
            "iat": now,
        }
        if access_token is not None:
            claims["ath"] = self._access_token_hash(access_token)
        if nonce is not None:
            claims["nonce"] = nonce

        headers = {
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": dict(public_jwk),
        }
        return str(jwt.encode(claims, private_key_pem, algorithm="ES256", headers=headers))

    def validate_dpop_proof(
        self,
        proof: str,
        *,
        http_method: str,
        http_url: str,
        access_token: str | None = None,
        nonce: str | None = None,
        now: float | None = None,
    ) -> DPoPProofClaims:
        """Validate a DPoP proof JWT and record its ``jti`` for replay protection."""
        current_time = now if now is not None else time.time()

        try:
            header = jwt.get_unverified_header(proof)
        except JWTError as exc:
            raise DPoPProofError("Malformed DPoP proof header") from exc

        if header.get("typ") != "dpop+jwt":
            raise DPoPProofError("DPoP proof header typ must be 'dpop+jwt'")

        public_jwk = header.get("jwk")
        if not isinstance(public_jwk, dict):
            raise DPoPProofError("DPoP proof header must embed a public JWK")

        public_pem = _public_pem_from_jwk(public_jwk)
        algorithm = str(header.get("alg", "ES256"))
        try:
            payload = jwt.decode(proof, public_pem, algorithms=[algorithm])
        except ExpiredSignatureError as exc:
            raise DPoPProofError("DPoP proof has expired") from exc
        except JWTError as exc:
            raise DPoPProofError("DPoP proof signature validation failed") from exc

        proof_claims = DPoPProofClaims.model_validate(payload)
        if proof_claims.htm.upper() != http_method.upper():
            raise DPoPProofError(
                f"DPoP proof htm mismatch: {proof_claims.htm!r} != {http_method.upper()!r}"
            )
        if proof_claims.htu != http_url:
            raise DPoPProofError(
                f"DPoP proof htu mismatch: {proof_claims.htu!r} != {http_url!r}"
            )

        earliest_valid_iat = current_time - settings.dpop_proof_ttl_seconds
        latest_valid_iat = current_time + settings.dpop_clock_skew_seconds
        if proof_claims.iat < earliest_valid_iat or proof_claims.iat > latest_valid_iat:
            raise DPoPProofError("DPoP proof iat is outside the acceptable time window")

        if nonce is not None and proof_claims.nonce != nonce:
            raise DPoPProofError("DPoP proof nonce mismatch")

        if access_token is not None:
            expected_ath = self._access_token_hash(access_token)
            if proof_claims.ath != expected_ath:
                raise DPoPProofError("DPoP proof ath mismatch for presented access token")

        replay_key = proof_claims.jti
        if not self._replay_store.register_if_unused(
            replay_key,
            settings.dpop_proof_ttl_seconds,
        ):
            raise DPoPReplayError(f"DPoP proof jti={replay_key!r} has already been used")
        return proof_claims

    def validate_sender_constrained_token(
        self,
        token: str,
        dpop_proof: str,
        *,
        http_method: str,
        http_url: str,
        nonce: str | None = None,
        now: float | None = None,
    ) -> TokenClaims:
        """Validate a sender-constrained token against a DPoP proof."""
        claims = self.validate_token(token)
        if claims.cnf is None:
            raise TokenBindingError("Access token is not sender-constrained (missing cnf.jkt)")

        try:
            header = jwt.get_unverified_header(dpop_proof)
        except JWTError as exc:
            raise DPoPProofError("Malformed DPoP proof header") from exc

        public_jwk = header.get("jwk")
        if not isinstance(public_jwk, dict):
            raise DPoPProofError("DPoP proof header must embed a public JWK")

        proof_thumbprint = self.public_jwk_thumbprint(public_jwk)
        if proof_thumbprint != claims.cnf.jkt:
            raise TokenBindingError(
                "DPoP proof key thumbprint does not match access token cnf.jkt"
            )

        self.validate_dpop_proof(
            dpop_proof,
            http_method=http_method,
            http_url=http_url,
            access_token=token,
            nonce=nonce,
            now=now,
        )
        return claims

    def revoke_token(self, token: str) -> str:
        """Revoke a token by extracting its ``jti`` without requiring a valid signature."""
        try:
            claims = jwt.get_unverified_claims(token)
        except JWTError as exc:
            raise ValueError("Unable to revoke malformed token") from exc

        jti = str(claims["jti"])
        expires_at = float(claims.get("exp", time.time()))
        self.revoke_jti(jti, expires_at=expires_at)
        return jti

    def revoke_jti(self, jti: str, expires_at: float | None = None) -> None:
        """Add a token ``jti`` to the in-memory revocation list."""
        ttl = expires_at if expires_at is not None else time.time() + settings.token_expiry_seconds
        self._revoked_jtis[jti] = ttl

    def is_revoked(self, jti: str) -> bool:
        """Return ``True`` when the ``jti`` appears in the revocation list."""
        self._purge_expired_revocations(time.time())
        return jti in self._revoked_jtis

    def ensure_action_allowed(self, claims: TokenClaims, action: str) -> None:
        """Assert that *action* is included in the token's ``allowed_actions`` scope."""
        if action not in claims.allowed_actions:
            raise TokenActionError(
                f"Token jti={claims.jti!r} is not scoped for action {action!r}"
            )

    def is_expired(self, claims: TokenClaims) -> bool:
        """Return True if the token has passed its expiry time."""
        return time.time() > claims.expires_at

    def time_remaining(self, claims: TokenClaims) -> float:
        """Return seconds until token expiry (negative if already expired)."""
        return claims.expires_at - time.time()

    def issued_at_utc(self, claims: TokenClaims) -> datetime:
        """Return the issuance time as a UTC datetime."""
        return datetime.fromtimestamp(claims.issued_at, tz=UTC)

    def _purge_expired_revocations(self, now: float) -> None:
        """Drop revocation entries whose original token lifetime has elapsed."""
        expired = [jti for jti, expires_at in self._revoked_jtis.items() if expires_at <= now]
        for jti in expired:
            self._revoked_jtis.pop(jti, None)

