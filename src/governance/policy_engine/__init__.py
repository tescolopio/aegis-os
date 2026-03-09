"""Public package surface for the policy engine."""

from src.governance.policy_engine.opa_client import (
    OpaUnavailableError,
    PolicyEngine,
    PolicyInput,
    PolicyResult,
)

__all__ = [
    "OpaUnavailableError",
    "PolicyEngine",
    "PolicyInput",
    "PolicyResult",
]
