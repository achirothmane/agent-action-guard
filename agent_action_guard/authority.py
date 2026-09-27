"""Evidence-before-Action AuthorityGrant adapter.

This module does not change agent-action-guard v0.1 decision semantics.
It derives a machine-readable AuthorityGrant only from an engine-produced
ALLOW Decision and the exact Action/Policy inputs that produced it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from agent_action_guard.model import Action, Decision, Effect, Policy

CONTRACT_VERSION = "eba.integration/v0.1"
AUTHORITY_KIND = "AuthorityGrant"


class AuthorityGrantError(ValueError):
    """Fail-closed authority artifact construction/validation error."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _stable_id(prefix: str, value: dict[str, Any]) -> str:
    return f"{prefix}_{_digest(value)[:24]}"


def _with_integrity(value: dict[str, Any]) -> dict[str, Any]:
    artifact = dict(value)
    artifact.pop("integrity", None)
    artifact["integrity"] = {
        "algorithm": "sha256",
        "digest": _digest(artifact),
    }
    return artifact


def action_scope_digest(action: Action) -> str:
    return _digest(
        {
            "actor": action.actor,
            "tool": action.tool,
            "operation": action.operation,
            "resource": action.resource,
            "side_effect": action.side_effect,
        }
    )


def build_authority_grant(
    *,
    action: Action,
    policy: Policy,
    decision: Decision,
    trace_id: str,
    created_at: str | None = None,
    expires_at: str | None = None,
    producer: str = "agent-action-guard",
) -> dict[str, Any]:
    """Derive an AuthorityGrant from one exact ALLOW evaluation.

    DENY and REQUIRE_APPROVAL never produce an authority grant.
    """
    if not trace_id:
        raise AuthorityGrantError("trace_id is required")
    if decision.action_id != action.action_id:
        raise AuthorityGrantError("decision/action id mismatch")
    if decision.policy_id != policy.policy_id:
        raise AuthorityGrantError("decision/policy id mismatch")
    if decision.decision is not Effect.ALLOW:
        raise AuthorityGrantError("AUTHORITY_NOT_GRANTED")
    if not decision.matched_allow:
        raise AuthorityGrantError("ALLOW decision has no matched ALLOW rule")

    timestamp = created_at or _utc_now()

    grant: dict[str, Any] = {
        "contract_version": CONTRACT_VERSION,
        "kind": AUTHORITY_KIND,
        "trace_id": trace_id,
        "producer": producer,
        "created_at": timestamp,
        "principal": {
            "type": "agent",
            "id": action.actor,
        },
        "allowed_actions": [
            {
                "tool": action.tool,
                "operation": action.operation,
                "side_effect": action.side_effect,
            }
        ],
        "resource_scope": [action.resource],
        "context_constraints": {},
        "issued_by": f"policy:{policy.policy_id}",
        "not_before": timestamp,
        "expires_at": expires_at,
        "revoked": False,
        "policy_ref": policy.policy_id,
        "matched_allow_rule_ids": list(decision.matched_allow),
        "action_id": action.action_id,
        "action_scope_digest": action_scope_digest(action),
    }
    grant["id"] = _stable_id("auth", grant)
    return _with_integrity(grant)


def validate_authority_grant(
    grant: dict[str, Any],
    *,
    action: Action | None = None,
) -> None:
    if grant.get("contract_version") != CONTRACT_VERSION:
        raise AuthorityGrantError("unsupported contract_version")
    if grant.get("kind") != AUTHORITY_KIND:
        raise AuthorityGrantError("expected AuthorityGrant")
    if grant.get("revoked") is not False:
        raise AuthorityGrantError("AUTHORITY_REVOKED")

    integrity = grant.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
        raise AuthorityGrantError("AUTHORITY_INTEGRITY_INVALID")
    unsigned = dict(grant)
    unsigned.pop("integrity", None)
    if integrity.get("digest") != _digest(unsigned):
        raise AuthorityGrantError("AUTHORITY_INTEGRITY_INVALID")

    if action is not None:
        principal = grant.get("principal")
        if not isinstance(principal, dict) or principal.get("id") != action.actor:
            raise AuthorityGrantError("AUTHORITY_PRINCIPAL_MISMATCH")
        if grant.get("action_scope_digest") != action_scope_digest(action):
            raise AuthorityGrantError("AUTHORITY_SCOPE_MISMATCH")
