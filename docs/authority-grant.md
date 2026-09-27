# EBA AuthorityGrant profile

`agent-action-guard` can derive an `AuthorityGrant` compatible with
`eba.integration/v0.1` from an existing deterministic policy evaluation.

This does **not** change the v0.1 policy semantics. The existing engine still
produces `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`.

Only an exact `ALLOW` evaluation may be converted into an AuthorityGrant.

## Flow

```text
Action + Policy
      ↓
agent-action-guard
      ↓
ALLOW
      ↓
AuthorityGrant
      ↓
EBA Decision authority_ref
```

`DENY` and `REQUIRE_APPROVAL` produce no grant.

## Binding

The grant is bound to:

- actor
- tool
- operation
- resource
- side_effect
- policy id
- matched ALLOW rule ids

A SHA-256 integrity digest protects the artifact, and
`action_scope_digest` prevents using a grant for a materially different
action.

## Example shape

```json
{
  "contract_version": "eba.integration/v0.1",
  "kind": "AuthorityGrant",
  "id": "auth_...",
  "trace_id": "tr_...",
  "producer": "agent-action-guard",
  "principal": {"type": "agent", "id": "ci-retry-gate"},
  "allowed_actions": [{
    "tool": "github-actions",
    "operation": "rerun_failed_jobs",
    "side_effect": true
  }],
  "resource_scope": [
    "github://achirothmane/workflow-failure-lab/actions/runs/123"
  ],
  "issued_by": "policy:ci-retry-authority-v1",
  "revoked": false,
  "policy_ref": "ci-retry-authority-v1",
  "matched_allow_rule_ids": ["allow-ci-rerun"],
  "action_scope_digest": "...",
  "integrity": {"algorithm": "sha256", "digest": "..."}
}
```
