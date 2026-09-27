import copy
import unittest

from agent_action_guard.authority import (
    AuthorityGrantError,
    build_authority_grant,
    validate_authority_grant,
)
from agent_action_guard.engine import evaluate
from agent_action_guard.model import Action, Effect, Policy, Rule


def action(**overrides):
    values = dict(
        action_id="req-1",
        actor="ci-retry-gate",
        tool="github-actions",
        operation="rerun_failed_jobs",
        resource="github://achirothmane/workflow-failure-lab/actions/runs/123",
        side_effect=True,
    )
    values.update(overrides)
    return Action(**values)


def policy(effect=Effect.ALLOW):
    return Policy(
        "ci-retry-authority-v1",
        (
            Rule(
                "allow-ci-rerun",
                effect,
                (
                    ("actor", "ci-retry-gate"),
                    ("tool", "github-actions"),
                    ("operation", "rerun_failed_jobs"),
                    ("side_effect", True),
                ),
            ),
        ),
    )


class TestAuthorityGrant(unittest.TestCase):
    def test_allow_can_produce_authority_grant(self):
        act = action()
        pol = policy()
        decision = evaluate(act, pol)
        grant = build_authority_grant(
            action=act,
            policy=pol,
            decision=decision,
            trace_id="tr-1",
            created_at="2026-09-27T16:00:00Z",
        )

        self.assertEqual(grant["contract_version"], "eba.integration/v0.1")
        self.assertEqual(grant["kind"], "AuthorityGrant")
        self.assertEqual(grant["principal"]["id"], "ci-retry-gate")
        self.assertEqual(grant["matched_allow_rule_ids"], ["allow-ci-rerun"])
        validate_authority_grant(grant, action=act)

    def test_deny_cannot_produce_authority_grant(self):
        act = action()
        pol = policy(Effect.DENY)
        decision = evaluate(act, pol)
        with self.assertRaisesRegex(AuthorityGrantError, "NOT_GRANTED"):
            build_authority_grant(
                action=act,
                policy=pol,
                decision=decision,
                trace_id="tr-1",
            )

    def test_require_approval_cannot_produce_authority_grant(self):
        act = action()
        pol = policy(Effect.REQUIRE_APPROVAL)
        decision = evaluate(act, pol)
        with self.assertRaisesRegex(AuthorityGrantError, "NOT_GRANTED"):
            build_authority_grant(
                action=act,
                policy=pol,
                decision=decision,
                trace_id="tr-1",
            )

    def test_tampering_fails_integrity(self):
        act = action()
        pol = policy()
        grant = build_authority_grant(
            action=act,
            policy=pol,
            decision=evaluate(act, pol),
            trace_id="tr-1",
        )
        tampered = copy.deepcopy(grant)
        tampered["resource_scope"] = ["github://other"]
        with self.assertRaisesRegex(AuthorityGrantError, "INTEGRITY"):
            validate_authority_grant(tampered, action=act)

    def test_grant_is_bound_to_exact_action_scope(self):
        act = action()
        pol = policy()
        grant = build_authority_grant(
            action=act,
            policy=pol,
            decision=evaluate(act, pol),
            trace_id="tr-1",
        )
        changed = action(resource="github://achirothmane/workflow-failure-lab/actions/runs/999")
        with self.assertRaisesRegex(AuthorityGrantError, "SCOPE_MISMATCH"):
            validate_authority_grant(grant, action=changed)

    def test_principal_mismatch_is_rejected(self):
        act = action()
        pol = policy()
        grant = build_authority_grant(
            action=act,
            policy=pol,
            decision=evaluate(act, pol),
            trace_id="tr-1",
        )
        changed = action(actor="other-agent")
        with self.assertRaisesRegex(AuthorityGrantError, "PRINCIPAL_MISMATCH"):
            validate_authority_grant(grant, action=changed)


if __name__ == "__main__":
    unittest.main()
