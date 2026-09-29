import copy
import unittest

from agent_action_guard.authority import (
    AuthorityGrantError,
    build_authority_grant,
    validate_authority_grant,
)
from agent_action_guard.engine import evaluate
from agent_action_guard.model import Action, Effect, Policy, Rule


NOW = "2026-09-27T16:00:00Z"
EXPIRY = "2026-09-27T16:05:00Z"


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
            created_at=NOW,
            expires_at=EXPIRY,
        )

        self.assertEqual(grant["contract_version"], "eba.integration/v0.1")
        self.assertEqual(grant["kind"], "AuthorityGrant")
        self.assertEqual(grant["principal"]["id"], "ci-retry-gate")
        self.assertEqual(grant["matched_allow_rule_ids"], ["allow-ci-rerun"])
        validate_authority_grant(grant, action=act, now=NOW)

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
                created_at=NOW,
                expires_at=EXPIRY,
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
                created_at=NOW,
                expires_at=EXPIRY,
            )

    def test_tampering_fails_integrity(self):
        act = action()
        pol = policy()
        grant = build_authority_grant(
            action=act,
            policy=pol,
            decision=evaluate(act, pol),
            trace_id="tr-1",
            created_at=NOW,
            expires_at=EXPIRY,
        )
        tampered = copy.deepcopy(grant)
        tampered["resource_scope"] = ["github://other"]
        with self.assertRaisesRegex(AuthorityGrantError, "INTEGRITY"):
            validate_authority_grant(tampered, action=act, now=NOW)

    def test_grant_is_bound_to_exact_action_scope(self):
        act = action()
        pol = policy()
        grant = build_authority_grant(
            action=act,
            policy=pol,
            decision=evaluate(act, pol),
            trace_id="tr-1",
            created_at=NOW,
            expires_at=EXPIRY,
        )
        changed = action(resource="github://achirothmane/workflow-failure-lab/actions/runs/999")
        with self.assertRaisesRegex(AuthorityGrantError, "SCOPE_MISMATCH"):
            validate_authority_grant(grant, action=changed, now=NOW)

    def test_principal_mismatch_is_rejected(self):
        act = action()
        pol = policy()
        grant = build_authority_grant(
            action=act,
            policy=pol,
            decision=evaluate(act, pol),
            trace_id="tr-1",
            created_at=NOW,
            expires_at=EXPIRY,
        )
        changed = action(actor="other-agent")
        with self.assertRaisesRegex(AuthorityGrantError, "PRINCIPAL_MISMATCH"):
            validate_authority_grant(grant, action=changed, now=NOW)




    def test_expiry_is_half_open(self):
        act = action()
        pol = policy()
        grant = build_authority_grant(
            action=act,
            policy=pol,
            decision=evaluate(act, pol),
            trace_id="tr-1",
            created_at=NOW,
            expires_at=EXPIRY,
        )
        validate_authority_grant(
            grant,
            action=act,
            now="2026-09-27T16:04:59Z",
        )
        with self.assertRaisesRegex(AuthorityGrantError, "AUTHORITY_EXPIRED"):
            validate_authority_grant(
                grant,
                action=act,
                now=EXPIRY,
            )

    def test_missing_expiry_cannot_create_authority(self):
        act = action()
        pol = policy()
        with self.assertRaisesRegex(AuthorityGrantError, "EXPIRES_AT_MISSING"):
            build_authority_grant(
                action=act,
                policy=pol,
                decision=evaluate(act, pol),
                trace_id="tr-1",
                created_at=NOW,
            )

    def test_malformed_expiry_is_rejected(self):
        act = action()
        pol = policy()
        grant = build_authority_grant(
            action=act,
            policy=pol,
            decision=evaluate(act, pol),
            trace_id="tr-1",
            created_at=NOW,
            expires_at=EXPIRY,
        )
        broken = copy.deepcopy(grant)
        broken["expires_at"] = 123
        import hashlib, json
        unsigned = dict(broken)
        unsigned.pop("integrity", None)
        broken["integrity"] = {
            "algorithm": "sha256",
            "digest": hashlib.sha256(
                json.dumps(
                    unsigned,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest(),
        }
        with self.assertRaisesRegex(AuthorityGrantError, "AUTHORITY_EXPIRES_AT_INVALID"):
            validate_authority_grant(broken, action=act, now=NOW)


if __name__ == "__main__":
    unittest.main()
