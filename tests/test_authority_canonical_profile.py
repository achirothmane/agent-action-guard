from __future__ import annotations

import hashlib
import unittest

from agent_action_guard.authority import AuthorityGrantError, canonical_json_bytes


class CanonicalProfileTests(unittest.TestCase):
    def test_shared_key_order_vector(self):
        body = canonical_json_bytes({"b": 2, "a": 1})
        self.assertEqual(body, b'{"a":1,"b":2}')
        self.assertEqual(
            hashlib.sha256(body).hexdigest(),
            "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
        )

    def test_ambiguous_numbers_reject(self):
        with self.assertRaisesRegex(AuthorityGrantError, "CANONICAL_NON_INTEGER_NUMBER"):
            canonical_json_bytes({"n": 1.0})
        with self.assertRaisesRegex(AuthorityGrantError, "CANONICAL_INTEGER_OUT_OF_RANGE"):
            canonical_json_bytes({"n": 9007199254740992})


if __name__ == "__main__":
    unittest.main()
