#!/usr/bin/env python3
"""Regression tests for the ATP §8.1 revocation-entry checks in verify.py.

Run from this directory:
    python3 -m unittest -v test_verify
"""

from __future__ import annotations

import unittest
from typing import Any

import verify

# The ATP §8.1 example entry, as pinned in fixtures/revocation-list-valid.json.
SPEC_ENTRY: dict[str, Any] = {
    "agentDid": "did:opena2a:mcp_server:compromised-package",
    "revokedAt": "2026-03-22T15:00:00Z",
    "reason": "Supply chain compromise detected",
    "transparencyLogIndex": 1847300,
    "revokedByKeyId": "did:opena2a:authority:opena2a.org#key-v3",
}


def verify_entry(entry: dict[str, Any]) -> verify.VerifyResult:
    return verify.verify_fixture(
        {
            "fixtureType": "revocationList",
            "revocationList": {"revocations": [entry], "nextSince": "2026-03-22T15:00:00Z"},
        }
    )


class TransparencyLogIndexTest(unittest.TestCase):
    """transparencyLogIndex is optional on a §8.1 entry; a present one must be >= 0."""

    def test_absent_index_is_accepted(self) -> None:
        entry = {k: v for k, v in SPEC_ENTRY.items() if k != "transparencyLogIndex"}
        got = verify_entry(entry)
        self.assertTrue(got.accepted, str(got))

    def test_null_index_is_accepted(self) -> None:
        got = verify_entry({**SPEC_ENTRY, "transparencyLogIndex": None})
        self.assertTrue(got.accepted, str(got))

    def test_zero_index_is_accepted(self) -> None:
        got = verify_entry({**SPEC_ENTRY, "transparencyLogIndex": 0})
        self.assertTrue(got.accepted, str(got))

    def test_spec_example_index_is_accepted(self) -> None:
        got = verify_entry(dict(SPEC_ENTRY))
        self.assertTrue(got.accepted, str(got))

    def test_negative_index_is_rejected(self) -> None:
        got = verify_entry({**SPEC_ENTRY, "transparencyLogIndex": -1})
        self.assertFalse(got.accepted)
        self.assertEqual(got.reject_category, "PARSE_ERROR")
        self.assertIn("transparencyLogIndex", got.reason)


if __name__ == "__main__":
    unittest.main()
