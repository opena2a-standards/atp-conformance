#!/usr/bin/env python3
"""Regression tests for verify.py: the ATP §8.1 revocation-entry checks and
the PARSE_ERROR verdict for members of the wrong JSON type.

Run from this directory:
    python3 -m unittest -v test_verify
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
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


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


def revocation_with(**overrides: Any) -> dict[str, Any]:
    fx = load("revocation-list-valid.json")
    fx["revocationList"]["revocations"][0].update(overrides)
    return fx


class MalformedMemberTest(unittest.TestCase):
    """A member of the wrong JSON type is a PARSE_ERROR verdict, not an exception."""

    def assert_parse_error(self, fixture: dict[str, Any]) -> None:
        got = verify.verify_fixture(fixture)
        self.assertFalse(got.accepted, str(got))
        self.assertEqual(got.reject_category, "PARSE_ERROR", str(got))

    def test_transparency_log_index_wrong_type(self) -> None:
        for value in ("abc", "", "0x10", {}, []):
            with self.subTest(value=value):
                self.assert_parse_error(revocation_with(transparencyLogIndex=value))

    def test_revocations_null(self) -> None:
        fx = load("revocation-list-valid.json")
        fx["revocationList"]["revocations"] = None
        self.assert_parse_error(fx)

    def test_revoked_by_key_id_null(self) -> None:
        self.assert_parse_error(revocation_with(revokedByKeyId=None))

    def test_agent_did_number(self) -> None:
        self.assert_parse_error(revocation_with(agentDid=42))

    def test_revocation_entry_number(self) -> None:
        fx = load("revocation-list-valid.json")
        fx["revocationList"]["revocations"][0] = 7
        self.assert_parse_error(fx)

    def test_inclusion_log_index_null(self) -> None:
        fx = load("transparency-inclusion-proof-valid.json")
        fx["inclusionProof"]["logIndex"] = None
        self.assert_parse_error(fx)

    def test_sth_tree_size_null(self) -> None:
        fx = load("transparency-log-sth.json")
        fx["signedTreeHead"]["treeSize"] = None
        self.assert_parse_error(fx)

    def test_consistency_from_size_null(self) -> None:
        fx = load("transparency-consistency-proof-valid.json")
        fx["consistencyProof"]["fromSize"] = None
        self.assert_parse_error(fx)

    def test_discovery_conformance_level_wrong_type(self) -> None:
        for value in (None, "2"):
            with self.subTest(value=value):
                fx = load("discovery-valid.json")
                fx["discoveryResponse"]["conformanceLevel"] = value
                self.assert_parse_error(fx)


class DirectoryRunTest(unittest.TestCase):
    """A malformed fixture in a directory run does not stop the fixtures after it."""

    def test_run_continues_and_prints_summary(self) -> None:
        valid = load("revocation-list-valid.json")
        bad = revocation_with(transparencyLogIndex="abc")
        with tempfile.TemporaryDirectory() as d:
            for name, fx in (("a-valid.json", valid), ("b-bad.json", bad), ("c-valid.json", valid)):
                (Path(d) / name).write_text(json.dumps(fx))
            (Path(d) / "d-array.json").write_text("[]")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = verify.main(["verify.py", d])
        lines = out.getvalue().splitlines()
        self.assertEqual(code, 1)
        self.assertEqual([ln.split()[0] for ln in lines if ln.startswith(("PASS", "FAIL"))], ["PASS", "FAIL", "PASS", "FAIL"])
        self.assertIn("REJECT[PARSE_ERROR", out.getvalue())
        self.assertEqual(lines[-1], "summary: 2 pass, 2 fail (4 fixtures)")


if __name__ == "__main__":
    unittest.main()
