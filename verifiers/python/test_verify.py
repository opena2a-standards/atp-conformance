#!/usr/bin/env python3
"""Regression tests for verify.py: the ATP §8.1 revocation-entry checks and
the PARSE_ERROR verdict for members of the wrong JSON type, under the
wire-shape rules both reference verifiers apply.

Run from this directory:
    python3 -m unittest -v test_verify
"""

from __future__ import annotations

import contextlib
import copy
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


def with_member(fixture: dict[str, Any], path: str, literal: str) -> dict[str, Any]:
    """A copy of fixture with the member at the dotted path (array steps as
    indexes) replaced by the JSON literal, read the way json.loads reads it
    from a fixture file."""
    doc = copy.deepcopy(fixture)
    steps: list[Any] = [int(step) if step.isdigit() else step for step in path.split(".")]
    cur: Any = doc
    for step in steps[:-1]:
        cur = cur[step]
    cur[steps[-1]] = json.loads(literal)
    return doc


# One member of a committed ACCEPT fixture replaced by a value whose JSON
# type or range the vendored schema rejects. ../go/verify_test.go holds the
# same table.
SCHEMA_TYPE_VIOLATIONS: list[tuple[str, str, str]] = [
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", '"5"'),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", '"1847300"'),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", '" 42 "'),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", '"1_000"'),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "true"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "false"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "1847300.0"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "1847300.5"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "1e3"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "1e30"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "9223372036854775808"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "9" * 400),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "-0.5"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "-0.999"),
    ("revocation-list-valid.json", "revocationList.revocations.0.reason", "1"),
    ("revocation-list-valid.json", "revocationList.revocations.0.revokedByKeyId", '["#"]'),
    ("revocation-list-valid.json", "revocationList.revocations", "{}"),
    ("revocation-list-valid.json", "revocationList.nextSince", "20260322"),
    ("trust-proof-baseline.json", "trustProof.trustLevel", '"3"'),
    ("trust-proof-baseline.json", "trustProof.trustLevel", "3.7"),
    ("trust-proof-baseline.json", "trustProof.trustScore", '"0.825"'),
    ("trust-proof-baseline.json", "trustProof.transparencyLogIndex", '"7"'),
    ("trust-proof-baseline.json", "trustProof.transparencyLogIndex", "-0.5"),
    ("trust-proof-baseline.json", "trustProof.transparencyLogIndex", "-5"),
    ("trust-proof-baseline.json", "trustProof.signatures.0.value", "42"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.logIndex", "3.5"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.logIndex", '"3"'),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead.treeSize", '"8"'),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.auditPath", '"SHA256:00"'),
    ("transparency-consistency-proof-valid.json", "consistencyProof.fromSize", '"4"'),
    ("transparency-log-sth.json", "signedTreeHead.treeSize", '"1847294"'),
    ("transparency-log-sth.json", "signedTreeHead.rootHash", '["SHA256:00"]'),
    ("discovery-valid.json", "discoveryResponse.conformanceLevel", "2.5"),
    ("discovery-valid.json", "discoveryResponse.conformanceLevel", "true"),
    ("discovery-valid.json", "discoveryResponse.version", "1.0"),
    ("discovery-valid.json", "discoveryResponse.endpoints", '["/api/v1/trust/proof"]'),
]


class SchemaTypeViolationTest(unittest.TestCase):
    """A member whose JSON type or range violates the vendored schema is
    REJECT[PARSE_ERROR] naming the member, the verdict the Go verifier
    returns for the same input, instead of being coerced with int() or
    float() and accepted."""

    def test_unmodified_fixtures_are_accepted(self) -> None:
        for name in sorted({case[0] for case in SCHEMA_TYPE_VIOLATIONS}):
            with self.subTest(fixture=name):
                got = verify.verify_fixture(load(name))
                self.assertTrue(got.accepted, str(got))

    def test_type_violation_is_parse_error(self) -> None:
        for name, path, literal in SCHEMA_TYPE_VIOLATIONS:
            with self.subTest(fixture=name, path=path, value=literal[:24]):
                got = verify.verify_fixture(with_member(load(name), path, literal))
                member = path.rsplit(".", 1)[-1]
                self.assertFalse(got.accepted, str(got))
                self.assertEqual(got.reject_category, "PARSE_ERROR", str(got))
                self.assertIn(member, got.reason)


# One member of a committed ACCEPT fixture set to JSON null where the vendored
# schema gives it a type: each member kind (string, integer, number, array,
# array element, object, object value) on each payload type.
# ../go/verify_test.go holds the same table.
NULL_VIOLATIONS: list[tuple[str, str]] = [
    ("revocation-list-valid.json", "revocationList.revocations"),
    ("revocation-list-valid.json", "revocationList.revocations.0"),
    ("revocation-list-valid.json", "revocationList.revocations.0.agentDid"),
    ("revocation-list-valid.json", "revocationList.revocations.0.reason"),
    ("revocation-list-valid.json", "revocationList.revocations.0.revokedByKeyId"),
    ("revocation-list-valid.json", "revocationList.nextSince"),
    ("trust-proof-baseline.json", "trustProof.did"),
    ("trust-proof-baseline.json", "trustProof.trustLevel"),
    ("trust-proof-baseline.json", "trustProof.trustScore"),
    ("trust-proof-baseline.json", "trustProof.signatures"),
    ("trust-proof-baseline.json", "trustProof.signatures.0.value"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.logIndex"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.auditPath"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.auditPath.0"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead.treeSize"),
    ("transparency-consistency-proof-valid.json", "consistencyProof.fromSize"),
    ("transparency-consistency-proof-valid.json", "consistencyProof.consistencyPath"),
    ("transparency-consistency-proof-valid.json", "consistencyProof.toSignedTreeHead.rootHash"),
    ("transparency-log-sth.json", "signedTreeHead.treeSize"),
    ("transparency-log-sth.json", "signedTreeHead.timestamp"),
    ("discovery-valid.json", "discoveryResponse.conformanceLevel"),
    ("discovery-valid.json", "discoveryResponse.authorityDid"),
    ("discovery-valid.json", "discoveryResponse.endpoints"),
    ("discovery-valid.json", "discoveryResponse.endpoints.trustProof"),
    ("discovery-valid.json", "discoveryResponse.publicKeys.0.status"),
    ("discovery-valid.json", "discoveryResponse.supportedMethods"),
]


def member_label(path: str) -> str:
    """A dotted fixture path written the way both verifiers name the member in
    a reason, with array steps as [index]."""
    label = ""
    for step in path.split("."):
        if step.isdigit():
            label += f"[{step}]"
        else:
            label += f".{step}" if label else step
    return label


class NullMemberTest(unittest.TestCase):
    """JSON null is a value of no schema type, so a null member is
    REJECT[PARSE_ERROR] naming the member, the verdict the Go verifier
    returns for the same input, and not the zero value encoding/json decodes
    it to: revocations null is not an empty revocation list, and logIndex
    null is not leaf 0. The members that take null take it as absent: an
    optional transparencyLogIndex is then not checked
    (TransparencyLogIndexTest covers the §8.1 entry's) and an embedded tree
    head is reported missing."""

    def test_null_member_is_parse_error(self) -> None:
        for name, path in NULL_VIOLATIONS:
            with self.subTest(fixture=name, path=path):
                got = verify.verify_fixture(with_member(load(name), path, "null"))
                want = f"{member_label(path)}: JSON null does not fit the "
                self.assertFalse(got.accepted, str(got))
                self.assertEqual(got.reject_category, "PARSE_ERROR", str(got))
                self.assertTrue(got.reason.startswith(want), f"{got} does not begin {want!r}")

    def test_null_trust_proof_index_is_accepted(self) -> None:
        got = verify.verify_fixture(
            with_member(load("trust-proof-baseline.json"), "trustProof.transparencyLogIndex", "null")
        )
        self.assertTrue(got.accepted, str(got))

    def test_absent_trust_proof_index_is_accepted(self) -> None:
        doc = load("trust-proof-baseline.json")
        del doc["trustProof"]["transparencyLogIndex"]
        got = verify.verify_fixture(doc)
        self.assertTrue(got.accepted, str(got))

    def test_null_embedded_tree_head_is_missing(self) -> None:
        for name, path, reason in (
            ("transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead", "signedTreeHead missing"),
            (
                "transparency-consistency-proof-valid.json",
                "consistencyProof.fromSignedTreeHead",
                "fromSignedTreeHead/toSignedTreeHead missing",
            ),
        ):
            with self.subTest(path=path):
                got = verify.verify_fixture(with_member(load(name), path, "null"))
                self.assertEqual(got.reject_category, "PARSE_ERROR", str(got))
                self.assertIn(reason, got.reason)


class FixtureDocumentTest(unittest.TestCase):
    """parse_fixture refuses at load time what the Go verifier's decoder
    refuses: the NaN / Infinity extensions and a document that is not a
    JSON object."""

    def test_nan_literal_is_a_load_error(self) -> None:
        with self.assertRaises(ValueError):
            verify.parse_fixture('{"fixtureType": "trustProof", "trustProof": {"trustScore": NaN}}')

    def test_infinity_literal_is_a_load_error(self) -> None:
        with self.assertRaises(ValueError):
            verify.parse_fixture('{"trustProof": {"trustScore": -Infinity}}')

    def test_non_object_document_is_a_load_error(self) -> None:
        with self.assertRaises(ValueError):
            verify.parse_fixture("[]")

    def test_committed_fixture_parses(self) -> None:
        doc = verify.parse_fixture((FIXTURES / "trust-proof-baseline.json").read_text())
        self.assertEqual(doc["fixtureType"], "trustProof")


if __name__ == "__main__":
    unittest.main()
